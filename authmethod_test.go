// SPDX-License-Identifier: LGPL-2.1-or-later

// How a connection authenticates: which method a profile selects, what that
// method presents for each exchange, and what it makes of the server's answer.
//
// The credential half sits here because authmethod.go's does, and the leak
// scans below are the same seam from the other side: a credential the report
// was not told to scrub is a credential that travels.

package vpn

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/openlawsvpn/go-openlawsvpn/diag"
	"github.com/openlawsvpn/go-openlawsvpn/internal/control"
	"github.com/openlawsvpn/go-openlawsvpn/internal/keymethod2"
	"github.com/openlawsvpn/go-openlawsvpn/profile"
	"github.com/openlawsvpn/go-openlawsvpn/routing"
)

// methodTestClient returns a client whose profile selects one authentication
// method, built the way a caller's would be: from the profile, not by assigning
// the method directly.
func methodTestClient(t *testing.T, certAuth, federated bool) *Client {
	t.Helper()
	p := credentialTestProfile(t, "", certAuth)
	p.Federated = federated
	c := New(p)
	c.auth = c.authMethodFor(p)
	return c
}

// The three answers a server can give to the first PUSH_REQUEST, as they
// arrive: classified by control, unparsed.
var (
	pushReplyMsg = &control.Message{
		Kind: control.MsgKindPushReply,
		Raw:  "PUSH_REPLY,ifconfig 10.8.0.2 255.255.255.0",
	}
	crv1Msg = &control.Message{
		Kind: control.MsgKindAuthFailedCRV1,
		Raw:  "AUTH_FAILED,CRV1:R,52.1.2.3:stateABC::https://idp.example.com/saml",
	}
	restartMsg = &control.Message{Kind: control.MsgKindRestart, Raw: "RESTART"}
)

// TestHandleReplyTable is the reply contract, one row per (method, answer).
//
// The rows that matter are the CRV1 ones: a challenge is the SAML method's
// expected answer, and to any other method it is the server naming an
// authentication method the profile carries no material for — ClassAuth rather
// than the ClassProtocol a malformed message would be.
func TestHandleReplyTable(t *testing.T) {
	for _, tc := range []struct {
		name      string
		certAuth  bool
		federated bool
		msg       *control.Message
		want      authReply
		wantFail  bool
		wantClass diag.Class
	}{
		{name: "cert: a reply is the reply", certAuth: true, msg: pushReplyMsg, want: replyPushed},
		{name: "cert: a challenge is an auth failure", certAuth: true, msg: crv1Msg, wantFail: true, wantClass: diag.ClassAuth},
		{name: "cert: anything else is protocol", certAuth: true, msg: restartMsg, wantFail: true, wantClass: diag.ClassProtocol},

		{name: "user/pass: a reply is the reply", msg: pushReplyMsg, want: replyPushed},
		{name: "user/pass: a challenge is an auth failure", msg: crv1Msg, wantFail: true, wantClass: diag.ClassAuth},

		{name: "saml: a challenge asks for a second exchange", federated: true, msg: crv1Msg, want: replySecondExchange},
		{name: "saml: a reply finishes it in one", federated: true, msg: pushReplyMsg, want: replyPushed},
		{name: "saml: anything else is protocol", federated: true, msg: restartMsg, wantFail: true, wantClass: diag.ClassProtocol},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := methodTestClient(t, tc.certAuth, tc.federated)
			got, derr := c.method().handleReply(tc.msg)
			if tc.wantFail {
				if derr == nil {
					t.Fatalf("handleReply = (%v, nil), want a %s failure", got, tc.wantClass)
				}
				if derr.Class != tc.wantClass {
					t.Errorf("class = %s, want %s", derr.Class, tc.wantClass)
				}
				if derr.Stage != diag.StagePush {
					t.Errorf("stage = %s, want %s", derr.Stage, diag.StagePush)
				}
				return
			}
			if derr != nil {
				t.Fatalf("handleReply: %v", derr)
			}
			if got != tc.want {
				t.Errorf("handleReply = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestSAMLChallengeIsStoredForTheSecondExchange pins what the SAML method keeps
// from a challenge, because the second exchange authenticates with it and dials
// the address it names. The address matters on its own: AWS binds the state id
// to one backend instance, and the IP the first exchange dialled may be a load
// balancer that routes the second one somewhere the state id means nothing.
func TestSAMLChallengeIsStoredForTheSecondExchange(t *testing.T) {
	c := methodTestClient(t, false, true)
	c.backendIP = "198.51.100.9" // what the first exchange dialled

	got, derr := c.method().handleReply(crv1Msg)
	if derr != nil {
		t.Fatalf("handleReply: %v", derr)
	}
	if got != replySecondExchange {
		t.Fatalf("handleReply = %v, want %v", got, replySecondExchange)
	}

	c.mu.Lock()
	session, ip := c.samlSession, c.backendIP
	c.mu.Unlock()

	if session == nil {
		t.Fatal("no SAML session stored")
	}
	if session.StateID != "stateABC" {
		t.Errorf("StateID = %q, want %q", session.StateID, "stateABC")
	}
	if session.URL != "https://idp.example.com/saml" {
		t.Errorf("URL = %q", session.URL)
	}
	if ip != "52.1.2.3" {
		t.Errorf("backendIP = %q, want the address the challenge named", ip)
	}
	// The state id is session-bearing, and the report is the one thing about
	// an attempt that gets shared. Registration is what stops it travelling.
	c.recordServerOpts("V4,dev-type tun,state stateABC")
	if opts := c.Report().Redacted().ServerOpts; strings.Contains(opts, "stateABC") {
		t.Errorf("the state id was not registered for redaction: %q", opts)
	}
}

// bothAsks is every caller a method can be asked by. A row that must answer
// the same to both is written against this, so that an implementation which
// starts distinguishing them has to say so here.
var bothAsks = []missingFor{missingForAnyEntry, missingForConnect}

// TestMissingNamesWhatTheCallerDidNotSet covers the precondition both entry
// points check: a method whose credential comes from somewhere nobody supplied
// cannot be driven, and saying so before a socket is opened is the difference
// between a config error and an unexplained auth failure. It is also where the
// one asymmetry between the two questions is pinned — two of the three methods
// answer both the same, and the federated one does not.
func TestMissingNamesWhatTheCallerDidNotSet(t *testing.T) {
	cert := methodTestClient(t, true, false)
	for _, ask := range bothAsks {
		if got := cert.method().missing(ask); got != "" {
			t.Errorf("cert-only wants %q; the certificate is the whole credential", got)
		}
	}

	// A password reaches this client through CredentialsFn and nowhere else,
	// so both callers want the same thing.
	c := methodTestClient(t, false, false)
	for _, ask := range bothAsks {
		if c.method().missing(ask) == "" {
			t.Error("a user/pass profile with no CredentialsFn reported nothing missing")
		}
	}
	c.CredentialsFn = func(context.Context) (Credentials, error) { return Credentials{}, nil }
	for _, ask := range bothAsks {
		if got := c.method().missing(ask); got != "" {
			t.Errorf("missing = %q with a CredentialsFn set", got)
		}
	}

	// The assertion has a second way in — the relay and mobile entry points
	// collect it and hand it to ConnectPhase2 — so the preflight must welcome
	// a federated profile Connect refuses.
	s := methodTestClient(t, false, true)
	if got := s.method().missing(missingForAnyEntry); got != "" {
		t.Errorf("the preflight refused a federated profile for want of SAMLTokenFn (%q); "+
			"ConnectPhase2 drives one without it", got)
	}
	if s.method().missing(missingForConnect) == "" {
		t.Error("Connect accepted a federated profile with no SAMLTokenFn, which it cannot drive end to end")
	}
	s.SAMLTokenFn = func(context.Context, SAMLChallenge) (string, error) { return "", nil }
	for _, ask := range bothAsks {
		if got := s.method().missing(ask); got != "" {
			t.Errorf("missing = %q with a SAMLTokenFn set", got)
		}
	}
}

// TestConnectRefusesAFederatedProfileItCannotDrive pins the reachability of
// Connect's own precondition. beginAttempt already refuses everything the
// preflight's question and Connect's agree on, so the guard in Connect can only
// ever fire for the federated method with no SAMLTokenFn.
//
// The discrimination is the stage, not the error text: without the guard this
// profile reaches the dial, and the remote is a closed loopback port precisely
// so that the mutation fails fast and offline instead of resolving a hostname.
func TestConnectRefusesAFederatedProfileItCannotDrive(t *testing.T) {
	p, err := profile.ParseString(fmt.Sprintf(
		"client\nremote 127.0.0.1 %d\nproto tcp-client\n", closedTCPPort(t)))
	if err != nil {
		t.Fatalf("ParseString: %v", err)
	}
	p.CA = testCAPEM(t)
	p.Federated = true

	c := New(p)
	c.EventFn = func(Event) {}
	connErr := c.Connect(context.Background())
	if connErr == nil {
		t.Fatal("Connect drove a federated profile with no SAMLTokenFn to a tunnel")
	}

	var derr *diag.Error
	if !errors.As(connErr, &derr) {
		t.Fatalf("Connect = %v, want a *diag.Error", connErr)
	}
	if derr.Class != diag.ClassConfig || derr.Stage != diag.StageParse {
		t.Errorf("Connect failed with %v at %v, want %v at %v: nothing was presented to a server",
			derr.Class, derr.Stage, diag.ClassConfig, diag.StageParse)
	}
	if !strings.Contains(derr.Error(), "SAMLTokenFn") {
		t.Errorf("the refusal does not name what the caller must set: %v", derr)
	}
	for _, st := range c.Report().Stages {
		if st.Stage == diag.StageDial {
			t.Fatal("a profile refused before a socket is opened reached the dial")
		}
	}
}

// TestSetRelayPhase2PicksUpAtTheSecondExchange covers an app that ran the
// browser flow elsewhere and handed this client the result over a relay. It has
// to arrive at exactly what a first exchange would have left behind — the state
// id, the backend address, a method that speaks AWS's framing, and the mark
// that says an exchange has happened — because the second exchange reads all
// four and nothing else fills them in.
func TestSetRelayPhase2PicksUpAtTheSecondExchange(t *testing.T) {
	c := methodTestClient(t, false, true)
	c.auth = nil // the relay entry point runs before anything has set a method

	c.SetRelayPhase2("52.1.2.3", "state-from-the-relay")

	c.mu.Lock()
	st, ip, session, reply := c.state, c.backendIP, c.samlSession, c.reply
	c.mu.Unlock()

	if st != stateConnecting {
		t.Errorf("state = %v, want stateConnecting: the second exchange refuses to start elsewhere", st)
	}
	if ip != "52.1.2.3" {
		t.Errorf("backendIP = %q, want the backend the relay named", ip)
	}
	if session == nil || session.StateID != "state-from-the-relay" {
		t.Errorf("samlSession = %+v, want the relayed state id", session)
	}
	if reply != replySecondExchange {
		t.Errorf("reply = %v, want %v", reply, replySecondExchange)
	}
	if got := c.method().framing(); got != keymethod2.FramingAWSLargeToken {
		t.Errorf("framing = %v, want %v", got, keymethod2.FramingAWSLargeToken)
	}
	// And it is not that assignment which saves it: a method nobody set
	// still comes out of the profile.
	c.mu.Lock()
	c.auth = nil
	c.mu.Unlock()
	if got := c.method().framing(); got != keymethod2.FramingAWSLargeToken {
		t.Errorf("framing with no method set = %v, want %v", got, keymethod2.FramingAWSLargeToken)
	}

	// The two public accessors are the caller's view of the same seed: the
	// backend is readable, and the tunnel address is not invented before a
	// tunnel exists.
	if ip := c.Phase1IP(); ip != "52.1.2.3" {
		t.Errorf("Phase1IP = %q, want the backend the relay named", ip)
	}
	if ip := c.LocalIP(); ip != "" {
		t.Errorf("LocalIP = %q, want empty until the second exchange has pushed one", ip)
	}

	// And the second exchange starts from it, with no SAMLTokenFn anywhere:
	// the relay delivered the assertion, so demanding the browser hook here
	// would refuse a connection that has everything it needs.
	if err := c.beginBringUp("a-relayed-assertion"); err != nil {
		t.Fatalf("beginBringUp after SetRelayPhase2: %v", err)
	}
	c.mu.Lock()
	cached := c.cachedStateID
	c.mu.Unlock()
	if cached != "state-from-the-relay" {
		t.Errorf("cachedStateID = %q, want the relayed state id kept for a reconnect", cached)
	}
}

// TestCapturedUserPassResumptionCarriesTheCallback pins the one thing a
// captured resumption knows that cannot be recovered from it afterwards:
// whether a CredentialsFn was set when the loop started.
//
// mayAsk is the whole of the second-chance policy. Captured false, a reconnect
// after a mistyped password fails where asking again would have fixed it;
// captured true with no callback behind it, the loop re-presents a password
// nothing can correct, which is how an account gets locked.
func TestCapturedUserPassResumptionCarriesTheCallback(t *testing.T) {
	refused := errors.New("authentication rejected")

	t.Run("a callback behind the password is worth one more presentation", func(t *testing.T) {
		c := methodTestClient(t, false, false)
		c.CredentialsFn = stubCredentials("u", "p")

		res := c.method().captureResumption()
		if _, ok := res.(*userPassResumption); !ok {
			t.Fatalf("resumption = %T, want the user/pass one", res)
		}
		if retry, out := res.rejected(c, refused); !retry || out != nil {
			t.Errorf("rejected = (%t, %v), want (true, nil): the callback may answer differently",
				retry, out)
		}
	})

	t.Run("without one the rejection is final", func(t *testing.T) {
		// Connect refuses this profile outright, but Reconnect can be driven
		// on a client whose credentials arrived by another route — the mobile
		// binding's SetCredentials — and the policy has to hold there too.
		c := methodTestClient(t, false, false)
		c.mu.Lock()
		c.creds, c.credsCached = Credentials{Username: "u", Password: "p"}, true
		c.mu.Unlock()

		res := c.method().captureResumption()
		retry, out := res.rejected(c, refused)
		if retry {
			t.Error("retried with nothing that could answer differently")
		}
		if !errors.Is(out, refused) {
			t.Errorf("out = %v, want the rejection itself", out)
		}
	})
}

// TestAnAWSEndpointIsFederatedWithoutTheDirective covers the profile the
// hostname rule exists for: an AWS Client VPN config that has lost its
// auth-federate line to hand-editing. Read from the file alone it carries no
// credential of any kind and falls back to user/pass, which would present a
// password to a server that wants an assertion — and would be refused before
// dialling for want of a CredentialsFn, an error naming the wrong thing.
func TestAnAWSEndpointIsFederatedWithoutTheDirective(t *testing.T) {
	p, err := profile.ParseString(
		"client\nproto udp\nremote cvpn-endpoint-0123456789abcdef.prod.clientvpn.eu-central-1.amazonaws.com 443\n")
	if err != nil {
		t.Fatalf("ParseString: %v", err)
	}
	p.CA = testCAPEM(t)
	if p.Federated {
		t.Fatal("the profile says auth-federate after all; this test proves nothing")
	}
	if got := p.AuthFlow(); got != profile.FlowUserPass {
		t.Fatalf("AuthFlow = %v, want %v: the parser reads the file and nothing else", got, profile.FlowUserPass)
	}

	c := New(p)
	if _, ok := c.method().(samlMethod); !ok {
		t.Errorf("method = %T, want samlMethod", c.method())
	}
	// And it is not refused for the credential it does not need.
	if missing := c.method().missing(missingForAnyEntry); missing != "" {
		t.Errorf("missing = %q, want none: the assertion is the credential", missing)
	}
	if err := c.beginAttempt(); err != nil {
		t.Errorf("beginAttempt: %v", err)
	}
}

// ---- the credential seam --------------------------------------------------

// sentinelUser and sentinelPassword are the values every leak test below
// scans for. They are deliberately unlike anything the protocol produces, so a
// substring hit anywhere in a report or an error is unambiguous.
const (
	sentinelUser     = "credential-username-sentinel"
	sentinelPassword = "credential-password-sentinel"
)

// TestCredentialFlowTable is the credential contract, restated as a test: one
// row per (flow, exchange) pair, and the AWS literals in the AWS rows only.
func TestCredentialFlowTable(t *testing.T) {
	const (
		stateID   = "state-abcdef"
		assertion = "a-saml-assertion"
	)
	crv1 := crv1Material{stateID: stateID, assertion: assertion}

	tests := []struct {
		name       string
		directives string
		certAuth   bool
		forceSAML  bool
		exchange   authExchange
		crv1       crv1Material
		authToken  string
		wantUser   string
		wantPass   string
	}{
		{
			name:     "cert-only sends nothing",
			certAuth: true,
			exchange: authInitial,
			wantUser: "", wantPass: "",
		},
		{
			name:       "user-pass sends what CredentialsFn returned",
			directives: "auth-user-pass\n",
			exchange:   authInitial,
			wantUser:   sentinelUser, wantPass: sentinelPassword,
		},
		{
			name:       "a certificate does not silence a password",
			directives: "auth-user-pass\n",
			certAuth:   true,
			exchange:   authInitial,
			wantUser:   sentinelUser, wantPass: sentinelPassword,
		},
		{
			name:      "AWS phase 1 sends the ACS prompt",
			forceSAML: true,
			exchange:  authInitial,
			wantUser:  "N/A", wantPass: "ACS::35001",
		},
		{
			name:      "AWS phase 2 sends the CRV1 password",
			forceSAML: true,
			exchange:  authCRV1Phase2,
			crv1:      crv1,
			wantUser:  "N/A", wantPass: "CRV1::" + stateID + "::" + assertion,
		},
		{
			// The pushed auth-token outranks the cached assertion: it is the
			// server's own session handle, and unlike an assertion it cannot
			// have expired underneath us.
			name:      "an AWS rekey prefers the pushed auth-token",
			forceSAML: true,
			exchange:  authRekey,
			crv1:      crv1,
			authToken: "server-session-token",
			wantUser:  "N/A", wantPass: "server-session-token",
		},
		{
			name:      "an AWS rekey with no auth-token reuses the cached CRV1 password",
			forceSAML: true,
			exchange:  authRekey,
			crv1:      crv1,
			wantUser:  "N/A", wantPass: "CRV1::" + stateID + "::" + assertion,
		},
		{
			name:       "a cert-only rekey with no auth-token sends nothing",
			certAuth:   true,
			exchange:   authRekey,
			wantUser:   "",
			wantPass:   "",
			directives: "",
		},
		{
			name:       "a user-pass rekey with no auth-token repeats the password",
			directives: "auth-user-pass\n",
			exchange:   authRekey,
			wantUser:   sentinelUser, wantPass: sentinelPassword,
		},
		{
			// The initial-exchange row above says a certificate does not
			// silence a password; this says a renegotiation does not either.
			name:       "a rekey with a certificate still repeats the password",
			directives: "auth-user-pass\n",
			certAuth:   true,
			exchange:   authRekey,
			wantUser:   sentinelUser, wantPass: sentinelPassword,
		},
		{
			// The token replaces the password and nothing else. OpenVPN 2.6
			// mixes the username into the token's HMAC when it issues one
			// (auth_token.c:244-256) and recomputes it over what comes back
			// (:300-310), so a placeholder here fails check_hmac_token and the
			// server refuses the token.
			name:       "a user-pass rekey keeps its username beside the auth-token",
			directives: "auth-user-pass\n",
			exchange:   authRekey,
			authToken:  "server-session-token",
			wantUser:   sentinelUser, wantPass: "server-session-token",
		},
		{
			// openvpn3 stores a pushed token only when it has a credentials
			// object to put it in (cliproto.hpp:613); a cert-only profile has
			// none, so the reference presents nothing on renegotiation.
			name:      "a cert-only rekey presents no auth-token",
			certAuth:  true,
			exchange:  authRekey,
			authToken: "server-session-token",
			wantUser:  "", wantPass: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := credentialTestProfile(t, tc.directives, tc.certAuth)
			p.Federated = tc.forceSAML

			c := New(p)
			c.CredentialsFn = stubCredentials(sentinelUser, sentinelPassword)
			if tc.authToken != "" {
				c.pushOpts = &routing.PushOptions{AuthToken: tc.authToken}
			}

			// The CRV1 material is where the method looks for it: on the client,
			// cached by the phase-1 exchange that collected it.
			c.cachedStateID, c.cachedSAMLToken = tc.crv1.stateID, tc.crv1.assertion

			creds, err := c.authCredentials(context.Background(), tc.exchange)
			if err != nil {
				t.Fatalf("authCredentials: %v", err)
			}
			if creds.Username != tc.wantUser {
				t.Errorf("username = %q, want %q", creds.Username, tc.wantUser)
			}
			if creds.Password != tc.wantPass {
				t.Errorf("password = %q, want %q", creds.Password, tc.wantPass)
			}
		})
	}
}

// TestCredentialsFnCalledAtMostOncePerAttempt pins the contract's "at most
// once": the callback may put a prompt in front of the user, and a rekey four
// hours in must not put a second one there.
func TestCredentialsFnCalledAtMostOncePerAttempt(t *testing.T) {
	c := New(credentialTestProfile(t, "auth-user-pass\n", false))

	var calls int
	c.CredentialsFn = func(context.Context) (Credentials, error) {
		calls++
		return Credentials{Username: sentinelUser, Password: sentinelPassword}, nil
	}

	for _, ex := range []authExchange{authInitial, authRekey, authRekey} {
		if _, err := c.authCredentials(context.Background(), ex); err != nil {
			t.Fatalf("authCredentials: %v", err)
		}
	}
	if calls != 1 {
		t.Errorf("CredentialsFn called %d times, want 1", calls)
	}
}

// TestCredentialsFnErrorPropagates checks that a callback that cannot answer —
// a cancelled prompt, a locked keychain — ends the exchange rather than
// sending blanks that a server would read as a wrong password.
func TestCredentialsFnErrorPropagates(t *testing.T) {
	sentinel := errors.New("the user closed the prompt")
	c := New(credentialTestProfile(t, "auth-user-pass\n", false))
	c.CredentialsFn = func(context.Context) (Credentials, error) {
		return Credentials{Username: sentinelUser, Password: sentinelPassword}, sentinel
	}

	creds, err := c.authCredentials(context.Background(), authInitial)
	if !errors.Is(err, sentinel) {
		t.Fatalf("error = %v, want it to wrap the callback's own", err)
	}
	if creds != (Credentials{}) {
		t.Errorf("credentials = %+v, want the zero value on failure", creds)
	}
	// A callback that returns both a value and an error must not have its
	// value leak into the message.
	if strings.Contains(err.Error(), sentinelPassword) {
		t.Errorf("the error carries the password: %v", err)
	}
}

// TestMissingCredentialsFnIsConfigAtParse covers a profile that needs a
// password and has no way to get one. It fails before dialing, because dialing
// cannot help, and it fails as ClassConfig: no server rejected anything.
func TestMissingCredentialsFnIsConfigAtParse(t *testing.T) {
	for _, directives := range []string{"", "auth-user-pass\n"} {
		t.Run(directives, func(t *testing.T) {
			p := credentialTestProfile(t, directives, false)
			if got := p.AuthFlow(); got != profile.FlowUserPass {
				t.Fatalf("AuthFlow = %v, want FlowUserPass", got)
			}
			c := New(p)

			err := c.Preflight()
			var derr *diag.Error
			if !errors.As(err, &derr) {
				t.Fatalf("error is not a *diag.Error: %T: %v", err, err)
			}
			if derr.Class != diag.ClassConfig || derr.Stage != diag.StageParse {
				t.Fatalf("got %s at %s, want config at parse", derr.Class, derr.Stage)
			}

			rep := c.Report()
			if got := stageNames(rep); !equalStrings(got, []string{"parse"}) {
				t.Errorf("stages = %v, want [parse]: the attempt must not dial", got)
			}
		})
	}
}

// TestCertOnlyProfileIsNotRefusedForCredentials is the other side of the gate:
// the shape with the most to lose must still get past StageParse without a
// CredentialsFn, because it never needed one.
func TestCertOnlyProfileIsNotRefusedForCredentials(t *testing.T) {
	c := New(credentialTestProfile(t, "", true))
	if err := c.Preflight(); err != nil {
		t.Fatalf("Preflight refused a cert-only profile: %v", err)
	}
	creds, err := c.authCredentials(context.Background(), authInitial)
	if err != nil {
		t.Fatalf("authCredentials: %v", err)
	}
	if creds != (Credentials{}) {
		t.Errorf("cert-only credentials = %+v, want empty", creds)
	}
}

// TestCredentialsAreRegisteredBeforeUse is the leak scan. It registers the
// credentials by the only route the client has — asking for them — then pushes
// them through every free-text field a report can carry and checks that nothing
// the report or the error path can emit contains either value. The registration
// happens inside authCredentials rather than at the call sites, so a caller
// cannot send a credential the report has not been told to scrub.
func TestCredentialsAreRegisteredBeforeUse(t *testing.T) {
	c := New(credentialTestProfile(t, "auth-user-pass\n", false))
	c.CredentialsFn = stubCredentials(sentinelUser, sentinelPassword)

	c.enterStage(diag.StageAuth)
	creds, err := c.authCredentials(context.Background(), authInitial)
	if err != nil {
		t.Fatalf("authCredentials: %v", err)
	}

	// Everything below is a place a credential can escape through: the
	// server's own options echo, the raw push reply, and the error chain of
	// the stage that failed.
	c.recordAdvertised(creds.Username, creds.Password)
	c.recordServerOpts("V4,dev-type tun,user " + sentinelUser + ",token " + sentinelPassword)
	c.recordPush("PUSH_REPLY,auth-token "+sentinelPassword,
		&routing.PushOptions{AuthToken: sentinelPassword}, 0)
	_ = c.failStage(diag.ClassAuth, diag.StageAuth,
		errors.New("server rejected "+sentinelUser+"/"+sentinelPassword), "auth")

	blob, err := json.Marshal(c.Report().Redacted())
	if err != nil {
		t.Fatalf("marshal redacted report: %v", err)
	}
	for _, secret := range []string{sentinelUser, sentinelPassword} {
		if bytes.Contains(blob, []byte(secret)) {
			t.Errorf("redacted report leaked %q: %s", secret, blob)
		}
	}
	if !bytes.Contains(blob, []byte(diag.RedactedPlaceholder)) {
		t.Fatalf("nothing was scrubbed at all: %s", blob)
	}

	// The error chain is where credentials most often leak, so check it on its
	// own rather than trusting the whole-blob scan. The unredacted report is
	// deliberately not checked: it is the form that still holds the values,
	// which is why Redacted exists and why SessionReport does not implement
	// json.Marshaler.
	for _, line := range c.Report().Redacted().Outcome.ErrorChain {
		for _, secret := range []string{sentinelUser, sentinelPassword} {
			if strings.Contains(line, secret) {
				t.Errorf("redacted error chain leaked %q: %q", secret, line)
			}
		}
	}
}

// TestAdvertisedRegistersOnlyRealSecrets pins the distinction recordAdvertised
// draws. diag scrubs by substring and has no minimum length, so registering the
// AWS flow's three-character "N/A" would blank it wherever it legitimately
// occurs — including in a server options string, where "auth N/A" is the digest
// the peer chose. A genuine credential has to disappear from every field it
// reached, and without taking the placeholder beside it.
func TestAdvertisedRegistersOnlyRealSecrets(t *testing.T) {
	const serverOpts = "V4,dev-type tun,auth N/A,cipher AES-256-GCM"

	t.Run("the AWS placeholder is not registered", func(t *testing.T) {
		p := credentialTestProfile(t, "", false)
		p.Federated = true
		c := New(p)

		creds, err := c.authCredentials(context.Background(), authInitial)
		if err != nil {
			t.Fatalf("authCredentials: %v", err)
		}
		if creds.Username != awsPlaceholderUsername || creds.Password != awsACSPassword {
			t.Fatalf("credentials = %q/%q, want the AWS placeholder pair",
				creds.Username, creds.Password)
		}
		c.recordAdvertised(creds.Username, creds.Password)
		c.recordServerOpts(serverOpts)

		red := c.Report().Redacted()
		if red.ServerOpts != serverOpts {
			t.Errorf("ServerOpts was over-redacted:\n got %q\nwant %q", red.ServerOpts, serverOpts)
		}
		// The credential fields themselves are blanked whether or not the
		// value was registered, so declining to register discloses nothing.
		if red.Credentials.Username != "" {
			t.Errorf("the report recorded a protocol placeholder as a user name: %q",
				red.Credentials.Username)
		}
		if red.Credentials.Password == awsACSPassword {
			t.Error("the credential field was not blanked")
		}
	})

	t.Run("a real credential is scrubbed and the placeholder beside it survives", func(t *testing.T) {
		const secret = "CRV1::state-abcdef::a-real-saml-token"
		c := New(credentialTestProfile(t, "", true))
		c.recordAdvertised("", secret)
		c.recordServerOpts(serverOpts + ",token " + secret)

		red := c.Report().Redacted()
		if strings.Contains(red.ServerOpts, secret) {
			t.Errorf("credential survived redaction: %q", red.ServerOpts)
		}
		if !strings.Contains(red.ServerOpts, "auth N/A") {
			t.Errorf("placeholder over-redacted alongside it: %q", red.ServerOpts)
		}
	})
}

// TestClearCredentialsDropsTheCallbackAnswer checks that an explicit
// disconnect forgets what CredentialsFn returned, so the next attempt asks
// again rather than replaying a password the caller may since have changed.
func TestClearCredentialsDropsTheCallbackAnswer(t *testing.T) {
	c := New(credentialTestProfile(t, "auth-user-pass\n", false))

	var calls int
	c.CredentialsFn = func(context.Context) (Credentials, error) {
		calls++
		return Credentials{Username: sentinelUser, Password: sentinelPassword}, nil
	}

	if _, err := c.authCredentials(context.Background(), authInitial); err != nil {
		t.Fatalf("authCredentials: %v", err)
	}
	c.mu.Lock()
	c.clearCredentialsLocked()
	c.mu.Unlock()
	if _, err := c.authCredentials(context.Background(), authInitial); err != nil {
		t.Fatalf("authCredentials after clear: %v", err)
	}
	if calls != 2 {
		t.Errorf("CredentialsFn called %d times, want 2: the answer must not survive a clear", calls)
	}
}
