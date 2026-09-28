// SPDX-License-Identifier: LGPL-2.1-or-later

// The reconnect loop: that it makes attempts rather than one long effort, that
// each attempt keeps the report explaining it, and that whether there is a next
// attempt is decided from the class of the failure rather than from a count.
//
// The live half — a link broken underneath a tunnel and repaired — lives in
// netstack, because breaking a link needs a server to break.

package vpn

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/buengese/go-openvpn/diag"
	"github.com/buengese/go-openvpn/internal/control"
	"github.com/buengese/go-openvpn/profile"
)

// unreachableClient returns a client whose only remote is a closed loopback
// port, so every attempt fails at StageDial with diag.ClassNetwork and none of
// them touches anything outside the process. The profile carries a CA because
// a profile without one never dials at all, and a CredentialsFn because a
// FlowUserPass profile without one is refused at StageParse.
func unreachableClient(t *testing.T, credsCalls *int) *Client {
	t.Helper()
	p, err := profile.ParseString(fmt.Sprintf(
		"client\nproto tcp-client\nremote 127.0.0.1 %d\nauth-user-pass\n", closedTCPPort(t)))
	if err != nil {
		t.Fatalf("ParseString: %v", err)
	}
	p.CA = testCAPEM(t)
	c := New(p)
	c.EventFn = func(Event) {}
	c.CredentialsFn = func(context.Context) (Credentials, error) {
		if credsCalls != nil {
			*credsCalls++
		}
		return Credentials{Username: "u", Password: "p"}, nil
	}
	return c
}

// chachaClient returns a client whose profile asks for a cipher this
// implementation does not have, which is a diag.SeverityFatal capability gap
// and therefore a StageParse refusal in the default preflight mode.
func chachaClient(t *testing.T) *Client {
	t.Helper()
	p, err := profile.ParseString(
		"client\nproto tcp-client\nremote 127.0.0.1 1194\ncipher CHACHA20-POLY1305\n")
	if err != nil {
		t.Fatalf("ParseString: %v", err)
	}
	p.CA = testCAPEM(t)
	c := New(p)
	c.EventFn = func(Event) {}
	c.CredentialsFn = func(context.Context) (Credentials, error) {
		return Credentials{}, errors.New("must not be asked: the attempt never dials")
	}
	return c
}

// TestReconnectFatalGapMakesExactlyOneAttempt is the acceptance property for
// the half of the retry policy that says no: a profile the client cannot
// honour will not become honourable by being dialed again, so an unsupported
// cipher costs one attempt rather than MaxReconnects of them.
func TestReconnectFatalGapMakesExactlyOneAttempt(t *testing.T) {
	c := chachaClient(t)

	err := c.Reconnect(context.Background())
	if err == nil {
		t.Fatal("Reconnect succeeded against an unsupported cipher")
	}
	derr := diag.AsError(err)
	if derr == nil || derr.Class != diag.ClassUnsupported || derr.Stage != diag.StageParse {
		t.Fatalf("Reconnect error = %v, want unsupported at parse", err)
	}

	attempts := c.Attempts()
	if len(attempts) != 1 {
		t.Fatalf("attempts = %d, want exactly 1: %s", len(attempts), attemptSummary(attempts))
	}
	if got := attempts[0].Report.Outcome.Class; got != diag.ClassUnsupported {
		t.Errorf("attempt 1 outcome class = %s, want unsupported", got)
	}
	if got := attempts[0].Report.Outcome.Feature; got != "cipher" {
		t.Errorf("attempt 1 outcome feature = %q, want the directive that was refused", got)
	}
	// Nothing was dialed, and the report is what says so.
	for _, s := range attempts[0].Report.Stages {
		if s.Stage != diag.StageParse {
			t.Errorf("attempt 1 reached %s: a fatal gap must not open a socket", s.Stage)
		}
	}
}

// TestReconnectKeepsOneReportPerAttempt: every attempt keeps its own report,
// and the loop does not overwrite the one belonging to the attempt that failed.
// Two attempts is the smallest case in which a shared report is visible.
func TestReconnectKeepsOneReportPerAttempt(t *testing.T) {
	c := unreachableClient(t, nil)
	c.MaxReconnects = 2

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := c.Reconnect(ctx); err == nil {
		t.Fatal("Reconnect succeeded against a closed port")
	}

	attempts := c.Attempts()
	if len(attempts) != 2 {
		t.Fatalf("attempts = %d, want 2: %s", len(attempts), attemptSummary(attempts))
	}
	for i, a := range attempts {
		if a.N != i+1 {
			t.Errorf("attempts[%d].N = %d, want %d", i, a.N, i+1)
		}
		if a.StartedAt.IsZero() {
			t.Errorf("attempt %d has no start time", a.N)
		}
		if a.Report == nil {
			t.Fatalf("attempt %d has no report", a.N)
		}
		if a.Report.Outcome.Class != diag.ClassNetwork || a.Report.Outcome.Stage != diag.StageDial {
			t.Errorf("attempt %d outcome = %s at %s, want network at dial",
				a.N, a.Report.Outcome.Class, a.Report.Outcome.Stage)
		}
		if len(a.Report.Outcome.ErrorChain) == 0 {
			t.Errorf("attempt %d kept no error chain: the reason it failed is the point", a.N)
		}
	}
	// Independent reports, not two views of one. Sharing the backing report
	// is how a failed attempt's outcome disappears.
	if attempts[0].Report == attempts[1].Report {
		t.Fatal("both attempts returned the same report pointer")
	}
	if attempts[1].StartedAt.Before(attempts[0].StartedAt) {
		t.Error("attempts are not in order")
	}

	// The compatibility property: Report keeps answering for the most recent
	// attempt, so everything reading it today reads the same thing.
	rep := c.Report()
	last := attempts[len(attempts)-1].Report
	if rep.Outcome.Class != last.Outcome.Class || rep.Outcome.Stage != last.Outcome.Stage {
		t.Errorf("Report outcome = %s at %s, want the last attempt's %s at %s",
			rep.Outcome.Class, rep.Outcome.Stage, last.Outcome.Class, last.Outcome.Stage)
	}
	if len(rep.Stages) != len(last.Stages) {
		t.Errorf("Report has %d stages, the last attempt %d", len(rep.Stages), len(last.Stages))
	}
}

// TestPreflightThenConnectIsOneAttempt pins the idempotence of the StageParse
// boundary, and only that: beginAttempt replays the answer it already gave, so
// the second entry point does not open a second Attempt slot.
func TestPreflightThenConnectIsOneAttempt(t *testing.T) {
	c := chachaClient(t)

	if err := c.Preflight(); err == nil {
		t.Fatal("Preflight accepted an unsupported cipher")
	}
	if err := c.Connect(context.Background()); err == nil {
		t.Fatal("Connect accepted an unsupported cipher")
	}
	if got := len(c.Attempts()); got != 1 {
		t.Fatalf("attempts after Preflight+Connect = %d, want 1", got)
	}
}

// TestAttemptsOutsideAReconnectReplaceTheSequence pins registerAttempt's
// guard, which is what makes Attempts describe the connection the caller is
// asking about rather than every connection this client has ever tried.
// Reconnect's own clearing cannot stand in for it: that runs when a reconnect
// starts, and what this guards is the attempt arriving when none is running —
// exactly the Connect a caller makes after ErrReauthRequired.
func TestAttemptsOutsideAReconnectReplaceTheSequence(t *testing.T) {
	// Nothing here dials, so the profile only has to be one New accepts.
	c := New(credentialTestProfile(t, "", false))

	c.registerAttempt(newSessionRecorder())
	c.registerAttempt(newSessionRecorder())
	if got := c.Attempts(); len(got) != 1 || got[0].N != 1 {
		t.Fatalf("attempts outside a reconnect = %s, want a sequence of one numbered 1",
			attemptSummary(got))
	}

	c.mu.Lock()
	c.reconnecting = true
	c.mu.Unlock()

	c.registerAttempt(newSessionRecorder())
	got := c.Attempts()
	if len(got) != 2 || got[0].N != 1 || got[1].N != 2 {
		t.Fatalf("attempts during a reconnect = %s, want the sequence extended to two",
			attemptSummary(got))
	}
}

// TestRetryClassFollowsTheTaxonomy states the policy as a table: every answer
// is the next action a class implies, read as "would dialing again change
// this".
func TestRetryClassFollowsTheTaxonomy(t *testing.T) {
	for _, tc := range []struct {
		class diag.Class
		retry bool
	}{
		{diag.ClassNetwork, true},
		{diag.ClassTLS, true},
		{diag.ClassConfig, false},
		{diag.ClassUnsupported, false},
		{diag.ClassAuth, false}, // Reconnect decides this one; the table says no.
		{diag.ClassProtocol, false},
		{diag.ClassCrypto, false},
		{diag.ClassLocal, false},
		{diag.ClassServerBusy, true}, // the server itself asked us back
		{diag.ClassPeerClosed, false},
	} {
		if got := retryClass(tc.class); got != tc.retry {
			t.Errorf("retryClass(%s) = %t, want %t", tc.class, got, tc.retry)
		}
	}
}

// TestAttemptMessagesNameTheAttemptAndTheMethod pins the one line a caller
// gets per attempt. It reaches them as an EventLog, which is what a GUI's
// connection log and cmd/cli's output are made of.
//
// It asserts properties and not prose — which attempt the message describes,
// and where a resumed attempt is going — because a test that failed on every
// rewording would be edited to match rather than read.
func TestAttemptMessagesNameTheAttemptAndTheMethod(t *testing.T) {
	token := samlResumption{
		assertion: "a-saml-assertion",
		stateID:   "state-abcdef",
		serverIP:  "192.0.2.1",
		expiry:    time.Now().Add(time.Hour),
	}

	for _, r := range []resumption{redialResumption{}, &userPassResumption{}, token} {
		this, next := r.attemptMessage(42), r.attemptMessage(43)
		if !strings.Contains(this, "42") {
			t.Errorf("%T: attemptMessage(42) = %q, does not say which attempt it describes", r, this)
		}
		if this == next {
			t.Errorf("%T: attempts 42 and 43 read identically: %q", r, this)
		}
	}

	// A resumed second exchange goes to a backend the profile does not name,
	// on a credential with an expiry, and a user reading the log of a failed
	// reconnect needs both.
	msg := token.attemptMessage(1)
	if !strings.Contains(msg, token.serverIP) {
		t.Errorf("attemptMessage = %q, does not name the backend the state id is bound to", msg)
	}
	sooner := token
	sooner.expiry = time.Now().Add(5 * time.Minute)
	if sooner.attemptMessage(1) == msg {
		t.Errorf("an assertion with five minutes left reads the same as one with an hour: %q", msg)
	}
	// And it carries neither of the two secrets it holds. A caller that logs
	// EventLog would otherwise be writing session-bearing material into a file
	// nothing redacts.
	if strings.Contains(msg, token.assertion) || strings.Contains(msg, token.stateID) {
		t.Errorf("attemptMessage = %q, puts the assertion or the state id in a log line", msg)
	}

	// The two are different things to be told. A resumed token announcing
	// itself as a redial would hide the one attempt that opens no browser.
	if (redialResumption{}).attemptMessage(1) == token.attemptMessage(1) {
		t.Error("a redial and a resumed assertion announce themselves identically")
	}
}

// TestReconnectAnnouncesEveryAttemptWithTheMethodsOwnMessage pins the wiring
// between the loop and those messages. It compares against the resumption's own
// output instead of a literal, so a reworded message stays green while a loop
// that stopped emitting, or announced the wrong attempt number, does not.
func TestReconnectAnnouncesEveryAttemptWithTheMethodsOwnMessage(t *testing.T) {
	c := unreachableClient(t, nil)
	c.MaxReconnects = 2

	var mu sync.Mutex
	var logs []string
	// The events arrive on the loop's own goroutine here, but a client emits
	// from the goroutines it starts too, so the collector takes a lock rather
	// than relying on which failure this profile happens to produce.
	c.EventFn = func(e Event) {
		if e.Type != EventLog {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		logs = append(logs, e.Message)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := c.Reconnect(ctx); err == nil {
		t.Fatal("Reconnect succeeded against a closed port")
	}

	mu.Lock()
	defer mu.Unlock()
	for n := 1; n <= c.MaxReconnects; n++ {
		// The user/pass resumption redials, and takes its message from the
		// redial it embeds.
		want := (&userPassResumption{}).attemptMessage(n)
		if !slices.Contains(logs, want) {
			t.Errorf("attempt %d was never announced; want %q, log was:\n%s",
				n, want, strings.Join(logs, "\n"))
		}
	}
}

// TestResumptionUsableIsASAMLQuestion pins where ErrReauthRequired can come
// from. Only the SAML method has resumption state that can expire; a cert-only
// profile still has its certificate and a user/pass profile still has its
// callback, so neither can ever be out of things to try.
func TestResumptionUsableIsASAMLQuestion(t *testing.T) {
	full := samlResumption{
		assertion: "assertion",
		stateID:   "state",
		serverIP:  "192.0.2.1",
		expiry:    time.Now().Add(time.Hour),
	}
	if err := full.usable(); err != nil {
		t.Errorf("a complete, unexpired SAML resumption is not usable: %v", err)
	}

	expired := full
	expired.expiry = time.Now().Add(-time.Minute)
	if expired.usable() == nil {
		t.Error("an expired assertion is usable")
	}

	marginal := full
	marginal.expiry = time.Now().Add(samlExpiryMargin / 2)
	if marginal.usable() == nil {
		t.Error("an assertion expiring inside the margin is usable: it would be spent for nothing")
	}

	unknownExpiry := full
	unknownExpiry.expiry = time.Time{}
	if unknownExpiry.usable() == nil {
		t.Error("an assertion with no NotOnOrAfter is usable")
	}

	for _, missing := range []samlResumption{
		{stateID: "state", serverIP: "192.0.2.1", expiry: full.expiry},
		{assertion: "assertion", serverIP: "192.0.2.1", expiry: full.expiry},
		{assertion: "assertion", stateID: "state", expiry: full.expiry},
	} {
		if missing.usable() == nil {
			t.Errorf("an incomplete SAML resumption is usable: %+v", missing)
		}
	}
	// And it is ErrReauthRequired specifically: cmd/cli tests for it to know
	// that a browser, and nothing else, is what the session needs next.
	if err := (samlResumption{}).usable(); !errors.Is(err, ErrReauthRequired) {
		t.Errorf("usable() = %v, want ErrReauthRequired", err)
	}

	for _, r := range []resumption{redialResumption{}, &userPassResumption{}} {
		if err := r.usable(); err != nil {
			t.Errorf("%T is not usable: %v — nothing about it can expire", r, err)
		}
	}
}

// TestSeedLockedRestoresWhatAFailedAttemptCleared asserts the seam: a failed
// attempt calls clearCredentialsLocked, which drops the SAML triple and the
// cached password together, and resumption is what carries them across.
// Without it a second attempt goes back to CredentialsFn — a second prompt in
// front of a user whose only problem was a dropped link.
func TestSeedLockedRestoresWhatAFailedAttemptCleared(t *testing.T) {
	t.Run("user/pass carries the credentials", func(t *testing.T) {
		c := unreachableClient(t, nil)
		c.mu.Lock()
		c.creds = Credentials{Username: "u", Password: "p"}
		c.credsCached = true
		c.mu.Unlock()

		res := c.method().captureResumption()
		if _, ok := res.(*userPassResumption); !ok {
			t.Fatalf("resumption = %T, want the user/pass one", res)
		}

		c.mu.Lock()
		c.clearCredentialsLocked() // what a failing attempt does
		if c.credsCached {
			t.Fatal("clearCredentialsLocked left the cache in place")
		}
		res.seedLocked(c)
		got, cached := c.creds, c.credsCached
		c.mu.Unlock()

		if !cached || got.Username != "u" || got.Password != "p" {
			t.Errorf("credentials after seeding = %+v (cached=%t), want the captured pair", got, cached)
		}
	})

	t.Run("AWS carries the assertion, the state id and the IP", func(t *testing.T) {
		c := New(makeAWSFlowProfile(t))
		c.EventFn = func(Event) {}
		c.mu.Lock()
		c.cachedSAMLToken = "assertion"
		c.cachedStateID = "state"
		c.cachedBackendIP = "192.0.2.1"
		c.cachedSAMLExpiry = time.Now().Add(time.Hour)
		c.mu.Unlock()

		res := c.method().captureResumption()
		if err := res.usable(); err != nil {
			t.Fatalf("a freshly cached assertion is not usable: %v", err)
		}

		c.mu.Lock()
		c.clearCredentialsLocked()
		res.seedLocked(c)
		challenge, ip, st := c.samlSession, c.backendIP, c.state
		c.mu.Unlock()

		if challenge == nil || challenge.StateID != "state" {
			t.Errorf("challenge after seeding = %+v, want the cached state id", challenge)
		}
		if ip != "192.0.2.1" {
			t.Errorf("backendIP after seeding = %q, want the cached Phase 1 IP", ip)
		}
		// Phase 2 refuses to start from anywhere else.
		if st != stateConnecting {
			t.Errorf("state after seeding = %v, want stateConnecting", st)
		}
	})
}

// TestReconnectWithoutAnAssertionIsReauthRequired keeps the contract cmd/cli
// depends on: an AWS profile with nothing cached cannot reconnect, and says so
// with the sentinel rather than by failing somewhere the caller has to
// interpret. It must also leave the client able to run a fresh Connect, which
// is what the caller does next.
func TestReconnectWithoutAnAssertionIsReauthRequired(t *testing.T) {
	c := New(makeAWSFlowProfile(t))
	c.EventFn = func(Event) {}

	if err := c.Reconnect(context.Background()); !errors.Is(err, ErrReauthRequired) {
		t.Fatalf("Reconnect = %v, want ErrReauthRequired", err)
	}
	if got := len(c.Attempts()); got != 0 {
		t.Errorf("attempts = %d, want 0: no attempt was possible, so none was made", got)
	}
	c.mu.Lock()
	st := c.state
	c.mu.Unlock()
	if st != stateNew {
		t.Errorf("state after ErrReauthRequired = %v, want stateNew so Connect can run", st)
	}
}

// TestReconnectResumesTheSecondExchangeAgainstTheBackend is the only path on
// which samlResumption.reattempt runs, and it pins that the cached assertion is
// spent without a browser and against the instance the CRV1 state id is bound
// to. An attempt that redialled through Connect would ask for the SAMLTokenFn
// this client does not have, and one that dialled the profile's own remote
// would present the assertion to a server that never heard of the session.
func TestReconnectResumesTheSecondExchangeAgainstTheBackend(t *testing.T) {
	p := makeAWSFlowProfile(t)
	// A closed port, so the attempt fails at the dial instead of hanging, and
	// a remote that is not the backend, so the address it dialed says which of
	// the two it chose.
	port := closedTCPPort(t)
	p.Remote, p.Port = "127.0.0.2", port
	p.Remotes[0].Host, p.Remotes[0].Port = p.Remote, port

	c := New(p)
	c.MaxReconnects = 1

	var mu sync.Mutex
	var states []ClientState
	c.EventFn = func(e Event) {
		if e.Type != EventStateChanged {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		states = append(states, e.State)
	}

	// Everything a resumption carries, and no SAMLTokenFn: an attempt that
	// needs a browser has misunderstood what it is resuming.
	c.mu.Lock()
	c.cachedSAMLToken = "a-saml-assertion"
	c.cachedStateID = "state-abcdef"
	c.cachedBackendIP = "127.0.0.1"
	c.cachedSAMLExpiry = time.Now().Add(time.Hour)
	c.mu.Unlock()

	err := c.Reconnect(context.Background())
	if err == nil {
		t.Fatal("Reconnect succeeded against a closed port")
	}
	if errors.Is(err, ErrReauthRequired) {
		t.Fatalf("Reconnect = %v: an assertion with an hour left was refused before it was tried", err)
	}
	derr := diag.AsError(err)
	if derr == nil || derr.Class != diag.ClassNetwork || derr.Stage != diag.StageDial {
		t.Fatalf("Reconnect = %v, want a network failure at the dial", err)
	}
	if want := fmt.Sprintf("127.0.0.1:%d", port); !strings.Contains(derr.Detail, want) {
		t.Errorf("the attempt reported %q, want a dial of the backend at %s", derr.Detail, want)
	}
	if attempts := c.Attempts(); len(attempts) != 1 {
		t.Errorf("attempts = %d, want the one that was made: %s",
			len(attempts), attemptSummary(attempts))
	}

	mu.Lock()
	defer mu.Unlock()
	// The resumed attempt says it is connecting, because nothing else on this
	// path does: the emit it skips is Connect's, and this path does not go
	// through Connect.
	if !slices.Contains(states, StateConnecting) {
		t.Errorf("states = %v, want StateConnecting: without it a GUI shows no connection in progress", states)
	}
}

// TestRejectedCredentialPolicy pins what each method does when the server
// refuses what it presented. It is the one place the reconnect loop is allowed
// to try again after a rejection, and presenting a refused password a third
// time is how an account gets locked. The states are built here rather than
// captured, so this says what the policy does with a mayAsk and nothing about
// which clients get one.
func TestRejectedCredentialPolicy(t *testing.T) {
	refused := errors.New("authentication rejected")

	t.Run("a certificate is refused for good", func(t *testing.T) {
		retry, out := redialResumption{}.rejected(nil, refused)
		if retry {
			t.Error("retried a refused certificate: the next attempt presents the same one")
		}
		if !errors.Is(out, refused) {
			t.Errorf("out = %v, want the rejection itself", out)
		}
	})

	t.Run("a password from a callback is asked for once more", func(t *testing.T) {
		r := &userPassResumption{
			creds:  Credentials{Username: "u", Password: "wrong"},
			cached: true,
			mayAsk: true,
		}
		retry, out := r.rejected(nil, refused)
		if !retry || out != nil {
			t.Fatalf("rejected = (%t, %v), want (true, nil): the callback may answer differently", retry, out)
		}
		// The cache has to go with it. It is what makes a reconnect silent,
		// and here it is the only thing between the loop and a password the
		// user may have corrected in the meantime.
		if r.cached || r.creds.Password != "" {
			t.Errorf("the refused password survived: %+v (cached=%t)", r.creds, r.cached)
		}

		retry, out = r.rejected(nil, refused)
		if retry {
			t.Error("asked a second time: the callback has now confirmed the credential")
		}
		if !errors.Is(out, refused) {
			t.Errorf("out = %v, want the rejection itself", out)
		}
	})

	t.Run("a password with no callback behind it is refused for good", func(t *testing.T) {
		r := &userPassResumption{creds: Credentials{Password: "p"}, cached: true}
		if retry, _ := r.rejected(nil, refused); retry {
			t.Error("retried with nothing that could answer differently")
		}
	})

	t.Run("a refused assertion needs a browser", func(t *testing.T) {
		c := New(makeAWSFlowProfile(t))
		c.EventFn = func(Event) {}

		retry, out := samlResumption{}.rejected(c, refused)
		if retry {
			t.Error("retried a refused assertion: it is bound to the exchange that obtained it")
		}
		if !errors.Is(out, ErrReauthRequired) {
			t.Errorf("out = %v, want ErrReauthRequired", out)
		}
		// And the client is left where Connect starts, because running it
		// again is exactly what the caller does next.
		c.mu.Lock()
		st := c.state
		c.mu.Unlock()
		if st != stateNew {
			t.Errorf("state = %v, want stateNew so Connect can run", st)
		}
	})
}

// makeAWSFlowProfile returns a profile the flow detector reads as AWS SSO
// without needing a resolvable amazonaws.com hostname.
func makeAWSFlowProfile(t *testing.T) *profile.Profile {
	t.Helper()
	p, err := profile.ParseString("client\nproto tcp-client\nremote 127.0.0.1 443\n")
	if err != nil {
		t.Fatalf("ParseString: %v", err)
	}
	p.CA = testCAPEM(t)
	p.Federated = true
	return p
}

// attemptSummary renders a sequence of attempts for a failure message, so a
// wrong count says what the attempts were rather than only how many.
func attemptSummary(attempts []Attempt) string {
	if len(attempts) == 0 {
		return "(none)"
	}
	out := ""
	for _, a := range attempts {
		if out != "" {
			out += ", "
		}
		out += fmt.Sprintf("#%d %s at %s", a.N, a.Report.Outcome.Class, a.Report.Outcome.Stage)
	}
	return out
}

// TestReconnectStopsOnACancelledContextDuringTheBackoff pins the backoff
// select's ctx.Done arm — the one thing standing between an unlimited reconnect
// loop and a goroutine that never returns.
//
// Reaching the backoff is the whole design here: unreachableClient fails at
// StageDial with ClassNetwork, which is retryable, so the loop goes on to wait,
// and it fails in microseconds, so the wait is reached long before the context
// expires. A profile refused at StageParse never reaches the backoff at all.
//
// The unlimited row carries the timing assertion because it is the only one
// that can: with a limit the loop has a second way to terminate.
// reconnectBackoffBase is one second, the context expires at 100 ms, and the
// bound is 500 ms — half the shortest backoff.
func TestReconnectStopsOnACancelledContextDuringTheBackoff(t *testing.T) {
	for _, tc := range []struct {
		name          string
		maxReconnects int
		bound         time.Duration
	}{
		{"with an attempt limit", 1, 0},
		{"unlimited", 0, 500 * time.Millisecond},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := unreachableClient(t, nil)
			c.MaxReconnects = tc.maxReconnects

			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()

			// In a goroutine, so that a loop which ignores ctx.Done fails here
			// in milliseconds rather than by running until the test binary's own
			// timeout: without the arm an unlimited loop retries for ever, so the
			// synchronous form of this test would hang rather than fail.
			done := make(chan error, 1)
			go func() { done <- c.Reconnect(ctx) }()

			bound := tc.bound
			if bound == 0 {
				bound = 5 * time.Second // the limited row ends by its limit
			}
			var err error
			select {
			case err = <-done:
			case <-time.After(bound):
				t.Fatalf("Reconnect had not returned %s after the context expired; "+
					"with an unlimited loop that means it is sitting out a %s backoff "+
					"instead of leaving on ctx.Done", bound, reconnectBackoffBase)
			}

			if err == nil {
				t.Fatal("Reconnect returned nil for a context that expired")
			}
			if tc.bound == 0 {
				return
			}
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Errorf("Reconnect = %v, want the context's own error: the loop "+
					"gave up for some other reason and the backoff arm is unproven", err)
			}
		})
	}
}

// ---- what the loop reads off a failed attempt -----------------------------

// TestIsCredentialsRejected pins which control messages mean "the server
// refused what we sent" rather than "the exchange went wrong somewhere else",
// because only the first is worth asking the user for a fresh assertion over.
func TestIsCredentialsRejected(t *testing.T) {
	for _, kind := range []control.MsgKind{control.MsgKindAuthFailed, control.MsgKindAuthFailedCRV1} {
		if !isCredentialsRejected(&control.Message{Kind: kind}) {
			t.Errorf("kind %s was not classified as a credential rejection", kind)
		}
	}
	if isCredentialsRejected(&control.Message{Kind: control.MsgKindPushReply}) {
		t.Error("PUSH_REPLY was classified as a credential rejection")
	}
	if isCredentialsRejected(nil) {
		t.Error("nil control message was classified as a credential rejection")
	}
}

// TestRequestedBackoffReadsWhatTheServerAsked covers the plumbing between
// failPushReply, which types a busy server's refusal with the wait it asked for,
// and this loop: the wait has to survive the error chain that carries it here,
// and nothing else may claim to have named one.
func TestRequestedBackoffReadsWhatTheServerAsked(t *testing.T) {
	busy := &diag.Error{Class: diag.ClassServerBusy, Stage: diag.StagePush, RetryAfter: 45 * time.Second}
	if got := requestedBackoff(fmt.Errorf("wrapped: %w", busy)); got != 45*time.Second {
		t.Errorf("requestedBackoff = %s, want 45s — through a wrapped error", got)
	}
	if got := requestedBackoff(errors.New("no class at all")); got != 0 {
		t.Errorf("requestedBackoff = %s on an untyped error, want 0", got)
	}
	if got := requestedBackoff(nil); got != 0 {
		t.Errorf("requestedBackoff = %s on nil, want 0", got)
	}
}
