package vpn

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/openlawsvpn/go-openlawsvpn/diag"
	"github.com/openlawsvpn/go-openlawsvpn/internal/compress"
	"github.com/openlawsvpn/go-openlawsvpn/internal/control"
	"github.com/openlawsvpn/go-openlawsvpn/internal/datachannel"
	"github.com/openlawsvpn/go-openlawsvpn/profile"
	"github.com/openlawsvpn/go-openlawsvpn/routing"
)

// TestConnectUnreachableEndpointIsNetworkAtDial pins that an unreachable
// endpoint fails as a *diag.Error of ClassNetwork at StageDial, and that the
// report says the same.
func TestConnectUnreachableEndpointIsNetworkAtDial(t *testing.T) {
	c := New(&profile.Profile{
		Remote: "127.0.0.1",
		Port:   closedTCPPort(t),
		Proto:  profile.ProtoTCP,
		CA:     testCAPEM(t),
	})
	// A profile with no client certificate is FlowUserPass, and a FlowUserPass
	// profile with no CredentialsFn stops at StageParse before it ever dials.
	// The failure under test is the dial, so give it something to present.
	c.CredentialsFn = stubCredentials("user", "pass")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := c.Connect(ctx)
	if err == nil {
		t.Fatal("expected Connect to fail against a closed port")
	}

	var derr *diag.Error
	if !errors.As(err, &derr) {
		t.Fatalf("error is not a *diag.Error: %T: %v", err, err)
	}
	if derr.Class != diag.ClassNetwork {
		t.Errorf("class: got %s, want %s", derr.Class, diag.ClassNetwork)
	}
	if derr.Stage != diag.StageDial {
		t.Errorf("stage: got %s, want %s", derr.Stage, diag.StageDial)
	}

	rep := c.Report()
	if rep == nil {
		t.Fatal("Report returned nil after a failed Connect")
	}
	if rep.Outcome.Succeeded {
		t.Error("outcome reports success after a failed Connect")
	}
	if rep.Outcome.Class != diag.ClassNetwork || rep.Outcome.Stage != diag.StageDial {
		t.Errorf("outcome: got %s at %s, want network at dial",
			rep.Outcome.Class, rep.Outcome.Stage)
	}
	if len(rep.Outcome.ErrorChain) == 0 {
		t.Error("outcome carries no error chain")
	}
	// The attempt must have passed through parse and stopped in dial.
	if got := stageNames(rep); !equalStrings(got, []string{"parse", "dial"}) {
		t.Errorf("stages: got %v, want [parse dial]", got)
	}
	if rep.Stages[0].Duration == 0 {
		t.Error("parse stage has no duration but the attempt got past it")
	}
	if rep.Stages[len(rep.Stages)-1].Err == "" {
		t.Error("the failing stage records no error")
	}
	if rep.Endpoint.Host != "127.0.0.1" || rep.Endpoint.Proto != "tcp" {
		t.Errorf("endpoint: got %+v", rep.Endpoint)
	}
	if rep.Profile.Fingerprint == "" {
		t.Error("profile fingerprint is empty")
	}
	t.Logf("outcome: %s at %s; chain=%v", rep.Outcome.Class, rep.Outcome.Stage, rep.Outcome.ErrorChain)
}

// TestReportValidBeforeConnect verifies that Report is usable on a fresh
// client, so a caller never has to guard against a nil report.
func TestReportValidBeforeConnect(t *testing.T) {
	rep := New(makeReportTestProfile(t)).Report()
	if rep == nil {
		t.Fatal("Report returned nil before Connect")
	}
	if len(rep.Stages) != 0 {
		t.Errorf("fresh report already has stages: %v", stageNames(rep))
	}
}

// TestProfileFingerprintIgnoresHowTheCipherWasSpelled is why the parser folds
// the case of --cipher and --auth at all.
//
// Every functional reader of Profile.Cipher and Profile.Auth folds again on its
// own. profileFingerprint is the exception: it hashes both fields as written,
// and its contract is that two attempts against the same profile share an
// identifier — so a profile differing from another only in how it spelled a
// cipher name has to hash to the same thing.
func TestProfileFingerprintIgnoresHowTheCipherWasSpelled(t *testing.T) {
	const base = "client\nremote vpn.example.test 443\n"

	shouted, err := profile.ParseString(base + "cipher AES-128-CBC\nauth SHA256\n")
	if err != nil {
		t.Fatalf("ParseString: %v", err)
	}
	muttered, err := profile.ParseString(base + "cipher aes-128-cbc\nauth sha256\n")
	if err != nil {
		t.Fatalf("ParseString: %v", err)
	}

	// Stated separately from the fingerprint, because the fingerprint is a
	// hash and would agree just as well if both profiles had come out wrong.
	if muttered.Cipher != "AES-128-CBC" || muttered.Auth != "SHA256" {
		t.Errorf("lower-case directives parsed to cipher %q, auth %q; want the canonical spellings",
			muttered.Cipher, muttered.Auth)
	}
	if got, want := profileFingerprint(muttered), profileFingerprint(shouted); got != want {
		t.Errorf("the same profile fingerprints as %s when its cipher is lower-case and %s when it is upper-case",
			got, want)
	}

	// And the fingerprint still separates profiles that really do name
	// different ciphers, or this test would pass on one that hashed neither.
	other, err := profile.ParseString(base + "cipher AES-256-GCM\nauth SHA256\n")
	if err != nil {
		t.Fatalf("ParseString: %v", err)
	}
	if profileFingerprint(other) == profileFingerprint(shouted) {
		t.Error("two profiles naming different ciphers share a fingerprint")
	}
}

// TestNegotiatedInfoRecordsTheDigest pins that NegotiatedInfo.Digest comes from
// the resolved parameters rather than from the push: params is what was
// installed, and a server that pushes no `auth` leaves the profile's — or
// OpenVPN's SHA1 default — in force.
func TestNegotiatedInfoRecordsTheDigest(t *testing.T) {
	for _, tc := range []struct {
		name         string
		cipher       string
		digest       string
		wantCipher   string
		wantDigest   string
		digestReason string
	}{
		{
			name:   "CBC records the resolved digest",
			cipher: "AES-128-CBC", digest: "SHA1",
			wantCipher: "AES-128-CBC", wantDigest: "SHA1",
			digestReason: "an AES-128-CBC fleet whose SHA1 must be measured",
		},
		{
			name:   "CBC with no auth directive records OpenVPN's default",
			cipher: "AES-256-CBC", digest: "",
			wantCipher: "AES-256-CBC", wantDigest: "SHA1",
			digestReason: "an absent auth directive means SHA1, and the report must say so",
		},
		{
			name:   "CBC records a pushed digest that outranks the profile",
			cipher: "AES-256-CBC", digest: "SHA512",
			wantCipher: "AES-256-CBC", wantDigest: "SHA512",
			digestReason: "what was installed, not what the profile asked for",
		},
		{
			name:   "AEAD records no digest at all",
			cipher: "AES-256-GCM", digest: "SHA256",
			wantCipher: "AES-256-GCM", wantDigest: "",
			digestReason: "an AEAD cipher authenticates its own output and resolves no digest; " +
				"reporting one would name a value nothing used",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			params, feature, err := datachannel.ResolveParams(tc.cipher, tc.digest)
			if err != nil {
				t.Fatalf("datachannel.ResolveParams(%q, %q): %v (%s)", tc.cipher, tc.digest, err, feature)
			}
			n := negotiatedInfo(&routing.PushOptions{}, 7, params, "none", compress.ModeNone)
			if n.Cipher != tc.wantCipher {
				t.Errorf("Cipher = %q, want %q", n.Cipher, tc.wantCipher)
			}
			if n.Digest != tc.wantDigest {
				t.Errorf("Digest = %q, want %q — %s", n.Digest, tc.wantDigest, tc.digestReason)
			}
		})
	}

	// No push reply, no negotiation. The field stays empty rather than
	// reporting what the client would have used had it got that far.
	if n := negotiatedInfo(nil, 0, datachannel.Params{}, "none", compress.ModeNone); n.Digest != "" {
		t.Errorf("Digest = %q with no push reply; nothing was negotiated", n.Digest)
	}
}

// TestPushUnknownOptions pins the boundary between what the client parses and
// what it merely receives. Every keyword listed as handled must be silent; a
// keyword no parser touches must show up as a candidate feature.
func TestPushUnknownOptions(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want []string
	}{
		{
			name: "everything handled",
			raw: "PUSH_REPLY,ifconfig 10.8.0.6 10.8.0.5,route 10.8.0.0 255.255.0.0," +
				"dhcp-option DNS 10.8.0.1,cipher AES-256-GCM,ping 10,ping-restart 60," +
				"key-derivation tls-ekm,peer-id 7,tun-mtu 1400\x00",
		},
		{
			name: "unhandled keywords are reported verbatim",
			raw:  "PUSH_REPLY,ifconfig 10.8.0.6 10.8.0.5,explicit-exit-notify 1,dhcp-option WINS 10.8.0.9,block-ipv6",
			want: []string{"explicit-exit-notify 1", "block-ipv6"},
		},
		{
			name: "a repeated unknown keyword is reported once",
			raw:  "PUSH_REPLY,route 10.0.0.0 255.0.0.0,tls-crypt-v2 x,tls-crypt-v2 y",
			want: []string{"tls-crypt-v2 x"},
		},
		{
			name: "keyword matching is case-insensitive",
			raw:  "PUSH_REPLY,Redirect-Gateway def1,Route-Gateway 10.8.0.1",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := pushUnknownOptions(tt.raw); !equalStrings(got, tt.want) {
				t.Errorf("pushUnknownOptions: got %v, want %v", got, tt.want)
			}
		})
	}
}

// TestPushParsedOptionsKeepsRepeats verifies the parsed view keeps every
// occurrence of a repeated directive, which is the normal case for "route".
func TestPushParsedOptionsKeepsRepeats(t *testing.T) {
	parsed := pushParsedOptions("PUSH_REPLY,route 10.0.0.0 255.0.0.0,route 10.1.0.0 255.255.0.0,comp-lzo\x00")
	if got := parsed["route"]; len(got) != 2 {
		t.Fatalf("route: got %v, want two entries", got)
	}
	if got, ok := parsed["comp-lzo"]; !ok || len(got) != 1 || got[0] != "" {
		t.Errorf("comp-lzo: got %v (present=%t), want one empty argument", got, ok)
	}
}

// TestStageTimelineOrdersAndStamps checks the recorder's bookkeeping: entries
// are appended in order, a completed stage gets a duration, and an open one
// does not.
func TestStageTimelineOrdersAndStamps(t *testing.T) {
	c := New(makeReportTestProfile(t))
	c.enterStage(diag.StageDial)
	c.completeStage(diag.StageDial)
	c.enterStage(diag.StageTLS)

	rep := c.Report()
	if got := stageNames(rep); !equalStrings(got, []string{"dial", "tls"}) {
		t.Fatalf("stages: got %v", got)
	}
	if rep.Stages[0].Duration == 0 {
		t.Error("a completed stage must carry a duration")
	}
	if rep.Stages[1].Duration != 0 {
		t.Error("an open stage must not carry a duration")
	}
}

// TestReportSnapshotIsIndependent verifies that a report handed out earlier is
// not mutated by later stage transitions.
func TestReportSnapshotIsIndependent(t *testing.T) {
	c := New(makeReportTestProfile(t))
	c.enterStage(diag.StageDial)
	before := c.Report()
	c.enterStage(diag.StageTLS)

	if len(before.Stages) != 1 {
		t.Fatalf("earlier snapshot grew to %d stages", len(before.Stages))
	}
}

// TestEventStageEmitted verifies that every stage transition reaches EventFn
// as an EventStage without disturbing the state events the D-Bus service
// consumes.
func TestEventStageEmitted(t *testing.T) {
	c := New(makeReportTestProfile(t))
	var stages []diag.Stage
	c.EventFn = func(e Event) {
		if e.Type == EventStage {
			stages = append(stages, e.Stage)
		}
	}
	c.enterStage(diag.StageDial)
	c.enterStage(diag.StageTLS)

	if len(stages) != 2 || stages[0] != diag.StageDial || stages[1] != diag.StageTLS {
		t.Fatalf("stage events: got %v", stages)
	}
}

// makeReportTestProfile returns a minimal profile for the report tests.
func makeReportTestProfile(t *testing.T) *profile.Profile {
	t.Helper()
	return &profile.Profile{
		Remote: "vpn.example.com", Port: 443, Proto: profile.ProtoTCP,
		// Incidental to what these tests assert, but required: a profile with
		// no usable CA is refused at StageParse and never reaches the stage
		// under test.
		CA: testCAPEM(t),
	}
}

// TestSessionFailureClass pins how a session that ended gets classified: a
// server ending a working session on purpose is the peer's decision, not the
// network fault ClassNetwork would make it.
func TestSessionFailureClass(t *testing.T) {
	for _, tt := range []struct {
		name       string
		err        error
		wantClass  diag.Class
		wantDetail string
	}{
		{
			name:       "a pushed halt is the peer's decision",
			err:        &control.ServerPushedSignal{Reason: "maintenance"},
			wantClass:  diag.ClassPeerClosed,
			wantDetail: "server pushed HALT",
		},
		{
			name:       "so is a pushed restart",
			err:        &control.ServerPushedSignal{Restart: true},
			wantClass:  diag.ClassPeerClosed,
			wantDetail: "server pushed RESTART",
		},
		{
			name:       "an expiry is still an auth problem",
			err:        &control.SessionExpiredError{Msg: "AUTH_FAILED"},
			wantClass:  diag.ClassAuth,
			wantDetail: "session ended",
		},
		{
			name:       "anything else is the link",
			err:        io.ErrUnexpectedEOF,
			wantClass:  diag.ClassNetwork,
			wantDetail: "session ended",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := &Client{}
			c.noteSessionFailure(tt.err)

			out := c.Report().Outcome
			if out.Class != tt.wantClass {
				t.Errorf("class = %v, want %v", out.Class, tt.wantClass)
			}
			if !strings.Contains(strings.Join(out.ErrorChain, " | "), tt.wantDetail) {
				t.Errorf("error chain = %q, want it to mention %q", out.ErrorChain, tt.wantDetail)
			}
		})
	}
}

// TestPushedTunnelAddressIsRedactedBeforeTheDeviceOpens covers the window
// between the server naming the tunnel address and the backend accepting it.
// Push.Parsed carries the address from StagePush onward and Redacted can only
// remove it once it is registered as a secret, so registering it where the
// device is recorded is too late for every attempt that fails before the
// backend opens.
func TestPushedTunnelAddressIsRedactedBeforeTheDeviceOpens(t *testing.T) {
	const (
		v4 = "10.31.7.42"
		v6 = "fd00:dead:beef::42"
	)
	raw := "PUSH_REPLY,ifconfig " + v4 + " 255.255.255.0,ifconfig-ipv6 " + v6 + "/64 fd00:dead:beef::1,route-gateway 10.31.7.1"

	opts, err := routing.ParsePushReply(raw)
	if err != nil {
		t.Fatalf("ParsePushReply: %v", err)
	}

	c := New(makeReportTestProfile(t))
	c.enterStage(diag.StagePush)
	// Deliberately no recordDevice: this is the failed-before-the-device case.
	c.recordPush(raw, opts, 0)

	blob, err := json.Marshal(c.Report().Redacted())
	if err != nil {
		t.Fatalf("marshal redacted report: %v", err)
	}
	for _, addr := range []string{v4, v6} {
		if bytes.Contains(blob, []byte(addr)) {
			t.Errorf("redacted report discloses the pushed tunnel address %q: %s", addr, blob)
		}
	}
}

// TestPeerCompressionClassifies pins how the peer's own options string is read.
// The answer decides whether a framing byte goes on every data packet, and it
// is recorded in the report so that a consumer and the data channel cannot
// disagree about the same peer.
func TestPeerCompressionClassifies(t *testing.T) {
	const occ = "V4,dev-type tun,link-mtu 1558,tun-mtu 1500,proto UDPv4,%scipher AES-256-CBC," +
		"auth SHA256,keysize 256,key-method 2,tls-server"
	with := func(comp string) string { return strings.Replace(occ, "%s", comp, 1) }

	for _, tt := range []struct{ name, in, want string }{
		{"no options string at all", "", ""},
		{"whitespace only", "   ", ""},
		{"comp-lzo enabled", with("comp-lzo,"), "framing"},
		// "comp-lzo no" is compression off and *framing on*: the peer still
		// expects the leading byte, which is why OpenVPN writes it here at
		// all. Reading it as "no framing" breaks every server that pushes it.
		{"comp-lzo explicitly off", with("comp-lzo no,"), "framing"},
		{"the v2 compress framework", with("compress,"), "framing"},
		{"no compression declared", with(""), "none"},
		{"both declared", with("compress,comp-lzo,"), "framing"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := peerCompression(tt.in); got != tt.want {
				t.Errorf("peerCompression() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestPeerCompressionNeverEchoesPeerText is the property that matters more than
// any individual verdict: the options string is written by the peer, and the
// answer reaches a report a caller may write down.
func TestPeerCompressionNeverEchoesPeerText(t *testing.T) {
	allowed := map[string]bool{"framing": true, "none": true, "": true}
	for _, in := range []string{
		"V4,comp-lzo evil\ninjected: line,cipher AES-256-CBC",
		"comp-lzo " + string(rune(0)) + "nul",
		"compress `rm -rf /`",
		"V4," + string(make([]byte, 4096)),
		"<script>alert(1)</script>,comp-lzo",
	} {
		if got := peerCompression(in); !allowed[got] {
			t.Errorf("peerCompression(%q) = %q, which is outside the fixed token set", in, got)
		}
	}
}
