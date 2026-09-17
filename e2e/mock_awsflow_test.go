//go:build mockserver

// End-to-end tests for the federated (CRV1) flow — require a running mock
// server. They build the mock server binary, start it on a random port, connect
// the Go client, and assert on the server's structured event log.
//
// Run with:
//
//	go test -v -tags=mockserver ./e2e/
package e2e

import (
	"context"
	"encoding/json"
	"errors"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	vpn "github.com/openlawsvpn/go-openlawsvpn"
	"github.com/openlawsvpn/go-openlawsvpn/diag"
	"github.com/openlawsvpn/go-openlawsvpn/profile"
	"github.com/openlawsvpn/go-openlawsvpn/testenv"
)

// assertReportReachedData checks the report a mock-server run must produce: the
// attempt's furthest stage is StageData, and the report captured the server's
// options string. Reaching StageData is not the same as succeeding — without
// CAP_NET_ADMIN the tunnel device cannot be opened, so the run ends inside the
// data stage with diag.ClassLocal.
func assertReportReachedData(t *testing.T, client *vpn.Client) {
	t.Helper()
	rep := client.Report()
	if rep == nil {
		t.Fatal("Report returned nil")
	}
	if len(rep.Stages) == 0 {
		t.Fatal("report has no stages")
	}

	var names []string
	for _, s := range rep.Stages {
		names = append(names, s.Stage.String())
	}
	t.Logf("stages: %s", strings.Join(names, " → "))
	t.Logf("outcome: succeeded=%t class=%s stage=%s",
		rep.Outcome.Succeeded, rep.Outcome.Class, rep.Outcome.Stage)
	t.Logf("ServerOpts: %q", rep.ServerOpts)
	t.Logf("advertised: IV_PROTO=%d IV_CIPHERS=%s", rep.Advertised.IVProto, rep.Advertised.IVCiphers)
	t.Logf("advertised options: %q", rep.Advertised.Options)
	t.Logf("negotiated: cipher=%s compression=%s peer_id=%d key_derivation=%s tls_wrap=%s",
		rep.Negotiated.Cipher, rep.Negotiated.Compression, rep.Negotiated.PeerID,
		rep.Negotiated.KeyDerivation, rep.Negotiated.TLSWrap)
	t.Logf("tls: %s / %s ekm_available=%t", rep.TLS.Version, rep.TLS.CipherSuite, rep.TLS.EKMAvailable)
	t.Logf("push unknown_options: %v", rep.Push.UnknownOptions)

	last := rep.Stages[len(rep.Stages)-1].Stage
	if last != diag.StageData {
		t.Errorf("furthest stage: got %s, want %s", last, diag.StageData)
	}
	if !strings.HasPrefix(rep.ServerOpts, "V4,") {
		t.Errorf("ServerOpts not captured from the server auth packet: %q", rep.ServerOpts)
	}
	if !strings.Contains(rep.ServerOpts, "key-method 2") {
		t.Errorf("ServerOpts lost the key-method fingerprint: %q", rep.ServerOpts)
	}
	if rep.Advertised.IVProto == 0 || rep.Advertised.Options == "" {
		t.Error("advertised block was not captured")
	}
	if rep.Negotiated.KeyDerivation == "" {
		t.Error("negotiated key derivation was not captured")
	}

	// A report that leaks a credential defeats the point of having one.
	blob, err := json.Marshal(rep.Redacted())
	if err != nil {
		t.Fatalf("marshal redacted report: %v", err)
	}
	if strings.Contains(string(blob), demoSAMLResponse) {
		t.Error("redacted report disclosed the SAML token")
	}
}

// demoSAMLResponse mirrors defaultDemoSAMLResponse in testenv/mockserver/main.go —
// the fixed base64 SAMLResponse the demo login page POSTs to the ACS server.
const demoSAMLResponse = "PHNhbWxwOlJlc3BvbnNlIHhtbG5zOnNhbWxwPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6cHJvdG9jb2wiIElEPSJvcGVubGF3c3Zwbi1kZW1vIj48L3NhbWxwOlJlc3BvbnNlPg=="

// startMock brings up the mock server with a certificate authority the client
// is given, and returns the server and a profile pointing at it. The CA is not
// incidental: a profile with no usable CA is a diag.ClassConfig error, so the
// mock path exercises the same verification a real server does.
func startMock(t *testing.T, crv1 bool) (*testenv.Server, *profile.Profile) {
	t.Helper()
	pki, err := testenv.NewMockPKI(t.TempDir())
	if err != nil {
		t.Fatalf("generate mock PKI: %v", err)
	}
	srv, err := testenv.Start(testenv.Config{
		Binary:   buildMockServer(t),
		CertDir:  pki.Dir,
		CRV1Mode: crv1,
	})
	if err != nil {
		t.Fatalf("start mock server: %v", err)
	}
	t.Cleanup(func() { _ = srv.Stop() })
	time.Sleep(200 * time.Millisecond)
	return srv, mockProfile(t, srv.TCPAddr, pki.CAPEM)
}

// mockProfile returns an AWS-flow profile pointing to a local mock server.
//
// It declares the flow rather than inferring it: x-openlawsvpn-flow saml is how
// a profile says "AWS flow" for a server whose hostname is not an
// amazonaws.com endpoint, which 127.0.0.1 is not. Inferred, this profile is
// FlowUserPass, which would present the wrong credentials to a server that
// wants the ACS prompt.
func mockProfile(t *testing.T, addr string, caPEM []byte) *profile.Profile {
	t.Helper()
	p := bareMockProfile(t, addr, caPEM)
	p.Federated = true
	return p
}

// bareMockProfile returns a profile pointing to a local mock server with no
// flow-deciding fields set, for a caller that supplies its own.
func bareMockProfile(t *testing.T, addr string, caPEM []byte) *profile.Profile {
	t.Helper()
	host, port := splitAddr(t, addr)
	return &profile.Profile{
		Remote: host,
		Port:   port,
		Proto:  profile.ProtoTCP,
		CA:     caPEM,
	}
}

// TestConnectNoCRV1 verifies that in normal mode an AWS-flow client receives
// PUSH_REPLY and the server logs an auth_packet_recv event with username="N/A"
// and the fixed ACS password — two literals nothing else sends.
func TestConnectNoCRV1(t *testing.T) {
	srv, p := startMock(t, false)
	client := vpn.New(p)
	client.Device = &idleBackend{} // a running tunnel without CAP_NET_ADMIN
	// Connect refuses an AWS-flow profile with no SAMLTokenFn. The mock is
	// not in CRV1 mode and will never issue a challenge, so this must not be
	// reached — and says so if it is.
	client.SAMLTokenFn = func(context.Context, vpn.SAMLChallenge) (string, error) {
		t.Error("SAMLTokenFn called: the mock issued a challenge it was not asked for")
		return "", errors.New("unexpected challenge")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := client.Connect(ctx); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	assertReportReachedData(t, client)
	client.Disconnect()        //nolint:errcheck
	client.WaitForDisconnect() //nolint:errcheck

	time.Sleep(300 * time.Millisecond)

	authEvents := srv.AuthEvents()
	if len(authEvents) == 0 {
		t.Fatal("no auth_packet_recv events logged by mock server")
	}
	ae := authEvents[0]
	t.Logf("auth_packet_recv: username=%q password_len=%d options=%q peer_info=%q",
		ae.Username, ae.PasswordLen, ae.Options, ae.PeerInfo)

	if ae.Username != "N/A" {
		t.Errorf("username: got %q, want %q", ae.Username, "N/A")
	}
	if ae.CredentialKind != "acs" {
		t.Errorf("credential kind: got %q, want %q", ae.CredentialKind, "acs")
	}
	if !strings.HasPrefix(ae.Options, "V4,") {
		t.Errorf("options should start with 'V4,', got %q", ae.Options)
	}
	if ae.TotalBytes < 200 {
		t.Errorf("auth packet too small: %d bytes", ae.TotalBytes)
	}
}

// TestConnectCertOnlyPresentsNoCredentials pins both halves of what a cert-only
// profile puts on the wire: the server sees a genuinely empty credential pair,
// and the attempt still gets all the way to StageData.
func TestConnectCertOnlyPresentsNoCredentials(t *testing.T) {
	srv, base := startMock(t, false)
	p := base
	p.Federated = false
	p.Cert, p.Key = selfSignedClientPair(t)
	if got := p.AuthFlow(); got != profile.FlowCertAuth {
		t.Fatalf("AuthFlow = %v, want FlowCertAuth", got)
	}

	client := vpn.New(p)
	client.Device = &idleBackend{} // a running tunnel without CAP_NET_ADMIN
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := client.Connect(ctx); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	assertReportReachedData(t, client)
	client.Disconnect()        //nolint:errcheck
	client.WaitForDisconnect() //nolint:errcheck

	time.Sleep(300 * time.Millisecond)

	authEvents := srv.AuthEvents()
	if len(authEvents) == 0 {
		t.Fatal("no auth_packet_recv events logged by mock server")
	}
	ae := authEvents[0]
	t.Logf("auth_packet_recv: username=%q password_len=%d credential_kind=%q",
		ae.Username, ae.PasswordLen, ae.CredentialKind)

	if ae.Username != "" {
		t.Errorf("username: got %q, want empty — a cert-only profile has none", ae.Username)
	}
	if ae.PasswordLen != 0 {
		t.Errorf("password length: got %d, want 0", ae.PasswordLen)
	}
	if ae.CredentialKind != "empty" {
		t.Errorf("credential kind: got %q, want %q", ae.CredentialKind, "empty")
	}
	// The AWS literals must not appear on a cert-only wire at all.
	for _, event := range srv.EventLog() {
		if strings.Contains(event.Detail, "ACS::35001") {
			t.Errorf("cert-only attempt sent the AWS ACS password: %s", event.Detail)
		}
	}
}

// TestConnectUserPassPresentsCredentials is the other half of the seam: a
// profile that asks for a username and password gets what CredentialsFn
// returns, on the wire, and neither value survives into the report. The profile
// is parsed so that it carries a real auth-user-pass directive, whose file form
// is SeverityFatal in the capability registry — hence advisory mode.
func TestConnectUserPassPresentsCredentials(t *testing.T) {
	const (
		wantUser = "integration-sentinel-user"
		wantPass = "integration-sentinel-password"
	)

	srv, base := startMock(t, false)
	p, err := profile.ParseString("client\nremote 127.0.0.1 1\nproto tcp-client\nauth-user-pass\n")
	if err != nil {
		t.Fatalf("ParseString: %v", err)
	}
	p.Remote, p.Port, p.CA = base.Remote, base.Port, base.CA
	if got := p.AuthFlow(); got != profile.FlowUserPass {
		t.Fatalf("AuthFlow = %v, want FlowUserPass", got)
	}

	var (
		calls int
		logs  []string
	)
	client := vpn.New(p)
	client.Device = &idleBackend{} // a running tunnel without CAP_NET_ADMIN
	client.PreflightMode = diag.PreflightAdvisory
	client.CredentialsFn = func(context.Context) (vpn.Credentials, error) {
		calls++
		return vpn.Credentials{Username: wantUser, Password: wantPass}, nil
	}
	// Every line the client would have printed, captured so the leak scan can
	// cover the log surface and not only the report. EventFn is called
	// concurrently once the data path is up, hence the lock.
	var logsMu sync.Mutex
	client.EventFn = func(e vpn.Event) {
		logsMu.Lock()
		defer logsMu.Unlock()
		logs = append(logs, e.Message)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := client.Connect(ctx); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	assertReportReachedData(t, client)
	client.Disconnect()        //nolint:errcheck
	client.WaitForDisconnect() //nolint:errcheck

	time.Sleep(300 * time.Millisecond)

	if calls != 1 {
		t.Errorf("CredentialsFn called %d times, want exactly 1 per attempt", calls)
	}

	authEvents := srv.AuthEvents()
	if len(authEvents) == 0 {
		t.Fatal("no auth_packet_recv events logged by mock server")
	}
	ae := authEvents[0]
	t.Logf("auth_packet_recv: username=%q password_len=%d credential_kind=%q",
		ae.Username, ae.PasswordLen, ae.CredentialKind)

	if ae.Username != wantUser {
		t.Errorf("username: got %q, want %q", ae.Username, wantUser)
	}
	if ae.PasswordLen != len(wantPass) {
		t.Errorf("password length: got %d, want %d", ae.PasswordLen, len(wantPass))
	}
	if ae.CredentialKind == "acs" {
		t.Error("a username/password profile sent the AWS Phase 1 password")
	}

	// Nothing the client can emit may carry either value. The user name is a
	// credential too and is registered alongside the password.
	blob, err := json.Marshal(client.Report().Redacted())
	if err != nil {
		t.Fatalf("marshal redacted report: %v", err)
	}
	logsMu.Lock()
	captured := slices.Clone(logs)
	logsMu.Unlock()

	for _, secret := range []string{wantUser, wantPass} {
		if strings.Contains(string(blob), secret) {
			t.Errorf("redacted report disclosed %q: %s", secret, blob)
		}
		for _, line := range captured {
			if strings.Contains(line, secret) {
				t.Errorf("event log disclosed %q: %q", secret, line)
			}
		}
	}
}

// TestWrongCredentialsAreAuthClass verifies the classification that tells a bad
// password from a missing feature: a server that answers AUTH_FAILED is
// ClassAuth. The stage is StagePush rather than StageAuth, because OpenVPN's
// AUTH_FAILED arrives in place of the PUSH_REPLY, after the key-method-2
// exchange the server accepted.
func TestWrongCredentialsAreAuthClass(t *testing.T) {
	srv, p := startMock(t, true)
	client := vpn.New(p)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	challenge, err := client.Phase1ForTest(ctx)
	if err != nil {
		t.Fatalf("Phase1ForTest: %v", err)
	}
	if challenge == nil {
		t.Fatal("expected SAML challenge in CRV1 mode, got nil")
	}

	const wrongToken = "wrong-assertion-sentinel"
	err = client.ConnectPhase2(ctx, wrongToken)
	if err == nil {
		t.Fatal("expected Phase 2 to fail with a rejected assertion")
	}

	var derr *diag.Error
	if !errors.As(err, &derr) {
		t.Fatalf("error is not a *diag.Error: %T: %v", err, err)
	}
	if derr.Class != diag.ClassAuth {
		t.Errorf("class = %s, want %s: a rejected credential must not look like "+
			"a missing feature", derr.Class, diag.ClassAuth)
	}
	t.Logf("rejected credential classified as %s at %s", derr.Class, derr.Stage)

	rep := client.Report()
	if rep.Outcome.Class != diag.ClassAuth {
		t.Errorf("report outcome class = %s, want %s", rep.Outcome.Class, diag.ClassAuth)
	}

	blob, err := json.Marshal(rep.Redacted())
	if err != nil {
		t.Fatalf("marshal redacted report: %v", err)
	}
	if strings.Contains(string(blob), wrongToken) {
		t.Errorf("a rejected credential survived redaction: %s", blob)
	}

	client.Disconnect()        //nolint:errcheck
	client.WaitForDisconnect() //nolint:errcheck
	time.Sleep(300 * time.Millisecond)

	// The server's own log confirms this was a credential rejection and not
	// something else that happens to end in ClassAuth.
	var rejected bool
	for _, event := range srv.EventLog() {
		if event.Event == "crv1_phase2_rejected" {
			rejected = true
		}
		if strings.Contains(event.Detail, wrongToken) {
			t.Errorf("the mock logged the assertion verbatim: %s", event.Detail)
		}
	}
	if !rejected {
		t.Error("the mock server did not log a rejection; ClassAuth came from somewhere else")
	}
}

// TestConnectCRV1Flow verifies the full two-phase SAML/CRV1 flow against the
// local mock server, driving the two phases via Phase1ForTest + ConnectPhase2
// so that no resolvable amazonaws.com hostname is needed.
func TestConnectCRV1Flow(t *testing.T) {
	srv, p := startMock(t, true)
	client := vpn.New(p)
	client.Device = &idleBackend{} // a running tunnel without CAP_NET_ADMIN

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	challenge, err := client.Phase1ForTest(ctx)
	if err != nil {
		t.Fatalf("Phase1ForTest: %v", err)
	}
	if challenge == nil {
		t.Fatal("expected SAML challenge in CRV1 mode, got nil")
	}
	t.Logf("challenge: stateID=%q url=%q", challenge.StateID, challenge.URL)

	// The fixed demo token — the same value the static login page POSTs to the
	// ACS server and that mockserver validates in Phase 2. It must stay in sync
	// with defaultDemoSAMLResponse, which is in package main.
	if err := client.ConnectPhase2(ctx, demoSAMLResponse); err != nil {
		t.Fatalf("ConnectPhase2: %v", err)
	}
	assertReportReachedData(t, client)
	client.Disconnect()        //nolint:errcheck
	client.WaitForDisconnect() //nolint:errcheck

	time.Sleep(300 * time.Millisecond)

	authEvents := srv.AuthEvents()
	if len(authEvents) < 2 {
		t.Fatalf("expected at least 2 auth_packet_recv events (phase1 + phase2), got %d: %v",
			len(authEvents), authEvents)
	}

	p1 := authEvents[0]
	t.Logf("phase1 auth: username=%q credential_kind=%q", p1.Username, p1.CredentialKind)
	if p1.CredentialKind != "acs" {
		t.Errorf("phase1 credential kind: got %q, want %q", p1.CredentialKind, "acs")
	}

	p2 := authEvents[1]
	t.Logf("phase2 auth: username=%q credential_kind=%q", p2.Username, p2.CredentialKind)
	if p2.CredentialKind != "crv1" {
		t.Errorf("phase2 credential kind: got %q, want %q", p2.CredentialKind, "crv1")
	}
	for _, event := range srv.EventLog() {
		if strings.Contains(event.Detail, demoSAMLResponse) {
			t.Errorf("mock-server event %q disclosed the SAML token", event.Event)
		}
	}
}

// settleGoroutines gives goroutines released by a teardown a chance to be gone
// before they are counted. Named apart from the docker pass's settle so a build
// carrying both tags still compiles.
func settleGoroutines() {
	for range 5 {
		runtime.GC()
		time.Sleep(50 * time.Millisecond)
	}
}

// TestCancelledSAMLCollectionTearsTheAttemptDown covers the one failure inside
// Connect that can return without tearing anything down. dialRemote
// deliberately leaves the first exchange's connection open because the second
// exchange is supposed to use it, so a user closing the browser can leave the
// socket, the raw reader, the inbound relay, the send goroutine and the
// retransmit ticker all running with Done() still open.
func TestCancelledSAMLCollectionTearsTheAttemptDown(t *testing.T) {
	_, p := startMock(t, true)

	settleGoroutines()
	before := runtime.NumGoroutine()

	const cycles = 5
	for i := range cycles {
		client := vpn.New(p)
		client.Device = &idleBackend{}
		client.SAMLTokenFn = func(context.Context, vpn.SAMLChallenge) (string, error) {
			return "", errors.New("user closed the browser")
		}

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		err := client.Connect(ctx)
		cancel()
		if err == nil {
			t.Fatalf("cycle %d: Connect succeeded without a SAML assertion", i)
		}

		select {
		case <-client.Done():
		case <-time.After(10 * time.Second):
			t.Fatalf("cycle %d: Done() is still open after Connect failed — "+
				"the attempt was never torn down", i)
		}
		if err := client.WaitForDisconnect(); err == nil {
			t.Errorf("cycle %d: WaitForDisconnect reported no reason for a failed attempt", i)
		}
	}

	settleGoroutines()
	after := runtime.NumGoroutine()
	// A per-cycle leak of goroutines and a socket shows up well clear of the
	// runtime's own drift.
	if after > before+10 {
		t.Errorf("goroutines grew from %d to %d over %d cancelled SAML attempts",
			before, after, cycles)
	}
	t.Logf("goroutines: %d before, %d after %d cancelled attempts", before, after, cycles)
}
