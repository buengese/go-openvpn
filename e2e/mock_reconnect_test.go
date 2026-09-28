//go:build mockserver

// The AWS half of the reconnect loop: generalising the loop past the AWS shape
// is only safe if the shape it came from still works. The mock server runs as a
// subprocess and the tunnel device is a stub, so what is under test is the loop
// rather than the host.
package e2e

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	vpn "github.com/buengese/go-openvpn"
	"github.com/buengese/go-openvpn/device"
)

// ---- A tunnel device that needs no privilege -----------------------------

// idleBackend hands out devices that carry nothing, so that this test can reach
// a *running* tunnel without CAP_NET_ADMIN: a session that never came up has
// nothing to reconnect. It also counts — one device per attempt that reaches
// the data stage is the device.Backend contract as a reconnect exercises it.
type idleBackend struct{ opens atomic.Int64 }

func (b *idleBackend) Open(_ context.Context, p device.Params) (device.Device, error) {
	b.opens.Add(1)
	return &idleDevice{mtu: p.MTU, closed: make(chan struct{})}, nil
}

// idleDevice is a device.Device that blocks until it is closed and discards
// everything written to it. Blocking is deliberate: tunToWire loops on
// ReadPacket, so a device that returned immediately would spin and one that
// produced packets would put traffic on the wire at teardown.
type idleDevice struct {
	mtu    int
	once   sync.Once
	closed chan struct{}
}

func (d *idleDevice) ReadPacket(ctx context.Context, _ []byte) (int, error) {
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-d.closed:
		return 0, net.ErrClosed
	}
}

func (d *idleDevice) WritePacket([]byte) error { return nil }
func (d *idleDevice) MTU() int                 { return d.mtu }
func (d *idleDevice) Name() string             { return "idle0" }
func (d *idleDevice) Close() error {
	d.once.Do(func() { close(d.closed) })
	return nil
}

// ---- The assertion the mock will accept ----------------------------------

// expiringDemoToken returns a base64 SAML response carrying a NotOnOrAfter ttl
// from now, and points the mock server at it as the token its demo login page
// issues. The fixed demo assertion has none, and Reconnect refuses to spend an
// assertion it cannot date.
func expiringDemoToken(t *testing.T, ttl time.Duration) string {
	t.Helper()
	xml := fmt.Sprintf(
		`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" `+
			`ID="go-openvpn-reconnect"><Conditions NotOnOrAfter="%s"/></samlp:Response>`,
		time.Now().Add(ttl).UTC().Format("2006-01-02T15:04:05Z"))
	token := base64.StdEncoding.EncodeToString([]byte(xml))
	// The mock reads this when it validates a Phase 2 CRV1 password, and
	// startBinary passes the test process's environment through.
	t.Setenv("DEMO_TOKEN", token)
	return token
}

// TestCRV1MockReconnectsWithTheCachedAssertion is the AWS acceptance: a tunnel
// that was up comes back without a browser, using the assertion, the CRV1
// state id and the Phase 1 IP already held.
func TestCRV1MockReconnectsWithTheCachedAssertion(t *testing.T) {
	token := expiringDemoToken(t, time.Hour)
	srv, p := startMock(t, true)

	backend := &idleBackend{}
	client := vpn.New(p)
	client.Device = backend

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	challenge, err := client.Phase1ForTest(ctx)
	if err != nil {
		t.Fatalf("Phase1ForTest: %v", err)
	}
	if challenge == nil {
		t.Fatal("expected a CRV1 challenge in CRV1 mode, got nil")
	}
	if err := client.ConnectPhase2(ctx, token); err != nil {
		t.Fatalf("ConnectPhase2: %v", err)
	}
	t.Cleanup(func() {
		client.Disconnect()        //nolint:errcheck
		client.WaitForDisconnect() //nolint:errcheck
	})

	// One attempt so far, and it succeeded. The two-phase entry points share
	// an attempt: Phase 1 and Phase 2 are one attempt at one session.
	if got := client.Attempts(); len(got) != 1 || !got[0].Report.Outcome.Succeeded {
		t.Fatalf("after connect, attempts = %s, want one that succeeded", summariseAttempts(got))
	}

	if err := client.Reconnect(ctx); err != nil {
		t.Fatalf("Reconnect: %v", err)
	}

	attempts := client.Attempts()
	if len(attempts) != 1 {
		t.Fatalf("reconnect attempts = %s, want exactly one: the assertion was still good "+
			"and the mock answers the first Phase 2", summariseAttempts(attempts))
	}
	if !attempts[0].Report.Outcome.Succeeded {
		t.Errorf("reconnect attempt 1 outcome = %s at %s, want success",
			attempts[0].Report.Outcome.Class, attempts[0].Report.Outcome.Stage)
	}
	if got := backend.opens.Load(); got != 2 {
		t.Errorf("devices opened = %d, want 2: one for the connect and one for the reconnect", got)
	}

	client.Disconnect()        //nolint:errcheck
	client.WaitForDisconnect() //nolint:errcheck
	time.Sleep(300 * time.Millisecond)

	// The server's own view: three auth exchanges, and the second and third
	// are both CRV1 Phase 2 passwords. A reconnect that had gone back to
	// Phase 1 would show a second "acs" here instead.
	var kinds []string
	for _, ev := range srv.AuthEvents() {
		kinds = append(kinds, ev.CredentialKind)
	}
	t.Logf("auth exchanges: %v", kinds)
	if len(kinds) != 3 {
		t.Fatalf("auth exchanges = %v, want three (phase 1, phase 2, reconnect phase 2)", kinds)
	}
	if kinds[0] != "acs" {
		t.Errorf("exchange 1 = %q, want acs", kinds[0])
	}
	if kinds[1] != "crv1" || kinds[2] != "crv1" {
		t.Errorf("exchanges 2 and 3 = %q, %q, want crv1 twice: the reconnect must skip Phase 1",
			kinds[1], kinds[2])
	}
}

// TestCRV1MockReconnectWithoutAnExpiryNeedsReauth pins the other half of the
// AWS rule against the real mock: an assertion that cannot be dated cannot be
// spent, because the CRV1 session it would be spent against cannot be got back.
// cmd/cli reads this sentinel and runs the browser flow.
func TestCRV1MockReconnectWithoutAnExpiryNeedsReauth(t *testing.T) {
	_, p := startMock(t, true)

	client := vpn.New(p)
	client.Device = &idleBackend{}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	if _, err := client.Phase1ForTest(ctx); err != nil {
		t.Fatalf("Phase1ForTest: %v", err)
	}
	if err := client.ConnectPhase2(ctx, demoSAMLResponse); err != nil {
		t.Fatalf("ConnectPhase2: %v", err)
	}

	err := client.Reconnect(ctx)
	if err == nil {
		t.Fatal("Reconnect succeeded with an undatable assertion")
	}
	if !errors.Is(err, vpn.ErrReauthRequired) {
		t.Fatalf("Reconnect = %v, want ErrReauthRequired", err)
	}
	if got := client.Attempts(); len(got) != 0 {
		t.Errorf("attempts = %s, want none: no attempt was possible", summariseAttempts(got))
	}
}

// Compile-time proof that the stubs satisfy the seam they stand in for.
var (
	_ device.Backend = (*idleBackend)(nil)
	_ device.Device  = (*idleDevice)(nil)
)
