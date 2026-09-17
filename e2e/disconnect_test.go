// SPDX-License-Identifier: LGPL-2.1-or-later

//go:build docker

// Teardown: a deliberate one returns nil, and a genuine transport failure still
// does not.
//
// The load shape is the one that matters: an idle close never reaches the write
// path at all. Both directions are asserted together because a guard keyed on
// the error text rather than on the context would silence the spurious error
// and the real one alike.
package e2e

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	vpn "github.com/openlawsvpn/go-openlawsvpn"
	"github.com/openlawsvpn/go-openlawsvpn/netstack"
	"github.com/openlawsvpn/go-openlawsvpn/profile"
	"github.com/openlawsvpn/go-openlawsvpn/testenv"
)

// disconnectEntry is the entry the cycles run against, and the simplest entry
// this client completes: a non-nil return cannot be attributed to a wrap, a
// credential exchange or a compression framing.
const disconnectEntry = "v26-gcm256-sha256-plain-udp"

// failureEntry is the entry the counter-test runs against.
//
// `docker rm -f` does not break the stream promptly even over TCP: the
// connection black-holes rather than being reset. What notices is the dead-link
// timer — the matrix servers push `keepalive 10 60` — which is why the deadline
// below is 90 seconds, and why keepaliveLoop is the site under test.
const failureEntry = "v26-gcm256-sha256-plain-udp"

// disconnectCyclesEnv overrides the cycle count per shape. The committed
// default keeps the suite quick; a run meant to settle the question uses 200.
const disconnectCyclesEnv = "OPENLAWSVPN_DISCONNECT_CYCLES"

// defaultDisconnectCycles is the committed sample size.
const defaultDisconnectCycles = 50

// disconnectCycles returns the configured cycle count.
func disconnectCycles(t *testing.T) int {
	t.Helper()
	raw := os.Getenv(disconnectCyclesEnv)
	if raw == "" {
		return defaultDisconnectCycles
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 {
		t.Fatalf("%s=%q: want a positive integer", disconnectCyclesEnv, raw)
	}
	return n
}

// TestCleanDisconnectReturnsNil asserts that a deliberate teardown reports no
// error, idle and under load. Every failure is collected before the test fails
// rather than stopping at the first, because the rate is the diagnostic.
func TestCleanDisconnectReturnsNil(t *testing.T) {
	e, ok := testenv.Entry(disconnectEntry)
	if !ok {
		t.Fatalf("no matrix entry %q", disconnectEntry)
	}
	if reason := e.ClientUnsupported; reason != "" {
		t.Skipf("client cannot drive %s: %s", disconnectEntry, reason)
	}
	cycles := disconnectCycles(t)

	for _, shape := range []struct {
		name string
		// carry, when true, keeps plaintext moving through the tunnel for
		// the whole of its life, so the close lands on a tunToWire that is
		// mid-write rather than one parked in a read.
		carry bool
	}{
		{name: "idle", carry: false},
		{name: "carrying", carry: true},
	} {
		t.Run(shape.name, func(t *testing.T) {
			// A server per shape, not one for both: the address pool is a /24
			// and freed leases do not come back fast enough. A connect timing
			// out partway through would be read as a teardown failure.
			srv, err := testenv.StartMatrix(e)
			if err != nil {
				t.Skipf("StartMatrix: %v", err)
			}
			t.Cleanup(func() { _ = srv.Stop() })

			// explicit-exit-notify, added to the generated profile rather than
			// left to the entry. The server holds a finished instance until its
			// own timeout, so a recycled ephemeral port stalls the connect; the
			// notification frees it, and writes to the socket at teardown.
			p, err := profile.ParseString(srv.ClientProfile() + "\nexplicit-exit-notify 1\n")
			if err != nil {
				t.Fatalf("ParseString: %v", err)
			}
			if p.ExplicitExitNotify != 1 {
				t.Fatalf("ExplicitExitNotify = %d, want 1; the cycles need the "+
					"server to free each session as it ends", p.ExplicitExitNotify)
			}

			var failures []string
			started := time.Now()
			for i := 1; i <= cycles; i++ {
				err, connErr := oneDisconnectCycle(t, p, shape.carry)
				if connErr != nil {
					t.Fatalf("cycle %d of %d, %s in: connect failed: %v",
						i, cycles, time.Since(started).Round(time.Millisecond), connErr)
				}
				if err != nil {
					failures = append(failures, fmt.Sprintf("cycle %d: %v", i, err))
				}
			}
			if len(failures) > 0 {
				for _, f := range failures {
					t.Errorf("    %s", f)
				}
				t.Fatalf("%s/%s: %d of %d deliberate teardowns reported an error; "+
					"a goroutine woken by its own teardown must not record one "+
					"(see Client.endSession)",
					disconnectEntry, shape.name, len(failures), cycles)
			}
			t.Logf("%s/%s: %d of %d cycles returned nil", disconnectEntry, shape.name, cycles, cycles)
		})
	}
}

// oneDisconnectCycle connects, optionally carries traffic, and closes. It
// returns the error Close reported and fails the test only when the connect
// itself did not work — an attempt that never came up is not a sample.
func oneDisconnectCycle(t *testing.T, p *profile.Profile, carry bool) (closeErr, connErr error) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	tun, err := netstack.Connect(ctx, p, netstack.Options{})
	if err != nil {
		return nil, err
	}

	var wg sync.WaitGroup
	stop := make(chan struct{})
	if carry {
		// A UDP conn to a port nothing is listening on is enough: the point
		// is that tunToWire encrypts and writes to the socket. Errors are
		// ignored — the writes start failing the instant Close lands.
		conn, derr := tun.DialUDP(serverTunIP + ":9")
		if derr != nil {
			_ = tun.Close()
			t.Fatalf("DialUDP: %v", derr)
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			defer conn.Close() //nolint:errcheck
			payload := make([]byte, 512)
			for {
				select {
				case <-stop:
					return
				default:
				}
				conn.Write(payload) //nolint:errcheck
			}
		}()
		// Let the writer get going, so the close really does land on a
		// tunnel in the middle of writing.
		time.Sleep(200 * time.Millisecond)
	}

	err = tun.Close()
	close(stop)
	wg.Wait()
	return err, nil
}

// TestTransportFailureStillReportsAnError is the other half: endSession
// suppresses a failure only when the context says a teardown is already under
// way, and here nothing has been torn down. A guard keyed on the error text
// instead — every one of these fails with "use of closed network connection",
// exactly like a clean close — would pass the first test and fail this one.
func TestTransportFailureStillReportsAnError(t *testing.T) {
	e, ok := testenv.Entry(failureEntry)
	if !ok {
		t.Fatalf("no matrix entry %q", failureEntry)
	}
	if reason := e.ClientUnsupported; reason != "" {
		t.Skipf("client cannot drive %s: %s", failureEntry, reason)
	}
	srv, err := testenv.StartMatrix(e)
	if err != nil {
		t.Skipf("StartMatrix: %v", err)
	}
	t.Cleanup(func() { _ = srv.Stop() })

	p, err := profile.ParseString(srv.ClientProfile())
	if err != nil {
		t.Fatalf("ParseString: %v", err)
	}

	// Driven through vpn.Client rather than netstack.Connect, so the assertion
	// is on WaitForDisconnect's own return rather than on Tunnel.Close's
	// summary of it. The backend is the same one netstack.Connect installs.
	c := vpn.New(p)
	c.Device = &netstack.Backend{}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := c.Connect(ctx); err != nil {
		t.Fatalf("Connect to %s: %v", failureEntry, err)
	}
	t.Cleanup(func() {
		c.Disconnect()        //nolint:errcheck
		c.WaitForDisconnect() //nolint:errcheck
	})

	// Take the server away. Interrupt removes the container, so the stream is
	// broken with nothing listening behind it, and nothing on this side has
	// asked for a teardown.
	if err := srv.Interrupt(); err != nil {
		t.Fatalf("Interrupt: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- c.WaitForDisconnect() }()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("the session ended with no error after the server was taken " +
				"away; a genuine transport failure must still be reported, or the " +
				"teardown guard is swallowing real failures along with spurious ones")
		}
		t.Logf("transport failure reported: %v", err)
	case <-time.After(90 * time.Second):
		t.Fatal("the session did not end within 90s of the server being taken away, " +
			"which is past the pushed ping-restart of 60s")
	}
}
