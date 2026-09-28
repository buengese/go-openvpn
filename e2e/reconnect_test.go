// SPDX-License-Identifier: LGPL-2.1-or-later

//go:build docker

// Reconnection: a link broken underneath a live tunnel, and repaired.
//
// testenv.Interrupt and testenv.Resume break and repair it at the same
// published port, so the client's remote still resolves to the address the
// profile names.
package e2e

import (
	"context"
	"crypto/rand"
	"fmt"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	vpn "github.com/buengese/go-openvpn"
	"github.com/buengese/go-openvpn/diag"
	"github.com/buengese/go-openvpn/netstack"
	"github.com/buengese/go-openvpn/profile"
	"github.com/buengese/go-openvpn/testenv"
)

// reconnectEntries are the two credential flows a reconnect has to cover, one
// entry each. Cert-only on TCP and user/pass on UDP are the transports the
// matrix offers each flow, so taking both exercises the reconnect over a stream
// and a datagram transport as well as over two credential shapes.
var reconnectEntries = []struct {
	name  string
	entry string
}{
	{"cert-only", "v26-gcm256-sha512-plain-tcp"},
	{"user/pass", "v24-gcm256-sha256-plain-udp-userpass"},
}

// reconnectMaxAttempts caps each reconnect in this file. It is a bound on how
// long a broken test waits, not on how hard the client tries: the backoff
// doubles from a second, so six attempts span about a minute.
const reconnectMaxAttempts = 6

// startReconnectableTunnel brings up a matrix server and a tunnel to it whose
// client will reconnect, and returns the number of times the credential
// callback has been asked. The counter is the point: a reconnect that
// re-prompts is a reconnect the user notices.
func startReconnectableTunnel(t *testing.T, entry string) (*testenv.MatrixServer, *netstack.Tunnel, *atomic.Int64) {
	t.Helper()

	e, ok := testenv.Entry(entry)
	if !ok {
		t.Fatalf("no matrix entry %q", entry)
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

	var credsCalls atomic.Int64
	opts := netstack.Options{MaxReconnects: reconnectMaxAttempts}
	if e.Auth.RequiresCredentials() {
		opts.CredentialsFn = func(context.Context) (vpn.Credentials, error) {
			credsCalls.Add(1)
			return vpn.Credentials{
				Username: testenv.MatrixUsername,
				Password: testenv.MatrixPassword,
			}, nil
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	tun, err := netstack.Connect(ctx, p, opts)
	if err != nil {
		t.Fatalf("Connect to %s: %v", entry, err)
	}
	t.Cleanup(func() { _ = tun.Close() })
	return srv, tun, &credsCalls
}

// carriesTraffic pings the tunnel's own gateway with a random payload. The
// gateway is inside the server's tunnel subnet, so a reply cannot have come
// from anywhere but the far end.
func carriesTraffic(t *testing.T, tun *netstack.Tunnel, seq uint16, what string) {
	t.Helper()
	gw, err := tun.Gateway()
	if err != nil {
		t.Fatalf("%s: Gateway: %v", what, err)
	}
	payload := make([]byte, 64)
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("%s: random payload: %v", what, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	rtt, err := tun.Ping(ctx, gw, payload, seq)
	if err != nil {
		t.Fatalf("%s: ping %s through the tunnel: %v", what, gw, err)
	}
	t.Logf("%s: %s answered in %s", what, redactedGateway(gw), rtt)
}

// redactedGateway renders a pushed gateway address for a log line without
// printing it. It is an internal address the server assigned, and this project
// treats a pushed address as identifying, so only its width is logged.
func redactedGateway(gw netip.Addr) string {
	return fmt.Sprintf("the gateway (%d-bit)", gw.BitLen())
}

// TestReconnectAfterTheLinkIsBroken stops the server underneath a tunnel that
// is up and starts it again at the same address. The client must come back
// having made at least one attempt that failed while nothing was listening, and
// having kept the report that says why.
func TestReconnectAfterTheLinkIsBroken(t *testing.T) {
	for _, tc := range reconnectEntries {
		t.Run(tc.name, func(t *testing.T) {
			srv, tun, credsCalls := startReconnectableTunnel(t, tc.entry)
			carriesTraffic(t, tun, 1, "before the break")

			// Idle before the break, deliberately: tearing a tunnel down while
			// it carries traffic runs into a separate write race, which has its
			// own test.
			if err := srv.Interrupt(); err != nil {
				t.Fatalf("Interrupt the server: %v", err)
			}
			broke := time.Now()

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()

			// The server comes back only once an attempt has been refused,
			// so the sequence is guaranteed to contain a failure and the
			// test does not depend on how quickly a container boots.
			resumed := make(chan error, 1)
			go func() {
				if err := waitForFailedAttempt(ctx, tun, broke); err != nil {
					resumed <- err
					return
				}
				resumed <- srv.Resume()
			}()

			reconnectErr := tun.Reconnect(ctx)
			if err := <-resumed; err != nil {
				t.Fatalf("bring the server back: %v", err)
			}
			if reconnectErr != nil {
				t.Fatalf("Reconnect: %v\nattempts: %s", reconnectErr, summariseAttempts(tun.Attempts()))
			}

			attempts := tun.Attempts()
			t.Logf("attempts: %s", summariseAttempts(attempts))
			assertDistinctOutcomes(t, attempts)

			// The tunnel that came back is a different stack with the same
			// address, and it has to carry traffic like the first one.
			carriesTraffic(t, tun, 2, "after the reconnect")

			if tc.name == "user/pass" && credsCalls.Load() != 1 {
				t.Errorf("CredentialsFn calls = %d, want 1: a dropped link must not "+
					"put a second prompt in front of the user", credsCalls.Load())
			}
		})
	}
}

// waitForFailedAttempt blocks until the client has an attempt on record that
// started after notBefore and failed. notBefore is what keeps this from
// matching the session that was just broken: killing the server records a
// failure against the attempt that established the tunnel.
func waitForFailedAttempt(ctx context.Context, tun *netstack.Tunnel, notBefore time.Time) error {
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	for {
		for _, a := range tun.Attempts() {
			if !a.StartedAt.After(notBefore) {
				continue
			}
			if !a.Report.Outcome.Succeeded && len(a.Report.Outcome.ErrorChain) > 0 {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("no attempt failed before the deadline: %w", ctx.Err())
		case <-tick.C:
		}
	}
}

// assertDistinctOutcomes checks the property the Attempts contract exists for:
// one report per attempt, and the failed attempt's report still says why it
// failed after a later attempt succeeded.
func assertDistinctOutcomes(t *testing.T, attempts []vpn.Attempt) {
	t.Helper()
	if len(attempts) < 2 {
		t.Fatalf("attempts = %d, want at least two: one refused while the server was "+
			"down and one that succeeded", len(attempts))
	}

	last := attempts[len(attempts)-1]
	if !last.Report.Outcome.Succeeded {
		t.Errorf("the last attempt did not succeed: %s at %s",
			last.Report.Outcome.Class, last.Report.Outcome.Stage)
	}

	for _, a := range attempts[:len(attempts)-1] {
		out := a.Report.Outcome
		if out.Succeeded {
			t.Errorf("attempt %d succeeded but was followed by another", a.N)
			continue
		}
		// The reason, still there: a recorder replaced on the next attempt
		// leaves the earlier attempt's report empty.
		if len(out.ErrorChain) == 0 {
			t.Errorf("attempt %d no longer says why it failed", a.N)
		}
		// Only a class the policy retries can be followed by another attempt:
		// nothing listening is ClassNetwork, and a server caught halfway
		// through binding can refuse the handshake as ClassTLS.
		if out.Class != diag.ClassNetwork && out.Class != diag.ClassTLS {
			t.Errorf("attempt %d failed as %s at %s, and the loop continued anyway: "+
				"only network and tls are retried", a.N, out.Class, out.Stage)
		}
		if len(a.Report.Stages) == 0 {
			t.Errorf("attempt %d kept no stage timeline", a.N)
		}
	}

	// Independent reports, not one report seen several times.
	for i := 1; i < len(attempts); i++ {
		if attempts[i].Report == attempts[i-1].Report {
			t.Fatalf("attempts %d and %d returned the same report", attempts[i-1].N, attempts[i].N)
		}
		if attempts[i].N != attempts[i-1].N+1 {
			t.Errorf("attempt numbers are not consecutive: %d then %d", attempts[i-1].N, attempts[i].N)
		}
	}
}
