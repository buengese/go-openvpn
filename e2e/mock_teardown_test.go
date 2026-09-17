// SPDX-License-Identifier: LGPL-2.1-or-later

//go:build mockserver

// Teardown against a peer that is still sending — the shape a data-path
// teardown race hides behind, and the one a disconnect against a peer that has
// gone quiet after PUSH_REPLY cannot reach.
//
// Run with:
//
//	go test -race -tags=mockserver ./e2e/ -run TestDisconnectUnderTraffic
package e2e

import (
	"context"
	"os"
	"testing"
	"time"

	vpn "github.com/openlawsvpn/go-openlawsvpn"
	"github.com/openlawsvpn/go-openlawsvpn/netstack"
	"github.com/openlawsvpn/go-openlawsvpn/profile"
	"github.com/openlawsvpn/go-openlawsvpn/testenv"
)

// teardownCycles is how many connect/disconnect rounds each protocol runs. More
// than one because what is under test is a race: a single round that happens to
// serialise proves nothing.
const teardownCycles = 10

// TestDisconnectUnderTrafficTearsDownCleanly disconnects while the server is
// pushing data-channel packets, over both transports, repeatedly. The process
// surviving is itself an assertion — a send on a closed channel panics in a
// goroutine no caller can recover — and PacketsRecv > 0 is checked rather than
// assumed, or a mock that stopped sending would turn this back into the
// quiet-peer test it exists to replace.
func TestDisconnectUnderTrafficTearsDownCleanly(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("the netstack backend is the point here; re-run as a normal user")
	}

	pki, err := testenv.NewMockPKI(t.TempDir())
	if err != nil {
		t.Fatalf("generate mock PKI: %v", err)
	}
	// One millisecond, not the server's 25: the window under test is the few
	// milliseconds a teardown takes, and a packet every 25 ms would overlap it
	// perhaps one cycle in twenty-five.
	srv, err := testenv.Start(testenv.Config{
		Binary:      buildMockServer(t),
		CertDir:     pki.Dir,
		KeepaliveMS: 1,
	})
	if err != nil {
		t.Fatalf("start mock server: %v", err)
	}
	defer func() { _ = srv.Stop() }()

	for _, tc := range []struct {
		name  string
		proto profile.Proto
		addr  string
	}{
		{"tcp", profile.ProtoTCP, srv.TCPAddr},
		{"udp", profile.ProtoUDP, srv.UDPAddr},
	} {
		t.Run(tc.name, func(t *testing.T) {
			host, port := splitAddr(t, tc.addr)
			for cycle := range teardownCycles {
				c := vpn.New(&profile.Profile{
					Remote: host,
					Port:   port,
					Proto:  tc.proto,
					CA:     pki.CAPEM,
				})
				c.Device = netstack.NewBackend()
				c.CredentialsFn = func(context.Context) (vpn.Credentials, error) {
					return vpn.Credentials{Username: "mock", Password: "mock"}, nil
				}

				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				if err := c.Connect(ctx); err != nil {
					cancel()
					t.Fatalf("cycle %d: connect: %v", cycle, err)
				}
				if got := waitForInboundPackets(c, inFlightPackets, 5*time.Second); got < inFlightPackets {
					cancel()
					t.Fatalf("cycle %d: only %d data-channel packets arrived within 5s, want %d; "+
						"the mock server is not pushing keepalives and this test proves nothing",
						cycle, got, inFlightPackets)
				}
				if err := c.Disconnect(); err != nil {
					cancel()
					t.Fatalf("cycle %d: disconnect: %v", cycle, err)
				}
				if err := c.WaitForDisconnect(); err != nil {
					cancel()
					t.Fatalf("cycle %d: wait for disconnect: %v", cycle, err)
				}
				cancel()

				rep := c.Report()
				if rep == nil {
					t.Fatalf("cycle %d: Report returned nil", cycle)
				}
				if !rep.Outcome.Succeeded {
					t.Errorf("cycle %d: outcome succeeded=false class=%s stage=%s chain=%v",
						cycle, rep.Outcome.Class, rep.Outcome.Stage, rep.Outcome.ErrorChain)
				}
				if n := rep.Counters.DecryptFailures; n != 0 {
					t.Errorf("cycle %d: %d data packets failed to decrypt; a teardown that "+
						"drops the keys before the read loop stops looks exactly like this",
						cycle, n)
				}
				if cycle == 0 {
					t.Logf("cycle 0: packets_recv=%d bytes_recv=%d decrypt_failures=%d",
						rep.Counters.PacketsRecv, rep.Counters.BytesRecv, rep.Counters.DecryptFailures)
				}
			}
		})
	}
}

// inFlightPackets is how many packets must have arrived before the teardown
// starts. More than one, so that a steady stream is established rather than a
// single packet that happened to land.
const inFlightPackets = 5

// waitForInboundPackets polls the report until the client has decrypted at
// least want data-channel packets. The report rather than Stats: a keepalive is
// dropped in wireToTun before it reaches bytesRecv.
func waitForInboundPackets(c *vpn.Client, want uint64, within time.Duration) uint64 {
	deadline := time.Now().Add(within)
	var seen uint64
	for {
		if rep := c.Report(); rep != nil {
			seen = rep.Counters.PacketsRecv
			if seen >= want {
				return seen
			}
		}
		if time.Now().After(deadline) {
			return seen
		}
		time.Sleep(time.Millisecond)
	}
}
