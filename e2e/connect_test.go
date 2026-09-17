// SPDX-License-Identifier: LGPL-2.1-or-later

//go:build docker

// The tunnel as a consumer actually uses it, plus the fixtures every other
// integration test in this package is built from.
//
// These run against the pinned Docker matrix and need no privilege. The
// endpoints they reach live on the tunnel subnet inside the server container,
// so a connection that reached one cannot have gone round the tunnel.
package e2e

import (
	"context"
	"errors"
	"fmt"
	"net"
	"runtime"
	"strings"
	"testing"
	"time"

	vpn "github.com/openlawsvpn/go-openlawsvpn"
	"github.com/openlawsvpn/go-openlawsvpn/diag"
	"github.com/openlawsvpn/go-openlawsvpn/netstack"
	"github.com/openlawsvpn/go-openlawsvpn/profile"
	"github.com/openlawsvpn/go-openlawsvpn/testenv"
)

// dataPathEntry is the simplest entry that exercises a stream transport end to
// end: 2.6 offers EKM, GCM and a plain control channel, so nothing about the
// negotiation is in the way of whatever the test is really about.
const dataPathEntry = "v26-gcm256-sha512-plain-tcp"

// startMatrixTunnel brings up a matrix server and a netstack tunnel to it.
//
// The levers come from the entry rather than from the caller, because the entry
// is what decides whether they are needed: a FlowUserPass profile with no
// CredentialsFn is refused at StageParse before a socket is opened, and there
// is no server-side way to configure P_DATA_V1 — every pinned version decides
// it from the client's IV_PROTO, so an entry driven without vpn.WithholdDataV2
// is served P_DATA_V2 and the test measures the wrong format.
func startMatrixTunnel(t *testing.T, entry string) (*testenv.MatrixServer, *netstack.Tunnel) {
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

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	tun, err := netstack.Connect(ctx, p, matrixOptions(e))
	if err != nil {
		t.Fatalf("Connect to %s: %v", entry, err)
	}
	t.Cleanup(func() { _ = tun.Close() })
	return srv, tun
}

// matrixOptions returns the Connect options an entry's own axes call for. It is
// the one place that reads an entry's levers, so a tunnel opened by any test in
// this package is driven the same way as one opened by any other.
func matrixOptions(e testenv.MatrixEntry) netstack.Options {
	var opts netstack.Options
	if e.DataV1 {
		opts.DataV2 = vpn.WithholdDataV2
	}
	if e.Auth.RequiresCredentials() {
		opts.CredentialsFn = func(context.Context) (vpn.Credentials, error) {
			return vpn.Credentials{
				Username: testenv.MatrixUsername,
				Password: testenv.MatrixPassword,
			}, nil
		}
	}
	return opts
}

// fetchThroughTunnel serves a body inside the container, on the tunnel subnet
// only, and fetches it through the tunnel with an ordinary http.Client built on
// Tunnel.DialContext. A response that arrived cannot have gone round the tunnel
// and cannot have been sent in a format the peer discards, which makes it the
// one assertion that a *working* data channel exists.
func fetchThroughTunnel(t *testing.T, srv *testenv.MatrixServer, tun *netstack.Tunnel, port int, body string) {
	t.Helper()
	startResponder(t, srv, port, body)

	url := fmt.Sprintf("http://%s:%d/", serverTunIP, port)
	getThroughTunnel(t, tun, url, body, "through the tunnel")
}

// assertCarriedBothWays checks the record that says plaintext crossed in both
// directions, and returns it so the caller can log its duration. StageData
// completes only once a packet has gone each way, so a completed record
// carrying a duration is the both-ways proof; the counters are the independent
// witness, maintained by different code than the stage timeline.
func assertCarriedBothWays(t *testing.T, tun *netstack.Tunnel) *diag.StageRecord {
	t.Helper()

	rep := tun.Report()
	var data *diag.StageRecord
	for i := range rep.Stages {
		if rep.Stages[i].Stage == diag.StageData {
			data = &rep.Stages[i]
		}
	}
	if data == nil {
		t.Fatal("no StageData record")
	}
	if data.Duration <= 0 {
		t.Errorf("StageData duration is %v; plaintext crossed, so it should be complete", data.Duration)
	}
	if rep.Counters.BytesSent == 0 || rep.Counters.BytesRecv == 0 {
		t.Errorf("counters show no traffic both ways: %+v", rep.Counters)
	}
	return data
}

// TestResolverDoesNotReachTheHost proves the resolver never falls back, by
// pushing a DNS server address that nothing can answer and asking for a name
// the host can certainly resolve, so a fallback would be visible as a success.
func TestResolverDoesNotReachTheHost(t *testing.T) {
	_, tun := startMatrixTunnel(t, dataPathEntry)

	// Sanity: the host really can resolve this, so the negative result below
	// means something.
	if _, err := net.DefaultResolver.LookupHost(context.Background(), "localhost"); err != nil {
		t.Skipf("the host cannot resolve localhost either, so this proves nothing: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	_, err := tun.LookupHost(ctx, "localhost")
	if err == nil {
		t.Fatal("resolution succeeded through a tunnel whose server pushed no DNS; it fell back to the host")
	}
	if !errors.Is(err, netstack.ErrNoPushedDNS) {
		t.Errorf("error = %v, want ErrNoPushedDNS", err)
	}
	t.Logf("resolver refused as designed: %v", err)
}

// TestCloseIsIdempotentAndLeaksNothing is the tunnel lifecycle at the API
// level: fifty open/close cycles leave the goroutine count where they found it.
func TestCloseIsIdempotentAndLeaksNothing(t *testing.T) {
	e, ok := testenv.Entry(dataPathEntry)
	if !ok {
		t.Fatalf("no matrix entry %q", dataPathEntry)
	}
	srv, err := testenv.StartMatrix(e)
	if err != nil {
		t.Skipf("StartMatrix: %v", err)
	}
	defer srv.Stop() //nolint:errcheck

	p, err := profile.ParseString(srv.ClientProfile())
	if err != nil {
		t.Fatalf("ParseString: %v", err)
	}

	// One warm-up cycle first: the first connection populates caches and
	// starts runtime workers that would otherwise read as a leak.
	warm, err := netstack.Connect(context.Background(), p, netstack.Options{})
	if err != nil {
		t.Fatalf("warm-up Connect: %v", err)
	}
	if err := warm.Close(); err != nil {
		t.Fatalf("warm-up Close: %v", err)
	}
	if err := warm.Close(); err != nil {
		t.Errorf("second Close should be a no-op, got: %v", err)
	}
	settle()
	before := runtime.NumGoroutine()

	const cycles = 50
	for i := range cycles {
		tun, connErr := netstack.Connect(context.Background(), p, netstack.Options{})
		if connErr != nil {
			t.Fatalf("cycle %d: Connect: %v", i, connErr)
		}
		if closeErr := tun.Close(); closeErr != nil {
			t.Fatalf("cycle %d: Close: %v", i, closeErr)
		}
	}
	settle()
	after := runtime.NumGoroutine()

	// A small drift is normal — the runtime keeps workers around — so this
	// looks for a per-cycle leak rather than exact equality.
	if after > before+10 {
		t.Errorf("goroutines grew from %d to %d over %d cycles", before, after, cycles)
	}
	t.Logf("goroutines: %d before, %d after %d cycles", before, after, cycles)
}

// TestReportSurvivesAFailedConnect is the measurement property carried through
// the wrapper: an attempt that fails still explains itself.
func TestReportSurvivesAFailedConnect(t *testing.T) {
	// A profile pointing at a closed port: it parses, and then fails to dial.
	p, err := profile.ParseString(strings.Join([]string{
		"client", "dev tun", "proto tcp", "remote 127.0.0.1 1", "nobind",
	}, "\n"))
	if err != nil {
		t.Fatalf("ParseString: %v", err)
	}
	// Incidental to the property under test, but required to reach the dial:
	// the client refuses a profile with no usable CA at StageParse, in every
	// preflight mode, rather than building an unverified tunnel.
	pki, err := testenv.NewMockPKI(t.TempDir())
	if err != nil {
		t.Fatalf("generate a CA: %v", err)
	}
	p.CA = pki.CAPEM

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	tun, rep, connErr := netstack.ConnectWithReport(ctx, p, netstack.Options{
		// Also incidental, one stage further on: a profile with no client
		// certificate is FlowUserPass, and a FlowUserPass attempt with nothing
		// to present is refused at StageParse rather than dialing. Threading it
		// here proves the Options field reaches the client.
		CredentialsFn: func(context.Context) (vpn.Credentials, error) {
			return vpn.Credentials{Username: "user", Password: "pass"}, nil
		},
	})
	if connErr == nil {
		_ = tun.Close()
		t.Fatal("Connect to a closed port succeeded")
	}
	if tun != nil {
		t.Error("a failed Connect returned a non-nil Tunnel")
	}
	if rep == nil {
		t.Fatal("a failed Connect returned no report; a failed attempt explaining " +
			"itself is the whole point of the report")
	}
	if len(rep.Stages) == 0 {
		t.Error("report has no stages")
	}
	if rep.Outcome.Succeeded {
		t.Error("report says the failed attempt succeeded")
	}
	// A closed port is a transport failure, and the taxonomy exists so that
	// the class implies the next action — here, "the endpoint is down or
	// filtered" rather than anything about our protocol code.
	if rep.Outcome.Class != diag.ClassNetwork {
		t.Errorf("class = %s, want %s for a refused connection", rep.Outcome.Class, diag.ClassNetwork)
	}
	t.Logf("failed attempt still reported: class=%s stage=%s stages=%d",
		rep.Outcome.Class, rep.Outcome.Stage, len(rep.Stages))
}

// settle gives closed tunnels a moment to finish unwinding before goroutines
// are counted.
func settle() {
	for range 3 {
		runtime.GC()
		time.Sleep(300 * time.Millisecond)
	}
}
