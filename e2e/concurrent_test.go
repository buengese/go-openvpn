// SPDX-License-Identifier: LGPL-2.1-or-later

//go:build docker

// Concurrency at scale: an unprivileged process opening many tunnels at once,
// with no global state to collide over.
package e2e

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/openlawsvpn/go-openlawsvpn/netstack"
	"github.com/openlawsvpn/go-openlawsvpn/profile"
	"github.com/openlawsvpn/go-openlawsvpn/testenv"
)

// scaleEntry is the entry the scale runs use. UDP, because a hundred
// simultaneous TCP transports would measure the server's accept loop rather
// than our concurrency.
const scaleEntry = "v26-gcm256-sha256-plain-udp"

// tunnelResult is one tunnel's outcome in a scale run.
type tunnelResult struct {
	index     int
	localAddr string
	handshake time.Duration
	err       error
}

// runConcurrentTunnels opens n tunnels at once, has each fetch through its own
// stack, and returns what happened to each. The tunnels are left open and
// belong to the caller, so "how many are live at once" stays answerable.
func runConcurrentTunnels(t *testing.T, p *profile.Profile, n int, body string, ramp time.Duration) ([]tunnelResult, []*netstack.Tunnel, time.Duration) {
	t.Helper()

	results := make([]tunnelResult, n)
	tunnels := make([]*netstack.Tunnel, n)

	start := time.Now()
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i].index = i
			// The ramp spreads handshake starts. It is a concession to the
			// server, not to our client — see hundredRamp.
			if ramp > 0 {
				time.Sleep(time.Duration(i) * ramp)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
			defer cancel()

			dialStart := time.Now()
			tun, err := netstack.Connect(ctx, p, netstack.Options{
				DeviceName: fmt.Sprintf("scale%03d", i),
			})
			results[i].handshake = time.Since(dialStart)
			if err != nil {
				results[i].err = fmt.Errorf("connect: %w", err)
				return
			}
			tunnels[i] = tun
			if addrs := tun.LocalAddresses(); len(addrs) > 0 {
				results[i].localAddr = addrs[0].String()
			}

			if body != "" {
				if err := fetchThrough(tun, body); err != nil {
					results[i].err = err
				}
			}
		}()
	}
	wg.Wait()
	return results, tunnels, time.Since(start)
}

// fetchThrough performs one HTTP fetch through a tunnel and checks the body.
func fetchThrough(tun *netstack.Tunnel, want string) error {
	client := &http.Client{
		Transport: &http.Transport{
			DialContext:       tun.DialContext,
			DisableKeepAlives: true,
		},
		Timeout: 60 * time.Second,
	}
	resp, err := client.Get(fmt.Sprintf("http://%s:%d/", serverTunIP, echoPort))
	if err != nil {
		return fmt.Errorf("fetch: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read: %w", err)
	}
	if string(got) != want {
		return fmt.Errorf("body = %q, want %q", got, want)
	}
	return nil
}

// summarise reports how many tunnels succeeded and the handshake spread.
func summarise(t *testing.T, results []tunnelResult) (ok int, slowest time.Duration) {
	t.Helper()
	addrs := map[string]int{}
	for _, r := range results {
		if r.err != nil {
			if ok < len(results) { // only log the first few, to keep output readable
				t.Logf("tunnel %d failed: %v", r.index, r.err)
			}
			continue
		}
		ok++
		if r.handshake > slowest {
			slowest = r.handshake
		}
		addrs[r.localAddr]++
	}
	for addr, n := range addrs {
		if n > 1 && addr != "" {
			t.Errorf("address %s was assigned to %d tunnels; the pool collided", addr, n)
		}
	}
	return ok, slowest
}

// TestConcurrentTunnels opens n tunnels at once, has each fetch through its own
// stack, and requires every one of them to be live at the same moment. The
// tunnels are held open rather than closed after each fetch, because "n
// concurrent tunnels" is a claim about how many are up at once.
func TestConcurrentTunnels(t *testing.T) {
	for _, tc := range []struct {
		name string
		n    int
		// ramp spreads the start of the handshakes. It is a concession to
		// the server, not to our client — see hundredRamp.
		ramp time.Duration
		// skipShort keeps the long run out of a -short invocation.
		skipShort bool
	}{
		{name: "20", n: 20, ramp: 0},
		{name: "100", n: 100, ramp: hundredRamp, skipShort: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requireUnprivileged(t)
			if tc.skipShort && testing.Short() {
				t.Skipf("skipping the %d-tunnel run in short mode", tc.n)
			}
			srv, p := scaleFixture(t)

			body := fmt.Sprintf("scale-%d", tc.n)
			startResponder(t, srv, echoPort, body)

			results, tunnels, wall := runConcurrentTunnels(t, p, tc.n, body, tc.ramp)
			live := 0
			for _, tun := range tunnels {
				if tun != nil {
					live++
				}
			}
			ok, slowest := summarise(t, results)
			t.Logf("SCALE %d: %d/%d completed, %d live simultaneously, in %s (slowest handshake %s)",
				tc.n, ok, tc.n, live, wall.Round(time.Millisecond), slowest.Round(time.Millisecond))

			for _, tun := range tunnels {
				if tun != nil {
					_ = tun.Close()
				}
			}

			if ok != tc.n {
				t.Errorf("%d of %d tunnels completed", ok, tc.n)
			}
			if live != tc.n {
				t.Errorf("%d tunnels were live simultaneously, want %d", live, tc.n)
			}
		})
	}
}

// hundredRamp spreads the start of a hundred handshakes over five seconds.
//
// It is there for the server, not for us: started in one instant, a hundred
// handshakes saturate the single openvpn process serving them, which drops
// control packets until the slowest attempts blow past their deadline. The
// hundred that do come up stay up, so a ramp is the honest way to measure how
// many this process holds at once.
const hundredRamp = 50 * time.Millisecond

// TestIdleTunnelRSS measures steady-state resident memory per idle tunnel. One
// stack per tunnel is settled, so this is a sanity check rather than a decision
// input.
func TestIdleTunnelRSS(t *testing.T) {
	requireUnprivileged(t)
	if runtime.GOOS != "linux" {
		t.Skip("RSS is read from /proc; Linux only")
	}
	srv, p := scaleFixture(t)
	_ = srv

	const n = 50

	// One warm-up tunnel so that first-use allocations are not attributed to
	// the measured set.
	warm, err := netstack.Connect(context.Background(), p, netstack.Options{})
	if err != nil {
		t.Fatalf("warm-up connect: %v", err)
	}
	_ = warm.Close()
	settleRSS()
	before := rssKB(t)

	_, tunnels, _ := runConcurrentTunnels(t, p, n, "", hundredRamp)
	live := 0
	for _, tun := range tunnels {
		if tun != nil {
			live++
		}
	}
	if live != n {
		t.Fatalf("only %d of %d tunnels came up; RSS would not be comparable", live, n)
	}

	settleRSS()
	after := rssKB(t)

	for _, tun := range tunnels {
		if tun != nil {
			_ = tun.Close()
		}
	}

	perTunnel := float64(after-before) / float64(n)
	t.Logf("SCALE RSS: %d kB before, %d kB with %d idle tunnels, %.0f kB per tunnel",
		before, after, n, perTunnel)
	if after <= before {
		t.Logf("RSS did not grow measurably; the allocator likely served the tunnels from existing arenas")
	}
}

// scaleFixture starts one matrix server and returns it with a parsed profile.
func scaleFixture(t *testing.T) (*testenv.MatrixServer, *profile.Profile) {
	t.Helper()
	e, ok := testenv.Entry(scaleEntry)
	if !ok {
		t.Fatalf("no matrix entry %q", scaleEntry)
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
	return srv, p
}

// settleRSS gives the runtime a chance to return freed memory before a reading.
func settleRSS() {
	for range 4 {
		runtime.GC()
		time.Sleep(400 * time.Millisecond)
	}
}
