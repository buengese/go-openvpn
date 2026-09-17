// SPDX-License-Identifier: LGPL-2.1-or-later

//go:build soak

// The soak: a tunnel that still works an hour later.
//
// An hour of an idle tunnel is an hour of nothing: a tunnel whose data channel
// has silently stopped stays "up" indefinitely and passes any liveness check
// you care to write. So all four of these are asserted throughout, not merely
// at the end:
//
//   - traffic actually crosses, in both directions, on every sample
//   - decrypt failures stay at zero — a rekey must not drop a packet
//   - rekeys advance — the tunnel is rotating keys, not just surviving
//   - RSS and goroutine count stay flat — twenty tunnels for an hour is where
//     a per-tunnel leak becomes visible and a single handshake never would
//
// Gated behind OPENLAWSVPN_SOAK and skipped without it:
//
//	OPENLAWSVPN_SOAK=1h go test -tags=soak -timeout 150m \
//	    -run 'TestSoak' ./e2e/
//
// A short duration exercises the harness itself, but only a run long enough to
// contain several renegotiations proves anything about rotation.
package e2e

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/openlawsvpn/go-openlawsvpn/netstack"
	"github.com/openlawsvpn/go-openlawsvpn/profile"
	"github.com/openlawsvpn/go-openlawsvpn/testenv"
)

// soakEntry carries reneg-sec 30 on both ends, so an hour holds roughly a
// hundred renegotiations rather than none, and both directions of renegotiation
// occur on it by construction.
const soakEntry = "v24-gcm256-sha256-plain-udp-reneg30"

// soakDurationEnv gates the whole file. Unset means skip.
const soakDurationEnv = "OPENLAWSVPN_SOAK"

// soakTunnels is the concurrent count for the fleet run. The measurement
// system's shape is many simultaneous sessions, and a leak that matters is a
// leak per tunnel, so one tunnel for an hour cannot find it.
const soakTunnels = 20

// soakSampleInterval is how often the tunnels are exercised and measured.
const soakSampleInterval = 15 * time.Second

// soakWarmup is discarded before the flatness comparison. The heap and the
// goroutine count both climb while tunnels are still coming up, and comparing
// against a reading taken then would call ordinary startup a leak.
const soakWarmup = 90 * time.Second

// soakDuration returns the configured run length, or skips.
func soakDuration(t *testing.T) time.Duration {
	t.Helper()
	raw := os.Getenv(soakDurationEnv)
	if raw == "" {
		t.Skipf("soak is gated: set %s (e.g. %s=1h) and a -timeout to match",
			soakDurationEnv, soakDurationEnv)
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		t.Fatalf("%s=%q: want a positive Go duration, e.g. 1h", soakDurationEnv, raw)
	}
	return d
}

// soakSample is one observation of the whole process and of one tunnel.
type soakSample struct {
	at         time.Time
	rss        int
	goroutines int
	rekeys     uint64
	decrypt    uint64
	bytesRecv  uint64
}

// TestSoakSingleTunnel holds one tunnel open, carrying traffic throughout.
func TestSoakSingleTunnel(t *testing.T) {
	d := soakDuration(t)
	requireUnprivileged(t)
	runSoak(t, 1, d)
}

// TestSoakTwentyTunnels holds twenty open at once, for the same duration. A
// leak of a few hundred kilobytes per tunnel is invisible on one and obvious on
// twenty, and twenty tunnels each renegotiating every thirty seconds is the
// heaviest exercise of the rekey path this suite contains.
func TestSoakTwentyTunnels(t *testing.T) {
	d := soakDuration(t)
	requireUnprivileged(t)
	runSoak(t, soakTunnels, d)
}

// runSoak brings up n tunnels, exercises and measures them for d, and asserts
// the four properties.
func runSoak(t *testing.T, n int, d time.Duration) {
	t.Helper()

	e, ok := testenv.Entry(soakEntry)
	if !ok {
		t.Fatalf("no matrix entry %q", soakEntry)
	}
	if reason := e.ClientUnsupported; reason != "" {
		t.Skipf("client cannot drive %s: %s", soakEntry, reason)
	}
	srv, err := testenv.StartMatrix(e)
	if err != nil {
		t.Skipf("StartMatrix: %v", err)
	}
	t.Cleanup(func() { _ = srv.Stop() })

	const body = "soak"
	startResponder(t, srv, echoPort, body)

	p, err := profile.ParseString(srv.ClientProfile())
	if err != nil {
		t.Fatalf("ParseString: %v", err)
	}

	tunnels := make([]*netstack.Tunnel, 0, n)
	for i := range n {
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		tun, cerr := netstack.Connect(ctx, p, netstack.Options{})
		cancel()
		if cerr != nil {
			for _, up := range tunnels {
				_ = up.Close()
			}
			t.Fatalf("Connect tunnel %d of %d: %v", i+1, n, cerr)
		}
		tunnels = append(tunnels, tun)
	}
	t.Cleanup(func() {
		for _, tun := range tunnels {
			_ = tun.Close()
		}
	})
	t.Logf("%d tunnel(s) up against %s; soaking for %s", n, soakEntry, d)

	clients := make([]*http.Client, n)
	for i, tun := range tunnels {
		clients[i] = &http.Client{
			Transport: &http.Transport{DialContext: tun.DialContext},
			Timeout:   20 * time.Second,
		}
	}
	url := fmt.Sprintf("http://%s:%d/", serverTunIP, echoPort)

	var samples []soakSample
	deadline := time.Now().Add(d)
	started := time.Now()
	ticker := time.NewTicker(soakSampleInterval)
	defer ticker.Stop()

	for time.Now().Before(deadline) {
		<-ticker.C

		// Traffic first, then the reading. Every tunnel, every sample: a
		// tunnel that stopped carrying has to be caught while the run is
		// going rather than inferred from a counter afterwards.
		var wg sync.WaitGroup
		errs := make([]error, n)
		for i, cl := range clients {
			wg.Add(1)
			go func() {
				defer wg.Done()
				resp, ferr := cl.Get(url)
				if ferr != nil {
					errs[i] = ferr
					return
				}
				defer resp.Body.Close() //nolint:errcheck
				got, rerr := io.ReadAll(resp.Body)
				if rerr != nil {
					errs[i] = rerr
					return
				}
				if string(got) != body {
					errs[i] = fmt.Errorf("body = %q, want %q", got, body)
				}
			}()
		}
		wg.Wait()
		for i, ferr := range errs {
			if ferr != nil {
				t.Fatalf("tunnel %d stopped carrying traffic %s into the soak: %v",
					i+1, time.Since(started).Round(time.Second), ferr)
			}
		}

		s := soakSample{at: time.Now(), goroutines: runtime.NumGoroutine(), rss: rssKB(t)}
		for _, tun := range tunnels {
			life := tun.Lifetime()
			rep := tun.Report()
			s.rekeys += life.Rekeys
			s.decrypt += rep.Counters.DecryptFailures
			s.bytesRecv += rep.Counters.BytesRecv
			if life.LastError != nil {
				// A renegotiation that failed and left the session running.
				// Nothing else reports it, which is why Lifetime carries it.
				t.Errorf("tunnel recovered from a transient failure during the soak: %v",
					life.LastError)
			}
		}
		if s.decrypt > 0 {
			t.Fatalf("decrypt failures = %d after %s; a rekey must not drop a packet, "+
				"and zero is the assertion rather than 'few'",
				s.decrypt, time.Since(started).Round(time.Second))
		}
		samples = append(samples, s)
	}

	if len(samples) < 4 {
		t.Fatalf("only %d samples in %s; the soak needs a duration that holds "+
			"several sample intervals of %s", len(samples), d, soakSampleInterval)
	}

	first, last := samples[0], samples[len(samples)-1]
	t.Logf("soak over %s, %d sample(s), %d tunnel(s):", d, len(samples), n)
	t.Logf("  rekeys      %d → %d", first.rekeys, last.rekeys)
	t.Logf("  decrypt     %d throughout", last.decrypt)
	t.Logf("  bytes recv  %d → %d", first.bytesRecv, last.bytesRecv)
	t.Logf("  rss KB      %d → %d", first.rss, last.rss)
	t.Logf("  goroutines  %d → %d", first.goroutines, last.goroutines)

	// Rekeys must advance. Two is the floor, and a run long enough to be
	// worth calling a soak produces far more; a run that produced none soaked
	// an idle key epoch and proved nothing about rotation.
	if got := last.rekeys - first.rekeys; got < 2 {
		t.Errorf("rekeys advanced by %d across the soak (%d → %d); with reneg-sec 30 "+
			"a run of %s should hold many, and fewer than two means key rotation "+
			"was not exercised", got, first.rekeys, last.rekeys, d)
	}

	// Traffic must have kept crossing. The per-sample fetch already proves
	// this, but the counter is the independent witness: a fetch that somehow
	// succeeded without the tunnel moving bytes would show up here.
	if last.bytesRecv <= first.bytesRecv {
		t.Errorf("received bytes did not increase across the soak (%d → %d)",
			first.bytesRecv, last.bytesRecv)
	}

	assertFlat(t, "RSS KB", samples, func(s soakSample) int { return s.rss })
	assertFlat(t, "goroutines", samples, func(s soakSample) int { return s.goroutines })
}

// assertFlat compares the post-warm-up baseline against the tail of the run.
//
// The comparison is between medians of a window at each end rather than between
// two single readings, because both quantities are noisy: one GC cycle or one
// in-flight fetch moves either of them. The allowance is proportional and
// generous on purpose — this is looking for something that grows without bound,
// and a tight bound here would only make the soak flaky.
func assertFlat(t *testing.T, what string, samples []soakSample, get func(soakSample) int) {
	t.Helper()

	// Discard the warm-up: tunnels coming up allocate, and comparing against
	// a reading taken mid-startup calls that a leak.
	start := samples[0].at
	var settled []soakSample
	for _, s := range samples {
		if s.at.Sub(start) >= soakWarmup {
			settled = append(settled, s)
		}
	}
	if len(settled) < 4 {
		t.Logf("%s: only %d samples after the %s warm-up; not asserting flatness "+
			"on a run this short", what, len(settled), soakWarmup)
		return
	}

	window := len(settled) / 4
	if window < 1 {
		window = 1
	}
	base := medianOf(settled[:window], get)
	tail := medianOf(settled[len(settled)-window:], get)

	// 50% over the settled baseline. A per-tunnel leak compounds over the run
	// and clears this comfortably; ordinary heap and goroutine churn does not.
	limit := base + base/2
	t.Logf("  %-11s baseline %d → tail %d (limit %d)", what, base, tail, limit)
	if tail > limit {
		t.Errorf("%s grew from %d to %d across the soak, past the %d allowance; "+
			"that is the shape of a per-tunnel leak rather than churn",
			what, base, tail, limit)
	}
}

// medianOf returns the median of a window, which is what makes a noisy
// quantity comparable at two points in a run.
func medianOf(window []soakSample, get func(soakSample) int) int {
	vals := make([]int, 0, len(window))
	for _, s := range window {
		vals = append(vals, get(s))
	}
	for i := 1; i < len(vals); i++ {
		for j := i; j > 0 && vals[j] < vals[j-1]; j-- {
			vals[j], vals[j-1] = vals[j-1], vals[j]
		}
	}
	return vals[len(vals)/2]
}
