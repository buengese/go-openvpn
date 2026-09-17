// SPDX-License-Identifier: LGPL-2.1-or-later

//go:build docker

// explicit-exit-notify: the client says goodbye, and the server hears it.
//
// The assertion is on the server's log, because "we wrote 17 bytes" and "the
// peer freed the session" are different claims and only the second one is the
// feature. The negative shapes carry the same weight.
package e2e

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/openlawsvpn/go-openlawsvpn/netstack"
	"github.com/openlawsvpn/go-openlawsvpn/profile"
	"github.com/openlawsvpn/go-openlawsvpn/testenv"
)

// The two markers below are what the pinned servers write when they read an
// OCC_EXIT. The series disagree, so each entry is asserted against its own, and
// both are substrings because set_prefix() prefixes the line.
const (
	// exitNotify24Marker is 2.4's. OpenVPN 2.4.12 src/openvpn/occ.c line 421
	// answers OCC_EXIT by raising SIGTERM with signal_text "remote-exit", and
	// multi.c line 3120 prints it through print_signal() at D_MULTI_LOW. The
	// OCC path leaves the source at SIG_SOURCE_SOFT (sig.h line 32).
	exitNotify24Marker = "SIGTERM[soft,remote-exit] received, client-instance exiting"

	// exitNotify26Marker is 2.6's, and it names the OCC path outright: OpenVPN
	// 2.6.22 src/openvpn/occ.c line 430 logs it at D_STREAM_ERRORS before
	// register_signal(c->sig, SIGUSR1, "remote-exit") on line 431.
	exitNotify26Marker = "OCC exit message received by peer"
)

// exitNotifyClientPrefix is the log line sendExitNotify emits. It says how many
// copies went out, which is the only way from outside to tell one notification
// from a directive's retry count.
const exitNotifyClientPrefix = "vpn: explicit-exit-notify: sent "

// exitNotifyGrace is how long a negative shape waits before concluding that
// nothing was sent. The real thing is immediate, so the grace has only to be
// comfortably shorter than the server's own "keepalive 10 60" timeout, which is
// the other way its session could end.
const exitNotifyGrace = 5 * time.Second

// TestExplicitExitNotify is the whole of the feature, positive and negative.
//
// Five shapes. The two negatives are what make the positives mean anything: the
// same 2.6 entry with the directive removed must produce no such line at all,
// and a TCP entry keeping it must not send, because a closed socket already
// tells the peer everything the notification would.
func TestExplicitExitNotify(t *testing.T) {
	for _, tc := range []struct {
		name  string
		entry string
		// directive is appended to the generated client profile. The matrix
		// entry needs no change: a server reads OCC_EXIT unconditionally,
		// with no option guarding the receive side (occ.c line 421).
		directive string
		// marker is the line this entry's server writes on reading the
		// notification. It differs by pinned series; see above.
		marker string
		// wantSent is how many copies the client should report writing.
		// -1 means it must not report at all, because it must not try.
		wantSent int
		// wantServerNotified is whether the server should log the
		// notification.
		wantServerNotified bool
	}{
		{
			name:               "udp bare directive on 2.6",
			entry:              "v26-gcm256-sha256-plain-udp",
			directive:          "explicit-exit-notify",
			marker:             exitNotify26Marker,
			wantSent:           1,
			wantServerNotified: true,
		},
		{
			name:               "udp retry count on 2.6",
			entry:              "v26-gcm256-sha256-plain-udp",
			directive:          "explicit-exit-notify 5",
			marker:             exitNotify26Marker,
			wantSent:           5,
			wantServerNotified: true,
		},
		{
			name:               "udp bare directive on 2.4",
			entry:              "v24-gcm256-sha256-plain-udp",
			directive:          "explicit-exit-notify",
			marker:             exitNotify24Marker,
			wantSent:           1,
			wantServerNotified: true,
		},
		{
			name:               "udp without the directive",
			entry:              "v26-gcm256-sha256-plain-udp",
			directive:          "",
			marker:             exitNotify26Marker,
			wantSent:           -1,
			wantServerNotified: false,
		},
		{
			name:               "tcp with the directive",
			entry:              "v26-gcm256-sha512-plain-tcp",
			directive:          "explicit-exit-notify 5",
			marker:             exitNotify26Marker,
			wantSent:           -1,
			wantServerNotified: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, ok := testenv.Entry(tc.entry)
			if !ok {
				t.Fatalf("no matrix entry %q", tc.entry)
			}
			if reason := e.ClientUnsupported; reason != "" {
				t.Skipf("client cannot drive %s: %s", tc.entry, reason)
			}
			srv, err := testenv.StartMatrix(e)
			if err != nil {
				t.Skipf("StartMatrix: %v", err)
			}
			t.Cleanup(func() { _ = srv.Stop() })

			text := srv.ClientProfile()
			if tc.directive != "" {
				text += tc.directive + "\n"
			}
			p, err := profile.ParseString(text)
			if err != nil {
				t.Fatalf("ParseString: %v", err)
			}

			// The teardown is idle on purpose: a close taken while the tunnel
			// carries traffic has a teardown defect of its own, with its own
			// test, and measuring that here would not be measuring this feature.
			logs := &exitNotifyLog{}
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()

			tun, err := netstack.Connect(ctx, p, netstack.Options{EventFn: logs.record})
			if err != nil {
				t.Fatalf("Connect to %s: %v", tc.entry, err)
			}

			// The mark is where the server's log stood before the teardown:
			// everything asserted below has to appear after it, or a line left
			// over from an earlier session would do just as well.
			before, err := srv.Logs()
			if err != nil {
				t.Fatalf("Logs before teardown: %v", err)
			}

			if err := tun.Close(); err != nil {
				t.Fatalf("Close on an idle tunnel returned %v, want nil; "+
					"the notification puts a socket write on the teardown "+
					"path and must not reintroduce a teardown error", err)
			}

			// --- what the client says it did -------------------------------
			sent, reported := logs.sent()
			switch {
			case tc.wantSent < 0 && reported:
				t.Errorf("client reported sending %d exit notification(s); it must not "+
					"have tried at all", sent)
			case tc.wantSent >= 0 && !reported:
				t.Errorf("client logged no %q line; it never attempted the notification\n%s",
					strings.TrimSpace(exitNotifyClientPrefix), logs.dump())
			case tc.wantSent >= 0 && sent != tc.wantSent:
				t.Errorf("client sent %d exit notification(s), want %d — the retry count "+
					"is the directive's argument", sent, tc.wantSent)
			}

			// --- what the server did about it ------------------------------
			after, notified := waitForNewServerLine(t, srv, before, tc.marker)
			if notified != tc.wantServerNotified {
				if tc.wantServerNotified {
					t.Fatalf("server never logged %q, so it did not act on the "+
						"notification and is holding the session to its own timeout\n%s",
						tc.marker, testenv.TailLines(after, 25))
				}
				t.Fatalf("server logged %q with no notification expected; the marker "+
					"does not mean what this test claims it means\n%s",
					tc.marker, testenv.TailLines(after, 25))
			}
		})
	}
}

// waitForNewServerLine polls the container log for marker appearing beyond what
// before already held. One timing serves both shapes: a positive returns the
// moment the line lands, a negative spends the whole grace.
func waitForNewServerLine(t *testing.T, srv *testenv.MatrixServer,
	before, marker string,
) (string, bool) {
	t.Helper()

	deadline := time.Now().Add(exitNotifyGrace)
	for {
		logs, err := srv.Logs()
		if err != nil {
			t.Fatalf("Logs: %v", err)
		}
		// docker logs is append-only, so trimming the mark leaves exactly
		// what the container wrote since the tunnel was still up.
		if strings.Contains(strings.TrimPrefix(logs, before), marker) {
			return logs, true
		}
		if time.Now().After(deadline) {
			return logs, false
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// exitNotifyLog collects the client's log events so the teardown can be checked
// from this side too. EventFn is called from the client's own goroutines, hence
// the mutex and hence reading it only after Close has returned.
type exitNotifyLog struct{ eventLog }

// sent returns how many copies the client reported writing, and whether it
// reported at all. A client that never reached the send logs nothing, which is
// what the negative shapes assert.
func (l *exitNotifyLog) sent() (int, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, line := range l.lines {
		rest, ok := strings.CutPrefix(line, exitNotifyClientPrefix)
		if !ok {
			continue
		}
		// "N of M exit notification(s)" — N is what actually went out.
		n, err := strconv.Atoi(strings.Fields(rest)[0])
		if err != nil {
			continue
		}
		return n, true
	}
	return 0, false
}

// dump returns every log line, for a failure that needs to show what the
// client did instead.
func (l *exitNotifyLog) dump() string { return l.eventLog.dump("\n") }
