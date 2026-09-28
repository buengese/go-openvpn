// SPDX-License-Identifier: LGPL-2.1-or-later

//go:build docker || soak

// Helpers used by more than one pass. A helper that only one tag can compile
// is a helper that silently removes tests from the others.

package e2e

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	vpn "github.com/buengese/go-openvpn"
	"github.com/buengese/go-openvpn/netstack"
	"github.com/buengese/go-openvpn/testenv"
)

// requireUnprivileged fails the run if it is not proving what it claims to.
func requireUnprivileged(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("the point of these tests is that they need no privilege; re-run as a normal user")
	}
}

// startResponder starts an HTTP responder inside the container, bound to the
// server's tunnel address on the given port.
//
// That address only exists on the server's tun interface, so nothing on the
// host or on Docker's bridge can route to it: a fetch that succeeds went
// through the tunnel. It forks per connection, so a hundred simultaneous
// fetches are not serialised behind a single accept loop.
func startResponder(t *testing.T, srv *testenv.MatrixServer, port int, body string) {
	t.Helper()

	script := fmt.Sprintf(`use IO::Socket::INET;
$SIG{CHLD} = 'IGNORE';
$| = 1;
my $s = IO::Socket::INET->new(LocalAddr => '%s', LocalPort => %d, Proto => 'tcp',
    Listen => 256, ReuseAddr => 1) or die "listen: $!";
while (my $c = $s->accept()) {
    my $pid = fork();
    if (!defined $pid) { close $c; next; }
    if ($pid == 0) {
        local $/ = "\r\n\r\n";
        my $req = <$c>;
        print $c "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s";
        close $c;
        exit 0;
    }
    close $c;
}`, serverTunIP, port, len(body), body)

	if out, err := exec.Command("docker", "exec", "-d", srv.ContainerID, "perl", "-e", script).CombinedOutput(); err != nil {
		t.Fatalf("start in-container HTTP responder: %v\n%s", err, out)
	}
	// Give perl a moment to bind before the first dial.
	time.Sleep(700 * time.Millisecond)
}

// echoPort is where the in-container responder listens on the tunnel subnet.
const echoPort = 8099

// serverTunIP is the server's address on the tunnel subnet. testenv configures
// the server with "server 10.8.0.0 255.255.255.0" and topology subnet, so the
// server takes .1 and is the only thing on that subnet besides our client.
const serverTunIP = "10.8.0.1"

// rssKB reads this process's resident set size from /proc/self/status.
func rssKB(t *testing.T) int {
	t.Helper()
	f, err := os.Open("/proc/self/status")
	if err != nil {
		t.Fatalf("open /proc/self/status: %v", err)
	}
	defer f.Close() //nolint:errcheck

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "VmRSS:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			break
		}
		kb, convErr := strconv.Atoi(fields[1])
		if convErr != nil {
			t.Fatalf("parse VmRSS %q: %v", line, convErr)
		}
		return kb
	}
	t.Fatal("VmRSS not found in /proc/self/status")
	return 0
}

// eventLog collects the log lines a client emits, for a test that has to say
// what the client did rather than only that it failed. vpn.EventFn is called
// from several client goroutines at once — the data-path pumps, the keepalive
// and inactivity timers, and a renegotiation — so the slice needs a lock.
type eventLog struct {
	mu    sync.Mutex
	lines []string
}

// record is the vpn.EventFn to hand to a client or to netstack.Options.
func (l *eventLog) record(ev vpn.Event) {
	if ev.Type != vpn.EventLog {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, ev.Message)
}

// saw returns the first line containing substr, and whether there was one.
func (l *eventLog) saw(substr string) (string, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, line := range l.lines {
		if strings.Contains(line, substr) {
			return line, true
		}
	}
	return "", false
}

// dump joins every line with sep, for a failure message.
func (l *eventLog) dump(sep string) string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.lines, sep)
}

// getThroughTunnel fetches url over tun and compares the body with want. when
// names the moment for a failure message, so a test that fetches more than
// once says which fetch failed.
func getThroughTunnel(t *testing.T, tun *netstack.Tunnel, url, want, when string) {
	t.Helper()

	client := &http.Client{
		Transport: &http.Transport{DialContext: tun.DialContext},
		Timeout:   20 * time.Second,
	}
	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("GET %s %s: %v", url, when, err)
	}
	defer resp.Body.Close() //nolint:errcheck

	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body %s: %v", when, err)
	}
	if string(got) == want {
		return
	}
	// A long body is one a caller chose for its content — an incompressible
	// run, a maximally compressible one — and printing it buries the failure.
	// The lengths are the diagnostic there.
	if len(want) > 64 {
		t.Fatalf("body %s differs from what the container served: %d bytes back, %d sent. "+
			"A framing byte in the wrong place produces packets that decrypt cleanly "+
			"and mean nothing, and this is where that shows up", when, len(got), len(want))
	}
	t.Fatalf("body %s = %q, want %q", when, got, want)
}
