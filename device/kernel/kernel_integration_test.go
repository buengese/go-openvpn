//go:build privileged && !android && !ios && !darwin

// SPDX-License-Identifier: LGPL-2.1-or-later

// Privileged tests for the kernel backend.
//
// They create a real TUN interface and write to the host route table, so they
// are guarded twice: by root, and by an explicit opt-in environment variable.
//
// Run with:
//
//	sudo GO_OPENVPN_PRIVILEGED_TESTS=1 \
//	  go test -v -tags=privileged -timeout=60s ./device/kernel/
//
// What they prove: Open either returns a usable Device or returns an error
// having left `ip link` and `ip route` exactly as it found them.
package kernel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/buengese/go-openvpn/device"
	"github.com/buengese/go-openvpn/routing"
)

// privilegedEnv is the opt-in switch for every test in this file. Root alone
// is not enough: a root test run in a container should not silently start
// rewriting that container's route table.
const privilegedEnv = "GO_OPENVPN_PRIVILEGED_TESTS"

// requirePrivileged skips unless the test may create a TUN interface and write
// host routes.
func requirePrivileged(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires root (CAP_NET_ADMIN) — re-run with sudo")
	}
	if os.Getenv(privilegedEnv) == "" {
		t.Skipf("set %s=1 to opt in: these tests create a TUN interface and write the host route table", privilegedEnv)
	}
	if _, err := os.Stat("/dev/net/tun"); err != nil {
		t.Skipf("/dev/net/tun not present: %v", err)
	}
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("iproute2 (ip) not in PATH")
	}
}

// hostState is what the tests assert has not changed: the set of interfaces
// and the IPv4 route table, as `ip` reports them.
type hostState struct {
	links  string
	routes string
}

// captureHostState reads `ip link` and `ip route`.
func captureHostState(t *testing.T) hostState {
	t.Helper()
	return hostState{links: ipLinkNames(t), routes: ipRoutes(t)}
}

// assertHostUnchanged fails the test if the host differs from before.
func assertHostUnchanged(t *testing.T, before hostState) {
	t.Helper()
	after := captureHostState(t)
	if after.links != before.links {
		t.Errorf("ip link changed:\nbefore:\n%s\nafter:\n%s", before.links, after.links)
	}
	if after.routes != before.routes {
		t.Errorf("ip route changed:\nbefore:\n%s\nafter:\n%s", before.routes, after.routes)
	}
}

// ipLinkNames reduces `ip link` to the sorted set of interface names. Flags
// such as LOWER_UP flicker for reasons unrelated to this package; a leaked TUN
// device always shows up as a new name.
func ipLinkNames(t *testing.T) string {
	t.Helper()
	var names []string
	for _, line := range strings.Split(runIP(t, "-o", "link", "show"), "\n") {
		fields := strings.SplitN(line, ":", 3)
		if len(fields) < 3 {
			continue
		}
		name, _, _ := strings.Cut(strings.TrimSpace(fields[1]), "@")
		names = append(names, name)
	}
	sort.Strings(names)
	return strings.Join(names, "\n")
}

// ipRoutes returns `ip route show` with its lines sorted, so an unrelated
// reordering by the kernel does not read as a change.
func ipRoutes(t *testing.T) string {
	t.Helper()
	var lines []string
	for _, line := range strings.Split(runIP(t, "route", "show"), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			lines = append(lines, line)
		}
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n")
}

// runIP runs iproute2 and returns its stdout.
func runIP(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command("ip", args...).Output()
	if err != nil {
		t.Fatalf("ip %s: %v", strings.Join(args, " "), err)
	}
	return string(out)
}

// TestOpenUnwindsAfterConfigureFailure pins that an Open failing mid-configure
// leaves `ip link` and `ip route` unchanged. The failure is forced with an IPv6
// literal in the IPv4 ifconfig slot, which SIOCSIFADDR rejects after tun.Open
// has already succeeded.
func TestOpenUnwindsAfterConfigureFailure(t *testing.T) {
	requirePrivileged(t)
	before := captureHostState(t)

	p := device.Params{
		Push: &routing.PushOptions{
			Topology: routing.TopologyNet30,
			Ifconfig: &routing.Ifconfig{
				Local:   net.ParseIP("fd00::1"),
				Gateway: net.ParseIP("fd00::2"),
			},
		},
		MTU: 1400,
	}

	var b Backend
	dev, err := b.Open(context.Background(), p)
	if err == nil {
		dev.Close() //nolint:errcheck
		t.Fatal("Open accepted an IPv6 address in the IPv4 ifconfig slot; expected Configure to fail")
	}
	if dev != nil {
		t.Fatalf("Open returned a device alongside error %v", err)
	}
	if !strings.Contains(err.Error(), "configure TUN device") {
		t.Errorf("error = %v, want it to name the configure step", err)
	}

	assertHostUnchanged(t, before)
}

// TestOpenUnwindsBypassRouteAfterApplyRoutesFailure covers the other half of
// the all-or-nothing promise: the redirect-gateway bypass route goes in before
// ApplyRoutes, so a route failure has to take it back out again.
func TestOpenUnwindsBypassRouteAfterApplyRoutesFailure(t *testing.T) {
	requirePrivileged(t)

	// 203.0.113.0/24 is TEST-NET-3 (RFC 5737) — reserved, safe to stand in
	// for the VPN server the bypass route points at.
	serverIP := net.IPv4(203, 0, 113, 42)
	gw, err := routing.LookupGateway(serverIP)
	if err != nil {
		t.Skipf("LookupGateway: %v", err)
	}
	if gw == nil {
		t.Skip("no default gateway — direct-link host, bypass route not applicable")
	}

	before := captureHostState(t)

	p := device.Params{
		Push: &routing.PushOptions{
			Topology: routing.TopologySubnet,
			Ifconfig: &routing.Ifconfig{
				Local:   net.IPv4(10, 99, 8, 6),
				Mask:    net.CIDRMask(24, 32),
				Gateway: net.IPv4(10, 99, 8, 1),
			},
			// 192.0.2.1 is TEST-NET-1, on no host interface, so the kernel
			// rejects this route with ENETUNREACH — after the bypass route
			// is in and before ApplyRoutes installs 0.0.0.0/0.
			Routes: []routing.Route{{
				Network: net.IPv4(198, 51, 100, 0),
				Mask:    net.CIDRMask(24, 32),
				Gateway: net.IPv4(192, 0, 2, 1),
			}},
			RedirectGateway: true,
		},
		MTU:      1400,
		ServerIP: serverIP,
	}

	var logged []string
	b := Backend{Logf: func(format string, args ...any) {
		logged = append(logged, fmt.Sprintf(format, args...))
	}}

	dev, openErr := b.Open(context.Background(), p)
	if openErr == nil {
		dev.Close() //nolint:errcheck
		t.Skip("the kernel accepted a route via an unreachable gateway on this host; cannot force the failure")
	}
	if dev != nil {
		t.Fatalf("Open returned a device alongside error %v", openErr)
	}
	if !strings.Contains(openErr.Error(), "apply routes") {
		t.Fatalf("error = %v, want it to name the apply-routes step", openErr)
	}

	var bypassInstalled bool
	for _, msg := range logged {
		if strings.HasPrefix(msg, "vpn: redirect-gateway bypass route:") {
			bypassInstalled = true
		}
	}
	if !bypassInstalled {
		t.Skipf("no bypass route was installed, so there is nothing to unwind; log: %v", logged)
	}

	assertHostUnchanged(t, before)
}

// TestOpenAndCloseRestoresHostState is the happy path: a device comes up,
// carries the pushed routes, and Close puts the host back. It also pins that
// ReadPacket honours a cancelled context and returns when one expires.
func TestOpenAndCloseRestoresHostState(t *testing.T) {
	requirePrivileged(t)
	before := captureHostState(t)

	p := device.Params{
		Push: &routing.PushOptions{
			Topology: routing.TopologySubnet,
			Ifconfig: &routing.Ifconfig{
				Local:   net.IPv4(10, 99, 8, 6),
				Mask:    net.CIDRMask(24, 32),
				Gateway: net.IPv4(10, 99, 8, 1),
			},
			Routes: []routing.Route{{
				Network: net.IPv4(10, 99, 9, 0),
				Mask:    net.CIDRMask(24, 32),
			}},
		},
		MTU: 1400,
	}

	var b Backend
	dev, err := b.Open(context.Background(), p)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	// Close twice: the contract requires idempotency, and a failure below
	// must not leave the interface behind.
	defer dev.Close() //nolint:errcheck

	if dev.MTU() != 1400 {
		t.Errorf("MTU() = %d, want 1400", dev.MTU())
	}
	if _, ifErr := net.InterfaceByName(dev.Name()); ifErr != nil {
		t.Fatalf("interface %q not found after Open: %v", dev.Name(), ifErr)
	}
	if got := ipRoutes(t); !strings.Contains(got, "10.99.9.0/24") {
		t.Errorf("pushed route 10.99.9.0/24 missing from the route table:\n%s", got)
	}

	// A context that has already ended is reported without reading.
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	buf := make([]byte, 2048)
	if _, rerr := dev.ReadPacket(cancelled, buf); !errors.Is(rerr, context.Canceled) {
		t.Errorf("ReadPacket(cancelled) = %v, want context.Canceled", rerr)
	}

	// A fresh interface is not silent — the kernel emits IPv6 router
	// solicitations — so drain until the context ends. readTimeout is
	// 500 ms, so a 1200 ms budget covers two passes of the deadline loop.
	const budget = 1200 * time.Millisecond
	deadline, cancelDeadline := context.WithTimeout(context.Background(), budget)
	defer cancelDeadline()
	start := time.Now()
	var rerr error
	for rerr == nil {
		_, rerr = dev.ReadPacket(deadline, buf)
	}
	if !errors.Is(rerr, context.DeadlineExceeded) {
		t.Errorf("ReadPacket(%v deadline) = %v, want context.DeadlineExceeded", budget, rerr)
	}
	if elapsed := time.Since(start); elapsed < budget || elapsed > budget+2*time.Second {
		t.Errorf("ReadPacket returned after %v; want it to wait out the %v deadline and no longer", elapsed, budget)
	}

	if err := dev.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := dev.Close(); err != nil {
		t.Fatalf("Close (second call): %v", err)
	}

	assertHostUnchanged(t, before)
}
