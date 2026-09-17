//go:build privileged && !android && !ios && !darwin

// Privileged tests for the Linux TUN device.
//
// Every test here opens /dev/net/tun and configures a real interface, so the
// whole file carries the `privileged` tag rather than skipping test by test;
// `make test-privileged` is where this coverage runs.
//
// Run with:
//
//	sudo OPENLAWSVPN_PRIVILEGED_TESTS=1 \
//	  go test -v -tags=privileged -timeout=60s ./tun/
package tun

import (
	"net"
	"os"
	"testing"
)

// privilegedEnv is the opt-in switch for every test in this file. Root alone
// is not enough: a root test run in a container should not silently start
// creating interfaces in that container.
const privilegedEnv = "OPENLAWSVPN_PRIVILEGED_TESTS"

// requirePrivileged skips unless the test may open /dev/net/tun and configure
// the interface it gets back.
func requirePrivileged(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires root (CAP_NET_ADMIN) — re-run with sudo")
	}
	if os.Getenv(privilegedEnv) == "" {
		t.Skipf("set %s=1 to opt in: these tests create a TUN interface on the host", privilegedEnv)
	}
	if _, err := os.Stat("/dev/net/tun"); err != nil {
		t.Skipf("/dev/net/tun not present: %v", err)
	}
}

// deviceMTU asks the kernel what MTU an interface is holding. It is the only
// place Configure's effect can be observed from: Config is the caller's copy
// and says nothing about what the ioctl did with it.
func deviceMTU(t *testing.T, name string) int {
	t.Helper()
	iface, err := net.InterfaceByName(name)
	if err != nil {
		t.Fatalf("InterfaceByName(%q): %v", name, err)
	}
	return iface.MTU
}

// TestOpenAllocatesAnInterface checks that Open returns a device the kernel
// has actually named, rather than a zero Device and a nil error.
func TestOpenAllocatesAnInterface(t *testing.T) {
	requirePrivileged(t)

	dev, err := Open("")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer dev.Close() //nolint:errcheck

	name := dev.Name()
	if name == "" {
		t.Fatal("expected non-empty interface name")
	}
	if _, err := net.InterfaceByName(name); err != nil {
		t.Errorf("Open named %q, which the kernel does not have: %v", name, err)
	}
	t.Logf("allocated TUN interface: %s", name)
}

// TestConfigure runs Open + Configure on /dev/net/tun.
func TestConfigure(t *testing.T) {
	requirePrivileged(t)

	dev, err := Open("")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer dev.Close() //nolint:errcheck

	cfg := Config{
		LocalIP: net.ParseIP("10.99.0.1"),
		PeerIP:  net.ParseIP("10.99.0.2"),
		MTU:     1400,
	}
	if err := dev.Configure(cfg); err != nil {
		t.Fatalf("Configure: %v", err)
	}
	t.Logf("configured %s: local=%s peer=%s mtu=%d",
		dev.Name(), cfg.LocalIP, cfg.PeerIP, cfg.MTU)
}

// TestConfig_DefaultMTU verifies that a zero MTU is treated as 1500, reading it
// back from the kernel. Reading 1500 back is only evidence if the interface was
// not already at 1500, and a fresh tun device is, so the MTU is moved off the
// default first.
func TestConfig_DefaultMTU(t *testing.T) {
	requirePrivileged(t)

	dev, err := Open("")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer dev.Close() //nolint:errcheck

	cfg := Config{
		LocalIP: net.ParseIP("10.99.1.1"),
		PeerIP:  net.ParseIP("10.99.1.2"),
		MTU:     1400,
	}
	if err := dev.Configure(cfg); err != nil {
		t.Fatalf("Configure with MTU 1400: %v", err)
	}
	if got := deviceMTU(t, dev.Name()); got != 1400 {
		t.Fatalf("MTU = %d after configuring 1400, want 1400: the ioctl did not take", got)
	}

	cfg.MTU = 0
	if err := dev.Configure(cfg); err != nil {
		t.Fatalf("Configure with zero MTU: %v", err)
	}
	if got := deviceMTU(t, dev.Name()); got != 1500 {
		t.Errorf("MTU = %d after configuring 0, want 1500: the zero-MTU default was not applied", got)
	}
}
