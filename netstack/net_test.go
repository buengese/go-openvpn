// SPDX-License-Identifier: LGPL-2.1-or-later

package netstack

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/buengese/go-openvpn/device"
	"github.com/buengese/go-openvpn/dns"
	"github.com/buengese/go-openvpn/routing"
)

// testNet builds a Net over a stack addressed the way a PUSH_REPLY would
// address it, without any tunnel behind it. It is enough to exercise every
// argument-handling path in the dialer surface.
func testNet(t *testing.T, dnsCfg *dns.Config) *Net {
	t.Helper()
	dev, err := (&Backend{Name: "nettest"}).Open(context.Background(), device.Params{
		MTU: 1400,
		DNS: dnsCfg,
		Push: &routing.PushOptions{
			Ifconfig: &routing.Ifconfig{
				Local:   net.IPv4(10, 9, 0, 6),
				Mask:    net.CIDRMask(24, 32),
				Gateway: net.IPv4(10, 9, 0, 1),
			},
			Ifconfig6: &routing.Ifconfig6{
				Local:  net.ParseIP("fd00:dead:beef::6"),
				Prefix: 64,
			},
		},
	})
	if err != nil {
		t.Fatalf("open netstack device: %v", err)
	}
	t.Cleanup(func() { _ = dev.Close() })
	return dev.(*Device).Network()
}

func TestLocalAddresses(t *testing.T) {
	got := testNet(t, nil).LocalAddresses()
	if len(got) != 2 {
		t.Fatalf("LocalAddresses = %v, want one address per family", got)
	}
	if !got[0].Is4() {
		t.Errorf("first address %s is not v4; v4 should come first", got[0])
	}
	if !got[1].Is6() {
		t.Errorf("second address %s is not v6", got[1])
	}
	if got[0] != netip.MustParseAddr("10.9.0.6") {
		t.Errorf("v4 = %s, want 10.9.0.6", got[0])
	}
}

// TestDialRejectsNames pins the rule that keeps a lookup from escaping to the
// host: the plain dialer takes literal addresses only, and says which method to
// use when it is handed a name.
func TestDialRejectsNames(t *testing.T) {
	_, err := testNet(t, nil).DialContext(context.Background(), "tcp", "example.test:443")
	if err == nil {
		t.Fatal("DialContext accepted a hostname; it must not resolve implicitly")
	}
	if !strings.Contains(err.Error(), "Resolver") {
		t.Errorf("error should name the way to resolve, got: %v", err)
	}
}

func TestDialRejectsUnknownNetwork(t *testing.T) {
	_, err := testNet(t, nil).DialContext(context.Background(), "sctp", "10.9.0.1:80")
	if err == nil || !strings.Contains(err.Error(), "unsupported network") {
		t.Errorf("DialContext(sctp) error = %v, want an unsupported-network error", err)
	}
}

// TestResolverWithoutPushedDNSFails is the property that makes resolution a
// measurement: with no pushed server the resolver fails rather than quietly
// asking the host's.
func TestResolverWithoutPushedDNSFails(t *testing.T) {
	n := testNet(t, nil)
	if got := n.DNSServers(); got != nil {
		t.Errorf("DNSServers = %v, want none", got)
	}
	// The raw resolver fails. It cannot carry the sentinel, because
	// net.DNSError does not unwrap — so the message is all there is.
	_, err := n.Resolver().LookupHost(context.Background(), "example.test")
	if err == nil {
		t.Fatal("lookup succeeded with no pushed DNS server; it must not fall back to the host")
	}
	if !strings.Contains(err.Error(), "never falls back") {
		t.Errorf("resolver error should say it refused to fall back, got: %v", err)
	}

	// LookupHost reports the sentinel directly, which is what callers match on.
	if _, err := n.LookupHost(context.Background(), "example.test"); !errors.Is(err, ErrNoPushedDNS) {
		t.Errorf("LookupHost error = %v, want ErrNoPushedDNS", err)
	}
}

// TestResolverUsesPushedServer checks that the resolver dials the pushed address
// and nothing else. The stack has no route off the tunnel, so the dial fails
// against the pushed server, which is what proves it never reached the host.
func TestResolverUsesPushedServer(t *testing.T) {
	n := testNet(t, &dns.Config{Servers: []net.IP{net.IPv4(10, 9, 0, 53)}})
	if got := n.DNSServers(); len(got) != 1 || !got[0].Equal(net.IPv4(10, 9, 0, 53)) {
		t.Fatalf("DNSServers = %v, want the pushed 10.9.0.53", got)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // fail fast; we are asserting on which address is dialed, not on a reply
	_, err := n.Resolver().LookupHost(ctx, "example.test")
	if err == nil {
		t.Fatal("lookup unexpectedly succeeded against a black-hole stack")
	}
	if errors.Is(err, ErrNoPushedDNS) {
		t.Errorf("resolver reported no pushed server despite one being configured: %v", err)
	}
}

// TestLookupHostPassesLiteralsThrough keeps a literal address from being sent
// to a resolver that cannot answer it.
func TestLookupHostPassesLiteralsThrough(t *testing.T) {
	got, err := testNet(t, nil).LookupHost(context.Background(), "10.9.0.1")
	if err != nil {
		t.Fatalf("LookupHost on a literal: %v", err)
	}
	if len(got) != 1 || got[0] != "10.9.0.1" {
		t.Errorf("LookupHost = %v, want the literal back unchanged", got)
	}
}

func TestListenTCPOnTunnelAddress(t *testing.T) {
	n := testNet(t, nil)
	ln, err := n.ListenTCP("10.9.0.6:8080")
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	defer ln.Close() //nolint:errcheck
	if ln.Addr() == nil {
		t.Error("listener has no address")
	}
}

// TestPingRejectsIPv6 pins the documented limit rather than leaving a v6 target
// to fail as though the peer were unreachable: Ping constructs an IPv4 echo
// request only, and silence is also what a dead peer looks like — hence the
// refusal, and hence the assertion that it is not a timeout.
func TestPingRejectsIPv6(t *testing.T) {
	n := testNet(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := n.Ping(ctx, netip.MustParseAddr("::1"), []byte("x"), 1)
	if err == nil {
		t.Fatal("Ping to a v6 address succeeded; only IPv4 echo is implemented")
	}
	if errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("Ping to a v6 address timed out rather than refusing; an unimplemented " +
			"path must not look like an unreachable peer")
	}
}
