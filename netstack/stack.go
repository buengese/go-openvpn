// SPDX-License-Identifier: LGPL-2.1-or-later

// The gVisor stack behind one netstack Device: construction, addressing and the
// stack's own route table.
//
// # Why gvisor.dev/gvisor is pinned to v0.0.0-20260224225140-573d5e7127a8
//
// Every revision from release-20260302.0 onward fails `go build` for an
// external consumer: pkg/tcpip/stack/bridge_test.go declares `package
// bridge_test` in a directory whose package is `stack`, so the go tool reports
// "found packages stack (addressable_endpoint_state.go) and bridge
// (bridge_test.go)". gVisor builds itself with Bazel, which does not mind.
//
// v0.0.0-20260224225140-573d5e7127a8 is the newest revision that does build,
// and it declares go 1.25.5, which leaves our go directive alone where
// post-February revisions would bump it. Moving the pin forward is a deliberate
// act with a build check attached, not a `go get -u`.
//
// This pin builds CGO_ENABLED=0 for all four `make check-platforms` targets —
// linux/amd64, android/arm64, darwin/arm64 and darwin/arm64 -tags ios — so the
// package carries no build constraint and gVisor reaches a binary only when
// something imports this package.

package netstack

import (
	"fmt"
	"net/netip"

	"github.com/buengese/go-openvpn/device"
	"github.com/buengese/go-openvpn/routing"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

const (
	// nicID is the identifier of the stack's only NIC. There is exactly one
	// per tunnel, so the value is a constant rather than an allocation.
	nicID tcpip.NICID = 1

	// outboundQueue is how many packets the channel endpoint buffers on the
	// way out before it starts dropping — which is what a real link does; the
	// alternative is blocking the stack's own transport goroutines behind
	// our encryptor.
	outboundQueue = 512

	// maxMTU bounds the negotiated MTU. An IP datagram cannot exceed 65535
	// bytes, so anything larger is a parsing bug upstream of us rather than
	// a tunnel to bring up.
	maxMTU = 65535
)

// tunnelStack is the gVisor stack backing one Device: a single NIC over a
// channel endpoint, addressed from the PUSH_REPLY, with a route table of its
// own that no host route can contradict.
type tunnelStack struct {
	stack *stack.Stack
	ep    *channel.Endpoint

	// v4 and v6 are the addresses assigned to the NIC. Either may be the
	// zero Addr, when the server pushed no addressing for that family.
	v4 netip.Addr
	v6 netip.Addr

	// gw4 is the peer's own tunnel-side address from the PUSH_REPLY, zero
	// when none was pushed. The routes below carry no gateway — the link is
	// point-to-point — so this is kept for its other use: the one host beyond
	// the tunnel a probe may address without involving a third party.
	gw4 netip.Addr
}

// newTunnelStack builds and configures the stack for one tunnel. It returns an
// error rather than a half-configured stack, and destroys what it built if a
// later step fails.
func newTunnelStack(p device.Params, name string) (*tunnelStack, error) {
	if p.Push == nil {
		return nil, fmt.Errorf("netstack: no pushed options")
	}
	if p.Push.Ifconfig == nil && p.Push.Ifconfig6 == nil {
		return nil, fmt.Errorf("netstack: PUSH_REPLY carried neither ifconfig nor ifconfig-ipv6")
	}

	s := stack.New(stack.Options{
		// Both families. Registering v6 costs nothing when the server
		// pushes no v6 address, and skipping it would make v6 support a
		// migration rather than a configuration.
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocol,
			ipv6.NewProtocol,
		},
		// ICMP is registered alongside TCP and UDP because an echo that
		// crosses and comes back is the cheapest proof that the data path
		// works.
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol,
			udp.NewProtocol,
			icmp.NewProtocol4,
			icmp.NewProtocol6,
		},
		// Traffic from one of our own addresses to another is handled
		// inside the stack rather than emitted onto the link and sent
		// back to us over the tunnel.
		HandleLocal: true,
	})

	ts := &tunnelStack{
		stack: s,
		ep:    channel.New(outboundQueue, uint32(p.MTU), ""),
	}

	if err := s.CreateNICWithOptions(nicID, ts.ep, stack.NICOptions{Name: name}); err != nil {
		ts.destroy()
		return nil, fmt.Errorf("netstack: create NIC: %s", err)
	}

	var routes []tcpip.Route

	if ic := p.Push.Ifconfig; ic != nil {
		pa, addr, err := protocolAddress4(ic)
		if err != nil {
			ts.destroy()
			return nil, err
		}
		if err := s.AddProtocolAddress(nicID, pa, stack.AddressProperties{}); err != nil {
			ts.destroy()
			return nil, fmt.Errorf("netstack: add IPv4 address %s: %s", addr, err)
		}
		ts.v4 = addr
		if gw, ok := netip.AddrFromSlice(ic.Gateway.To4()); ok {
			ts.gw4 = gw
		}
		routes = append(routes, tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: nicID})
	}

	if ic6 := p.Push.Ifconfig6; ic6 != nil {
		pa, addr, err := protocolAddress6(ic6)
		if err != nil {
			ts.destroy()
			return nil, err
		}
		if err := s.AddProtocolAddress(nicID, pa, stack.AddressProperties{}); err != nil {
			ts.destroy()
			return nil, fmt.Errorf("netstack: add IPv6 address %s: %s", addr, err)
		}
		ts.v6 = addr
		routes = append(routes, tcpip.Route{Destination: header.IPv6EmptySubnet, NIC: nicID})
	}

	// The route table is the stack's own and holds one default route per
	// family that got an address. Three things look like omissions and are
	// not:
	//
	//   - Push.RedirectGateway is read and not acted on. There is no host
	//     route table to replace, no host default route to preserve, and
	//     the transport socket lives outside this stack, so no bypass route
	//     is needed either.
	//
	//   - Push.Routes and Push.Routes6 are subsumed: every one would resolve
	//     to this NIC, where the default route already sends everything. A
	//     per-tunnel netstack has no second interface, so it cannot express
	//     a split tunnel — whether a flow is offered to the stack at all is
	//     the caller's decision, not a route-table one.
	//
	//   - The routes carry no Gateway. The link is point-to-point with no
	//     link-layer addressing (ARPHardwareNone), so there is no next hop
	//     to resolve.
	s.SetRouteTable(routes)

	return ts, nil
}

// destroy tears the stack down: it shuts the channel endpoint, which unblocks
// any reader, then aborts every endpoint, removes the NIC and waits for
// gVisor's worker goroutines to stop. It is safe to call more than once, and on
// a partially built stack.
func (t *tunnelStack) destroy() {
	if t.ep != nil {
		t.ep.Close()
	}
	if t.stack != nil {
		t.stack.Destroy()
	}
}

// protocolAddress4 converts a pushed ifconfig into the gVisor address to assign
// to the NIC, and returns the same address as a netip.Addr for reporting.
func protocolAddress4(ic *routing.Ifconfig) (tcpip.ProtocolAddress, netip.Addr, error) {
	local := ic.Local.To4()
	if local == nil {
		return tcpip.ProtocolAddress{}, netip.Addr{}, fmt.Errorf("netstack: ifconfig local %q is not an IPv4 address", ic.Local)
	}

	// A pushed mask is the tunnel subnet in "topology subnet" and /30 in
	// net30. An absent or non-IPv4 mask leaves the address a host route on
	// the NIC, which is correct: the default route is what carries traffic.
	prefix := 32
	if ones, bits := ic.Mask.Size(); bits == 32 && ones > 0 {
		prefix = ones
	}

	addr, ok := netip.AddrFromSlice(local)
	if !ok {
		return tcpip.ProtocolAddress{}, netip.Addr{}, fmt.Errorf("netstack: ifconfig local %q is not an IPv4 address", ic.Local)
	}
	return tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFrom4Slice(local),
			PrefixLen: prefix,
		},
	}, addr.Unmap(), nil
}

// protocolAddress6 converts a pushed ifconfig-ipv6 into the gVisor address to
// assign to the NIC, and returns the same address as a netip.Addr for
// reporting.
func protocolAddress6(ic *routing.Ifconfig6) (tcpip.ProtocolAddress, netip.Addr, error) {
	local := ic.Local.To16()
	if local == nil || ic.Local.To4() != nil {
		return tcpip.ProtocolAddress{}, netip.Addr{}, fmt.Errorf("netstack: ifconfig-ipv6 local %q is not an IPv6 address", ic.Local)
	}

	prefix := ic.Prefix
	if prefix <= 0 || prefix > 128 {
		// A prefix outside 1..128 is not something to guess at, but a
		// host route on the NIC is exactly as reachable as the pushed
		// prefix would have been, and the default route does the rest.
		prefix = 128
	}

	addr, ok := netip.AddrFromSlice(local)
	if !ok {
		return tcpip.ProtocolAddress{}, netip.Addr{}, fmt.Errorf("netstack: ifconfig-ipv6 local %q is not an IPv6 address", ic.Local)
	}
	return tcpip.ProtocolAddress{
		Protocol: ipv6.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFrom16Slice(local),
			PrefixLen: prefix,
		},
	}, addr, nil
}
