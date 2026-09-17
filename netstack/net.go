// SPDX-License-Identifier: LGPL-2.1-or-later

// The dialer surface: what a consumer calls once a tunnel is up.
//
// Everything here goes through the tunnel's own gVisor stack and nothing
// touches the host: a measurement of what is reachable through a tunnel is
// worthless if a connection, or a lookup, can quietly fall back to the host's.

package netstack

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"

	"github.com/openlawsvpn/go-openlawsvpn/dns"
)

// defaultDNSPort is where a pushed DNS server is assumed to listen. OpenVPN's
// dhcp-option DNS carries an address and never a port.
const defaultDNSPort = 53

// Net is the network reachable through one tunnel. Its methods mirror the
// standard library's, so an http.Transport, a database driver, or anything else
// taking a DialContext func works unmodified — and every one of them dials out
// of the tunnel's stack.
type Net struct {
	ts *tunnelStack

	// dnsCfg is the merged pushed and profile DNS. Nil or empty means the
	// server pushed no resolver, in which case Resolver still refuses to
	// read the host's rather than silently working.
	dnsCfg *dns.Config
}

// Network returns the Net for this device. It stays valid until the Device is
// closed; using it afterwards returns an error rather than reaching the host.
func (d *Device) Network() *Net {
	return &Net{ts: d.ts, dnsCfg: d.dns}
}

// LocalAddresses returns the addresses assigned to this end of the tunnel, v4
// first when both are present. They are pushed internal addresses, so treat
// them as identifying.
func (n *Net) LocalAddresses() []netip.Addr {
	var out []netip.Addr
	if n.ts.v4.IsValid() {
		out = append(out, n.ts.v4)
	}
	if n.ts.v6.IsValid() {
		out = append(out, n.ts.v6)
	}
	return out
}

// fullAddr converts a host:port into the stack's address form, and reports the
// network protocol it belongs to. The host must be a literal address:
// resolution goes through Resolver, so a name lookup cannot silently happen on
// the host.
func (n *Net) fullAddr(address string) (tcpip.FullAddress, tcpip.NetworkProtocolNumber, error) {
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return tcpip.FullAddress{}, 0, fmt.Errorf("netstack: address %q: %w", address, err)
	}
	port, err := net.LookupPort("tcp", portStr)
	if err != nil {
		return tcpip.FullAddress{}, 0, fmt.Errorf("netstack: port %q: %w", portStr, err)
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return tcpip.FullAddress{}, 0, fmt.Errorf(
			"netstack: %q is not a literal IP address; resolve it with Net.Resolver first", host)
	}
	ip = ip.Unmap()

	proto := header.IPv4ProtocolNumber
	if ip.Is6() {
		proto = header.IPv6ProtocolNumber
	}
	return tcpip.FullAddress{
		NIC:  nicID,
		Addr: tcpip.AddrFromSlice(ip.AsSlice()),
		Port: uint16(port),
	}, tcpip.NetworkProtocolNumber(proto), nil
}

// networkIsTCP reports whether a Go network name names a stream protocol.
// The address family comes from the address itself, not from the suffix, so
// tcp4 and tcp6 are accepted and treated as tcp.
func networkIsTCP(network string) (bool, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
		return true, nil
	case "udp", "udp4", "udp6":
		return false, nil
	default:
		return false, fmt.Errorf("netstack: unsupported network %q", network)
	}
}

// DialContext connects to an address through the tunnel, and is the method to
// hand to an http.Transport. network is one of tcp, tcp4, tcp6, udp, udp4 or
// udp6. The address must carry a literal IP; use Resolver to turn a name into
// one, so that no lookup can escape to the host.
func (n *Net) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	full, proto, err := n.fullAddr(address)
	if err != nil {
		return nil, err
	}
	isTCP, err := networkIsTCP(network)
	if err != nil {
		return nil, err
	}
	if isTCP {
		return gonet.DialContextTCP(ctx, n.ts.stack, full, proto)
	}
	return gonet.DialUDP(n.ts.stack, nil, &full, proto)
}

// Dial connects to an address through the tunnel with no deadline beyond the
// stack's own. It is DialContext with a background context.
func (n *Net) Dial(network, address string) (net.Conn, error) {
	return n.DialContext(context.Background(), network, address)
}

// DialTCP opens a TCP connection through the tunnel.
func (n *Net) DialTCP(ctx context.Context, address string) (net.Conn, error) {
	return n.DialContext(ctx, "tcp", address)
}

// DialUDP opens a UDP association through the tunnel.
func (n *Net) DialUDP(address string) (net.Conn, error) {
	return n.DialContext(context.Background(), "udp", address)
}

// ListenTCP listens for inbound TCP connections on the tunnel address, for a
// consumer probing what an endpoint can initiate.
func (n *Net) ListenTCP(address string) (net.Listener, error) {
	full, proto, err := n.fullAddr(address)
	if err != nil {
		return nil, err
	}
	return gonet.ListenTCP(n.ts.stack, full, proto)
}

// ListenUDP binds a UDP endpoint on the tunnel address.
func (n *Net) ListenUDP(address string) (net.PacketConn, error) {
	full, proto, err := n.fullAddr(address)
	if err != nil {
		return nil, err
	}
	return gonet.DialUDP(n.ts.stack, &full, nil, proto)
}

// DNSServers returns the resolvers the server pushed, in preference order.
func (n *Net) DNSServers() []net.IP {
	if n.dnsCfg == nil {
		return nil
	}
	return n.dnsCfg.Servers
}

// ErrNoPushedDNS is returned by the resolver when the server pushed no DNS
// server. It is an error rather than a fallback: a resolver that quietly used
// the host's would report reachability that has nothing to do with the tunnel.
var ErrNoPushedDNS = errors.New("netstack: the server pushed no DNS server, and this resolver never falls back to the host's")

// Resolver returns a *net.Resolver that queries the pushed DNS servers through
// the tunnel, so anything in the standard library that accepts one takes it
// unmodified. PreferGo is set and Dial is overridden, so every query travels
// through the tunnel to a pushed server; when the server pushed none, every
// lookup fails rather than falling back.
//
// One caveat, because it looks like a leak in error messages: package net still
// reads /etc/resolv.conf to decide which server address to hand our Dial func,
// so a failure can name a host resolver such as 127.0.0.53. Dial ignores its
// argument entirely, but the string survives into the *net.DNSError.
//
// net.DNSError does not unwrap, so ErrNoPushedDNS cannot be recovered with
// errors.Is from a Resolver lookup. Use LookupHost, which reports it directly.
func (n *Net) Resolver() *net.Resolver {
	return &net.Resolver{
		PreferGo:     true,
		StrictErrors: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			servers := n.DNSServers()
			if len(servers) == 0 {
				return nil, ErrNoPushedDNS
			}
			// The address package net offers is the one it read from the
			// host's configuration. It is discarded: the pushed servers
			// are the only ones this resolver will talk to.
			var firstErr error
			for _, ip := range servers {
				addr := net.JoinHostPort(ip.String(), fmt.Sprint(defaultDNSPort))
				conn, err := n.DialContext(ctx, network, addr)
				if err == nil {
					return conn, nil
				}
				if firstErr == nil {
					firstErr = err
				}
			}
			return nil, fmt.Errorf("netstack: no pushed DNS server reachable through the tunnel: %w", firstErr)
		},
	}
}

// LookupHost resolves a name through the tunnel's resolver. It is shorthand for
// Resolver().LookupHost with a timeout, for callers that want one lookup rather
// than a resolver to install somewhere.
func (n *Net) LookupHost(ctx context.Context, host string) ([]string, error) {
	if _, err := netip.ParseAddr(host); err == nil {
		return []string{host}, nil
	}
	// Checked here rather than left to the Dial func, because net.DNSError
	// does not unwrap and would bury the sentinel in a string.
	if len(n.DNSServers()) == 0 {
		return nil, ErrNoPushedDNS
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return n.Resolver().LookupHost(ctx, host)
}

// DialContextResolving is DialContext that accepts a name as well as a literal
// address, resolving it through the tunnel first. It is separate so that the
// plain dialer cannot resolve by accident: a caller that passes a name to
// DialContext gets an error naming this method, not a lookup it did not ask
// for.
func (n *Net) DialContextResolving(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("netstack: address %q: %w", address, err)
	}
	if _, parseErr := netip.ParseAddr(host); parseErr == nil {
		return n.DialContext(ctx, network, address)
	}
	addrs, err := n.LookupHost(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("netstack: resolve %q through the tunnel: %w", host, err)
	}
	var firstErr error
	for _, a := range addrs {
		conn, dialErr := n.DialContext(ctx, network, net.JoinHostPort(a, port))
		if dialErr == nil {
			return conn, nil
		}
		if firstErr == nil {
			firstErr = dialErr
		}
	}
	return nil, firstErr
}
