//go:build linux || android

// Netlink route management for the routing package.
//
// ApplyRoutes adds the routes described by PushOptions to the kernel routing
// table.  It uses the Linux rtnetlink(7) socket interface via
// golang.org/x/sys/unix — no CGo, no external libraries.
//
// Route lifecycle:
//
//  1. If Ifconfig is present, add a host route to the peer address via the TUN
//     interface (so the P2P link is routable).
//  2. Add each explicit Route from the PUSH_REPLY.
//  3. If RedirectGateway is true, add the two /1 routes that carry the whole
//     IPv4 space into the tunnel (see RedirectRoutes4).
//
// What each of those amounts to on the wire is decided by routePlan and only
// then sent, so that the netlink messages this package builds can be asserted
// on without CAP_NET_ADMIN.
//
// Reference: linux/rtnetlink.h, RFC 3549
package routing

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// nlmsgHdrSize is the size of a netlink message header on the wire (16 bytes).
// Equivalent to NLMSG_HDRSIZE in linux/netlink.h.
const nlmsgHdrSize = 16

// ApplyRoutes programs the kernel routing table for the routes described by
// opts.  ifIndex is the kernel interface index of the TUN device (obtained
// from net.InterfaceByName(dev.Name()).Index or equivalent).
//
// For topology subnet, the TUN address is already configured as a /prefix
// address; only explicit routes and the redirect cover are added.
//
// For topology net30, Linux automatically adds a /32 host route for the P2P
// peer when the interface is configured; EEXIST is tolerated for that route.
//
// This function requires CAP_NET_ADMIN.
func ApplyRoutes(opts *PushOptions, ifIndex int) error {
	for _, s := range routePlan(opts, ifIndex, true) {
		if err := sendRouteSpec(s); err != nil {
			if s.tolerate != 0 && errors.Is(err, s.tolerate) {
				continue
			}
			return fmt.Errorf("routing: %s: %w", s.what, err)
		}
	}
	return nil
}

// DeleteRoutes removes the routes that ApplyRoutes would have added.
// It is the caller's responsibility to call DeleteRoutes on disconnect so
// that the system routing table is left in a clean state.
//
// Every deletion is attempted and the first failure is the one returned, so a
// route the kernel had already dropped cannot leave the rest installed.
func DeleteRoutes(opts *PushOptions, ifIndex int) error {
	var firstErr error
	for _, s := range routePlan(opts, ifIndex, false) {
		if err := sendRouteSpec(s); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("routing: delete %s: %w", s.what, err)
		}
	}
	return firstErr
}

// ---- the plan ----------------------------------------------------------------

// routeSpec is one change to the kernel route table, held as what it means
// rather than as the bytes that carry it. ApplyRoutes and DeleteRoutes settle
// their whole sequence of these before a socket is opened, which is what lets a
// test assert on the netlink messages this package would send without
// CAP_NET_ADMIN. buildRouteMsg is the only place a routeSpec becomes bytes, and
// sendRouteSpec the only place those bytes reach the kernel.
type routeSpec struct {
	msgType uint16
	flags   uint16
	ifIndex int
	family  uint8
	dst     net.IP
	mask    net.IPMask
	gw      net.IP

	// what names the change for an error message.
	what string

	// tolerate is an errno that is not a failure for this particular change.
	// Zero means every error is one.
	tolerate syscall.Errno
}

// routePlan lists, in order, every netlink message ApplyRoutes (add) or
// DeleteRoutes (!add) sends for opts. One function decides both directions, so
// that a teardown cannot come to disagree with the bring-up it undoes.
func routePlan(opts *PushOptions, ifIndex int, add bool) []routeSpec {
	if opts == nil {
		return nil
	}

	// spec turns one route into the message for this direction. replace marks
	// a route that has to end up in the table whatever was there before:
	// NLM_F_REPLACE cannot answer EEXIST, so such a route is either installed
	// or reported, never quietly neither.
	spec := func(family uint8, dst net.IP, mask net.IPMask, gw net.IP, replace bool, what string) routeSpec {
		s := routeSpec{ifIndex: ifIndex, family: family, dst: dst, mask: mask, gw: gw, what: what}
		switch {
		case !add:
			s.msgType = unix.RTM_DELROUTE
		case replace:
			s.msgType = unix.RTM_NEWROUTE
			s.flags = unix.NLM_F_CREATE | unix.NLM_F_REPLACE
		default:
			s.msgType = unix.RTM_NEWROUTE
			s.flags = unix.NLM_F_CREATE | unix.NLM_F_EXCL
			// An identical route already in the table — the peer route the
			// kernel installs with the interface, or a pushed route the host
			// already had — is the state this was asking for.
			s.tolerate = syscall.EEXIST
		}
		return s
	}

	var plan []routeSpec

	// --- IPv4 ---
	var defaultGW net.IP
	if opts.Ifconfig != nil {
		defaultGW = opts.Ifconfig.Gateway
	}

	if opts.Topology == TopologyNet30 && opts.Ifconfig != nil {
		plan = append(plan, spec(unix.AF_INET, opts.Ifconfig.Gateway, net.CIDRMask(32, 32), nil, false,
			fmt.Sprintf("host route to peer %s", opts.Ifconfig.Gateway)))
	}

	for _, r := range opts.Routes {
		if r.Symbolic.AroundTunnel() {
			// net_gateway and remote_host mean the opposite of every other
			// pushed route: this destination is to be reached *without* the
			// tunnel, and the nil-Gateway fallback below would send it to the
			// tunnel's own gateway.
			//
			// Skipping is correct while the host keeps its own default route,
			// which already reaches these destinations. It is NOT sufficient
			// under redirect-gateway, where the /1 cover below outranks that
			// default: those exclusions then need explicit bypass routes via
			// the pre-VPN gateway.
			continue
		}
		gw := r.Gateway
		if gw == nil {
			gw = defaultGW
		}
		plan = append(plan, spec(unix.AF_INET, r.Network, r.Mask, gw, false,
			fmt.Sprintf("route %s/%s", r.Network, net.IP(r.Mask))))
	}

	if opts.RedirectGateway {
		// Two /1 routes, not one 0.0.0.0/0 — see RedirectRoutes4. They go in
		// as replacements, because a redirect that finds its route already
		// present and installs nothing is precisely the silence this cover
		// exists to end.
		for _, r := range RedirectRoutes4(defaultGW) {
			ones, _ := r.Mask.Size()
			plan = append(plan, spec(unix.AF_INET, r.Network, r.Mask, r.Gateway, true,
				fmt.Sprintf("redirect-gateway route %s/%d", r.Network, ones)))
		}
	}

	// --- IPv6 ---
	var defaultGW6 net.IP
	if opts.Ifconfig6 != nil {
		defaultGW6 = opts.Ifconfig6.Gateway
	}

	for _, r := range opts.Routes6 {
		gw := r.Gateway
		if gw == nil {
			gw = defaultGW6
		}
		plan = append(plan, spec(unix.AF_INET6, r.Network, net.CIDRMask(r.Prefix, 128), gw, false,
			fmt.Sprintf("IPv6 route %s/%d", r.Network, r.Prefix)))
	}

	if opts.RedirectsIPv6() {
		for _, r := range RedirectRoutes6(defaultGW6) {
			plan = append(plan, spec(unix.AF_INET6, r.Network, net.CIDRMask(r.Prefix, 128), r.Gateway, true,
				fmt.Sprintf("redirect-gateway ipv6 route %s/%d", r.Network, r.Prefix)))
		}
	}

	return plan
}

// ---- low-level netlink helpers -----------------------------------------------

// buildRouteMsg serialises one routeSpec into the complete netlink datagram
// that carries it, header and padding included.
//
// Layout: nlmsghdr (16B) + rtmsg (12B) + RTA_DST + RTA_GATEWAY [+ RTA_OIF].
// RTA_OIF is omitted when ifIndex == 0; the kernel resolves the output
// interface from the gateway in that case.
func buildRouteMsg(s routeSpec) ([]byte, error) {
	ones, bits := s.mask.Size()
	switch s.family {
	case unix.AF_INET:
		if bits != 32 {
			return nil, fmt.Errorf("routing: IPv4 route needs a contiguous 32-bit mask, got %s", s.mask)
		}
	case unix.AF_INET6:
		if bits != 128 {
			return nil, fmt.Errorf("routing: IPv6 route needs a contiguous 128-bit mask, got %s", s.mask)
		}
	default:
		return nil, fmt.Errorf("routing: unsupported address family %d", s.family)
	}

	dst, err := addrBytes(s.family, s.dst)
	if err != nil {
		return nil, fmt.Errorf("routing: route destination: %w", err)
	}
	var gw []byte
	if s.gw != nil {
		if gw, err = addrBytes(s.family, s.gw); err != nil {
			return nil, fmt.Errorf("routing: route gateway: %w", err)
		}
	}

	rtMsg := unix.RtMsg{
		Family:   s.family,
		Dst_len:  uint8(ones),
		Table:    unix.RT_TABLE_MAIN,
		Protocol: unix.RTPROT_STATIC,
		Scope:    unix.RT_SCOPE_UNIVERSE,
		Type:     unix.RTN_UNICAST,
	}
	// A host route with no next hop is on-link, and the kernel refuses it at
	// universe scope.
	if ones == bits && s.gw == nil {
		rtMsg.Scope = unix.RT_SCOPE_LINK
	}

	payload := marshalRtMsg(rtMsg)
	payload = append(payload, nlAttr(unix.RTA_DST, dst)...)
	if gw != nil {
		payload = append(payload, nlAttr(unix.RTA_GATEWAY, gw)...)
	}
	if s.ifIndex > 0 {
		var oifBuf [4]byte
		binary.LittleEndian.PutUint32(oifBuf[:], uint32(s.ifIndex))
		payload = append(payload, nlAttr(unix.RTA_OIF, oifBuf[:])...)
	}

	return frameNetlinkMsg(s.msgType, s.flags, payload), nil
}

// addrBytes returns ip in the wire width family expects, or an error when it
// is not an address of that family.
func addrBytes(family uint8, ip net.IP) ([]byte, error) {
	if family == unix.AF_INET {
		v4 := ip.To4()
		if v4 == nil {
			return nil, fmt.Errorf("%v is not an IPv4 address", ip)
		}
		return v4, nil
	}
	v6 := ip.To16()
	if v6 == nil {
		return nil, fmt.Errorf("%v is not an IPv6 address", ip)
	}
	return v6, nil
}

// sendRouteSpec builds s, sends it on a fresh netlink socket and returns what
// the kernel made of it.
func sendRouteSpec(s routeSpec) error {
	msg, err := buildRouteMsg(s)
	if err != nil {
		return err
	}

	sock, err := netlinkRouteSocket()
	if err != nil {
		return err
	}
	defer unix.Close(sock)

	return sendNetlinkMsg(sock, msg)
}

// netlinkRouteSocket opens and binds a NETLINK_ROUTE socket. The caller closes
// it.
func netlinkRouteSocket() (int, error) {
	sock, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_ROUTE)
	if err != nil {
		return -1, fmt.Errorf("netlink socket: %w", err)
	}
	lsa := unix.SockaddrNetlink{Family: unix.AF_NETLINK}
	if err := unix.Bind(sock, &lsa); err != nil {
		unix.Close(sock) //nolint:errcheck
		return -1, fmt.Errorf("netlink bind: %w", err)
	}
	return sock, nil
}

// frameNetlinkMsg wraps payload in an nlmsghdr and pads it to a 4-byte
// boundary. NLM_F_ACK ensures the kernel always answers with NLMSG_ERROR
// (errno == 0 on success).
func frameNetlinkMsg(msgType, flags uint16, payload []byte) []byte {
	hdr := unix.NlMsghdr{
		Len:   uint32(nlmsgHdrSize + len(payload)),
		Type:  msgType,
		Flags: unix.NLM_F_REQUEST | unix.NLM_F_ACK | flags,
		Seq:   1,
		Pid:   uint32(unix.Getpid()),
	}
	msg := marshalNlHdr(hdr)
	msg = append(msg, payload...)
	for len(msg)%4 != 0 {
		msg = append(msg, 0)
	}
	return msg
}

// sendNetlinkMsg sends an already-framed message and reads the ACK.
func sendNetlinkMsg(sock int, msg []byte) error {
	ksa := unix.SockaddrNetlink{Family: unix.AF_NETLINK}
	if err := unix.Sendto(sock, msg, 0, &ksa); err != nil {
		return fmt.Errorf("netlink send: %w", err)
	}
	buf := make([]byte, 4096)
	n, _, err := unix.Recvfrom(sock, buf, 0)
	if err != nil {
		return fmt.Errorf("netlink recv: %w", err)
	}
	return parseNlError(buf[:n])
}

// LookupGateway returns the gateway IP for the best route to dst in the main
// routing table.  Returns (nil, nil) when the route is a direct link route
// (no gateway — dst is on a directly connected subnet).
func LookupGateway(dst net.IP) (net.IP, error) {
	family, addr, bits := routeFamily(dst)
	if addr == nil {
		return nil, fmt.Errorf("routing: LookupGateway: not an IP address: %v", dst)
	}

	sock, err := netlinkRouteSocket()
	if err != nil {
		return nil, fmt.Errorf("routing: lookup gateway: %w", err)
	}
	defer unix.Close(sock)

	rtMsg := unix.RtMsg{
		Family:  family,
		Dst_len: uint8(bits),
		Table:   unix.RT_TABLE_MAIN,
	}
	rtaDst := nlAttr(unix.RTA_DST, addr)
	payload := marshalRtMsg(rtMsg)
	payload = append(payload, rtaDst...)

	hdr := unix.NlMsghdr{
		Len:   uint32(nlmsgHdrSize + len(payload)),
		Type:  unix.RTM_GETROUTE,
		Flags: unix.NLM_F_REQUEST,
		Seq:   2,
		Pid:   uint32(unix.Getpid()),
	}
	msg := marshalNlHdr(hdr)
	msg = append(msg, payload...)
	for len(msg)%4 != 0 {
		msg = append(msg, 0)
	}

	ksa := unix.SockaddrNetlink{Family: unix.AF_NETLINK}
	if err := unix.Sendto(sock, msg, 0, &ksa); err != nil {
		return nil, fmt.Errorf("routing: lookup gateway: send: %w", err)
	}

	buf := make([]byte, 4096)
	n, _, err := unix.Recvfrom(sock, buf, 0)
	if err != nil {
		return nil, fmt.Errorf("routing: lookup gateway: recv: %w", err)
	}

	return parseRouteGateway(buf[:n])
}

// parseRouteGateway extracts RTA_GATEWAY from an RTM_GETROUTE response.
// Returns (nil, nil) for direct link routes (no gateway attribute).
//
// The walk is the standard library's, which knows how long an rtmsg is and how
// each attribute is aligned; restating it here risks reading an IPv6 next hop
// at an IPv4 width.
func parseRouteGateway(buf []byte) (net.IP, error) {
	msgs, err := syscall.ParseNetlinkMessage(buf)
	if err != nil {
		return nil, fmt.Errorf("routing: lookup gateway: %w", err)
	}
	for i := range msgs {
		if msgs[i].Header.Type == unix.NLMSG_ERROR {
			if err := parseNlError(buf); err != nil {
				return nil, fmt.Errorf("routing: lookup gateway: %w", err)
			}
			return nil, nil
		}
		attrs, err := syscall.ParseNetlinkRouteAttr(&msgs[i])
		if err != nil {
			return nil, fmt.Errorf("routing: lookup gateway: %w", err)
		}
		for _, attr := range attrs {
			if attr.Attr.Type == unix.RTA_GATEWAY {
				// 4 bytes for an IPv4 next hop, 16 for an IPv6 one.
				return net.IP(append([]byte(nil), attr.Value...)), nil
			}
		}
	}
	return nil, nil // direct link route — no gateway
}

// AddBypassRoute adds a /32 host route for serverIP via gw so that the VPN
// server's traffic is never routed through the TUN after redirect-gateway is
// applied.  A gateway of nil is accepted (direct link) but the route is only
// useful when a gateway is present.  EEXIST is treated as success.
func AddBypassRoute(serverIP, gw net.IP) error {
	if gw == nil {
		return nil // direct link — no bypass route needed
	}
	err := sendRouteSpec(bypassSpec(unix.RTM_NEWROUTE,
		unix.NLM_F_CREATE|unix.NLM_F_EXCL, serverIP, gw))
	if errors.Is(err, syscall.EEXIST) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("routing: add bypass route for %s: %w", serverIP, err)
	}
	return nil
}

// bypassSpec is the /32 host route that keeps serverIP reachable via the
// host's own gateway. It carries no RTA_OIF: the kernel resolves the output
// interface from gw, which is the pre-VPN one by construction.
//
// Reference: openvpn-2.6.22 src/openvpn/route.c:1046-1055 installs the same
// route for the remote host before the default is redirected.
func bypassSpec(msgType, flags uint16, serverIP, gw net.IP) routeSpec {
	family, _, bits := routeFamily(serverIP)
	return routeSpec{
		msgType: msgType,
		flags:   flags,
		family:  family,
		dst:     serverIP,
		mask:    net.CIDRMask(bits, bits),
		gw:      gw,
		what:    "bypass route for " + serverIP.String(),
	}
}

// routeFamily classifies an address for a netlink route message: the address
// family, the address in its natural width, and the host-route prefix length.
func routeFamily(ip net.IP) (family uint8, addr net.IP, bits int) {
	if v4 := ip.To4(); v4 != nil {
		return unix.AF_INET, v4, 32
	}
	if v6 := ip.To16(); v6 != nil {
		return unix.AF_INET6, v6, 128
	}
	return unix.AF_INET, nil, 32
}

// DeleteBypassRoute removes the /32 bypass route added by AddBypassRoute.
// ESRCH (no such route) is treated as success.
func DeleteBypassRoute(serverIP, gw net.IP) error {
	if gw == nil {
		return nil
	}
	err := sendRouteSpec(bypassSpec(unix.RTM_DELROUTE, 0, serverIP, gw))
	if errors.Is(err, syscall.ESRCH) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("routing: delete bypass route for %s: %w", serverIP, err)
	}
	return nil
}

// nlAttr serialises a single rtattr: 2-byte length + 2-byte type + data.
func nlAttr(typ uint16, data []byte) []byte {
	attrLen := 4 + len(data)
	b := make([]byte, attrLen)
	binary.LittleEndian.PutUint16(b[0:2], uint16(attrLen))
	binary.LittleEndian.PutUint16(b[2:4], typ)
	copy(b[4:], data)
	// Pad to 4-byte boundary.
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return b
}

// marshalNlHdr serialises a unix.NlMsghdr to wire format (16 bytes).
func marshalNlHdr(h unix.NlMsghdr) []byte {
	b := make([]byte, nlmsgHdrSize)
	binary.LittleEndian.PutUint32(b[0:4], h.Len)
	binary.LittleEndian.PutUint16(b[4:6], h.Type)
	binary.LittleEndian.PutUint16(b[6:8], h.Flags)
	binary.LittleEndian.PutUint32(b[8:12], h.Seq)
	binary.LittleEndian.PutUint32(b[12:16], h.Pid)
	return b
}

// marshalRtMsg serialises a unix.RtMsg to wire format (12 bytes).
func marshalRtMsg(m unix.RtMsg) []byte {
	return []byte{
		m.Family,
		m.Dst_len,
		m.Src_len,
		m.Tos,
		m.Table,
		m.Protocol,
		byte(m.Scope),
		m.Type,
		byte(m.Flags), byte(m.Flags >> 8), byte(m.Flags >> 16), byte(m.Flags >> 24),
	}
}

// parseNlError reads a netlink NLMSG_ERROR response and returns an error if
// the kernel reported a failure.
func parseNlError(buf []byte) error {
	msgs, err := syscall.ParseNetlinkMessage(buf)
	if err != nil {
		return fmt.Errorf("netlink: %w", err)
	}
	for _, m := range msgs {
		if m.Header.Type != unix.NLMSG_ERROR {
			continue // NLMSG_DONE or a payload message — not a failure
		}
		if len(m.Data) < 4 {
			return fmt.Errorf("netlink: NLMSG_ERROR too short")
		}
		// A signed int32 in native byte order, immediately after the header.
		// Zero is the kernel's acknowledgement, not a failure.
		if code := int32(binary.LittleEndian.Uint32(m.Data)); code != 0 {
			return fmt.Errorf("netlink: %w", syscall.Errno(-code))
		}
	}
	return nil
}

// AddIPv6Addr assigns an IPv6 address with the given prefix length to the
// interface identified by ifIndex.  It uses RTM_NEWADDR via the netlink
// socket — the SIOCS* ioctls only work for AF_INET.
//
// This is equivalent to: ip -6 addr add <local>/<prefix> dev <iface>
//
// Requires CAP_NET_ADMIN.
func AddIPv6Addr(ifIndex int, local net.IP, prefix int) error {
	sock, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_ROUTE)
	if err != nil {
		return fmt.Errorf("netlink socket: %w", err)
	}
	defer unix.Close(sock)

	lsa := unix.SockaddrNetlink{Family: unix.AF_NETLINK}
	if err := unix.Bind(sock, &lsa); err != nil {
		return fmt.Errorf("netlink bind: %w", err)
	}

	ifaMsg := ifAddrMsg{
		Family:    unix.AF_INET6,
		Prefixlen: uint8(prefix),
		Flags:     0,
		Scope:     unix.RT_SCOPE_UNIVERSE,
		Index:     uint32(ifIndex),
	}

	local16 := local.To16()
	rtaAddr := nlAttr(unix.IFA_ADDRESS, local16)
	rtaLocal := nlAttr(unix.IFA_LOCAL, local16)

	payload := marshalIfAddrMsg(ifaMsg)
	payload = append(payload, rtaAddr...)
	payload = append(payload, rtaLocal...)

	return sendNetlinkMsg(sock,
		frameNetlinkMsg(unix.RTM_NEWADDR, unix.NLM_F_CREATE|unix.NLM_F_REPLACE, payload))
}

// ifAddrMsg is the wire layout of struct ifaddrmsg (linux/if_addr.h, 8 bytes).
type ifAddrMsg struct {
	Family    uint8
	Prefixlen uint8
	Flags     uint8
	Scope     uint8
	Index     uint32
}

func marshalIfAddrMsg(m ifAddrMsg) []byte {
	b := make([]byte, 8)
	b[0] = m.Family
	b[1] = m.Prefixlen
	b[2] = m.Flags
	b[3] = byte(m.Scope)
	binary.LittleEndian.PutUint32(b[4:8], m.Index)
	return b
}

// InterfaceIndex returns the kernel interface index for the named interface.
// This is a convenience wrapper around net.InterfaceByName so callers do not
// need to import "net" just for a single lookup.
func InterfaceIndex(name string) (int, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return 0, fmt.Errorf("routing: interface %q: %w", name, err)
	}
	return iface.Index, nil
}
