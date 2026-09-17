// SPDX-License-Identifier: LGPL-2.1-or-later

package netstack

import (
	"bytes"
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/openlawsvpn/go-openlawsvpn/device"
	"github.com/openlawsvpn/go-openlawsvpn/routing"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// The synthesised tunnel. These are the addresses a matrix server hands out
// (testenv.tunnelNet4 and tunnelNet6), so the numbers in a failing test look
// like the ones in a real PUSH_REPLY.
const (
	tunLocal4   = "10.8.0.2"
	tunGateway4 = "10.8.0.1"
	tunPeer4    = "10.8.0.9"

	tunLocal6 = "fd00:4f4c:5650:4e00::1002"
	tunPeer6  = "fd00:4f4c:5650:4e00::1"

	testMTU = 1500
)

// paramsV4 is a PUSH_REPLY that addresses IPv4 only.
func paramsV4() device.Params {
	return device.Params{
		Push: &routing.PushOptions{
			Topology: routing.TopologySubnet,
			Ifconfig: &routing.Ifconfig{
				Local:   net.ParseIP(tunLocal4).To4(),
				Mask:    net.CIDRMask(24, 32),
				Gateway: net.ParseIP(tunGateway4).To4(),
			},
			// redirect-gateway is deliberately set: a netstack has no
			// host route table to redirect, so this must change nothing.
			RedirectGateway: true,
		},
		MTU: testMTU,
	}
}

// paramsV6 is a PUSH_REPLY that addresses IPv6 only, driven through the channel
// endpoint because no live matrix entry proves v6 end to end.
func paramsV6() device.Params {
	return device.Params{
		Push: &routing.PushOptions{
			Ifconfig6: &routing.Ifconfig6{
				Local:   net.ParseIP(tunLocal6),
				Prefix:  64,
				Gateway: net.ParseIP(tunPeer6),
			},
			RedirectFlags: routing.RedirectIPv6,
		},
		MTU: testMTU,
	}
}

// paramsDual is a PUSH_REPLY that addresses both families.
func paramsDual() device.Params {
	p := paramsV4()
	p.Push.Ifconfig6 = paramsV6().Push.Ifconfig6
	p.Push.RedirectFlags |= routing.RedirectIPv6
	return p
}

// openDevice opens a netstack device and registers its Close.
func openDevice(t *testing.T, p device.Params) *Device {
	t.Helper()
	d, err := (&Backend{}).Open(context.Background(), p)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() {
		if err := d.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	nd, ok := d.(*Device)
	if !ok {
		t.Fatalf("Open returned %T, want *netstack.Device", d)
	}
	return nd
}

// mustAddr4 parses a dotted-quad into a gVisor address.
func mustAddr4(s string) tcpip.Address {
	ip := net.ParseIP(s).To4()
	if ip == nil {
		panic("netstack test: not an IPv4 address: " + s)
	}
	return tcpip.AddrFrom4Slice(ip)
}

// mustAddr6 parses an IPv6 literal into a gVisor address.
func mustAddr6(s string) tcpip.Address {
	ip := net.ParseIP(s).To16()
	if ip == nil {
		panic("netstack test: not an IPv6 address: " + s)
	}
	return tcpip.AddrFrom16Slice(ip)
}

// echoRequest4 builds a complete IPv4 ICMP echo request.
func echoRequest4(src, dst tcpip.Address, ident, seq uint16, payload []byte) []byte {
	total := header.IPv4MinimumSize + header.ICMPv4MinimumSize + len(payload)
	pkt := make([]byte, total)

	ip := header.IPv4(pkt)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(total),
		TTL:         64,
		Protocol:    uint8(header.ICMPv4ProtocolNumber),
		SrcAddr:     src,
		DstAddr:     dst,
	})
	ip.SetChecksum(^ip.CalculateChecksum())

	msg := header.ICMPv4(pkt[header.IPv4MinimumSize:])
	msg.SetType(header.ICMPv4Echo)
	msg.SetCode(header.ICMPv4UnusedCode)
	msg.SetIdent(ident)
	msg.SetSequence(seq)
	copy(msg.Payload(), payload)
	msg.SetChecksum(0)
	msg.SetChecksum(^checksum.Checksum(msg, 0))

	return pkt
}

// echoRequest6 builds a complete IPv6 ICMPv6 echo request.
func echoRequest6(src, dst tcpip.Address, ident, seq uint16, payload []byte) []byte {
	msgLen := header.ICMPv6EchoMinimumSize + len(payload)
	pkt := make([]byte, header.IPv6MinimumSize+msgLen)

	ip := header.IPv6(pkt)
	ip.Encode(&header.IPv6Fields{
		PayloadLength:     uint16(msgLen),
		TransportProtocol: header.ICMPv6ProtocolNumber,
		HopLimit:          64,
		SrcAddr:           src,
		DstAddr:           dst,
	})

	msg := header.ICMPv6(pkt[header.IPv6MinimumSize:])
	msg.SetType(header.ICMPv6EchoRequest)
	msg.SetCode(header.ICMPv6UnusedCode)
	msg.SetIdent(ident)
	msg.SetSequence(seq)
	copy(pkt[header.IPv6MinimumSize+header.ICMPv6EchoMinimumSize:], payload)
	msg.SetChecksum(0)
	msg.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
		Header: msg,
		Src:    src,
		Dst:    dst,
	}))

	return pkt
}

// readPacket reads one outbound packet with a deadline.
func readPacket(t *testing.T, d *Device) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	buf := make([]byte, d.MTU())
	n, err := d.ReadPacket(ctx, buf)
	if err != nil {
		t.Fatalf("ReadPacket: %v", err)
	}
	return buf[:n]
}

// TestDriveIPv4 pushes an ICMP echo request into a stack built from a
// synthesised ifconfig and reads the reply back out. That single exchange
// exercises the whole seam, inject to read.
func TestDriveIPv4(t *testing.T) {
	d := openDevice(t, paramsV4())

	local := mustAddr4(tunLocal4)
	peer := mustAddr4(tunPeer4)
	payload := []byte("drive v4")

	if err := d.WritePacket(echoRequest4(peer, local, 0xbeef, 1, payload)); err != nil {
		t.Fatalf("WritePacket: %v", err)
	}

	out := readPacket(t, d)
	if len(out) < header.IPv4MinimumSize {
		t.Fatalf("reply is %d bytes, too short for an IPv4 header", len(out))
	}
	ip := header.IPv4(out)
	if got, want := ip.SourceAddress(), local; got != want {
		t.Errorf("reply source = %s, want %s", got, want)
	}
	if got, want := ip.DestinationAddress(), peer; got != want {
		t.Errorf("reply destination = %s, want %s", got, want)
	}
	if got := ip.Protocol(); got != uint8(header.ICMPv4ProtocolNumber) {
		t.Fatalf("reply protocol = %d, want ICMPv4", got)
	}

	msg := header.ICMPv4(out[ip.HeaderLength():])
	if got := msg.Type(); got != header.ICMPv4EchoReply {
		t.Fatalf("reply ICMP type = %d, want echo reply", got)
	}
	if got := msg.Ident(); got != 0xbeef {
		t.Errorf("reply ident = %#x, want 0xbeef", got)
	}
	if !bytes.Equal(msg.Payload(), payload) {
		t.Errorf("reply payload = %q, want %q", msg.Payload(), payload)
	}
}

// TestDriveIPv6 is TestDriveIPv4's twin on a stack built from a synthesised
// ifconfig-ipv6. IPv6 is in the netstack path from day one and this is what
// holds it there until a matrix entry can prove it end to end.
func TestDriveIPv6(t *testing.T) {
	d := openDevice(t, paramsV6())

	local := mustAddr6(tunLocal6)
	peer := mustAddr6(tunPeer6)
	payload := []byte("drive v6")

	if err := d.WritePacket(echoRequest6(peer, local, 0xcafe, 7, payload)); err != nil {
		t.Fatalf("WritePacket: %v", err)
	}

	out := readPacket(t, d)
	if len(out) < header.IPv6MinimumSize {
		t.Fatalf("reply is %d bytes, too short for an IPv6 header", len(out))
	}
	ip := header.IPv6(out)
	if got, want := ip.SourceAddress(), local; got != want {
		t.Errorf("reply source = %s, want %s", got, want)
	}
	if got, want := ip.DestinationAddress(), peer; got != want {
		t.Errorf("reply destination = %s, want %s", got, want)
	}
	if got := ip.TransportProtocol(); got != header.ICMPv6ProtocolNumber {
		t.Fatalf("reply next header = %d, want ICMPv6", got)
	}

	msg := header.ICMPv6(out[header.IPv6MinimumSize:])
	if got := msg.Type(); got != header.ICMPv6EchoReply {
		t.Fatalf("reply ICMP type = %d, want echo reply", got)
	}
	if got := msg.Ident(); got != 0xcafe {
		t.Errorf("reply ident = %#x, want 0xcafe", got)
	}
	if body := out[header.IPv6MinimumSize+header.ICMPv6EchoMinimumSize:]; !bytes.Equal(body, payload) {
		t.Errorf("reply payload = %q, want %q", body, payload)
	}
}

// TestDriveDualStack proves the two families coexist on one stack: both
// addresses are assigned and both default routes are present at the same time.
func TestDriveDualStack(t *testing.T) {
	d := openDevice(t, paramsDual())

	if !d.ts.v4.IsValid() {
		t.Error("dual-stack device has no IPv4 address")
	}
	if !d.ts.v6.IsValid() {
		t.Error("dual-stack device has no IPv6 address")
	}

	local4 := mustAddr4(tunLocal4)
	peer4 := mustAddr4(tunPeer4)
	if err := d.WritePacket(echoRequest4(peer4, local4, 1, 1, []byte("v4"))); err != nil {
		t.Fatalf("WritePacket v4: %v", err)
	}
	if got := header.IPv4(readPacket(t, d)).SourceAddress(); got != local4 {
		t.Errorf("v4 reply source = %s, want %s", got, local4)
	}

	local6 := mustAddr6(tunLocal6)
	peer6 := mustAddr6(tunPeer6)
	if err := d.WritePacket(echoRequest6(peer6, local6, 2, 2, []byte("v6"))); err != nil {
		t.Fatalf("WritePacket v6: %v", err)
	}
	if got := header.IPv6(readPacket(t, d)).SourceAddress(); got != local6 {
		t.Errorf("v6 reply source = %s, want %s", got, local6)
	}
}

// TestAssignedAddresses checks that the addresses recorded on the stack are the
// ones the PUSH_REPLY named, for each of the three addressing shapes.
func TestAssignedAddresses(t *testing.T) {
	for _, tc := range []struct {
		name   string
		params device.Params
		want4  string
		want6  string
	}{
		{"v4only", paramsV4(), tunLocal4, ""},
		{"v6only", paramsV6(), "", tunLocal6},
		{"dual", paramsDual(), tunLocal4, tunLocal6},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := openDevice(t, tc.params)

			var got4, got6 string
			if d.ts.v4.IsValid() {
				got4 = d.ts.v4.String()
			}
			if d.ts.v6.IsValid() {
				got6 = d.ts.v6.String()
			}
			if got4 != tc.want4 {
				t.Errorf("IPv4 = %q, want %q", got4, tc.want4)
			}
			if got6 != tc.want6 {
				t.Errorf("IPv6 = %q, want %q", got6, tc.want6)
			}
		})
	}
}

// TestNet30Ifconfig covers the other topology: net30 pushes a peer address
// instead of a mask, and the parser turns that into a /30.
func TestNet30Ifconfig(t *testing.T) {
	p := device.Params{
		Push: &routing.PushOptions{
			Topology: routing.TopologyNet30,
			Ifconfig: &routing.Ifconfig{
				Local:   net.ParseIP("10.8.0.6").To4(),
				Mask:    net.CIDRMask(30, 32),
				Gateway: net.ParseIP("10.8.0.5").To4(),
			},
		},
		MTU: testMTU,
	}
	d := openDevice(t, p)
	if got, want := d.ts.v4.String(), "10.8.0.6"; got != want {
		t.Errorf("IPv4 = %q, want %q", got, want)
	}
}

// TestOpenRejects covers the parameter shapes that cannot produce a data path.
// A PUSH_REPLY with no addressing has to be an error: the alternative is a
// device that reports success and silently drops every packet.
func TestOpenRejects(t *testing.T) {
	for _, tc := range []struct {
		name   string
		params device.Params
		want   string
	}{
		{"no push", device.Params{MTU: testMTU}, "no pushed options"},
		{"no ifconfig", device.Params{Push: &routing.PushOptions{}, MTU: testMTU}, "neither ifconfig"},
		{"zero MTU", func() device.Params { p := paramsV4(); p.MTU = 0; return p }(), "MTU"},
		{"huge MTU", func() device.Params { p := paramsV4(); p.MTU = 1 << 20; return p }(), "MTU"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, err := (&Backend{}).Open(context.Background(), tc.params)
			if err == nil {
				d.Close() //nolint:errcheck
				t.Fatalf("Open succeeded, want an error mentioning %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("Open error = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

// TestOpenHonoursContext checks that a cancelled context does not produce a
// live stack.
func TestOpenHonoursContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	d, err := (&Backend{}).Open(ctx, paramsV4())
	if err == nil {
		d.Close() //nolint:errcheck
		t.Fatal("Open with a cancelled context succeeded")
	}
	if !strings.Contains(err.Error(), "context canceled") {
		t.Errorf("Open error = %v, want a context error", err)
	}
}
