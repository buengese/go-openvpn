//go:build darwin

// SPDX-License-Identifier: LGPL-2.1-or-later

// The utun packet framing macOS and iOS share.
//
// Both platforms hand this package a raw utun control socket — the CLI opens
// one itself through SYSPROTO_CONTROL, the Network Extension hands one over
// through NEPacketTunnelFlow — and a utun is the same kernel interface either
// way. So the framing is the same, and it was written out twice.
//
// tun_common.go says why that matters here specifically: the copies had already
// drifted once, and it was these two functions they drifted in. The macOS Write
// kept labelling every packet PF_INET after the iOS one learned to read the
// version nibble, so a dual-stack tunnel on macOS sent IPv6 out and the kernel
// discarded everything that came back — a tunnel that connects, reports green
// and carries half the traffic. Reunited here, where there is one place for the
// next such fix to land.
package tun

// utunPktInfo is the 4-byte big-endian AF_ header the kernel prepends to every
// packet read from a utun fd and expects before every packet written to it.
// AF_INET = 2 and AF_INET6 = 30 on Darwin.
var (
	utunPktInfoAFInet  = [4]byte{0x00, 0x00, 0x00, 0x02}
	utunPktInfoAFInet6 = [4]byte{0x00, 0x00, 0x00, 0x1e}
)

// Read reads one IP packet from the utun device, stripping the 4-byte AF header.
func (d *Device) Read(buf []byte) (int, error) {
	// We need room for the 4-byte header + the IP packet.
	tmp := make([]byte, len(buf)+4)
	n, err := d.file.Read(tmp)
	if err != nil {
		return 0, err
	}
	if n < 4 {
		return 0, nil
	}
	return copy(buf, tmp[4:n]), nil
}

// Write writes one IP packet to the utun device, prepending the 4-byte AF
// header matching the packet's IP version.
//
// The header must match: a utun injects by address family rather than by
// reading the packet, so an IPv6 packet labelled PF_INET is dropped on its
// version nibble. This said PF_INET unconditionally while the kernel backend
// applies a pushed ifconfig-ipv6 to the interface, so a dual-stack tunnel sent
// IPv6 out and silently discarded everything that came back.
func (d *Device) Write(pkt []byte) (int, error) {
	hdr := utunPktInfoAFInet
	if len(pkt) > 0 && pkt[0]>>4 == 6 {
		hdr = utunPktInfoAFInet6
	}
	buf := make([]byte, 4+len(pkt))
	copy(buf[:4], hdr[:])
	copy(buf[4:], pkt)
	_, err := d.file.Write(buf)
	return len(pkt), err
}
