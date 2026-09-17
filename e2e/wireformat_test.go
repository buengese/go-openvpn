// SPDX-License-Identifier: LGPL-2.1-or-later

//go:build docker

// Both data-channel wire formats, asserted on the wire.
//
// The two formats differ by three bytes in one place. A round trip cannot tell
// them apart — a client with the format backwards in both directions talks
// happily to itself — and neither can a report that records only the peer-id,
// because "peer-id 0" and no peer-id both leave that value 0. So these tests
// read the datagrams: a UDP relay sits between the client and the container,
// forwards everything, and keeps a copy of every data packet in each direction.
package e2e

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openlawsvpn/go-openlawsvpn/netstack"
	"github.com/openlawsvpn/go-openlawsvpn/profile"
	"github.com/openlawsvpn/go-openlawsvpn/testenv"
)

// Opcodes, spelled as the first byte of a packet rather than as the 5-bit
// opcode, because that is the form the assertions read off the wire.
// Hard-coding them is the point: a test that computed the expected byte from
// the same constant the client uses would agree with the client about a
// mistake.
//
//	P_DATA_V1 = 6, so 6<<3 = 0x30
//	P_DATA_V2 = 9, so 9<<3 = 0x48
const (
	firstByteDataV1 = 0x30
	firstByteDataV2 = 0x48
	opcodeMask      = 0xF8
)

// isDataPacket reports whether the first byte carries one of the two data
// opcodes. Everything else on the socket is control traffic.
func isDataPacket(b byte) bool {
	switch b & opcodeMask {
	case firstByteDataV1, firstByteDataV2:
		return true
	}
	return false
}

// udpTap is a one-flow UDP relay that records the data packets crossing it. It
// exists because the wire is the only place the format is visible: it forwards
// every datagram untouched in both directions and copies the data ones aside.
type udpTap struct {
	// Addr is the host:port the client dials instead of the server.
	Addr string

	down   *net.UDPConn // faces the client
	server *net.UDPAddr

	mu       sync.Mutex
	up       *net.UDPConn // faces the container, opened on the first datagram
	toServer [][]byte
	toClient [][]byte
}

// startUDPTap listens on an ephemeral loopback port and relays to serverAddr.
func startUDPTap(t *testing.T, serverAddr string) *udpTap {
	t.Helper()

	dst, err := net.ResolveUDPAddr("udp", serverAddr)
	if err != nil {
		t.Fatalf("resolve %s: %v", serverAddr, err)
	}
	down, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	tap := &udpTap{Addr: down.LocalAddr().String(), down: down, server: dst}
	t.Cleanup(tap.stop)

	go tap.run()
	return tap
}

// stop closes both sockets, which ends both relay loops.
func (tap *udpTap) stop() {
	_ = tap.down.Close()
	tap.mu.Lock()
	up := tap.up
	tap.mu.Unlock()
	if up != nil {
		_ = up.Close()
	}
}

// run relays client-to-server until the socket closes. One client and one
// server, which is what a tunnel test has: the client's source address is fixed
// for the life of its socket, so it is captured with the first datagram.
func (tap *udpTap) run() {
	var (
		up   *net.UDPConn
		once sync.Once
	)
	buf := make([]byte, 65535)
	for {
		n, from, err := tap.down.ReadFromUDP(buf)
		if err != nil {
			return
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])

		once.Do(func() {
			u, derr := net.DialUDP("udp", nil, tap.server)
			if derr != nil {
				return
			}
			tap.mu.Lock()
			tap.up = u
			tap.mu.Unlock()
			up = u
			go tap.relayBack(u, from)
		})
		if up == nil {
			return
		}
		if n > 0 && isDataPacket(pkt[0]) {
			tap.mu.Lock()
			tap.toServer = append(tap.toServer, pkt)
			tap.mu.Unlock()
		}
		if _, err := up.Write(pkt); err != nil {
			return
		}
	}
}

// relayBack relays server-to-client until either socket closes.
func (tap *udpTap) relayBack(up *net.UDPConn, client *net.UDPAddr) {
	buf := make([]byte, 65535)
	for {
		n, err := up.Read(buf)
		if err != nil {
			return
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		if n > 0 && isDataPacket(pkt[0]) {
			tap.mu.Lock()
			tap.toClient = append(tap.toClient, pkt)
			tap.mu.Unlock()
		}
		if _, err := tap.down.WriteToUDP(pkt, client); err != nil {
			return
		}
	}
}

// captured returns copies of the data packets seen in each direction.
func (tap *udpTap) captured() (toServer, toClient [][]byte) {
	tap.mu.Lock()
	defer tap.mu.Unlock()
	return append([][]byte(nil), tap.toServer...), append([][]byte(nil), tap.toClient...)
}

// startTappedMatrixTunnel is startMatrixTunnel with a UDP relay in the middle.
// The profile is the one the rig generated, with its remote port rewritten to
// the relay's; everything else is applied exactly as startMatrixTunnel applies
// it, so a tapped tunnel and an untapped one differ only in what can be
// observed.
func startTappedMatrixTunnel(t *testing.T, entry string) (*testenv.MatrixServer, *netstack.Tunnel, *udpTap) {
	t.Helper()

	e, ok := testenv.Entry(entry)
	if !ok {
		t.Fatalf("no matrix entry %q", entry)
	}
	if e.Proto != testenv.ProtoUDP {
		t.Fatalf("%s is not a UDP entry; the tap relays datagrams", entry)
	}
	srv, err := testenv.StartMatrix(e)
	if err != nil {
		t.Skipf("StartMatrix: %v", err)
	}
	t.Cleanup(func() { _ = srv.Stop() })

	tap := startUDPTap(t, srv.DialAddr())

	text := srv.ClientProfile()
	from := fmt.Sprintf("remote 127.0.0.1 %d", srv.Port)
	to := "remote " + strings.Replace(tap.Addr, ":", " ", 1)
	if !strings.Contains(text, from) {
		t.Fatalf("generated profile has no %q line to redirect through the tap:\n%s", from, text)
	}
	text = strings.Replace(text, from, to, 1)

	p, err := profile.ParseString(text)
	if err != nil {
		t.Fatalf("ParseString: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	tun, err := netstack.Connect(ctx, p, matrixOptions(e))
	if err != nil {
		t.Fatalf("Connect to %s through the tap: %v", entry, err)
	}
	t.Cleanup(func() { _ = tun.Close() })
	return srv, tun, tap
}

// TestDataV1CarriesTrafficBothWays drives the P_DATA_V1 isolate, the one entry
// in the matrix whose data channel speaks the shorter header. The report
// assertion comes first and is not decoration: a tunnel that carried HTTP as
// P_DATA_V2 is still a tunnel that carried HTTP, against a server that would
// have spoken either format.
func TestDataV1CarriesTrafficBothWays(t *testing.T) {
	const entry = "v24-cbc256-sha256-plain-udp-datav1"

	e, ok := testenv.Entry(entry)
	if !ok {
		t.Fatalf("no matrix entry %q", entry)
	}
	if e.ClientUnsupported != "" {
		t.Fatalf("%s is still marked unsupported (%q); this test is what earns "+
			"clearing that marker", entry, e.ClientUnsupported)
	}
	if !e.DataV1 {
		t.Fatalf("%s has lost its DataV1 axis, so it no longer isolates the format", entry)
	}

	srv, tun, tap := startTappedMatrixTunnel(t, entry)

	rep := tun.Report()
	if got := rep.Negotiated.WireFormat; got != "P_DATA_V1" {
		// The two inputs are in the report, so a failure here says which of
		// them was wrong: the bit we advertised, or what the server pushed
		// back.
		t.Fatalf("negotiated wire format = %q, want %q\nadvertised IV_PROTO = %d\n"+
			"pushed: %s", got, "P_DATA_V1", rep.Advertised.IVProto, rep.Push.Raw)
	}
	if rep.Negotiated.PeerID != 0 {
		t.Errorf("peer-id = %d, want 0: P_DATA_V1 has no field to carry one",
			rep.Negotiated.PeerID)
	}

	fetchThroughTunnel(t, srv, tun, 8085, "through-a-p-data-v1-tunnel")

	toServer, toClient := tap.captured()
	if len(toServer) == 0 || len(toClient) == 0 {
		t.Fatalf("the tap saw %d data packets out and %d back; HTTP crossed, so this is "+
			"the tap failing rather than the tunnel", len(toServer), len(toClient))
	}
	for i, pkt := range toServer {
		if got := pkt[0] & opcodeMask; got != firstByteDataV1 {
			t.Fatalf("outbound data packet %d begins %#02x, want opcode %#02x: the client "+
				"is still sending a peer-id header to a peer that expects none",
				i, pkt[0], firstByteDataV1)
		}
	}
	for i, pkt := range toClient {
		if got := pkt[0] & opcodeMask; got != firstByteDataV1 {
			t.Fatalf("inbound data packet %d begins %#02x, want opcode %#02x",
				i, pkt[0], firstByteDataV1)
		}
	}
	t.Logf("P_DATA_V1: %d data packets out, %d back, all one-byte headers",
		len(toServer), len(toClient))
}

// TestDataV2StillSendsThePeerIDOnTheWire is the other half, and guards the
// regression adding P_DATA_V1 could most easily introduce: shortening the
// header for everybody would leave every P_DATA_V2 round-trip test in the tree
// passing, because both ends would agree on the mistake. A GCM entry, so the
// packet_id is in the clear.
func TestDataV2StillSendsThePeerIDOnTheWire(t *testing.T) {
	const entry = "v26-gcm256-sha256-plain-udp"

	srv, tun, tap := startTappedMatrixTunnel(t, entry)

	rep := tun.Report()
	if got := rep.Negotiated.WireFormat; got != "P_DATA_V2" {
		t.Fatalf("negotiated wire format = %q, want %q", got, "P_DATA_V2")
	}

	fetchThroughTunnel(t, srv, tun, 8086, "through-a-p-data-v2-tunnel")

	toServer, toClient := tap.captured()
	if len(toServer) == 0 || len(toClient) == 0 {
		t.Fatalf("the tap saw %d data packets out and %d back", len(toServer), len(toClient))
	}

	peerID := rep.Negotiated.PeerID
	want := []byte{byte(peerID >> 16), byte(peerID >> 8), byte(peerID)}
	for i, pkt := range toServer {
		if got := pkt[0] & opcodeMask; got != firstByteDataV2 {
			t.Fatalf("outbound data packet %d begins %#02x, want opcode %#02x",
				i, pkt[0], firstByteDataV2)
		}
		if len(pkt) < 8 {
			t.Fatalf("outbound data packet %d is %d bytes; a GCM P_DATA_V2 packet is at "+
				"least header(4) + packet_id(4)", i, len(pkt))
		}
		if got := pkt[1:4]; string(got) != string(want) {
			t.Fatalf("outbound data packet %d carries peer-id bytes % x, want % x "+
				"(the server pushed peer-id %d)", i, got, want, peerID)
		}
		// The packet_id lives at offset 4 because three peer-id bytes precede
		// it. Read at offset 1 — where P_DATA_V1 puts it — the same bytes are
		// the peer-id and a fragment of the counter.
		if id := binary.BigEndian.Uint32(pkt[4:8]); id == 0 || id > 1<<20 {
			t.Fatalf("outbound data packet %d has packet_id %d at offset 4, which is not a "+
				"counter; the header is not 4 bytes long", i, id)
		}
	}
	for i, pkt := range toClient {
		if got := pkt[0] & opcodeMask; got != firstByteDataV2 {
			t.Fatalf("inbound data packet %d begins %#02x, want opcode %#02x",
				i, pkt[0], firstByteDataV2)
		}
	}
	t.Logf("P_DATA_V2: %d data packets out, %d back, peer-id % x on every one",
		len(toServer), len(toClient), want)
}
