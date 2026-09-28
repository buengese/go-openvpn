// SPDX-License-Identifier: LGPL-2.1-or-later

// The socket: which endpoint is dialled, and what a packet looks like on the
// way through.
//
// Everything here sits below the handshake: a packet is wrapped or it is not,
// it names this session or it is dropped, and the dial either moves on to the
// next --remote line or stops.

package vpn

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/buengese/go-openvpn/diag"
	"github.com/buengese/go-openvpn/internal/crypto"
	"github.com/buengese/go-openvpn/internal/framing"
	"github.com/buengese/go-openvpn/internal/wrap"
	"github.com/buengese/go-openvpn/profile"
)

// ---- choosing the control-channel wrap -------------------------------------

// The client's side of the control-channel wrap: choosing it from the profile
// before the socket opens, dropping rather than dying on a packet the wrap
// refuses, and telling a server we cannot speak to from a server that is not
// there. The profile alone decides between tls-auth and tls-crypt, because the
// wrap authenticates the packet that would carry a negotiation; the wraps
// themselves are measured against captured vectors in internal/wrap.

// staticKey builds a distinguishable 256-byte static key. seed makes two keys
// that share no byte, which is what a "wrong key" test needs.
func staticKey(seed byte) *profile.StaticKey {
	var k profile.StaticKey
	for i := range k {
		k[i] = byte(i) ^ seed
	}
	return &k
}

// wrapperFor builds the tls-auth wrapper a peer holding this key would run.
func wrapperFor(t *testing.T, key *profile.StaticKey, dir wrap.Direction, digest crypto.Digest) wrap.Wrapper {
	t.Helper()
	w, err := wrap.NewTLSAuth((*wrap.StaticKey)(key), dir, digest)
	if err != nil {
		t.Fatalf("NewTLSAuth: %v", err)
	}
	return w
}

// controlPkt builds a plausible plain control packet with the given opcode.
func controlPkt(opcode uint8, body ...byte) []byte {
	pkt := []byte{framing.FirstByte(opcode, 0), 1, 2, 3, 4, 5, 6, 7, 8}
	return append(pkt, body...)
}

// TestSelectWrapperComesFromTheProfile pins where the wrap is decided. It is
// a property of the profile alone: nothing is negotiated, because tls-auth
// authenticates the packet that would carry a negotiation.
func TestSelectWrapperComesFromTheProfile(t *testing.T) {
	key := staticKey(0)
	cases := []struct {
		name         string
		prof         *profile.Profile
		wantName     string
		wantOverhead int
	}{
		{"no wrap", &profile.Profile{}, "none", 0},
		{
			"tls-auth kd1, default digest",
			&profile.Profile{TLSAuth: key, KeyDirection: profile.KeyDirection1},
			"tls-auth", 20 + 8,
		},
		{
			"tls-auth kd0, SHA256",
			&profile.Profile{TLSAuth: key, KeyDirection: profile.KeyDirection0, Auth: "SHA256"},
			"tls-auth", 32 + 8,
		},
		{
			"tls-auth, SHA512 — the matrix's cbc256-sha512 pair",
			&profile.Profile{TLSAuth: key, KeyDirection: profile.KeyDirection1, Auth: "SHA512"},
			"tls-auth", 64 + 8,
		},
		{
			// Absent is a third behaviour, not a default of 0, and the
			// wrap implements it.
			"tls-auth, absent key-direction",
			&profile.Profile{TLSAuth: key, KeyDirection: profile.KeyDirectionAbsent},
			"tls-auth", 20 + 8,
		},
		{
			// tls-crypt takes nothing from the profile but the key: no
			// key-direction, and no digest — tls_crypt_kt() fixes SHA256 —
			// so --auth beside it changes nothing here.
			"tls-crypt",
			&profile.Profile{TLSCrypt: key},
			"tls-crypt", 32 + 8,
		},
		{
			"tls-crypt ignores --auth and key-direction",
			&profile.Profile{TLSCrypt: key, Auth: "SHA512", KeyDirection: profile.KeyDirection0},
			"tls-crypt", 32 + 8,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &Client{prof: tc.prof}
			if err := c.selectWrapper(); err != nil {
				t.Fatalf("selectWrapper: %v", err)
			}
			if got := c.controlWrapper().Name(); got != tc.wantName {
				t.Errorf("Name() = %q, want %q", got, tc.wantName)
			}
			if got := c.controlWrapper().Overhead(); got != tc.wantOverhead {
				t.Errorf("Overhead() = %d, want %d", got, tc.wantOverhead)
			}
		})
	}
}

// TestSelectWrapperRefusesProfilesItCannotHonour keeps an unbuildable wrap out
// of the dial. Both shapes are config errors, and dialing could not help
// either: the first packet we would send is the one the wrap has to produce.
func TestSelectWrapperRefusesProfilesItCannotHonour(t *testing.T) {
	t.Run("an --auth digest the wrap cannot be built from", func(t *testing.T) {
		c := &Client{prof: &profile.Profile{TLSAuth: staticKey(0), Auth: "MD5"}}
		if err := c.selectWrapper(); err == nil {
			t.Fatal("selectWrapper accepted an unsupported --auth digest")
		}
	})

	// OpenVPN refuses --tls-auth and --tls-crypt together, and so must we: they
	// are different wire formats for the same packet, and picking one would be
	// guessing which server is on the other end. Failing at parse is the honest
	// outcome — the alternative dies at reset with no way to tell why.
	t.Run("both wraps at once", func(t *testing.T) {
		c := &Client{prof: &profile.Profile{
			TLSAuth:      staticKey(0),
			TLSCrypt:     staticKey(1),
			KeyDirection: profile.KeyDirection1,
		}}
		err := c.selectWrapper()
		if err == nil {
			t.Fatal("selectWrapper accepted a profile carrying both a tls-auth and a tls-crypt key")
		}
		if !strings.Contains(err.Error(), "mutually exclusive") {
			t.Errorf("error = %v, want it to say the two wraps are mutually exclusive", err)
		}
		// And the key material must not have come along for the ride.
		for _, k := range []*profile.StaticKey{staticKey(0), staticKey(1)} {
			if strings.Contains(err.Error(), fmt.Sprintf("%x", k[:8])) {
				t.Error("the refusal carries static key bytes")
			}
		}
	})
}

// TestWrapIsChosenBeforeTheSocketOpens drives the real entry point. The wrap
// has to exist by the end of the parse stage, because the packet after the dial
// is the HARD_RESET the wrap authenticates, so the assertion that matters is
// the one after the failure: the wrapper is installed even though the attempt
// never got past the dial, and its overhead is the MTU budget's input.
func TestWrapIsChosenBeforeTheSocketOpens(t *testing.T) {
	for _, tc := range []struct {
		name         string
		prof         profile.Profile
		wantName     string
		wantOverhead int
	}{
		{
			name:         "tls-auth",
			prof:         profile.Profile{TLSAuth: staticKey(0), KeyDirection: profile.KeyDirection1},
			wantName:     "tls-auth",
			wantOverhead: 20 + 8,
		},
		{
			name:         "tls-crypt",
			prof:         profile.Profile{TLSCrypt: staticKey(0)},
			wantName:     "tls-crypt",
			wantOverhead: 40,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := tc.prof
			p.Remote, p.Port, p.Proto = "127.0.0.1", closedTCPPort(t), profile.ProtoTCP
			p.CA = testCAPEM(t)

			c := New(&p)
			// The profile carries no client certificate, so AuthFlow reads it
			// as FlowUserPass and the preflight gate would refuse it at
			// StageParse. This is about the wrap, not the credentials.
			c.CredentialsFn = stubCredentials("user", "pass")
			if got := c.controlWrapper().Name(); got != "none" {
				t.Fatalf("New installed %q before the attempt began; the wrap is per attempt", got)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			err := c.Connect(ctx) // fails at dial: the port is closed
			if err == nil {
				t.Fatal("Connect succeeded against a closed port")
			}
			if got := c.controlWrapper().Name(); got != tc.wantName {
				t.Fatalf("wrapper after a dial failure = %q, want %q: it must be fixed at parse",
					got, tc.wantName)
			}
			if got := c.controlWrapper().Overhead(); got != tc.wantOverhead {
				t.Fatalf("Overhead() = %d, want %d — the MTU budget is computed from this",
					got, tc.wantOverhead)
			}

			var derr *diag.Error
			if !errors.As(err, &derr) || derr.Stage != diag.StageDial {
				t.Fatalf("error = %v, want a dial-stage failure — the wrap must not have "+
					"moved the failure earlier", err)
			}
			if got := c.Report().Negotiated.TLSWrap; got != tc.wantName {
				t.Errorf("Negotiated.TLSWrap = %q, want %q", got, tc.wantName)
			}
		})
	}
}

// udpPair returns a connected UDP socket for the client and a function that
// sends one datagram to it from a different socket. Real UDP rather than
// net.Pipe, because the point is an off-path datagram arriving at a connected
// socket, which is the shape net.Pipe cannot have.
func udpPair(t *testing.T) (client net.Conn, send func([]byte)) {
	t.Helper()
	server, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { server.Close() })

	conn, err := net.DialUDP("udp", nil, server.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	// The server learns the client's address from one datagram, so that it
	// can answer on the four-tuple the client's socket is connected to.
	if _, err := conn.Write([]byte{0xff}); err != nil {
		t.Fatalf("hello: %v", err)
	}
	buf := make([]byte, 64)
	if err := server.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	_, from, err := server.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("read hello: %v", err)
	}
	return conn, func(pkt []byte) {
		if _, err := server.WriteToUDP(pkt, from); err != nil {
			t.Errorf("send: %v", err)
		}
	}
}

// TestGarbageDatagramDoesNotEndTheSession pins that a packet the wrap refuses
// is dropped rather than fatal: OpenVPN silently drops a packet that fails its
// HMAC, and on UDP an error would let any off-path attacker who can guess the
// four-tuple kill the session with one datagram. Garbage arrives mid-session,
// the next genuine packet is delivered, and the drop is counted.
func TestGarbageDatagramDoesNotEndTheSession(t *testing.T) {
	key := staticKey(0)
	conn, send := udpPair(t)

	c := clientWithWrapper(&profile.Profile{Proto: profile.ProtoUDP},
		wrapperFor(t, key, wrap.Direction1, crypto.DigestSHA1))
	// The peer of a key-direction 1 client runs direction 0.
	peer := wrapperFor(t, key, wrap.Direction0, crypto.DigestSHA1)

	genuine := controlPkt(framing.P_CONTROL_V1, 0xde, 0xad, 0xbe, 0xef)
	onWire, err := peer.Wrap(genuine)
	if err != nil {
		t.Fatalf("peer Wrap: %v", err)
	}

	// Three ways to be garbage: unauthenticated noise of a plausible size,
	// a genuine packet with one bit flipped, and a runt.
	noise := controlPkt(framing.P_CONTROL_V1)
	noise = append(noise, bytes.Repeat([]byte{0xaa}, 40)...)
	flipped := append([]byte(nil), onWire...)
	flipped[len(flipped)-1] ^= 0x80
	runt := []byte{framing.FirstByte(framing.P_ACK_V1, 0), 0x01}

	go func() {
		for _, pkt := range [][]byte{noise, flipped, runt} {
			send(pkt)
		}
		send(onWire)
	}()

	if err := conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	got, err := c.readPacket(conn)
	if err != nil {
		t.Fatalf("readPacket ended the session on garbage: %v", err)
	}
	if !bytes.Equal(got, genuine) {
		t.Fatalf("readPacket = %x, want the genuine packet %x", got, genuine)
	}
	if n := c.controlAuthFailures.Load(); n != 3 {
		t.Errorf("controlAuthFailures = %d, want 3; a drop nobody counts tells a sweep nothing", n)
	}
	if n := c.controlReplays.Load(); n != 0 {
		t.Errorf("controlReplays = %d, want 0: none of those authenticated", n)
	}
}

// TestReplayedControlPacketIsRejectedAndCounted pins the replay window at the
// seam the client uses. The replayed packet is a genuine one, so it
// authenticates and only the window refuses it; counting it apart from an
// authentication failure is the point, because a duplicating path and a wrong
// key are different diagnoses.
func TestReplayedControlPacketIsRejectedAndCounted(t *testing.T) {
	key := staticKey(0)
	conn, send := udpPair(t)

	c := clientWithWrapper(&profile.Profile{Proto: profile.ProtoUDP},
		wrapperFor(t, key, wrap.Direction1, crypto.DigestSHA1))
	peer := wrapperFor(t, key, wrap.Direction0, crypto.DigestSHA1)

	first := controlPkt(framing.P_ACK_V1, 0x01)
	second := controlPkt(framing.P_CONTROL_V1, 0x02)
	firstWire, err := peer.Wrap(first)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	secondWire, err := peer.Wrap(second)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}

	go func() {
		send(firstWire)
		send(firstWire) // the replay
		send(secondWire)
	}()

	if err := conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	got, err := c.readPacket(conn)
	if err != nil {
		t.Fatalf("first readPacket: %v", err)
	}
	if !bytes.Equal(got, first) {
		t.Fatalf("first packet = %x, want %x", got, first)
	}
	// The replay is dropped inside readPacket, so the next call returns the
	// packet after it rather than the duplicate.
	got, err = c.readPacket(conn)
	if err != nil {
		t.Fatalf("second readPacket: %v", err)
	}
	if !bytes.Equal(got, second) {
		t.Fatalf("second packet = %x, want %x — the replay was delivered", got, second)
	}
	if n := c.controlReplays.Load(); n != 1 {
		t.Errorf("controlReplays = %d, want 1", n)
	}
	if n := c.controlAuthFailures.Load(); n != 0 {
		t.Errorf("controlAuthFailures = %d, want 0: the replay authenticated fine", n)
	}
}

// TestControlDropsAreCountedByReason pins the split, which is the whole reason
// there are three counters rather than one.
func TestControlDropsAreCountedByReason(t *testing.T) {
	var c Client
	c.countControlDrop(wrap.ErrAuth)
	c.countControlDrop(wrap.ErrReplay)
	c.countControlDrop(wrap.ErrStaleTimestamp)
	c.countControlDrop(errors.New("something else entirely"))

	if got := c.controlAuthFailures.Load(); got != 2 {
		t.Errorf("controlAuthFailures = %d, want 2 (ErrAuth and the unclassified reason)", got)
	}
	if got := c.controlReplays.Load(); got != 1 {
		t.Errorf("controlReplays = %d, want 1", got)
	}
	if got := c.controlStaleTimestamps.Load(); got != 1 {
		t.Errorf("controlStaleTimestamps = %d, want 1", got)
	}

	// And they reach the report, which is the only place a sweep can read them.
	counters := c.counters()
	if counters.ControlAuthFailures != 2 || counters.ControlReplays != 1 || counters.ControlStaleTimestamps != 1 {
		t.Errorf("counters = %+v, want the tallies above", counters)
	}
	if counters.Replays != 0 {
		t.Error("a control-channel replay was counted as a data-channel one")
	}
}

// wrongKeyServer accepts one TCP connection, answers the client's HARD_RESET
// with a control packet authenticated under a different static key, and hangs
// up: reachable, talking, and impossible to speak to.
func wrongKeyServer(t *testing.T, serverKey *profile.StaticKey) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	w := wrapperFor(t, serverKey, wrap.Direction0, crypto.DigestSHA1)
	reply, err := w.Wrap(controlPkt(framing.P_CONTROL_HARD_RESET_SERVER_V2, 0x00, 0x00, 0x00, 0x00, 0x00))
	if err != nil {
		t.Fatalf("server Wrap: %v", err)
	}

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// Read the client's HARD_RESET, answer once, and hang up. The
		// hang-up is what keeps the test fast; a real server would simply
		// go on saying things we cannot read.
		if _, err := framing.ReadTCP(conn); err != nil {
			return
		}
		framing.WriteTCP(conn, reply) //nolint:errcheck
	}()

	return ln.Addr().(*net.TCPAddr).Port
}

// TestWrongStaticKeyFailsResetWithClassCrypto is the diagnostic point of the
// whole unit: a wrapped server we hold the wrong key for must not look like a
// dead one. The transport came up, the peer answered, and not one packet of its
// answer authenticated under the key the profile carries — which is ClassCrypto
// by diag's own definition, not the ClassNetwork that sends a reader to the
// network.
func TestWrongStaticKeyFailsResetWithClassCrypto(t *testing.T) {
	clientKey, serverKey := staticKey(0x00), staticKey(0x5a)
	port := wrongKeyServer(t, serverKey)

	c := New(&profile.Profile{
		Remote:       "127.0.0.1",
		Port:         port,
		Proto:        profile.ProtoTCP,
		CA:           testCAPEM(t),
		TLSAuth:      clientKey,
		KeyDirection: profile.KeyDirection1,
	})

	// The profile carries no client certificate, so AuthFlow reads it as
	// FlowUserPass and the preflight gate would refuse it at StageParse.
	// Satisfy that axis: this test is about the wrap, not the credentials.
	c.CredentialsFn = stubCredentials("user", "pass")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	err := c.Connect(ctx)
	if err == nil {
		t.Fatal("Connect succeeded against a server whose key we do not have")
	}

	var derr *diag.Error
	if !errors.As(err, &derr) {
		t.Fatalf("error is not a *diag.Error: %T: %v", err, err)
	}
	if derr.Stage != diag.StageReset {
		t.Errorf("stage = %s, want reset", derr.Stage)
	}
	if derr.Class != diag.ClassCrypto {
		t.Errorf("class = %s, want crypto — a wrapped server is not a dead one", derr.Class)
	}

	rep := c.Report()
	if rep.Outcome.Class != diag.ClassCrypto || rep.Outcome.Stage != diag.StageReset {
		t.Errorf("outcome = %s at %s, want crypto at reset", rep.Outcome.Class, rep.Outcome.Stage)
	}
	if rep.Counters.ControlAuthFailures == 0 {
		t.Error("the report carries no authentication failures; the class then rests on nothing")
	}
	if rep.Negotiated.TLSWrap != "tls-auth" {
		t.Errorf("Negotiated.TLSWrap = %q, want tls-auth", rep.Negotiated.TLSWrap)
	}
}

// TestSilentServerStaysClassNetwork is the other half, and what keeps the test
// above honest. A server that drops our packet because the key is wrong and a
// server that is gone both say nothing, so the class turns on having heard
// something we could not read.
func TestSilentServerStaysClassNetwork(t *testing.T) {
	var c Client
	class, detail := c.resetFailureClass()
	if class != diag.ClassNetwork {
		t.Errorf("class with no evidence = %s, want network", class)
	}
	if detail != "" {
		t.Errorf("detail = %q, want empty", detail)
	}

	c.controlAuthFailures.Add(4)
	class, detail = c.resetFailureClass()
	if class != diag.ClassCrypto {
		t.Errorf("class after 4 authentication failures = %s, want crypto", class)
	}
	if detail == "" {
		t.Error("detail is empty; the class must say what it rests on")
	}

	// A replay is not evidence of a wrong key: it authenticated.
	var d Client
	d.controlReplays.Add(9)
	d.controlStaleTimestamps.Add(9)
	if class, _ := d.resetFailureClass(); class != diag.ClassNetwork {
		t.Errorf("class from replays alone = %s, want network", class)
	}
}

// ---- the wrap seam ---------------------------------------------------------

// panicWrapper is a Wrapper that fails loudly the instant a packet reaches it.
// A counting mock would let a data packet through the wrap and report the count
// afterwards, by which time the test has proved nothing; panicking makes the
// wrong path unsurvivable, in the goroutine that took it.
type panicWrapper struct{}

func (panicWrapper) Wrap([]byte) ([]byte, error) {
	panic("wrap seam reached with a packet that must bypass it")
}

func (panicWrapper) Unwrap([]byte) ([]byte, error) {
	panic("unwrap seam reached with a packet that must bypass it")
}

func (panicWrapper) Overhead() int { return 0 }
func (panicWrapper) Name() string  { return "panic" }

// allOpcodes is every opcode defined in internal/framing, paired with whether
// the wrap seam is allowed to see it. The list is written out by hand because
// internal/framing offers no enumeration of its opcodes; what notices a new one
// is the "unknown opcodes are wrapped" subtest below, which needs no list.
var allOpcodes = []struct {
	name   string
	opcode uint8
	wraps  bool
}{
	{"P_CONTROL_HARD_RESET_CLIENT_V2", framing.P_CONTROL_HARD_RESET_CLIENT_V2, true},
	{"P_CONTROL_HARD_RESET_SERVER_V2", framing.P_CONTROL_HARD_RESET_SERVER_V2, true},
	{"P_CONTROL_SOFT_RESET_V1", framing.P_CONTROL_SOFT_RESET_V1, true},
	{"P_CONTROL_V1", framing.P_CONTROL_V1, true},
	{"P_ACK_V1", framing.P_ACK_V1, true},
	{"P_DATA_V1", framing.P_DATA_V1, false},
	{"P_DATA_V2", framing.P_DATA_V2, false},
}

// TestWrapsPacket pins which side of the seam every packet falls on. Data
// packets share the readPacket/writePacket seam with control packets, and a
// wrap applied to them corrupts the data channel after a successful handshake —
// a failure that only appears once everything else has gone right.
func TestWrapsPacket(t *testing.T) {
	t.Run("every declared opcode, at every key_id", func(t *testing.T) {
		for _, tc := range allOpcodes {
			t.Run(tc.name, func(t *testing.T) {
				for keyID := uint8(0); keyID < 8; keyID++ {
					pkt := []byte{framing.FirstByte(tc.opcode, keyID), 0xaa, 0xbb}
					if got := wrapsPacket(pkt); got != tc.wraps {
						t.Fatalf("wrapsPacket(opcode=%d key_id=%d) = %v, want %v",
							tc.opcode, keyID, got, tc.wraps)
					}
				}
			})
		}
	})

	// The default branch. Only the two data opcodes bypass the wrap; the 25
	// unassigned opcode values go through it, because an opcode this client
	// does not know is a control opcode it has not implemented, and wrapping it
	// is the recoverable error. Sweeping the range needs no list: a new control
	// opcode is in 0..31 and must be wrapped, and this fails naming it.
	t.Run("unknown opcodes are wrapped", func(t *testing.T) {
		for op := uint8(0); op < 32; op++ {
			if op == framing.P_DATA_V1 || op == framing.P_DATA_V2 {
				continue
			}
			pkt := []byte{framing.FirstByte(op, 0)}
			if !wrapsPacket(pkt) {
				t.Fatalf("opcode 0x%02x bypasses the wrap; only data opcodes may", op)
			}
		}
	})

	// A packet with no opcode must not be indexed. The framing layer rejects
	// it downstream; the wrap has nothing to say about it.
	t.Run("an empty packet is not wrapped", func(t *testing.T) {
		if wrapsPacket(nil) {
			t.Fatal("wrapsPacket(nil) = true, want false")
		}
		if wrapsPacket([]byte{}) {
			t.Fatal("wrapsPacket(empty) = true, want false")
		}
	})
}

// TestDataPacketsBypassTheWrapper drives the real readPacket and writePacket
// with a wrapper that panics, once per data opcode and once per direction, and
// requires the bytes to survive untouched. Both directions matter: tunToWire
// and keepaliveLoop write P_DATA_V2 frames through writePacket, the inbound
// relay reads them back through readPacket, and a blind wrap on either side
// corrupts the tunnel.
func TestDataPacketsBypassTheWrapper(t *testing.T) {
	for _, op := range []uint8{framing.P_DATA_V1, framing.P_DATA_V2} {
		pkt := []byte{framing.FirstByte(op, 0), 0x00, 0x00, 0x01, 0xde, 0xad, 0xbe, 0xef}

		t.Run(fmt.Sprintf("write opcode 0x%02x", op), func(t *testing.T) {
			clientConn, serverConn := net.Pipe()
			t.Cleanup(func() {
				clientConn.Close()
				serverConn.Close()
			})
			c := clientWithWrapper(&profile.Profile{Proto: profile.ProtoTCP}, panicWrapper{})

			errc := make(chan error, 1)
			go func() { errc <- c.writePacket(clientConn, pkt) }()

			got, err := framing.ReadTCP(serverConn)
			if err != nil {
				t.Fatalf("ReadTCP: %v", err)
			}
			if err := <-errc; err != nil {
				t.Fatalf("writePacket: %v", err)
			}
			if !bytes.Equal(got, pkt) {
				t.Fatalf("wire = %x, want %x", got, pkt)
			}
		})

		t.Run(fmt.Sprintf("read opcode 0x%02x", op), func(t *testing.T) {
			clientConn, serverConn := net.Pipe()
			t.Cleanup(func() {
				clientConn.Close()
				serverConn.Close()
			})
			c := clientWithWrapper(&profile.Profile{Proto: profile.ProtoTCP}, panicWrapper{})

			go framing.WriteTCP(serverConn, pkt) //nolint:errcheck

			got, err := c.readPacket(clientConn)
			if err != nil {
				t.Fatalf("readPacket: %v", err)
			}
			if !bytes.Equal(got, pkt) {
				t.Fatalf("got %x, want %x", got, pkt)
			}
		})
	}
}

// countingWrapper records the packets it sees, so the control direction can be
// asserted positively: the seam is not merely harmless, it is actually there.
type countingWrapper struct {
	wrapped   [][]byte
	unwrapped [][]byte
	suffix    []byte
	err       error
}

func (w *countingWrapper) Wrap(pkt []byte) ([]byte, error) {
	if w.err != nil {
		return nil, w.err
	}
	w.wrapped = append(w.wrapped, append([]byte(nil), pkt...))
	return append(append([]byte(nil), pkt...), w.suffix...), nil
}

func (w *countingWrapper) Unwrap(pkt []byte) ([]byte, error) {
	if w.err != nil {
		return nil, w.err
	}
	w.unwrapped = append(w.unwrapped, append([]byte(nil), pkt...))
	return bytes.TrimSuffix(pkt, w.suffix), nil
}

func (w *countingWrapper) Overhead() int { return len(w.suffix) }
func (w *countingWrapper) Name() string  { return "counting" }

// TestControlPacketsReachTheWrapper is the other half of the guard. A seam
// that wraps nothing would pass every bypass test above, so assert that a
// control packet does go through it and does arrive on the wire transformed.
func TestControlPacketsReachTheWrapper(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	w := &countingWrapper{suffix: []byte{0xf0, 0x0d}}
	c := clientWithWrapper(&profile.Profile{Proto: profile.ProtoTCP}, w)
	pkt := []byte{framing.FirstByte(framing.P_CONTROL_V1, 3), 0x01, 0x02}

	errc := make(chan error, 1)
	go func() { errc <- c.writePacket(clientConn, pkt) }()

	onWire, err := framing.ReadTCP(serverConn)
	if err != nil {
		t.Fatalf("ReadTCP: %v", err)
	}
	if err := <-errc; err != nil {
		t.Fatalf("writePacket: %v", err)
	}
	if want := append(append([]byte(nil), pkt...), w.suffix...); !bytes.Equal(onWire, want) {
		t.Fatalf("wire = %x, want %x", onWire, want)
	}
	if len(w.wrapped) != 1 || !bytes.Equal(w.wrapped[0], pkt) {
		t.Fatalf("Wrap saw %x, want exactly one call with %x", w.wrapped, pkt)
	}

	go framing.WriteTCP(serverConn, onWire) //nolint:errcheck
	back, err := c.readPacket(clientConn)
	if err != nil {
		t.Fatalf("readPacket: %v", err)
	}
	if !bytes.Equal(back, pkt) {
		t.Fatalf("readPacket = %x, want the unwrapped %x", back, pkt)
	}
	if len(w.unwrapped) != 1 || !bytes.Equal(w.unwrapped[0], onWire) {
		t.Fatalf("Unwrap saw %x, want exactly one call with %x", w.unwrapped, onWire)
	}
}

// TestWrapFailureIsFatalOnTheWayOut checks that a packet the wrap refuses to
// produce never reaches the socket, and that the caller is told. Outbound and
// inbound are deliberately not symmetric: a wrap that cannot build our own
// packet is our problem with nothing to fall back on, while a packet we cannot
// authenticate is the peer's or an attacker's and is dropped.
func TestWrapFailureIsFatalOnTheWayOut(t *testing.T) {
	sentinel := errors.New("wrap refused")

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	c := clientWithWrapper(&profile.Profile{Proto: profile.ProtoTCP}, &countingWrapper{err: sentinel})
	pkt := []byte{framing.FirstByte(framing.P_CONTROL_V1, 0), 0x01}

	// A failed Wrap must not reach the socket at all. Drain the far end anyway
	// so that a regression which does write shows up as a failed assertion
	// rather than as a net.Pipe deadlock.
	drained := make(chan []byte, 1)
	go func() {
		got, err := framing.ReadTCP(serverConn)
		if err == nil {
			drained <- got
		}
		close(drained)
	}()

	if err := c.writePacket(clientConn, pkt); !errors.Is(err, sentinel) {
		t.Fatalf("writePacket error = %v, want one wrapping %v", err, sentinel)
	}

	clientConn.Close()
	if leaked, ok := <-drained; ok {
		t.Fatalf("a packet whose Wrap failed still reached the wire: %x", leaked)
	}
}

// TestUnwrapFailureDropsThePacket pins where a refused packet is fatal and
// where it is not. OpenVPN silently drops a packet that fails its HMAC, so the
// connection-fatal path is the read and not the unwrap: the refused packet is
// swallowed and counted, and the transport error underneath it is what finally
// comes back. A wrapper that refuses everything holds the seam itself in place.
func TestUnwrapFailureDropsThePacket(t *testing.T) {
	sentinel := errors.New("wrap refused")

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	c := clientWithWrapper(&profile.Profile{Proto: profile.ProtoTCP}, &countingWrapper{err: sentinel})
	pkt := []byte{framing.FirstByte(framing.P_CONTROL_V1, 0), 0x01}

	go func() {
		framing.WriteTCP(serverConn, pkt) //nolint:errcheck
		framing.WriteTCP(serverConn, pkt) //nolint:errcheck
		serverConn.Close()
	}()

	_, err := c.readPacket(clientConn)
	if err == nil {
		t.Fatal("readPacket returned a packet the wrap refused")
	}
	if errors.Is(err, sentinel) {
		t.Fatalf("readPacket surfaced the unwrap failure as a connection error: %v", err)
	}
	if n := c.controlAuthFailures.Load(); n != 2 {
		t.Errorf("controlAuthFailures = %d, want 2: both refused packets must be counted", n)
	}
}

// TestZeroValueClientUsesPlain covers the Client literals the existing tests
// build, which never go through New and so have no wrapper. They must behave
// as an unwrapped control channel rather than panicking on a nil interface.
func TestZeroValueClientUsesPlain(t *testing.T) {
	var c Client
	if got := c.controlWrapper().Name(); got != wrap.Plain().Name() {
		t.Fatalf("zero-value Client wrapper = %q, want %q", got, wrap.Plain().Name())
	}
	if got := c.controlWrapper().Overhead(); got != 0 {
		t.Fatalf("zero-value Client wrapper overhead = %d, want 0", got)
	}
}

// TestNewInstallsPlainWrapper pins that a client built the normal way runs the
// seam. Plain is what makes an unwrapped profile a pure refactor of a wrapped
// one: every connection exercises the wrap path, and none changes a byte.
func TestNewInstallsPlainWrapper(t *testing.T) {
	c := New(&profile.Profile{Proto: profile.ProtoUDP})
	if c.wrapper.Load() == nil {
		t.Fatal("New left the wrapper nil; the seam would be untested by every connection")
	}
	if got := c.controlWrapper().Name(); got != "none" {
		t.Fatalf("New installed %q, want %q", got, "none")
	}
}

// TestControlSegmentSizeAccountsForOverhead pins the MTU arithmetic the send
// goroutine uses. Plain subtracts nothing today, which is why it is worth
// asserting now rather than during a wrapped handshake.
func TestControlSegmentSizeAccountsForOverhead(t *testing.T) {
	cases := []struct {
		name    string
		wrapper wrap.Wrapper
		want    int
	}{
		{"nil wrapper", nil, controlSegmentBudget},
		{"plain", wrap.Plain(), controlSegmentBudget},
		{"overhead 56", &countingWrapper{suffix: make([]byte, 56)}, controlSegmentBudget - 56},
		// A Wrapper claiming more overhead than the whole budget is broken,
		// but it must not produce a zero-length segment: the send loop would
		// never advance.
		{"absurd overhead", &countingWrapper{suffix: make([]byte, controlSegmentBudget*2)}, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := clientWithWrapper(nil, tc.wrapper)
			if got := c.controlSegmentSize(); got != tc.want {
				t.Fatalf("controlSegmentSize() = %d, want %d", got, tc.want)
			}
		})
	}
}

// ---- one packet on and off the socket --------------------------------------

func TestWritePacketSerializesTCPFrames(t *testing.T) {
	// net.Pipe makes each individual Write rendezvous with the reader. Without
	// Client.writeMu, concurrent WriteTCP calls can therefore interleave their
	// two writes (length then payload) deterministically.
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	c := &Client{prof: &profile.Profile{Proto: profile.ProtoTCP}}
	const packetCount = 32
	start := make(chan struct{})
	errs := make(chan error, packetCount)
	for i := 0; i < packetCount; i++ {
		payload := []byte{byte(i)}
		go func() {
			<-start
			errs <- c.writePacket(clientConn, payload)
		}()
	}

	readErr := make(chan error, 1)
	go func() {
		seen := make(map[byte]bool, packetCount)
		for i := 0; i < packetCount; i++ {
			pkt, err := framing.ReadTCP(serverConn)
			if err != nil {
				readErr <- err
				return
			}
			if len(pkt) != 1 || seen[pkt[0]] {
				readErr <- fmt.Errorf("unexpected TCP frame: %x", pkt)
				return
			}
			seen[pkt[0]] = true
		}
		readErr <- nil
	}()

	close(start)
	for i := 0; i < packetCount; i++ {
		if err := <-errs; err != nil {
			t.Fatalf("writePacket: %v", err)
		}
	}
	if err := <-readErr; err != nil {
		t.Fatalf("TCP framing was interleaved: %v", err)
	}
}

// ---- whose session is this packet? -----------------------------------------

// A control packet has to name this session at both ends before the dispatcher
// will look at it. The reference matches an inbound control packet's source
// session id against the peer it recorded and drops what matches nothing
// (openvpn-2.6.22 src/openvpn/ssl.c:3777, :3860-3868), and where the packet
// echoes an id back, reliable_ack_read requires that one to be ours
// (reliable.c:159-168).
func TestControlPacketMustNameThisSession(t *testing.T) {
	var (
		ours   = [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
		theirs = [8]byte{9, 10, 11, 12, 13, 14, 15, 16}
		forged = [8]byte{0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 0}
	)
	c := &Client{clientSID: ours, serverSID: theirs}

	tests := []struct {
		name string
		pkt  []byte
		want bool
	}{
		{
			name: "server packet with no acks",
			pkt:  framing.BuildControlV1(theirs, ours, 0, 1, nil, []byte("tls")),
			want: true,
		},
		{
			name: "server packet acknowledging ours",
			pkt:  framing.BuildControlV1(theirs, ours, 0, 2, []uint32{1}, []byte("tls")),
			want: true,
		},
		{
			name: "bare ack from the server",
			pkt:  framing.BuildAck(theirs, ours, 0, []uint32{1}),
			want: true,
		},
		{
			name: "another session's packet",
			pkt:  framing.BuildControlV1(forged, ours, 0, 1, nil, []byte("tls")),
			want: false,
		},
		{
			// The source is right and the echo is not: a packet replayed
			// from a session this server had with somebody else.
			name: "our server, but addressed to another client",
			pkt:  framing.BuildControlV1(theirs, forged, 0, 2, []uint32{1}, []byte("tls")),
			want: false,
		},
		{
			name: "truncated below a session id",
			pkt:  []byte{framing.P_CONTROL_V1 << 3, 1, 2, 3},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := controlPacketIsOurs(tt.pkt, c.clientSID, c.serverSID); got != tt.want {
				t.Fatalf("controlPacketIsOurs = %v, want %v", got, tt.want)
			}
		})
	}
}

// The gate runs on control opcodes only. A data packet has no session id
// where one would be read from, and judging it by those bytes would drop the
// tunnel's traffic.
func TestOnlyControlOpcodesCarryASessionID(t *testing.T) {
	for _, op := range []uint8{framing.P_DATA_V1, framing.P_DATA_V2} {
		if isControlOpcode(op) {
			t.Errorf("opcode %#x treated as control", op)
		}
	}
	for _, op := range []uint8{
		framing.P_CONTROL_V1,
		framing.P_ACK_V1,
		framing.P_CONTROL_SOFT_RESET_V1,
		framing.P_CONTROL_HARD_RESET_CLIENT_V2,
	} {
		if !isControlOpcode(op) {
			t.Errorf("opcode %#x not treated as control", op)
		}
	}
}

// Remote failover: what a profile with more than one --remote line does. Three
// properties are asserted here, each invisible to a single-remote profile:
//
//   - The framing follows the dialed remote, not the profile's --proto.
//   - A single-remote profile makes exactly one dial. Counted, not inspected.
//   - The failure class decides whether there is a next remote at all.

// ---- The framing seam ----------------------------------------------------

// captureConn is a net.Conn that records what is written to it and does nothing
// else. The embedded interface is deliberately nil: only Write is exercised,
// and any other method a future writePacket started calling would panic here
// rather than pass silently.
type captureConn struct {
	net.Conn
	buf bytes.Buffer
}

func (c *captureConn) Write(p []byte) (int, error) { return c.buf.Write(p) }

// disagreeingProfile parses a profile whose --proto says one thing and whose
// second --remote line says the other. That shape is not contrived — a config
// may state its transport in a remote line's third field alone — and it is the
// only shape in which a reader asking the profile instead of the endpoint gives
// a wrong answer.
func disagreeingProfile(t *testing.T, profileProto, secondRemoteProto string) *profile.Profile {
	t.Helper()
	src := fmt.Sprintf(
		"client\nproto %s\nremote first.example.test 1194\nremote second.example.test 443 %s\n",
		profileProto, secondRemoteProto)
	p, err := profile.ParseString(src)
	if err != nil {
		t.Fatalf("ParseString: %v", err)
	}
	if len(p.Remotes) != 2 {
		t.Fatalf("got %d remotes, want 2", len(p.Remotes))
	}
	return p
}

// TestFramingFollowsTheDialedRemoteNotTheProfile is the guard on the hazard
// failover introduces. readPacket and writePacket choose between the UDP and
// TCP wire framings; Profile.Proto equals Remotes[0].Proto, so a reader asking
// the profile stays correct until the second remote is on the wire, and
// disagreeing there produces a connection that handshakes and then misframes
// every packet, control and data alike. Both directions are asserted, because
// one of them would pass against a reader that had simply been hardcoded.
func TestFramingFollowsTheDialedRemoteNotTheProfile(t *testing.T) {
	pkt := []byte{framing.FirstByte(framing.P_CONTROL_HARD_RESET_CLIENT_V2, 0), 0xde, 0xad, 0xbe, 0xef}

	for _, tc := range []struct {
		name          string
		profileProto  string
		remoteProto   string
		wantPrefixed  bool
		wantProfilePr profile.Proto
	}{
		{
			name: "udp profile, tcp remote", profileProto: "udp", remoteProto: "tcp-client",
			wantPrefixed: true, wantProfilePr: profile.ProtoUDP,
		},
		{
			name: "tcp profile, udp remote", profileProto: "tcp-client", remoteProto: "udp",
			wantPrefixed: false, wantProfilePr: profile.ProtoTCP,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := disagreeingProfile(t, tc.profileProto, tc.remoteProto)
			if p.Proto != tc.wantProfilePr {
				t.Fatalf("Profile.Proto = %v, want %v — the two must disagree for this test to test anything",
					p.Proto, tc.wantProfilePr)
			}

			c := New(p)
			c.setActiveRemote(p.Remotes[1])
			if c.activeProto() == p.Proto {
				t.Fatal("the dialed remote and the profile agree; nothing here is being tested")
			}

			// Write: capture every byte that reaches the socket. The TCP
			// framing writes the length prefix and the payload as two separate
			// Writes, so the capture has to be a buffer rather than one Read.
			cap := &captureConn{}
			if err := c.writePacket(cap, pkt); err != nil {
				t.Fatalf("writePacket: %v", err)
			}

			wire := cap.buf.Bytes()
			if len(wire) == 0 {
				t.Fatal("nothing reached the socket")
			}
			prefixed := len(wire) == len(pkt)+2 &&
				int(wire[0])<<8|int(wire[1]) == len(pkt) &&
				string(wire[2:]) == string(pkt)
			bare := string(wire) == string(pkt)
			switch {
			case tc.wantPrefixed && !prefixed:
				t.Fatalf("wrote % x, want a two-byte length prefix in front of % x — "+
					"the writer followed the profile's %v rather than the remote's %v",
					wire, pkt, p.Proto, c.activeProto())
			case !tc.wantPrefixed && !bare:
				t.Fatalf("wrote % x, want the bare packet % x — "+
					"the writer followed the profile's %v rather than the remote's %v",
					wire, pkt, p.Proto, c.activeProto())
			}

			// Read: feed the framing the dialed remote implies and require it
			// back verbatim. A reader on the wrong framing does not error here —
			// it returns a differently sliced packet.
			readClient, readServer := net.Pipe()
			defer readClient.Close() //nolint:errcheck
			defer readServer.Close() //nolint:errcheck
			go func() {
				if tc.wantPrefixed {
					framing.WriteTCP(readServer, pkt) //nolint:errcheck
					return
				}
				readServer.Write(pkt) //nolint:errcheck
			}()
			back, err := c.readPacket(readClient)
			if err != nil {
				t.Fatalf("readPacket: %v", err)
			}
			if string(back) != string(pkt) {
				t.Fatalf("readPacket returned % x, want % x — the reader used the wrong framing", back, pkt)
			}
		})
	}
}

// TestActiveRemoteDefaultsToTheProfile pins the answer every path that never
// reaches the failover loop gets: the mobile and relay Phase 2 entry points, and
// every Client assembled in a test rather than by Connect. It is what keeps a
// Client built from a hand-assembled profile — which has no Remotes list at all
// — dialing anything.
func TestActiveRemoteDefaultsToTheProfile(t *testing.T) {
	assembled := &profile.Profile{Remote: "vpn.example.test", Port: 443, Proto: profile.ProtoTCP}
	c := New(assembled)
	got := c.activeRemote()
	if got.Host != "vpn.example.test" || got.Port != 443 || got.Proto != profile.ProtoTCP {
		t.Errorf("activeRemote() = %+v, want the profile's own scalars", got)
	}
	if order := c.dialOrder(); len(order) != 1 || order[0].Remote != got {
		t.Errorf("dialOrder() = %+v, want the one remote the scalars describe", order)
	}

	// And a Client with no profile at all must not panic: several tests build
	// one, and readPacket reaches activeProto on every packet.
	if got := (&Client{}).activeProto(); got != profile.ProtoTCP {
		t.Errorf("zero-value Client activeProto() = %v, want the zero Proto", got)
	}
}

// ---- The dial order ------------------------------------------------------

// TestDialOrderIsFileOrderUnlessShuffled pins both halves of --remote-random.
// The assertion is on the set rather than on a permutation: a shuffle that
// dropped or duplicated a remote would be worse than no shuffle at all.
func TestDialOrderIsFileOrderUnlessShuffled(t *testing.T) {
	const hosts = "remote a.example.test 1\nremote b.example.test 2\n" +
		"remote c.example.test 3\nremote d.example.test 4\n"

	plain, err := profile.ParseString("client\n" + hosts)
	if err != nil {
		t.Fatalf("ParseString: %v", err)
	}
	if plain.RemoteRandom {
		t.Fatal("RemoteRandom set without the directive")
	}
	for i, target := range New(plain).dialOrder() {
		if target.Remote != plain.Remotes[i] || target.Index != i {
			t.Fatalf("dialOrder()[%d] = %+v, want index %d and %+v — file order is OpenVPN's order",
				i, target, i, plain.Remotes[i])
		}
	}

	shuffled, err := profile.ParseString("client\nremote-random\n" + hosts)
	if err != nil {
		t.Fatalf("ParseString: %v", err)
	}
	if !shuffled.RemoteRandom {
		t.Fatal("remote-random was not parsed")
	}
	c := New(shuffled)
	varied := false
	for range 64 {
		order := c.dialOrder()
		if len(order) != len(shuffled.Remotes) {
			t.Fatalf("shuffled order has %d remotes, want %d", len(order), len(shuffled.Remotes))
		}
		seen := map[string]int{}
		for _, target := range order {
			seen[target.Remote.Host]++
			// The index must survive the shuffle, or a shuffled report could
			// not say which line of the profile an attempt came from.
			if target.Remote != shuffled.Remotes[target.Index] {
				t.Fatalf("shuffled entry %+v carries index %d, which is %+v in the profile",
					target.Remote, target.Index, shuffled.Remotes[target.Index])
			}
		}
		for _, want := range shuffled.Remotes {
			if seen[want.Host] != 1 {
				t.Fatalf("host %q appears %d times in the shuffled order, want once",
					want.Host, seen[want.Host])
			}
		}
		if order[0].Remote != shuffled.Remotes[0] {
			varied = true
		}
	}
	if !varied {
		t.Error("64 shuffles of four remotes never moved the first one; the list is not being shuffled")
	}

	// The profile itself must be untouched: New keeps the caller's pointer,
	// and a permutation written back into it would leak into the next attempt
	// and into every other reader of the same parsed profile.
	for i, rem := range shuffled.Remotes {
		if rem.Host != string(rune('a'+i))+".example.test" {
			t.Fatalf("Remotes[%d] = %q; the shuffle wrote back into the caller's profile", i, rem.Host)
		}
	}
}

// TestDialOrderHonoursRewrittenScalars pins the compatibility direction.
// Profile.Remote, Port and Proto are Remotes[0], so a caller that parses a
// profile and then overwrites them to pin a resolved address, or to point a
// config at a mock, is doing the supported thing: a dial order built only from
// Remotes would resolve the parsed hostname again, which is the one thing the
// caller wrote the field to prevent. The rest of the list is untouched.
func TestDialOrderHonoursRewrittenScalars(t *testing.T) {
	p, err := profile.ParseString(
		"client\nproto udp\nremote parsed.example.test 1194\nremote second.example.test 443 tcp-client\n")
	if err != nil {
		t.Fatalf("ParseString: %v", err)
	}
	p.Remote, p.Port, p.Proto = "127.0.0.1", 9999, profile.ProtoTCP

	order := New(p).dialOrder()
	if len(order) != 2 {
		t.Fatalf("dialOrder() has %d targets, want 2", len(order))
	}
	first := order[0].Remote
	if first.Host != "127.0.0.1" || first.Port != 9999 || first.Proto != profile.ProtoTCP {
		t.Errorf("first target = %+v, want the rewritten scalars", first)
	}
	if order[0].Index != 0 {
		t.Errorf("first target index = %d, want 0", order[0].Index)
	}
	if order[1].Remote != p.Remotes[1] {
		t.Errorf("second target = %+v, want the profile's second remote %+v",
			order[1].Remote, p.Remotes[1])
	}
}

// ---- The failover policy -------------------------------------------------

// TestFailoverContinuesOnlyForEndpointFailures states the policy as a table,
// one row per error class. Every row answers the same question — is the failure
// a property of the endpoint, or of everything we brought to it — and the table
// is here so that changing one is a deliberate edit rather than a side effect.
func TestFailoverContinuesOnlyForEndpointFailures(t *testing.T) {
	for _, tc := range []struct {
		class diag.Class
		want  bool
		why   string
	}{
		{diag.ClassNetwork, true, "the endpoint is down or filtered; another may not be"},
		{diag.ClassTLS, true, "this server's certificate did not verify; another's may"},
		{diag.ClassProtocol, true, "a server quirk, which is a property of that server"},
		{diag.ClassCrypto, true, "a derivation mismatch with this peer"},
		{diag.ClassConfig, false, "the profile is unusable and would be unusable at the next endpoint too"},
		{diag.ClassUnsupported, false, "a feature we have not built; the next endpoint would need it as well"},
		{diag.ClassAuth, false, "the same credentials would be rejected again"},
		{diag.ClassLocal, false, "our own environment; no endpoint can help"},
		{diag.ClassServerBusy, true, "this server is busy; the default advance flag says move on"},
		{diag.ClassPeerClosed, false, "a session that was already up ended; there was no dial to fail over"},
	} {
		t.Run(tc.class.String(), func(t *testing.T) {
			if got := failoverContinues(tc.class); got != tc.want {
				t.Errorf("failoverContinues(%s) = %v, want %v: %s", tc.class, got, tc.want, tc.why)
			}
		})
	}
}

// ---- How many dials actually happen --------------------------------------

// deadListener accepts TCP connections, counts them, and closes each one
// immediately. Closing rather than hanging is what makes this cheap: the
// HARD_RESET retransmit loop gives up on a read error at once and only backs
// off on a timeout, so each remote costs a connect and an EOF. The count is the
// assertion — "it failed the same way" would be satisfied by five dials.
type deadListener struct {
	ln net.Listener

	mu       sync.Mutex
	accepted int
}

func newDeadListener(t *testing.T) *deadListener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	d := &deadListener{ln: ln}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			d.mu.Lock()
			d.accepted++
			d.mu.Unlock()
			conn.Close() //nolint:errcheck
		}
	}()
	t.Cleanup(func() { ln.Close() }) //nolint:errcheck
	return d
}

func (d *deadListener) count() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.accepted
}

func (d *deadListener) port() int { return d.ln.Addr().(*net.TCPAddr).Port }

// TestDialCountFollowsTheRemoteCount asserts, rather than inspects, that a
// single-remote profile makes exactly one connection at the listener. The
// second row is the control: two remotes pointing at the same listener must
// produce exactly two, which is what proves the first row is a property of the
// profile and not of a loop that never runs.
func TestDialCountFollowsTheRemoteCount(t *testing.T) {
	for _, tc := range []struct {
		name    string
		remotes int
	}{
		{"one remote dials once", 1},
		{"two remotes dial twice", 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ln := newDeadListener(t)
			var b strings.Builder
			b.WriteString("client\nproto tcp-client\n")
			for range tc.remotes {
				fmt.Fprintf(&b, "remote 127.0.0.1 %d\n", ln.port())
			}
			p, err := profile.ParseString(b.String())
			if err != nil {
				t.Fatalf("ParseString: %v", err)
			}
			p.CA = testCAPEM(t)

			c := New(p)
			// A profile with neither a certificate nor a directive is
			// FlowUserPass, which beginAttempt refuses before any socket
			// exists unless the credentials are available.
			c.CredentialsFn = func(context.Context) (Credentials, error) {
				return Credentials{Username: "u", Password: "p"}, nil
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			connErr := c.Connect(ctx)
			if connErr == nil {
				t.Fatal("Connect succeeded against a listener that closes every connection")
			}
			var derr *diag.Error
			if !errors.As(connErr, &derr) {
				t.Fatalf("Connect returned %T (%v), want *diag.Error", connErr, connErr)
			}
			if derr.Stage == diag.StageParse {
				t.Fatalf("the attempt never left StageParse (%v); no dial was ever made", derr)
			}

			if got := ln.count(); got != tc.remotes {
				t.Errorf("the listener accepted %d connections, want %d", got, tc.remotes)
			}

			rep := c.Report()
			if len(rep.Endpoint.Attempts) != tc.remotes {
				t.Fatalf("report holds %d endpoint attempts, want %d: %+v",
					len(rep.Endpoint.Attempts), tc.remotes, rep.Endpoint.Attempts)
			}
			for i, a := range rep.Endpoint.Attempts {
				if a.Succeeded {
					t.Errorf("attempt %d claims success against a dead listener", i)
				}
				if a.Class != diag.ClassNetwork {
					t.Errorf("attempt %d class = %s, want %s", i, a.Class, diag.ClassNetwork)
				}
				if a.Index != i {
					t.Errorf("attempt %d has Index %d; unshuffled, the two are the same", i, a.Index)
				}
				if a.Proto != "tcp" {
					t.Errorf("attempt %d proto = %q, want tcp", i, a.Proto)
				}
			}
			if rep.Endpoint.Remotes != tc.remotes {
				t.Errorf("Endpoint.Remotes = %d, want %d — the profile's breadth",
					rep.Endpoint.Remotes, tc.remotes)
			}
		})
	}
}

// TestFailoverStopsOnAProfileWeCannotHonour is the other half of the policy: a
// failure that belongs to the profile rather than to the endpoint must not spend
// a second endpoint proving it again. The vehicle is the CA check, which is
// ClassConfig at StageParse and fires before any socket is opened, so a client
// that dialed anyway shows up as a connection at the listener.
func TestFailoverStopsOnAProfileWeCannotHonour(t *testing.T) {
	ln := newDeadListener(t)
	p, err := profile.ParseString(fmt.Sprintf(
		"client\nproto tcp-client\nremote 127.0.0.1 %d\nremote 127.0.0.1 %d\n", ln.port(), ln.port()))
	if err != nil {
		t.Fatalf("ParseString: %v", err)
	}
	// No CA: refused at StageParse, in every preflight mode.

	c := New(p)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	connErr := c.Connect(ctx)
	if connErr == nil {
		t.Fatal("Connect succeeded on a profile with no CA")
	}
	var derr *diag.Error
	if !errors.As(connErr, &derr) {
		t.Fatalf("Connect returned %T, want *diag.Error", connErr)
	}
	if derr.Class != diag.ClassConfig {
		t.Errorf("class = %s, want %s", derr.Class, diag.ClassConfig)
	}
	if got := ln.count(); got != 0 {
		t.Errorf("the listener accepted %d connections; a profile we cannot honour must not "+
			"spend an endpoint on it", got)
	}
	if n := len(c.Report().Endpoint.Attempts); n != 0 {
		t.Errorf("report holds %d endpoint attempts, want none", n)
	}
}

// TestEveryRemoteIsRetained proves both remotes reach the session report, which
// is where a caller sees what a profile named and what was actually tried. Both
// hosts are .invalid, so both fail to resolve, which is ClassNetwork — the class
// that moves on.
func TestEveryRemoteIsRetained(t *testing.T) {
	p, err := profile.ParseString(
		"client\nremote a.invalid 1194\nremote b.invalid 443 tcp-client\nauth-user-pass\n")
	if err != nil {
		t.Fatalf("ParseString: %v", err)
	}
	// A profile with no CA is refused at StageParse before any socket opens,
	// so the endpoints would never be reached. Any parseable certificate will
	// do: neither remote resolves, so nothing is ever verified against it.
	p.CA = testCAPEM(t)

	c := New(p)
	c.PreflightMode = diag.PreflightAdvisory
	c.CredentialsFn = func(context.Context) (Credentials, error) {
		return Credentials{Username: "u", Password: "p"}, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_ = c.Connect(ctx)
	rep := c.Report()
	if rep.Endpoint.Remotes != 2 {
		t.Errorf("Endpoint.Remotes = %d, want 2", rep.Endpoint.Remotes)
	}

	// One record per endpoint tried, in file order, each with its own port
	// and its own transport — the second remote's third field says tcp where
	// the profile says nothing and therefore means udp.
	if len(rep.Endpoint.Attempts) != 2 {
		t.Fatalf("Endpoint.Attempts = %+v, want one record per remote", rep.Endpoint.Attempts)
	}
	for i, want := range []struct {
		port  int
		proto string
	}{{1194, "udp"}, {443, "tcp"}} {
		got := rep.Endpoint.Attempts[i]
		if got.Index != i || got.Port != want.port || got.Proto != want.proto {
			t.Errorf("attempt %d = index %d, port %d, proto %q; want index %d, port %d, proto %q",
				i, got.Index, got.Port, got.Proto, i, want.port, want.proto)
		}
		if got.Class != diag.ClassNetwork {
			t.Errorf("attempt %d class = %s, want %s — an unresolvable host is a network failure",
				i, got.Class, diag.ClassNetwork)
		}
	}

	// The scalar Endpoint fields follow the endpoint the attempt ended on,
	// which is the last one tried when none of them answered.
	if rep.Endpoint.Port != 443 || rep.Endpoint.Proto != "tcp" {
		t.Errorf("Endpoint = port %d proto %q, want the last remote tried (443/tcp)",
			rep.Endpoint.Port, rep.Endpoint.Proto)
	}
}

// clientWithWrapper builds a Client with an explicit control-channel wrapping,
// which the field's atomic type puts out of reach of a composite literal. A nil
// wrapper leaves the field unset, which is the zero-value Client several of
// these tests are about: controlWrapper answers for it with the identity
// wrapper.
func clientWithWrapper(p *profile.Profile, w wrap.Wrapper) *Client {
	c := &Client{prof: p}
	if w != nil {
		c.setControlWrapper(w)
	}
	return c
}
