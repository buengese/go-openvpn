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

	"github.com/openlawsvpn/go-openlawsvpn/diag"
	"github.com/openlawsvpn/go-openlawsvpn/internal/framing"
	"github.com/openlawsvpn/go-openlawsvpn/profile"
)

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

}
