// SPDX-License-Identifier: LGPL-2.1-or-later

// Bringing a tunnel up: the exchange, the reply it asks for, and what that
// reply settles.
//
// An attempt is one or two exchanges — a federated profile runs a second one
// with its assertion — and what is asserted here is everything either exchange
// decides before a server has to exist.

package vpn

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/openlawsvpn/go-openlawsvpn/diag"
	"github.com/openlawsvpn/go-openlawsvpn/internal/control"
	"github.com/openlawsvpn/go-openlawsvpn/internal/datachannel"
	"github.com/openlawsvpn/go-openlawsvpn/internal/framing"
	"github.com/openlawsvpn/go-openlawsvpn/profile"
	"github.com/openlawsvpn/go-openlawsvpn/routing"
)

// ---- the exchange ---------------------------------------------------------

// hardResetServer builds a P_CONTROL_HARD_RESET_SERVER_V2 carrying the given
// packet id. Only the id is a variable: a real server always sends 0.
func hardResetServer(sid [8]byte, packetID uint32) []byte {
	b := []byte{framing.FirstByte(framing.P_CONTROL_HARD_RESET_SERVER_V2, 0)}
	b = append(b, sid[:]...)
	b = append(b, 0) // ack_array_len = 0
	b = append(b, byte(packetID>>24), byte(packetID>>16), byte(packetID>>8), byte(packetID))
	return b
}

// resetOnlyServer answers one HARD_RESET_CLIENT with a HARD_RESET_SERVER
// carrying packetID, then goes quiet. It never reaches TLS, which is all this
// test needs: the packet id is judged before the handshake starts.
func resetOnlyServer(t *testing.T, packetID uint32) (host string, port int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close() //nolint:errcheck
				pkt, err := framing.ReadTCP(conn)
				if err != nil || len(pkt) < 9 {
					return
				}
				var clientSID [8]byte
				copy(clientSID[:], pkt[1:9])
				_ = framing.WriteTCP(conn, hardResetServer(clientSID, packetID))
				// Hold the connection open so the client fails on the packet
				// id rather than on an EOF.
				time.Sleep(5 * time.Second)
			}()
		}
	}()

	h, p, _ := net.SplitHostPort(ln.Addr().String())
	n, _ := strconv.Atoi(p)
	return h, n
}

// TestResetPacketIDIsCheckedOnEveryExchange pins the rule that a HARD_RESET
// opening a session carries packet id 0, enforced wherever the handshake runs.
// The reference drops a reset whose id is not 0 rather than adopting the number
// (openvpn-2.6.22 src/openvpn/ssl.c:4022-4029); adopting it lets a peer place
// our receive window wherever it likes. Both exchanges run the one function, so
// the subtests differ only in the exchange's own parameters.
func TestResetPacketIDIsCheckedOnEveryExchange(t *testing.T) {
	for _, tc := range []struct {
		name string
		p    exchangeParams
	}{
		{"first exchange", exchangeParams{creds: authInitial}},
		{"second exchange", exchangeParams{creds: authCRV1Phase2, label: "second exchange: ", endsSession: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			host, port := resetOnlyServer(t, 7) // a real server sends 0
			c := New(credentialTestProfile(t, "", true))
			p := tc.p
			p.addr = net.JoinHostPort(host, strconv.Itoa(port))
			p.proto = profile.ProtoTCP

			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()

			_, _, derr := c.runExchange(ctx, p)
			if derr == nil {
				t.Fatal("a HARD_RESET_SERVER carrying packet id 7 was accepted")
			}
			if derr.Class != diag.ClassProtocol || derr.Stage != diag.StageReset {
				t.Errorf("got %s at %s, want protocol at reset", derr.Class, derr.Stage)
			}
			if !strings.Contains(derr.Detail, "packet id 7") {
				t.Errorf("detail = %q, want it to name the id the peer sent", derr.Detail)
			}
			if tc.p.label != "" && !strings.Contains(derr.Detail, tc.p.label) {
				t.Errorf("detail = %q, want it labelled %q so a report says which exchange stopped",
					derr.Detail, tc.p.label)
			}
		})
	}
}

// TestResetPacketIDZeroIsAccepted is the other half: the check must not refuse
// the id every real server sends.
func TestResetPacketIDZeroIsAccepted(t *testing.T) {
	host, port := resetOnlyServer(t, 0)
	c := New(credentialTestProfile(t, "", true))
	p := exchangeParams{
		addr:  net.JoinHostPort(host, strconv.Itoa(port)),
		proto: profile.ProtoTCP,
		creds: authInitial,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	_, _, derr := c.runExchange(ctx, p)
	if derr == nil {
		t.Fatal("the exchange completed against a server that only sends a reset")
	}
	// It must get past the reset and die at TLS instead, against a peer that
	// says nothing more.
	if derr.Stage == diag.StageReset {
		t.Errorf("packet id 0 was refused at the reset stage: %v", derr)
	}
}

// dialedAddr drives one exchange as far as the dial and returns the
// "host:port" it was about to open. Cancelling the context before the exchange
// starts is the whole trick: the address is assembled above the dial, so the
// failure detail names what would have gone on the wire without a resolver or
// a listener.
func dialedAddr(t *testing.T, p *profile.Profile, dial func(context.Context, *Client) *diag.Error) string {
	t.Helper()
	return dialedAddrFrom(t, New(p), dial)
}

// dialedAddrFrom is dialedAddr for a client the caller has already set up —
// one carrying a relay phase-2 backend, say, which is state no profile can
// express.
func dialedAddrFrom(t *testing.T, c *Client, dial func(context.Context, *Client) *diag.Error) string {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	derr := dial(ctx, c)
	if derr == nil {
		t.Fatal("the exchange did not fail, so it never said what it dialed")
	}
	if derr.Stage != diag.StageDial {
		t.Fatalf("failed at %s (%v); the address is only settled at the dial", derr.Stage, derr)
	}
	// "dial <addr>", prefixed with the exchange's label for the second one.
	_, addr, ok := strings.Cut(derr.Detail, "dial ")
	if !ok {
		t.Fatalf("detail = %q, want it to name the address that was dialed", derr.Detail)
	}
	return addr
}

// TestRandomHostnameIsAppliedToBothExchanges pins what remote-random-hostname
// does, as opposed to the field the parser sets for it: some endpoints publish
// no record for the bare name, so a client that dials the name as written
// reaches nothing. Both exchanges dial and each applies the label itself, so
// each needs its own assertion; the bare half is asserted too, or a client
// that labels every hostname it is given would pass.
func TestRandomHostnameIsAppliedToBothExchanges(t *testing.T) {
	const host = "vpn.example.com"

	for _, ex := range []struct {
		name string
		dial func(context.Context, *Client) *diag.Error
	}{
		{"first exchange", func(ctx context.Context, c *Client) *diag.Error {
			_, derr := c.dialRemote(ctx, c.activeRemote())
			return derr
		}},
		{"second exchange", func(ctx context.Context, c *Client) *diag.Error {
			_, err := c.readPushSecondExchange(ctx)
			// It hands back the plain error interface; the class, the stage
			// and the detail are all on the typed one underneath.
			var derr *diag.Error
			errors.As(err, &derr)
			return derr
		}},
	} {
		t.Run(ex.name, func(t *testing.T) {
			if got := dialedAddr(t, credentialTestProfile(t, "", true), ex.dial); got != host+":443" {
				t.Errorf("without the directive the client dialed %q, want the profile's own name %q",
					got, host+":443")
			}

			// Twice, because a label that never changed would satisfy every
			// assertion below on its own — and a constant label defeats the
			// reason the directive exists, which is a fresh name per attempt.
			seen := map[string]bool{}
			for range 2 {
				addr := dialedAddr(t, credentialTestProfile(t, "remote-random-hostname\n", true), ex.dial)
				name, port, err := net.SplitHostPort(addr)
				if err != nil {
					t.Fatalf("dialed %q, which is not a host and a port: %v", addr, err)
				}
				if port != "443" {
					t.Errorf("dialed port %q, want the profile's 443", port)
				}
				label, rest, found := strings.Cut(name, ".")
				if !found || rest != host {
					t.Fatalf("dialed %q, want a label prepended to %q", name, host)
				}
				// Four random bytes, hex-encoded: the shape randomSubdomain
				// builds.
				if raw, err := hex.DecodeString(label); err != nil || len(raw) != 4 {
					t.Errorf("label %q is not four hex-encoded bytes", label)
				}
				seen[label] = true
			}
			if len(seen) != 2 {
				t.Errorf("two dials produced the label %v; the subdomain is not random", seen)
			}
		})
	}
}

// TestIPv6LiteralsAreBracketedInBothExchanges pins the address the client
// assembles for an IPv6 literal: joined to its port with a bare colon it comes
// out as "2001:db8::1:1194", which net.Dial refuses. dialRemote and
// readPushSecondExchange each build their own address, so each is asserted —
// positively, and through a dialedAddr that refuses anything failing before
// StageDial, so an attempt that never assembles an address fails here.
func TestIPv6LiteralsAreBracketedInBothExchanges(t *testing.T) {
	// A documentation-range literal (RFC 3849), written out in full eight
	// groups so that "::" compression is not what is being measured.
	const v6 = "2001:db8:7c3a:91f2:4e6b:2d10:a8c4:5f39"

	t.Run("first exchange", func(t *testing.T) {
		p, err := profile.ParseString("client\nremote " + v6 + " 1194\nproto udp\n")
		if err != nil {
			t.Fatalf("ParseString: %v", err)
		}
		// Without a CA the attempt stops at StageParse and never assembles
		// an address.
		p.CA = testCAPEM(t)

		got := dialedAddr(t, p, func(ctx context.Context, c *Client) *diag.Error {
			_, derr := c.dialRemote(ctx, c.activeRemote())
			return derr
		})
		if want := "[" + v6 + "]:1194"; got != want {
			t.Errorf("dialed %q, want %q", got, want)
		}
	})

	t.Run("second exchange", func(t *testing.T) {
		// The backend the second exchange goes back to is phase-2 state rather
		// than a profile field, so the client is built here. The profile's own
		// remote is a name, deliberately: it would satisfy the assertion below.
		p, err := profile.ParseString("client\nremote vpn.example.com 443\nproto tcp-client\n")
		if err != nil {
			t.Fatalf("ParseString: %v", err)
		}
		p.CA = testCAPEM(t)
		c := New(p)
		c.SetRelayPhase2(v6, "state-xyz")

		got := dialedAddrFrom(t, c, func(ctx context.Context, c *Client) *diag.Error {
			_, err := c.readPushSecondExchange(ctx)
			var derr *diag.Error
			errors.As(err, &derr)
			return derr
		})
		if want := "[" + v6 + "]:443"; got != want {
			t.Errorf("dialed %q, want %q", got, want)
		}
	})
}

// ---- the PUSH_REPLY -------------------------------------------------------

// messageReader is the control channel as a server writes it: every message
// followed by its NUL terminator, in one flat stream, with no promise that a
// read stops on a message boundary.
type messageReader struct {
	msgs []string
	buf  []byte
	pos  int
	// reads counts the messages the client actually took off the stream, by
	// the terminators it consumed, so a test can assert that a complete reply
	// left the connection alone.
	reads int
}

func (r *messageReader) Read(b []byte) (int, error) {
	if r.buf == nil {
		for _, m := range r.msgs {
			r.buf = append(r.buf, m...)
			r.buf = append(r.buf, 0)
		}
	}
	if r.pos >= len(r.buf) {
		return 0, io.EOF
	}
	n := copy(b, r.buf[r.pos:])
	for _, c := range r.buf[r.pos : r.pos+n] {
		if c == 0 {
			r.reads++
		}
	}
	r.pos += n
	return n, nil
}

// TestJoinPushContinuation_WholeReply pins that a reply the server did not
// split costs no extra read. The buffered push path replays one message and
// then reports EOF, so a spurious read there would fail every ordinary session.
func TestJoinPushContinuation_WholeReply(t *testing.T) {
	const first = "PUSH_REPLY,ifconfig 10.8.0.6 10.8.0.5,route 10.8.0.0 255.255.0.0"
	r := &messageReader{}

	got, err := quietClient().joinPushContinuation(r, first)
	if err != nil {
		t.Fatalf("joinPushContinuation: %v", err)
	}
	if r.reads != 0 {
		t.Errorf("a complete reply took %d further reads, want 0", r.reads)
	}
	if got != first {
		t.Errorf("reply = %q, want it unchanged: %q", got, first)
	}
}

// TestJoinPushContinuation_Truncated pins that a server which promises a
// continuation and then hangs up fails the push stage instead of bringing the
// tunnel up on a partial route table.
func TestJoinPushContinuation_Truncated(t *testing.T) {
	r := &messageReader{}
	const first = "PUSH_REPLY,route 10.10.0.0 255.255.0.0,push-continuation 2"

	if _, err := quietClient().joinPushContinuation(r, first); err == nil {
		t.Fatal("a reply cut short after push-continuation 2 must fail, not be applied")
	}
}

// TestJoinPushContinuation_SplitReply pins that a reply split across control
// messages is reassembled before it is applied. Taking only the first fragment
// configures the tunnel from a third of its routes, and the rest arrive as
// unexpected control traffic during the data stage.
//
// Reference: openvpn-2.6.22 src/openvpn/push.c:1041-1066
// (process_incoming_push_reply keeps reading while push_continuation is 2),
// push.c:718-735 and push.c:795-806 for the server side.
func TestJoinPushContinuation_SplitReply(t *testing.T) {
	r := &messageReader{msgs: []string{
		"PUSH_REPLY,route 10.20.0.0 255.255.0.0,push-continuation 2",
		"PUSH_REPLY,route 10.30.0.0 255.255.0.0,cipher AES-256-GCM,push-continuation 1",
	}}
	first := "PUSH_REPLY,topology subnet,ifconfig 10.8.0.6 255.255.255.0," +
		"route-gateway 10.8.0.1,route 10.10.0.0 255.255.0.0,push-continuation 2"

	got, err := quietClient().joinPushContinuation(r, first)
	if err != nil {
		t.Fatalf("joinPushContinuation: %v", err)
	}
	if r.reads != 2 {
		t.Errorf("read %d continuation messages, want 2", r.reads)
	}

	opts, err := routing.ParsePushReply(got)
	if err != nil {
		t.Fatalf("ParsePushReply(%q): %v", got, err)
	}
	if len(opts.Routes) != 3 {
		t.Errorf("routes: got %d, want 3 — the reply was %q", len(opts.Routes), got)
	}
	if opts.Cipher != "AES-256-GCM" {
		t.Errorf("cipher: got %q, want AES-256-GCM — it is only in the last fragment", opts.Cipher)
	}
	if strings.Contains(got, "push-continuation") {
		t.Errorf("the reassembled reply still carries a continuation marker: %q", got)
	}
}

// TestPushFailureClassSeparatesBusyFromBroken pins the three-way split of a
// server's refusal of PUSH_REQUEST. AUTH_FAILED,TEMP under ClassProtocol gets
// both downstream decisions wrong at once: retryClass says a protocol fault
// will not go differently, so the client gives up against a server that asked
// it back, while failoverContinues says it might, so a multi-remote profile
// burns every remaining endpoint on it.
func TestPushFailureClassSeparatesBusyFromBroken(t *testing.T) {
	cause := errors.New("read server reply")
	for _, tc := range []struct {
		name       string
		cm         *control.Message
		wantClass  diag.Class
		wantBackof time.Duration
	}{
		{"plain AUTH_FAILED", &control.Message{Kind: control.MsgKindAuthFailed}, diag.ClassAuth, 0},
		{"CRV1 challenge answering cached credentials",
			&control.Message{Kind: control.MsgKindAuthFailedCRV1}, diag.ClassAuth, 0},
		{"TEMP with a backoff", &control.Message{
			Kind: control.MsgKindAuthFailedTemp,
			Raw:  "AUTH_FAILED,TEMP[backoff 5,advance no]:server busy",
		}, diag.ClassServerBusy, 5 * time.Second},
		{"TEMP with no flags at all", &control.Message{
			Kind: control.MsgKindAuthFailedTemp, Raw: "AUTH_FAILED,TEMP",
		}, diag.ClassServerBusy, 0},
		{"something we could not follow",
			&control.Message{Kind: control.MsgKindUnknown, Raw: "WAT"}, diag.ClassProtocol, 0},
		{"no message at all", nil, diag.ClassProtocol, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := New(credentialTestProfile(t, "", true))
			derr := c.failPushReply(exchangeParams{}, tc.cm, cause)
			if derr.Class != tc.wantClass {
				t.Errorf("class = %s, want %s", derr.Class, tc.wantClass)
			}
			if derr.Stage != diag.StagePush {
				t.Errorf("stage = %s, want push", derr.Stage)
			}
			if derr.RetryAfter != tc.wantBackof {
				t.Errorf("RetryAfter = %s, want %s", derr.RetryAfter, tc.wantBackof)
			}
			if !errors.Is(derr, cause) {
				t.Error("the cause did not survive into the typed error")
			}
			// Whatever it was, the recorder has it: a refusal that is not in
			// the report is a refusal the sweep cannot bucket.
			if got := c.Report().Outcome.Class; got != tc.wantClass {
				t.Errorf("report outcome class = %s, want %s", got, tc.wantClass)
			}
		})
	}
}

// ---- the wire format the push settles -------------------------------------

// The data-channel wire format is the peer's choice, taken from whether a
// peer-id directive is present, not from what it says: some servers push
// "peer-id 0" explicitly and some push no directive, and both leave the
// numeric value 0 while speaking different formats.

// pushWithPeerIDZero is a PUSH_REPLY naming peer-id 0 explicitly.
const pushWithPeerIDZero = "PUSH_REPLY,route-gateway 10.8.0.1,topology subnet,ping 10," +
	"ping-restart 60,ifconfig 10.8.0.2 255.255.255.0,peer-id 0,cipher AES-256-GCM"

// pushWithoutPeerID is the same reply with the peer-id directive absent, which
// is also the shape a server sends when the client withholds its IV_PROTO
// advertisement.
const pushWithoutPeerID = "PUSH_REPLY,route-gateway 10.8.0.1,topology subnet,ping 10," +
	"ping-restart 60,ifconfig 10.8.0.2 255.255.255.0,cipher AES-256-CBC"

// TestParsePeerIDDistinguishesZeroFromAbsent is the distinction the format
// selection rests on, as an assertion. A single uint32 return cannot make it.
func TestParsePeerIDDistinguishesZeroFromAbsent(t *testing.T) {
	for _, tc := range []struct {
		name       string
		push       string
		wantID     uint32
		wantPushed bool
	}{
		{"explicit zero", pushWithPeerIDZero, 0, true},
		{"absent", pushWithoutPeerID, 0, false},
		{"a real value", "PUSH_REPLY,peer-id 7,ifconfig 10.8.0.2 255.255.255.0", 7, true},
		{"out of range", "PUSH_REPLY,peer-id 16777215,ifconfig 10.8.0.2 255.255.255.0", 0, false},
		{"unparseable", "PUSH_REPLY,peer-id banana,ifconfig 10.8.0.2 255.255.255.0", 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			id, pushed := parsePeerID(tc.push)
			if id != tc.wantID || pushed != tc.wantPushed {
				t.Errorf("parsePeerID = (%d, %t), want (%d, %t)", id, pushed, tc.wantID, tc.wantPushed)
			}
			want := datachannel.WireDataV2
			if !tc.wantPushed {
				want = datachannel.WireDataV1
			}
			if got := pushedWireFormat(pushed); got != want {
				t.Errorf("pushedWireFormat(%t) = %v, want %v", pushed, got, want)
			}
		})
	}
}

// TestPushedPeerIDDecidesTheWireFormat drives the whole client-side selection
// without a socket: the push settles the format, the data channel is built
// with it, and the packets the manager produces carry a peer-id or do not. It
// asserts on the encrypted bytes because that is the only place the difference
// exists — a client with the format backwards produces well-formed packets,
// reports every stage green, and moves nothing.
func TestPushedPeerIDDecidesTheWireFormat(t *testing.T) {
	for _, tc := range []struct {
		name       string
		push       string
		wantWire   datachannel.WireFormat
		wantOpcode uint8
		wantName   string
	}{
		{
			name: "no peer-id pushed selects P_DATA_V1", push: pushWithoutPeerID,
			wantWire: datachannel.WireDataV1, wantOpcode: framing.P_DATA_V1, wantName: "P_DATA_V1",
		},
		{
			name: "an explicit peer-id 0 still selects P_DATA_V2", push: pushWithPeerIDZero,
			wantWire: datachannel.WireDataV2, wantOpcode: framing.P_DATA_V2, wantName: "P_DATA_V2",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newPushTestClient(t)
			pushOpts, _, err := c.applyPushReply(tc.push)
			if err != nil {
				t.Fatalf("applyPushReply: %v", err)
			}
			if c.wire != tc.wantWire {
				t.Fatalf("wire format = %v, want %v", c.wire, tc.wantWire)
			}
			if err := c.startDataChannel(pushOpts, make([]byte, 256)); err != nil {
				t.Fatalf("startDataChannel: %v", err)
			}

			pkt, err := c.manager.Encrypt([]byte{0x45, 0x00, 0x00, 0x1c})
			if err != nil {
				t.Fatalf("Encrypt: %v", err)
			}
			if got := framing.OpcodeFromByte(pkt[0]); got != tc.wantOpcode {
				t.Errorf("opcode = %d, want %d", got, tc.wantOpcode)
			}
			if tc.wantWire == datachannel.WireDataV2 && (pkt[1] != 0 || pkt[2] != 0 || pkt[3] != 0) {
				t.Errorf("peer-id bytes = % x, want 00 00 00", pkt[1:4])
			}
			if got := c.Report().Negotiated.WireFormat; got != tc.wantName {
				t.Errorf("Negotiated.WireFormat = %q, want %q — a format nobody can see "+
					"in a report is how this went unnoticed for so long", got, tc.wantName)
			}
		})
	}
}

// TestRekeyParametersKeepTheWireFormat pins the property doRekey depends on: a
// rekey renegotiates keys, not the format, and it builds its channel from the
// parameters settled at the first push.
func TestRekeyParametersKeepTheWireFormat(t *testing.T) {
	c := newPushTestClient(t)
	pushOpts, _, err := c.applyPushReply(pushWithoutPeerID)
	if err != nil {
		t.Fatalf("applyPushReply: %v", err)
	}
	if err := c.startDataChannel(pushOpts, make([]byte, 256)); err != nil {
		t.Fatalf("startDataChannel: %v", err)
	}

	// This is what doRekey does with c.dataParams for the next key epoch.
	rekeyParams := c.dataParams
	if rekeyParams.Wire != datachannel.WireDataV1 {
		t.Fatalf("rekey parameters carry %v, want %v", rekeyParams.Wire, datachannel.WireDataV1)
	}
	ch, err := rekeyParams.NewChannel(c.peerID, 1, make([]byte, 256))
	if err != nil {
		t.Fatalf("NewChannel for key epoch 1: %v", err)
	}
	pkt, err := ch.Encrypt([]byte{0x45, 0x00, 0x00, 0x1c})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if got := framing.OpcodeFromByte(pkt[0]); got != framing.P_DATA_V1 {
		t.Errorf("the second key epoch sends opcode %d, want P_DATA_V1 (%d)", got, framing.P_DATA_V1)
	}
	if got := framing.KeyIDFromByte(pkt[0]); got != 1 {
		t.Errorf("key_id = %d, want 1", got)
	}
}

// newPushTestClient is a client with enough profile to resolve a data channel
// and no socket at all: the push parse, the format selection, the channel
// build and the report all run before a byte would be written.
func newPushTestClient(t *testing.T) *Client {
	t.Helper()
	return New(&profile.Profile{
		Remote: "vpn.example.com", Port: 1194, Proto: profile.ProtoUDP,
		Cipher: "AES-256-CBC", Auth: "SHA256", AuthSet: true, CA: testCAPEM(t),
	})
}
