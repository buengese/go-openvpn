// SPDX-License-Identifier: LGPL-2.1-or-later

// The tunnel once it is up: the loops that keep it there, the sizes packets
// are cut to, and the notification that ends it politely.
//
// None of this needs a server: every value is resolved from the profile and the
// PUSH_REPLY before a packet moves, and the loops run against counters.

package vpn

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/buengese/go-openvpn/diag"
	"github.com/buengese/go-openvpn/internal/compress"
	"github.com/buengese/go-openvpn/internal/control"
	"github.com/buengese/go-openvpn/internal/datachannel"
	"github.com/buengese/go-openvpn/profile"
	"github.com/buengese/go-openvpn/routing"
)

// ---- the exit notification ------------------------------------------------

// TestExitNotifyCopies covers the whole of the decision, because every arm is a
// required behaviour rather than a defensive guard: send on a deliberate UDP
// disconnect that asked for it, and nowhere else. Disconnect passes
// deliberate=true; disconnect hard-codes false for every internal failure path.
func TestExitNotifyCopies(t *testing.T) {
	for _, tc := range []struct {
		name string
		// config is the profile text, which supplies both the transport and
		// the directive.
		config string
		// deliberate is what teardown was called with: true only from
		// Disconnect, false from every internal failure path.
		deliberate bool
		want       int
	}{
		{
			name:       "udp bare directive sends one",
			config:     "remote vpn.example.com 1194\nproto udp\nexplicit-exit-notify\n",
			deliberate: true,
			want:       1,
		},
		{
			name:       "udp explicit count sends that many",
			config:     "remote vpn.example.com 1194\nproto udp\nexplicit-exit-notify 5\n",
			deliberate: true,
			want:       5,
		},
		{
			name:       "no directive sends none",
			config:     "remote vpn.example.com 1194\nproto udp\n",
			deliberate: true,
			want:       0,
		},
		{
			name:       "explicit zero sends none",
			config:     "remote vpn.example.com 1194\nproto udp\nexplicit-exit-notify 0\n",
			deliberate: true,
			want:       0,
		},
		{
			name:       "tcp sends none however the profile asks",
			config:     "remote vpn.example.com 443\nproto tcp-client\nexplicit-exit-notify 5\n",
			deliberate: true,
			want:       0,
		},
		{
			name:       "a transport failure sends none",
			config:     "remote vpn.example.com 1194\nproto udp\nexplicit-exit-notify 5\n",
			deliberate: false,
			want:       0,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := profile.ParseString(tc.config)
			if err != nil {
				t.Fatalf("ParseString: %v", err)
			}
			c := New(p)
			if got := c.exitNotifyCopies(tc.deliberate); got != tc.want {
				t.Fatalf("exitNotifyCopies(%v) = %d, want %d", tc.deliberate, got, tc.want)
			}
		})
	}
}

// TestExitNotifyCopiesFollowsTheActiveRemote checks that the transport comes
// from the remote being dialed rather than from Profile.Proto: a --remote
// line's third field overrides --proto for that remote alone.
func TestExitNotifyCopiesFollowsTheActiveRemote(t *testing.T) {
	p, err := profile.ParseString(
		"proto udp\nremote a.example.com 1194 udp\nremote b.example.com 443 tcp\n" +
			"explicit-exit-notify 2\n")
	if err != nil {
		t.Fatalf("ParseString: %v", err)
	}
	if len(p.Remotes) != 2 {
		t.Fatalf("profile has %d remotes, want 2", len(p.Remotes))
	}

	c := New(p)
	c.setActiveRemote(p.Remotes[0])
	if got := c.exitNotifyCopies(true); got != 2 {
		t.Fatalf("udp remote: exitNotifyCopies(true) = %d, want 2", got)
	}
	c.setActiveRemote(p.Remotes[1])
	if got := c.exitNotifyCopies(true); got != 0 {
		t.Fatalf("tcp remote: exitNotifyCopies(true) = %d, want 0", got)
	}
}

// TestSendExitNotifyWithoutASessionIsSilent checks that a deliberate Disconnect
// of a client that never connected cannot fail: there is no key and no socket,
// so the send has to notice that rather than dereference either.
func TestSendExitNotifyWithoutASessionIsSilent(t *testing.T) {
	p, err := profile.ParseString(
		"remote vpn.example.com 1194\nproto udp\nexplicit-exit-notify 5\n")
	if err != nil {
		t.Fatalf("ParseString: %v", err)
	}
	c := New(p)
	if got := c.exitNotifyCopies(true); got != 5 {
		t.Fatalf("exitNotifyCopies(true) = %d, want 5; the send below would not be reached", got)
	}
	c.sendExitNotify(5)
	if err := c.Disconnect(); err != nil {
		t.Fatalf("Disconnect() = %v, want nil", err)
	}
}

// ---- keepalive ------------------------------------------------------------

// TestKeepaliveDefaultsFollowOpenVPN3 pins the numbers a session falls back to
// when neither the server nor the profile names one. keepaliveLoop always sends
// probes as openvpn3 does, so openvpn3's pair belongs here (openvpn3
// ssl/proto.hpp lines 508-509); 2.4/2.6 send no probe unless one is configured
// or pushed (openvpn-2.6.22 src/openvpn/ping.h line 33 and
// src/openvpn/init.c lines 200-205).
func TestKeepaliveDefaultsFollowOpenVPN3(t *testing.T) {
	c := &Client{prof: &profile.Profile{}}
	interval, restart := c.keepaliveFor(0, 0)
	if interval != 8 || restart != 40 {
		t.Errorf("keepaliveFor(0, 0) = %d/%d, want 8/40 (openvpn3 ssl/proto.hpp:508-509)", interval, restart)
	}
}

// TestKeepaliveResolutionPrecedence covers the whole order: a pushed value
// beats the profile's, the profile's beats the default, and the two are
// resolved independently — openvpn3 ssl/proto.hpp line 752 runs load_common
// over the pushed options after the config file's, and load_duration_parm
// writes only when the option it names is present.
func TestKeepaliveResolutionPrecedence(t *testing.T) {
	for _, tc := range []struct {
		name                          string
		prof                          *profile.Profile
		pushedInterval, pushedRestart int
		wantInterval, wantRestart     int
	}{
		{
			name:         "nothing anywhere takes the defaults",
			prof:         &profile.Profile{},
			wantInterval: 8, wantRestart: 40,
		},
		{
			// "ping 5" and nothing else: the interval is the profile's and
			// the restart falls back.
			name:         "profile ping alone, no push",
			prof:         &profile.Profile{PingInterval: 5},
			wantInterval: 5, wantRestart: 40,
		},
		{
			// "keepalive 10 120" against a silent server.
			name:         "profile keepalive, no push",
			prof:         &profile.Profile{PingInterval: 10, PingTimeout: 120},
			wantInterval: 10, wantRestart: 120,
		},
		{
			name:           "push beats the profile",
			prof:           &profile.Profile{PingInterval: 10, PingTimeout: 120},
			pushedInterval: 3, pushedRestart: 15,
			wantInterval: 3, wantRestart: 15,
		},
		{
			name:           "a half push leaves the profile's other half standing",
			prof:           &profile.Profile{PingInterval: 10, PingTimeout: 120},
			pushedInterval: 3,
			wantInterval:   3, wantRestart: 120,
		},
		{
			name:          "a pushed restart alone still defaults the interval",
			prof:          &profile.Profile{},
			pushedRestart: 15,
			wantInterval:  8, wantRestart: 15,
		},
		{
			name:         "a nil profile is not a crash",
			prof:         nil,
			wantInterval: 8, wantRestart: 40,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &Client{prof: tc.prof}
			interval, restart := c.keepaliveFor(tc.pushedInterval, tc.pushedRestart)
			if interval != tc.wantInterval || restart != tc.wantRestart {
				t.Errorf("keepaliveFor(%d, %d) = %d/%d, want %d/%d",
					tc.pushedInterval, tc.pushedRestart, interval, restart, tc.wantInterval, tc.wantRestart)
			}
		})
	}
}

// TestKeepaliveReadsTheProfileEndToEnd goes through the parser rather than a
// hand-built Profile, so that a directive the parse switch stops reading fails
// here and not only in profile's own tests.
func TestKeepaliveReadsTheProfileEndToEnd(t *testing.T) {
	p, err := profile.ParseString("remote vpn.example.test 1194\nkeepalive 10 120\n")
	if err != nil {
		t.Fatalf("ParseString: %v", err)
	}
	interval, restart := (&Client{prof: p}).keepaliveFor(0, 0)
	if interval != 10 || restart != 120 {
		t.Errorf("keepalive 10 120 against a silent server = %d/%d, want 10/120", interval, restart)
	}
}

// ---- the inactivity timer -------------------------------------------------

// newInactiveTestClient is the least Client inactiveLoop can run against: the
// two traffic counters it reads, the done channel its teardown closes, and an
// event sink that keeps the log off stderr.
func newInactiveTestClient() *Client {
	return &Client{
		doneCh:  make(chan struct{}),
		EventFn: func(Event) {},
	}
}

// TestInactiveCountsBothDirections is the send-only tunnel: bytes leave, none
// come back, and the session must stay up. Both references count both
// directions — openvpn3 client/cliproto.hpp lines 1484-1493 arms
// reset_inactive_timer on TUN_BYTES_OUT as well as TUN_BYTES_IN, and
// openvpn-2.6.22 src/openvpn/forward.c:487-490 sums tun_read and tun_write.
func TestInactiveCountsBothDirections(t *testing.T) {
	c := newInactiveTestClient()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Outbound traffic only, often enough that every one-second window sees
	// some. bytesRecv is never touched.
	sending := make(chan struct{})
	defer close(sending)
	go func() {
		tick := time.NewTicker(100 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-sending:
				return
			case <-tick.C:
				c.bytesSent.Add(1024)
			}
		}
	}()

	c.wg.Add(1)
	go c.inactiveLoop(ctx, 1, 0)

	// Long enough for at least two window evaluations at a one-second timeout.
	select {
	case <-c.Done():
		t.Fatal("inactiveLoop tore down a tunnel that was sending 10 KiB/s; only received bytes were being counted")
	case <-time.After(2500 * time.Millisecond):
	}
}

// TestInactiveStillExpiresOnSilence is the other half: counting both
// directions must not turn the timeout off. A tunnel carrying nothing at all
// is still idle, and both references end it.
func TestInactiveStillExpiresOnSilence(t *testing.T) {
	c := newInactiveTestClient()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c.wg.Add(1)
	go c.inactiveLoop(ctx, 1, 0)

	select {
	case <-c.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("inactiveLoop left a silent tunnel up past its inactive timeout")
	}
	if err := c.WaitForDisconnect(); err == nil {
		t.Error("an inactivity teardown recorded no reason")
	}
}

// TestInactivityTeardownReachesTheSessionReport pins the half of the teardown
// that is not the disconnect: a session that ended on its inactivity timer has
// to say so in its own report, or it keeps the Succeeded outcome startDataPath
// wrote when the tunnel came up.
//
// The succeed() below is what startDataPath does when a live session comes up.
func TestInactivityTeardownReachesTheSessionReport(t *testing.T) {
	c := newInactiveTestClient()
	c.recorder().enter(diag.StageData)
	c.recorder().succeed()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c.wg.Add(1)
	go c.inactiveLoop(ctx, 1, 0)

	select {
	case <-c.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("inactiveLoop left a silent tunnel up past its inactive timeout")
	}

	rep := c.Report()
	if rep.Outcome.Succeeded {
		t.Error("the report of a session torn down as idle still says it succeeded")
	}
	if rep.Outcome.Stage != diag.StageData {
		t.Errorf("outcome stage = %v, want %v: the session ended in the data stage",
			rep.Outcome.Stage, diag.StageData)
	}
	chain := strings.Join(rep.Outcome.ErrorChain, " | ")
	if !strings.Contains(chain, "inactive timeout") {
		t.Errorf("outcome error chain = %q, want the inactivity timeout named in it", chain)
	}
}

// TestInactiveByteThresholdCountsBothDirections covers the "inactive N bytes"
// form, which shares the counter the no-argument form reads: a window carrying
// fewer than the threshold expires whichever direction the bytes went, and one
// carrying more survives on outbound alone.
func TestInactiveByteThresholdCountsBothDirections(t *testing.T) {
	c := newInactiveTestClient()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sending := make(chan struct{})
	defer close(sending)
	go func() {
		tick := time.NewTicker(100 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-sending:
				return
			case <-tick.C:
				c.bytesSent.Add(4096)
			}
		}
	}()

	c.wg.Add(1)
	go c.inactiveLoop(ctx, 1, 8192)

	select {
	case <-c.Done():
		t.Fatal("inactiveLoop tore down a tunnel sending 40 KiB/s against an 8 KiB threshold")
	case <-time.After(2500 * time.Millisecond):
	}
}

// ---- the session monitor --------------------------------------------------

// monitorTestConn is the live control channel a one-exchange connection hands
// on to the session monitor, and the peer end a test writes to. net.Pipe is
// synchronous and carries deadlines, which is what *tls.Conn gives the real
// monitor: a read nobody answers blocks, and SetReadDeadline unblocks it.
func monitorTestConn(t *testing.T) (peer, conn net.Conn) {
	t.Helper()
	peer, conn = net.Pipe()
	t.Cleanup(func() {
		peer.Close()
		conn.Close()
	})
	return peer, conn
}

// monitorTestClient is a Client parked where startDataPath leaves one: the
// tunnel is up and c.tlsRW is whatever the exchange that authenticated it
// installed. Nothing here dials.
func monitorTestClient(t *testing.T, rw *prereadRW) *Client {
	t.Helper()
	c := New(credentialTestProfile(t, "", true))
	c.EventFn = func(Event) {}
	c.mu.Lock()
	c.state = stateTunnelUp
	c.tlsRW = rw
	c.mu.Unlock()
	return c
}

// TestSessionMonitorWatchesOneExchangeConnection pins that the monitor watches
// the live connection after a one-exchange authentication, where c.tlsRW holds
// a replay of the PUSH_REPLY the exchange already took off the wire. The replay
// is drained by the time the data channel starts, so a monitor reading only
// that sees io.EOF and returns before the tunnel has passed a packet
// (openvpn-2.6.22 src/openvpn/push.c:72-76 and :91-109).
func TestSessionMonitorWatchesOneExchangeConnection(t *testing.T) {
	const pushRaw = "PUSH_REPLY,topology subnet,ifconfig 10.8.0.2 255.255.255.0,route-gateway 10.8.0.1"

	peer, conn := monitorTestConn(t)
	c := monitorTestClient(t, newPrereadRW([]byte(pushRaw+"\x00"), conn))

	// What readPushBuffered does: take the reply the first exchange already
	// read back out of the preread, and not one byte more.
	cm, err := control.ReadServerReply(c.tlsRW)
	if err != nil {
		t.Fatalf("read buffered PUSH_REPLY: %v", err)
	}
	if cm.Raw != pushRaw {
		t.Fatalf("buffered PUSH_REPLY = %q, want %q", cm.Raw, pushRaw)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c.wg.Add(1)
	go c.sessionMonitor(ctx)

	// The server revokes the session well after the tunnel came up. Written
	// from a goroutine because net.Pipe only completes a write once the other
	// end reads it — which is the assertion.
	go func() {
		peer.SetWriteDeadline(time.Now().Add(10 * time.Second)) //nolint:errcheck
		peer.Write([]byte("AUTH_FAILED\x00"))                   //nolint:errcheck
	}()

	select {
	case <-c.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("the server sent AUTH_FAILED mid-session and the client never noticed: " +
			"the monitor was not watching the live connection")
	}

	var expired *control.SessionExpiredError
	if err := c.WaitForDisconnect(); !errors.As(err, &expired) {
		t.Fatalf("disconnect reason = %v, want a *control.SessionExpiredError", err)
	}
	if out := c.Report().Outcome; out.Class != diag.ClassAuth {
		t.Errorf("outcome class = %v, want %v", out.Class, diag.ClassAuth)
	}
}

// TestSessionMonitorSeesPushedHalt pins the other half: a server that ends a
// working session with a RESTART or HALT push says so on the same control
// channel, and only the monitor turns that into diag.ClassPeerClosed.
//
// Reference: openvpn-2.6.22 src/openvpn/push.c:91-109 (server_pushed_signal).
func TestSessionMonitorSeesPushedHalt(t *testing.T) {
	const pushRaw = "PUSH_REPLY,ifconfig 10.8.0.2 255.255.255.0"

	peer, conn := monitorTestConn(t)
	c := monitorTestClient(t, newPrereadRW([]byte(pushRaw+"\x00"), conn))
	if _, err := control.ReadServerReply(c.tlsRW); err != nil {
		t.Fatalf("read buffered PUSH_REPLY: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c.wg.Add(1)
	go c.sessionMonitor(ctx)

	go func() {
		peer.SetWriteDeadline(time.Now().Add(10 * time.Second)) //nolint:errcheck
		peer.Write([]byte("HALT,maintenance\x00"))              //nolint:errcheck
	}()

	select {
	case <-c.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("the server pushed HALT and the client never noticed")
	}

	var pushed *control.ServerPushedSignal
	if err := c.WaitForDisconnect(); !errors.As(err, &pushed) {
		t.Fatalf("disconnect reason = %v, want a *control.ServerPushedSignal", err)
	}
	if out := c.Report().Outcome; out.Class != diag.ClassPeerClosed {
		t.Errorf("outcome class = %v, want %v", out.Class, diag.ClassPeerClosed)
	}
}

// TestPrereadReplayLeavesTheSplitReplyAlone is the reason the preread exists:
// a PUSH_REPLY too large for PUSH_BUNDLE_SIZE arrives in fragments only the
// first exchange can collect, and handing the live connection to the replay
// must not make the buffered read reach past the reply's terminator and block
// on a fragment consumed one stage earlier.
//
// Reference: openvpn-2.6.22 src/openvpn/push.c:718-735, :795-806, :1041-1066.
func TestPrereadReplayLeavesTheSplitReplyAlone(t *testing.T) {
	const first = "PUSH_REPLY,topology subnet,ifconfig 10.8.0.6 255.255.255.0," +
		"route-gateway 10.8.0.1,route 10.10.0.0 255.255.0.0,push-continuation 2"
	rest := []string{
		"PUSH_REPLY,route 10.20.0.0 255.255.0.0,push-continuation 2",
		"PUSH_REPLY,route 10.30.0.0 255.255.0.0,cipher AES-256-GCM,push-continuation 1",
	}

	peer, conn := monitorTestConn(t)
	go func() {
		peer.SetWriteDeadline(time.Now().Add(10 * time.Second)) //nolint:errcheck
		for _, m := range rest {
			if _, err := peer.Write([]byte(m + "\x00")); err != nil {
				return
			}
		}
	}()

	// The first exchange's read, on the live connection.
	joined, err := quietClient().joinPushContinuation(conn, first)
	if err != nil {
		t.Fatalf("joinPushContinuation: %v", err)
	}

	c := monitorTestClient(t, newPrereadRW([]byte(joined+"\x00"), conn))

	// The second read, from the preread, is what bringUpTunnel does. It must
	// return the whole reply without touching the connection: nothing is
	// writing to the peer end now, so a read that fell through would park.
	done := make(chan *control.Message, 1)
	go func() {
		cm, err := control.ReadServerReply(c.tlsRW)
		if err != nil {
			done <- nil
			return
		}
		done <- cm
	}()
	var cm *control.Message
	select {
	case cm = <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the buffered PUSH_REPLY read blocked: the replay read past its own terminator")
	}
	if cm == nil {
		t.Fatal("read buffered PUSH_REPLY failed")
	}

	opts, err := routing.ParsePushReply(cm.Raw)
	if err != nil {
		t.Fatalf("ParsePushReply(%q): %v", cm.Raw, err)
	}
	if len(opts.Routes) != 3 {
		t.Errorf("routes: got %d, want 3 — the reply was %q", len(opts.Routes), cm.Raw)
	}
	if opts.Cipher != "AES-256-GCM" {
		t.Errorf("cipher: got %q, want AES-256-GCM — it is only in the last fragment", opts.Cipher)
	}

	// And the monitor that starts after it still watches the live connection.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c.wg.Add(1)
	go c.sessionMonitor(ctx)

	go func() {
		peer.SetWriteDeadline(time.Now().Add(10 * time.Second)) //nolint:errcheck
		peer.Write([]byte("AUTH_FAILED\x00"))                   //nolint:errcheck
	}()

	select {
	case <-c.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("a split reply left the monitor watching nothing")
	}
}

// ---- the sizes packets are cut to -----------------------------------------

// TestEffectiveMSSFixFollowsTheReference works the reference's own sum for a
// handful of negotiated shapes. mssfix is a link budget — the size of the whole
// encapsulated packet — not an MSS: `mssfix 1300` gives 1208 for AES-GCM over
// UDP with a peer-id once the encapsulation is subtracted.
//
// Reference: openvpn-2.6.22 src/openvpn/mss.c:286-332.
func TestEffectiveMSSFixFollowsTheReference(t *testing.T) {
	gcm, _, err := datachannel.ResolveParams("AES-256-GCM", "SHA256")
	if err != nil {
		t.Fatalf("ResolveParams: %v", err)
	}
	v4 := &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 443}

	// GCM over UDP with a peer-id costs 4+4+16 of tunnel header, then 40 of
	// inner IPv4 and TCP: budget - 64. The outer 20+8 of IP and UDP is counted
	// only when the budget measures the whole datagram, which an explicit
	// "mssfix N" does not. The profiles below name their transport, because
	// profile.ProtoTCP is the zero value and a TCP link costs 14 bytes more.
	const (
		gcmTunnelOverhead = 64
		gcmUDPv4Overhead  = gcmTunnelOverhead + 28
	)

	for _, tc := range []struct {
		name      string
		prof      *profile.Profile
		pushedMSS int
		tunMTU    int
		wantMSS   int
	}{
		// The derived default is the one budget that does measure the whole
		// datagram: options.c:3227-3229 sets mssfix_encap alongside it.
		{"no mssfix anywhere: OpenVPN 2's 1492 budget", &profile.Profile{Proto: profile.ProtoUDP}, 0, 1500, 1492 - gcmUDPv4Overhead},
		{"a pushed mssfix is a budget, not an MSS", &profile.Profile{Proto: profile.ProtoUDP}, 1350, 1500, 1350 - gcmTunnelOverhead},
		{"a profile mssfix is a budget too", &profile.Profile{Proto: profile.ProtoUDP, MSSFix: 1300, MSSFixSet: true}, 0, 1500, 1300 - gcmTunnelOverhead},
		{"mssfix 0 disables clamping", &profile.Profile{Proto: profile.ProtoUDP, MSSFixSet: true}, 0, 1500, 0},
		// "mtu" asks for the outer IP and UDP headers to be counted too.
		{"mssfix N mtu measures the datagram", &profile.Profile{Proto: profile.ProtoUDP, MSSFix: 1300, MSSFixSet: true, MSSFixMode: profile.MSSFixEncap}, 0, 1500, 1300 - gcmUDPv4Overhead},
		// "fixed" asks for no encapsulation to be counted at all.
		{"mssfix N fixed counts no encapsulation", &profile.Profile{Proto: profile.ProtoUDP, MSSFix: 1300, MSSFixSet: true, MSSFixMode: profile.MSSFixFixed}, 0, 1500, 1300 - 40},
		// A non-default tunnel MTU is the budget itself: mssfix := tun_mtu,
		// marked fixed, which gives up only the inner IPv4 and TCP headers.
		// Clamp takes the further 20 off for an IPv6 payload.
		{"a reduced tunnel MTU is a fixed budget", &profile.Profile{Proto: profile.ProtoUDP}, 0, 1400, 1400 - 40},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &Client{prof: tc.prof, dataParams: gcm}
			if got := c.effectiveMSSFix(tc.pushedMSS, tc.tunMTU, gcm, compress.ModeNone, v4); got != tc.wantMSS {
				t.Fatalf("effectiveMSSFix() = %d, want %d", got, tc.wantMSS)
			}
		})
	}
}

// TestTunMTURespectsProfileMaximum drives the whole chain: the PUSH_REPLY is
// tokenised and validated where every other pushed directive is, and the
// choice between the two numbers is made separately.
func TestTunMTURespectsProfileMaximum(t *testing.T) {
	tests := []struct {
		name       string
		push       string
		profileMTU int
		want       int
	}{
		{name: "profile without push", profileMTU: 1400, want: 1400},
		{name: "profile caps larger push", push: "PUSH_REPLY,tun-mtu 1500", profileMTU: 1400, want: 1400},
		{name: "server reduces profile", push: "PUSH_REPLY,tun-mtu 1300", profileMTU: 1400, want: 1300},
		{name: "push without profile", push: "PUSH_REPLY,tun-mtu 1400", want: 1400},
		{name: "default", want: 1500},
		// Out of range is not a value, and the parser is where that is decided.
		{name: "push below the floor", push: "PUSH_REPLY,tun-mtu 12", want: 1500},
		{name: "push above the ceiling", push: "PUSH_REPLY,tun-mtu 99999", want: 1500},
		{name: "push not a number", push: "PUSH_REPLY,tun-mtu wide", want: 1500},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pushed := 0
			if tt.push != "" {
				opts, err := routing.ParsePushReply(tt.push)
				if err != nil {
					t.Fatalf("ParsePushReply(%q): %v", tt.push, err)
				}
				pushed = opts.TunMTU
			}
			if got := effectiveTunMTU(pushed, tt.profileMTU); got != tt.want {
				t.Errorf("effectiveTunMTU(%d, %d) = %d, want %d", pushed, tt.profileMTU, got, tt.want)
			}
		})
	}
}
