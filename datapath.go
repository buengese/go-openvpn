// SPDX-License-Identifier: LGPL-2.1-or-later
//
// datapath.go: the data path and the monitors that watch it.

package vpn

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/openlawsvpn/go-openlawsvpn/diag"
	"github.com/openlawsvpn/go-openlawsvpn/internal/control"
	"github.com/openlawsvpn/go-openlawsvpn/internal/crypto"
	"github.com/openlawsvpn/go-openlawsvpn/internal/datachannel"
	"github.com/openlawsvpn/go-openlawsvpn/internal/mssfix"
	"github.com/openlawsvpn/go-openlawsvpn/internal/occ"
	"github.com/openlawsvpn/go-openlawsvpn/profile"
)

// endSession records why an established session ended and starts the teardown
// — unless the context says a teardown is already under way, in which case it
// records nothing and does nothing. It is the only way a running session ends.
//
// A goroutine that notices its context is cancelled has observed a deliberate
// teardown, not a failure: Disconnect cancels the context and closes the
// socket underneath every loop that holds it. The rule is keyed on the context
// and never on the error, because the transport sites fail with "use of closed
// network connection" on a clean close and a genuine mid-session transport
// failure produces that same text with the context still alive.
//
// err is what WaitForDisconnect hands back and what the outcome is classified
// from; noteSessionFailure leaves an outcome already recorded standing.
func (c *Client) endSession(ctx context.Context, err error) {
	if ctx.Err() != nil || errors.Is(err, context.Canceled) {
		return
	}
	c.noteSessionFailure(err)
	c.mu.Lock()
	if c.doneErr == nil {
		c.doneErr = err
	}
	c.mu.Unlock()
	c.disconnect(true) //nolint:errcheck
}

// tunToWire reads plaintext IP packets from the TUN device, encrypts them, and
// writes data packets — P_DATA_V2, or P_DATA_V1 against a server that pushed no
// peer-id — to the raw connection.
func (c *Client) tunToWire(ctx context.Context) {
	defer c.wg.Done()
	// Taken once: the device is published before these goroutines start and
	// cleared only after wg.Wait sees them exit, so it cannot change underneath
	// the loop and does not need the lock on every packet.
	dev := c.TunnelDevice()
	if dev == nil {
		return
	}
	buf := make([]byte, 65535)
	for {
		// ReadPacket ends with ctx; a backend that needs a read deadline of its
		// own keeps one.
		n, err := dev.ReadPacket(ctx, buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			c.emit(Event{Type: EventLog, Message: fmt.Sprintf("vpn: tunToWire: TUN read error: %v", err)})
			return
		}
		plain := buf[:n]
		c.clampMSS(plain)
		wire, err := c.manager.Encrypt(plain)
		if err != nil {
			if errors.Is(err, datachannel.ErrPacketIDExhausted) {
				// Every later packet fails the same way, so continuing leaves
				// a tunnel that reports itself up and carries nothing.
				// NeedsRekey asks for a key 16M packets earlier.
				c.endSession(ctx, c.failStage(diag.ClassCrypto, diag.StageData, err,
					"data key ran out of packet ids and was not renegotiated"))
				return
			}
			continue
		}
		if werr := c.writePacket(c.rawConn, wire); werr != nil {
			// The socket is gone: either it died under a live session, or a
			// deliberate Disconnect closed it while this write was in flight.
			// endSession is where those two are told apart.
			c.endSession(ctx, fmt.Errorf("vpn: tunToWire: write error: %w", werr))
			return
		}
		c.bytesSent.Add(uint64(n))
		c.packetsSent.Add(1)
		c.markDataFlow(true)
	}
}

// clampMSS applies the MSS allowance this connection settled on, which is one
// number however it was derived: Clamp takes the IPv6 difference off itself.
func (c *Client) clampMSS(pkt []byte) {
	mssfix.Clamp(pkt, c.mssFix)
}

// wireToTun reads data packets — P_DATA_V2 or P_DATA_V1, whichever the session
// settled on — from dataCh (fed by the relay goroutine inside tlsHandshake,
// which is the sole reader of rawConn), decrypts them, and writes the plaintext
// IP packets to the TUN device.
//
// Keepalive magic packets are recognised and discarded (not forwarded to TUN).
// Each successfully decrypted packet (including keepalives) resets the
// ping-restart dead-link timer via lastRecv.
func (c *Client) wireToTun(ctx context.Context) {
	defer c.wg.Done()
	// See tunToWire: taken once, for the same reason.
	dev := c.TunnelDevice()
	if dev == nil {
		return
	}
	// Captured once: this starts after the connect path installed the channel,
	// and a Reconnect replaces the field while this goroutine is still draining
	// the old attempt. Nothing closes it — ctx is what ends the loop.
	dataCh := c.dataChannel()
	if dataCh == nil {
		return
	}
	for {
		select {
		case <-ctx.Done():
			return
		case pkt := <-dataCh:
			plain, err := c.manager.Decrypt(pkt)
			if err != nil {
				// A replay drop reaches us as an ordinary decrypt error, so
				// diag.Counters.Replays stays zero and this tally covers both.
				c.decryptFailures.Add(1)
				continue
			}
			c.packetsRecv.Add(1)
			// Reset the last-received timestamp for dead-link detection.
			c.lastRecv.Store(time.Now().UnixNano())
			// Drop keepalive magic — it is not a real IP packet.
			if occ.IsKeepalive(plain) {
				continue
			}
			c.clampMSS(plain)
			c.bytesRecv.Add(uint64(len(plain)))
			c.markDataFlow(false)
			dev.WritePacket(plain) //nolint:errcheck
		}
	}
}

// Keepalive defaults, in seconds, for a session where neither the PUSH_REPLY
// nor the profile names a value.
//
// They are openvpn3's: ssl/proto.hpp lines 508-509 initialise keepalive_ping
// to 8 seconds and keepalive_timeout to 40, and nothing writes over them
// unless a config file or a pushed option says so (lines 1278-1294). 2.4 and
// 2.6 are not the model, because they send no probe unless ping or keepalive
// is configured or pushed and set only a pre-pull dead-link timeout of 120
// seconds on a pulling UDP client (src/openvpn/ping.h line 33
// PRE_PULL_INITIAL_PING_RESTART, src/openvpn/init.c lines 200-205).
// keepaliveLoop is unconditional, like openvpn3's.
const (
	defaultPingInterval = 8
	defaultPingRestart  = 40
)

// keepaliveFor resolves the probe interval and dead-link timeout for one
// session, in seconds, from what the server pushed, what the profile asked for
// and the defaults above — in that order of precedence.
//
// The precedence is per value rather than per source, which is openvpn3's:
// ssl/proto.hpp line 752 runs load_common over the pushed option list after
// the config file, and load_duration_parm writes only when the option it names
// is present, so a PUSH_REPLY carrying ping and no ping-restart leaves the
// profile's ping-restart standing. A zero means "said nothing"; keepalive
// cannot be switched off through it, since openvpn3 refuses a ping below 1
// (load_duration_parm's min_value, ssl/proto.hpp lines 1292-1293).
func (c *Client) keepaliveFor(pushedInterval, pushedRestart int) (interval, restart int) {
	interval, restart = defaultPingInterval, defaultPingRestart
	if c.prof != nil {
		if c.prof.PingInterval > 0 {
			interval = c.prof.PingInterval
		}
		if c.prof.PingTimeout > 0 {
			restart = c.prof.PingTimeout
		}
	}
	if pushedInterval > 0 {
		interval = pushedInterval
	}
	if pushedRestart > 0 {
		restart = pushedRestart
	}
	return interval, restart
}

// keepaliveLoop sends a keepalive P_DATA_V2 packet every pingInterval seconds
// and triggers a disconnect if no data arrives within pingRestart seconds. The
// two arguments are what the server pushed; a zero means it pushed nothing,
// and keepaliveFor fills the gap from the profile or the defaults.
//
// The dead-link check uses a 1-second polling ticker rather than a one-shot
// timer so that it can account for packets arriving between ticks via lastRecv.
//
// Reference: openvpn3-core ssl/proto.hpp
//   - ProtoContext::housekeeping() line ~4580: calls primary->send_keepalive()
//     when now >= keepalive_xmit.
//   - keepalive_xmit is rescheduled by send_keepalive() line ~4280.
//   - ProtoContext::housekeeping() line ~4503: keepalive_expire reset on any recv.
//   - is_keepalive_enabled() line ~4345 guards both send and recv paths.
func (c *Client) keepaliveLoop(ctx context.Context, pingInterval, pingRestart int) {
	defer c.wg.Done()

	pingInterval, pingRestart = c.keepaliveFor(pingInterval, pingRestart)

	pollInterval := time.Second
	if pingInterval > 0 && time.Duration(pingInterval)*time.Second < pollInterval {
		pollInterval = time.Duration(pingInterval) * time.Second
	}
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	var nextSend time.Time
	if pingInterval > 0 {
		nextSend = time.Now().Add(time.Duration(pingInterval) * time.Second)
	}

	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			// Send keepalive if interval elapsed.
			// Use a short write deadline so a stalled TCP socket does not block
			// this goroutine — if the write times out the dead-link check below
			// will fire on the next tick anyway.
			if !now.Before(nextSend) {
				wire, err := c.manager.Encrypt(occ.KeepaliveMagic)
				if err == nil {
					c.rawConn.SetWriteDeadline(time.Now().Add(3 * time.Second)) //nolint:errcheck
					c.writePacket(c.rawConn, wire)                              //nolint:errcheck
					c.rawConn.SetWriteDeadline(time.Time{})                     //nolint:errcheck
				}
				nextSend = now.Add(time.Duration(pingInterval) * time.Second)
			}
			// Dead-link detection: disconnect if nothing received for pingRestart seconds.
			if pingRestart > 0 {
				last := time.Unix(0, c.lastRecv.Load())
				if time.Since(last) >= time.Duration(pingRestart)*time.Second {
					c.emit(Event{Type: EventLog, Message: fmt.Sprintf("vpn: keepalive: no data for %d seconds, disconnecting", pingRestart)})
					c.endSession(ctx, fmt.Errorf("vpn: keepalive timeout: no data for %d seconds", pingRestart))
					return
				}
			}
		}
	}
}

// inactiveLoop disconnects the session when traffic falls below the threshold
// pushed by the server via "inactive <timeout> [bytes]".
//
// Traffic is counted in both directions, which is what makes an upload-only
// tunnel survive: openvpn3 client/cliproto.hpp arms reset_inactive_timer()
// (line 1512) on TUN_BYTES_OUT and TUN_BYTES_IN alike from process_inactive()
// (line 1474), and OpenVPN 2.6.22 src/openvpn/forward.c
// check_inactivity_timeout() (line 483) measures tun_read_bytes +
// tun_write_bytes. Only bytes carried by the tunnel count: keepalive probes
// are dropped before wireToTun reaches its counter.
func (c *Client) inactiveLoop(ctx context.Context, timeout, minBytes int) {
	defer c.wg.Done()

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	// Snapshot traffic at start of window.
	windowStart := time.Now()
	startSent := c.bytesSent.Load()
	startRecv := c.bytesRecv.Load()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if time.Since(windowStart) < time.Duration(timeout)*time.Second {
				continue
			}
			sent := c.bytesSent.Load()
			recv := c.bytesRecv.Load()
			totalFlow := (sent - startSent) + (recv - startRecv)

			// With no byte argument, any byte in either direction keeps the
			// session alive. Both references reset on either direction;
			// neither has a receive-only rule.
			expired := totalFlow == 0
			if minBytes > 0 {
				expired = totalFlow < uint64(minBytes)
			}

			if expired {
				c.emit(Event{Type: EventLog, Message: fmt.Sprintf("vpn: inactive: no traffic for %d seconds, disconnecting", timeout)})
				c.endSession(ctx, fmt.Errorf(
					"vpn: inactive timeout: no traffic for %d seconds", timeout))
				return
			}

			// Reset window for next period.
			windowStart = time.Now()
			startSent = sent
			startRecv = recv
		}
	}
}

// sessionMonitor watches for mid-session AUTH_FAILED messages from the server.
func (c *Client) sessionMonitor(ctx context.Context) {
	defer c.wg.Done()
	if c.tlsRW == nil {
		return
	}
	mon := control.NewSessionMonitor(c.tlsRW)
	mon.Start(ctx)
	select {
	case <-ctx.Done():
	case err := <-mon.Done():
		if errors.Is(err, io.EOF) {
			return
		}
		// A deliberate Disconnect tears the control transport down underneath
		// the monitor at the same instant ctx.Done becomes ready, and select
		// picks between two ready cases at random. endSession tells them apart.
		c.endSession(ctx, err)
	}
}

// effectiveTunMTU picks the tunnel MTU from what the profile asked for and
// what the server pushed. An explicit profileMTU is an upper bound: a server
// may only reduce it. Returns profileMTU, or 1500 when neither side said.
func effectiveTunMTU(pushedMTU, profileMTU int) int {
	if profileMTU > 0 {
		if pushedMTU > 0 && pushedMTU < profileMTU {
			return pushedMTU
		}
		return profileMTU
	}
	if pushedMTU > 0 {
		return pushedMTU
	}
	return 1500
}

const (
	openVPN2DefaultTunMTU = 1500
	// OpenVPN 2's default mssfix, applied when the profile uses the default
	// 1500-byte TUN MTU and sets no mssfix of its own. It is a link budget — the
	// whole encapsulated packet — which is what mssfix.MaxMSS takes.
	openVPN2DefaultMSSFixBudget = 1492

	// innerIPv4AndTCP is what a fixed budget gives up to the payload's own
	// headers, the only subtraction the reference makes in that mode.
	innerIPv4AndTCP = 40
)

// effectiveMSSFix returns the maximum MSS an inner IPv4 TCP SYN may advertise.
// Clamp derives the IPv6 figure from it, so one number covers both families —
// the shape the reference keeps (a single frame->mss_fix).
//
// mssfix is a *link budget*, not an MSS: the reference subtracts the whole
// encapsulation — transport, opcode, packet id, crypto and the inner IP and
// TCP headers — before clamping (openvpn-2.6.22 src/openvpn/mss.c:286-332),
// deriving 1336 from `mssfix 1400` rather than 1400. The overhead here is
// computed from the negotiated cipher, digest and wire format.
func (c *Client) effectiveMSSFix(pushedMSS, tunMTU int, dcp datachannel.Params, remoteAddr net.Addr) int {
	o := mssfix.Overhead{
		TCPTransport: c.activeProto() == profile.ProtoTCP,
		PeerID:       dcp.Wire == datachannel.WireDataV2,
		AEAD:         dcp.Spec.Mode == crypto.ModeAEAD,
		// Only the derived defaults below measure the outer headers: an
		// explicit "mssfix N" measures the tunnel packet alone unless it says
		// "mtu" (options.c:7318-7335, openvpn3 ssl/proto.hpp:2713).
		EncapCounted: c.prof.MSSFixMode == profile.MSSFixEncap,
	}
	if o.AEAD {
		o.TagLen = aeadTagLen
	} else {
		o.IVLen = cbcBlockLen
		o.BlockLen = cbcBlockLen
		o.DigestLen = dcp.Digest.Size()
	}
	if ip := addrIP(remoteAddr); ip != nil && ip.To4() == nil {
		o.OuterIPv6 = true
	}

	if pushedMSS > 0 {
		return mssfix.MaxMSS(pushedMSS, o)
	}
	if c.prof.MSSFixSet {
		if c.prof.MSSFixMode == profile.MSSFixFixed {
			// "fixed" says the number is already the payload budget: give up
			// only the inner headers (mss.c:289-294).
			if c.prof.MSSFix <= innerIPv4AndTCP {
				return 0
			}
			return c.prof.MSSFix - innerIPv4AndTCP
		}
		return mssfix.MaxMSS(c.prof.MSSFix, o)
	}
	// A non-default TUN MTU is itself the budget: the reference sets mssfix to
	// the tun MTU and marks it fixed, subtracting only the inner IPv4 and TCP
	// headers (openvpn-2.6.22 src/openvpn/options.c:3234-3239, mss.c:289-294).
	if tunMTU != openVPN2DefaultTunMTU {
		return tunMTU - innerIPv4AndTCP
	}
	o.EncapCounted = true // options.c:3227-3229 sets mssfix_encap with the default budget
	return mssfix.MaxMSS(openVPN2DefaultMSSFixBudget, o)
}

// AES block and GCM tag lengths, named here because the overhead sum reads
// better with them than with bare 16s.
const (
	aeadTagLen  = 16
	cbcBlockLen = 16
)

func addrIP(addr net.Addr) net.IP {
	switch a := addr.(type) {
	case *net.UDPAddr:
		return a.IP
	case *net.TCPAddr:
		return a.IP
	}
	if addr == nil {
		return nil
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return nil
	}
	return net.ParseIP(host)
}

// parsePeerID extracts the numeric peer-id value from a PUSH_REPLY message,
// and reports whether one was pushed at all.
//
// The second return value is not a convenience: "peer-id 0" is a value a
// server really pushes, a server that pushes no peer-id directive at all is a
// different fact, and the two select different wire formats. pushed is false
// too for a directive present but unparseable or out of range, since inventing
// 0 would claim a format the server did not ask for.
//
// openvpn3-core proto.hpp: remote_peer_id is a 24-bit value (0 to 0xFFFFFE).
func parsePeerID(pushRaw string) (id uint32, pushed bool) {
	for _, field := range strings.Split(strings.TrimRight(pushRaw, "\x00"), ",") {
		parts := strings.Fields(strings.TrimSpace(field))
		if len(parts) == 2 && strings.EqualFold(parts[0], "peer-id") {
			var v uint32
			if _, err := fmt.Sscanf(parts[1], "%d", &v); err == nil && v <= 0xFFFFFE {
				return v, true
			}
		}
	}
	return 0, false
}
