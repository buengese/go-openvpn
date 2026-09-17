// SPDX-License-Identifier: LGPL-2.1-or-later
//
// transport.go: framing seam, wrap seam, dial policy, packet classification.

package vpn

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	mrand "math/rand/v2"
	"net"
	"syscall"
	"time"

	"github.com/openlawsvpn/go-openlawsvpn/diag"
	"github.com/openlawsvpn/go-openlawsvpn/internal/framing"
	"github.com/openlawsvpn/go-openlawsvpn/profile"
)

// sendWithRetry sends pkt and retries until a packet with the expected opcode
// arrives or maxTries is exhausted.
//
// The timeout adapts based on observed RTT:
//   - If any packet arrives before the deadline (even wrong opcode), RTT is
//     recorded and subsequent intervals are set to min(RTT×2, 10 s).
//   - If the deadline fires with no response, the interval doubles
//     (exponential back-off, capped at 10 s).
//
// The adaptive interval is this client's. openvpn3 retransmits on a flat
// tls_timeout, reset on every send (reliable/relsend.hpp:50-53).
func (c *Client) sendWithRetry(conn net.Conn, pkt []byte, wantOpcode uint8, retryInterval time.Duration, maxTries int) ([]byte, error) {
	const maxInterval = 10 * time.Second
	interval := retryInterval
	var measuredRTT time.Duration

	for try := 0; try < maxTries; try++ {
		sentAt := time.Now()
		if err := c.writePacket(conn, pkt); err != nil {
			return nil, fmt.Errorf("write attempt %d: %w", try+1, err)
		}
		conn.SetReadDeadline(time.Now().Add(interval)) //nolint:errcheck
		timedOut := false
		for {
			resp, err := c.readPacket(conn)
			if err != nil {
				if isTimeout(err) {
					timedOut = true
					break
				}
				return nil, err
			}
			// Record RTT from the first received packet (any opcode).
			if measuredRTT == 0 {
				measuredRTT = time.Since(sentAt)
			}
			if len(resp) >= 1 && resp[0]>>3 == wantOpcode {
				conn.SetReadDeadline(time.Time{}) //nolint:errcheck
				return resp, nil
			}
			// Wrong opcode — keep reading until deadline.
		}
		if timedOut {
			if measuredRTT > 0 {
				interval = measuredRTT * 2
			} else {
				interval *= 2
			}
			if interval > maxInterval {
				interval = maxInterval
			}
		}
	}
	return nil, fmt.Errorf("no response after %d attempts", maxTries)
}

// isControlOpcode reports whether an opcode belongs to the control channel.
// Everything that is not one of the two data opcodes is, which is why an
// opcode we have never seen is treated as control rather than waved through.
func isControlOpcode(op uint8) bool {
	switch op {
	case framing.P_DATA_V1, framing.P_DATA_V2:
		return false
	default:
		return true
	}
}

// errForeignSession marks a control packet addressed to a session that is not
// ours. It is a sentinel for the drop counters, never returned to a caller.
var errForeignSession = errors.New("control packet names another session")

// controlPacketIsOurs reports whether a control packet belongs to this
// session, by the two comparisons the reference makes. The source session id
// must be the server's: tls_pre_decrypt drops a packet whose id matches no
// session it knows (openvpn-2.6.22 src/openvpn/ssl.c:3777, :3860-3868), and a
// client keeps one session, so the lookup is an equality. Where the packet
// echoes a session id back — only alongside an ack array, by the wire layout —
// it must be ours (reliable.c:159-168). A HARD_RESET is the exception on both
// counts and does not reach here; connect.go adopts the server's id from it.
//
// The session ids are passed in rather than read off the Client, where reading
// them is a data race: the only caller is the inbound relay, which no
// WaitGroup covers, so it outlives its attempt while a failover and a
// Reconnect zero both fields under the lock.
func controlPacketIsOurs(pkt []byte, clientSID, serverSID [8]byte) bool {
	src, ok := framing.ControlSrcSessionID(pkt)
	if !ok || src != serverSID {
		return false
	}
	if dst, present := framing.ControlDstSessionID(pkt); present && dst != clientSID {
		return false
	}
	return true
}

// readPacket reads one OpenVPN packet from conn using the framing of the
// dialed remote's protocol — 2-byte length prefix for TCP, raw datagram for
// UDP — and not the profile's --proto, which failover can make differ.
//
// A read failure is connection-fatal: a closed socket, a truncated length
// prefix or a deadline have no next packet to go back for.
func (c *Client) readPacket(conn net.Conn) ([]byte, error) {
	if c.activeProto() == profile.ProtoUDP {
		return framing.ReadUDP(conn)
	}
	return framing.ReadTCP(conn)
}

// countControlDrop tallies one control packet the client dropped, by reason.
func (c *Client) countControlDrop(err error) {
	if errors.Is(err, errForeignSession) {
		c.controlForeignSession.Add(1)
	}
}

// writePacket writes one complete OpenVPN packet to conn using the framing of
// the dialed remote, as readPacket does.  A net.Conn permits concurrent calls
// to Write, but it does not keep the two writes that make up a TCP-framed
// OpenVPN packet contiguous; serialize them here for every outbound path.
func (c *Client) writePacket(conn net.Conn, payload []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.activeProto() == profile.ProtoUDP {
		return framing.WriteUDP(conn, payload)
	}
	return framing.WriteTCP(conn, payload)
}

// randomSubdomain prepends a random 8-hex-char label to host.
// AWS Client VPN requires a random subdomain prefix — the bare endpoint DNS
// name does not resolve, but <random>.cvpn-endpoint-... does.
func randomSubdomain(host string) string {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "rand." + host
	}
	return hex.EncodeToString(b[:]) + "." + host
}

// ---- The dialed remote --------------------------------------------------
//
// Downstream of the dial the endpoint is read here, never from the profile.

// activeRemote returns the remote this attempt is dialing. Before failover has
// chosen one — and for a profile assembled in code, which has no Remotes list
// — it answers from Remote, Port and Proto, i.e. Remotes[0] once parsed.
func (c *Client) activeRemote() profile.Remote {
	if r := c.active.Load(); r != nil {
		return *r
	}
	if c.prof == nil {
		return profile.Remote{}
	}
	return profile.Remote{Host: c.prof.Remote, Port: c.prof.Port, Proto: c.prof.Proto}
}

// activeProto returns the transport of the remote this attempt is dialing. It
// decides framing, MSS arithmetic and the advertised link-mtu, and is not
// c.prof.Proto: a --remote line's third field overrides --proto for that line.
func (c *Client) activeProto() profile.Proto {
	return c.activeRemote().Proto
}

// setActiveRemote records the remote the next dial will use. Its value has to
// survive as long as the connection does: a rekey an hour later re-runs the
// key-method-2 exchange and advertises a link-mtu that depends on the transport.
func (c *Client) setActiveRemote(rem profile.Remote) {
	c.active.Store(&rem)
}

// dialTarget is one entry of a dial order: a remote and the line of the
// profile it came from. The index travels with the remote because a shuffled
// order cannot be searched back to file order by value.
type dialTarget struct {
	// Index is the remote's 0-based position in the profile's --remote list.
	Index int
	// Remote is the remote itself, with its port and transport resolved.
	Remote profile.Remote
}

// dialOrder returns the remotes to try, in the order to try them: the
// profile's --remote list in file order, which is the order OpenVPN dials them
// in, unless --remote-random asked for a shuffle. The shuffle is made here,
// per attempt, rather than written back into the profile, which New keeps a
// pointer to and a caller may attempt many times.
//
// A profile with no Remotes — one assembled in code rather than parsed —
// yields the single remote its scalar fields describe, so the list is never
// empty and the loop that consumes it has no no-remote case.
func (c *Client) dialOrder() []dialTarget {
	if c.prof == nil {
		return []dialTarget{{}}
	}
	if len(c.prof.Remotes) == 0 {
		return []dialTarget{{Remote: profile.Remote{
			Host: c.prof.Remote, Port: c.prof.Port, Proto: c.prof.Proto,
		}}}
	}
	order := make([]dialTarget, len(c.prof.Remotes))
	for i, rem := range c.prof.Remotes {
		order[i] = dialTarget{Index: i, Remote: rem}
	}
	// Profile.Remote, Port and Proto are Remotes[0] as the parser leaves them;
	// a caller that has written them since — pinning a resolved address, or
	// pointing a parsed profile at a mock — means them, and the reverse is not.
	if first := &order[0].Remote; first.Host != c.prof.Remote ||
		first.Port != c.prof.Port || first.Proto != c.prof.Proto {
		first.Host, first.Port, first.Proto = c.prof.Remote, c.prof.Port, c.prof.Proto
	}
	if c.prof.RemoteRandom {
		// Not crypto/rand: this spreads a fleet of clients across a
		// provider's endpoints, which is a load question and not a secrecy
		// one. OpenVPN's own --remote-random uses its ordinary PRNG too.
		mrand.Shuffle(len(order), func(i, j int) { order[i], order[j] = order[j], order[i] })
	}
	return order
}

// failoverContinues reports whether a remote that failed with class leaves any
// reason to try the next one: whether the failure was a property of the
// endpoint, or of everything we brought to it and would bring to the next.
//
//	network, tls, protocol, crypto  — the endpoint's, try the next one
//	config, unsupported, auth, local — ours, and the next endpoint would
//	                                   fail identically
//
// ClassServerBusy continues too: an AUTH_FAILED,TEMP carries an "advance" flag
// naming the next address, the next remote, or staying put, and the reference
// assumes "addr" — move on — when it is absent. The flag does not reach here,
// so an explicit "advance no" is not honoured.
func failoverContinues(class diag.Class) bool {
	switch class {
	case diag.ClassNetwork, diag.ClassTLS, diag.ClassProtocol, diag.ClassCrypto, diag.ClassServerBusy:
		return true
	default:
		return false
	}
}

// tcpKeepaliveIdle is the time a TCP connection must be idle before the kernel
// starts sending keepalive probes. Combined with tcpKeepaliveInterval and
// tcpKeepaliveCount this makes the OS declare the link dead in about 15 s,
// well before any application-level timeout fires.
const (
	tcpKeepaliveIdle     = 5 * time.Second
	tcpKeepaliveInterval = 3 * time.Second
	tcpKeepaliveCount    = 3 // 5 + 3*3 = 14 s total
)

// dialWithContext dials addr, enables TCP keepalives on the socket, and — if
// c.ProtectFn is set — calls it with the raw fd so Android can exclude the
// socket from VPN routing.
func (c *Client) dialWithContext(ctx context.Context, proto profile.Proto, addr string) (net.Conn, error) {
	d := &net.Dialer{
		// OS-level TCP keepalive: kernel detects dead links in ~15 s regardless
		// of whether the server pushes ping/ping-restart in PUSH_REPLY.
		KeepAlive: tcpKeepaliveIdle,
		KeepAliveConfig: net.KeepAliveConfig{
			Enable:   true,
			Idle:     tcpKeepaliveIdle,
			Interval: tcpKeepaliveInterval,
			Count:    tcpKeepaliveCount,
		},
	}
	if c.ProtectFn != nil {
		// Control callback fires after socket creation but before connect(2).
		d.Control = func(network, address string, rawConn syscall.RawConn) error {
			return rawConn.Control(func(fd uintptr) {
				_ = c.ProtectFn(int(fd)) //nolint:errcheck
			})
		}
	}
	switch proto {
	case profile.ProtoTCP:
		return d.DialContext(ctx, "tcp", addr)
	case profile.ProtoUDP:
		return d.DialContext(ctx, "udp", addr)
	default:
		return nil, fmt.Errorf("unknown proto %v", proto)
	}
}

// controlSegmentBudget is the most TLS payload this client puts in one
// P_CONTROL_V1 packet. Control-channel fragmentation is a local budget, not a
// negotiated MTU: the peer reassembles whatever it is sent.
const controlSegmentBudget = 1024

// isTimeout reports whether err is a network timeout error.
func isTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}
