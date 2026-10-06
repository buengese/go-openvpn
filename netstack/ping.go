// SPDX-License-Identifier: LGPL-2.1-or-later

package netstack

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// ErrNoGateway reports that the server pushed no next-hop address, so there is
// nothing on the far end of the tunnel to address directly.
var ErrNoGateway = errors.New("netstack: the server pushed no gateway address")

// Gateway returns the peer's own tunnel-side address — "route-gateway" under
// subnet topology, the peer address under net30.
//
// It is the one host reachable through the tunnel that belongs to the operator
// of the tunnel, which makes it the right target for a probe that should not
// send traffic to anybody else. It is a pushed internal address, so treat it as
// identifying.
func (n *Net) Gateway() (netip.Addr, error) {
	if n.ts == nil || n.ts.gw4 == (netip.Addr{}) {
		return netip.Addr{}, ErrNoGateway
	}
	return n.ts.gw4, nil
}

// pingIdent is the ICMP identifier written into every echo request. The stack
// rewrites it to the endpoint's own bound port, so its value is never observed
// on the wire and only the sequence number distinguishes replies.
const pingIdent = 0

// Ping sends one ICMP echo request through the tunnel and waits for its reply,
// returning the round-trip time.
//
// It exists as a measurement rather than as a reachability check, and the
// payload is the reason: compression is applied to whole data-channel packets,
// so an echo request whose payload the peer will compress comes back compressed
// if the peer compresses at all, which the session report's Decompressed
// counter then shows. A tunnel carrying incompressible traffic cannot tell
// those peers apart. Sending it to the gateway keeps the probe inside the
// operator's own network.
//
// The payload is echoed back verbatim by any conforming peer, so the caller
// chooses how compressible the reply is by choosing what to send.
//
// IPv4 only. ICMPv6 checksums cover a pseudo-header that this endpoint does not
// fill in, so a v6 echo would need its own construction, and a wrong checksum
// would look like packet loss rather than an unimplemented path.
func (n *Net) Ping(ctx context.Context, dst netip.Addr, payload []byte, seq uint16) (time.Duration, error) {
	if n.ts == nil || n.ts.stack == nil {
		return 0, errors.New("netstack: tunnel is closed")
	}
	if !dst.Is4() {
		return 0, fmt.Errorf("netstack: ping %s: only IPv4 echo is implemented", dst)
	}

	var wq waiter.Queue
	ep, terr := n.ts.stack.NewEndpoint(icmp.ProtocolNumber4, ipv4.ProtocolNumber, &wq)
	if terr != nil {
		return 0, fmt.Errorf("netstack: icmp endpoint: %s", terr)
	}
	defer ep.Close()

	// Register before writing. A reply to a short round trip can arrive
	// before a registration made afterwards would have seen it.
	we, notifyCh := waiter.NewChannelEntry(waiter.ReadableEvents)
	wq.EventRegister(&we)
	defer wq.EventUnregister(&we)

	req := make([]byte, header.ICMPv4MinimumSize+len(payload))
	h := header.ICMPv4(req)
	h.SetType(header.ICMPv4Echo)
	h.SetCode(header.ICMPv4UnusedCode)
	h.SetIdent(pingIdent)
	h.SetSequence(seq)
	copy(req[header.ICMPv4MinimumSize:], payload)
	h.SetChecksum(0)
	h.SetChecksum(^checksum.Checksum(req, 0))

	to := tcpip.FullAddress{NIC: nicID, Addr: tcpip.AddrFrom4Slice(dst.AsSlice())}
	start := time.Now()
	var r bytes.Reader
	r.Reset(req)
	if _, terr := ep.Write(&r, tcpip.WriteOptions{To: &to}); terr != nil {
		return 0, fmt.Errorf("netstack: icmp write: %s", terr)
	}

	for {
		var buf bytes.Buffer
		res, terr := ep.Read(&buf, tcpip.ReadOptions{})
		if terr != nil {
			if _, again := terr.(*tcpip.ErrWouldBlock); !again {
				return 0, fmt.Errorf("netstack: icmp read: %s", terr)
			}
			select {
			case <-notifyCh:
			case <-ctx.Done():
				return 0, ctx.Err()
			}
			continue
		}
		{
			rtt := time.Since(start)
			reply := header.ICMPv4(buf.Bytes())
			if len(reply) < header.ICMPv4MinimumSize {
				continue
			}
			if reply.Type() != header.ICMPv4EchoReply || reply.Sequence() != seq {
				// Somebody else's reply, or an error message. Keep waiting;
				// the caller's context bounds how long.
				continue
			}
			got := buf.Bytes()[header.ICMPv4MinimumSize:res.Count]
			if !bytes.Equal(got, payload) {
				return rtt, fmt.Errorf(
					"netstack: icmp reply echoed %d bytes, sent %d: the payload did not survive the round trip",
					len(got), len(payload))
			}
			return rtt, nil
		}
	}
}
