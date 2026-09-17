// SPDX-License-Identifier: LGPL-2.1-or-later

// Package netstack is the userspace tunnel backend: one gVisor network stack
// per tunnel, inside this process, needing no privilege and touching no host
// state.
//
// It implements the device.Backend and device.Device contracts over a gVisor
// channel endpoint. Packets the client decrypts off the wire are injected into
// the stack; packets the stack emits are handed back to the client to encrypt.
// No interface is created, no route is installed, no resolver is rewritten, so
// twenty tunnels in one unprivileged process cannot collide over an interface
// name, a route table or /etc/resolv.conf.
//
// # Nothing privileged, ever
//
// The package imports routing and dns solely for the types in device.Params —
// the parsed PUSH_REPLY and the merged DNS configuration. It must never call
// anything in either package that mutates host state: routing.ApplyRoutes,
// routing.DeleteRoutes, routing.AddBypassRoute, dns.Apply, dns.Revert. It must
// never import tun. TestHostStateUnchanged is the behavioural half of that
// promise: it diffs `ip link` and `ip route` across a full tunnel lifecycle and
// requires both to be byte-identical.
//
// gvisor.dev/gvisor is pinned in go.mod; the header of stack.go says why.
package netstack

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"

	"github.com/openlawsvpn/go-openlawsvpn/device"
	"github.com/openlawsvpn/go-openlawsvpn/dns"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// ErrDeviceClosed is returned by ReadPacket and WritePacket after Close. It
// wraps net.ErrClosed so callers can treat it like any other closed-endpoint
// error.
var ErrDeviceClosed = fmt.Errorf("netstack: device is closed: %w", net.ErrClosed)

// deviceSeq names successive devices in a process. A netstack device has no
// kernel interface to take a name from, and Device.Name has to be unique
// enough that a hundred concurrent tunnels are distinguishable in a log.
var deviceSeq atomic.Uint64

// Backend is the userspace device.Backend. It installs no host state, so it
// needs no privilege and has nothing to unwind.
//
// The zero Backend is ready to use. Per the device.Backend contract Open is
// called once per connection attempt that reaches the data stage, so a
// reconnect gets a second stack and Name is all the two have in common.
type Backend struct {
	// Name, when non-empty, is the name Device.Name reports. Left empty,
	// each device is named "netstack" followed by a per-process counter.
	Name string
}

// NewBackend returns a Backend with default settings. It is equivalent to
// &Backend{} and exists so callers need not know that the zero value works.
func NewBackend() *Backend { return &Backend{} }

// Open brings up a gVisor stack from the negotiated tunnel parameters.
//
// Whichever of Push.Ifconfig and Push.Ifconfig6 the server pushed becomes an
// address on the stack's single NIC, and each family that got one gets a
// default route. At least one must be present: a PUSH_REPLY with no addressing
// yields no data path, and this says so rather than returning a device that
// silently drops everything. The context bounds setup only, so that a cancelled
// connect attempt does not produce a live stack.
func (b *Backend) Open(ctx context.Context, p device.Params) (device.Device, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if p.MTU <= 0 || p.MTU > maxMTU {
		return nil, fmt.Errorf("netstack: MTU %d out of range (1..%d)", p.MTU, maxMTU)
	}

	name := b.Name
	if name == "" {
		name = fmt.Sprintf("netstack%d", deviceSeq.Add(1)-1)
	}

	ts, err := newTunnelStack(p, name)
	if err != nil {
		return nil, err
	}
	// A cancellation that raced setup must not leak a stack.
	if err := ctx.Err(); err != nil {
		ts.destroy()
		return nil, err
	}

	return &Device{
		ts:   ts,
		name: name,
		mtu:  p.MTU,
		dns:  p.DNS,
		done: make(chan struct{}),
	}, nil
}

// Device is one userspace tunnel end: a gVisor stack reachable only through
// ReadPacket and WritePacket. Per the device.Device contract ReadPacket runs on
// one goroutine and WritePacket on another, concurrently, and Close may arrive
// on a third at any time — including while a ReadPacket is blocked.
type Device struct {
	ts   *tunnelStack
	name string
	mtu  int

	// dns is the merged DNS configuration the server pushed. The host
	// resolver is not ours to rewrite, so this is recorded and not acted on;
	// Net.Resolver is what queries it.
	dns *dns.Config

	// done is closed by Close, so a ReadPacket that finds the channel
	// endpoint drained can tell "closed" from "context ended".
	done chan struct{}

	// mu guards closed against WritePacket. ReadPacket needs no lock: Close
	// shuts the channel endpoint, which unblocks it.
	mu     sync.RWMutex
	closed bool
}

// ReadPacket blocks until the stack emits an outbound packet, copies it into
// buf and returns its length, or returns an error when ctx ends or the device
// is closed. A packet longer than buf is truncated rather than split, per the
// device contract; buf should be at least MTU bytes.
func (d *Device) ReadPacket(ctx context.Context, buf []byte) (int, error) {
	pkt := d.ts.ep.ReadContext(ctx)
	if pkt == nil {
		// ReadContext returns nil for two reasons: ctx ended, or Close
		// shut the outbound queue. Report whichever happened.
		select {
		case <-d.done:
			return 0, ErrDeviceClosed
		default:
		}
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		return 0, ErrDeviceClosed
	}
	view := pkt.ToView()
	pkt.DecRef()
	n := copy(buf, view.AsSlice())
	view.Release()
	return n, nil
}

// WritePacket injects one inbound IP packet into the stack. It copies pkt and
// does not retain it. A packet that is not IPv4 or IPv6 is an error rather than
// a silent drop: the caller hands this method the plaintext of a decrypted data
// packet, and anything else there means the data channel is producing garbage.
func (d *Device) WritePacket(pkt []byte) error {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.closed {
		return ErrDeviceClosed
	}

	proto, err := ipVersion(pkt)
	if err != nil {
		return err
	}

	// MakeWithData copies pkt into a gVisor view, so the caller is free to
	// reuse its buffer the moment this returns.
	pb := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(pkt),
	})
	d.ts.ep.InjectInbound(proto, pb)
	pb.DecRef()
	return nil
}

// MTU is the negotiated tunnel MTU in bytes. It is constant for the life of the
// device.
func (d *Device) MTU() int { return d.mtu }

// Name is the synthetic device name, for example "netstack0". A netstack device
// has no kernel interface, so the name exists only to identify it in logs and
// session reports.
func (d *Device) Name() string { return d.name }

// Close tears down the stack. It is idempotent, it unblocks any ReadPacket in
// flight, and it waits for gVisor's worker goroutines to stop before returning.
// There is no host state to unwind: the backend installed none.
func (d *Device) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil
	}
	d.closed = true
	close(d.done)
	d.ts.destroy()
	return nil
}

// ipVersion returns the gVisor network-protocol number for a raw IP packet.
func ipVersion(pkt []byte) (tcpip.NetworkProtocolNumber, error) {
	if len(pkt) == 0 {
		return 0, fmt.Errorf("netstack: empty packet")
	}
	switch v := pkt[0] >> 4; v {
	case 4:
		return header.IPv4ProtocolNumber, nil
	case 6:
		return header.IPv6ProtocolNumber, nil
	default:
		return 0, fmt.Errorf("netstack: not an IP packet: version nibble %d", v)
	}
}

// Kind identifies this backend in a session report, so the client core can name
// the backend that served an attempt without importing this package — which it
// must not, since that would put gVisor in every consumer's import graph.
func (b *Backend) Kind() device.Kind { return device.KindNetstack }
