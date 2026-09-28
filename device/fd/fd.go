// SPDX-License-Identifier: LGPL-2.1-or-later

// Package fd is the supplied-descriptor tunnel backend.
//
// On Android and iOS an application cannot open a TUN interface. The host
// creates one — VpnService.Builder.establish() on Android,
// NEPacketTunnelProvider.setTunnelNetworkSettings on iOS and macOS — and hands
// this process a descriptor for an interface that is already addressed, already
// routed and already pointed at a resolver.
//
// This backend therefore installs nothing and unwinds nothing: it adopts the
// descriptor, moves raw IP packets across it, and on Close closes it. Every
// piece of host state belongs to the host, which tears it down when the VPN
// service stops.
//
// IfconfigJSON is the one thing the backend produces: the pushed addressing,
// routes and DNS in the shape the Kotlin and Swift layers parse.
package fd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/buengese/go-openvpn/device"
)

// readDeadline bounds a single blocking read so ReadPacket can observe a
// cancelled context on a tunnel with no outbound traffic.
const readDeadline = 500 * time.Millisecond

// tunDevice is the subset of tun.Device this backend uses. Naming it here keeps
// the platform split down to one function: the per-GOOS files supply adopt, and
// everything else compiles everywhere, including on desktop Linux where no host
// supplies a descriptor. Read and Write carry whatever framing the platform
// requires, so Device sees the raw IP the device.Device contract promises.
type tunDevice interface {
	Name() string
	File() *os.File
	Read(p []byte) (int, error)
	Write(p []byte) (int, error)
	Close() error
}

// Backend produces a Device from a descriptor the host supplies. The descriptor
// usually cannot be obtained before the tunnel parameters are known — the host
// needs the pushed addressing to configure the interface it is about to create
// — so Establish is called from Open, with the same Params. A Backend serves
// one tunnel and Open is called at most once.
type Backend struct {
	// Establish obtains the tunnel descriptor from the host, which must
	// already have configured the interface it belongs to. Implementations
	// typically render p with IfconfigJSON, hand that to the host, and return
	// what the host gives back.
	//
	// The descriptor is adopted by the Device and closed by Device.Close; the
	// caller must not close it itself. A negative value is an error.
	Establish func(ctx context.Context, p device.Params) (int, error)
}

// New returns a Backend that adopts a descriptor already in hand. When the
// descriptor can only be obtained after the PUSH_REPLY has been parsed — the
// ordinary mobile case — set Establish instead.
func New(fd int) *Backend {
	return &Backend{
		Establish: func(context.Context, device.Params) (int, error) { return fd, nil },
	}
}

// Open adopts the host's descriptor and returns a Device over it. It installs
// no addresses, no routes and no DNS, so a failure here leaves the host exactly
// as it found it. The context bounds Establish only.
func (b *Backend) Open(ctx context.Context, p device.Params) (device.Device, error) {
	if b == nil || b.Establish == nil {
		return nil, errors.New("device/fd: no Establish func: nothing supplies the descriptor")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	n, err := b.Establish(ctx, p)
	if err != nil {
		return nil, fmt.Errorf("device/fd: establish: %w", err)
	}
	if n < 0 {
		return nil, fmt.Errorf("device/fd: host supplied no descriptor (fd=%d)", n)
	}
	t, err := adopt(n)
	if err != nil {
		return nil, fmt.Errorf("device/fd: adopt fd %d: %w", n, err)
	}
	return &Device{tun: t, mtu: p.MTU}, nil
}

// Device is a tunnel over a descriptor the host owns. Per device.Device,
// ReadPacket and WritePacket run concurrently from one goroutine each, and
// Close may arrive from a third at any time.
type Device struct {
	tun tunDevice
	mtu int

	once     sync.Once
	closeErr error
}

// ReadPacket returns the next outbound packet, or ctx.Err() when ctx ends. The
// read deadline is what makes cancellation observable: without one a quiet
// tunnel would sit in Read until the host happened to send something.
func (d *Device) ReadPacket(ctx context.Context, buf []byte) (int, error) {
	for {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		_ = d.tun.File().SetReadDeadline(time.Now().Add(readDeadline))
		n, err := d.tun.Read(buf)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				continue
			}
			return 0, err
		}
		return n, nil
	}
}

// WritePacket delivers one inbound IP packet to the host's interface. It does
// not retain pkt.
func (d *Device) WritePacket(pkt []byte) error {
	_, err := d.tun.Write(pkt)
	return err
}

// MTU is the negotiated tunnel MTU in bytes, as the client computed it. The
// host applied its own value to the interface before handing the descriptor
// over; this is what the data path frames against.
func (d *Device) MTU() int { return d.mtu }

// Name is the interface name the platform gave the descriptor — "tun0" on
// Android, a utun name on iOS and macOS.
func (d *Device) Name() string { return d.tun.Name() }

// Close closes the descriptor and does nothing else: the host installed the
// addressing, routes and DNS, and the host removes them. It is idempotent, and
// it unblocks a ReadPacket in flight.
func (d *Device) Close() error {
	d.once.Do(func() { d.closeErr = d.tun.Close() })
	return d.closeErr
}

// Compile-time proof that this backend satisfies the seam.
var (
	_ device.Device  = (*Device)(nil)
	_ device.Backend = (*Backend)(nil)
)

// Kind identifies this backend in a session report.
func (b *Backend) Kind() device.Kind { return device.KindFD }
