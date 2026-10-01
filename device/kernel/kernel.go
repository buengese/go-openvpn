// SPDX-License-Identifier: LGPL-2.1-or-later

// Package kernel is the privileged tunnel backend.
//
// It opens a real kernel TUN interface, gives it the addressing the server
// pushed, installs the pushed routes into the host route table and points the
// host resolver at the pushed DNS servers. Every privileged operation in this
// project lives here and nowhere else.
//
// It serves Linux and macOS, the two platforms where this process is the one
// holding CAP_NET_ADMIN (or root); on Android and iOS the host owns the
// interface and its addressing, routes and DNS, so Open reports that there and
// device/fd serves those platforms instead. Open is all-or-nothing: it either
// returns a usable Device or returns an error having unwound everything it had
// installed, leaving the host exactly as it found it.
package kernel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/buengese/go-openvpn/device"
	"github.com/buengese/go-openvpn/dns"
	"github.com/buengese/go-openvpn/routing"
	"github.com/buengese/go-openvpn/tun"
)

// Backend opens a kernel TUN interface and installs the host state that goes
// with it. The zero value is usable. One Backend serves one tunnel; Open is
// called at most once.
type Backend struct {
	// Logf, when non-nil, receives the backend's progress and warning
	// messages; they are discarded when it is nil. Each call carries one
	// complete message and no trailing newline, so a sink writing to a stream
	// supplies its own line ending. Logf is called from Open only, and never
	// with credential material.
	Logf func(format string, args ...any)
}

// Backend must satisfy the seam it implements on every platform, including the
// ones where Open only reports that it is unavailable.
var _ device.Backend = (*Backend)(nil)

// logf routes one message to b.Logf, discarding it when no sink is set.
func (b *Backend) logf(format string, args ...any) {
	if b == nil || b.Logf == nil {
		return
	}
	b.Logf(format, args...)
}

// finishOpen installs everything that follows opening and configuring the
// interface: the IPv6 address, the redirect-gateway bypass, the pushed routes
// and the resolver. Only opening the device differs between the platforms this
// backend serves, so everything after that is shared rather than written once
// per platform. It is all-or-nothing: a route that fails unwinds what went in
// before it.
func (b *Backend) finishOpen(dev *tun.Device, p device.Params) (*kernelDevice, error) {
	d := &kernelDevice{
		dev:     dev,
		name:    dev.Name(),
		mtu:     effectiveMTU(p.MTU),
		push:    p.Push,
		dnsOpts: p.DNS,
	}

	iface, ifErr := net.InterfaceByName(dev.Name())
	if ifErr != nil {
		// Without an interface index there are no routes to install. The
		// device still works; it just carries nothing but its own subnet.
		b.logf("vpn: interface lookup failed: %v", ifErr)
	} else {
		if p.Push.Ifconfig6 != nil {
			if v6Err := routing.AddIPv6Addr(iface.Index, p.Push.Ifconfig6.Local, p.Push.Ifconfig6.Prefix); v6Err != nil {
				b.logf("vpn: configure IPv6 address: %v", v6Err)
			}
		}
		b.reportRedirectFlags(p.Push)

		// The bypass route goes in before the tunnel's own cover. Without it the
		// cover routes outrank the physical-interface route to the server, and
		// the VPN's own connection loops through the tunnel and dies. Either
		// family's redirect can capture the server's address: the IPv6 cover is
		// installed under "redirect-gateway ipv6" whether or not IPv4 is
		// redirected, and the transport may well have dialed an AAAA.
		if p.Push.RedirectGateway || p.Push.RedirectsIPv6() {
			b.installBypassRoute(p, d)
		}

		b.logf("vpn: applying %d routes via %s", len(p.Push.Routes), dev.Name())
		if routeErr := routing.ApplyRoutes(p.Push, iface.Index); routeErr != nil {
			// The bypass route is already in and some pushed routes may be
			// too. Take them all back out before reporting the failure.
			d.unwind()
			return nil, fmt.Errorf("vpn: apply routes: %w", routeErr)
		}
		b.logf("vpn: routes applied via %s", dev.Name())
	}

	dnsBackend, dnsBackup, dnsErr := dns.Apply(p.DNS, dev.Name(), b.logf)
	d.dnsBackend = dnsBackend
	d.dnsBackup = dnsBackup
	if dnsErr != nil {
		b.logf("vpn: apply DNS: %v", dnsErr)
	} else {
		b.logf("vpn: DNS applied (backend=%d)", dnsBackend)
	}
	return d, nil
}

// reportRedirectFlags says out loud what the pushed redirect-gateway carried and
// which of its flag words this backend does not act on: a flag dropped in
// silence is indistinguishable, from outside, from one that was honoured.
func (b *Backend) reportRedirectFlags(push *routing.PushOptions) {
	if push == nil || (!push.RedirectGateway && !push.RedirectsIPv6()) {
		return
	}
	if words := push.RedirectFlags.String(); words != "" {
		b.logf("vpn: redirect-gateway flags: %s", words)
	}
	if ignored := push.RedirectFlags.ParsedAndIgnored(); len(ignored) > 0 {
		b.logf("vpn: redirect-gateway: parsed and not acted on here: %s",
			strings.Join(ignored, ", "))
	}
	if len(push.RedirectUnknownFlags) > 0 {
		b.logf("vpn: redirect-gateway: unrecognised flag word(s): %s",
			strings.Join(push.RedirectUnknownFlags, ", "))
	}
}

// installBypassRoute adds the /32 host route that keeps the VPN server
// reachable outside the tunnel once redirect-gateway has covered the default.
// It records what it installed on d so Close can take it back out.
//
// Reference: openvpn-2.6.22 src/openvpn/route.c:1029-1055. The reference skips
// this route when the server is on the client's own LAN: unconditionally under
// the "local" flag (RG_LOCAL, route.c:1010), and under "autolocal"
// (RG_AUTO_LOCAL, route.c:1031-1044) when its own on-link test says so. This
// client always applies that test — a server whose route resolves to a direct
// link needs no bypass route — so "autolocal" is the behaviour here whether or
// not the server pushed it, and "local" additionally suppresses the lookup.
func (b *Backend) installBypassRoute(p device.Params, d *kernelDevice) {
	sip := p.ServerIP
	if sip == nil {
		return
	}
	if p.Push.RedirectFlags.Has(routing.RedirectLocal) {
		b.logf("vpn: redirect-gateway local: server %s is on this LAN, no bypass route", sip)
		return
	}
	gw, err := routing.LookupGateway(sip)
	if err != nil {
		b.logf("vpn: lookup gateway for bypass: %v", err)
		return
	}
	if gw == nil {
		b.logf("vpn: redirect-gateway: server %s is direct-link, no bypass needed", sip)
		return
	}
	if addErr := routing.AddBypassRoute(sip, gw); addErr != nil {
		b.logf("vpn: add bypass route: %v", addErr)
		return
	}
	b.logf("vpn: redirect-gateway bypass route: %s via %s", sip, gw)
	d.bypassIP = sip
	d.bypassGW = gw
}

// defaultMTU is the MTU a TUN interface gets when none was negotiated. It
// mirrors tun.Config, where an MTU of zero means 1500, so that MTU() reports
// what the interface actually carries rather than the unset value.
const defaultMTU = 1500

// effectiveMTU reports the MTU the interface actually carries: tun.Config
// treats zero as 1500, so MTU() should say 1500 rather than zero.
func effectiveMTU(mtu int) int {
	if mtu <= 0 {
		return defaultMTU
	}
	return mtu
}

// readTimeout bounds a single blocking read of the TUN file descriptor. The fd
// has no cancellation of its own, so ReadPacket arms this deadline, lets the read
// expire and rechecks ctx, which is what makes ReadPacket answer a cancellation.
const readTimeout = 500 * time.Millisecond

// kernelDevice is a kernel TUN interface plus the host state installed
// alongside it. Everything it records is something Close has to unwind.
type kernelDevice struct {
	dev  *tun.Device
	name string
	mtu  int

	// push is the pushed routing set, kept so Close can delete what
	// ApplyRoutes added.
	push *routing.PushOptions

	// dnsOpts is non-nil when DNS was applied and therefore has to be
	// reverted; dnsBackend and dnsBackup say how.
	dnsOpts    *dns.Config
	dnsBackend dns.Backend
	dnsBackup  string

	// bypassIP and bypassGW record the /32 host route to the VPN server
	// installed under redirect-gateway, when one was installed.
	bypassIP net.IP
	bypassGW net.IP

	closeOnce sync.Once
	closeErr  error
}

// kernelDevice must satisfy the seam.
var _ device.Device = (*kernelDevice)(nil)

// ReadPacket blocks until an outbound packet is available, fills buf and returns
// its length, or returns ctx.Err() when ctx ends. The read is bounded by
// readTimeout and retried; a closed device surfaces as an error from that loop.
func (d *kernelDevice) ReadPacket(ctx context.Context, buf []byte) (int, error) {
	for {
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		default:
		}
		if err := d.dev.File().SetReadDeadline(time.Now().Add(readTimeout)); err != nil {
			// The fd is gone — Close ran underneath us. Surfacing this
			// is what unblocks a ReadPacket in flight.
			return 0, err
		}
		n, err := d.dev.Read(buf)
		if err != nil {
			if isTimeout(err) {
				continue
			}
			return 0, err
		}
		return n, nil
	}
}

// WritePacket delivers one inbound IP packet to the interface. It does not
// retain pkt: any framing the platform needs is applied to a copy inside the
// tun package before the write.
func (d *kernelDevice) WritePacket(pkt []byte) error {
	_, err := d.dev.Write(pkt)
	return err
}

// MTU is the tunnel MTU the interface was configured with.
func (d *kernelDevice) MTU() int { return d.mtu }

// Name is the kernel interface name, e.g. "tun0" or "utun3".
func (d *kernelDevice) Name() string { return d.name }

// Close reverts DNS, tears the interface down and removes the routes that went
// with it. It is idempotent, and it unblocks any ReadPacket in flight.
func (d *kernelDevice) Close() error {
	d.closeOnce.Do(func() {
		// Capture names/indices before closing the device.
		var ifIndex int
		if iface, err := net.InterfaceByName(d.name); err == nil {
			ifIndex = iface.Index
		}

		// Revert DNS while the TUN interface still exists. This explicitly removes
		// its systemd-resolved state rather than relying on link deletion.
		if d.dnsOpts != nil {
			dns.Revert(d.dnsBackend, d.name, d.dnsBackup) //nolint:errcheck
		}

		// Close the TUN device so the kernel removes the interface and all
		// routes associated with it (including redirect-gateway 0.0.0.0/0). On
		// macOS, deleting routes via /sbin/route once the TUN gateway host route
		// is gone blocks indefinitely resolving an unreachable gateway.
		if d.dev != nil {
			d.closeErr = d.dev.Close()
		}

		// Belt-and-suspenders route cleanup after the interface is gone.
		if d.push != nil && ifIndex != 0 {
			routing.DeleteRoutes(d.push, ifIndex) //nolint:errcheck
		}
		if d.bypassIP != nil {
			routing.DeleteBypassRoute(d.bypassIP, d.bypassGW) //nolint:errcheck
			d.bypassIP = nil
			d.bypassGW = nil
		}
	})
	return d.closeErr
}

// unwind undoes a partially built device after a step of Open failed, so Open
// can return an error having left the host as it found it. It is deliberately
// not Close: nothing has been applied that Close's DNS revert or DeleteRoutes
// would have to undo, and on macOS a route deletion against a half-installed
// table is exactly the case that blocks. Destroying the interface removes any
// route the kernel attached to it; only the bypass route lives elsewhere.
func (d *kernelDevice) unwind() {
	if d.dev != nil {
		d.dev.Close() //nolint:errcheck
	}
	if d.bypassIP != nil {
		routing.DeleteBypassRoute(d.bypassIP, d.bypassGW) //nolint:errcheck
		d.bypassIP = nil
		d.bypassGW = nil
	}
}

// isTimeout reports whether err is a read deadline expiring rather than a real
// failure.
func isTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

// Kind identifies this backend in a session report.
func (b *Backend) Kind() device.Kind { return device.KindKernel }
