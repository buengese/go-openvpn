//go:build darwin && !ios

// SPDX-License-Identifier: LGPL-2.1-or-later

package kernel

import (
	"context"
	"fmt"

	"github.com/openlawsvpn/go-openlawsvpn/device"
	"github.com/openlawsvpn/go-openlawsvpn/tun"
)

// Open allocates a native utun interface via SYSPROTO_CONTROL, configures it,
// applies routes, and sets up DNS.
//
// Moved from (*vpn.Client).openNativeTUN, now Backend.Open here, which ConnectPhase2 called on the
// CLI / Homebrew path when no TUN descriptor was supplied by a host. Requires
// root / sudo.
//
// Open is all-or-nothing: if configuring the interface fails, or if applying
// the pushed routes fails after the redirect-gateway bypass route has gone in,
// it unwinds what it installed and returns an error.
func (b *Backend) Open(ctx context.Context, p device.Params) (device.Device, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if p.Push == nil {
		return nil, fmt.Errorf("vpn: open utun device: no pushed options")
	}

	dev, err := tun.Open()
	if err != nil {
		return nil, fmt.Errorf("vpn: open utun device: %w (run as root or with sudo)", err)
	}

	cfg := tun.Config{MTU: p.MTU}
	if p.Push.Ifconfig != nil {
		cfg.LocalIP = p.Push.Ifconfig.Local
		// macOS utun is always IFF_POINTOPOINT regardless of server topology.
		// SIOCSIFNETMASK does not create a connected subnet route on a P2P
		// interface, so the pushed gateway (e.g. 172.16.76.129) has no route
		// via utun and /sbin/route resolves it via the default (en0). Setting
		// SIOCSIFDSTADDR instead makes the kernel install a /32 host route to
		// the gateway via utun, allowing all subsequent pushed routes to
		// resolve correctly. Same approach used by WireGuard-go on macOS.
		cfg.PeerIP = p.Push.Ifconfig.Gateway
	}
	if cfgErr := dev.Configure(cfg); cfgErr != nil {
		dev.Close()
		return nil, fmt.Errorf("vpn: configure utun device: %w", cfgErr)
	}

	return b.finishOpen(dev, p)
}
