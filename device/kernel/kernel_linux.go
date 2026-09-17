//go:build !android && !ios && !darwin

// SPDX-License-Identifier: LGPL-2.1-or-later

package kernel

import (
	"context"
	"fmt"

	"github.com/openlawsvpn/go-openlawsvpn/device"
	"github.com/openlawsvpn/go-openlawsvpn/routing"
	"github.com/openlawsvpn/go-openlawsvpn/tun"
)

// Open opens /dev/net/tun, configures the interface, applies routes and DNS.
//
// Moved from (*vpn.Client).openNativeTUN, now Backend.Open here, which ConnectPhase2 called on Linux
// when no TUN descriptor was supplied by a host. Requires root or
// CAP_NET_ADMIN.
//
// Open is all-or-nothing: if configuring the interface fails, or if applying
// the pushed routes fails after the redirect-gateway bypass route has gone in,
// it unwinds what it installed and returns an error.
func (b *Backend) Open(ctx context.Context, p device.Params) (device.Device, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// Everything below dereferences the pushed interface address. The core
	// rejects a PUSH_REPLY without ifconfig before it reaches a backend; the
	// check is here so a caller that does not cannot turn it into a panic
	// halfway through the privileged sequence.
	if p.Push == nil || p.Push.Ifconfig == nil {
		return nil, fmt.Errorf("vpn: open TUN device: no ifconfig pushed")
	}

	dev, err := tun.Open("")
	if err != nil {
		return nil, fmt.Errorf("vpn: open TUN device: %w (run as root or grant CAP_NET_ADMIN)", err)
	}
	cfg := tun.Config{
		LocalIP: p.Push.Ifconfig.Local,
		MTU:     p.MTU,
	}
	if p.Push.Topology == routing.TopologySubnet {
		cfg.Mask = p.Push.Ifconfig.Mask
	} else {
		cfg.PeerIP = p.Push.Ifconfig.Gateway
	}
	if cfgErr := dev.Configure(cfg); cfgErr != nil {
		dev.Close()
		return nil, fmt.Errorf("vpn: configure TUN device: %w", cfgErr)
	}

	return b.finishOpen(dev, p)
}
