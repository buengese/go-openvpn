//go:build android || ios

// SPDX-License-Identifier: LGPL-2.1-or-later

package kernel

import (
	"context"
	"errors"

	"github.com/buengese/go-openvpn/device"
)

// ErrHostSuppliesDescriptor is returned by Open on Android and iOS, where an
// application cannot create a tunnel interface itself: VpnService.Builder and
// NEPacketTunnelProvider create it, configure its addressing, routes and DNS,
// and hand this process the descriptor. There is nothing left for a privileged
// backend to do, so device/fd serves those platforms.
var ErrHostSuppliesDescriptor = errors.New(
	"device/kernel: unavailable on this platform — the host supplies the tunnel descriptor (use device/fd)")

// Open reports that the kernel backend is unavailable on this platform. It
// installs nothing and therefore has nothing to unwind.
func (b *Backend) Open(_ context.Context, _ device.Params) (device.Device, error) {
	return nil, ErrHostSuppliesDescriptor
}
