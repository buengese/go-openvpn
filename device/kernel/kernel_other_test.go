//go:build android || ios

// SPDX-License-Identifier: LGPL-2.1-or-later

package kernel

import (
	"context"
	"errors"
	"testing"

	"github.com/buengese/go-openvpn/device"
	"github.com/buengese/go-openvpn/routing"
)

// TestOpenReportsHostSuppliesDescriptor checks that the mobile platforms refuse
// the kernel backend outright: VpnService.Builder and NEPacketTunnelProvider
// create the interface, and device/fd wraps what they hand back.
func TestOpenReportsHostSuppliesDescriptor(t *testing.T) {
	var b Backend
	dev, err := b.Open(context.Background(), device.Params{Push: &routing.PushOptions{}})
	if dev != nil {
		t.Fatalf("Open returned a device on a host-supplied-descriptor platform: %v", dev)
	}
	if !errors.Is(err, ErrHostSuppliesDescriptor) {
		t.Fatalf("error = %v, want ErrHostSuppliesDescriptor", err)
	}
}
