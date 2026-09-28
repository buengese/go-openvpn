//go:build !android && !ios && !darwin

// SPDX-License-Identifier: LGPL-2.1-or-later

package kernel

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/buengese/go-openvpn/device"
	"github.com/buengese/go-openvpn/routing"
)

// TestOpenRejectsMissingIfconfig checks that a PUSH_REPLY carrying routes but
// no ifconfig is refused before /dev/net/tun is opened: everything after that
// point dereferences the interface address.
func TestOpenRejectsMissingIfconfig(t *testing.T) {
	var b Backend
	p := device.Params{
		Push: &routing.PushOptions{
			Routes: []routing.Route{{
				Network: net.IPv4(10, 99, 0, 0),
				Mask:    net.CIDRMask(16, 32),
			}},
		},
		MTU: 1400,
	}
	dev, err := b.Open(context.Background(), p)
	if err == nil {
		dev.Close() //nolint:errcheck
		t.Fatal("Open without ifconfig succeeded; want an error")
	}
	if dev != nil {
		t.Fatalf("Open returned a device alongside error %v", err)
	}
	if !strings.Contains(err.Error(), "no ifconfig pushed") {
		t.Errorf("error = %v, want it to name the missing ifconfig", err)
	}
}

// TestOpenHonoursCancelledContext checks that Open declines to start when its
// context has already ended. The context bounds setup only, and the cheapest
// way to leave the host as it was found is to touch nothing at all.
func TestOpenHonoursCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var b Backend
	p := device.Params{
		Push: &routing.PushOptions{
			Topology: routing.TopologyNet30,
			Ifconfig: &routing.Ifconfig{
				Local:   net.IPv4(10, 99, 8, 6),
				Gateway: net.IPv4(10, 99, 8, 5),
			},
		},
		MTU: 1400,
	}
	dev, err := b.Open(ctx, p)
	if err == nil {
		dev.Close() //nolint:errcheck
		t.Fatal("Open with a cancelled context succeeded; want context.Canceled")
	}
	if !strings.Contains(err.Error(), context.Canceled.Error()) {
		t.Errorf("error = %v, want context.Canceled", err)
	}
}
