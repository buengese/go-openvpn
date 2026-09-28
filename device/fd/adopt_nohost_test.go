// SPDX-License-Identifier: LGPL-2.1-or-later

//go:build !android && !darwin && !ios

package fd

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/buengese/go-openvpn/device"
)

// TestOpenWithoutAHostFails pins what the fd backend does where nothing hands
// descriptors out: selecting it there is a configuration mistake, and it has to
// say so rather than fail further down with an EBADF.
func TestOpenWithoutAHostFails(t *testing.T) {
	b := New(3) // a plausible descriptor; the platform is the problem, not the value
	_, err := b.Open(context.Background(), device.Params{MTU: 1400})
	if err == nil {
		t.Fatal("Open succeeded on a platform with no VPN host, want an error")
	}
	if !errors.Is(err, errNoHost) {
		t.Errorf("Open = %v, want it to wrap errNoHost", err)
	}
	if !strings.Contains(err.Error(), "device/fd") {
		t.Errorf("error %q does not name the package it came from", err)
	}
}
