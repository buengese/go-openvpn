// SPDX-License-Identifier: LGPL-2.1-or-later

package kernel

import (
	"context"
	"fmt"
	"testing"

	"github.com/buengese/go-openvpn/device"
)

// TestLogfDiscardsWhenNil checks the documented default: a Backend with no
// Logf swallows its messages instead of panicking.
func TestLogfDiscardsWhenNil(t *testing.T) {
	var b Backend
	b.logf("vpn: apply routes: %v", context.Canceled)

	var nilBackend *Backend
	nilBackend.logf("vpn: apply DNS: %v", context.Canceled)
}

// TestLogfRoutesMessages checks that format and arguments reach the sink
// unformatted, so a sink can prefix, level or drop them as it likes.
func TestLogfRoutesMessages(t *testing.T) {
	var gotFormat string
	var gotArgs []any
	b := Backend{Logf: func(format string, args ...any) {
		gotFormat, gotArgs = format, args
	}}

	b.logf("vpn: redirect-gateway bypass route: %s via %s", "203.0.113.42", "192.168.1.1")

	if want := "vpn: redirect-gateway bypass route: %s via %s"; gotFormat != want {
		t.Errorf("format = %q, want %q", gotFormat, want)
	}
	if len(gotArgs) != 2 {
		t.Fatalf("args = %v, want 2 arguments", gotArgs)
	}
	if got, want := fmt.Sprintf(gotFormat, gotArgs...),
		"vpn: redirect-gateway bypass route: 203.0.113.42 via 192.168.1.1"; got != want {
		t.Errorf("rendered = %q, want %q", got, want)
	}
}

// TestOpenWithoutPushedOptionsFails checks that Open refuses empty Params
// before it touches anything privileged, on every platform: the kernel backends
// reject the parameters and the mobile stub rejects the platform.
func TestOpenWithoutPushedOptionsFails(t *testing.T) {
	var b Backend
	dev, err := b.Open(context.Background(), device.Params{})
	if err == nil {
		dev.Close() //nolint:errcheck
		t.Fatal("Open(zero Params) succeeded; want an error")
	}
	if dev != nil {
		t.Fatalf("Open returned a device alongside error %v", err)
	}
}

// TestCloseIsIdempotent checks the contract's idempotency requirement on a
// device that installed nothing: Close must be safe to call more than once,
// which is what lets the core call it from cleanup and from a failure path.
func TestCloseIsIdempotent(t *testing.T) {
	d := &kernelDevice{name: "go-openvpn-absent", mtu: 1400}
	for i := range 3 {
		if err := d.Close(); err != nil {
			t.Fatalf("Close #%d: %v", i+1, err)
		}
	}
}

// TestMTUAndName checks the two constant accessors report what Open recorded.
func TestMTUAndName(t *testing.T) {
	d := &kernelDevice{name: "tun7", mtu: 1400}
	if got := d.Name(); got != "tun7" {
		t.Errorf("Name() = %q, want %q", got, "tun7")
	}
	if got := d.MTU(); got != 1400 {
		t.Errorf("MTU() = %d, want 1400", got)
	}
}

// TestEffectiveMTU checks that an unset MTU is reported as the 1500 the
// interface actually gets, rather than as zero.
func TestEffectiveMTU(t *testing.T) {
	for _, tc := range []struct{ in, want int }{
		{0, defaultMTU},
		{-1, defaultMTU},
		{1400, 1400},
		{9000, 9000},
	} {
		if got := effectiveMTU(tc.in); got != tc.want {
			t.Errorf("effectiveMTU(%d) = %d, want %d", tc.in, got, tc.want)
		}
	}
}
