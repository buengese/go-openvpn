// SPDX-License-Identifier: LGPL-2.1-or-later

// The package as a consumer reaches it, from outside. This is the only file in
// package vpn_test; everything else lives inside the package, where it can
// assert on the state it is about.

package vpn_test

import (
	"testing"

	vpn "github.com/buengese/go-openvpn"
	"github.com/buengese/go-openvpn/profile"
)

func makeTestProfile() *profile.Profile {
	p, err := profile.ParseString("remote vpn.example.com 443\nproto tcp-client\n")
	if err != nil {
		panic(err)
	}
	return p
}

// TestFreshClientHasNoSessionState covers every accessor a caller may reach for
// before Connect, each of which has to answer rather than panic. MaxReconnects
// is the opposite case: its zero value means "unlimited", so New must leave it.
func TestFreshClientHasNoSessionState(t *testing.T) {
	c := vpn.New(makeTestProfile())
	if c == nil {
		t.Fatal("New returned nil")
	}
	if s := c.Stats(); s.BytesSent != 0 || s.BytesRecv != 0 || s.Uptime != 0 {
		t.Errorf("Stats() = %+v, want the zero value before any connection", s)
	}
	if ip := c.LocalIP(); ip != "" {
		t.Errorf("LocalIP before connect = %q, want empty", ip)
	}
	if c.MaxReconnects != 0 {
		t.Errorf("MaxReconnects = %d, want 0 (unlimited)", c.MaxReconnects)
	}
}
