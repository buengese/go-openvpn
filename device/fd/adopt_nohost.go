// SPDX-License-Identifier: LGPL-2.1-or-later

//go:build !android && !darwin && !ios

package fd

import "errors"

// errNoHost is what Open fails with where nothing supplies a descriptor.
//
// The constraints are the complement of adopt_host.go, in practice desktop
// Linux: there is no VpnService and no Network Extension to hand a descriptor
// over, so a tunnel comes from device/kernel or netstack instead.
var errNoHost = errors.New("no VPN host supplies a tunnel descriptor on this platform; use the kernel or netstack backend")

// adopt always fails here. See errNoHost.
func adopt(int) (tunDevice, error) {
	return nil, errNoHost
}
