// SPDX-License-Identifier: LGPL-2.1-or-later

//go:build android || darwin || ios

package fd

import "github.com/openlawsvpn/go-openlawsvpn/tun"

// adopt wraps a descriptor supplied by the platform's VPN host. The build tags
// mirror tun's own split: android has tun.OpenFd for VpnService, darwin and ios
// have it for NEPacketTunnelProvider. Per-platform framing — the four-byte
// address-family header a utun prepends — is handled inside tun.Device, so what
// comes back reads and writes raw IP.
func adopt(fd int) (tunDevice, error) {
	return tun.OpenFd(fd)
}
