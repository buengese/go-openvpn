// SPDX-License-Identifier: LGPL-2.1-or-later

// The parts of a TUN device that do not vary by platform.
//
// Opening the interface, configuring its addressing and framing a packet are
// all platform business and live in the per-platform files. What a device *is*
// — a file and a name — and what a caller asks for when opening one are the
// same everywhere, and were written out four times. The copies had already
// drifted once: darwin and ios disagreed about the utun header for an IPv6
// packet, which is the sort of thing four identical-looking files hide.

package tun

import (
	"net"
	"os"
)

// Config is the addressing to give a TUN interface.
type Config struct {
	// LocalIP is the IP address assigned to this end of the tunnel.
	LocalIP net.IP
	// PeerIP is the P2P peer address for net30 topology.
	// Mutually exclusive with Mask — set one or the other.
	PeerIP net.IP
	// Mask is the subnet mask for subnet topology.
	// When set, the interface is configured as a regular (non-P2P) subnet
	// rather than point-to-point, where the platform supports the difference.
	Mask net.IPMask
	// MTU is the maximum transmission unit for the interface (default 1500).
	MTU int
}

// Device represents an open TUN interface.
type Device struct {
	file *os.File
	name string
}

// Name returns the interface name, for example "tun0" or "utun4".
func (d *Device) Name() string { return d.name }

// File returns the underlying file, for a caller that needs the descriptor.
func (d *Device) File() *os.File { return d.file }

// Close closes the TUN device file descriptor.
func (d *Device) Close() error { return d.file.Close() }
