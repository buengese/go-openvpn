//go:build android

// Android TUN support via VpnService.
//
// On Android apps cannot open /dev/net/tun directly. Instead the system
// creates the TUN interface via VpnService.Builder.establish() and hands
// the app a pre-configured file descriptor. This file wraps that fd in a
// Device so the rest of the codebase can use it unchanged.
package tun

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// Read reads one IP packet from the TUN device.
func (d *Device) Read(buf []byte) (int, error) { return d.file.Read(buf) }

// Write writes one IP packet to the TUN device.
func (d *Device) Write(pkt []byte) (int, error) { return d.file.Write(pkt) }

// Configure is a no-op on Android: VpnService.Builder already configured
// the interface before handing us the fd.
func (d *Device) Configure(_ Config) error { return nil }

// OpenFd wraps a TUN file descriptor provided by Android's VpnService.
//
// The fd is the value returned by VpnService.Builder.establish() (passed
// through JNI/gomobile as an int). The interface is already fully configured
// (IP address, routes, DNS) by the Java layer before this call.
//
// OpenFd sets O_NONBLOCK on the fd so Go's runtime poller (epoll) can manage
// it, then wraps it with os.NewFile.
func OpenFd(fd int) (*Device, error) {
	if fd < 0 {
		return nil, fmt.Errorf("tun: invalid fd %d", fd)
	}
	// O_NONBLOCK is required so Go's runtime poller can use epoll on the fd.
	if err := unix.SetNonblock(fd, true); err != nil {
		return nil, fmt.Errorf("tun: SetNonblock: %w", err)
	}
	f := os.NewFile(uintptr(fd), "vpnservice-tun")
	if f == nil {
		return nil, fmt.Errorf("tun: os.NewFile returned nil for fd %d", fd)
	}
	return &Device{file: f, name: "tun0"}, nil
}
