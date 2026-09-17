//go:build ios

// iOS TUN support via NEPacketTunnelProvider.
//
// On iOS apps cannot open /dev/net/tun directly. Instead the Network Extension
// framework creates the TUN interface and exposes the raw file descriptor via
// a private KVC key on NEPacketTunnelFlow:
//
//	fd := (self.packetFlow as AnyObject).value(forKey: "mTunFileDescriptor") as! Int32
//
// The Swift PacketTunnelProvider passes this fd to VpnMobileClient.establishTUN,
// which calls OpenFd here to wrap it for use by the Go engine.
package tun

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// Read and Write are in tun_utun.go. The fd the Swift socket scan hands over is
// a raw utun control socket — the same kernel interface as macOS, not something
// NEPacketTunnelFlow wraps — so the 4-byte AF_ header is the same on both, and
// so is the code that puts it on.

// Configure is a no-op on iOS: NEPacketTunnelNetworkSettings already configured
// the interface before handing us the fd.
func (d *Device) Configure(_ Config) error { return nil }

// OpenFd wraps a TUN file descriptor provided by iOS's NEPacketTunnelFlow.
//
// The fd is the value extracted from packetFlow via the mTunFileDescriptor KVC
// key (a private but App-Store-approved API used by WireGuard-iOS since 2019).
// The interface is fully configured (IP address, routes, DNS) by the Swift
// PacketTunnelProvider via setTunnelNetworkSettings before this call.
//
// OpenFd sets O_NONBLOCK on the fd so Go's runtime poller can manage it,
// then wraps it with os.NewFile.
func OpenFd(fd int) (*Device, error) {
	if fd < 0 {
		return nil, fmt.Errorf("tun: invalid fd %d", fd)
	}
	// O_NONBLOCK is required so Go's runtime poller can use kqueue on the fd.
	if err := unix.SetNonblock(fd, true); err != nil {
		return nil, fmt.Errorf("tun: SetNonblock: %w", err)
	}
	f := os.NewFile(uintptr(fd), "packettunnel-tun")
	if f == nil {
		return nil, fmt.Errorf("tun: os.NewFile returned nil for fd %d", fd)
	}
	return &Device{file: f, name: "utun0"}, nil
}
