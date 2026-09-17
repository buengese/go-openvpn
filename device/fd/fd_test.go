// SPDX-License-Identifier: LGPL-2.1-or-later

package fd

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/openlawsvpn/go-openlawsvpn/device"
)

// pipeTUN stands in for the descriptor a VpnService or NEPacketTunnelProvider
// hands over: os.Pipe gives an *os.File the runtime poller manages, so
// SetReadDeadline works, and a read that blocks until the other side writes.
type pipeTUN struct {
	outR, outW *os.File // host to tunnel: the test writes outW, ReadPacket reads outR
	inR, inW   *os.File // tunnel to host: WritePacket writes inW, the test reads inR

	mu     sync.Mutex
	closes int
}

func newPipeTUN(t *testing.T) *pipeTUN {
	t.Helper()
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	inR, inW, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	return &pipeTUN{outR: outR, outW: outW, inR: inR, inW: inW}
}

func (p *pipeTUN) Name() string                { return "pipe0" }
func (p *pipeTUN) File() *os.File              { return p.outR }
func (p *pipeTUN) Read(b []byte) (int, error)  { return p.outR.Read(b) }
func (p *pipeTUN) Write(b []byte) (int, error) { return p.inW.Write(b) }

func (p *pipeTUN) Close() error {
	p.mu.Lock()
	p.closes++
	p.mu.Unlock()
	p.outR.Close() //nolint:errcheck
	p.outW.Close() //nolint:errcheck
	p.inR.Close()  //nolint:errcheck
	p.inW.Close()  //nolint:errcheck
	return nil
}

// closeCount reports how many times Close reached the descriptor.
func (p *pipeTUN) closeCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.closes
}

var _ tunDevice = (*pipeTUN)(nil)

// TestDeviceMovesPackets is the whole job of this backend: raw IP out, raw IP
// in, nothing else touched.
func TestDeviceMovesPackets(t *testing.T) {
	p := newPipeTUN(t)
	d := &Device{tun: p, mtu: 1400}
	defer d.Close() //nolint:errcheck

	if got := d.MTU(); got != 1400 {
		t.Errorf("MTU() = %d, want 1400", got)
	}
	if got := d.Name(); got != "pipe0" {
		t.Errorf("Name() = %q, want pipe0", got)
	}

	outbound := []byte{0x45, 0x00, 0x00, 0x14, 0xde, 0xad}
	if _, err := p.outW.Write(outbound); err != nil {
		t.Fatalf("write to pipe: %v", err)
	}
	buf := make([]byte, d.MTU())
	n, err := d.ReadPacket(context.Background(), buf)
	if err != nil {
		t.Fatalf("ReadPacket: %v", err)
	}
	if string(buf[:n]) != string(outbound) {
		t.Errorf("ReadPacket = % x, want % x", buf[:n], outbound)
	}

	inbound := []byte{0x60, 0x00, 0x00, 0x00, 0xbe, 0xef}
	if err := d.WritePacket(inbound); err != nil {
		t.Fatalf("WritePacket: %v", err)
	}
	got := make([]byte, len(inbound))
	if _, err := p.inR.Read(got); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(got) != string(inbound) {
		t.Errorf("WritePacket delivered % x, want % x", got, inbound)
	}
}

// TestDeviceReadPacketHonoursContext is the property that lets the core drop
// SetReadDeadline: a read blocked on a quiet tunnel ends when the context does,
// reporting the context's own error.
func TestDeviceReadPacketHonoursContext(t *testing.T) {
	d := &Device{tun: newPipeTUN(t), mtu: 1400}
	defer d.Close() //nolint:errcheck

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		_, err := d.ReadPacket(ctx, make([]byte, d.MTU()))
		errCh <- err
	}()

	// Let the read block before cancelling, so this exercises the blocked
	// path rather than the pre-cancelled shortcut at the top of the loop.
	time.Sleep(10 * time.Millisecond)
	cancel()

	select {
	case err := <-errCh:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("ReadPacket after cancel = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ReadPacket did not return after the context was cancelled")
	}
}

// TestDeviceCloseUnblocksReadPacket pins the other half of the concurrency
// contract: Close arrives from a third goroutine while a read is in flight and
// must not deadlock on it.
func TestDeviceCloseUnblocksReadPacket(t *testing.T) {
	d := &Device{tun: newPipeTUN(t), mtu: 1400}

	errCh := make(chan error, 1)
	go func() {
		_, err := d.ReadPacket(context.Background(), make([]byte, d.MTU()))
		errCh <- err
	}()
	time.Sleep(10 * time.Millisecond)

	if err := d.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case err := <-errCh:
		if err == nil {
			t.Error("ReadPacket returned nil after Close, want an error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ReadPacket did not return after Close")
	}
}

// TestDeviceCloseIsIdempotent covers the contract's requirement directly, and
// with it the claim that Close does nothing but close the descriptor: a second
// call reaches the host's fd zero extra times.
func TestDeviceCloseIsIdempotent(t *testing.T) {
	p := newPipeTUN(t)
	d := &Device{tun: p, mtu: 1400}

	for i := range 3 {
		if err := d.Close(); err != nil {
			t.Fatalf("Close #%d: %v", i+1, err)
		}
	}
	if got := p.closeCount(); got != 1 {
		t.Errorf("descriptor closed %d times, want 1", got)
	}
}

// TestBackendOpenRejectsBadHosts covers every way Open can fail before it
// reaches a descriptor. This backend installs nothing, so the bar is that each
// reports rather than returning a Device that cannot work.
func TestBackendOpenRejectsBadHosts(t *testing.T) {
	t.Run("no establish func", func(t *testing.T) {
		var b Backend
		if _, err := b.Open(context.Background(), device.Params{}); err == nil {
			t.Fatal("Open with a nil Establish succeeded, want an error")
		}
	})

	t.Run("establish fails", func(t *testing.T) {
		sentinel := errors.New("VpnService.Builder.establish() threw")
		b := &Backend{Establish: func(context.Context, device.Params) (int, error) {
			return -1, sentinel
		}}
		_, err := b.Open(context.Background(), device.Params{})
		if !errors.Is(err, sentinel) {
			t.Fatalf("Open = %v, want it to wrap %v", err, sentinel)
		}
	})

	t.Run("negative fd", func(t *testing.T) {
		// -1 is how both the Android and the iOS callback report failure
		// without an error value, so it has to be an error here.
		b := &Backend{Establish: func(context.Context, device.Params) (int, error) {
			return -1, nil
		}}
		if _, err := b.Open(context.Background(), device.Params{}); err == nil {
			t.Fatal("Open with fd=-1 succeeded, want an error")
		}
	})

	t.Run("cancelled context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		called := false
		b := &Backend{Establish: func(context.Context, device.Params) (int, error) {
			called = true
			return 3, nil
		}}
		_, err := b.Open(ctx, device.Params{})
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Open on a cancelled context = %v, want context.Canceled", err)
		}
		if called {
			t.Error("Establish was called on a cancelled context")
		}
	})
}

// TestNewPassesTheDescriptorThrough pins the fixed-descriptor form: New wraps a
// value already in hand and hands it to Open unchanged.
func TestNewPassesTheDescriptorThrough(t *testing.T) {
	b := New(7)
	got, err := b.Establish(context.Background(), device.Params{})
	if err != nil {
		t.Fatalf("Establish: %v", err)
	}
	if got != 7 {
		t.Errorf("Establish returned fd=%d, want 7", got)
	}
}

// TestBackendPassesParamsToTheHost pins the ordering the mobile path depends
// on: the host is asked for a descriptor with the negotiated parameters in
// hand, because it configures the interface it is about to create.
func TestBackendPassesParamsToTheHost(t *testing.T) {
	var got device.Params
	b := &Backend{Establish: func(_ context.Context, p device.Params) (int, error) {
		got = p
		return -1, nil // stop before adopt: there is no real descriptor here
	}}
	want := device.Params{MTU: 1400}
	if _, err := b.Open(context.Background(), want); err == nil {
		t.Fatal("Open with fd=-1 succeeded, want an error")
	}
	if got.MTU != want.MTU {
		t.Errorf("Establish saw MTU %d, want %d", got.MTU, want.MTU)
	}
}
