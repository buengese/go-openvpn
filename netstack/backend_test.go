// SPDX-License-Identifier: LGPL-2.1-or-later

package netstack

import (
	"bytes"
	"context"
	"errors"
	"net"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openlawsvpn/go-openlawsvpn/device"

	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// Backend and Device must satisfy the device package's contracts.
var (
	_ device.Backend = (*Backend)(nil)
	_ device.Device  = (*Device)(nil)
)

// TestMTUAndName checks the two constant properties of a device.
func TestMTUAndName(t *testing.T) {
	p := paramsV4()
	p.MTU = 1400
	d := openDevice(t, p)

	if got := d.MTU(); got != 1400 {
		t.Errorf("MTU = %d, want 1400", got)
	}
	if got := d.Name(); !strings.HasPrefix(got, "netstack") {
		t.Errorf("Name = %q, want a netstack* synthetic name", got)
	}
}

// TestNameIsUnique checks that two devices in one process are distinguishable
// in a log, which is the only thing the synthetic name is for.
func TestNameIsUnique(t *testing.T) {
	a := openDevice(t, paramsV4())
	b := openDevice(t, paramsV4())
	if a.Name() == b.Name() {
		t.Errorf("two devices share the name %q", a.Name())
	}
}

// TestNameOverride checks the Backend.Name knob.
func TestNameOverride(t *testing.T) {
	d, err := (&Backend{Name: "measure-7"}).Open(context.Background(), paramsV4())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer d.Close() //nolint:errcheck

	if got := d.Name(); got != "measure-7" {
		t.Errorf("Name = %q, want %q", got, "measure-7")
	}
}

// TestNewBackend checks that the constructor and the zero value agree.
func TestNewBackend(t *testing.T) {
	if got := NewBackend(); *got != (Backend{}) {
		t.Errorf("NewBackend() = %+v, want the zero Backend", *got)
	}
}

// TestCloseIsIdempotent calls Close repeatedly, as the device contract and the
// defer-plus-cleanup pattern both require.
func TestCloseIsIdempotent(t *testing.T) {
	d, err := (&Backend{}).Open(context.Background(), paramsDual())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	for i := range 3 {
		if err := d.Close(); err != nil {
			t.Fatalf("Close #%d: %v", i+1, err)
		}
	}
}

// TestUseAfterClose checks that both packet paths fail cleanly rather than
// panicking or blocking once the device is gone, and that the error is
// recognisable as a closed endpoint.
func TestUseAfterClose(t *testing.T) {
	d, err := (&Backend{}).Open(context.Background(), paramsV4())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := d.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if err := d.WritePacket(make([]byte, 40)); !errors.Is(err, ErrDeviceClosed) {
		t.Errorf("WritePacket after Close = %v, want ErrDeviceClosed", err)
	} else if !errors.Is(err, net.ErrClosed) {
		t.Errorf("WritePacket after Close = %v, want it to wrap net.ErrClosed", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := d.ReadPacket(ctx, make([]byte, 1500)); !errors.Is(err, ErrDeviceClosed) {
		t.Errorf("ReadPacket after Close = %v, want ErrDeviceClosed", err)
	}
}

// TestCloseUnblocksReadPacket is the load-bearing half of the Close contract:
// Close may arrive while a ReadPacket is blocked, and must not deadlock waiting
// for it to return.
func TestCloseUnblocksReadPacket(t *testing.T) {
	d, err := (&Backend{}).Open(context.Background(), paramsV4())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	readErr := make(chan error, 1)
	go func() {
		_, err := d.ReadPacket(context.Background(), make([]byte, 1500))
		readErr <- err
	}()

	// Give the reader time to actually block in ReadContext.
	time.Sleep(50 * time.Millisecond)

	closed := make(chan error, 1)
	go func() { closed <- d.Close() }()

	select {
	case err := <-closed:
		if err != nil {
			t.Fatalf("Close: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close blocked behind an in-flight ReadPacket")
	}

	select {
	case err := <-readErr:
		if !errors.Is(err, ErrDeviceClosed) {
			t.Errorf("ReadPacket returned %v, want ErrDeviceClosed", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not unblock ReadPacket")
	}
}

// TestReadPacketHonoursContext checks that a reader with nothing to read comes
// back when its context ends. This is what replaced the 500 ms SetReadDeadline
// loop for backends that are not files.
func TestReadPacketHonoursContext(t *testing.T) {
	d := openDevice(t, paramsV4())

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := d.ReadPacket(ctx, make([]byte, d.MTU()))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("ReadPacket = %v, want context.DeadlineExceeded", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("ReadPacket took %s to honour a 100ms deadline", elapsed)
	}
}

// TestReadPacketTruncates checks the device contract's truncation rule: a
// packet longer than buf is cut, not split across two reads.
func TestReadPacketTruncates(t *testing.T) {
	d := openDevice(t, paramsV4())

	local := mustAddr4(tunLocal4)
	peer := mustAddr4(tunPeer4)
	if err := d.WritePacket(echoRequest4(peer, local, 1, 1, make([]byte, 200))); err != nil {
		t.Fatalf("WritePacket: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	small := make([]byte, 20)
	n, err := d.ReadPacket(ctx, small)
	if err != nil {
		t.Fatalf("ReadPacket: %v", err)
	}
	if n != len(small) {
		t.Errorf("ReadPacket returned %d, want the full %d-byte buffer", n, len(small))
	}

	// The remainder must not surface as a second packet.
	ctx2, cancel2 := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel2()
	if _, err := d.ReadPacket(ctx2, make([]byte, d.MTU())); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("a truncated packet produced a second read: %v", err)
	}
}

// TestWritePacketRejectsNonIP checks that garbage from the data channel is
// reported rather than injected.
func TestWritePacketRejectsNonIP(t *testing.T) {
	d := openDevice(t, paramsV4())

	for _, tc := range []struct {
		name string
		pkt  []byte
	}{
		{"empty", nil},
		{"version 0", []byte{0x00, 0x01, 0x02, 0x03}},
		{"version 5", []byte{0x50, 0x01, 0x02, 0x03}},
	} {
		if err := d.WritePacket(tc.pkt); err == nil {
			t.Errorf("WritePacket(%s) succeeded, want an error", tc.name)
		}
	}
}

// TestWritePacketDoesNotRetain checks the "must not retain pkt" half of the
// contract: the caller reuses its buffer the moment WritePacket returns, so the
// stack must have copied.
func TestWritePacketDoesNotRetain(t *testing.T) {
	d := openDevice(t, paramsV4())

	local := mustAddr4(tunLocal4)
	peer := mustAddr4(tunPeer4)
	payload := []byte("do-not-retain")

	buf := echoRequest4(peer, local, 0x1234, 1, payload)
	if err := d.WritePacket(buf); err != nil {
		t.Fatalf("WritePacket: %v", err)
	}
	// Scribble over the caller's buffer before the reply is read.
	for i := range buf {
		buf[i] = 0xff
	}

	out := readPacket(t, d)
	ip := header.IPv4(out)
	got := header.ICMPv4(out[ip.HeaderLength():]).Payload()
	if !bytes.Equal(got, payload) {
		t.Errorf("reply payload = %q, want %q: the stack retained the caller's buffer", got, payload)
	}
}

// TestConcurrentReadWrite runs the two packet paths against each other the way
// the client does — one goroutine each, concurrently — while Close arrives on a
// third.
func TestConcurrentReadWrite(t *testing.T) {
	d, err := (&Backend{}).Open(context.Background(), paramsDual())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		local := mustAddr4(tunLocal4)
		peer := mustAddr4(tunPeer4)
		for seq := uint16(0); ; seq++ {
			if err := d.WritePacket(echoRequest4(peer, local, 1, seq, []byte("x"))); err != nil {
				return // the device closed under us; that is the point
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Millisecond):
			}
		}
	}()

	go func() {
		defer wg.Done()
		buf := make([]byte, d.MTU())
		for {
			if _, err := d.ReadPacket(ctx, buf); err != nil {
				return
			}
		}
	}()

	time.Sleep(200 * time.Millisecond)
	if err := d.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("packet goroutines did not stop after Close")
	}
}

// TestCloseLeavesNoGoroutines opens and closes a run of devices and checks the
// goroutine count comes back. A backend meant for a hundred concurrent tunnels
// in one process cannot leak a worker per tunnel.
func TestCloseLeavesNoGoroutines(t *testing.T) {
	// Warm up, so one-off initialisation is not counted as a leak.
	d, err := (&Backend{}).Open(context.Background(), paramsDual())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := d.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	baseline := settledGoroutines()

	for i := range 20 {
		d, err := (&Backend{}).Open(context.Background(), paramsDual())
		if err != nil {
			t.Fatalf("Open #%d: %v", i, err)
		}
		local := mustAddr4(tunLocal4)
		peer := mustAddr4(tunPeer4)
		if err := d.WritePacket(echoRequest4(peer, local, uint16(i), 1, []byte("ping"))); err != nil {
			t.Fatalf("WritePacket #%d: %v", i, err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if _, err := d.ReadPacket(ctx, make([]byte, d.MTU())); err != nil {
			cancel()
			t.Fatalf("ReadPacket #%d: %v", i, err)
		}
		cancel()
		if err := d.Close(); err != nil {
			t.Fatalf("Close #%d: %v", i, err)
		}
	}

	if got := settledGoroutines(); got > baseline+2 {
		t.Errorf("goroutines after 20 open/close cycles = %d, baseline %d", got, baseline)
	}
}

// settledGoroutines waits for the goroutine count to stop falling, then returns
// it. Teardown is asynchronous enough that a bare NumGoroutine is noise.
func settledGoroutines() int {
	best := runtime.NumGoroutine()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		runtime.GC()
		time.Sleep(20 * time.Millisecond)
		n := runtime.NumGoroutine()
		if n >= best {
			return best
		}
		best = n
	}
	return best
}
