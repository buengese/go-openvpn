// SPDX-License-Identifier: LGPL-2.1-or-later

package netstack

import (
	"context"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"
)

// hostStateCommands are the views the canary compares: the interface list and
// both route tables. A netstack backend must leave every one of them
// byte-identical across a full tunnel lifecycle.
var hostStateCommands = [][]string{
	{"ip", "-o", "link", "show"},
	{"ip", "-4", "route", "show"},
	{"ip", "-6", "route", "show"},
}

// TestHostStateUnchanged is the canary for "nothing privileged, ever": open a
// dual-stack device, push traffic through it in both directions, close it, and
// assert that `ip link` and `ip route` say exactly what they said before.
func TestHostStateUnchanged(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skipf("the ip(8) canary is Linux-only; GOOS is %s", runtime.GOOS)
	}
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skipf("ip(8) not available: %v", err)
	}

	before := captureHostState(t)

	// A full lifecycle, not just open and close: addresses assigned, both
	// families routed, packets crossing in both directions.
	d, err := (&Backend{}).Open(context.Background(), paramsDual())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	local4, peer4 := mustAddr4(tunLocal4), mustAddr4(tunPeer4)
	if err := d.WritePacket(echoRequest4(peer4, local4, 1, 1, []byte("canary"))); err != nil {
		t.Fatalf("WritePacket v4: %v", err)
	}
	local6, peer6 := mustAddr6(tunLocal6), mustAddr6(tunPeer6)
	if err := d.WritePacket(echoRequest6(peer6, local6, 2, 1, []byte("canary"))); err != nil {
		t.Fatalf("WritePacket v6: %v", err)
	}
	for range 2 {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if _, err := d.ReadPacket(ctx, make([]byte, d.MTU())); err != nil {
			cancel()
			t.Fatalf("ReadPacket: %v", err)
		}
		cancel()
	}

	during := captureHostState(t)
	if err := d.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	after := captureHostState(t)

	for i, cmd := range hostStateCommands {
		label := strings.Join(cmd, " ")
		if before[i] != during[i] {
			t.Errorf("%q changed while the device was open:\n--- before\n%s\n--- during\n%s",
				label, before[i], during[i])
		}
		if before[i] != after[i] {
			t.Errorf("%q changed across the device lifecycle:\n--- before\n%s\n--- after\n%s",
				label, before[i], after[i])
		}
	}
}

// captureHostState runs the canary commands and returns their output.
func captureHostState(t *testing.T) []string {
	t.Helper()
	out := make([]string, len(hostStateCommands))
	for i, cmd := range hostStateCommands {
		b, err := exec.Command(cmd[0], cmd[1:]...).Output()
		if err != nil {
			t.Skipf("%q failed, cannot run the canary: %v", strings.Join(cmd, " "), err)
		}
		out[i] = string(b)
	}
	return out
}
