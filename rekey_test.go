// SPDX-License-Identifier: LGPL-2.1-or-later

// Renegotiation: the key exchange that happens on a session that is already
// up.
//
// A rekey is the ordinary handshake run again inside a live tunnel, so what is
// asserted here is the part that is not the handshake: how long it may take,
// how long the new epoch waits, and the waits that sequence the soft reset.

package vpn

import (
	"context"
	"testing"
	"time"

	"github.com/openlawsvpn/go-openlawsvpn/internal/ctls"
	"github.com/openlawsvpn/go-openlawsvpn/internal/reliable"
	"github.com/openlawsvpn/go-openlawsvpn/profile"
)

func TestWaitForRekeyResetRequiresPeerResetAndAck(t *testing.T) {
	sess := &controlSession{
		peerReset:  make(chan struct{}),
		resetAcked: make(chan struct{}),
	}
	result := make(chan error, 1)
	go func() {
		result <- waitForRekeyReset(context.Background(), sess, time.Now().Add(time.Second))
	}()

	close(sess.peerReset)
	select {
	case err := <-result:
		t.Fatalf("waitForRekeyReset returned before reset ACK: %v", err)
	case <-time.After(20 * time.Millisecond):
	}

	close(sess.resetAcked)
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("waitForRekeyReset: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("waitForRekeyReset did not complete after both reset events")
	}
}

func TestWaitForRekeyResetDeadline(t *testing.T) {
	sess := &controlSession{
		peerReset:  make(chan struct{}),
		resetAcked: make(chan struct{}),
	}
	err := waitForRekeyReset(context.Background(), sess, time.Now().Add(5*time.Millisecond))
	if err == nil || err.Error() != "rekey reset exchange: deadline exceeded (peer reset received=false, local reset acknowledged=false)" {
		t.Fatalf("waitForRekeyReset error = %v, want detailed reset-exchange deadline", err)
	}
}

func TestWaitForControlAcks(t *testing.T) {
	sess := &controlSession{sendQueue: reliable.NewSendQueue(0)}
	if _, err := sess.sendQueue.Enqueue([]byte("auth")); err != nil {
		t.Fatalf("enqueue auth: %v", err)
	}

	result := make(chan error, 1)
	go func() {
		result <- waitForControlAcks(context.Background(), sess, time.Now().Add(time.Second))
	}()

	select {
	case err := <-result:
		t.Fatalf("waitForControlAcks returned before ACK: %v", err)
	case <-time.After(20 * time.Millisecond):
	}

	sess.sendQueue.Ack(0)
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("waitForControlAcks: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("waitForControlAcks did not complete after ACK")
	}
}

func TestWaitForControlAcksDeadline(t *testing.T) {
	sess := &controlSession{sendQueue: reliable.NewSendQueue(0)}
	sess.sendQueue.Enqueue([]byte("auth")) //nolint:errcheck

	err := waitForControlAcks(context.Background(), sess, time.Now().Add(5*time.Millisecond))
	if err == nil || err.Error() != "rekey auth acknowledgement: deadline exceeded (1 control packets unacknowledged)" {
		t.Fatalf("waitForControlAcks error = %v", err)
	}
}

// TestRekeyPromotionDelay covers how long the new key epoch waits before it
// becomes the one packets are sent under. --tls-exit-becomes-primary decides it
// when the profile names one; otherwise it is openvpn3's
// min(hand-window, reneg-sec/2) from ssl/proto.hpp:1268-1270.
func TestRekeyPromotionDelay(t *testing.T) {
	for _, tc := range []struct {
		name string
		prof profile.Profile
		want time.Duration
	}{
		{"an explicit become-primary delay wins", profile.Profile{RenegSec: 60, BecomePrimarySec: 5}, 5 * time.Second},
		{"a short reneg-sec takes the scaled default", profile.Profile{RenegSec: 60}, 30 * time.Second},
		{"a long reneg-sec is capped at the default hand-window", profile.Profile{RenegSec: 3600}, 60 * time.Second},
		{"an explicit hand-window is the cap", profile.Profile{RenegSec: 3600, HandWindowSec: 20}, 20 * time.Second},
		{"a hand-window above the half-interval does not raise it", profile.Profile{RenegSec: 60, HandWindowSec: 300}, 30 * time.Second},
		{"a hand-window still loses to become-primary", profile.Profile{RenegSec: 3600, HandWindowSec: 20, BecomePrimarySec: 45}, 45 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := tc.prof
			c := &Client{prof: &p}
			if got := c.rekeyPromotionDelay(); got != tc.want {
				t.Fatalf("rekeyPromotionDelay = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestRekeySoftResetAdvancesReceiveWindow(t *testing.T) {
	sess := &controlSession{
		transport:  ctls.NewControlTransport(nil, nil, 1),
		recvWindow: reliable.NewRecvWindow(),
	}
	defer sess.transport.Close() //nolint:errcheck

	// The server's SOFT_RESET is the first reliable packet in the new key
	// epoch.  Its empty payload must advance the window to packet ID 1.
	sess.receiveControl(0, nil)
	sess.receiveControl(1, []byte("server TLS"))

	if err := sess.transport.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	buf := make([]byte, len("server TLS"))
	n, err := sess.transport.Read(buf)
	if err != nil {
		t.Fatalf("read TLS payload: %v", err)
	}
	if got := string(buf[:n]); got != "server TLS" {
		t.Fatalf("TLS payload = %q, want %q", got, "server TLS")
	}
}

// TestHandWindowBoundsTheKeyExchange pins the directive's primary meaning: the
// reference sets must_negotiate from hand-window (ssl.c:2590) and gives up with
// "TLS key negotiation failed to occur within %d seconds".
func TestHandWindowBoundsTheKeyExchange(t *testing.T) {
	for _, tc := range []struct {
		name string
		prof *profile.Profile
		want time.Duration
	}{
		{"unset uses the reference's 60", &profile.Profile{}, 60 * time.Second},
		{"a longer window is honoured", &profile.Profile{HandWindowSec: 120}, 120 * time.Second},
		{"a shorter window is honoured", &profile.Profile{HandWindowSec: 15}, 15 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &Client{prof: tc.prof}
			if got := c.handWindow(); got != tc.want {
				t.Errorf("handWindow() = %v, want %v", got, tc.want)
			}
			// The same number bounds the initial handshake and every
			// renegotiation, against a context that carries no deadline of
			// its own.
			gotDeadline := time.Until(c.keyExchangeDeadline(context.Background()))
			if gotDeadline < tc.want-time.Second || gotDeadline > tc.want+time.Second {
				t.Errorf("keyExchangeDeadline is %v away, want about %v", gotDeadline, tc.want)
			}
		})
	}
}

// TestCallerDeadlineStillWinsWhenTighter keeps hand-window from extending a
// deadline the caller set.
func TestCallerDeadlineStillWinsWhenTighter(t *testing.T) {
	c := &Client{prof: &profile.Profile{HandWindowSec: 300}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if got := time.Until(c.keyExchangeDeadline(ctx)); got > 6*time.Second {
		t.Errorf("keyExchangeDeadline is %v away; the caller's 5s deadline should have won", got)
	}
}
