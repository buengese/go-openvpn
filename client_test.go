// SPDX-License-Identifier: LGPL-2.1-or-later

// The Client's own lifetime: what it answers before a connection, what ending
// one releases, and the order the two paths that end it may arrive in.
//
// Nothing here connects; a client is driven into the state a connection would
// have left it in and then ended. It is an internal test because most of that
// state is unexported — the exported accessors are covered in api_test.go.

package vpn

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openlawsvpn/go-openlawsvpn/internal/framing"

	"github.com/openlawsvpn/go-openlawsvpn/internal/prf"
	"github.com/openlawsvpn/go-openlawsvpn/profile"
	"github.com/openlawsvpn/go-openlawsvpn/routing"
)

func makeTestProfile() *profile.Profile {
	p, err := profile.ParseString("remote vpn.example.com 443\nproto tcp-client\n")
	if err != nil {
		panic(err)
	}
	return p
}

// TestDisconnectIdempotent verifies that calling Disconnect multiple times is safe.
func TestDisconnectIdempotent(t *testing.T) {
	c := New(makeTestProfile())
	if err := c.Disconnect(); err != nil {
		t.Fatalf("first Disconnect: %v", err)
	}
	if err := c.Disconnect(); err != nil {
		t.Fatalf("second Disconnect: %v", err)
	}
}

// TestDoneChannelClosedAfterDisconnect verifies that Done() returns a channel
// that is closed after Disconnect+Wait complete, so a caller can select on it
// rather than polling the state.
func TestDoneChannelClosedAfterDisconnect(t *testing.T) {
	c := New(makeTestProfile())
	c.Disconnect()        //nolint:errcheck
	c.WaitForDisconnect() //nolint:errcheck
	select {
	case <-c.Done():
		// expected
	default:
		t.Fatal("Done() channel not closed after Disconnect+Wait")
	}
}

// TestPhase1IPBeforeConnect verifies Phase1IP returns "" before any connection.
func TestPhase1IPBeforeConnect(t *testing.T) {
	c := New(makeTestProfile())
	if ip := c.Phase1IP(); ip != "" {
		t.Errorf("Phase1IP before connect = %q, want empty", ip)
	}
}

// TestDoneIsClosedOnceWhateverOrderTeardownAndFailureArriveIn drives the two
// paths that end a client concurrently. They are not alternatives — a connect
// attempt failing while teardown is in stateDisconnecting reaches doneCh too —
// and an unguarded close panics from a goroutine the caller cannot recover.
func TestDoneIsClosedOnceWhateverOrderTeardownAndFailureArriveIn(t *testing.T) {
	for range 500 {
		c := New(credentialTestProfile(t, "", true))
		c.mu.Lock()
		c.state = stateConnecting // what Connect sets before it dials
		c.mu.Unlock()

		var start, done sync.WaitGroup
		start.Add(1)
		done.Add(2)
		go func() {
			defer done.Done()
			start.Wait()
			_ = c.teardown(false)
		}()
		go func() {
			defer done.Done()
			start.Wait()
			c.setDisconnected(errors.New("dial failed"))
		}()
		start.Done()
		done.Wait()

		<-c.Done() // both paths must leave the channel closed, not one of them
	}
}

// TestDoneChannelIsOnlyTouchedUnderTheLock pins that every reader and writer of
// doneCh goes through the lock: reset installs a fresh doneCh for the next
// attempt, so an unsynchronised read races that swap.
//
// The assertion is the race detector's. It deliberately does not wait on the
// channel it gets back — after a reset that channel belongs to the next
// attempt and stays open until that one ends.
func TestDoneChannelIsOnlyTouchedUnderTheLock(t *testing.T) {
	for range 200 {
		c := New(credentialTestProfile(t, "", true))
		c.mu.Lock()
		c.state = stateConnecting
		c.mu.Unlock()

		var wg sync.WaitGroup
		wg.Add(3)
		go func() {
			defer wg.Done()
			c.setDisconnected(errors.New("attempt failed"))
		}()
		go func() {
			defer wg.Done()
			c.reset() // the reconnect loop, starting the next attempt
		}()
		go func() {
			defer wg.Done()
			_ = c.Done() // a supervisor asking which channel to watch
		}()
		wg.Wait()
	}
}

// TestCloseDoneIsIdempotent is the property the two paths above rely on, on its
// own: whichever of them arrives second must find the channel already closed
// and do nothing.
func TestCloseDoneIsIdempotent(t *testing.T) {
	c := New(credentialTestProfile(t, "", true))
	c.closeDone()
	c.closeDone()
	c.closeDone()

	select {
	case <-c.Done():
	default:
		t.Fatal("Done() is still open after closeDone")
	}
}

// TestDataChannelSurvivesATeardownUnderAnActiveSender stands in for the inbound
// relay, which feeds dataCh and is the one goroutine teardown does not wait
// for: it is started inside tlsHandshake as a bare `go func()`, so it is not in
// c.wg. Closing dataCh under it is a send on a closed channel, which panics a
// process that was only disconnecting.
func TestDataChannelSurvivesATeardownUnderAnActiveSender(t *testing.T) {
	for range 200 {
		c := New(credentialTestProfile(t, "", true))
		c.mu.Lock()
		c.state = stateConnecting
		c.dataCh = make(chan []byte, 256)
		c.mu.Unlock()

		// The relay asks once and keeps what it got: a channel handed out by
		// dataChannel has to stay safe to send on for as long as the sender
		// lives, because nothing tells the sender when the attempt ended.
		ch := c.dataChannel()
		if ch == nil {
			t.Fatal("dataChannel returned nil for an attempt that has one")
		}

		stop := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { // the relay
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				select {
				case ch <- []byte{0x09}:
				default:
				}
			}
		}()
		go func() { // wireToTun, so the buffer never wedges full and the
			defer wg.Done() // send above stays live across the teardown
			for {
				select {
				case <-stop:
					return
				case <-ch:
				}
			}
		}()

		c.finish(nil, false)
		close(stop)
		wg.Wait()
	}
}

// TestTLSSecretsAreOnlyTouchedUnderTheLock covers the capture holding the TLS
// master secret. Wipe zeroes the 48 bytes in place, so a teardown landing
// between the handshake and deriveDataKeys can bring the tunnel up on a key
// block built from zeroes.
//
// The assertion is the race detector's, plus the once-only property below.
func TestTLSSecretsAreOnlyTouchedUnderTheLock(t *testing.T) {
	for range 200 {
		c := New(credentialTestProfile(t, "", true))

		var mu sync.Mutex
		var taken []*prf.Capture
		var wg sync.WaitGroup
		wg.Add(4)
		go func() {
			defer wg.Done()
			c.installTLSSecrets(prf.NewCapture(&tls.Config{}))
		}()
		for range 3 { // deriveDataKeys and two teardown paths, all racing
			go func() {
				defer wg.Done()
				got := c.takeTLSSecrets()
				mu.Lock()
				if got != nil {
					taken = append(taken, got)
				}
				mu.Unlock()
				got.Wipe()
			}()
		}
		wg.Wait()

		// Either order of install and take is fine; what must hold is that the
		// one capture reached exactly one caller. Two owners means one of them
		// wipes it while the other is still deriving a key block from it.
		if last := c.takeTLSSecrets(); last != nil {
			taken = append(taken, last)
			last.Wipe()
		}
		if len(taken) != 1 {
			t.Fatalf("one capture was installed and %d callers were handed it; "+
				"it must reach exactly one owner", len(taken))
		}
	}
}

// TestAFailedAttemptDoesNotKeepTheMasterSecret covers the attempts that never
// reach deriveDataKeys. teardown returns early for a client setDisconnected
// already moved, so its goroutine never runs cleanup, and a caller with
// nothing left to disconnect must not keep the 48-byte master secret.
//
// No Disconnect here on purpose: ending the attempt has to be enough.
func TestAFailedAttemptDoesNotKeepTheMasterSecret(t *testing.T) {
	c := New(credentialTestProfile(t, "", true))
	c.mu.Lock()
	c.state = stateConnecting
	c.mu.Unlock()
	c.installTLSSecrets(prf.NewCapture(&tls.Config{}))

	// An attempt that got past the handshake and was then refused at auth or
	// push, which is where a sweep's attempts mostly stop.
	c.setDisconnected(errors.New("authentication rejected"))

	if got := c.takeTLSSecrets(); got != nil {
		t.Error("the TLS capture survived a failed attempt: the master secret " +
			"sits in memory until this Client runs another handshake, or for good")
	}
}

// TestDisconnectAfterAFailedAttemptRunsNoCleanup states the mechanism the test
// above depends on, so that a later change to teardown cannot quietly move the
// wipe back somewhere it will not run.
func TestDisconnectAfterAFailedAttemptRunsNoCleanup(t *testing.T) {
	c := New(credentialTestProfile(t, "", true))
	c.mu.Lock()
	c.state = stateConnecting
	c.mu.Unlock()
	c.setDisconnected(errors.New("dial failed"))

	// Whatever Disconnect does from here, it is not a teardown: the state it
	// would have to move out of is the one setDisconnected already left.
	if err := c.Disconnect(); err != nil {
		t.Fatalf("Disconnect after a failed attempt: %v", err)
	}
	c.mu.Lock()
	st := c.state
	c.mu.Unlock()
	if st != stateDisconnected {
		t.Fatalf("state = %v, want disconnected", st)
	}
	// And it returns immediately rather than waiting on a cleanup goroutine.
	select {
	case <-c.Done():
	default:
		t.Error("Done() is open after a failed attempt and a Disconnect")
	}
}

// countingDevice is a device.Device that records how often it was closed.
// Everything else on the interface is unreachable here: nothing reads or writes
// a device that is only being torn down.
type countingDevice struct{ closes atomic.Int64 }

func (d *countingDevice) ReadPacket(ctx context.Context, _ []byte) (int, error) {
	<-ctx.Done()
	return 0, ctx.Err()
}
func (d *countingDevice) WritePacket([]byte) error { return nil }
func (d *countingDevice) MTU() int                 { return 1500 }
func (d *countingDevice) Name() string             { return "counting0" }
func (d *countingDevice) Close() error             { d.closes.Add(1); return nil }

// TestFinishReleasesTheDeviceExactlyOnce pins the other half of what ending a
// client releases. Closing the device is the whole of the tunnel's teardown —
// the backend unwinds addresses, routes and DNS behind it. Exactly once, not
// at least once: a second close means two owners.
func TestFinishReleasesTheDeviceExactlyOnce(t *testing.T) {
	for _, tc := range []struct {
		name   string
		finish func(c *Client)
	}{
		{"a deliberate teardown", func(c *Client) {
			_ = c.Disconnect()
			_ = c.WaitForDisconnect()
		}},
		{"an attempt that failed", func(c *Client) {
			c.setDisconnected(errors.New("push rejected"))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dev := &countingDevice{}
			c := New(credentialTestProfile(t, "", true))
			c.mu.Lock()
			c.state = stateTunnelUp
			c.dev = dev
			c.mu.Unlock()

			tc.finish(c)

			if got := dev.closes.Load(); got != 1 {
				t.Errorf("device closed %d times, want exactly 1", got)
			}
			if held := c.TunnelDevice(); held != nil {
				t.Error("the client still hands out a device it has closed")
			}
		})
	}
}

// TestOnlyADeliberateTeardownAnnouncesIdle pins the one thing finish does
// differently depending on how it was reached. A caller that asked for the
// teardown hears the client went idle; a failed attempt does not, because
// Connect has already reported StateError and a StateIdle behind it would
// change what the D-Bus service and the GTK front end display.
func TestOnlyADeliberateTeardownAnnouncesIdle(t *testing.T) {
	for _, tc := range []struct {
		name      string
		end       func(c *Client)
		wantIdle  bool
		wantState ClientState
	}{
		{"Disconnect", func(c *Client) {
			_ = c.Disconnect()
			_ = c.WaitForDisconnect()
		}, true, StateIdle},
		{"a failed attempt", func(c *Client) {
			c.setDisconnected(errors.New("auth rejected"))
		}, false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var mu sync.Mutex
			var states []ClientState
			c := New(credentialTestProfile(t, "", true))
			c.EventFn = func(e Event) {
				if e.Type != EventStateChanged {
					return
				}
				mu.Lock()
				states = append(states, e.State)
				mu.Unlock()
			}
			c.mu.Lock()
			c.state = stateTunnelUp
			c.mu.Unlock()

			tc.end(c)

			mu.Lock()
			defer mu.Unlock()
			var sawIdle bool
			for _, s := range states {
				if s == StateIdle {
					sawIdle = true
				}
			}
			if sawIdle != tc.wantIdle {
				t.Errorf("StateIdle emitted = %t, want %t (states: %v)", sawIdle, tc.wantIdle, states)
			}
		})
	}
}

// TestPhase1IPDoesNotRaceTheConnectPath pins the lock around c.rawConn and
// c.backendIP, which runExchange writes after the dial and Phase1IP reads.
//
// The listener accepts and then says nothing, which is what holds the window
// open: a closed port returns at StageDial before either write. The handshake
// against a silent peer then blocks, so the attempt is abandoned rather than
// waited for, and EventFn is a sink so the orphan cannot log after the test
// has finished.
func TestPhase1IPDoesNotRaceTheConnectPath(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			defer conn.Close() //nolint:revive // held open for the test's lifetime, on purpose
		}
	}()

	p, err := profile.ParseString(fmt.Sprintf(
		"client\nproto tcp-client\nremote 127.0.0.1 %d\nauth-user-pass\n",
		ln.Addr().(*net.TCPAddr).Port))
	if err != nil {
		t.Fatalf("ParseString: %v", err)
	}
	p.CA = testCAPEM(t)

	c := New(p)
	c.EventFn = func(Event) {}
	c.CredentialsFn = func(context.Context) (Credentials, error) {
		return Credentials{Username: "u", Password: "p"}, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = c.Connect(ctx) }()

	// Long enough to cover the dial and the two assignments, short enough that
	// the suite does not notice. The detector reports on the first overlap, so
	// this does not need to be lucky twice.
	deadline := time.Now().Add(150 * time.Millisecond)
	for time.Now().Before(deadline) {
		_ = c.Phase1IP()
	}
}

// ---- the lifetime of a cached credential -----------------------------------

// credentialLifecycleClient is a connected-looking client holding one of every
// piece of state a disconnect has to decide about. The values are canaries,
// unlike anything the protocol produces, so finding one afterwards is
// unambiguous.
func credentialLifecycleClient(t *testing.T) *Client {
	t.Helper()
	c := New(credentialTestProfile(t, "", false))
	c.cachedSAMLToken = "CANARY_SAML_ASSERTION"
	c.cachedSAMLExpiry = time.Now().Add(time.Minute)
	c.cachedStateID = "CANARY_STATE"
	c.cachedBackendIP = "192.0.2.1"
	c.samlSession = &SAMLChallenge{StateID: "CANARY_STATE", URL: "https://idp.example/canary"}
	c.pushOpts = &routing.PushOptions{AuthToken: "CANARY_AUTH_TOKEN"}
	return c
}

// TestDisconnectKeepsCredentialsOnlyForAReconnect pins both directions of the
// one decision teardown makes about cached credentials: an explicit Disconnect
// drops the SAML triple and the auth-token, a transient one keeps them so that
// a dropped link does not put a browser in front of the user.
func TestDisconnectKeepsCredentialsOnlyForAReconnect(t *testing.T) {
	t.Run("an explicit disconnect clears them", func(t *testing.T) {
		c := credentialLifecycleClient(t)
		if err := c.Disconnect(); err != nil {
			t.Fatal(err)
		}
		if err := c.WaitForDisconnect(); err != nil {
			t.Fatal(err)
		}

		c.mu.Lock()
		defer c.mu.Unlock()
		if c.cachedSAMLToken != "" || !c.cachedSAMLExpiry.IsZero() ||
			c.cachedStateID != "" || c.cachedBackendIP != "" || c.samlSession != nil {
			t.Fatal("explicit disconnect retained SAML credentials")
		}
		if c.pushOpts.AuthToken != "" {
			t.Fatal("explicit disconnect retained server auth-token")
		}
	})

	t.Run("a transient disconnect preserves them", func(t *testing.T) {
		c := credentialLifecycleClient(t)
		if err := c.disconnect(true); err != nil {
			t.Fatal(err)
		}
		if err := c.WaitForDisconnect(); err != nil {
			t.Fatal(err)
		}

		c.mu.Lock()
		defer c.mu.Unlock()
		if c.cachedSAMLToken == "" || c.cachedStateID == "" || c.cachedBackendIP == "" {
			t.Fatal("transient disconnect cleared credentials required by Reconnect")
		}
	})
}

// TestSetupFailureClearsCredentials covers the path that is neither: a
// connection that never came up at all. Nothing is going to reconnect from it,
// so the assertion must not be left behind in the Client.
func TestSetupFailureClearsCredentials(t *testing.T) {
	c := credentialLifecycleClient(t)
	c.setDisconnected(assertionError("setup failed"))

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cachedSAMLToken != "" || c.cachedStateID != "" || c.samlSession != nil {
		t.Fatal("connection-setup failure retained SAML credentials")
	}
}

type assertionError string

func (e assertionError) Error() string { return string(e) }

// TestTeardownEmptiesTheCapture pins that a session's TLS master secret does
// not outlive the session. It drives the teardown rather than asserting that
// deriveDataKeys defers a wipe, because an attempt failing between the
// handshake and the key block has a populated capture and reaches only
// cleanup. The assertion is behavioural: a wiped capture refuses to export.
func TestTeardownEmptiesTheCapture(t *testing.T) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	capture := prf.NewCapture(cfg)
	capture.Write([]byte("CLIENT_RANDOM " + //nolint:errcheck
		"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff " +
		"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
		"202122232425262728292a2b2c2d2e2f\n"))

	c := New(credentialTestProfile(t, "", true))
	c.installTLSSecrets(capture)
	// The teardown a caller reaches through Disconnect, run directly because
	// there is no session here to tear down — only the capture a failed
	// attempt would have left.
	c.finish(nil, false)

	c.mu.Lock()
	held := c.tlsSecrets
	c.mu.Unlock()
	if held != nil {
		t.Error("the client still holds a capture after teardown")
	}
	if !capture.Wiped() {
		t.Error("teardown released the capture without emptying it; the master " +
			"secret outlives the session it came from")
	}
}

// TestRelaySessionIDsSurviveTheNextAttempt pins that the inbound relay reads
// clientSID and serverSID through the lock. No WaitGroup covers the relay, so
// it outlives its attempt while the next one zeroes both fields through
// rewindConnectionLocked or reset. It drives the two functions directly rather
// than forcing a real failover.
func TestRelaySessionIDsSurviveTheNextAttempt(t *testing.T) {
	c := New(nil)
	c.clientSID = [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	c.serverSID = [8]byte{8, 7, 6, 5, 4, 3, 2, 1}

	// What the relay captures once, at launch, and keeps.
	clientSID, serverSID := c.sessionIDs()
	pkt := framing.BuildAck(serverSID, clientSID, 0, []uint32{1})

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for range 500 {
			c.mu.Lock()
			c.rewindConnectionLocked()
			c.mu.Unlock()
		}
	}()
	go func() {
		defer wg.Done()
		for range 500 {
			// The relay's own judgement, on the values it captured. It must
			// keep answering for the connection it belongs to no matter what
			// the next attempt has done to the Client.
			if !controlPacketIsOurs(pkt, clientSID, serverSID) {
				t.Errorf("the relay stopped recognising its own session's packet")
				return
			}
		}
	}()
	wg.Wait()
}
