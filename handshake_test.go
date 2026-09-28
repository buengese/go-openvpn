// SPDX-License-Identifier: LGPL-2.1-or-later

// The control channel's handshake: the TLS session the client opens over it,
// and the reliable sessions that carry the packets.
//
// Nothing here reaches a server. What the handshake decides before the first
// byte and what it leaves behind afterwards are both observable without one.

package vpn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/buengese/go-openvpn/diag"
	"github.com/buengese/go-openvpn/internal/reliable"
	"github.com/buengese/go-openvpn/internal/tlsverify"
	"github.com/buengese/go-openvpn/profile"
)

// ---- the client's own half of certificate verification ---------------------
// The two ways a profile's CA does or does not reach the trust store, and the
// line the client prints about the certificate it accepted. The verifier's own
// behaviour is tested in internal/tlsverify, where it is implemented.

// TestNoUsableCAIsAConfigErrorBeforeAnySocket pins that the attempt is refused
// at StageParse with ClassConfig, in every preflight mode, and that nothing is
// dialled: the endpoint is a loopback port with nothing listening, so a dial
// would be observable as a ClassNetwork failure at StageDial.
func TestNoUsableCAIsAConfigErrorBeforeAnySocket(t *testing.T) {
	for _, mode := range []diag.PreflightMode{diag.PreflightFailFast, diag.PreflightAdvisory} {
		t.Run(mode.String(), func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("reserve a port: %v", err)
			}
			addr := ln.Addr().(*net.TCPAddr)
			// Close it again: nothing is listening, so any dial is visible as
			// a failure at StageDial rather than as a hang.
			if err := ln.Close(); err != nil {
				t.Fatalf("release the port: %v", err)
			}

			c := New(&profile.Profile{
				Remote: "127.0.0.1", Port: addr.Port, Proto: profile.ProtoTCP,
				Cert: []byte("x"), Key: []byte("y"),
			})
			c.PreflightMode = mode

			derr := c.Preflight()
			if derr == nil {
				t.Fatal("a profile with no CA passed the preflight")
			}
			var de *diag.Error
			if !errors.As(derr, &de) {
				t.Fatalf("error is not a *diag.Error: %v", derr)
			}
			if de.Class != diag.ClassConfig {
				t.Errorf("class = %s, want %s", de.Class, diag.ClassConfig)
			}
			if de.Stage != diag.StageParse {
				t.Errorf("stage = %s, want %s", de.Stage, diag.StageParse)
			}
			// And it wraps the exported sentinel. A consumer writes
			// errors.Is(err, vpn.ErrNoUsableCA), and this is the only thing in
			// the repo pinning root's alias to tlsverify's own variable.
			if !errors.Is(derr, ErrNoUsableCA) {
				t.Errorf("preflight error does not wrap ErrNoUsableCA: %v", derr)
			}

			rep := c.Report()
			for _, s := range rep.Stages {
				if s.Stage >= diag.StageDial {
					t.Errorf("attempt reached %s; a profile with no CA must not open a socket", s.Stage)
				}
			}
		})
	}
}

// TestFileReferencedCAPassesThePreflight covers a profile whose CA is in a file
// beside it rather than inline: it must reach the network, and the way to show
// that without a server is that the preflight passes. The same bytes parsed by
// ParseString must still be refused with ErrNoProfileDir.
func TestFileReferencedCAPassesThePreflight(t *testing.T) {
	pki := newTestPKI(t, "Example VPN CA")

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ca.example.crt"), pki.caPEM, 0o600); err != nil {
		t.Fatalf("write CA: %v", err)
	}
	// The shape, minus the endpoint: a file-referenced CA, credentials asked
	// for by name only, and a CBC cipher with an explicit digest.
	body := "client\ndev tun\nproto udp\nremote 127.0.0.1 1194\nnobind\n" +
		"ca ca.example.crt\nauth-user-pass\nverb 3\nauth SHA256\ncipher AES-256-CBC\n"
	cfgPath := filepath.Join(dir, "fileref-ca.ovpn")
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatalf("write profile: %v", err)
	}

	p, err := profile.ParsePath(cfgPath)
	if err != nil {
		t.Fatalf("ParsePath: %v", err)
	}
	if len(p.CA) == 0 {
		t.Fatal("the profile parsed with an empty CA")
	}

	// The trust store builds, which is what ErrNoUsableCA reports on.
	if _, _, err := tlsverify.BuildConfig(p); err != nil {
		t.Fatalf("tlsverify.BuildConfig on a file-referenced CA: %v", err)
	}

	for _, mode := range []diag.PreflightMode{diag.PreflightFailFast, diag.PreflightAdvisory} {
		t.Run(mode.String(), func(t *testing.T) {
			c := New(p)
			c.PreflightMode = mode
			// The profile asks for credentials, and the preflight checks
			// that a caller can supply them. That is not what is under
			// test here.
			c.CredentialsFn = stubCredentials("user", "pass")
			if err := c.Preflight(); err != nil {
				t.Fatalf("preflight refused a profile whose CA is in a file: %v", err)
			}
		})
	}

	// The bytes alone are still refused, and the refusal says which call to
	// make instead.
	if _, err := profile.ParseString(body); !errors.Is(err, profile.ErrNoProfileDir) {
		t.Errorf("ParseString on the same profile = %v, want ErrNoProfileDir", err)
	}
}

// ---- what the client says about the certificate it accepted ----------------

// TestLogRemoteCertificateAtVerb4 pins the certificate line the client prints
// at --verb 4, field by field. It is stock openvpn's own rendering: the serial
// in upper hex, the validity in OpenSSL's "Jan  1 00:00:00 2026 GMT" form, the
// SANs prefixed by type.
func TestLogRemoteCertificateAtVerb4(t *testing.T) {
	c := New(&profile.Profile{Verb: 4})
	var message string
	c.EventFn = func(e Event) { message = e.Message }
	// A real certificate, not a struct literal: subject and issuer are rendered
	// from the DER the peer sent, in the order it carries them, so a literal
	// with empty RawSubject/RawIssuer would exercise only the fallback.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Country: []string{"US"}, Organization: []string{"Example"}, CommonName: "Example CA"},
		NotBefore:             time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA: %v", err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "vpn.example.com"},
		NotBefore:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		DNSNames:     []string{"vpn.example.com"},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create leaf: %v", err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}

	c.logRemoteCertificate(tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{leaf},
	}, "vpn.example.com", true)

	for _, want := range []string{
		// The issuer reads in certificate order, which is how OpenSSL prints
		// it and what a verify-x509-name subject has to match.
		"verified", "subject=CN=vpn.example.com", "issuer=C=US, O=Example, CN=Example CA", "serial=2A",
		"notBefore=Jan  1 00:00:00 2026 GMT", "DNS:vpn.example.com", "sha256 Fingerprint=",
	} {
		if !strings.Contains(message, want) {
			t.Errorf("certificate log %q does not contain %q", message, want)
		}
	}
}

// ---- the control sessions the handshake leaves behind ---------------------

// queuedSession builds a control session holding one unacknowledged control
// packet, in the state a renegotiation leaves behind.
func queuedSession(t *testing.T, keyID uint8, finished bool) *controlSession {
	t.Helper()
	sess := &controlSession{keyID: keyID, sendQueue: reliable.NewSendQueue(0)}
	if _, err := sess.sendQueue.Enqueue([]byte("control")); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	sess.finished.Store(finished)
	return sess
}

// TestSpentSessionsAreNotRetransmitted pins that a renegotiation which has
// ended stops putting packets on the wire: its session stays in the map to
// absorb a late inbound packet — that is what finished means — but its own
// unacknowledged packets belong to an epoch that is over. key_id 0 is the
// connection's own control channel, is never finished, and must keep going.
func TestSpentSessionsAreNotRetransmitted(t *testing.T) {
	primary := queuedSession(t, 0, false)
	live := queuedSession(t, 3, false)
	spent := queuedSession(t, 4, true)
	sessions := map[uint8]*controlSession{0: primary, 3: live, 4: spent}

	// An entry is due only once its initial retransmit deadline has passed.
	time.Sleep(reliable.RetransmitTimeout + 100*time.Millisecond)

	due := dueRetransmits(sessions)

	if len(due) != 2 {
		t.Fatalf("got %d packets due for retransmit, want 2 (the primary and the live session)", len(due))
	}
	if spent.sendQueue.Len() != 1 {
		t.Errorf("the spent session's queue holds %d entries, want 1: it should be left alone, not drained",
			spent.sendQueue.Len())
	}
	for _, sess := range []*controlSession{primary, live} {
		if sess.sendQueue.Len() != 1 {
			t.Errorf("key_id %d: queue holds %d entries, want 1 (retransmit does not dequeue)",
				sess.keyID, sess.sendQueue.Len())
		}
	}
}
