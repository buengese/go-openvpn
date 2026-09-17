// SPDX-License-Identifier: LGPL-2.1-or-later

package tlsverify

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openlawsvpn/go-openlawsvpn/profile"
)

// The tests in this file cover the SSLKEYLOGFILE branch of BuildConfig, which
// has two properties that pull against each other: the key log has to keep
// receiving key material — it is a debugging facility people use to read a
// capture in Wireshark — and BuildConfig has to survive being called thousands
// of times in one process without spending a file descriptor each time, since
// it runs once per connect attempt and once per rekey.
//
// The CA fixture at the bottom is the package's, not this file's.

// keylogProfile points SSLKEYLOGFILE at path and returns a profile BuildConfig
// will accept.
func keylogProfile(t *testing.T, path string, ca []byte) *profile.Profile {
	t.Helper()
	t.Setenv("SSLKEYLOGFILE", path)
	return &profile.Profile{Remote: "vpn.example.com", Port: 1194, CA: ca}
}

// openFDCount counts this process's open file descriptors. /proc/self/fd is
// Linux-only; elsewhere the leak is real but not observable this cheaply, so
// the test says so rather than passing silently.
func openFDCount(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skipf("cannot count open descriptors on this platform: %v", err)
	}
	return len(entries)
}

// TestBuildConfigKeyLogDoesNotLeakDescriptors pins that BuildConfig does not
// open SSLKEYLOGFILE once per call. The configs are retained for the whole test
// on purpose: a discarded *os.File is closed by its finalizer, which would hide
// the leak here while doing nothing for the real caller, whose tls.Config lives
// as long as the tunnel does.
func TestBuildConfigKeyLogDoesNotLeakDescriptors(t *testing.T) {
	prof := keylogProfile(t, filepath.Join(t.TempDir(), "keys.log"), testCAPEM(t))

	// The first call is allowed to open the file; the leak is what the calls
	// after it cost.
	if _, _, err := BuildConfig(prof); err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	before := openFDCount(t)

	const calls = 64
	configs := make([]*tls.Config, 0, calls)
	for range calls {
		cfg, _, err := BuildConfig(prof)
		if err != nil {
			t.Fatalf("BuildConfig: %v", err)
		}
		if cfg.KeyLogWriter == nil {
			t.Fatal("SSLKEYLOGFILE is set but no key log writer was installed")
		}
		configs = append(configs, cfg)
	}
	after := openFDCount(t)
	runtime.KeepAlive(configs)

	// Two descriptors of slack: the runtime opens and closes its own while a
	// test runs, and the count is a snapshot rather than a ledger.
	if grew := after - before; grew > 2 {
		t.Fatalf("%d calls to BuildConfig leaked %d file descriptors (%d -> %d); SSLKEYLOGFILE must be opened once, not per call",
			calls, grew, before, after)
	}
}

// TestBuildConfigKeyLogReceivesKeyMaterial pins that a key log costing no
// descriptors still records keys. The handshake is pinned to TLS 1.2 because
// that is what the control channel negotiates, and because its key log line is
// the one Wireshark needs to decrypt such a capture (CLIENT_RANDOM); a 1.3
// handshake writes traffic secrets under different labels.
func TestBuildConfigKeyLogReceivesKeyMaterial(t *testing.T) {
	pki := newTestCA(t, "tlsverify test CA")
	path := filepath.Join(t.TempDir(), "keys.log")
	prof := keylogProfile(t, path, pki.caPEM)

	cfg, _, err := BuildConfig(prof)
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	if cfg.KeyLogWriter == nil {
		t.Fatal("SSLKEYLOGFILE is set but no key log writer was installed")
	}

	clientConn, serverConn := net.Pipe()
	deadline := time.Now().Add(20 * time.Second)
	clientConn.SetDeadline(deadline) //nolint:errcheck
	serverConn.SetDeadline(deadline) //nolint:errcheck
	// The raw pipe ends are closed rather than the tls.Conns: the key log line
	// is written during the handshake, and two peers exchanging close_notify
	// over a synchronous pipe just wait out crypto/tls's close timeout.
	defer clientConn.Close() //nolint:errcheck
	defer serverConn.Close() //nolint:errcheck

	serverErr := make(chan error, 1)
	go func() {
		server := tls.Server(serverConn, &tls.Config{
			Certificates: []tls.Certificate{pki.serverCert(t)},
			MaxVersion:   tls.VersionTLS12,
		})
		serverErr <- server.Handshake()
	}()

	client := tls.Client(clientConn, cfg)
	if err := client.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("server handshake: %v", err)
	}
	if got := client.ConnectionState().Version; got != tls.VersionTLS12 {
		t.Fatalf("negotiated TLS version 0x%04x, want TLS 1.2", got)
	}

	logged, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read key log: %v", err)
	}
	if !strings.Contains(string(logged), "CLIENT_RANDOM ") {
		t.Fatalf("key log holds no CLIENT_RANDOM line after a TLS 1.2 handshake; got %q", logged)
	}
}

// TestBuildConfigKeyLogAppendsAcrossCalls covers the sharing itself: two configs
// built from one profile — a connect attempt and the rekey after it — must both
// reach the same file, and the second must not truncate the first's lines.
func TestBuildConfigKeyLogAppendsAcrossCalls(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys.log")
	prof := keylogProfile(t, path, testCAPEM(t))

	first, _, err := BuildConfig(prof)
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	second, _, err := BuildConfig(prof)
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	if first.KeyLogWriter == nil || second.KeyLogWriter == nil {
		t.Fatal("SSLKEYLOGFILE is set but no key log writer was installed")
	}
	if _, err := first.KeyLogWriter.Write([]byte("CLIENT_RANDOM first\n")); err != nil {
		t.Fatalf("write through the first config: %v", err)
	}
	if _, err := second.KeyLogWriter.Write([]byte("CLIENT_RANDOM second\n")); err != nil {
		t.Fatalf("write through the second config: %v", err)
	}

	logged, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read key log: %v", err)
	}
	for _, want := range []string{"CLIENT_RANDOM first", "CLIENT_RANDOM second"} {
		if !strings.Contains(string(logged), want) {
			t.Fatalf("key log is missing %q; got %q", want, logged)
		}
	}
}

// TestBuildConfigKeyLogConcurrentWrites drives the shared handle the way the
// client drives it: a rekey builds its own config and hands it to crypto/tls
// while the primary session's config is still live. The assertion is that every
// line arrives whole — O_APPEND plus one write syscall per line is what keeps
// them from interleaving.
func TestBuildConfigKeyLogConcurrentWrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys.log")
	prof := keylogProfile(t, path, testCAPEM(t))

	const writers, lines = 8, 32
	var wg sync.WaitGroup
	for w := range writers {
		cfg, _, err := BuildConfig(prof)
		if err != nil {
			t.Fatalf("BuildConfig: %v", err)
		}
		if cfg.KeyLogWriter == nil {
			t.Fatal("SSLKEYLOGFILE is set but no key log writer was installed")
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range lines {
				fmt.Fprintf(cfg.KeyLogWriter, "CLIENT_RANDOM %02d %04d\n", w, i)
			}
		}()
	}
	wg.Wait()

	logged, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read key log: %v", err)
	}
	got := strings.Split(strings.TrimSuffix(string(logged), "\n"), "\n")
	if len(got) != writers*lines {
		t.Fatalf("key log holds %d lines, want %d", len(got), writers*lines)
	}
	for _, line := range got {
		if len(strings.Fields(line)) != 3 {
			t.Fatalf("torn key log line %q", line)
		}
	}
}

// testCA is a throwaway certificate authority for the profiles these tests
// build, and the server leaf the key-material test hands to tls.Server.
type testCA struct {
	key   *ecdsa.PrivateKey
	cert  *x509.Certificate
	caPEM []byte
}

// newTestCA generates a self-signed CA. The common name is a parameter because
// two CAs in one test have to be distinguishable in a failure message.
func newTestCA(t *testing.T, commonName string) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}
	return &testCA{
		key:   key,
		cert:  cert,
		caPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
	}
}

// serverCert issues a leaf the CA signs, for a tls.Server the verifier will
// accept. It carries no DNS name, because the verifier does not look at one.
func (ca *testCA) serverCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "vpn.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// issueServer issues a server leaf. dnsNames may be empty, which is the case
// that matters: a certificate naming nothing the client dialled.
func (ca *testCA) issueServer(t *testing.T, commonName string, eku []x509.ExtKeyUsage, dnsNames []string) [][]byte {
	t.Helper()
	return ca.issueLeaf(t, &x509.Certificate{
		Subject:     pkix.Name{CommonName: commonName},
		ExtKeyUsage: eku,
		DNSNames:    dnsNames,
	})
}

// issueLeaf issues a server leaf from a caller-supplied template, filling in the
// serial, validity and key usage every leaf needs. It exists for the subject and
// ns-cert-type checks, which issueServer has no parameter for.
func (ca *testCA) issueLeaf(t *testing.T, tmpl *x509.Certificate) [][]byte {
	t.Helper()
	tmpl.KeyUsage = x509.KeyUsageDigitalSignature
	return ca.issueLeafVerbatim(t, tmpl)
}

// issueLeafVerbatim issues a leaf without filling in a key usage, so that a
// template asking for none produces a certificate with no key usage extension at
// all — crypto/x509 emits the extension only for a non-zero KeyUsage. That shape
// is a case in its own right, because the SSL-server purpose check waves it
// through and remote-cert-tls server does not.
func (ca *testCA) issueLeafVerbatim(t *testing.T, tmpl *x509.Certificate) [][]byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	tmpl.SerialNumber = big.NewInt(2)
	tmpl.NotBefore = time.Now().Add(-time.Hour)
	tmpl.NotAfter = time.Now().Add(24 * time.Hour)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}
	return [][]byte{der}
}

// testCAPEM returns a CA for tests whose subject is not certificate
// verification but whose profile must still carry one, because a profile
// without a CA is ErrNoUsableCA before BuildConfig reaches the key log.
func testCAPEM(t *testing.T) []byte {
	t.Helper()
	sharedCAOnce.Do(func() { sharedCA = newTestCA(t, "tlsverify test CA") })
	return sharedCA.caPEM
}

var (
	sharedCAOnce sync.Once
	sharedCA     *testCA
)
