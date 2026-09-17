// SPDX-License-Identifier: LGPL-2.1-or-later

//go:build mockserver

// Fixtures shared by every test that drives testenv/mockserver as a subprocess.
// Each takes *testing.T and fails the test itself rather than returning an
// error the caller has to remember to check.

package e2e

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// buildMockServer compiles the mock server into a temp dir and returns its path.
func buildMockServer(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "mock-server")
	cmd := exec.Command("go", "build", "-o", bin, "./testenv/mockserver")
	cmd.Dir = moduleRoot(t)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("build mock server: %v", err)
	}
	return bin
}

// moduleRoot walks up from the working directory to the directory holding go.mod.
func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
}

// splitAddr splits a host:port the mock server reported.
func splitAddr(t *testing.T, addr string) (string, int) {
	t.Helper()
	i := strings.LastIndex(addr, ":")
	if i < 0 {
		t.Fatalf("address %q has no port", addr)
	}
	port, err := strconv.Atoi(addr[i+1:])
	if err != nil {
		t.Fatalf("address %q: %v", addr, err)
	}
	return addr[:i], port
}

// selfSignedClientPair returns a client certificate and key in PEM form. The
// mock server asks for a client certificate but does not verify it
// (tls.RequestClientCert), so a self-signed pair is enough: what it is for is
// profile.AuthFlow, where <cert> plus <key> and no auth-user-pass is
// FlowCertAuth.
func selfSignedClientPair(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate client key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "mock-client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create client certificate: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal client key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}
