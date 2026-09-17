// SPDX-License-Identifier: LGPL-2.1-or-later

// Fixtures used by more than one test file in this package.
//
// The rule is "used by two or more files", not "looks reusable". What must NOT
// move here is anything whose correctness depends on the test reading it: a
// fixture that hides a precondition is how a suite ends up asserting against
// its own scaffolding.
package vpn

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/openlawsvpn/go-openlawsvpn/diag"
	"github.com/openlawsvpn/go-openlawsvpn/profile"
)

// testPKI is a throwaway certificate authority, of which this package uses only
// the PEM encoding.
type testPKI struct {
	caPEM []byte
}

var (
	sharedTestCAOnce sync.Once
	sharedTestCA     *testPKI
)

// newTestPKI generates a self-signed CA.
func newTestPKI(t *testing.T, commonName string) *testPKI {
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
	return &testPKI{caPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// testCAPEM returns a PEM CA for tests whose subject is not certificate
// verification but whose profile must still carry one, because a profile with
// no CA is a diag.ClassConfig error before any socket is opened.
func testCAPEM(t *testing.T) []byte {
	t.Helper()
	sharedTestCAOnce.Do(func() { sharedTestCA = newTestPKI(t, "Shared Test CA") })
	return sharedTestCA.caPEM
}

// credentialTestProfile returns a parsed profile in the requested shape. It
// goes through the parser because AuthFlow reads the directives the parser
// recorded: an assembled profile has none.
func credentialTestProfile(t *testing.T, directives string, certAuth bool) *profile.Profile {
	t.Helper()
	p, err := profile.ParseString("client\nremote vpn.example.com 443\nproto tcp-client\n" + directives)
	if err != nil {
		t.Fatalf("ParseString: %v", err)
	}
	p.CA = testCAPEM(t)
	if certAuth {
		// AuthFlow only asks whether both are non-empty.
		p.Cert = []byte("-----BEGIN CERTIFICATE-----\nnot-parsed-here\n-----END CERTIFICATE-----\n")
		p.Key = []byte("-----BEGIN PRIVATE KEY-----\nnot-parsed-here\n-----END PRIVATE KEY-----\n")
	}
	return p
}

// stubCredentials returns a CredentialsFn that answers at once.
//
// auth-user-pass makes a profile FlowUserPass, and a FlowUserPass profile with
// no CredentialsFn is refused at StageParse in every preflight mode.
func stubCredentials(username, password string) func(context.Context) (Credentials, error) {
	return func(context.Context) (Credentials, error) {
		return Credentials{Username: username, Password: password}, nil
	}
}

// closedTCPPort returns a loopback port with nothing listening on it, by
// binding one and immediately releasing it.
func closedTCPPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if err := ln.Close(); err != nil {
		t.Fatalf("close listener: %v", err)
	}
	return port
}

// equalStrings compares two string slices, treating nil and empty as equal.
func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// stageNames renders a report's stage timeline as names, for readable failures.
func stageNames(r *diag.SessionReport) []string {
	var out []string
	for _, s := range r.Stages {
		out = append(out, s.Stage.String())
	}
	return out
}

// quietClient is a Client that can be driven by a test without a connection:
// emit falls back to os.Stderr when EventFn is nil, and nothing here needs a
// recorder it does not create for itself.
func quietClient() *Client { return &Client{EventFn: func(Event) {}} }
