// SPDX-License-Identifier: LGPL-2.1-or-later

// The ephemeral PKI each matrix server is given. Generated per run and thrown
// away with the container.

package testenv

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net"
	"strings"
	"sync"
	"time"
)

// Ephemeral PKI
// ---------------------------------------------------------------------------

// matrixKeyBits is the RSA modulus size for the throwaway matrix PKI. RSA
// rather than an elliptic curve because that is what deployed profiles use,
// and 2048 because these keys live for the duration of one test.
const matrixKeyBits = 2048

// matrixCertValidity is how long the throwaway certificates are valid. They are
// regenerated per run, so this only has to outlast a test.
const matrixCertValidity = 24 * time.Hour

// nsCertTypeOID is the legacy Netscape certificate-type extension,
// 2.16.840.1.113730.1.1. OpenVPN's --ns-cert-type reads it and nothing else
// does; it has been deprecated since 2.4 and is still accepted by all three
// pinned builds.
var nsCertTypeOID = asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 1, 1}

// nsCertTypeServerDER is the extension's value for a server certificate: a DER
// BIT STRING (tag 0x03, two content bytes) with six unused bits and the single
// byte 0x40, which is the SSL-server bit.
//
// OpenSSL caches the first content byte as X509->ex_nscert, and OpenVPN's
// verify_nsCertType tests it against NS_SSL_SERVER == 0x40. Writing the DER out
// by hand rather than through a BIT STRING helper keeps the one byte that has
// to be right visible at the point it is decided.
var nsCertTypeServerDER = []byte{0x03, 0x02, 0x06, 0x40}

// newMatrixPKI generates a fresh CA, server certificate and client certificate,
// and optionally an OpenVPN static key. The three RSA keys are generated
// concurrently, which keeps the whole thing well inside the start budget.
//
// It takes the entry rather than a pair of flags because the certificates are
// part of what an axis selects: a CertCheckNSCertType entry needs a server
// certificate carrying the Netscape certificate-type extension, and every other
// entry needs one without it. Issued unconditionally, the extension would prove
// nothing — a client that never looks at it and one that finds it present
// behave identically.
func newMatrixPKI(e MatrixEntry) (MatrixPKI, error) {
	withStaticKey := e.Wrap.UsesStaticKey()
	var (
		pki  MatrixPKI
		keys [3]*rsa.PrivateKey
		errs [3]error
		wg   sync.WaitGroup
	)
	for i := range keys {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			keys[i], errs[i] = rsa.GenerateKey(rand.Reader, matrixKeyBits)
		}(i)
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			return pki, err
		}
	}
	caKey, serverKey, clientKey := keys[0], keys[1], keys[2]

	now := time.Now().Add(-time.Hour)
	notAfter := now.Add(matrixCertValidity)

	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: MatrixCACN},
		NotBefore:             now,
		NotAfter:              notAfter,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return pki, err
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return pki, err
	}

	// remote-cert-tls server checks the serverAuth EKU plus the
	// digitalSignature/keyEncipherment key usages, so both must be present.
	serverTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: MatrixServerCN},
		NotBefore:    now,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"matrix-server", "localhost"},
		// ClientProfile dials the container by address — 127.0.0.1, or ::1 for
		// an AFInet6 entry — never by name. Without a matching IP SAN Go's
		// verifier rejects the certificate and every matrix run fails at
		// StageTLS for a reason unrelated to the axis under test.
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	if e.CertCheck == CertCheckNSCertType {
		serverTmpl.ExtraExtensions = []pkix.Extension{
			{Id: nsCertTypeOID, Value: nsCertTypeServerDER},
		}
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTmpl, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		return pki, err
	}

	clientTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: MatrixClientCN},
		NotBefore:    now,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientDER, err := x509.CreateCertificate(rand.Reader, clientTmpl, caCert, &clientKey.PublicKey, caKey)
	if err != nil {
		return pki, err
	}

	pki = MatrixPKI{
		CACertPEM:     pemBlock("CERTIFICATE", caDER),
		ServerCertPEM: pemBlock("CERTIFICATE", serverDER),
		ServerKeyPEM:  pemBlock("PRIVATE KEY", mustPKCS8(serverKey)),
		ClientCertPEM: pemBlock("CERTIFICATE", clientDER),
		ClientKeyPEM:  pemBlock("PRIVATE KEY", mustPKCS8(clientKey)),
	}
	if withStaticKey {
		key, err := newOpenVPNStaticKey()
		if err != nil {
			return pki, err
		}
		pki.StaticKey = key
	}
	return pki, nil
}

// mustPKCS8 marshals an RSA key to PKCS#8 DER. The only documented failure mode
// of MarshalPKCS8PrivateKey is an unsupported key type, which cannot happen for
// a *rsa.PrivateKey.
func mustPKCS8(k *rsa.PrivateKey) []byte {
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		panic("testenv: marshal RSA key: " + err.Error())
	}
	return der
}

// pemBlock encodes DER bytes as a PEM block.
func pemBlock(typ string, der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}))
}

// openvpnStaticKeyBytes is the size of an OpenVPN static key (2048 bits).
const openvpnStaticKeyBytes = 256

// newOpenVPNStaticKey generates an OpenVPN "Static key V1" file, the shared
// secret used by both tls-auth and tls-crypt. The format is 256 random bytes
// rendered as 16 lines of 32 hex characters between the tag lines.
func newOpenVPNStaticKey() (string, error) {
	raw := make([]byte, openvpnStaticKeyBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	h := hex.EncodeToString(raw)

	var b strings.Builder
	b.WriteString("#\n# 2048 bit OpenVPN static key\n#\n")
	b.WriteString("-----BEGIN OpenVPN Static key V1-----\n")
	for i := 0; i < len(h); i += 32 {
		b.WriteString(h[i : i+32])
		b.WriteByte('\n')
	}
	b.WriteString("-----END OpenVPN Static key V1-----\n")
	return b.String(), nil
}
