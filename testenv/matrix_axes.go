// SPDX-License-Identifier: LGPL-2.1-or-later

// The axes a matrix entry varies, and the credentials the Auth axis needs.
// One value of one axis is what separates two entries in the ladder.

package testenv

import (
	"fmt"
	"strings"
)

// ---------------------------------------------------------------------------
// Axes
// ---------------------------------------------------------------------------

// ServerVersion names an OpenVPN server minor series covered by the matrix.
type ServerVersion string

// The three server series in the matrix.
const (
	// V24 is OpenVPN 2.4 — no TLS keying-material exporter, so the classic
	// PRF path is the only one available.
	V24 ServerVersion = "2.4"
	// V25 is OpenVPN 2.5.
	V25 ServerVersion = "2.5"
	// V26 is OpenVPN 2.6.
	V26 ServerVersion = "2.6"
)

// ServerVersions returns every server series in the matrix, in ascending order.
func ServerVersions() []ServerVersion {
	return []ServerVersion{V24, V25, V26}
}

// PinnedVersion returns the exact upstream OpenVPN release built for a series.
// The boolean is false for a series the matrix does not cover.
func PinnedVersion(v ServerVersion) (string, bool) {
	switch v {
	case V24:
		return OpenVPN24Version, true
	case V25:
		return OpenVPN25Version, true
	case V26:
		return OpenVPN26Version, true
	default:
		return "", false
	}
}

// ImageFor returns the local image tag for a server series, for example
// "go-openvpn-test/openvpn-server:2.4.12". The tag always carries the exact
// upstream version; there is deliberately no "latest" tag. The boolean is false
// for a series the matrix does not cover.
func ImageFor(v ServerVersion) (string, bool) {
	ver, ok := PinnedVersion(v)
	if !ok {
		return "", false
	}
	return MatrixImageRepo + ":" + ver, true
}

// Cipher is a data-channel cipher.
type Cipher string

// Data-channel ciphers in the matrix. AES-128-CBC and AES-256-CBC exercise the
// two key lengths of the MAC-then-encrypt path; AES-128-GCM and AES-256-GCM do
// the same for AEAD.
const (
	// CipherAES128CBC is AES-128-CBC.
	CipherAES128CBC Cipher = "AES-128-CBC"
	// CipherAES256CBC is AES-256-CBC.
	CipherAES256CBC Cipher = "AES-256-CBC"
	// CipherAES128GCM is AES-128-GCM.
	CipherAES128GCM Cipher = "AES-128-GCM"
	// CipherAES256GCM is AES-256-GCM.
	CipherAES256GCM Cipher = "AES-256-GCM"
)

// AEAD reports whether the cipher is an AEAD mode, in which case the digest
// applies only to the control channel.
func (c Cipher) AEAD() bool { return strings.HasSuffix(string(c), "-GCM") }

// Digest is an HMAC digest, used for the data channel in CBC mode and for the
// control-channel wrapping in every mode.
type Digest string

// HMAC digests in the matrix: 20-, 32- and 64-byte outputs.
const (
	// DigestSHA1 is SHA1 (20-byte HMAC).
	DigestSHA1 Digest = "SHA1"
	// DigestSHA256 is SHA256 (32-byte HMAC).
	DigestSHA256 Digest = "SHA256"
	// DigestSHA512 is SHA512 (64-byte HMAC).
	DigestSHA512 Digest = "SHA512"
)

// Wrap is the control-channel wrapping mode. Each value changes the on-the-wire
// layout of control packets.
type Wrap int

// Control-channel wrapping modes. The KD0/KD1 suffix is the *client's*
// key-direction, matching how a .ovpn profile reads; the server is given the
// opposite direction.
const (
	// WrapPlain is an unwrapped control channel: no tls-auth, no tls-crypt.
	WrapPlain Wrap = iota
	// WrapTLSAuthKD0 is tls-auth with the client at key-direction 0 (server 1).
	WrapTLSAuthKD0
	// WrapTLSAuthKD1 is tls-auth with the client at key-direction 1 (server 0).
	// This is the conventional deployment.
	WrapTLSAuthKD1
	// WrapTLSCrypt is tls-crypt: control packets are encrypted as well as
	// authenticated.
	WrapTLSCrypt
)

// String returns a short stable token for the wrapping mode.
func (w Wrap) String() string {
	switch w {
	case WrapPlain:
		return "plain"
	case WrapTLSAuthKD0:
		return "tls-auth-kd0"
	case WrapTLSAuthKD1:
		return "tls-auth-kd1"
	case WrapTLSCrypt:
		return "tls-crypt"
	default:
		return fmt.Sprintf("Wrap(%d)", int(w))
	}
}

// UsesStaticKey reports whether the mode needs a shared static key file.
func (w Wrap) UsesStaticKey() bool { return w != WrapPlain }

// Proto is the transport protocol.
type Proto int

// Transport protocols. UDP and TCP differ in framing and in who provides
// reliability.
const (
	// ProtoUDP is UDP transport.
	ProtoUDP Proto = iota
	// ProtoTCP is TCP transport, which adds the 2-byte length prefix.
	ProtoTCP
)

// String returns "udp" or "tcp".
func (p Proto) String() string {
	switch p {
	case ProtoUDP:
		return "udp"
	case ProtoTCP:
		return "tcp"
	default:
		return fmt.Sprintf("Proto(%d)", int(p))
	}
}

// Compression is the compression framing mode.
type Compression int

// Compression modes. Even the stub modes matter: they change the framing byte
// the data channel must account for.
const (
	// CompNone disables compression framing entirely.
	CompNone Compression = iota
	// CompLZO is the legacy comp-lzo framing.
	CompLZO
	// CompStub is the "compress" stub framing (stub-v2 on 2.5 and 2.6).
	CompStub
	// CompLZOForced is `comp-lzo yes`: LZO with adaptive compression turned
	// off, so the peer compresses every payload that comes out smaller
	// instead of only the ones its heuristic judges worth trying.
	//
	// It is the only mode in the matrix that puts a genuinely compressed
	// payload on the wire — every other compression entry negotiates a framing
	// byte and sends plaintext behind it — so it is the only vehicle for the
	// branch that has to come back as ErrCompressed rather than hand a
	// compressed payload to a client with no codec linked.
	//
	// It only works on 2.4: the captures in docker/COMPRESSION-VECTORS.md
	// measured all three pinned builds, and 2.5 and 2.6 servers never compress
	// on send without `allow-compression yes`, so an entry on either connects
	// and tests nothing. TestForcedLZOIsOnAVersionThatCompresses refuses one.
	CompLZOForced
)

// String returns a short stable token for the compression mode.
func (c Compression) String() string {
	switch c {
	case CompNone:
		return "nocomp"
	case CompLZO:
		return "comp-lzo"
	case CompStub:
		return "comp-stub"
	case CompLZOForced:
		return "comp-lzo-yes"
	default:
		return fmt.Sprintf("Compression(%d)", int(c))
	}
}

// UsesLZO reports whether the mode drives OpenVPN's LZO path, which 2.6 refuses
// to enable at all unless compression is explicitly re-allowed.
func (c Compression) UsesLZO() bool { return c == CompLZO || c == CompLZOForced }

// Reneg is the renegotiation policy.
type Reneg int

// Renegotiation policies. A short reneg interval cannot be observed against a
// live deployment, which is why the matrix has to carry one.
const (
	// RenegDefault leaves both ends at the OpenVPN default (3600s).
	RenegDefault Reneg = iota
	// RenegSec30 sets reneg-sec 30 on both ends, so a rekey happens inside a
	// test's lifetime.
	RenegSec30
	// RenegServerInitiated sets reneg-sec 30 on the server and reneg-sec 0 on
	// the client, so only the server can start a rekey.
	RenegServerInitiated
)

// String returns a short stable token for the renegotiation policy.
func (r Reneg) String() string {
	switch r {
	case RenegDefault:
		return "reneg-default"
	case RenegSec30:
		return "reneg30"
	case RenegServerInitiated:
		return "reneg-server"
	default:
		return fmt.Sprintf("Reneg(%d)", int(r))
	}
}

// AddressFamily is the transport address family the server listens on.
type AddressFamily int

// Address families. The netstack IPv6 path has no vehicle in the field, so the
// matrix is the only place it can be exercised.
const (
	// AFInet listens on IPv4 only and pushes an IPv4 tunnel.
	AFInet AddressFamily = iota
	// AFInet6 listens on an IPv6 socket and additionally pushes an IPv6
	// tunnel. Only the IPv6 host address is published.
	AFInet6
	// AFDual listens on an IPv6 socket accepting v4-mapped connections and
	// pushes both an IPv4 and an IPv6 tunnel. Both host addresses are
	// published.
	AFDual
)

// String returns a short stable token for the address family.
func (a AddressFamily) String() string {
	switch a {
	case AFInet:
		return "v4"
	case AFInet6:
		return "v6"
	case AFDual:
		return "dual"
	default:
		return fmt.Sprintf("AddressFamily(%d)", int(a))
	}
}

// Auth is how the server makes the client prove who it is. It is the axis the
// `auth-user-pass` isolate turns on.
type Auth int

// Authentication methods. Both keep the client certificate: a deployment that
// asks for a username and password asks for it *in addition to* a certificate,
// never instead of one, so there is no cert-less value here.
const (
	// AuthCert is certificate-only: the client certificate is the whole
	// credential.
	AuthCert Auth = iota
	// AuthUserPass additionally demands a username and password, which the
	// server checks with an --auth-user-pass-verify hook. The directive's bare
	// form — no file argument — is what the matrix reproduces.
	AuthUserPass
)

// String returns a short stable token for the authentication method.
func (a Auth) String() string {
	switch a {
	case AuthCert:
		return "cert"
	case AuthUserPass:
		return "userpass"
	default:
		return fmt.Sprintf("Auth(%d)", int(a))
	}
}

// RequiresCredentials reports whether the method needs a username and password
// on top of the client certificate.
func (a Auth) RequiresCredentials() bool { return a == AuthUserPass }

// CertCheck is the additional check the client profile asks for on the server
// certificate, on top of the chain verification both OpenSSL and Go perform
// unprompted. It is the axis the certificate-verification isolates turn on.
//
// The two `verify-x509-name` values are one axis apart: the same server and the
// same certificate, with one profile naming the CN the server has and the other
// naming one it does not. A client that ignores the directive connects to both,
// and only the pair can say so.
type CertCheck int

// Certificate checks. All four are client-side; only CertCheckNSCertType also
// changes the server certificate, because the extension it tests has to be
// there for the check to mean anything.
const (
	// CertCheckNone asks for nothing beyond `remote-cert-tls server`, which
	// every entry carries.
	CertCheckNone CertCheck = iota
	// CertCheckX509NameMatch is `verify-x509-name <CN> name` naming the
	// server certificate's real common name. It must connect.
	CertCheckX509NameMatch
	// CertCheckX509NameMismatch is the same directive naming a common name
	// the server does not have. It must be refused, and the refusal is the
	// result: this entry exists to be failed.
	CertCheckX509NameMismatch
	// CertCheckNSCertType is `ns-cert-type server`, the legacy Netscape
	// certificate-type extension, which nothing in the field asks for — so
	// this is the only place it can be exercised at all. The server
	// certificate is issued with the extension when an entry selects this
	// value and without it otherwise.
	CertCheckNSCertType
)

// String returns a short stable token for the certificate check.
func (c CertCheck) String() string {
	switch c {
	case CertCheckNone:
		return "no-cert-check"
	case CertCheckX509NameMatch:
		return "x509-name"
	case CertCheckX509NameMismatch:
		return "x509-name-bad"
	case CertCheckNSCertType:
		return "ns-cert-type"
	default:
		return fmt.Sprintf("CertCheck(%d)", int(c))
	}
}

// CASource is where the client profile's certificate authority comes from: an
// inline block, or a file beside the profile. It is an axis because it changes
// what a client has to be able to do rather than what goes on the wire, and a
// profile naming its CA by path has no inline block to fall back on.
type CASource int

// Where the CA comes from.
const (
	// CAInline is an inline <ca> block, which is what every other matrix
	// entry ships.
	CAInline CASource = iota
	// CAFile is a `ca <path>` reference to a file beside the profile. The
	// path is supplied per run, because it differs between a profile written
	// into a directory on this host and one unpacked into a container.
	CAFile
)

// String returns a short stable token for the CA source.
func (s CASource) String() string {
	switch s {
	case CAInline:
		return "ca-inline"
	case CAFile:
		return "ca-file"
	default:
		return fmt.Sprintf("CASource(%d)", int(s))
	}
}

// RemoteSet is how many `remote` lines the client profile carries, and whether
// the first of them is alive. It is the axis the failover isolate turns on.
type RemoteSet int

// Remote sets.
const (
	// RemoteSingle is one remote, the running server. Every entry that does
	// not say otherwise is this.
	RemoteSingle RemoteSet = iota
	// RemoteDeadFirst is two remotes: a port nothing is listening on,
	// followed by the running server. A client that tries only the first
	// never connects; one that fails over connects on the second and can say
	// why the first did not answer.
	RemoteDeadFirst
)

// String returns a short stable token for the remote set.
func (r RemoteSet) String() string {
	switch r {
	case RemoteSingle:
		return "one-remote"
	case RemoteDeadFirst:
		return "dead-first-remote"
	default:
		return fmt.Sprintf("RemoteSet(%d)", int(r))
	}
}

// ---------------------------------------------------------------------------
// Credentials for the Auth axis
//
// These two constants are test fixtures and are in the repository on purpose.
// They authenticate nothing: the only thing that has ever accepted them is a
// shell script this package generates, running inside a container that lives
// for the length of one test, in front of a certificate authority generated
// seconds earlier and discarded when the process exits.
//
// Credential material is kept out of this tree because real material opens a
// real account, which a string unlocking a throwaway container does not. The
// converse does apply: do not put these anywhere that implies they are real,
// not in a profile, not in a SessionReport, not in an example a reader could
// mistake for a working account.
// ---------------------------------------------------------------------------

const (
	// MatrixUsername is the username every AuthUserPass entry expects.
	MatrixUsername = "matrix-user"
	// MatrixPassword is the password every AuthUserPass entry expects.
	MatrixPassword = "matrix-not-a-secret"
)

// ---------------------------------------------------------------------------
