// SPDX-License-Identifier: LGPL-2.1-or-later

// The MatrixEntry type and the curated entry set.

package testenv

import (
	"fmt"
	"sort"
)

// Matrix entries
// ---------------------------------------------------------------------------

// MatrixEntry is one point in the server matrix. It is the single source for
// both the server configuration and the client .ovpn profile, so the two
// cannot drift apart.
type MatrixEntry struct {
	// Name is a stable identifier, usable both as a Go subtest name and as a
	// lookup key for Entry. It never changes for a given combination.
	Name string

	// Version selects which pinned server image runs the entry.
	Version ServerVersion
	// Cipher is the data-channel cipher.
	Cipher Cipher
	// Digest is the HMAC digest.
	Digest Digest
	// Wrap is the control-channel wrapping mode.
	Wrap Wrap
	// Proto is the transport protocol.
	Proto Proto
	// Compression is the compression framing mode.
	Compression Compression
	// Reneg is the renegotiation policy.
	Reneg Reneg
	// Family is the transport address family.
	Family AddressFamily
	// Auth is how the client authenticates: certificate only, or certificate
	// plus a username and password.
	Auth Auth
	// CertCheck is the additional server-certificate check the client
	// profile asks for.
	CertCheck CertCheck
	// CASource is whether the client profile inlines its CA or names a file.
	CASource CASource
	// Remotes is how many remote lines the client profile carries, and
	// whether the first one answers.
	Remotes RemoteSet

	// DataV1 marks an entry whose purpose is to exercise the P_DATA_V1 data
	// channel (no peer-id prefix).
	//
	// There is no server configuration for it: 2.4, 2.5 and 2.6 all decide the
	// format from the client's IV_PROTO, so the flag is an instruction to the
	// client under test and the rig side is the ordinary server. The
	// instruction is "advertise no IV_PROTO extensions" rather than "omit the
	// DATA_V2 bit", because 2.4 and 2.5 push a peer-id whenever
	// sscanf("IV_PROTO=%d") >= 2 (push.c:prepare_push_reply) where 2.6 tests
	// the bit (multi.c:multi_client_connect_late_setup via extract_iv_proto).
	// vpn.WithholdDataV2 is that value, and a test that does not apply it for
	// an entry with this flag set measures nothing.
	DataV1 bool

	// Unimplemented, when non-empty, explains why the rig cannot bring this
	// entry up. Enumerating tests must skip such entries with this message
	// rather than fail. StartMatrix returns ErrUnimplemented for them.
	Unimplemented string

	// ClientUnsupported, when non-empty, explains why *this repository's*
	// client cannot drive the entry. The rig can: the server starts, the
	// generated profile is correct, and the reference client connects to it.
	//
	// It is not Unimplemented, and the two must never be conflated.
	// StartMatrix refuses an Unimplemented entry, so marking one that way to
	// spare our client would also deny the reference client the chance to
	// prove it. A test driving our client should skip on a non-empty value and
	// say so; one driving the rig or the reference client must ignore it.
	ClientUnsupported string

	// ReferenceRejects, when non-empty, names the ClassifyReferenceLog rule
	// the reference client is expected to report against this entry instead
	// of connecting.
	//
	// Unimplemented and ClientUnsupported both say something could not be
	// tried; this says the entry was tried and the design was to be refused.
	// An entry whose point is a check that fails is only sound if the refusal
	// is the intended one, so the rule is asserted rather than the weaker "did
	// not connect", which a server that never started would also satisfy.
	ReferenceRejects string
}

// SkipReason returns a non-empty explanation when the entry cannot be started,
// and the empty string when it can. It covers both the static Unimplemented
// field and combinations that are invalid for the selected server version.
func (e MatrixEntry) SkipReason() string {
	if e.Unimplemented != "" {
		return e.Unimplemented
	}
	if _, ok := ImageFor(e.Version); !ok {
		return fmt.Sprintf("no matrix image is pinned for OpenVPN %s", e.Version)
	}
	if e.Compression.UsesLZO() && e.Version == V26 {
		return "comp-lzo is refused by OpenVPN 2.6 servers unless compression is re-enabled; " +
			"the matrix exercises comp-lzo on 2.4 and 2.5 instead"
	}
	return ""
}

// String returns the entry's name, so an entry can be logged directly.
func (e MatrixEntry) String() string { return e.Name }

// ---------------------------------------------------------------------------
// The curated set
// ---------------------------------------------------------------------------

// matrix is the curated entry set. The full cartesian product of the axes is
// several thousand combinations and is not worth running; this set covers every
// value of every axis at least once, including the ones no deployment in the
// field offers: tls-crypt, reneg-sec 30, server-initiated renegotiation, IPv6
// and P_DATA_V1.
var matrix = []MatrixEntry{
	// --- one canonical entry per server version -------------------------
	{
		// The load-bearing entry: 2.4 has no EKM, so this is the classic PRF
		// path, which is what a server older than 2.6 requires.
		Name:    "v24-cbc256-sha512-tlsauth-kd1-udp",
		Version: V24, Cipher: CipherAES256CBC, Digest: DigestSHA512,
		Wrap: WrapTLSAuthKD1, Proto: ProtoUDP,
	},
	{
		Name:    "v25-cbc256-sha256-tlsauth-kd1-udp",
		Version: V25, Cipher: CipherAES256CBC, Digest: DigestSHA256,
		Wrap: WrapTLSAuthKD1, Proto: ProtoUDP,
	},
	{
		Name:    "v26-gcm256-sha256-tlscrypt-udp",
		Version: V26, Cipher: CipherAES256GCM, Digest: DigestSHA256,
		Wrap: WrapTLSCrypt, Proto: ProtoUDP,
	},

	// --- cipher and digest coverage -------------------------------------
	{
		Name:    "v24-cbc128-sha1-plain-udp",
		Version: V24, Cipher: CipherAES128CBC, Digest: DigestSHA1,
		Wrap: WrapPlain, Proto: ProtoUDP,
	},
	{
		Name:    "v24-gcm256-sha256-tlsauth-kd0-udp",
		Version: V24, Cipher: CipherAES256GCM, Digest: DigestSHA256,
		Wrap: WrapTLSAuthKD0, Proto: ProtoUDP,
	},

	// --- one-axis isolates for the key derivation and CBC breadth -------
	//
	// The entries above vary two or three axes between neighbours, which is
	// fine for coverage and useless for attribution. These five form a chain
	// in which every step moves exactly one field, anchored on
	// v26-gcm256-sha256-plain-udp. All are plain and cert-only, so no
	// control-channel wrap and no credentials sit in front of the axis under
	// test.
	{
		// The classic-derivation isolate: 2.4 has no keying-material exporter,
		// plain so no wrap is in the way, GCM and cert-only so nothing else
		// can intervene. Its single difference from
		// v26-gcm256-sha256-plain-udp is the key derivation.
		Name:    "v24-gcm256-sha256-plain-udp",
		Version: V24, Cipher: CipherAES256GCM, Digest: DigestSHA256,
		Wrap: WrapPlain, Proto: ProtoUDP,
	},
	{
		// The same isolate one step along, onto the CBC path: one axis — the
		// cipher — from the entry above, which separates "the derivation is
		// wrong" from "the CBC slot mapping is wrong". It is also one axis
		// (DataV1) from v24-cbc256-sha256-plain-udp-datav1.
		Name:    "v24-cbc256-sha256-plain-udp",
		Version: V24, Cipher: CipherAES256CBC, Digest: DigestSHA256,
		Wrap: WrapPlain, Proto: ProtoUDP,
	},
	{
		// CBC breadth on the digest axis: one step (the digest) from the entry
		// above, and the one combination in the table that a cert-only, plain
		// deployment can confirm in the field.
		Name:    "v24-cbc256-sha512-plain-udp",
		Version: V24, Cipher: CipherAES256CBC, Digest: DigestSHA512,
		Wrap: WrapPlain, Proto: ProtoUDP,
	},
	{
		// The 2.5 anchor: one axis (the version) from both
		// v26-gcm256-sha256-plain-udp and v24-gcm256-sha256-plain-udp, so a
		// 2.4-only failure can be told from one shared by every pre-2.6
		// server. It also gives the AEAD key-length entry below something one
		// axis away to be compared against.
		Name:    "v25-gcm256-sha256-plain-udp",
		Version: V25, Cipher: CipherAES256GCM, Digest: DigestSHA256,
		Wrap: WrapPlain, Proto: ProtoUDP,
	},
	{
		// Cipher breadth on the AEAD side: one step (the key length) from the
		// 2.5 anchor above, and the only 128-bit AEAD key in the table.
		Name:    "v25-gcm128-sha256-plain-udp",
		Version: V25, Cipher: CipherAES128GCM, Digest: DigestSHA256,
		Wrap: WrapPlain, Proto: ProtoUDP,
	},

	// --- transport ------------------------------------------------------
	{
		// The data-path vehicle on TCP: 2.6 offers the keying-material
		// exporter, GCM and an unwrapped control channel, so no tls-auth,
		// tls-crypt or classic PRF sits in front of the data path.
		Name:    "v26-gcm256-sha512-plain-tcp",
		Version: V26, Cipher: CipherAES256GCM, Digest: DigestSHA512,
		Wrap: WrapPlain, Proto: ProtoTCP,
	},
	{
		// Its UDP twin, and the second data-path vehicle the netstack backend
		// is exercised against, with the transport and the control-channel
		// digest varied so that a framing failure shows up as one transport
		// passing and the other not.
		Name:    "v26-gcm256-sha256-plain-udp",
		Version: V26, Cipher: CipherAES256GCM, Digest: DigestSHA256,
		Wrap: WrapPlain, Proto: ProtoUDP,
	},
	{
		Name:    "v25-cbc256-sha256-tlsauth-kd1-tcp",
		Version: V25, Cipher: CipherAES256CBC, Digest: DigestSHA256,
		Wrap: WrapTLSAuthKD1, Proto: ProtoTCP,
	},
	{
		Name:    "v24-cbc256-sha256-tlscrypt-tcp",
		Version: V24, Cipher: CipherAES256CBC, Digest: DigestSHA256,
		Wrap: WrapTLSCrypt, Proto: ProtoTCP,
	},

	// --- compression framing --------------------------------------------
	{
		Name:    "v24-cbc256-sha1-complzo-udp",
		Version: V24, Cipher: CipherAES256CBC, Digest: DigestSHA1,
		Wrap: WrapTLSAuthKD1, Proto: ProtoUDP, Compression: CompLZO,
	},
	{
		Name:    "v25-cbc128-sha256-compstub-udp",
		Version: V25, Cipher: CipherAES128CBC, Digest: DigestSHA256,
		Wrap: WrapTLSAuthKD1, Proto: ProtoUDP, Compression: CompStub,
	},
	{
		Name:    "v26-gcm256-sha256-compstub-udp",
		Version: V26, Cipher: CipherAES256GCM, Digest: DigestSHA256,
		Wrap: WrapTLSCrypt, Proto: ProtoUDP, Compression: CompStub,
	},
	{
		// The compression question's other half, and the only entry that puts
		// a genuinely compressed payload on the wire: one axis — the
		// compression mode — from v24-cbc256-sha1-complzo-udp, which separates
		// a wrong LZO framing byte from an inability to cope with a payload
		// that really is compressed.
		//
		// `comp-lzo yes` on both ends turns adaptive compression off, so the
		// server compresses everything that comes out smaller rather than
		// deciding per packet. LZO still emits the uncompressed marker when
		// compression would not shrink a payload, so a test that needs a
		// compressed packet has to send something compressible. 2.4 is not a
		// free choice — 2.5 and 2.6 decline to compress on send whatever the
		// payload — see the CompLZOForced doc comment.
		Name:    "v24-cbc256-sha1-complzoyes-udp",
		Version: V24, Cipher: CipherAES256CBC, Digest: DigestSHA1,
		Wrap: WrapTLSAuthKD1, Proto: ProtoUDP, Compression: CompLZOForced,
	},

	// --- renegotiation (untestable against a live deployment) ------------
	{
		// The rekey vehicle with no wrap in the way: the classic-derivation
		// isolate with reneg-sec 30 and nothing else changed, so a failure
		// against it is a rekey failure rather than a wrap failure. The other
		// two reneg entries both wrap their control channel.
		Name:    "v24-gcm256-sha256-plain-udp-reneg30",
		Version: V24, Cipher: CipherAES256GCM, Digest: DigestSHA256,
		Wrap: WrapPlain, Proto: ProtoUDP, Reneg: RenegSec30,
	},
	{
		Name:    "v24-cbc256-sha256-tlsauth-kd1-udp-reneg30",
		Version: V24, Cipher: CipherAES256CBC, Digest: DigestSHA256,
		Wrap: WrapTLSAuthKD1, Proto: ProtoUDP, Reneg: RenegSec30,
	},
	{
		Name:    "v26-gcm256-sha256-tlscrypt-udp-reneg-server",
		Version: V26, Cipher: CipherAES256GCM, Digest: DigestSHA256,
		Wrap: WrapTLSCrypt, Proto: ProtoUDP, Reneg: RenegServerInitiated,
	},

	// --- address family --------------------------------------------------
	{
		Name:    "v26-gcm256-sha256-tlscrypt-udp6",
		Version: V26, Cipher: CipherAES256GCM, Digest: DigestSHA256,
		Wrap: WrapTLSCrypt, Proto: ProtoUDP, Family: AFInet6,
	},
	{
		Name:    "v26-gcm256-sha256-tlscrypt-udp-dual",
		Version: V26, Cipher: CipherAES256GCM, Digest: DigestSHA256,
		Wrap: WrapTLSCrypt, Proto: ProtoUDP, Family: AFDual,
	},

	// --- P_DATA_V1 (client-side lever; see MatrixEntry.DataV1) -----------
	{
		Name:    "v24-cbc256-sha256-plain-udp-datav1",
		Version: V24, Cipher: CipherAES256CBC, Digest: DigestSHA256,
		Wrap: WrapPlain, Proto: ProtoUDP, DataV1: true,
		// Old deployments push no peer-id at all, so a client that cannot
		// speak P_DATA_V1 completes the handshake, enters StageData and moves
		// nothing. internal/datachannel implements both formats and selects
		// from whether a peer-id was pushed; a test must still set
		// vpn.WithholdDataV2 — see the DataV1 field.
	},
	{
		// The same isolate with reneg-sec 30, so a key epoch rotates inside a
		// test's lifetime while P_DATA_V1 is on the wire; the two features
		// meet nowhere else. A rekey rebuilds the data channel from the
		// connection's negotiated parameters, so a wire format re-derived per
		// epoch instead of per connection carries traffic for thirty seconds
		// and then stops. One axis (Reneg) from
		// v24-cbc256-sha256-plain-udp-datav1.
		Name:    "v24-cbc256-sha256-plain-udp-datav1-reneg30",
		Version: V24, Cipher: CipherAES256CBC, Digest: DigestSHA256,
		Wrap: WrapPlain, Proto: ProtoUDP, DataV1: true, Reneg: RenegSec30,
	},

	// --- authentication --------------------------------------------------
	{
		// The credentials isolate, and the reason the Auth axis exists:
		// exactly one field — Auth — separates it from
		// v24-gcm256-sha256-plain-udp, so a failure here is a credentials
		// failure and can be nothing else. Plain on purpose, because behind a
		// wrapped control channel "the password was wrong" and "no reply ever
		// came" are the same silence.
		Name:    "v24-gcm256-sha256-plain-udp-userpass",
		Version: V24, Cipher: CipherAES256GCM, Digest: DigestSHA256,
		Wrap: WrapPlain, Proto: ProtoUDP, Auth: AuthUserPass,
	},
	{
		// The shape a deployment that wraps its control channel actually
		// ships: it requires credentials too, so in the field the wrap and the
		// credentials can only be confirmed jointly, and the matrix needs one
		// entry of that shape even though the combination isolates nothing
		// new. It is still one axis (Auth) from
		// v24-cbc256-sha512-tlsauth-kd1-udp, so running the pair says whether
		// the credentials moved or the wrap did.
		Name:    "v24-cbc256-sha512-tlsauth-kd1-udp-userpass",
		Version: V24, Cipher: CipherAES256CBC, Digest: DigestSHA512,
		Wrap: WrapTLSAuthKD1, Proto: ProtoUDP, Auth: AuthUserPass,
	},

	// --- certificate verification ----------------------------------------
	//
	// All four hang off v24-gcm256-sha256-plain-udp, so nothing sits in front
	// of the check under test. 2.4 rather than 2.6 for the same reason and one
	// more: `ns-cert-type` has been deprecated since 2.4, so the build most
	// likely to still honour it is the one to ask.
	{
		// The first certificate-check isolate: `verify-x509-name <CN> name`
		// naming the common name the matrix server certificate carries. One
		// axis — the certificate check — from v24-gcm256-sha256-plain-udp.
		//
		// It has to connect, because its value is as the control for the entry
		// below: without a matching pair, "the client refused" and "the client
		// cannot reach this server at all" are the same observation.
		Name:    "v24-gcm256-sha256-plain-udp-x509name",
		Version: V24, Cipher: CipherAES256GCM, Digest: DigestSHA256,
		Wrap: WrapPlain, Proto: ProtoUDP, CertCheck: CertCheckX509NameMatch,
	},
	{
		// One axis from the entry above: the same server, the same
		// certificate, and a common name the certificate does not carry. The
		// reference client must refuse it, and that refusal is the entry's
		// result rather than a defect, which is what ReferenceRejects records.
		// The pair is the only thing that can tell a client performing the
		// check from one ignoring it, which passes both.
		Name:    "v24-gcm256-sha256-plain-udp-x509name-bad",
		Version: V24, Cipher: CipherAES256GCM, Digest: DigestSHA256,
		Wrap: WrapPlain, Proto: ProtoUDP, CertCheck: CertCheckX509NameMismatch,
		ReferenceRejects: "cert-verify-failed",
	},
	{
		// `ns-cert-type server`, which nothing in the field asks for, so this
		// entry is the only vehicle the capability will ever have. The server
		// certificate is issued with the legacy Netscape certificate-type
		// extension when — and only when — an entry selects this check, so the
		// check has something to test. One axis from
		// v24-gcm256-sha256-plain-udp.
		Name:    "v24-gcm256-sha256-plain-udp-nscerttype",
		Version: V24, Cipher: CipherAES256GCM, Digest: DigestSHA256,
		Wrap: WrapPlain, Proto: ProtoUDP, CertCheck: CertCheckNSCertType,
	},
	{
		// Certificate verification's other half: the CA named by path rather
		// than inlined. One axis — the CA source — from
		// v24-gcm256-sha256-plain-udp. Nothing changes on the wire; what
		// changes is whether a client can read the profile at all.
		Name:    "v24-gcm256-sha256-plain-udp-cafile",
		Version: V24, Cipher: CipherAES256GCM, Digest: DigestSHA256,
		Wrap: WrapPlain, Proto: ProtoUDP, CASource: CAFile,
		ClientUnsupported: "a ca file reference is refused at StageParse, so the " +
			"profile never reaches the network",
	},

	// --- multiple remotes and failover -----------------------------------
	//
	// TCP, and deliberately: the isolate below needs a first remote that is
	// unambiguously dead, and on UDP nothing is — a refused datagram and a
	// server dropping an unauthenticated packet are the same silence, which is
	// what makes the oracle's no-peer-reply rule ambiguous. A refused TCP
	// connection is ClassNetwork at StageDial and can be nothing else.
	{
		// The 2.4 TCP anchor the pair below needs, and worth having on its
		// own: one axis (proto) from v24-gcm256-sha256-plain-udp, at the
		// version that forces the classic derivation. The only other plain-TCP
		// entry is 2.6 on SHA512, three axes from anything at 2.4.
		Name:    "v24-gcm256-sha256-plain-tcp",
		Version: V24, Cipher: CipherAES256GCM, Digest: DigestSHA256,
		Wrap: WrapPlain, Proto: ProtoTCP,
	},
	{
		// The failover isolate: two remotes, the first of them a port nothing
		// is listening on. One axis — the remote set — from the anchor above.
		// A client that dials only the first remote fails; one that fails over
		// connects on the second and can say why the first did not answer.
		//
		// The dead port is not a fixed number: it is probed beside the live
		// one at start and then never bound, so the entry does not come to
		// depend on what happens to be free on the machine running it.
		Name:    "v24-gcm256-sha256-plain-tcp-multiremote",
		Version: V24, Cipher: CipherAES256GCM, Digest: DigestSHA256,
		Wrap: WrapPlain, Proto: ProtoTCP, Remotes: RemoteDeadFirst,
		// The client dials the remotes in order and connects on the second.
	},
}

// entryIndex is the Name -> MatrixEntry lookup, built once at init.
var entryIndex = func() map[string]MatrixEntry {
	m := make(map[string]MatrixEntry, len(matrix))
	for _, e := range matrix {
		if _, dup := m[e.Name]; dup {
			panic("testenv: duplicate matrix entry name " + e.Name)
		}
		m[e.Name] = e
	}
	return m
}()

// Matrix returns the curated matrix entry set. The returned slice is a copy;
// mutating it does not affect the package-level table.
func Matrix() []MatrixEntry {
	out := make([]MatrixEntry, len(matrix))
	copy(out, matrix)
	return out
}

// MatrixFor returns the curated entries for a single server version.
func MatrixFor(v ServerVersion) []MatrixEntry {
	var out []MatrixEntry
	for _, e := range matrix {
		if e.Version == v {
			out = append(out, e)
		}
	}
	return out
}

// Entry looks up a matrix entry by name. The boolean reports whether it exists.
func Entry(name string) (MatrixEntry, bool) {
	e, ok := entryIndex[name]
	return e, ok
}

// EntryNames returns every matrix entry name in sorted order.
func EntryNames() []string {
	out := make([]string, 0, len(entryIndex))
	for name := range entryIndex {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// ---------------------------------------------------------------------------
