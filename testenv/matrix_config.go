// SPDX-License-Identifier: LGPL-2.1-or-later

// Turning a matrix entry into the two configuration files it describes: the
// server's and the client's, generated from the same entry so they cannot
// drift.

package testenv

import (
	"fmt"
	"strings"
)

// Configuration generation
// ---------------------------------------------------------------------------

// Fixed paths inside the container. The entrypoint unpacks the bundle here.
const (
	serverConfDir  = "/etc/openvpn"
	serverCAPath   = serverConfDir + "/ca.crt"
	serverCertPath = serverConfDir + "/server.crt"
	serverKeyPath  = serverConfDir + "/server.key"
	serverTAPath   = serverConfDir + "/ta.key"

	// The two files the Auth axis adds to a bundle: the server's
	// --auth-user-pass-verify hook, and the credentials file a containerised
	// stock OpenVPN client reads. Both are plain base names, which is what a
	// bundle entry and an OracleOptions.Files key both have to be.
	authVerifyFileName = "auth-verify.sh"

	serverAuthVerifyPath  = serverConfDir + "/" + authVerifyFileName
	clientCredentialsPath = serverConfDir + "/" + MatrixCredentialsFile
	clientCAPath          = serverConfDir + "/" + MatrixCAFile

	// serverTmpDir is where OpenVPN writes the temporary file that the
	// via-file form of --auth-user-pass-verify hands to the hook. via-file
	// rather than via-env because a password in the environment needs
	// --script-security 3, and 2 is the lowest level that runs a script at all.
	serverTmpDir = "/tmp"
)

// MatrixCredentialsFile is the base name of the credentials file a
// containerised stock OpenVPN client reads for an AuthUserPass entry. It is
// exported because overriding it is how a deliberate wrong-password run is
// built: an OracleOptions.Files entry under this name replaces the one
// MatrixServer.OracleOptions supplies.
const MatrixCredentialsFile = "auth.txt"

// MatrixCAFile is the base name of the CA file a CAFile entry's client profile
// names instead of carrying an inline <ca> block. Like MatrixCredentialsFile it
// is both a bundle entry name and an OracleOptions.Files key, so a caller
// assembling either by hand has to spell it the same way.
const MatrixCAFile = "ca.crt"

// Common names on the ephemeral matrix PKI. The server's is what a
// CertCheckX509NameMatch entry names in its verify-x509-name directive, and the
// wrong one is what CertCheckX509NameMismatch names.
const (
	// MatrixServerCN is the common name on every matrix server certificate.
	MatrixServerCN = "matrix-server"
	// MatrixWrongServerCN is a common name no certificate the matrix issues
	// can carry. It shares no substring with MatrixServerCN, so a profile
	// carrying it can be checked for the real name without a spurious hit.
	MatrixWrongServerCN = "no-such-server"
	// MatrixClientCN is the common name on every matrix client certificate.
	MatrixClientCN = "matrix-client"
	// MatrixCACN is the common name on the throwaway CA.
	MatrixCACN = "go-openvpn-matrix-ca"
)

// ContainerPort is the port the server listens on inside the container. The
// host-side port is allocated per run and published onto it.
const ContainerPort = 1194

// Tunnel networks handed out by the matrix servers. They are private to the
// container's network namespace and never reach the host.
const (
	tunnelNet4    = "10.8.0.0 255.255.255.0"
	tunnelNet6    = "fd00:4f4c:5650:4e00::/64"
	tunnelNet6Len = 64
)

// serverProtoDirective returns the value for the server's "proto" directive.
func (e MatrixEntry) serverProtoDirective() string {
	v6 := e.Family != AFInet
	switch {
	case e.Proto == ProtoTCP && v6:
		return "tcp6-server"
	case e.Proto == ProtoTCP:
		return "tcp-server"
	case v6:
		return "udp6"
	default:
		return "udp"
	}
}

// clientProtoDirective returns the value for the client's "proto" directive.
// AFDual uses the plain v4 token because the server's IPv6 socket accepts
// v4-mapped connections; the caller picks which host address to dial.
func (e MatrixEntry) clientProtoDirective() string {
	if e.Family == AFInet6 {
		return e.Proto.String() + "6"
	}
	return e.Proto.String()
}

// cipherDirectives returns the version-appropriate way to pin exactly one
// data-channel cipher. Left to their defaults, 2.4 and 2.5 would negotiate an
// NCP cipher that is not the one the entry names.
func (e MatrixEntry) cipherDirectives() []string {
	c := string(e.Cipher)
	switch e.Version {
	case V26:
		// 2.6 removed --ncp-disable and deprecated --cipher.
		return []string{
			"data-ciphers " + c,
			"data-ciphers-fallback " + c,
		}
	case V25:
		return []string{
			"cipher " + c,
			"data-ciphers " + c,
		}
	default: // V24
		return []string{
			"cipher " + c,
			"ncp-ciphers " + c,
		}
	}
}

// compressDirectives returns the version-appropriate compression directives.
func (e MatrixEntry) compressDirectives() []string {
	switch e.Compression {
	case CompNone:
		return nil
	case CompLZO:
		return []string{"comp-lzo"}
	case CompLZOForced:
		// "yes" rather than the bare directive: bare is "adaptive", which
		// lets the peer stop compressing whenever its heuristic says so, and
		// this entry's purpose is to produce a compressed payload.
		return []string{"comp-lzo yes"}
	case CompStub:
		if e.Version == V24 {
			// 2.4 spells the stub as a bare --compress.
			return []string{"compress"}
		}
		return []string{"compress stub-v2"}
	default:
		return nil
	}
}

// ServerConfig returns the complete openvpn server configuration for this
// entry, referencing the PKI paths the entrypoint unpacks into /etc/openvpn.
func (e MatrixEntry) ServerConfig() string {
	var b strings.Builder
	w := func(format string, args ...any) {
		fmt.Fprintf(&b, format+"\n", args...)
	}

	w("# generated by testenv: matrix entry %q — do not edit by hand", e.Name)
	w("# openvpn %s / %s / %s / %s / %s / %s / %s / %s",
		e.Version, e.Cipher, e.Digest, e.Wrap, e.Proto, e.Compression, e.Family, e.Auth)
	w("")
	w("dev tun")
	w("topology subnet")
	w("proto %s", e.serverProtoDirective())
	w("port %d", ContainerPort)
	w("")
	w("ca %s", serverCAPath)
	w("cert %s", serverCertPath)
	w("key %s", serverKeyPath)
	// ECDHE only. Generating DH parameters would add tens of seconds to
	// every start and buys nothing for a throwaway test server.
	w("dh none")
	w("")
	w("server %s", tunnelNet4)
	if e.Family != AFInet {
		w("server-ipv6 %s", tunnelNet6)
	}
	w("duplicate-cn")
	w("keepalive 10 60")
	w("")
	for _, d := range e.cipherDirectives() {
		w("%s", d)
	}
	w("auth %s", e.Digest)
	w("tls-version-min 1.2")
	w("")
	switch e.Wrap {
	case WrapPlain:
		w("# control channel: unwrapped")
	case WrapTLSAuthKD0:
		// Client key-direction 0 => server key-direction 1.
		w("tls-auth %s 1", serverTAPath)
	case WrapTLSAuthKD1:
		// Client key-direction 1 => server key-direction 0.
		w("tls-auth %s 0", serverTAPath)
	case WrapTLSCrypt:
		w("tls-crypt %s", serverTAPath)
	}
	w("")
	switch e.Auth {
	case AuthCert:
		w("# authentication: client certificate only")
	case AuthUserPass:
		// script-security 2 is the lowest level that runs a script at all,
		// and the via-file form keeps it there; see serverTmpDir.
		w("script-security 2")
		w("tmp-dir %s", serverTmpDir)
		w("auth-user-pass-verify %s via-file", serverAuthVerifyPath)
	}
	w("")
	for _, d := range e.compressDirectives() {
		w("%s", d)
	}
	switch e.Reneg {
	case RenegDefault:
	case RenegSec30, RenegServerInitiated:
		w("reneg-sec 30")
	}
	w("")
	w("persist-key")
	w("persist-tun")
	w("verb 4")

	return b.String()
}

// authVerifyScript returns the --auth-user-pass-verify hook shipped into the
// server container of an AuthUserPass entry. matrixBundle gives it an
// executable mode; the entrypoint re-asserts that mode before openvpn starts.
//
// It is generated rather than checked in so that it cannot disagree with
// MatrixUsername and MatrixPassword, and it prints nothing at all: OpenVPN
// forwards a script's output into its own log, which tests capture and print
// on failure.
func authVerifyScript() string {
	return fmt.Sprintf(`#!/bin/sh
# Generated by testenv — do not edit by hand.
#
# --auth-user-pass-verify hook for a matrix entry whose Auth axis is
# AuthUserPass. The via-file form passes the path of a temporary file as $1:
# username on line 1, password on line 2. Exit 0 accepts, anything else rejects.
#
# The credentials below are test constants (testenv.MatrixUsername and
# testenv.MatrixPassword). They authenticate nothing outside this container.
set -eu

[ -f "${1:-}" ] || exit 1

user=$(sed -n 1p "$1")
pass=$(sed -n 2p "$1")

if [ "$user" = "%s" ] && [ "$pass" = "%s" ]; then
    exit 0
fi
exit 1
`, MatrixUsername, MatrixPassword)
}

// credentialsFileBody returns the file OpenVPN's --auth-user-pass <file> form
// reads: the username on the first line and the password on the second.
func credentialsFileBody() string {
	return MatrixUsername + "\n" + MatrixPassword + "\n"
}

// ClientProfileOptions carries the per-run values a client profile needs that
// the matrix entry itself cannot know: where the server ended up listening and
// the ephemeral PKI generated for that run.
type ClientProfileOptions struct {
	// Remote is the host to dial, e.g. "127.0.0.1" or "::1".
	Remote string
	// Port is the published host-side port.
	Port int
	// CACertPEM is the run's CA certificate.
	CACertPEM string
	// ClientCertPEM is the run's client certificate.
	ClientCertPEM string
	// ClientKeyPEM is the run's client private key.
	ClientKeyPEM string
	// StaticKey is the OpenVPN static key file contents, required when the
	// entry's Wrap is not WrapPlain.
	StaticKey string
	// CredentialsFile, when non-empty, is the in-container path the generated
	// auth-user-pass directive points at. Ignored unless the entry's Auth is
	// AuthUserPass. Leave it empty for the bare directive, which is what this
	// client's credential seam consumes; set it for a stock OpenVPN client,
	// which has no terminal to be prompted on inside a container and must read
	// the pair from a file.
	CredentialsFile string

	// CAFile is the path the generated `ca` directive names. Ignored unless
	// the entry's CASource is CAFile, and required when it is.
	//
	// It is per-run because one entry produces two profiles: a bare base name
	// for a profile written into a directory on this host, where OpenVPN and
	// this client both resolve it beside the profile, and an absolute
	// in-container path for the reference client, whose working directory is /
	// and not /etc/openvpn.
	CAFile string

	// DeadRemotePort is the port of the deliberately unreachable first
	// remote. Ignored unless the entry's Remotes is RemoteDeadFirst, and
	// required when it is. Nothing must be listening on it: the point of the
	// entry is that the first remote does not answer, and a port that happens
	// to be in use turns the failover test into an accident.
	DeadRemotePort int
}

// ClientProfile returns a complete inline .ovpn profile for this entry,
// generated from the same MatrixEntry as ServerConfig so the two agree on
// cipher, digest, control-channel wrapping, compression framing and
// renegotiation by construction.
func (e MatrixEntry) ClientProfile(o ClientProfileOptions) string {
	var b strings.Builder
	w := func(format string, args ...any) {
		fmt.Fprintf(&b, format+"\n", args...)
	}

	w("# generated by testenv: matrix entry %q — do not edit by hand", e.Name)
	w("client")
	w("dev tun")
	w("proto %s", e.clientProtoDirective())
	if e.Remotes == RemoteDeadFirst {
		// The dead one first, in file order: OpenVPN tries them in the order
		// they are written, so an entry that put the live one first would
		// test nothing.
		w("remote %s %d", o.Remote, o.DeadRemotePort)
	}
	w("remote %s %d", o.Remote, o.Port)
	w("nobind")
	w("resolv-retry infinite")
	w("persist-key")
	w("persist-tun")
	w("remote-cert-tls server")
	switch e.CertCheck {
	case CertCheckNone:
	case CertCheckX509NameMatch:
		w("verify-x509-name %s name", MatrixServerCN)
	case CertCheckX509NameMismatch:
		w("verify-x509-name %s name", MatrixWrongServerCN)
	case CertCheckNSCertType:
		w("ns-cert-type server")
	}
	w("tls-version-min 1.2")

	// The client mirrors the server's cipher pinning. 2.6 clients reject
	// --ncp-ciphers, and 2.4 clients do not know --data-ciphers, so the
	// version split is the same one ServerConfig makes.
	switch e.Version {
	case V26:
		w("data-ciphers %s", e.Cipher)
		w("data-ciphers-fallback %s", e.Cipher)
	case V25:
		w("cipher %s", e.Cipher)
		w("data-ciphers %s", e.Cipher)
	default:
		w("cipher %s", e.Cipher)
	}
	w("auth %s", e.Digest)
	if e.Auth.RequiresCredentials() {
		if o.CredentialsFile != "" {
			w("auth-user-pass %s", o.CredentialsFile)
		} else {
			w("auth-user-pass")
		}
	}

	for _, d := range e.compressDirectives() {
		w("%s", d)
	}
	switch e.Reneg {
	case RenegDefault:
	case RenegSec30:
		w("reneg-sec 30")
	case RenegServerInitiated:
		// Only the server may start a rekey.
		w("reneg-sec 0")
	}
	w("verb 3")
	w("")

	switch e.CASource {
	case CAFile:
		// The CA is the one piece of a matrix profile that is not a secret,
		// so it is the one that can move out of the profile without weakening
		// anything. The client certificate and its key stay inline: this rig
		// does not put a private key on disk beside a generated profile.
		w("ca %s", o.CAFile)
	default:
		w("<ca>\n%s</ca>", ensureTrailingNewline(o.CACertPEM))
	}
	w("<cert>\n%s</cert>", ensureTrailingNewline(o.ClientCertPEM))
	w("<key>\n%s</key>", ensureTrailingNewline(o.ClientKeyPEM))
	switch e.Wrap {
	case WrapPlain:
	case WrapTLSAuthKD0:
		w("<tls-auth>\n%s</tls-auth>", ensureTrailingNewline(o.StaticKey))
		w("key-direction 0")
	case WrapTLSAuthKD1:
		w("<tls-auth>\n%s</tls-auth>", ensureTrailingNewline(o.StaticKey))
		w("key-direction 1")
	case WrapTLSCrypt:
		w("<tls-crypt>\n%s</tls-crypt>", ensureTrailingNewline(o.StaticKey))
	}

	return b.String()
}

// ensureTrailingNewline appends a newline if s does not already end with one,
// so inline PEM blocks never run into their closing tag.
func ensureTrailingNewline(s string) string {
	if s == "" || strings.HasSuffix(s, "\n") {
		return s
	}
	return s + "\n"
}
