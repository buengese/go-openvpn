// SPDX-License-Identifier: LGPL-2.1-or-later

// Assembling a Profile from directives, whichever produced them.
//
// A profile is the struct plus everything the parser does to it: the defaults
// it starts from, the normalisers each directive passes through, and the
// resolution that runs once the last line is read. Filling the struct by hand
// skips all three. Every front-end hands its directives to this one assembler,
// so there is no second set of rules to keep in step.

package profile

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/openlawsvpn/go-openlawsvpn/dns"
	"github.com/openlawsvpn/go-openlawsvpn/internal/crypto"
)

// defaultPort is the port a profile dials when no directive names one.
// OpenVPN's own default, and the one both front-ends start from.
const defaultPort = 1194

// assembler builds a Profile from directives and inline blocks. Its zero value
// is not usable; start from newAssembler.
type assembler struct {
	p *Profile
}

// newAssembler returns an assembler holding the defaults a profile starts
// from, before a single directive is read.
func newAssembler() *assembler {
	return &assembler{p: &Profile{
		Port:   defaultPort,
		Proto:  ProtoUDP,
		Cipher: "AES-256-GCM",
		// OpenVPN's built-in digest default is SHA1, not SHA256: openvpn(8)
		// documents "--auth alg ... The default is SHA1", and openvpn3-core
		// inherits it. AuthSet stays false, so this default stays
		// distinguishable from an explicit "auth SHA1".
		Auth: crypto.DefaultAuthName,
		Verb: 3,
		// openvpn3-core ssl/proto.hpp starts with this default, then lets an
		// explicit reneg-sec directive (including zero) override it.
		RenegSec: 3600,
	}}
}

// openBlock records that an inline <tag> block began. It is separate from
// closeBlock because an unterminated block still counts as present: OpenVPN
// consumes the body to end of file and loads nothing from it, and the
// capability registry still has a block to classify.
func (a *assembler) openBlock(tag string, line int) {
	a.p.InlineBlocks = append(a.p.InlineBlocks, InlineBlock{Tag: tag, Line: line})
}

// closeBlock takes the body of a completed inline block. The bodies of <ca>,
// <cert> and <key> are kept; every other tag is dropped, so its contents are
// never read as directives.
//
// The tag is folded here, as it is by hasInlineBlock and by the capability
// registry. Comparing it verbatim leaves <CA> marking a "ca ca.crt" reference
// superseded and loading the body nowhere: a profile that parses cleanly and
// cannot connect.
func (a *assembler) closeBlock(tag string, body []byte) error {
	p := a.p
	// Not the tag recorded on InlineBlocks, which goes on saying what the
	// file said.
	tag = strings.ToLower(tag)
	switch tag {
	case "ca":
		p.CA = append([]byte{}, body...)
	case "cert":
		p.Cert = append([]byte{}, body...)
	case "key":
		p.Key = append([]byte{}, body...)
	}
	return nil
}

// directive folds one directive into the profile. Every directive is
// recorded, recognised or not, because the capability registry classifies
// what this switch ignores.
func (a *assembler) directive(d Directive) error {
	p := a.p
	p.Directives = append(p.Directives, d)

	// The switch reads the directive the way the line parser produced it:
	// fields[0] is the keyword and the arguments start at fields[1].
	fields := append([]string{d.Name}, d.Args...)
	directive := d.Name
	switch directive {
	case "remote":
		// remote <host> [port] [proto]. Every line is retained, in file
		// order; the third field is that remote's own transport, and a
		// remote that names one is dialed over it whatever --proto says.
		//
		// Port and Proto are left unset here and resolved against the
		// profile's own --port and --proto after the file is read,
		// because either directive may appear below the remote line it
		// applies to.
		if len(fields) < 2 {
			return fmt.Errorf("profile: remote: missing hostname")
		}
		rem := Remote{Host: fields[1]}
		if len(fields) >= 3 {
			port, err := strconv.Atoi(fields[2])
			if err != nil || port < 1 || port > 65535 {
				return fmt.Errorf("profile: remote: invalid port %q", fields[2])
			}
			rem.Port = port
		}
		if len(fields) >= 4 {
			proto, ok := ParseProto(fields[3])
			if !ok {
				return fmt.Errorf("profile: remote: unknown protocol %q", fields[3])
			}
			rem.Proto, rem.ProtoSet = proto, true
		}
		p.Remotes = append(p.Remotes, rem)
	case "port":
		if len(fields) < 2 {
			return fmt.Errorf("profile: port: missing value")
		}
		port, err := strconv.Atoi(fields[1])
		if err != nil || port < 1 || port > 65535 {
			return fmt.Errorf("profile: port: invalid %q", fields[1])
		}
		p.Port = port
	case "proto":
		if len(fields) < 2 {
			return fmt.Errorf("profile: proto: missing value")
		}
		proto, ok := ParseProto(fields[1])
		if !ok {
			return fmt.Errorf("profile: proto: unknown %q", fields[1])
		}
		p.Proto = proto
	case "cipher":
		// The upper-casing decides nothing on the wire: crypto.LookupCipher
		// and caps.isCBC both fold again, so "aes-256-gcm" and "AES-256-GCM"
		// already build the same tunnel. It settles the exported field a
		// library caller reads, and the session report's profileFingerprint,
		// which hashes Cipher and Auth as written and has to give one profile
		// one identifier however it spelled them.
		if len(fields) < 2 {
			return fmt.Errorf("profile: cipher: missing value")
		}
		p.Cipher = strings.ToUpper(fields[1])
	case "auth":
		// The packet HMAC digest and nothing else: the switch matches the
		// whole keyword, so auth-user-pass, auth-nocache, auth-retry and
		// auth-federate cannot reach it and must never set the digest.
		if len(fields) < 2 {
			return fmt.Errorf("profile: auth: missing value")
		}
		p.Auth = strings.ToUpper(fields[1])
		p.AuthSet = true
	case "verb":
		if len(fields) < 2 {
			return fmt.Errorf("profile: verb: missing value")
		}
		n, err := strconv.Atoi(fields[1])
		if err != nil || n < 0 || n > 11 {
			return fmt.Errorf("profile: verb: invalid %q", fields[1])
		}
		p.Verb = n
	case "reneg-sec":
		if len(fields) < 2 {
			return fmt.Errorf("profile: reneg-sec: missing value")
		}
		n, err := strconv.Atoi(fields[1])
		if err != nil || n < 0 {
			return fmt.Errorf("profile: reneg-sec: invalid %q", fields[1])
		}
		p.RenegSec = n
	case "reneg-bytes":
		if len(fields) < 2 {
			return fmt.Errorf("profile: reneg-bytes: missing value")
		}
		n, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil || n < 0 {
			return fmt.Errorf("profile: reneg-bytes: invalid %q", fields[1])
		}
		p.RenegBytes = n
	case "become-primary":
		if len(fields) < 2 {
			return fmt.Errorf("profile: become-primary: missing value")
		}
		n, err := strconv.Atoi(fields[1])
		if err != nil || n < 0 {
			return fmt.Errorf("profile: become-primary: invalid %q", fields[1])
		}
		p.BecomePrimarySec = n
	case "tun-mtu":
		if len(fields) < 2 {
			return fmt.Errorf("profile: tun-mtu: missing value")
		}
		n, err := strconv.Atoi(fields[1])
		if err != nil || n < 68 || n > 65535 {
			return fmt.Errorf("profile: tun-mtu: invalid %q", fields[1])
		}
		p.TunMTU = n
	case "mssfix":
		// OpenVPN accepts a bare "mssfix" and applies its default. Keep
		// MSSFixSet false in that case, exactly as when the directive is
		// omitted. A numeric zero is an explicit opt-out.
		if len(fields) >= 2 {
			n, err := strconv.Atoi(fields[1])
			if err != nil || n < 0 {
				return fmt.Errorf("profile: mssfix: invalid %q", fields[1])
			}
			p.MSSFix = n
			p.MSSFixSet = true
			// A numeric mssfix measures the tunnel packet; "mtu" counts the
			// outer IP and transport headers too, and "fixed" neither
			// (openvpn-2.6.22 src/openvpn/options.c:7314-7344, openvpn3
			// ssl/proto.hpp:2713). An unknown word is a warning there, so it
			// is not fatal here either.
			if len(fields) >= 3 {
				switch fields[2] {
				case "mtu":
					p.MSSFixMode = MSSFixEncap
				case "fixed":
					p.MSSFixMode = MSSFixFixed
				}
			}
		}
	case "remote-random":
		// The order of the remote list, not a property of any remote.
		// The shuffle itself is the dialer's; see Profile.RemoteRandom.
		p.RemoteRandom = true
	case "remote-random-hostname":
		p.RandomHostname = true
	case "auth-federate":
		// AWS Client VPN profiles use this OpenVPN directive to request
		// federated (SAML) authentication. Treat it as the standard spelling
		// of the existing explicit SAML-flow override.
		p.ForceSAMLFlow = true
	case "x-openlawsvpn-flow":
		if len(fields) >= 2 && strings.ToLower(fields[1]) == "saml" {
			p.ForceSAMLFlow = true
		}
	case "verify-x509-name":
		if len(fields) >= 2 {
			p.VerifyX509Name = fields[1]
		}
	case "dhcp-option":
		// The same syntax the server pushes, so the same parser reads it.
		if err := dns.ParseDHCPOption(&p.DNS, fields); err != nil {
			return fmt.Errorf("profile: %w", err)
		}
	}
	return nil
}

// finish resolves what could only be settled once every directive was seen,
// then hands back the profile.
func (a *assembler) finish() (*Profile, error) {
	p := a.p

	if len(p.Remotes) == 0 {
		return nil, fmt.Errorf("profile: missing 'remote' directive")
	}

	// Resolve each remote against the profile's own --port and --proto, which
	// may have been set anywhere in the file, including below the remote they
	// apply to. A remote that named its own keeps it.
	for i := range p.Remotes {
		if p.Remotes[i].Port == 0 {
			p.Remotes[i].Port = p.Port
		}
		if !p.Remotes[i].ProtoSet {
			p.Remotes[i].Proto = p.Proto
		}
	}

	// Remote, Port and Proto are the first remote, not the last: OpenVPN
	// dials the list in order and starts with the first.
	p.Remote = p.Remotes[0].Host
	p.Port = p.Remotes[0].Port
	p.Proto = p.Remotes[0].Proto

	return p, nil
}
