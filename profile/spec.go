// SPDX-License-Identifier: LGPL-2.1-or-later

// Building a profile programmatically.
//
// Spec is the second front-end onto the assembler, for a caller holding a
// host, a port and a CA rather than a file. It does not build a Profile: it
// renders the directives a file would have carried and hands them to the same
// assembler the text parser uses, so there is no value Build can produce that
// ParseString could not, and no second set of rules to keep in step.

package profile

import (
	"fmt"
	"strconv"
	"strings"
)

// Spec describes a tunnel programmatically. Each field is one OpenVPN
// directive or inline block, spelled the way a profile spells it; a zero field
// is an absent directive, so a built profile takes the same defaults a parsed
// one does, from the same code.
//
// Fields naming a transport or a compression algorithm are strings, not this
// package's enums: the enums have zero values that mean something — Proto's is
// TCP, where OpenVPN's default is UDP — and absent has to differ from chosen.
type Spec struct {
	// Remotes is the --remote list, in dial order. At least one is required.
	Remotes []Endpoint
	// Port is --port: the default for any Endpoint that names none.
	// Zero means the directive is absent, and the profile default of 1194
	// applies.
	Port int
	// Proto is --proto in OpenVPN's spelling ("udp", "tcp", "tcp-client",
	// "udp4", …), the default for any Endpoint that names none. Empty means
	// the directive is absent, and UDP applies. Server spellings are refused,
	// exactly as they are in a file.
	Proto string

	// CA, Cert and Key are the PEM bodies of the <ca>, <cert> and <key>
	// blocks. The client refuses to connect without a usable CA; Cert and Key
	// go together.
	CA, Cert, Key []byte

	// TLSAuth and TLSCrypt are the bodies of <tls-auth> and <tls-crypt>, as
	// "openvpn --genkey" writes them. They are mutually exclusive.
	TLSAuth, TLSCrypt []byte
	// KeyDirection is --key-direction. KeyDirectionAbsent emits no directive,
	// which is its own behaviour: the whole key is used in both directions.
	KeyDirection KeyDirection

	// AuthUserPass is the bare auth-user-pass directive: authenticate with the
	// username and password the client's CredentialsFn supplies. The
	// file-argument form is deliberately not offered — a built profile has no
	// directory to resolve it against.
	AuthUserPass bool
	// AuthFederate is auth-federate: use the SAML/CRV1 flow.
	AuthFederate bool

	// Cipher is --cipher; empty means absent, and AES-256-GCM applies.
	Cipher string
	// Auth is --auth; empty means absent, and SHA1 applies. The distinction
	// matters: an explicit "auth SHA1" and no directive at all are told apart
	// by the profile and reported differently.
	Auth string

	// RemoteCertTLSServer emits "remote-cert-tls server".
	RemoteCertTLSServer bool
	// NSCertTypeServer emits "ns-cert-type server".
	NSCertTypeServer bool
	// VerifyX509Name and VerifyX509NameMatch are --verify-x509-name. The match
	// type is only emitted when a name is set.
	VerifyX509Name      string
	VerifyX509NameMatch X509NameMatch

	// Compression is the whole compression directive, as a file spells it:
	// "comp-lzo", "comp-lzo no", "compress", "compress lz4-v2",
	// "compress stub-v2", and so on. Empty means none. The spelling matters —
	// a bare "compress" and "comp-lzo no" put different bytes on the wire.
	Compression string
	// AllowCompression is --allow-compression: "no", "asym" or "yes".
	AllowCompression string

	// TunMTU is --tun-mtu.
	TunMTU int
	// MSSFix is --mssfix N, with MSSFixMode its optional second word.
	MSSFix     int
	MSSFixMode MSSFixMode
	// MSSFixOff is an explicit "mssfix 0", the opt-out. It is refused
	// alongside a non-zero MSSFix, because a file cannot say both.
	MSSFixOff bool

	// RenegSec is --reneg-sec. Zero means absent, and 3600 applies.
	RenegSec int
	// NoReneg is an explicit "reneg-sec 0", which disables client-initiated
	// renegotiation and is what AWS-issued profiles carry. Refused alongside a
	// non-zero RenegSec.
	NoReneg bool
	// RenegBytes is --reneg-bytes.
	RenegBytes int64
	// HandWindow is --hand-window; BecomePrimary is --become-primary.
	HandWindow    int
	BecomePrimary int

	// Ping, PingRestart and PingExit are the individual timer directives.
	// PingExit and PingRestart share a slot in the profile, as they do in a
	// file, and are refused together.
	Ping, PingRestart, PingExit int
	// Keepalive is "keepalive N M". It outranks Ping and PingRestart wherever
	// they appear, exactly as in a file.
	Keepalive Keepalive
	// ExplicitExitNotify is --explicit-exit-notify. Use ExplicitExitNotifyBare
	// for the argument-less form, which means one.
	ExplicitExitNotify     int
	ExplicitExitNotifyBare bool

	// RemoteRandom is --remote-random; RemoteRandomHostname is
	// --remote-random-hostname.
	RemoteRandom         bool
	RemoteRandomHostname bool

	// DNS is rendered as dhcp-option DNS / DOMAIN / DOMAIN-ROUTE directives.
	DNS DNSOptions

	// Extra carries any directive without a field above, applied after them
	// and classified by the capability preflight like a line of a file. A name
	// a field above already emits is refused, so the two cannot disagree.
	Extra []Directive
}

// Endpoint is one --remote line.
type Endpoint struct {
	// Host is the hostname or address. Required.
	Host string
	// Port is this remote's own port. Zero inherits Spec.Port, then 1194.
	Port int
	// Proto is this remote's own transport, in OpenVPN's spelling. Empty
	// inherits Spec.Proto, then UDP.
	Proto string
}

// Keepalive is the two arguments of the keepalive directive.
type Keepalive struct{ Interval, Timeout int }

// DNSOptions is the resolver configuration to push through dhcp-option.
type DNSOptions struct {
	// Servers are dhcp-option DNS addresses, in preference order.
	Servers []string
	// SearchDomains are dhcp-option DOMAIN; RouteDomains are DOMAIN-ROUTE.
	SearchDomains []string
	RouteDomains  []string
}

// Build assembles the profile. Every check the parser makes, Build makes,
// with the parser's own code. What it cannot check — that the CA parses, that
// the control-channel wrap can be built, that credentials are on hand — is
// what Client.Preflight checks, without opening a socket.
func (s Spec) Build() (*Profile, error) {
	blocks, ds, err := s.directives()
	if err != nil {
		return nil, err
	}
	a := newAssembler()
	// Blocks first, so an inline body settles a reference before the
	// directives are read — the order a file gives them.
	line := 0
	for _, b := range blocks {
		line++
		a.openBlock(b.tag, line)
		if err := a.closeBlock(b.tag, b.body); err != nil {
			return nil, err
		}
	}
	for _, d := range ds {
		line++
		d.Line = line
		if err := a.directive(d); err != nil {
			return nil, err
		}
	}
	// No base directory: a Spec carries bytes, never file references, so
	// there is nothing outside it to resolve.
	return a.finish("")
}

// specBlockTags are the inline blocks a Spec renders from its own fields. A
// caller reaching for one of these through Extra has mistaken a block for a
// directive, and a directive is not where its body can go.
var specBlockTags = map[string]struct{}{
	"ca": {}, "cert": {}, "key": {}, "tls-auth": {}, "tls-crypt": {},
}

// specBlock is one inline block a Spec renders.
type specBlock struct {
	tag  string
	body []byte
}

// directives renders the typed fields into the blocks and directives a file
// would have carried.
func (s Spec) directives() ([]specBlock, []Directive, error) {
	var blocks []specBlock
	for _, b := range []specBlock{
		{"ca", s.CA}, {"cert", s.Cert}, {"key", s.Key},
		{"tls-auth", s.TLSAuth}, {"tls-crypt", s.TLSCrypt},
	} {
		if len(b.body) > 0 {
			blocks = append(blocks, b)
		}
	}
	if len(s.TLSAuth) > 0 && len(s.TLSCrypt) > 0 {
		return nil, nil, fmt.Errorf("profile: spec: tls-auth and tls-crypt are mutually exclusive")
	}
	if s.MSSFix > 0 && s.MSSFixOff {
		return nil, nil, fmt.Errorf("profile: spec: MSSFix and MSSFixOff both set; a profile cannot say both")
	}
	if s.RenegSec > 0 && s.NoReneg {
		return nil, nil, fmt.Errorf("profile: spec: RenegSec and NoReneg both set; a profile cannot say both")
	}
	if s.PingRestart > 0 && s.PingExit > 0 {
		return nil, nil, fmt.Errorf("profile: spec: PingRestart and PingExit share a slot; set one")
	}
	if s.ExplicitExitNotify > 0 && s.ExplicitExitNotifyBare {
		return nil, nil, fmt.Errorf("profile: spec: ExplicitExitNotify and ExplicitExitNotifyBare both set; set one")
	}

	var ds []Directive
	add := func(name string, args ...string) {
		// A bare directive carries a nil Args, not an empty one: that is what
		// the line parser produces, and a caller comparing two profiles would
		// otherwise see a difference that is not there.
		if len(args) == 0 {
			args = nil
		}
		ds = append(ds, Directive{Name: name, Args: args})
	}

	for _, r := range s.Remotes {
		args := []string{r.Host}
		switch {
		case r.Proto != "":
			// The grammar cannot say "inherit the port but pin the proto", so
			// a remote naming its own transport must name a port too. Resolve
			// it the way the assembler would.
			port := r.Port
			if port == 0 {
				port = s.Port
			}
			if port == 0 {
				port = defaultPort
			}
			args = append(args, strconv.Itoa(port), r.Proto)
		case r.Port != 0:
			args = append(args, strconv.Itoa(r.Port))
		}
		add("remote", args...)
	}
	if s.Port != 0 {
		add("port", strconv.Itoa(s.Port))
	}
	if s.Proto != "" {
		add("proto", s.Proto)
	}
	if s.KeyDirection != KeyDirectionAbsent {
		add("key-direction", s.KeyDirection.String())
	}
	if s.AuthUserPass {
		add("auth-user-pass")
	}
	if s.AuthFederate {
		add("auth-federate")
	}
	if s.Cipher != "" {
		add("cipher", s.Cipher)
	}
	if s.Auth != "" {
		add("auth", s.Auth)
	}
	if s.RemoteCertTLSServer {
		add("remote-cert-tls", "server")
	}
	if s.NSCertTypeServer {
		add("ns-cert-type", "server")
	}
	if s.VerifyX509Name != "" {
		args := []string{s.VerifyX509Name}
		if w := x509MatchWord(s.VerifyX509NameMatch); w != "" {
			args = append(args, w)
		}
		add("verify-x509-name", args...)
	}
	if s.Compression != "" {
		// A file spells a directive on one line, so two lines here are two
		// directives and not this one. strings.Fields does not care and
		// would weld them into one.
		if strings.ContainsRune(s.Compression, '\n') {
			return nil, nil, fmt.Errorf(
				"profile: spec: Compression %q is more than one line, and a directive is one", s.Compression)
		}
		f := strings.Fields(s.Compression)
		// Whitespace and nothing else names no directive.
		if len(f) == 0 {
			return nil, nil, fmt.Errorf(
				"profile: spec: Compression %q names no directive", s.Compression)
		}
		// The only field that supplies a directive name as well as its
		// arguments, so the only one that folds the name the way the line
		// parser folds fields[0]: "COMP-LZO" has to reach comp-lzo.
		add(strings.ToLower(f[0]), f[1:]...)
	}
	if s.AllowCompression != "" {
		add("allow-compression", s.AllowCompression)
	}
	if s.TunMTU != 0 {
		add("tun-mtu", strconv.Itoa(s.TunMTU))
	}
	switch {
	case s.MSSFixOff:
		add("mssfix", "0")
	case s.MSSFix > 0:
		args := []string{strconv.Itoa(s.MSSFix)}
		if w := mssFixModeWord(s.MSSFixMode); w != "" {
			args = append(args, w)
		}
		add("mssfix", args...)
	}
	switch {
	case s.NoReneg:
		add("reneg-sec", "0")
	case s.RenegSec != 0:
		add("reneg-sec", strconv.Itoa(s.RenegSec))
	}
	if s.RenegBytes != 0 {
		add("reneg-bytes", strconv.FormatInt(s.RenegBytes, 10))
	}
	if s.HandWindow != 0 {
		add("hand-window", strconv.Itoa(s.HandWindow))
	}
	if s.BecomePrimary != 0 {
		add("become-primary", strconv.Itoa(s.BecomePrimary))
	}
	if s.Ping != 0 {
		add("ping", strconv.Itoa(s.Ping))
	}
	if s.PingRestart != 0 {
		add("ping-restart", strconv.Itoa(s.PingRestart))
	}
	if s.PingExit != 0 {
		add("ping-exit", strconv.Itoa(s.PingExit))
	}
	if s.Keepalive.Interval != 0 || s.Keepalive.Timeout != 0 {
		add("keepalive", strconv.Itoa(s.Keepalive.Interval), strconv.Itoa(s.Keepalive.Timeout))
	}
	switch {
	case s.ExplicitExitNotifyBare:
		add("explicit-exit-notify")
	case s.ExplicitExitNotify != 0:
		add("explicit-exit-notify", strconv.Itoa(s.ExplicitExitNotify))
	}
	if s.RemoteRandom {
		add("remote-random")
	}
	if s.RemoteRandomHostname {
		add("remote-random-hostname")
	}
	for _, v := range s.DNS.Servers {
		add("dhcp-option", "DNS", v)
	}
	for _, v := range s.DNS.SearchDomains {
		add("dhcp-option", "DOMAIN", v)
	}
	for _, v := range s.DNS.RouteDomains {
		add("dhcp-option", "DOMAIN-ROUTE", v)
	}

	// Extra last, and refused where it would restate a field above.
	owned := make(map[string]struct{}, len(ds))
	for _, d := range ds {
		owned[d.Name] = struct{}{}
	}
	for _, d := range s.Extra {
		name := strings.ToLower(d.Name)
		if name == "" {
			return nil, nil, fmt.Errorf("profile: spec: Extra carries a directive with no name")
		}
		if _, clash := owned[name]; clash {
			return nil, nil, fmt.Errorf("profile: spec: Extra restates %q, which a field already sets", name)
		}
		if _, block := specBlockTags[name]; block {
			return nil, nil, fmt.Errorf("profile: spec: %q is an inline block, not a directive", name)
		}
		ds = append(ds, Directive{Name: name, Args: append([]string(nil), d.Args...)})
	}

	for _, d := range ds {
		if err := roundTrips(d); err != nil {
			return nil, nil, err
		}
	}
	return blocks, ds, nil
}

// roundTrips checks that a directive survives being written to a file and
// read back, which is the whole of Build's contract: no value Build can
// produce that ParseString could not.
//
// A file is whitespace-separated, so a word survives only if it is exactly one
// field and already equal to it: an empty word disappears, one holding a space
// becomes two, a leading space is trimmed. An empty or space-padded host is
// the case that matters, since it promotes the port to the hostname without
// saying so.
//
// The name is checked as well as the arguments, and for one thing more: it is
// the first word of a line, where '#' and ';' make the line a comment the
// parser drops and '<' makes it markup, with "<ca>" opening an inline block
// that swallows the rest of the file.
func roundTrips(d Directive) error {
	if f := strings.Fields(d.Name); len(f) != 1 || f[0] != d.Name {
		return fmt.Errorf(
			"profile: spec: directive name %q is not a single whitespace-free word", d.Name)
	}
	switch d.Name[0] {
	case '#', ';', '<':
		return fmt.Errorf(
			"profile: spec: directive name %q begins a comment or a block in a file, not a directive", d.Name)
	}
	for _, a := range d.Args {
		if f := strings.Fields(a); len(f) != 1 || f[0] != a {
			return fmt.Errorf(
				"profile: spec: %s: argument %q is not a single whitespace-free word", d.Name, a)
		}
	}
	return nil
}

// x509MatchWord is the profile spelling of a match type, or "" for the default
// that a file leaves unwritten.
func x509MatchWord(m X509NameMatch) string {
	switch m {
	case X509NameCN:
		return "name"
	case X509NameCNPrefix:
		return "name-prefix"
	default:
		return ""
	}
}

// mssFixModeWord is the profile spelling of an mssfix mode, or "" for the
// default that a file leaves unwritten.
func mssFixModeWord(m MSSFixMode) string {
	switch m {
	case MSSFixEncap:
		return "mtu"
	case MSSFixFixed:
		return "fixed"
	default:
		return ""
	}
}
