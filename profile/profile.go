// Package profile parses OpenVPN .ovpn configuration files.
//
// It handles the directives that go-openlawsvpn needs: remote, port, proto,
// inline PEM blocks (<ca>, <cert>, <key>), the static-key blocks <tls-auth>
// and <tls-crypt>, cipher, auth, rekey timing, and common extra options such
// as comp-lzo / compress.
//
// Inline <tag>...</tag> blocks are recognised generically, so a block the
// client has no field for is consumed as a block rather than having its body
// parsed as directives. Every directive line is recorded on
// Profile.Directives, and every block tag on Profile.InlineBlocks, for the
// capability preflight in the caps package.
//
// A profile may also name its CA, certificate or key in a separate file
// rather than inlining it. Resolving that name needs a directory, which is
// the one behaviour that differs between the entry points: ParsePath and
// ParseFileIn have one and read the file, ParseFile and ParseString do not
// and refuse the profile rather than returning one with an empty trust
// store. See ErrNoProfileDir and resolveFileRefs.
//
// <tls-auth> and <tls-crypt> bodies are secrets rather than public material:
// see StaticKey for how they are kept out of logs, errors and reports.
package profile

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/openlawsvpn/go-openlawsvpn/internal/compress"

	"github.com/openlawsvpn/go-openlawsvpn/dns"
)

// Directive is one directive line exactly as the parser saw it, recorded
// whether or not ParseFile acts on it. It lets the capability registry
// answer what a profile asks for without re-reading the file; nothing on the
// connection path reads it.
type Directive struct {
	// Name is the directive keyword, lowercased.
	Name string
	// Args are the whitespace-separated arguments after the keyword.
	// It is nil for a bare directive such as "nobind".
	Args []string
	// Line is the 1-based line number the directive appeared on.
	Line int
}

// String renders the directive back into its source form, keyword first.
func (d Directive) String() string {
	if len(d.Args) == 0 {
		return d.Name
	}
	return d.Name + " " + strings.Join(d.Args, " ")
}

// InlineBlock records that an inline <tag>...</tag> block was present.
//
// Only the tag name and its opening line are kept. Block bodies are
// certificates, private keys and tls-auth keys; they are never copied into
// this record, so an InlineBlock is always safe to log.
type InlineBlock struct {
	// Tag is the block's tag name, verbatim, for example "ca" or "tls-auth".
	Tag string
	// Line is the 1-based line number of the opening tag.
	Line int
}

// FileRef records a ca, cert or key directive that named a file instead of
// inlining the material, and what the parser did with it.
//
// "The material is loaded" and "the file was read" are different facts and
// the capability registry has to tell them apart: a profile carrying both an
// inline <ca> block and a "ca ca.crt" line loads the CA from the block, as
// OpenVPN does, and never opens the file.
//
// The file name is not kept — these records reach session reports.
type FileRef struct {
	// Tag is the directive keyword: "ca", "cert" or "key".
	Tag string
	// Line is the 1-based line number the directive appeared on.
	Line int
	// Loaded reports that the file was read from the profile's directory
	// into the matching field.
	Loaded bool
	// Superseded reports that the profile also carried an inline <tag>
	// block. The block is what the client uses and the file is not opened.
	Superseded bool
}

// Proto is the transport protocol for the VPN tunnel.
type Proto int

const (
	// ProtoTCP uses TCP with the 2-byte length-prefix framing.
	ProtoTCP Proto = iota
	// ProtoUDP uses raw UDP packets.
	ProtoUDP
)

// String is the profile spelling of the transport: "tcp" or "udp".
func (p Proto) String() string {
	if p == ProtoTCP {
		return "tcp"
	}
	return "udp"
}

// ParseProto normalises one of OpenVPN's transport spellings. It serves both
// places a profile can name a transport — the --proto directive and the third
// field of a --remote line — which accept the same vocabulary in OpenVPN.
//
// The address-family spellings (udp4, tcp6-client) are reduced to their
// transport. The family half restricts which addresses the name may resolve
// to; the client does not implement that, and the capability registry reports
// the directive as degraded rather than supported.
//
// The -server spellings are refused: they ask this process to listen, and a
// client that quietly dialed instead would not be doing what the config said.
func ParseProto(s string) (Proto, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "udp", "udp4", "udp6":
		return ProtoUDP, true
	case "tcp", "tcp4", "tcp6",
		"tcp-client", "tcp4-client", "tcp6-client":
		return ProtoTCP, true
	default:
		return 0, false
	}
}

// X509NameMatch is the match type of the --verify-x509-name directive: which
// part of the server certificate's subject the directive's value is compared
// against.
//
// It is never a SAN. OpenVPN's verify_cert compares the value against the
// subject DN, or against the common name taken out of that DN, and no part of
// the check looks at subjectAltName.
type X509NameMatch int

const (
	// X509NameSubject compares the value against the whole subject DN. It is
	// the zero value because it is also OpenVPN's default: a
	// --verify-x509-name line with no second argument means this one.
	X509NameSubject X509NameMatch = iota
	// X509NameCN compares the value against the certificate's common name,
	// spelled "name" in the profile.
	X509NameCN
	// X509NameCNPrefix requires the certificate's common name to start with
	// the value, spelled "name-prefix" in the profile.
	X509NameCNPrefix
)

// String returns the directive spelling of the match type, so that the value
// a profile round-trips back to is the text the profile contained.
func (m X509NameMatch) String() string {
	switch m {
	case X509NameSubject:
		return "subject"
	case X509NameCN:
		return "name"
	case X509NameCNPrefix:
		return "name-prefix"
	default:
		return "unknown"
	}
}

// ParseX509NameMatch normalises the optional second argument of
// --verify-x509-name. The empty string is the default, which is "subject".
//
// An unrecognised type is refused rather than defaulted: defaulting to
// subject applies a stricter check than the profile asked for, and defaulting
// to no check drops a certificate check on the floor. OpenVPN refuses it too
// ("Unrecognized --verify-x509-name type" in options.c).
//
// The keyword is matched without regard to case, where OpenVPN's streq is
// exact: a spelling OpenVPN would refuse to start on is accepted here, and
// the certificate check is the same one either way.
func ParseX509NameMatch(s string) (X509NameMatch, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "subject":
		return X509NameSubject, true
	case "name":
		return X509NameCN, true
	case "name-prefix":
		return X509NameCNPrefix, true
	default:
		return 0, false
	}
}

// Remote is one --remote line: a host, a port, and optionally a protocol
// that overrides the profile's own.
//
// Port and Proto are always resolved: a line that named neither carries the
// profile's --port and --proto, which is what OpenVPN dials. ProtoSet is what
// records whether the file said so.
type Remote struct {
	// Host is the hostname or address as written in the profile.
	Host string
	// Port is the port to dial.
	Port int
	// Proto is the per-remote protocol from the third field. Absent means
	// the profile's --proto applies, which is what OpenVPN does.
	Proto Proto
	// ProtoSet reports whether the remote line named a protocol itself. It
	// distinguishes a remote that inherited the profile's transport from one
	// that chose the same transport explicitly.
	ProtoSet bool
}

// Profile holds the parsed contents of an .ovpn file.
type Profile struct {
	// Remote is the VPN server hostname or IP.
	Remote string
	// Port is the server port (default 1194).
	Port int
	// Proto is the transport protocol.
	Proto Proto

	// Remotes is every --remote line, in file order. It is never empty in a
	// parsed profile: a file with no remote is refused.
	//
	// Remote, Port and Proto above are Remotes[0] — the compatibility
	// surface, not the model. Anything that has to know there were others
	// reads this. The client dials them in turn, in file order or shuffled
	// when --remote-random asks for it, until one completes a handshake.
	Remotes []Remote

	// CA is the PEM-encoded certificate authority bundle, from an inline
	// <ca> block or from the file a "ca <file>" directive named.
	CA []byte
	// Cert is the PEM-encoded client certificate, from <cert> or a file.
	Cert []byte
	// Key is the PEM-encoded client private key, from <key> or a file.
	Key []byte

	// FileRefs records every ca, cert or key directive that named a file
	// rather than inlining its contents, in file order, and says for each
	// whether the file was read or an inline block superseded it. It never
	// holds the name — see FileRef.
	FileRefs []FileRef

	// TLSAuth is the static key from the profile's <tls-auth> block, or nil
	// when the profile carries none. It authenticates every control packet,
	// the opening HARD_RESET included.
	TLSAuth *StaticKey
	// TLSCrypt is the static key from the profile's <tls-crypt> block, or
	// nil when the profile carries none. It encrypts as well as
	// authenticates the control channel.
	//
	// A profile carrying both blocks is contradictory — the two wraps are
	// alternatives, not layers — and the parser loads both rather than
	// choosing between them. Refusing the combination is the wrapper's
	// decision, made from the whole profile.
	TLSCrypt *StaticKey
	// KeyDirection is the --key-direction value: 0, 1, or absent. Absent is
	// a behaviour of its own and not a default of 0 — see KeyDirection.
	KeyDirection KeyDirection

	// Cipher is the negotiated data-channel cipher name, e.g. "AES-256-GCM".
	Cipher string
	// Auth is the HMAC digest, e.g. "SHA256" (unused for GCM). A profile
	// with no 'auth' directive gets OpenVPN's built-in default of SHA1; see
	// the default in ParseFile for why that is not SHA256.
	Auth string
	// AuthSet reports whether the profile carried an explicit 'auth'
	// directive. It distinguishes "auth SHA1" from an omitted directive,
	// which yields the same SHA1 but says nothing about what was asked for.
	AuthSet bool
	// Verb controls optional diagnostic logging. It follows OpenVPN's 0–11
	// verbosity scale; the default is 3. Verbosity 4 logs the verified server
	// certificate during each TLS handshake.
	Verb int

	// RenegSec is the data-channel key renegotiation interval in seconds.
	// An explicit "reneg-sec 0" disables client-initiated renegotiation, as it
	// does in OpenVPN3. Profiles without the directive use the OpenVPN default
	// of 3600 seconds.
	RenegSec int
	// RenegBytes is the data-channel key renegotiation byte threshold.
	// 0 means no byte-limit renegotiation.
	RenegBytes int64
	// BecomePrimarySec is the optional delay before a negotiated rekey becomes
	// the primary send key. 0 uses the OpenVPN default derived from reneg-sec.
	BecomePrimarySec int

	// HandWindowSec is "hand-window": the time a key exchange is given to
	// finish, and the ceiling on how long a renegotiated key waits before it
	// becomes the send key. 0 means the profile asked for nothing and the
	// reference's 60 applies (openvpn-2.6.22 src/openvpn/options.c:880).
	HandWindowSec int

	// PingInterval is the keepalive send interval in seconds, from "ping N"
	// or the first argument of "keepalive N M". 0 means the profile asked for
	// nothing, and the client's default applies.
	PingInterval int

	// PingTimeout is the dead-link receive timeout in seconds, from
	// "ping-restart N", "ping-exit N", or the second argument of
	// "keepalive N M". 0 means the profile asked for nothing.
	//
	// One field for three directives because the reference keeps one
	// variable: OpenVPN 2.6.22 src/openvpn/options.c lines 6963-6975 writes
	// both ping-restart and ping-exit into options->ping_rec_timeout and
	// separates them only by ping_rec_timeout_action, which is what PingExit
	// records here.
	PingTimeout int

	// PingExit reports that PingTimeout came from "ping-exit" rather than
	// "ping-restart": the profile asked for the session to end when the link
	// goes quiet, not to be restarted.
	//
	// Nothing acts on it — this client's dead-link teardown is terminal
	// either way, and Reconnect is the caller's to invoke — but discarding it
	// would make "ping-exit 60" indistinguishable from "ping-restart 60".
	PingExit bool

	// ExplicitExitNotify is how many exit notifications a deliberate
	// disconnect puts on the wire, from "explicit-exit-notify [n]". 0 sends
	// none, and is both the absent directive and an explicit
	// "explicit-exit-notify 0".
	//
	// The bare directive means one notification, not "on" (OpenVPN 2.4.12
	// src/openvpn/options.c:6133 stores a literal 1 when no argument is
	// present).
	//
	// Stock openvpn refuses the directive alongside a TCP transport
	// (options.c:2181). This client parses it either way and declines to send
	// instead — a profile is a thing to measure, not a thing to reject.
	ExplicitExitNotify int

	// Compression is the data-channel framing the profile itself asked for,
	// from 'comp-lzo' or 'compress [algo]', independent of what the server
	// later pushes. compress.EffectiveMode reconciles the two.
	//
	// It matters more than a client-side preference usually would, because
	// OpenVPN's server does not push its compression setting at all: a
	// comp-lzo config talking to a comp-lzo server agrees by silence, and a
	// client that reads only the PUSH_REPLY concludes there is no framing and
	// sends unframed packets that the peer drops.
	Compression compress.Mode
	// AllowCompression is the '--allow-compression' policy. 'no' refuses a
	// compressing algorithm from either source and permits a framing stub.
	AllowCompression compress.AllowCompression

	// TunMTU is the MTU for the TUN interface, from the 'tun-mtu' directive.
	// 0 means use the default (1500).
	TunMTU int

	// MSSFix is the maximum segment size clamp value, from the 'mssfix' directive.
	// A zero value with MSSFixSet true explicitly disables MSS clamping.
	MSSFix int
	// MSSFixMode is how the MSSFix number is measured, from the directive's
	// optional second word.
	MSSFixMode MSSFixMode
	// MSSFixSet reports whether the profile explicitly set a numeric mssfix
	// value. It distinguishes "mssfix 0" from an omitted directive, for which
	// OpenVPN applies its default MSS clamp.
	MSSFixSet bool

	// RemoteRandom reports that the profile carried '--remote-random'. When
	// true, the client shuffles Remotes before trying them, so that a fleet
	// of clients sharing one config does not converge on the first endpoint.
	//
	// Remotes itself stays in file order: the shuffle is the dialer's, made
	// per attempt. Writing it back into the parsed profile would make a
	// second attempt against the same profile start from the first attempt's
	// permutation.
	RemoteRandom bool

	// RandomHostname indicates the 'remote-random-hostname' directive was present.
	// When true, the client must prepend a random subdomain to Remote before dialing.
	// It is not cosmetic: a deployment that carries the directive may have no
	// DNS record for the bare hostname at all, so the label is what makes the
	// endpoint resolvable. The dialer applies it on both paths.
	RandomHostname bool

	// VerifyX509Name is the value of the 'verify-x509-name' directive: the
	// subject DN or common name the server certificate must present. It is
	// empty when the profile carries no such directive, which is what the
	// verifier reads to decide whether to make the check at all.
	//
	// It is not a hostname and it is not matched against a SAN. Profiles are
	// issued that set it to the certificate's own CN, which is precisely not
	// the endpoint they are dialled at.
	VerifyX509Name string

	// VerifyX509NameMatch is the directive's optional second argument, which
	// says which part of the subject VerifyX509Name is compared against.
	// The zero value is X509NameSubject, matching OpenVPN's default for a
	// line that omits it.
	VerifyX509NameMatch X509NameMatch

	// ForceSAMLFlow is set when the profile contains 'auth-federate' or
	// 'x-openlawsvpn-flow saml'. It forces FlowAWSSSO regardless of the remote
	// hostname, allowing non-AWS servers (e.g. the demo mockserver) to use the
	// CRV1/SAML two-phase flow.
	ForceSAMLFlow bool

	// DNS is the static resolver configuration the profile's dhcp-option
	// directives asked for. It is merged with what the server pushes, which
	// wins where the two overlap.
	DNS dns.Config

	// Directives records every directive line the parser encountered, in
	// file order, including directives it does not act on. Lines inside an
	// inline <tag>...</tag> block are never recorded here.
	//
	// This is diagnostic data for the capability preflight; the connection
	// path uses the typed fields above.
	Directives []Directive

	// InlineBlocks records the inline <tag>...</tag> blocks the profile
	// contained, in file order — tag names and line numbers only, never the
	// bodies. The parser loads the bodies of <ca>, <cert>, <key>,
	// <tls-auth> and <tls-crypt>; any other tag, <tls-crypt-v2> among them,
	// is recognised as a block so that its contents are not mistaken for
	// directives, but is otherwise unused. This list is the input to the
	// capability preflight, so it describes what the file said whether or not
	// the client has anywhere to put it.
	InlineBlocks []InlineBlock
}

// AuthFlow describes which authentication mechanism the profile uses.
type AuthFlow int

const (
	// FlowAWSSSO is the AWS Client VPN SAML/CRV1 two-phase flow.
	// Detected when the remote hostname matches cvpn-endpoint-*.amazonaws.com.
	FlowAWSSSO AuthFlow = iota
	// FlowCertAuth is standard mutual-TLS client certificate authentication.
	// Detected when the profile embeds both <cert> and <key> blocks.
	FlowCertAuth
	// FlowUserPass is username/password authentication (auth-user-pass).
	// Used as the fallback when no other pattern matches.
	FlowUserPass
)

// DetectFlow inspects the profile and returns the appropriate AuthFlow.
func (p *Profile) DetectFlow() AuthFlow {
	if p.ForceSAMLFlow {
		return FlowAWSSSO
	}
	if strings.HasPrefix(p.Remote, "cvpn-endpoint-") && strings.HasSuffix(p.Remote, ".amazonaws.com") {
		return FlowAWSSSO
	}
	if len(p.Cert) > 0 && len(p.Key) > 0 {
		return FlowCertAuth
	}
	return FlowUserPass
}

// ParseFile parses an .ovpn profile from the provided reader.
//
// It has bytes and no location, so a profile that names its CA, certificate
// or key in a file is refused with ErrNoProfileDir rather than returned with
// the material missing. ParsePath, or ParseFileIn when the bytes are already
// in hand, is the entry point that can read one.
func ParseFile(r io.Reader) (*Profile, error) {
	return parse(r, "")
}

// ParseFileIn parses an .ovpn profile from r, resolving the file-referenced
// ca, cert and key directives against baseDir.
//
// It is ParsePath for a caller that already holds the bytes, or that must not
// let the path reach an error message. An empty baseDir behaves exactly as
// ParseFile.
func ParseFileIn(r io.Reader, baseDir string) (*Profile, error) {
	return parse(r, baseDir)
}

// parse is the parser proper. The exported entry points differ in one thing
// only: baseDir, the directory a "ca <file>" reference resolves against, and
// whether they have one at all.
func parse(r io.Reader, baseDir string) (*Profile, error) {
	a := newAssembler()

	scanner := bufio.NewScanner(r)
	var inlineTag string
	var inlineBuf bytes.Buffer
	lineNo := 0

	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())

		// Skip blank lines and comments.
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		// Inside an inline block: the body is opaque to the directive parser.
		// An unterminated block is not an error, here or in OpenVPN — the body
		// is consumed to end of file and closeBlock never runs, so nothing is
		// loaded from it.
		if inlineTag != "" {
			if line == "</"+inlineTag+">" {
				if err := a.closeBlock(inlineTag, inlineBuf.Bytes()); err != nil {
					return nil, err
				}
				inlineTag = ""
				inlineBuf.Reset()
			} else {
				inlineBuf.WriteString(line)
				inlineBuf.WriteByte('\n')
			}
			continue
		}

		// Opening inline block tag, for any tag name.
		if tag, ok := inlineOpenTag(line); ok {
			inlineTag = tag
			inlineBuf.Reset()
			a.openBlock(tag, lineNo)
			continue
		}

		// Markup, not a directive: a well-formed opening tag was consumed
		// above, so a line still starting with '<' is a stray closing tag or
		// malformed markup. No OpenVPN directive begins with '<', and
		// recording one would collide with the inline-block names the
		// capability registry uses.
		if strings.HasPrefix(line, "<") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		d := Directive{Name: strings.ToLower(fields[0]), Line: lineNo}
		if len(fields) > 1 {
			d.Args = append([]string(nil), fields[1:]...)
		}
		if err := a.directive(d); err != nil {
			return nil, err
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("profile: read: %w", err)
	}

	return a.finish(baseDir)
}

// inlineOpenTag reports whether line is an opening inline block tag such as
// "<tls-auth>", returning the tag name.
//
// A tag name is a non-empty run of letters, digits, '-' and '_'. Anything
// else — "<", "<>", "< ca >", "</ca>" — is not a tag, so a stray angle
// bracket cannot swallow the rest of the file.
func inlineOpenTag(line string) (string, bool) {
	if len(line) < 3 || line[0] != '<' || line[len(line)-1] != '>' {
		return "", false
	}
	tag := line[1 : len(line)-1]
	for i := 0; i < len(tag); i++ {
		c := tag[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z',
			c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return "", false
		}
	}
	return tag, true
}

// ParseString is a convenience wrapper around ParseFile for in-memory
// profiles.
//
// Like ParseFile it has no directory, so a profile naming its CA in a file is
// refused with ErrNoProfileDir rather than returned with an empty trust store.
func ParseString(s string) (*Profile, error) {
	return ParseFile(strings.NewReader(s))
}

// ParsePath opens path and parses it as an .ovpn profile file.
//
// It is the entry point that can resolve a "ca <file>" reference, because it
// is the only one that knows where the profile came from. Names are resolved
// against the profile's own directory and confined to it; see readConfined.
func ParsePath(path string) (*Profile, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("profile: open %s: %w", path, err)
	}
	defer f.Close()
	return parse(f, filepath.Dir(path))
}

// MSSFixMode says how a numeric mssfix value is measured. It is the directive's
// optional second word, and the three modes subtract different things before
// the result becomes an MSS.
type MSSFixMode int

const (
	// MSSFixLink counts the tunnel encapsulation — transport prefix, opcode,
	// packet id and crypto — but not the outer IP and UDP/TCP headers. This is
	// what a bare "mssfix N" means.
	MSSFixLink MSSFixMode = iota
	// MSSFixEncap counts the outer IP and UDP/TCP headers as well: "mssfix N mtu".
	MSSFixEncap
	// MSSFixFixed counts no encapsulation at all. The value is the payload
	// budget, less only the inner IPv4 and TCP headers: "mssfix N fixed".
	MSSFixFixed
)

// String names the mode as the directive spells it.
func (m MSSFixMode) String() string {
	switch m {
	case MSSFixEncap:
		return "mtu"
	case MSSFixFixed:
		return "fixed"
	default:
		return "link"
	}
}
