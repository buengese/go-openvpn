package profile_test

import (
	"strings"
	"testing"

	"github.com/openlawsvpn/go-openlawsvpn/profile"
)

const minimal = `
client
remote vpn.example.com 443
proto tcp-client
cipher AES-256-GCM
auth SHA256
reneg-sec 3600

<ca>
-----BEGIN CERTIFICATE-----
MIIB...
-----END CERTIFICATE-----
</ca>

<cert>
-----BEGIN CERTIFICATE-----
MIIC...
-----END CERTIFICATE-----
</cert>

<key>
-----BEGIN RSA PRIVATE KEY-----
MIIE...
-----END RSA PRIVATE KEY-----
</key>
`

func TestParseMinimal(t *testing.T) {
	p, err := profile.ParseString(minimal)
	if err != nil {
		t.Fatal(err)
	}
	if p.Remote != "vpn.example.com" {
		t.Errorf("Remote = %q", p.Remote)
	}
	if p.Port != 443 {
		t.Errorf("Port = %d, want 443", p.Port)
	}
	if p.Proto != profile.ProtoTCP {
		t.Errorf("Proto = %v, want TCP", p.Proto)
	}
	if p.Cipher != "AES-256-GCM" {
		t.Errorf("Cipher = %q", p.Cipher)
	}
	if p.Auth != "SHA256" || !p.AuthSet {
		t.Errorf("Auth = %q (set %v), want SHA256 (set true)", p.Auth, p.AuthSet)
	}
	if p.RenegSec != 3600 {
		t.Errorf("RenegSec = %d, want 3600", p.RenegSec)
	}
	if !strings.Contains(string(p.CA), "BEGIN CERTIFICATE") {
		t.Error("CA PEM not parsed")
	}
	if !strings.Contains(string(p.Cert), "BEGIN CERTIFICATE") {
		t.Error("Cert PEM not parsed")
	}
	if !strings.Contains(string(p.Key), "BEGIN RSA PRIVATE KEY") {
		t.Error("Key PEM not parsed")
	}
}

func TestParseDefaults(t *testing.T) {
	p, err := profile.ParseString("remote vpn.example.com\n")
	if err != nil {
		t.Fatal(err)
	}
	if p.Port != 1194 {
		t.Errorf("default Port = %d, want 1194", p.Port)
	}
	if p.Proto != profile.ProtoUDP {
		t.Errorf("default Proto = %v, want UDP", p.Proto)
	}
	if p.Cipher != "AES-256-GCM" {
		t.Errorf("default Cipher = %q", p.Cipher)
	}
	if p.Auth != "SHA1" {
		t.Errorf("default Auth = %q, want SHA1 (OpenVPN's built-in default)", p.Auth)
	}
	if p.AuthSet {
		t.Error("default AuthSet = true, want false: the profile said nothing about auth")
	}
	if p.Verb != 3 {
		t.Errorf("default Verb = %d, want 3", p.Verb)
	}
}

// TestParseAuthDigest pins the digest the parser reports for every shape of the
// 'auth' directive, absent included. OpenVPN's built-in default is SHA1, and for
// a profile carrying no 'auth' directive the default alone decides what it
// advertises and therefore what its server agrees to.
func TestParseAuthDigest(t *testing.T) {
	tests := []struct {
		name    string
		config  string
		want    string
		wantSet bool
	}{
		{
			name:   "absent yields the SHA1 default",
			config: "remote vpn.example.test 443\n",
			want:   "SHA1",
		},
		{
			name:   "absent with a CBC cipher still yields SHA1",
			config: "remote vpn.example.test 443\ncipher AES-256-CBC\n",
			want:   "SHA1",
		},
		{
			name:    "explicit SHA1 is indistinguishable in value, not in AuthSet",
			config:  "remote vpn.example.test 443\nauth SHA1\n",
			want:    "SHA1",
			wantSet: true,
		},
		{
			name:    "explicit SHA256",
			config:  "remote vpn.example.test 443\nauth SHA256\n",
			want:    "SHA256",
			wantSet: true,
		},
		{
			name:    "explicit SHA512",
			config:  "remote vpn.example.test 443\nauth SHA512\n",
			want:    "SHA512",
			wantSet: true,
		},
		{
			name:    "lowercase is upcased",
			config:  "remote vpn.example.test 443\nauth sha512\n",
			want:    "SHA512",
			wantSet: true,
		},
		{
			name:    "the last directive wins, as it does in OpenVPN",
			config:  "remote vpn.example.test 443\nauth SHA1\nauth SHA512\n",
			want:    "SHA512",
			wantSet: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := profile.ParseString(tt.config)
			if err != nil {
				t.Fatal(err)
			}
			if p.Auth != tt.want {
				t.Errorf("Auth = %q, want %q", p.Auth, tt.want)
			}
			if p.AuthSet != tt.wantSet {
				t.Errorf("AuthSet = %v, want %v", p.AuthSet, tt.wantSet)
			}
		})
	}
}

// TestParseAuthPrefixedDirectivesLeaveDigestAlone pins that in an .ovpn file
// 'auth' is the packet HMAC digest and nothing else: the directives that merely
// begin with "auth" are unrelated, and a prefix match would hand every
// auth-user-pass profile a digest of "creds.txt".
func TestParseAuthPrefixedDirectivesLeaveDigestAlone(t *testing.T) {
	tests := []struct {
		name string
		line string
	}{
		{"auth-user-pass", "auth-user-pass"},
		{"auth-user-pass with a file argument", "auth-user-pass creds.txt"},
		{"auth-nocache", "auth-nocache"},
		{"auth-retry", "auth-retry nointeract"},
		{"auth-federate", "auth-federate"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := profile.ParseString("remote vpn.example.test 443\n" + tt.line + "\n")
			if err != nil {
				t.Fatal(err)
			}
			if p.AuthSet {
				t.Errorf("AuthSet = true: %q was mistaken for an auth directive", tt.line)
			}
			if p.Auth != "SHA1" {
				t.Errorf("Auth = %q, want the SHA1 default: %q must not set the digest", p.Auth, tt.line)
			}
			// It is still recorded verbatim for the capability preflight.
			keyword := strings.Fields(tt.line)[0]
			var seen bool
			for _, d := range p.Directives {
				if d.Name == keyword {
					seen = true
				}
			}
			if !seen {
				t.Errorf("%q not recorded on Directives", keyword)
			}
		})
	}
}

// TestParseNumericDirectives covers the directives whose whole argument is a
// number, and the value the field takes when the directive is absent. Each case
// is one line added to the same minimal profile.
func TestParseNumericDirectives(t *testing.T) {
	for _, tc := range []struct {
		name string
		src  string
		get  func(*profile.Profile) int64
		want int64
	}{
		{"verb", "verb 4\n", func(p *profile.Profile) int64 { return int64(p.Verb) }, 4},
		{"reneg-sec", "reneg-sec 7200\n", func(p *profile.Profile) int64 { return int64(p.RenegSec) }, 7200},
		{
			// Zero is not "unset": it disables client-initiated rekey.
			name: "reneg-sec 0 disables client rekey",
			src:  "reneg-sec 0\n",
			get:  func(p *profile.Profile) int64 { return int64(p.RenegSec) },
			want: 0,
		},
		{
			name: "absent reneg-sec takes OpenVPN's default",
			src:  "",
			get:  func(p *profile.Profile) int64 { return int64(p.RenegSec) },
			want: 3600,
		},
		{"reneg-bytes", "reneg-bytes 10485760\n", func(p *profile.Profile) int64 { return p.RenegBytes }, 10485760},
		{"become-primary", "become-primary 5\n", func(p *profile.Profile) int64 { return int64(p.BecomePrimarySec) }, 5},
		{"tun-mtu", "tun-mtu 1400\n", func(p *profile.Profile) int64 { return int64(p.TunMTU) }, 1400},
		{
			// Zero means "the profile said nothing", not an MTU of zero.
			name: "absent tun-mtu leaves the field unset",
			src:  "",
			get:  func(p *profile.Profile) int64 { return int64(p.TunMTU) },
			want: 0,
		},
		{"mssfix", "mssfix 1200\n", func(p *profile.Profile) int64 { return int64(p.MSSFix) }, 1200},
		{
			// mssfix 0 is valid and means "disabled".
			name: "mssfix 0",
			src:  "mssfix 0\n",
			get:  func(p *profile.Profile) int64 { return int64(p.MSSFix) },
			want: 0,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := profile.ParseString("remote vpn.example.test 443\n" + tc.src)
			if err != nil {
				t.Fatalf("ParseString(%q): %v", tc.src, err)
			}
			if got := tc.get(p); got != tc.want {
				t.Errorf("%q parsed to %d, want %d", tc.src, got, tc.want)
			}
		})
	}
}

// TestParseRejectsOutOfRangeArguments is the refusal half of the numeric
// directives: an argument outside the range, or not a number at all, is a
// parse error rather than a silently clamped value.
func TestParseRejectsOutOfRangeArguments(t *testing.T) {
	for _, src := range []string{
		"verb 12\n",
		"tun-mtu 0\n",
		"tun-mtu abc\n",
		"tun-mtu 65536\n",
		"tun-mtu -1\n",
		"mssfix abc\n",
		"mssfix -1\n",
	} {
		t.Run(strings.TrimSpace(src), func(t *testing.T) {
			if _, err := profile.ParseString("remote vpn.example.test 443\n" + src); err == nil {
				t.Errorf("ParseString(%q) succeeded, want an error", src)
			}
		})
	}
}

// TestParseMSSFixSetSeparatesZeroFromAbsent is why MSSFix has a companion
// flag. "mssfix 0" disables the clamp and a bare "mssfix" asks for OpenVPN's
// own default, so the number alone cannot say which the profile wrote.
func TestParseMSSFixSetSeparatesZeroFromAbsent(t *testing.T) {
	explicit, err := profile.ParseString("remote vpn.example.test 443\nmssfix 0\n")
	if err != nil {
		t.Fatal(err)
	}
	if !explicit.MSSFixSet {
		t.Error("MSSFixSet = false for an explicit mssfix 0")
	}
	bare, err := profile.ParseString("remote vpn.example.test 443\nmssfix\n")
	if err != nil {
		t.Fatal(err)
	}
	if bare.MSSFixSet {
		t.Error("MSSFixSet = true for a bare mssfix, which names no value")
	}
}

func TestParseStaticDNSOptions(t *testing.T) {
	p, err := profile.ParseString(`
remote vpn.example.test
dhcp-option DNS 10.130.0.2
dhcp-option DOMAIN corp.example.test
dhcp-option DOMAIN-ROUTE internal.company.com
dhcp-option DOMAIN-ROUTE us-east-2.eks.amazonaws.com
`)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := len(p.DNS.Servers), 1; got != want || p.DNS.Servers[0].String() != "10.130.0.2" {
		t.Errorf("DNS servers = %v, want [10.130.0.2]", p.DNS.Servers)
	}
	if got, want := p.DNS.SearchDomains, []string{"corp.example.test"}; strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("search domains = %v, want %v", got, want)
	}
	if got, want := p.DNS.RouteDomains, []string{"internal.company.com", "us-east-2.eks.amazonaws.com"}; strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("route domains = %v, want %v", got, want)
	}
}

func TestParseComments(t *testing.T) {
	cfg := `
# This is a comment
; And this
remote vpn.example.com 1194
`
	p, err := profile.ParseString(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if p.Remote != "vpn.example.com" {
		t.Errorf("Remote = %q", p.Remote)
	}
}

func TestParsePathMissing(t *testing.T) {
	_, err := profile.ParsePath("/nonexistent/path/test.ovpn")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestAuthFederateForcesSAMLFlow(t *testing.T) {
	p, err := profile.ParseString("remote vpn.example.test 443\nauth-federate\n")
	if err != nil {
		t.Fatal(err)
	}
	if !p.ForceSAMLFlow {
		t.Fatal("ForceSAMLFlow = false, want true")
	}
	if got := p.DetectFlow(); got != profile.FlowAWSSSO {
		t.Errorf("DetectFlow() = %v, want FlowAWSSSO", got)
	}
}

func TestParseRecordsDirectives(t *testing.T) {
	p, err := profile.ParseString(minimal)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"client", "remote", "proto", "cipher", "auth", "reneg-sec"}
	if len(p.Directives) != len(want) {
		t.Fatalf("Directives = %v, want %d entries", p.Directives, len(want))
	}
	for i, name := range want {
		if p.Directives[i].Name != name {
			t.Errorf("Directives[%d].Name = %q, want %q", i, p.Directives[i].Name, name)
		}
		if p.Directives[i].Line <= 0 {
			t.Errorf("Directives[%d].Line = %d, want positive", i, p.Directives[i].Line)
		}
	}
	if got := p.Directives[1].String(); got != "remote vpn.example.com 443" {
		t.Errorf("Directives[1].String() = %q", got)
	}
	if len(p.Directives[0].Args) != 0 {
		t.Errorf("bare directive kept args: %v", p.Directives[0].Args)
	}
}

func TestParseRecordsUnrecognisedDirectives(t *testing.T) {
	p, err := profile.ParseString("remote vpn.example.com 443\nfast-io\nsndbuf 524288\n")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string][]string{}
	for _, d := range p.Directives {
		got[d.Name] = d.Args
	}
	if _, ok := got["fast-io"]; !ok {
		t.Error("fast-io not recorded")
	}
	if args := got["sndbuf"]; len(args) != 1 || args[0] != "524288" {
		t.Errorf("sndbuf args = %v, want [524288]", args)
	}
}

func TestParseInlineBlocksStillLoadCertAndKey(t *testing.T) {
	p, err := profile.ParseString(minimal)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.CA) == 0 || len(p.Cert) == 0 || len(p.Key) == 0 {
		t.Fatalf("CA/Cert/Key = %d/%d/%d bytes, want all non-empty", len(p.CA), len(p.Cert), len(p.Key))
	}
	var tags []string
	for _, b := range p.InlineBlocks {
		tags = append(tags, b.Tag)
	}
	if got := strings.Join(tags, ","); got != "ca,cert,key" {
		t.Errorf("InlineBlocks = %q, want ca,cert,key", got)
	}
}

// TestParseInlineBlockTagsAreCaseInsensitive pins the tag spelling for the
// three blocks whose bodies are loaded. openBlock records the tag whatever its
// case and the capability registry folds it, so closeBlock has to fold too, or
// <CA> is recorded as present with CA left empty.
//
// The tolerant reading is the one this package already takes for directive
// names. It is more tolerant than the reference: openvpn3-core keys its option
// map on the tag verbatim (common/options.hpp update_map), so <CA> reaches no
// lookup for "ca" there and the block is silently unused.
func TestParseInlineBlockTagsAreCaseInsensitive(t *testing.T) {
	const body = "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n"
	for _, tc := range []struct {
		tag  string
		want func(*profile.Profile) int
	}{
		{"CA", func(p *profile.Profile) int { return len(p.CA) }},
		{"Cert", func(p *profile.Profile) int { return len(p.Cert) }},
		{"KEY", func(p *profile.Profile) int { return len(p.Key) }},
	} {
		t.Run(tc.tag, func(t *testing.T) {
			p, err := profile.ParseString("remote vpn.example.com 443\n" +
				"<" + tc.tag + ">\n" + body + "</" + tc.tag + ">\n")
			if err != nil {
				t.Fatal(err)
			}
			if tc.want(p) == 0 {
				t.Errorf("<%s> was recorded as present but its body was loaded nowhere", tc.tag)
			}
			if len(p.InlineBlocks) != 1 || p.InlineBlocks[0].Tag != tc.tag {
				t.Errorf("InlineBlocks = %v, want the tag as the file spelled it", p.InlineBlocks)
			}
		})
	}
}

// TestParseInlineBlockClosesOnlyOnItsOwnTag pins the closing tag, which is the
// half that stays exact. openvpn3-core compares it to the opening one byte for
// byte (common/options.hpp is_close_tag), and matching loosely here would let a
// stray "</x>" in a certificate body end the block early.
func TestParseInlineBlockClosesOnlyOnItsOwnTag(t *testing.T) {
	for _, closer := range []string{"</CA>", "</cert>", "</x>"} {
		t.Run(closer, func(t *testing.T) {
			p, err := profile.ParseString("remote vpn.example.com 443\n" +
				"<ca>\nMIIB...\n" + closer + "\nfast-io\n")
			if err != nil {
				t.Fatal(err)
			}
			// The block never closed, so it consumed "fast-io" too and
			// the body was loaded nowhere — OpenVPN's behaviour for an
			// unterminated block.
			if len(p.CA) != 0 {
				t.Errorf("%s closed the <ca> block: CA = %q", closer, p.CA)
			}
			for _, d := range p.Directives {
				if d.Name == "fast-io" {
					t.Errorf("%s closed the <ca> block: %q escaped the body", closer, d.Name)
				}
			}
		})
	}
}

// TestParseRemoteRandomHostname pins a directive the dialer reads on both
// paths: connect.go hands Remote to randomSubdomain when this is set, and an
// endpoint whose bare hostname has no DNS record is unreachable without it.
func TestParseRemoteRandomHostname(t *testing.T) {
	p, err := profile.ParseString("remote vpn.example.com 443\nremote-random-hostname\n")
	if err != nil {
		t.Fatal(err)
	}
	if !p.RandomHostname {
		t.Error("RandomHostname = false, want true")
	}
	// Distinct from remote-random, which shuffles the list instead.
	if p.RemoteRandom {
		t.Error("RemoteRandom = true: remote-random-hostname is not remote-random")
	}

	q, err := profile.ParseString("remote vpn.example.com 443\nremote-random\n")
	if err != nil {
		t.Fatal(err)
	}
	if q.RandomHostname {
		t.Error("remote-random set RandomHostname")
	}
	if !q.RemoteRandom {
		t.Error("RemoteRandom = false, want true")
	}
}

// TestParseFlowDirectiveAsksForSAML covers x-openlawsvpn-flow, this project's
// own directive rather than OpenVPN's: it is how a server asks for the
// federated flow, and "saml" is the only argument it answers to. A bare
// directive, or one naming anything else, must not put the client on a browser
// flow.
func TestParseFlowDirectiveAsksForSAML(t *testing.T) {
	for _, tc := range []struct {
		line string
		want bool
	}{
		{"x-openlawsvpn-flow saml", true},
		// The argument is folded, like the directive name above it.
		{"x-openlawsvpn-flow SAML", true},
		{"x-openlawsvpn-flow Saml", true},
		{"x-openlawsvpn-flow", false},
		{"x-openlawsvpn-flow cert", false},
		{"x-openlawsvpn-flow samlx", false},
	} {
		t.Run(tc.line, func(t *testing.T) {
			p, err := profile.ParseString("remote vpn.example.com 443\n" + tc.line + "\n")
			if err != nil {
				t.Fatal(err)
			}
			if p.ForceSAMLFlow != tc.want {
				t.Errorf("ForceSAMLFlow = %t, want %t", p.ForceSAMLFlow, tc.want)
			}
			wantFlow := profile.FlowUserPass
			if tc.want {
				wantFlow = profile.FlowAWSSSO
			}
			if got := p.DetectFlow(); got != wantFlow {
				t.Errorf("DetectFlow() = %v, want %v", got, wantFlow)
			}
		})
	}
}

func TestParseMalformedTagsAreNeitherBlocksNorDirectives(t *testing.T) {
	// "<>", "< ca >" and a stray "</ca>" are not tags. They must not open a
	// block and swallow the rest of the file, and they must not be recorded
	// as directives under a name that collides with the block namespace.
	p, err := profile.ParseString("remote vpn.example.com 443\n<>\n< ca >\n</ca>\nfast-io\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(p.InlineBlocks) != 0 {
		t.Errorf("InlineBlocks = %v, want none", p.InlineBlocks)
	}
	var names []string
	for _, d := range p.Directives {
		if strings.HasPrefix(d.Name, "<") {
			t.Errorf("markup recorded as directive: %q", d.Name)
		}
		names = append(names, d.Name)
	}
	if got := strings.Join(names, " "); got != "remote fast-io" {
		t.Errorf("directives = %q, want \"remote fast-io\"", got)
	}
}

// TestMSSFixModeParsesTheSecondWord covers the word that decides how the mssfix
// number is measured. Discarding it makes every explicit "mssfix N" behave as
// "mssfix N mtu", which subtracts an outer IP and UDP header the directive did
// not ask about — 28 bytes of MSS on every clamped segment.
func TestMSSFixModeParsesTheSecondWord(t *testing.T) {
	for _, tc := range []struct {
		directive string
		wantMode  profile.MSSFixMode
	}{
		{"mssfix 1400", profile.MSSFixLink},
		{"mssfix 1400 mtu", profile.MSSFixEncap},
		{"mssfix 1400 fixed", profile.MSSFixFixed},
		// The reference warns and carries on rather than refusing
		// (options.c:7341-7343), so an unknown word keeps the default.
		{"mssfix 1400 nonsense", profile.MSSFixLink},
	} {
		t.Run(tc.directive, func(t *testing.T) {
			p, err := profile.ParseString("client\nremote example.com 1194\n" + tc.directive + "\n")
			if err != nil {
				t.Fatalf("Parse(%q): %v", tc.directive, err)
			}
			if !p.MSSFixSet || p.MSSFix != 1400 {
				t.Fatalf("MSSFix = %d (set=%v), want 1400 set", p.MSSFix, p.MSSFixSet)
			}
			if p.MSSFixMode != tc.wantMode {
				t.Errorf("MSSFixMode = %v, want %v", p.MSSFixMode, tc.wantMode)
			}
		})
	}
}
