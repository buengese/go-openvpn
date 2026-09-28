package profile_test

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/buengese/go-openvpn/profile"
)

// render writes a Spec as the .ovpn text a file would have carried. It exists
// only so the equivalence property below has something to compare against: if
// Build and the parser agree on this text, they agree on the rules.
func render(t *testing.T, s profile.Spec) string {
	t.Helper()
	var b strings.Builder
	block := func(tag string, body []byte) {
		if len(body) > 0 {
			fmt.Fprintf(&b, "<%s>\n%s</%s>\n", tag, ensureNL(string(body)), tag)
		}
	}
	block("ca", s.CA)
	block("cert", s.Cert)
	block("key", s.Key)
	block("tls-auth", s.TLSAuth)
	block("tls-crypt", s.TLSCrypt)

	for _, r := range s.Remotes {
		switch {
		case r.Proto != "":
			port := r.Port
			if port == 0 {
				port = s.Port
			}
			if port == 0 {
				port = 1194
			}
			fmt.Fprintf(&b, "remote %s %d %s\n", r.Host, port, r.Proto)
		case r.Port != 0:
			fmt.Fprintf(&b, "remote %s %d\n", r.Host, r.Port)
		default:
			fmt.Fprintf(&b, "remote %s\n", r.Host)
		}
	}
	line := func(f string, a ...any) { fmt.Fprintf(&b, f+"\n", a...) }
	if s.Port != 0 {
		line("port %d", s.Port)
	}
	if s.Proto != "" {
		line("proto %s", s.Proto)
	}
	if s.KeyDirection != profile.KeyDirectionAbsent {
		line("key-direction %s", s.KeyDirection)
	}
	if s.AuthUserPass {
		line("auth-user-pass")
	}
	if s.AuthFederate {
		line("auth-federate")
	}
	if s.Cipher != "" {
		line("cipher %s", s.Cipher)
	}
	if s.Auth != "" {
		line("auth %s", s.Auth)
	}
	if s.RemoteCertTLSServer {
		line("remote-cert-tls server")
	}
	if s.NSCertTypeServer {
		line("ns-cert-type server")
	}
	if s.VerifyX509Name != "" {
		switch s.VerifyX509NameMatch {
		case profile.X509NameCN:
			line("verify-x509-name %s name", s.VerifyX509Name)
		case profile.X509NameCNPrefix:
			line("verify-x509-name %s name-prefix", s.VerifyX509Name)
		default:
			line("verify-x509-name %s", s.VerifyX509Name)
		}
	}
	if s.Compression != "" {
		line("%s", s.Compression)
	}
	if s.AllowCompression != "" {
		line("allow-compression %s", s.AllowCompression)
	}
	if s.TunMTU != 0 {
		line("tun-mtu %d", s.TunMTU)
	}
	switch {
	case s.MSSFixOff:
		line("mssfix 0")
	case s.MSSFix > 0:
		switch s.MSSFixMode {
		case profile.MSSFixEncap:
			line("mssfix %d mtu", s.MSSFix)
		case profile.MSSFixFixed:
			line("mssfix %d fixed", s.MSSFix)
		default:
			line("mssfix %d", s.MSSFix)
		}
	}
	switch {
	case s.NoReneg:
		line("reneg-sec 0")
	case s.RenegSec != 0:
		line("reneg-sec %d", s.RenegSec)
	}
	if s.RenegBytes != 0 {
		line("reneg-bytes %d", s.RenegBytes)
	}
	if s.HandWindow != 0 {
		line("hand-window %d", s.HandWindow)
	}
	if s.BecomePrimary != 0 {
		line("become-primary %d", s.BecomePrimary)
	}
	if s.Ping != 0 {
		line("ping %d", s.Ping)
	}
	if s.PingRestart != 0 {
		line("ping-restart %d", s.PingRestart)
	}
	if s.PingExit != 0 {
		line("ping-exit %d", s.PingExit)
	}
	if s.Keepalive.Interval != 0 || s.Keepalive.Timeout != 0 {
		line("keepalive %d %d", s.Keepalive.Interval, s.Keepalive.Timeout)
	}
	switch {
	case s.ExplicitExitNotifyBare:
		line("explicit-exit-notify")
	case s.ExplicitExitNotify != 0:
		line("explicit-exit-notify %d", s.ExplicitExitNotify)
	}
	if s.RemoteRandom {
		line("remote-random")
	}
	if s.RemoteRandomHostname {
		line("remote-random-hostname")
	}
	for _, v := range s.DNS.Servers {
		line("dhcp-option DNS %s", v)
	}
	for _, v := range s.DNS.SearchDomains {
		line("dhcp-option DOMAIN %s", v)
	}
	for _, v := range s.DNS.RouteDomains {
		line("dhcp-option DOMAIN-ROUTE %s", v)
	}
	for _, d := range s.Extra {
		line("%s", strings.TrimSpace(d.Name+" "+strings.Join(d.Args, " ")))
	}
	return b.String()
}

func ensureNL(s string) string {
	if strings.HasSuffix(s, "\n") {
		return s
	}
	return s + "\n"
}

// stripLines clears Line on every recorded directive and block. Build numbers
// them by the order it emits; a file numbers them by where they sit in it, and
// nothing reads the number except a human looking at a report.
func stripLines(p *profile.Profile) {
	for i := range p.Directives {
		p.Directives[i].Line = 0
	}
	for i := range p.InlineBlocks {
		p.InlineBlocks[i].Line = 0
	}
}

// 512 hex digits, which is the only length ParseStaticKey accepts.
var testStaticKey = "-----BEGIN OpenVPN Static key V1-----\n" +
	strings.Repeat("abcdef0123456789", 32) + "\n" +
	"-----END OpenVPN Static key V1-----\n"

const testCA = `-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKZ1x2Y3Z4Q5MA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNVBAMMCXRl
-----END CERTIFICATE-----
`

// TestBuildEqualsParse is the property the whole design rests on: a profile
// built from a Spec is the profile the parser would have produced from the
// equivalent file. Without it, Build is a second set of rules that will drift
// from the first.
func TestBuildEqualsParse(t *testing.T) {
	specs := map[string]profile.Spec{
		"bare remote": {
			Remotes: []profile.Endpoint{{Host: "vpn.example.test"}},
		},
		"certificate auth": {
			Remotes:             []profile.Endpoint{{Host: "vpn.example.test", Port: 1194}},
			CA:                  []byte(testCA),
			RemoteCertTLSServer: true,
		},
		"username and password over tcp": {
			Remotes:      []profile.Endpoint{{Host: "vpn.example.test", Port: 443, Proto: "tcp"}},
			CA:           []byte(testCA),
			AuthUserPass: true,
			Cipher:       "AES-256-CBC",
			Auth:         "SHA256",
			Compression:  "comp-lzo",
		},
		"tls-crypt wrapped": {
			Remotes:  []profile.Endpoint{{Host: "vpn.example.test"}},
			CA:       []byte(testCA),
			TLSCrypt: []byte(testStaticKey),
		},
		"tls-auth with a key direction": {
			Remotes:      []profile.Endpoint{{Host: "vpn.example.test"}},
			CA:           []byte(testCA),
			TLSAuth:      []byte(testStaticKey),
			KeyDirection: profile.KeyDirection1,
			Auth:         "SHA1",
		},
		"several remotes inheriting port and proto": {
			Remotes: []profile.Endpoint{
				{Host: "a.example.test"},
				{Host: "b.example.test", Port: 8443},
				{Host: "c.example.test", Port: 9443, Proto: "tcp"},
			},
			Port:         443,
			Proto:        "udp",
			RemoteRandom: true,
		},
		"timers, with keepalive outranking ping": {
			Remotes:     []profile.Endpoint{{Host: "vpn.example.test"}},
			Ping:        5,
			PingRestart: 30,
			Keepalive:   profile.Keepalive{Interval: 10, Timeout: 60},
		},
		"the tri-state opt-outs": {
			Remotes:   []profile.Endpoint{{Host: "vpn.example.test"}},
			MSSFixOff: true,
			NoReneg:   true,
		},
		"mssfix with a mode word": {
			Remotes:    []profile.Endpoint{{Host: "vpn.example.test"}},
			MSSFix:     1400,
			MSSFixMode: profile.MSSFixFixed,
			TunMTU:     1400,
		},
		"dns and x509 name": {
			Remotes:             []profile.Endpoint{{Host: "vpn.example.test"}},
			VerifyX509Name:      "server-1",
			VerifyX509NameMatch: profile.X509NameCN,
			DNS: profile.DNSOptions{
				Servers:       []string{"10.0.0.1", "10.0.0.2"},
				SearchDomains: []string{"corp.example.test"},
				RouteDomains:  []string{"internal.example.test"},
			},
		},
		// A file's directive names are case-folded by the parser, and
		// Compression is the only Spec field that carries one: unfolded, this
		// spec and the identical file put different bytes on the wire.
		"an upper-case compression directive": {
			Remotes:     []profile.Endpoint{{Host: "vpn.example.test"}},
			Compression: "COMP-LZO",
		},
		"everything else": {
			Remotes:                []profile.Endpoint{{Host: "vpn.example.test"}},
			AuthFederate:           true,
			NSCertTypeServer:       true,
			AllowCompression:       "no",
			RenegSec:               1800,
			RenegBytes:             1 << 20,
			HandWindow:             90,
			BecomePrimary:          45,
			PingExit:               20,
			ExplicitExitNotifyBare: true,
			RemoteRandomHostname:   true,
			Extra:                  []profile.Directive{{Name: "tls-version-min", Args: []string{"1.2"}}},
		},
	}

	for name, spec := range specs {
		t.Run(name, func(t *testing.T) {
			built, err := spec.Build()
			if err != nil {
				t.Fatalf("Build: %v", err)
			}
			text := render(t, spec)
			parsed, err := profile.ParseString(text)
			if err != nil {
				t.Fatalf("ParseString of the equivalent file: %v\n%s", err, text)
			}
			stripLines(built)
			stripLines(parsed)
			if !reflect.DeepEqual(built, parsed) {
				t.Errorf("Build and ParseString disagree.\nfile:\n%s\nbuilt:  %+v\nparsed: %+v", text, built, parsed)
			}
		})
	}
}

// TestBuildRefusesWhatAFileCouldNotSay covers the shapes a Spec can express
// but a profile cannot, which are exactly the ones that would let a caller
// build something the parser could never produce.
func TestBuildRefusesWhatAFileCouldNotSay(t *testing.T) {
	base := func() profile.Spec {
		return profile.Spec{Remotes: []profile.Endpoint{{Host: "vpn.example.test"}}}
	}
	for name, mutate := range map[string]func(*profile.Spec){
		"no remote":                  func(s *profile.Spec) { s.Remotes = nil },
		"both wrap keys":             func(s *profile.Spec) { s.TLSAuth, s.TLSCrypt = []byte(testStaticKey), []byte(testStaticKey) },
		"mssfix set and off":         func(s *profile.Spec) { s.MSSFix, s.MSSFixOff = 1400, true },
		"reneg set and disabled":     func(s *profile.Spec) { s.RenegSec, s.NoReneg = 1800, true },
		"ping-restart and ping-exit": func(s *profile.Spec) { s.PingRestart, s.PingExit = 30, 30 },
		"extra restates a field": func(s *profile.Spec) {
			s.Cipher = "AES-256-GCM"
			s.Extra = []profile.Directive{{Name: "cipher", Args: []string{"AES-128-GCM"}}}
		},
		"extra names a block":      func(s *profile.Spec) { s.Extra = []profile.Directive{{Name: "ca", Args: []string{"x"}}} },
		"argument with whitespace": func(s *profile.Spec) { s.Extra = []profile.Directive{{Name: "setenv", Args: []string{"a b"}}} },
		"unparseable proto":        func(s *profile.Spec) { s.Proto = "tcp-server" },
		"unusable static key":      func(s *profile.Spec) { s.TLSAuth = []byte("not a key") },
		// Compression is the one field that hands over a directive name, so
		// it is the one that can be handed a string naming no directive at
		// all — an empty strings.Fields result, where a neighbour returns.
		"compression is only whitespace": func(s *profile.Spec) { s.Compression = " " },
		// strings.Fields does not stop at a line break, so two lines weld
		// into one directive carrying the second line's words as arguments.
		"compression spans two lines": func(s *profile.Spec) { s.Compression = "comp-lzo\nno" },
		// The caller slip the round-trip guard exists to catch: the whole
		// directive written into Name with nothing in Args, which comes back
		// from the parser as a name carrying an argument.
		"extra name carries its argument": func(s *profile.Spec) {
			s.Extra = []profile.Directive{{Name: "tls-version-min 1.2"}}
		},
		// A name is the first word of a line, and these three characters
		// make a line something other than a directive: "<ca>" opens an
		// inline block, and the other two make the line a comment.
		"extra name opens an inline block": func(s *profile.Spec) {
			s.Extra = []profile.Directive{{Name: "<ca>"}}
		},
		"extra name is a comment": func(s *profile.Spec) {
			s.Extra = []profile.Directive{{Name: "#tls-version-min", Args: []string{"1.2"}}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			s := base()
			mutate(&s)
			if _, err := s.Build(); err == nil {
				t.Error("Build accepted a spec no profile could express")
			}
		})
	}
}

// FuzzBuildEqualsParse drives the same property over generated specs, the half
// that would notice a field added to Spec without a matching line in the
// renderer. A spec Build rejects is not interesting — Build is allowed to be
// stricter than a file; what must never happen is Build accepting something the
// parser then reads differently. Compression and Extra are generated because
// their contents are directive text rather than a typed value, so they are the
// two fields that can say something a file cannot.
func FuzzBuildEqualsParse(f *testing.F) {
	f.Add("vpn.example.test", 1194, "udp", "AES-256-GCM", "SHA256", 1500, 1400, 3600, 10, 60, true, false,
		"comp-lzo", "tls-version-min", "1.2")
	f.Add("a.test", 0, "", "", "", 0, 0, 0, 0, 0, false, false, "", "", "")
	f.Add("b.test", 443, "tcp", "AES-128-CBC", "SHA1", 1400, 0, 0, 5, 30, false, true,
		"compress lz4-v2", "", "")
	// Two seeds from this fuzzer: an empty host renders as "remote  1130" and
	// strings.Fields reads the port as the hostname, and a host of " 0"
	// renders as "remote  0 443" and is trimmed to "0". Build refuses any
	// argument that is not already one whitespace-free word.
	f.Add("", 1130, "", "", "", 0, 0, 0, 0, 0, false, false, "", "", "")
	f.Add(" 0", 443, "", "0", "0", 1400, 0, 0, 153, 30, true, true, "", "", "")
	// Four more seeds: " " indexes an empty strings.Fields result; "COMP-LZO"
	// builds a profile with compression off where the identical file parses to
	// comp-lzo; "0\n0" welds into one directive where the file holds two; and a
	// whole directive in Extra's Name comes back split into name and argument.
	f.Add("c.test", 0, "", "", "", 0, 0, 0, 0, 0, false, false, " ", "", "")
	f.Add("d.test", 0, "", "", "", 0, 0, 0, 0, 0, false, false, "COMP-LZO", "", "")
	f.Add("0", 13, "", "", "0", 0, 0, 0, 0, 91, true, false, "0\n0", "1", "0")
	f.Add("e.test", 0, "", "", "", 0, 0, 0, 0, 0, false, false, "", "tls-version-min 1.2", "")

	f.Fuzz(func(t *testing.T, host string, port int, proto, cipher, auth string,
		mtu, mssfix, reneg, ping, keepalive int, userpass, certtls bool,
		compression, extraName, extraArg string) {
		s := profile.Spec{
			Remotes:             []profile.Endpoint{{Host: host, Port: port, Proto: proto}},
			Cipher:              cipher,
			Auth:                auth,
			TunMTU:              mtu,
			MSSFix:              mssfix,
			RenegSec:            reneg,
			Ping:                ping,
			AuthUserPass:        userpass,
			RemoteCertTLSServer: certtls,
			Compression:         compression,
		}
		if keepalive > 0 {
			s.Keepalive = profile.Keepalive{Interval: keepalive, Timeout: keepalive * 6}
		}
		// An empty name with an argument is generated on purpose: it is the
		// one Extra shape Build refuses outright, and refusing it is what
		// keeps a nameless directive out of the rendered file.
		if extraName != "" || extraArg != "" {
			d := profile.Directive{Name: extraName}
			if extraArg != "" {
				d.Args = []string{extraArg}
			}
			s.Extra = []profile.Directive{d}
		}
		built, err := s.Build()
		if err != nil {
			return // stricter than a file is allowed; wrong is not
		}
		text := render(t, s)
		parsed, perr := profile.ParseString(text)
		if perr != nil {
			t.Fatalf("Build accepted a spec the parser refuses: %v\n%s", perr, text)
		}
		stripLines(built)
		stripLines(parsed)
		if !reflect.DeepEqual(built, parsed) {
			t.Fatalf("Build and ParseString disagree.\nfile:\n%s\nbuilt:  %+v\nparsed: %+v", text, built, parsed)
		}
	})
}

// ExampleSpec_Build shows the shape a caller writes when there is no file to
// read, and what the assembler fills in around it: the port and transport a
// remote did not name, and the cipher and digest an absent directive implies.
func ExampleSpec_Build() {
	p, err := profile.Spec{
		Remotes:             []profile.Endpoint{{Host: "vpn.example.test"}},
		CA:                  []byte(testCA),
		AuthUserPass:        true,
		RemoteCertTLSServer: true,
	}.Build()
	if err != nil {
		fmt.Println("build:", err)
		return
	}
	fmt.Printf("dial      %s:%d over %v\n", p.Remote, p.Port, p.Proto)
	fmt.Printf("cipher    %s, auth %s (explicit: %t)\n", p.Cipher, p.Auth, p.AuthSet)
	fmt.Printf("reneg-sec %d\n", p.RenegSec)
	fmt.Printf("needs credentials: %t\n", p.RequiresCredentials())
	// Output:
	// dial      vpn.example.test:1194 over udp
	// cipher    AES-256-GCM, auth SHA1 (explicit: false)
	// reneg-sec 3600
	// needs credentials: true
}
