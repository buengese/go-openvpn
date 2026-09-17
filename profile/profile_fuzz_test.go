package profile_test

import (
	"strings"
	"testing"

	"github.com/openlawsvpn/go-openlawsvpn/profile"
)

// FuzzParseString feeds random strings to ParseString to verify it never
// panics. Profile files are read from disk but may also come from untrusted
// sources (MDM push, CI pipelines, etc.).
func FuzzParseString(f *testing.F) {
	// Seed: minimal valid profile.
	f.Add("remote vpn.example.com 443\nproto tcp-client\n")
	// Seed: AWS Client VPN profile structure.
	f.Add("remote cvpn-endpoint-abc123.amazonaws.com 443\nproto tcp-client\nremote-random-hostname\nverify-x509-name mtlab.ai\n")
	// Seed: with inline CA block.
	f.Add("remote vpn.example.com 1194\nproto udp\n<ca>\n-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n</ca>\n")
	// Seed: all directives.
	f.Add("remote vpn.example.com 443\nproto tcp-client\ncipher AES-128-GCM\nauth SHA512\nreneg-sec 3600\nreneg-bytes 10000000\ntun-mtu 1400\nmssfix 1350\n")
	// Seed: missing remote (should error, not panic).
	f.Add("proto tcp-client\ncipher AES-256-GCM\n")
	// Seed: empty.
	f.Add("")
	// Seed: only comments.
	f.Add("# comment\n; another comment\n")
	// Seed: invalid port.
	f.Add("remote vpn.example.com 99999\n")
	// Seed: long lines.
	f.Add("remote " + strings.Repeat("a", 1000) + ".example.com 443\nproto tcp-client\n")
	// Seed: unclosed inline block.
	f.Add("remote vpn.example.com 443\nproto tcp-client\n<ca>\n-----BEGIN CERTIFICATE-----\nMIIB\n")
	// Seed: nested-looking tags.
	f.Add("remote vpn.example.com 443\nproto tcp-client\n<ca>\n<cert>\n-----END CERTIFICATE-----\n</ca>\n")

	f.Fuzz(func(t *testing.T, s string) {
		_, _ = profile.ParseString(s)
	})
}

// blockBodyLines is an independent, deliberately naive implementation of the
// parser's inline-block rules. It is the oracle FuzzParseRecording checks the
// parser against: no line it reports may ever surface as a directive.
func blockBodyLines(s string) map[int]bool {
	body := map[int]bool{}
	inside := ""
	for i, raw := range strings.Split(s, "\n") {
		line := strings.TrimSpace(raw)
		if inside != "" {
			if line == "</"+inside+">" {
				inside = ""
			} else {
				body[i+1] = true
			}
			continue
		}
		if len(line) < 3 || line[0] != '<' || line[len(line)-1] != '>' {
			continue
		}
		tag := line[1 : len(line)-1]
		if strings.TrimFunc(tag, func(r rune) bool {
			return r == '-' || r == '_' ||
				(r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
		}) == "" {
			inside = tag
		}
	}
	return body
}

// FuzzParseRecording exercises the directive- and inline-block-recording path
// the capability preflight reads: line numbers are real and ordered, directive
// names are normalised, and — the one that matters — nothing inside an inline
// block ever becomes a directive.
func FuzzParseRecording(f *testing.F) {
	f.Add("remote vpn.example.com 443\nproto tcp-client\nfast-io\nsndbuf 524288\n")
	// Unclosed non-standard block: must not resurface as directives.
	f.Add("remote vpn.example.com 1194\n<tls-auth>\nAAAA\nBBBB\n")
	// Stray and malformed tags.
	f.Add("remote vpn.example.com 1194\n</ca>\n<>\n< ca >\n<a b>\nfast-io\n")
	// A tag name that is also a directive keyword.
	f.Add("remote vpn.example.com 1194\n<cipher>\nAES-256-CBC\n</cipher>\n")
	// Two remotes, as a failover profile ships them.
	f.Add("remote a.example.com 1195\nremote 203.0.113.9 1195\nproto tcp\n")

	f.Fuzz(func(t *testing.T, s string) {
		p, err := profile.ParseString(s)
		if err != nil {
			return
		}
		lines := strings.Split(s, "\n")
		body := blockBodyLines(s)

		prev := 0
		for _, d := range p.Directives {
			if d.Line <= prev {
				t.Fatalf("directive lines not increasing: %d after %d", d.Line, prev)
			}
			prev = d.Line
			if d.Line > len(lines) {
				t.Fatalf("directive line %d beyond input (%d lines)", d.Line, len(lines))
			}
			if d.Name == "" || strings.ContainsAny(d.Name, " \t") || strings.HasPrefix(d.Name, "<") {
				t.Fatalf("malformed directive name %q", d.Name)
			}
			if d.Name != strings.ToLower(d.Name) {
				t.Fatalf("directive name not lowercased: %q", d.Name)
			}
			if body[d.Line] {
				t.Fatalf("inline block body recorded as directive %q at line %d", d.Name, d.Line)
			}
			fields := strings.Fields(strings.TrimSpace(lines[d.Line-1]))
			if len(fields) == 0 || strings.ToLower(fields[0]) != d.Name {
				t.Fatalf("directive %q does not match source line %d: %q", d.Name, d.Line, lines[d.Line-1])
			}
			if len(d.Args) != len(fields)-1 {
				t.Fatalf("directive %q recorded %d args, source line has %d", d.Name, len(d.Args), len(fields)-1)
			}
		}

		prev = 0
		tags := map[string]bool{}
		for _, b := range p.InlineBlocks {
			if b.Line <= prev {
				t.Fatalf("block lines not increasing: %d after %d", b.Line, prev)
			}
			prev = b.Line
			if b.Tag == "" || strings.ContainsAny(b.Tag, " \t<>/") {
				t.Fatalf("malformed block tag %q", b.Tag)
			}
			if body[b.Line] {
				t.Fatalf("block opener %q recorded inside another block at line %d", b.Tag, b.Line)
			}
			tags[strings.ToLower(b.Tag)] = true
		}
	})
}
