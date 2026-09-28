package profile_test

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/buengese/go-openvpn/profile"
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
	// Seed: a well-formed wrap key in the shape a real config ships.
	f.Add(wrappedProfile("tls-auth", testKeyFill, "key-direction 1\n"))
	// Seed: a wrap key one digit short — the parse now fails rather than
	// dropping the block, so the failure path needs seeding too.
	f.Add("remote vpn.example.com 1194\n<tls-crypt>\n" +
		staticKeyHex(testKeyFill)[:511] + "\n</tls-crypt>\n")

	f.Fuzz(func(t *testing.T, s string) {
		_, _ = profile.ParseString(s)
	})
}

// hexRun is the longest run of consecutive hexadecimal digits in s.
func hexRun(s string) int {
	longest, run := 0, 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') {
			run++
			if run > longest {
				longest = run
			}
			continue
		}
		run = 0
	}
	return longest
}

// maxErrorHexRun bounds how many consecutive hex digits a static-key error
// message may contain. Sixteen is eight bytes of key: more than enough to make
// a leak visible, far more than a line number or a count could reach.
const maxErrorHexRun = 16

// FuzzParseStaticKey feeds random bytes to ParseStaticKey, whose input, unlike
// the rest of the parser's, is key material. Two invariants: a success is
// exactly 256 bytes and decodes back to the digits it was built from, and a
// failure names what is wrong without echoing any of it — the leading half of a
// truncated tls-auth key is the whole of the send HMAC key.
func FuzzParseStaticKey(f *testing.F) {
	f.Add([]byte(staticKeyBlock(testKeyFill)))
	f.Add([]byte(staticKeyHex(testKeyFill)))
	f.Add([]byte(strings.ToUpper(staticKeyHex(testKeyFill))))
	f.Add([]byte("#\n# 2048 bit OpenVPN static key\n#\n" + staticKeyBlock(testKeyFill)))
	f.Add([]byte(staticKeyHex(testKeyFill)[:511]))
	f.Add([]byte(staticKeyHex(testKeyFill) + "00"))
	f.Add([]byte("-----BEGIN OpenVPN Static key V1-----\n"))
	f.Add([]byte(""))
	f.Add([]byte("zz"))
	f.Add([]byte("\r\n\t \n;x\n#y\n"))

	f.Fuzz(func(t *testing.T, body []byte) {
		key, err := profile.ParseStaticKey(body)
		if err != nil {
			if key != nil {
				t.Fatal("a key came back alongside an error")
			}
			if n := hexRun(err.Error()); n > maxErrorHexRun {
				t.Fatalf("error message carries a run of %d hex digits, "+
					"which is key material: %q", n, err.Error())
			}
			return
		}
		if key == nil {
			t.Fatal("no key and no error")
		}
		if len(key) != profile.StaticKeySize {
			t.Fatalf("key is %d bytes, want %d", len(key), profile.StaticKeySize)
		}
		// Round-trip: the canonical rendering of what we parsed must parse
		// back to the same bytes. A parser that dropped or duplicated digits
		// would still return 256 bytes, and this is what notices.
		again, err := profile.ParseStaticKey([]byte(hex.EncodeToString(key[:])))
		if err != nil {
			t.Fatalf("re-parsing a parsed key failed: %v", err)
		}
		if *again != *key {
			t.Fatal("re-parsing a parsed key produced different bytes")
		}
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
	f.Add(wrappedProfile("tls-auth", testKeyFill, "key-direction 1\n"))
	f.Add("remote vpn.example.com 1194\n<tls-crypt>\n" + staticKeyBlock(testKeyFill) +
		"</tls-crypt>\n<ca>\nMIIB\n</ca>\n")
	// A wrap block whose body is not a key: the parse fails, so this seed
	// exercises the error path rather than the recording invariants.
	f.Add("remote vpn.example.com 1194\nkey-direction 1\n<tls-auth>\ndeadbeef\n</tls-auth>\n")
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

		// A loaded wrap key must have come from a recorded block. The two
		// records are built in different places, and the capability preflight
		// would understate a profile whose key arrived some other way.
		if p.TLSAuth != nil && !tags["tls-auth"] {
			t.Fatal("a tls-auth key was loaded with no <tls-auth> block recorded")
		}
		if p.TLSCrypt != nil && !tags["tls-crypt"] {
			t.Fatal("a tls-crypt key was loaded with no <tls-crypt> block recorded")
		}
		// An absent key-direction is its own value, so a profile that
		// recorded no key-direction directive must not report one.
		if _, given := p.KeyDirection.Value(); given {
			found := false
			for _, d := range p.Directives {
				if d.Name == "key-direction" {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("KeyDirection = %v with no key-direction directive", p.KeyDirection)
			}
		}
	})
}
