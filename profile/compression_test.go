// Parser tests for the compression directives. A profile that carries one and
// parses it into nothing reaches the data channel believing there is no
// framing.
//
// TestCompressionDirectives in fixtures_test.go holds the parsing to the
// framing each spelling names.
// What is here is the shape of the parse — every spelling, including the ones
// deployed profiles do not use, and the refusals.
package profile_test

import (
	"strings"
	"testing"

	"github.com/buengese/go-openvpn/internal/compress"
	"github.com/buengese/go-openvpn/profile"
)

// compressionProfile wraps src in the smallest profile ParseString accepts.
func compressionProfile(src string) string {
	return strings.Join([]string{"client", "dev tun", "remote host.example.test 1194", src}, "\n") + "\n"
}

// TestParseCompressionDirectives covers every spelling OpenVPN accepts, and
// the two that decide the framing rather than the algorithm: bare "compress"
// carries COMP_F_SWAP and "comp-lzo no" does not, though both select
// COMP_ALG_STUB and neither ever compresses.
func TestParseCompressionDirectives(t *testing.T) {
	cases := []struct {
		src  string
		want compress.Mode
	}{
		{"", compress.ModeNone},
		{"comp-lzo", compress.ModeLZO},
		{"comp-lzo yes", compress.ModeLZO},
		{"comp-lzo adaptive", compress.ModeLZO},
		{"comp-lzo no", compress.ModeStubNoSwap},
		{"compress", compress.ModeStub},
		{"compress stub", compress.ModeStub},
		{"compress stub-v2", compress.ModeStubV2},
		{"compress lzo", compress.ModeLZO},
		{"compress lz4", compress.ModeLZ4},
		{"compress lz4-v2", compress.ModeLZ4v2},
		// OpenVPN applies its options in order, so the last one wins.
		{"comp-lzo\ncompress stub-v2", compress.ModeStubV2},
		// Case is folded, as it is for every other directive argument.
		{"COMPRESS LZ4", compress.ModeLZ4},
	}
	for _, tc := range cases {
		p, err := profile.ParseString(compressionProfile(tc.src))
		if err != nil {
			t.Errorf("ParseString(%q): %v", tc.src, err)
			continue
		}
		if p.Compression != tc.want {
			t.Errorf("%q parsed to %v, want %v", tc.src, p.Compression, tc.want)
		}
	}
}

// TestParseAllowCompressionDirective covers the policy directive. Profiles
// carry "allow-compression no", and a parser that reads no compression
// directive at all honours it by accident: there is nothing to refuse.
func TestParseAllowCompressionDirective(t *testing.T) {
	cases := []struct {
		src  string
		want compress.AllowCompression
	}{
		{"", compress.AllowUnset},
		{"allow-compression no", compress.AllowNo},
		{"allow-compression asym", compress.AllowAsym},
		{"allow-compression yes", compress.AllowYes},
	}
	for _, tc := range cases {
		p, err := profile.ParseString(compressionProfile(tc.src))
		if err != nil {
			t.Errorf("ParseString(%q): %v", tc.src, err)
			continue
		}
		if p.AllowCompression != tc.want {
			t.Errorf("%q parsed to %v, want %v", tc.src, p.AllowCompression, tc.want)
		}
	}
}

// TestParseCompressionRefusesWhatOpenVPNRefuses keeps the parser from
// inventing a mode for a directive OpenVPN would reject. A profile that names
// an algorithm nobody implements is a config error, and saying so is more use
// than silently framing it as something else.
func TestParseCompressionRefusesWhatOpenVPNRefuses(t *testing.T) {
	for _, src := range []string{
		"comp-lzo maybe",
		"compress snappy",
		"compress lzo-v9",
		"allow-compression",
		"allow-compression sometimes",
	} {
		if _, err := profile.ParseString(compressionProfile(src)); err == nil {
			t.Errorf("ParseString(%q) succeeded; OpenVPN refuses this directive", src)
		}
	}
}

// TestCompressionSurvivesAllowCompressionNo states the interaction the parser
// does *not* resolve. Both fields are recorded as the file wrote them;
// reconciling them is compress.EffectiveMode's job, at the point where the
// server's pushed directive is also known.
func TestCompressionSurvivesAllowCompressionNo(t *testing.T) {
	p, err := profile.ParseString(compressionProfile("comp-lzo\nallow-compression no"))
	if err != nil {
		t.Fatalf("ParseString: %v", err)
	}
	if p.Compression != compress.ModeLZO {
		t.Errorf("Compression = %v, want %v: the parser records what the file said",
			p.Compression, compress.ModeLZO)
	}
	if p.AllowCompression != compress.AllowNo {
		t.Errorf("AllowCompression = %v, want %v", p.AllowCompression, compress.AllowNo)
	}
	if _, err := compress.EffectiveMode(p.Compression, compress.ModeNone, p.AllowCompression); err == nil {
		t.Error("EffectiveMode accepted comp-lzo under allow-compression no; that " +
			"combination must fail rather than downgrade silently")
	}
}
