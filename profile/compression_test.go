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

// TestParseCompressionDirectives covers every spelling OpenVPN accepts. Bare
// "compress" swaps and "comp-lzo no" does not, though both are stubs.
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
		// Last one wins.
		{"comp-lzo\ncompress stub-v2", compress.ModeStubV2},
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

// TestCompressionSurvivesAllowCompressionNo pins that the parser records both
// fields as written; compress.EffectiveMode reconciles them.
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
