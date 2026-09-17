// SPDX-License-Identifier: LGPL-2.1-or-later

// Acceptance for the parser, over the generated profile fixtures.
//
// Every statement here is quantified over configs rather than measured from a
// set of them. That is what lets these run on fixtures at all: a claim that
// needs one particular corpus to hold is a census, and a census of real
// provider profiles is measured by a separate tool that holds one.
//
// No socket is opened, no credential is read and no key byte is printed.
package profile_test

import (
	"bytes"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/openlawsvpn/go-openlawsvpn/internal/compress"
	"github.com/openlawsvpn/go-openlawsvpn/profile"
)

// fixtures writes the profile fixtures and returns them.
func fixtures(t *testing.T) []fixtureFile {
	t.Helper()
	return writeFixtures(t, t.TempDir())
}

// parseFixture parses one fixture from its own bytes, with its directory.
//
// It opens the file rather than calling profile.ParsePath so that no error can
// carry the path, and it hands over the directory because a config naming its
// CA in a file beside it is refused when parsed from bytes alone.
func parseFixture(path string) (*profile.Profile, []byte, error) {
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, nil, err
	}
	p, err := profile.ParseFileIn(bytes.NewReader(raw), filepath.Dir(path))
	return p, raw, err
}

// countBlocks returns how many inline blocks with the given tag a profile
// recorded. The parser lowercases nothing in InlineBlocks, so the comparison
// does.
func countBlocks(p *profile.Profile, tag string) int {
	n := 0
	for _, b := range p.InlineBlocks {
		if strings.EqualFold(b.Tag, tag) {
			n++
		}
	}
	return n
}

// hasDirective reports whether the profile recorded a directive by name.
func hasDirective(p *profile.Profile, name string) bool {
	for _, d := range p.Directives {
		if d.Name == name {
			return true
		}
	}
	return false
}

// firstArg returns a directive's first argument, or "".
func firstArg(p *profile.Profile, name string) string {
	for _, d := range p.Directives {
		if d.Name == name && len(d.Args) > 0 {
			return d.Args[0]
		}
	}
	return ""
}

// TestWrapKeysComeFromInlineBlocks states the wrap-key rule: a key is
// loaded exactly when an inline block carries one, every block that reaches the
// parser yields 256 bytes, and key-direction parses exactly when the directive
// is there.
func TestWrapKeysComeFromInlineBlocks(t *testing.T) {
	fixtures := fixtures(t)
	var parsed, refused, authKeys, cryptKeys, directions int
	for _, f := range fixtures {
		p, _, err := parseFixture(f.path)
		if err != nil {
			refused++
			continue
		}
		parsed++

		if n := countBlocks(p, "tls-auth"); n > 0 {
			if p.TLSAuth == nil {
				t.Errorf("%s: a <tls-auth> block loaded no key", f.id())
			} else {
				authKeys++
			}
		} else if p.TLSAuth != nil {
			t.Errorf("%s: a tls-auth key was loaded with no block to load it from", f.id())
		}

		if n := countBlocks(p, "tls-crypt"); n > 0 {
			if p.TLSCrypt == nil {
				t.Errorf("%s: a <tls-crypt> block loaded no key", f.id())
			} else {
				cryptKeys++
			}
		} else if p.TLSCrypt != nil {
			t.Errorf("%s: a tls-crypt key was loaded with no block to load it from", f.id())
		}

		given := hasDirective(p, "key-direction")
		value, parsedDir := p.KeyDirection.Value()
		if given != parsedDir {
			t.Errorf("%s: key-direction directive=%v but parsed=%v", f.id(), given, parsedDir)
		}
		if given {
			directions++
			if want := firstArg(p, "key-direction"); want != "" && want != string(rune('0'+value)) {
				t.Errorf("%s: key-direction %q parsed as %d", f.id(), want, value)
			}
		}
	}
	// Every count above is a property quantified over the fixtures, and a
	// property over nothing holds. These say the fixtures still carry what
	// this test is about, so pruning one of them fails here rather than
	// quietly emptying the assertion.
	requireSome(t, map[string]int{
		"parsed": parsed, "refused": refused,
		"tls-auth keys": authKeys, "tls-crypt keys": cryptKeys, "key-direction": directions,
	})
	t.Logf("%d configs: %d parsed, %d refused; %d tls-auth keys, %d tls-crypt keys, "+
		"%d key-direction lines", len(fixtures), parsed, refused, authKeys, cryptKeys, directions)
}

// TestWrapKeyFileReferenceLoadsNoKey covers the other way a profile can
// name a wrap key. The file-reference path carries ca, cert and key only, so a
// "tls-auth ta.key" line loads nothing — which is a fatal capability gap and
// not a silent plaintext control channel.
func TestWrapKeyFileReferenceLoadsNoKey(t *testing.T) {
	fixtures := fixtures(t)
	seen := 0
	for _, f := range fixtures {
		p, _, err := parseFixture(f.path)
		if err != nil {
			continue
		}
		for _, name := range []string{"tls-auth", "tls-crypt"} {
			if !hasDirective(p, name) {
				continue
			}
			seen++
			if countBlocks(p, name) > 0 {
				continue // The block is what loaded the key.
			}
			if (name == "tls-auth" && p.TLSAuth != nil) || (name == "tls-crypt" && p.TLSCrypt != nil) {
				t.Errorf("%s: %q named a file and a key was loaded anyway", f.id(), name)
			}
			for _, ref := range p.FileRefs {
				if ref.Tag == name {
					t.Errorf("%s: %q was recorded as a file reference; only ca, cert "+
						"and key are resolved", f.id(), name)
				}
			}
		}
	}
	requireSome(t, map[string]int{"wrap directives naming a file": seen})
	t.Logf("%d wrap directives naming a file", seen)
}

// TestRemotesSurviveParsing states what the dial loop is handed: every
// config that parses names at least one endpoint, a third field on a remote
// line is read as its transport, and the single-remote fields agree with the
// list they are a view of.
func TestRemotesSurviveParsing(t *testing.T) {
	fixtures := fixtures(t)
	var lines, perRemoteProto, multi int
	for _, f := range fixtures {
		p, _, err := parseFixture(f.path)
		if err != nil {
			continue
		}
		if len(p.Remotes) == 0 {
			t.Errorf("%s: parsed with no remote; such a config is refused", f.id())
			continue
		}
		lines += len(p.Remotes)
		if len(p.Remotes) > 1 {
			multi++
		}

		// Remote, Port and Proto are Remotes[0] under another name.
		// A reader of either must get the same endpoint.
		first := p.Remotes[0]
		if p.Remote != first.Host || p.Port != first.Port || p.Proto != first.Proto {
			t.Errorf("%s: the single-remote fields and Remotes[0] disagree", f.id())
		}

		for _, r := range p.Remotes {
			if r.Host == "" {
				t.Errorf("%s: a remote line parsed with no host", f.id())
			}
			if r.Port <= 0 || r.Port > 65535 {
				t.Errorf("%s: a remote line parsed to port %d", f.id(), r.Port)
			}
			if !r.ProtoSet {
				continue
			}
			perRemoteProto++
			if r.Proto != profile.ProtoUDP && r.Proto != profile.ProtoTCP {
				t.Errorf("%s: a remote line's transport parsed to %v", f.id(), r.Proto)
			}
		}
	}
	requireSome(t, map[string]int{
		"remote lines": lines, "configs with several": multi, "lines with a transport": perRemoteProto,
	})
	t.Logf("%d remote lines, %d configs with more than one, %d lines carrying a transport",
		lines, multi, perRemoteProto)
}

// TestFileReferencedCA is the acceptance for file references:
//
//   - every reference is a ca, cert or key one, and is read or superseded,
//     never both and never neither;
//   - a CA that was read builds a certificate pool, which is what makes the
//     profile usable rather than merely parsed;
//   - the same bytes with no directory are refused with ErrNoProfileDir, and
//     only for the configs that had to read something.
func TestFileReferencedCA(t *testing.T) {
	fixtures := fixtures(t)
	var refs, loaded, superseded, pools, readers, noDir int
	for _, f := range fixtures {
		p, raw, err := parseFixture(f.path)
		if err != nil {
			continue
		}

		readsAFile := false
		for _, ref := range p.FileRefs {
			refs++
			switch ref.Tag {
			case "ca", "cert", "key":
			default:
				t.Errorf("%s: a %q file reference; only ca, cert and key are resolved",
					f.id(), ref.Tag)
			}
			switch {
			case ref.Loaded && ref.Superseded:
				t.Errorf("%s: a file reference is both read and superseded", f.id())
			case ref.Loaded:
				loaded++
				readsAFile = true
			case ref.Superseded:
				superseded++
			default:
				t.Errorf("%s: a file reference was neither read nor superseded", f.id())
			}
		}

		if readsAFile {
			readers++
		}
		if readsAFile && len(p.CA) > 0 {
			if pool := x509.NewCertPool(); !pool.AppendCertsFromPEM(p.CA) {
				t.Errorf("%s: the CA read from a file builds no certificate pool", f.id())
			} else {
				pools++
			}
		}

		// The same bytes with nowhere to resolve a name from. Only a
		// config that had to read one may be refused, and only for
		// that reason.
		_, err = profile.ParseFile(bytes.NewReader(raw))
		switch {
		case err == nil && readsAFile:
			t.Errorf("%s: parsed from bytes alone, with no directory to read its CA from", f.id())
		case errors.Is(err, profile.ErrNoProfileDir):
			noDir++
			if !readsAFile {
				t.Errorf("%s: refused for want of a directory it does not need", f.id())
			}
		}
	}
	if noDir != readers {
		t.Errorf("%d configs read a file and %d were refused without a directory; "+
			"they are the same configs", readers, noDir)
	}
	requireSome(t, map[string]int{
		"file references": refs, "read": loaded, "superseded": superseded, "pools built": pools,
	})
	t.Logf("%d file references: %d read, %d superseded by an inline block; %d pools built",
		refs, loaded, superseded, pools)
}

// TestCompressionDirectives states that the parser reads a compression
// directive as the framing it names, because the three are three wire formats
// and not three spellings of one: comp-lzo prepends a byte, a bare compress
// replaces the payload's first byte and moves it to the tail, and stub-v2
// writes nothing at all.
func TestCompressionDirectives(t *testing.T) {
	// The spelling on the left decides the framing on the right. A directive
	// not listed here is one whose argument the mapping does not pin.
	want := map[string]compress.Mode{
		"comp-lzo":          compress.ModeLZO,
		"comp-lzo yes":      compress.ModeLZO,
		"comp-lzo adaptive": compress.ModeLZO,
		"comp-lzo no":       compress.ModeStubNoSwap,
		"compress":          compress.ModeStub,
		"compress stub":     compress.ModeStub,
		"compress stub-v2":  compress.ModeStubV2,
		"compress lz4":      compress.ModeLZ4,
		"compress lz4-v2":   compress.ModeLZ4v2,
	}

	fixtures := fixtures(t)
	byMode := map[compress.Mode]int{}
	refusals := 0
	for _, f := range fixtures {
		p, _, err := parseFixture(f.path)
		if err != nil {
			continue
		}
		byMode[p.Compression]++

		spelling := ""
		for _, d := range p.Directives {
			if d.Name != "comp-lzo" && d.Name != "compress" {
				continue
			}
			spelling = strings.TrimSpace(d.Name + " " + strings.Join(d.Args, " "))
			if mode, ok := want[spelling]; ok && p.Compression != mode {
				t.Errorf("%s: %q parsed as %v, want %v", f.id(), spelling, p.Compression, mode)
			}
		}
		if spelling == "" && p.Compression != compress.ModeNone {
			t.Errorf("%s: parsed as %v with no compression directive", f.id(), p.Compression)
		}

		// "allow-compression no" forbids a compressing algorithm from
		// either source. The pair parses; the refusal is made where
		// the framing is chosen, and a set in which the two never meet
		// says nothing about it either way.
		if p.AllowCompression != compress.AllowNo {
			continue
		}
		_, err = compress.EffectiveMode(p.Compression, compress.ModeNone, p.AllowCompression)
		switch {
		case p.Compression.Compresses() && err == nil:
			t.Errorf("%s: %v survived \"allow-compression no\"", f.id(), p.Compression)
		case !p.Compression.Compresses() && err != nil:
			t.Errorf("%s: \"allow-compression no\" refused the framing stub %v: %v",
				f.id(), p.Compression, err)
		case err != nil:
			refusals++
		}
	}
	requireSome(t, map[string]int{
		"comp-lzo": byMode[compress.ModeLZO], "compress": byMode[compress.ModeStub],
		"stub-v2":                      byMode[compress.ModeStubV2],
		"refused by allow-compression": refusals,
	})
	t.Logf("compression: lzo %d, stub %d, stub-v2 %d, none %d; %d refused by allow-compression",
		byMode[compress.ModeLZO], byMode[compress.ModeStub], byMode[compress.ModeStubV2],
		byMode[compress.ModeNone], refusals)
}

// TestLineEndingsDoNotChangeMeaning states that a profile means the same
// thing whichever way its lines are terminated. Over half the profiles in a
// real corpus are written with CRLF, and a carriage return that survives into
// a directive's last argument is invisible in every printed form of it.
func TestLineEndingsDoNotChangeMeaning(t *testing.T) {
	fixtures := fixtures(t)
	flipped := 0
	for _, f := range fixtures {
		raw, err := os.ReadFile(filepath.Clean(f.path))
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		lf := bytes.ReplaceAll(raw, []byte("\r\n"), []byte("\n"))
		crlf := bytes.ReplaceAll(lf, []byte("\n"), []byte("\r\n"))
		if !bytes.Equal(lf, crlf) {
			flipped++
		}

		dir := filepath.Dir(f.path)
		a, errA := profile.ParseFileIn(bytes.NewReader(lf), dir)
		b, errB := profile.ParseFileIn(bytes.NewReader(crlf), dir)
		if (errA == nil) != (errB == nil) {
			t.Errorf("%s: parses with LF=%v and with CRLF=%v", f.id(), errA == nil, errB == nil)
			continue
		}
		if errA != nil {
			continue
		}
		if !reflect.DeepEqual(a, b) {
			t.Errorf("%s: the same profile parses differently with CRLF line endings", f.id())
		}
	}
	requireSome(t, map[string]int{"configs compared in both line endings": flipped})
	t.Logf("%d configs compared in both line endings", flipped)
}

// TestParseErrorsNameNoPath is the standing guard on failure output: a
// config's own name carries country, city and server labels, so a refusal must
// not quote the path it was asked to read, whatever else it says.
func TestParseErrorsNameNoPath(t *testing.T) {
	fixtures := fixtures(t)
	checked := 0
	for _, f := range fixtures {
		_, _, err := parseFixture(f.path)
		if err == nil {
			continue
		}
		checked++
		for _, leak := range []string{f.path, filepath.Base(f.path)} {
			if strings.Contains(err.Error(), leak) {
				t.Errorf("%s: a parse error names the file it was reading", f.id())
				break
			}
		}
	}
	requireSome(t, map[string]int{"refusals": checked})
	t.Logf("%d refusals checked", checked)
}

// requireSome fails when a count this suite ranges over is zero.
//
// Every assertion here is universally quantified, and a property over an empty
// set holds. Deleting the fixtures a test is about would otherwise leave it
// green — which is how a suite stops covering the thing it names without
// anyone noticing.
func requireSome(t *testing.T, counts map[string]int) {
	t.Helper()
	for what, n := range counts {
		if n == 0 {
			t.Errorf("no fixture produced any %s; this test asserts nothing", what)
		}
	}
}
