// The profiles the parser properties range over.
//
// One fixture per shape the parser treats differently: each inline block and
// the empty one it must refuse, a file reference read and one an inline block
// supersedes, every spelling of a remote and of a compression directive, and
// the ways a profile can be written — CRLF, comments, blank lines inside a
// block.
//
// caps has a set of its own. The two overlap in content and are deliberately
// separate: caps needs every registry row instantiated and grades directives
// without reading key material; these need a certificate that builds a trust
// store, and no coverage obligation at all. One table serving both was a
// package imported from three places, and the shape of it outlived the corpus
// it was named for.
//
// What is *not* here: caps' lexical shapes, the profiles written with CRLF or
// with comments padding their inline blocks. They were tried here and caught
// nothing — every fixture's static key already carries a comment banner, so
// the block reader's comment skipping is exercised by all of them. They earn
// their place in caps, where the published shape inventory has to claim them.

package profile_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// shape is one profile the fixtures carry, and what it is there to exercise.
type fixtureShape struct {
	// Group is the subdirectory it is written to, and the dimension caps'
	// matrix aggregates by.
	Group string
	// Name is the file's base name, without the extension.
	Name string
	// Refused says the parser must decline this profile.
	Refused bool

	// directives is the body, after the prelude every profile shares. A shape
	// naming no remote is given one.
	directives string
	// inline names the blocks to embed, in order.
	inline []string
	// beside names the files to write next to the profile.
	beside []string
	// crlf writes the profile with CRLF line endings. Over half the profiles
	// in a real corpus are written that way, and a tokenizer that keeps the
	// carriage return puts it in an argument.
	crlf bool
	// padded pads the inline blocks with the blank and comment lines real
	// generators leave in them, and the profile with comment lines of its own.
	padded bool
}

// prelude opens every generated profile. Both lines are graded, so they are
// part of what the fixtures cover rather than boilerplate around them.
const prelude = "client\ndev tun\n"

// defaultRemote is appended to a shape that names no endpoint of its own: a
// profile with no remote line is refused, and only the shape that means to be
// refused may be.
const defaultRemote = "remote vpn.example.test 1194\n"

// fixtureShapes is the table. Each entry is one structural pattern a deployed profile
// exhibits, or one group of directives that would otherwise be graded by
// nothing.
//
// The groups after "misc" exist for coverage rather than realism: no deployed
// profile carries every routing directive at once, but a registry row nothing
// instantiates is a row whose grading can change without moving a number.
var fixtureShapes = []fixtureShape{
	// ---- Trust store -------------------------------------------------

	{Group: "trust", Name: "inline-ca-userpass",
		directives: "auth-user-pass\nverb 3\n",
		inline:     []string{"ca"}},

	{Group: "trust", Name: "inline-ca-cert-key",
		directives: "verb 3\n",
		inline:     []string{"ca", "cert", "key"}},

	{Group: "trust", Name: "fileref-ca",
		directives: "ca ca.crt\nauth-user-pass\n",
		beside:     []string{"ca.crt"}},

	// The named file is deliberately not written. The inline block supersedes
	// it, so a parser that opened it anyway would fail here rather than
	// quietly load the wrong trust store.
	{Group: "trust", Name: "fileref-ca-superseded",
		directives: "ca ca.crt\nauth-user-pass\n",
		inline:     []string{"ca"}},

	{Group: "trust", Name: "fileref-cert-key",
		directives: "ca ca.crt\ncert client.crt\nkey client.key\n",
		beside:     []string{"ca.crt", "client.crt", "client.key"}},

	// ---- Control-channel wrap ----------------------------------------

	{Group: "wrap", Name: "tls-auth-direction-1",
		directives: "key-direction 1\nauth-user-pass\n",
		inline:     []string{"ca", "tls-auth"}},

	{Group: "wrap", Name: "tls-auth-direction-0",
		directives: "key-direction 0\nauth-user-pass\n",
		inline:     []string{"ca", "tls-auth"}},

	{Group: "wrap", Name: "tls-auth-no-direction",
		directives: "auth-user-pass\n",
		inline:     []string{"ca", "tls-auth"}},

	{Group: "wrap", Name: "tls-crypt",
		directives: "auth-user-pass\n",
		inline:     []string{"ca", "tls-crypt"}},

	{Group: "wrap", Name: "tls-auth-file-reference",
		directives: "tls-auth ta.key 1\nauth-user-pass\n",
		inline:     []string{"ca"},
		beside:     []string{"ta.key"}},

	{Group: "wrap", Name: "tls-crypt-v2-file-reference",
		directives: "tls-crypt-v2 client-v2.key\nauth-user-pass\n",
		inline:     []string{"ca"}},

	{Group: "wrap", Name: "key-direction-without-wrap",
		directives: "key-direction 1\nauth-user-pass\n",
		inline:     []string{"ca"}},

	// An inline wrap block whose body is not a 256-byte static key.
	{Group: "wrap", Name: "tls-auth-empty",
		directives: "auth-user-pass\n",
		inline:     []string{"ca", "tls-auth-empty"},
		Refused:    true},

	// ---- Endpoints and transport -------------------------------------

	{Group: "transport", Name: "several-remotes",
		directives: "remote vpn1.example.test 1194\nremote vpn2.example.test 1194\n" +
			"remote vpn3.example.test 443\nauth-user-pass\n",
		inline: []string{"ca"}},

	// The third field is the only statement of transport these make.
	{Group: "transport", Name: "per-remote-proto",
		directives: "remote vpn1.example.test 1194 udp\nremote vpn2.example.test 443 tcp-client\n" +
			"auth-user-pass\n",
		inline: []string{"ca"}},

	// remote-random with somewhere to shuffle to. Deployed profiles pair it
	// with a single remote, where a shuffle is unobservable; without this one
	// the shuffle is never actually exercised.
	{Group: "transport", Name: "remote-random-several",
		directives: "remote vpn1.example.test 1194\nremote vpn2.example.test 1194\n" +
			"remote-random\nauth-user-pass\n",
		inline: []string{"ca"}},

	{Group: "transport", Name: "remote-random-single",
		directives: "remote-random\nremote-random-hostname\nauth-user-pass\n",
		inline:     []string{"ca"}},

	{Group: "transport", Name: "tcp-explicit",
		directives: "remote vpn.example.test 443\nproto tcp-client\nport 443\nfloat\nauth-user-pass\n",
		inline:     []string{"ca"}},

	// An endpoint given as an address rather than a name, and a flag written
	// bare where the same directive elsewhere carries a count.
	{Group: "transport", Name: "address-literal-remote",
		directives: "remote 203.0.113.9 1194\nexplicit-exit-notify\nauth-user-pass\n",
		inline:     []string{"ca"}},

	// proto spelled in upper case. OpenVPN matches the argument case-sensitively
	// and refuses the file; this client lowercases it first, so the two
	// disagree about a profile that is otherwise ordinary.
	{Group: "transport", Name: "uppercase-proto",
		directives: "remote vpn.example.test 1194 UDP\nproto UDP\nauth-user-pass\n",
		inline:     []string{"ca"}},

	// ---- Compression --------------------------------------------------

	{Group: "compression", Name: "comp-lzo-bare",
		directives: "comp-lzo\nauth-user-pass\n", inline: []string{"ca"}},
	{Group: "compression", Name: "comp-lzo-no",
		directives: "comp-lzo no\nauth-user-pass\n", inline: []string{"ca"}},
	{Group: "compression", Name: "comp-noadapt",
		directives: "comp-lzo\ncomp-noadapt\nauth-user-pass\n", inline: []string{"ca"}},
	{Group: "compression", Name: "compress-stub",
		directives: "compress\nauth-user-pass\n", inline: []string{"ca"}},
	{Group: "compression", Name: "compress-stub-v2",
		directives: "compress stub-v2\nauth-user-pass\n", inline: []string{"ca"}},
	{Group: "compression", Name: "compress-lz4",
		directives: "compress lz4\nauth-user-pass\n", inline: []string{"ca"}},
	{Group: "compression", Name: "allow-compression-no",
		directives: "allow-compression no\nauth-user-pass\n", inline: []string{"ca"}},

	// A compressing algorithm beside the directive that forbids one. The pair
	// parses: the refusal belongs to compress.EffectiveMode, at the point the
	// framing is chosen, and a set in which the two never meet states nothing
	// about it.
	{Group: "compression", Name: "allow-compression-no-with-lzo",
		directives: "allow-compression no\ncomp-lzo\nauth-user-pass\n", inline: []string{"ca"}},

	// ---- Data channel --------------------------------------------------

	{Group: "crypto", Name: "cbc-explicit-digest",
		directives: "cipher AES-256-CBC\nauth SHA256\nauth-user-pass\n",
		inline:     []string{"ca"}},

	// No auth directive, so the digest is the SHA1 OpenVPN implies. That gap
	// is reported for something the profile does not say.
	{Group: "crypto", Name: "cbc-implied-digest",
		directives: "cipher AES-256-CBC\nauth-user-pass\n",
		inline:     []string{"ca"}},

	{Group: "crypto", Name: "gcm",
		directives: "cipher AES-256-GCM\nauth-user-pass\n",
		inline:     []string{"ca"}},

	// Cipher and digest in lower case. Both are looked up case-insensitively,
	// and a profile that writes them this way is the only thing that says so.
	{Group: "crypto", Name: "lowercase-cipher-and-digest",
		directives: "cipher aes-256-cbc\nauth sha256\nauth-user-pass\n",
		inline:     []string{"ca"}},

	{Group: "crypto", Name: "negotiable-ciphers",
		directives: "data-ciphers AES-256-GCM:AES-128-GCM\ndata-ciphers-fallback AES-256-CBC\n" +
			"ncp-disable\nauth-user-pass\n",
		inline: []string{"ca"}},

	{Group: "crypto", Name: "legacy-knobs",
		directives: "keysize 256\ntls-cipher TLS-DHE-RSA-WITH-AES-256-CBC-SHA\ntls-version-min 1.2\n" +
			"auth-user-pass\n",
		inline: []string{"ca"}},

	// ---- Session ------------------------------------------------------

}

// writeFixtures writes every fixture into dir, one subdirectory per group,
// and returns what it wrote.
func writeFixtures(t *testing.T, dir string) []fixtureFile {
	t.Helper()
	out := make([]fixtureFile, 0, len(fixtureShapes))
	for _, s := range fixtureShapes {
		group := filepath.Join(dir, s.Group)
		if err := os.MkdirAll(group, 0o700); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		for _, name := range s.beside {
			if err := os.WriteFile(filepath.Join(group, name), []byte(besideFile(name)), 0o600); err != nil {
				t.Fatalf("write %s: %v", name, err)
			}
		}
		body, err := s.render()
		if err != nil {
			t.Fatalf("%s/%s: %v", s.Group, s.Name, err)
		}
		path := filepath.Join(group, s.Name+".ovpn")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
		out = append(out, fixtureFile{group: s.Group, name: s.Name, path: path, refused: s.Refused})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].path < out[j].path })
	return out
}

// render assembles one profile.
func (s fixtureShape) render() (string, error) {
	var b strings.Builder
	if s.padded {
		b.WriteString("# generated fixture\n;\n")
	}
	b.WriteString(prelude)
	if !strings.Contains(s.directives, "remote ") {
		b.WriteString(defaultRemote)
	}
	if s.padded {
		b.WriteString("\n# the rest of the profile\n")
	}
	b.WriteString(s.directives)
	for _, tag := range s.inline {
		block, err := inlineBlock(tag)
		if err != nil {
			return "", err
		}
		if s.padded {
			block = pad(block)
		}
		b.WriteString(block)
	}
	out := b.String()
	if s.crlf {
		out = strings.ReplaceAll(out, "\n", "\r\n")
	}
	return out, nil
}

// pad puts a comment and a blank line inside an inline block, where a real
// generator's banner and its spacing end up. The body between the tags is the
// part a parser has to skip over to find the material.
func pad(block string) string {
	open, rest, ok := strings.Cut(block, "\n")
	if !ok {
		return block
	}
	return open + "\n#\n# key material follows\n#\n\n" + rest
}

// wrapBlock renders body between an opening and closing tag.
func wrapBlock(tag, body string) string {
	if !strings.HasSuffix(body, "\n") {
		body += "\n"
	}
	return "<" + tag + ">\n" + body + "</" + tag + ">\n"
}

// fixtureFile is one written fixture.
type fixtureFile struct {
	group, name, path string
	// refused says the parser must decline it.
	refused bool
}

// id names the fixture in output — "wrap/tls-auth-empty".
func (f fixtureFile) id() string { return f.group + "/" + f.name }

// inertKey is a stand-in private key. Nothing parses it: the parser carries a
// key body without reading it.
const inertKey = "-----BEGIN PRIVATE KEY-----\nMIIBinertfixturebody\n-----END PRIVATE KEY-----\n"

// inertCert is a real self-signed certificate, generated once per run.
//
// It has to be real, unlike caps', because one property here asks whether the
// CA a profile names actually builds a trust store — which is what makes a
// file-referenced CA usable rather than merely read. P-256 and a day's
// validity: it is thrown away with the test.
var inertCert = func() string {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic("fixture CA: " + err.Error())
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Example Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		panic("fixture CA: " + err.Error())
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}()

// inertStaticKey is a well-formed OpenVPN static key: the parser *does* read
// these, and refuses a body that is not 256 bytes, so this one has to be real
// hex of the right length even though its value means nothing.
var inertStaticKey = func() string {
	var b strings.Builder
	b.WriteString("#\n# 2048 bit OpenVPN static key\n#\n")
	b.WriteString("-----BEGIN OpenVPN Static key V1-----\n")
	for range 16 {
		b.WriteString("0123456789abcdef0123456789abcdef\n")
	}
	b.WriteString("-----END OpenVPN Static key V1-----\n")
	return b.String()
}()

// inlineBlock renders one inline block. The tag "tls-auth-empty" is the wrap
// block with nothing between the tags, which is a shape and not an omission.
func inlineBlock(tag string) (string, error) {
	switch tag {
	case "ca", "cert":
		return wrapBlock(tag, inertCert), nil
	case "key":
		return wrapBlock(tag, inertKey), nil
	case "tls-auth", "tls-crypt":
		return wrapBlock(tag, inertStaticKey), nil
	case "tls-auth-empty":
		return "<tls-auth>\n</tls-auth>\n", nil
	}
	return "", fmt.Errorf("no inline block named %q", tag)
}

// besideFile returns the contents of a file written next to a profile.
func besideFile(name string) string {
	switch name {
	case "client.key":
		return inertKey
	case "ta.key":
		return inertStaticKey
	default:
		return inertCert
	}
}
