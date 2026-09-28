// Unit tests for the server matrix. These run under plain `go test ./...`
// and must never need a Docker daemon: they only exercise the table and the
// configuration generators.
package testenv_test

import (
	"bufio"
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/buengese/go-openvpn/testenv"
)

// versionsEnvPath is the shell-sourceable pin file build.sh reads.
const versionsEnvPath = "../docker/openvpn-server/versions.env"

// readVersionsEnv parses the shell assignments out of versions.env.
func readVersionsEnv(t *testing.T) map[string]string {
	t.Helper()
	f, err := os.Open(filepath.Clean(versionsEnvPath))
	if err != nil {
		t.Fatalf("open %s: %v", versionsEnvPath, err)
	}
	defer f.Close() //nolint:errcheck

	out := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		out[strings.TrimSpace(k)] = strings.Trim(strings.TrimSpace(v), `"`)
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("read %s: %v", versionsEnvPath, err)
	}
	return out
}

// TestPinsMatchVersionsEnv guards the one place this package duplicates state:
// the image pins live in versions.env for build.sh and as Go constants for
// ImageFor, and a drift runs a test against an image built from other sources.
func TestPinsMatchVersionsEnv(t *testing.T) {
	env := readVersionsEnv(t)

	want := map[string]string{
		"MATRIX_IMAGE_REPO":  testenv.MatrixImageRepo,
		"OPENVPN_24_VERSION": testenv.OpenVPN24Version,
		"OPENVPN_25_VERSION": testenv.OpenVPN25Version,
		"OPENVPN_26_VERSION": testenv.OpenVPN26Version,
		"OPENVPN_24_SHA256":  testenv.OpenVPN24SHA256,
		"OPENVPN_25_SHA256":  testenv.OpenVPN25SHA256,
		"OPENVPN_26_SHA256":  testenv.OpenVPN26SHA256,
		"OPENVPN_24_BASE":    testenv.OpenVPN24Base,
		"OPENVPN_25_BASE":    testenv.OpenVPN25Base,
		"OPENVPN_26_BASE":    testenv.OpenVPN26Base,
	}
	for key, goValue := range want {
		if env[key] != goValue {
			t.Errorf("%s: versions.env has %q, Go constant has %q", key, env[key], goValue)
		}
	}
}

// TestNoFloatingPins asserts that nothing in the pin set is a moving target.
// The matrix has to be deterministic to be comparable across runs; a "latest"
// tag or an undigested base image makes every captured result irreproducible.
func TestNoFloatingPins(t *testing.T) {
	bases := map[string]string{
		"2.4": testenv.OpenVPN24Base,
		"2.5": testenv.OpenVPN25Base,
		"2.6": testenv.OpenVPN26Base,
	}
	for series, base := range bases {
		if !strings.Contains(base, "@sha256:") {
			t.Errorf("%s base image %q is not pinned by digest", series, base)
		}
		if strings.HasSuffix(base, ":latest") {
			t.Errorf("%s base image %q uses a floating tag", series, base)
		}
	}
	for _, v := range testenv.ServerVersions() {
		img, ok := testenv.ImageFor(v)
		if !ok {
			t.Fatalf("ImageFor(%s): no image", v)
		}
		if strings.HasSuffix(img, ":latest") {
			t.Errorf("ImageFor(%s) = %q uses a floating tag", v, img)
		}
		pinned, _ := testenv.PinnedVersion(v)
		if !strings.HasSuffix(img, ":"+pinned) {
			t.Errorf("ImageFor(%s) = %q does not carry the pinned version %q", v, img, pinned)
		}
	}
}

// axisValue is one axis of a matrix entry, carried with its name so a
// difference between two entries can be reported as "the cipher moved" rather
// than as two struct dumps for the reader to compare by eye.
type axisValue struct {
	name  string
	value string
}

// matrixAxes projects an entry onto the thirteen fields that make it a distinct
// point in the matrix: the eight wire-level axes — version, cipher, digest,
// wrap, proto, compression, reneg and family — plus DataV1, Auth, and the three
// that carry the certificate checks and failover: certcheck, ca and remotes.
// Name is deliberately absent; it is a label for the combination, not part of it.
//
// Every field of MatrixEntry that changes the experiment has to appear here, or
// an isolate can silently vary two things at once while
// TestLadderIsolatesDifferByExactlyOneAxis still passes. "Changes the
// experiment" is broader than "changes what is on the wire": a file-referenced
// CA puts the same bytes on the wire as an inline one, and what it changes is
// whether a client can read the profile at all.
func matrixAxes(e testenv.MatrixEntry) []axisValue {
	return []axisValue{
		{"version", string(e.Version)},
		{"cipher", string(e.Cipher)},
		{"digest", string(e.Digest)},
		{"wrap", e.Wrap.String()},
		{"proto", e.Proto.String()},
		{"compression", e.Compression.String()},
		{"reneg", e.Reneg.String()},
		{"family", e.Family.String()},
		{"auth", e.Auth.String()},
		{"certcheck", e.CertCheck.String()},
		{"ca", e.CASource.String()},
		{"remotes", e.Remotes.String()},
		{"datav1", strconv.FormatBool(e.DataV1)},
	}
}

// axisDiff returns the names of the axes on which two entries differ, in the
// fixed order matrixAxes uses.
func axisDiff(a, b testenv.MatrixEntry) []string {
	av, bv := matrixAxes(a), matrixAxes(b)
	var out []string
	for i := range av {
		if av[i].value != bv[i].value {
			out = append(out, av[i].name)
		}
	}
	return out
}

// TestMatrixNamesAreUniqueAndUsable checks that every entry name is a stable,
// unique identifier usable both as a Go subtest name and as a lookup key, and
// that no two names stand for the same combination of axes — a duplicated
// combination passes everything else here while being one experiment wearing
// two labels.
func TestMatrixNamesAreUniqueAndUsable(t *testing.T) {
	entries := testenv.Matrix()

	seen := map[string]bool{}
	for _, e := range entries {
		if e.Name == "" {
			t.Fatalf("matrix entry with empty name: %+v", e)
		}
		if seen[e.Name] {
			t.Errorf("duplicate matrix entry name %q", e.Name)
		}
		seen[e.Name] = true

		if strings.ContainsAny(e.Name, " \t/") {
			t.Errorf("entry name %q contains characters that break Go subtest names", e.Name)
		}
		got, ok := testenv.Entry(e.Name)
		if !ok {
			t.Errorf("Entry(%q) not found", e.Name)
			continue
		}
		if got.Name != e.Name {
			t.Errorf("Entry(%q) returned entry named %q", e.Name, got.Name)
		}
	}
	if _, ok := testenv.Entry("no-such-entry"); ok {
		t.Error("Entry returned ok for an unknown name")
	}
	if n := len(testenv.EntryNames()); n != len(seen) {
		t.Errorf("EntryNames returned %d names, matrix has %d entries", n, len(seen))
	}

	for i, a := range entries {
		for _, b := range entries[i+1:] {
			if len(axisDiff(a, b)) == 0 {
				t.Errorf("%s and %s are the same combination under two names",
					a.Name, b.Name)
			}
		}
	}
}

// TestMatrixCoversEveryAxisValue asserts the curated set is actually curated:
// every value of every axis appears at least once. The values are read back
// through matrixAxes rather than re-projected here, and the trailing check
// catches an axis added to matrixAxes but given no required values below.
func TestMatrixCoversEveryAxisValue(t *testing.T) {
	seen := map[string]map[string]bool{}
	for _, e := range testenv.Matrix() {
		for _, a := range matrixAxes(e) {
			if seen[a.name] == nil {
				seen[a.name] = map[string]bool{}
			}
			seen[a.name][a.value] = true
		}
	}

	want := []struct {
		axis   string
		values []string
	}{
		{"version", []string{"2.4", "2.5", "2.6"}},
		{"cipher", []string{"AES-128-CBC", "AES-256-CBC", "AES-128-GCM", "AES-256-GCM"}},
		{"digest", []string{"SHA1", "SHA256", "SHA512"}},
		{"wrap", []string{"plain", "tls-auth-kd0", "tls-auth-kd1", "tls-crypt"}},
		{"proto", []string{"udp", "tcp"}},
		{"compression", []string{"nocomp", "comp-lzo", "comp-stub", "comp-lzo-yes"}},
		{"reneg", []string{"reneg-default", "reneg30", "reneg-server"}},
		{"family", []string{"v4", "v6", "dual"}},
		{"auth", []string{"cert", "userpass"}},
		{"certcheck", []string{"no-cert-check", "x509-name", "x509-name-bad", "ns-cert-type"}},
		{"ca", []string{"ca-inline", "ca-file"}},
		{"remotes", []string{"one-remote", "dead-first-remote"}},
		// P_DATA_V1 is a wire format rather than a directive, so only the
		// "on" value is required: an entry that does not set it is every
		// other entry in the table.
		{"datav1", []string{"true"}},
	}

	required := map[string]bool{}
	for _, a := range want {
		required[a.axis] = true
		for _, v := range a.values {
			if !seen[a.axis][v] {
				t.Errorf("no matrix entry covers %s=%s", a.axis, v)
			}
		}
	}
	for axis := range seen {
		if !required[axis] {
			t.Errorf("matrixAxes projects %q but no value of it is required here, so "+
				"nothing asserts the table exercises the axis at all", axis)
		}
	}
}

// ladderIsolates are the entries that exist to make each capability
// attributable, each paired with the neighbour it must be exactly one axis
// from — a chain in which every step moves one field. An isolate that drifts to
// two axes still starts, still connects, and silently stops isolating
// anything.
var ladderIsolates = []struct {
	entry     string
	neighbour string
	axis      string
	isolates  string
}{
	{
		entry: "v24-gcm256-sha256-plain-udp", neighbour: "v26-gcm256-sha256-plain-udp",
		axis:     "version",
		isolates: "the classic key derivation, over a data channel already known to work",
	},
	{
		entry: "v24-cbc256-sha256-plain-udp", neighbour: "v24-gcm256-sha256-plain-udp",
		axis:     "cipher",
		isolates: "the CBC path at a fixed derivation: derivation wrong vs slot mapping wrong",
	},
	{
		entry: "v24-cbc256-sha512-plain-udp", neighbour: "v24-cbc256-sha256-plain-udp",
		axis:     "digest",
		isolates: "CBC digest breadth, at a cipher deployed profiles ship",
	},
	{
		entry: "v25-gcm256-sha256-plain-udp", neighbour: "v24-gcm256-sha256-plain-udp",
		axis:     "version",
		isolates: "a 2.4-only failure against one shared by every pre-2.6 server",
	},
	{
		entry: "v25-gcm128-sha256-plain-udp", neighbour: "v25-gcm256-sha256-plain-udp",
		axis:     "cipher",
		isolates: "cipher breadth for AEAD: the 128-bit key length",
	},
	{
		entry: "v24-gcm256-sha256-plain-udp-reneg30", neighbour: "v24-gcm256-sha256-plain-udp",
		axis:     "reneg",
		isolates: "a rekey that re-derives, at a control channel the client can reach",
	},
	{
		entry: "v24-gcm256-sha256-plain-udp-userpass", neighbour: "v24-gcm256-sha256-plain-udp",
		axis:     "auth",
		isolates: "auth-user-pass, with no control-channel wrap in front of it",
	},
	{
		entry: "v24-cbc256-sha512-tlsauth-kd1-udp-userpass", neighbour: "v24-cbc256-sha512-tlsauth-kd1-udp",
		axis: "auth",
		isolates: "credentials behind tls-auth — the shape wrapped providers ship, so a " +
			"failure that is jointly credentials and wrap can still be attributed",
	},
	// The two control-channel wraps. These three pairs need no dedicated
	// entries: the plain entries are the twins the wrap entries pair with,
	// so both wraps isolate against something already in the table.
	{
		entry: "v24-gcm256-sha256-tlsauth-kd0-udp", neighbour: "v24-gcm256-sha256-plain-udp",
		axis: "wrap",
		isolates: "the tls-auth wrap at key-direction 0, over the data channel the " +
			"classic-derivation isolate proved works",
	},
	{
		entry: "v24-cbc256-sha512-tlsauth-kd1-udp", neighbour: "v24-cbc256-sha512-plain-udp",
		axis: "wrap",
		isolates: "tls-auth at key-direction 1 — the direction deployed profiles ship, " +
			"on a cipher and digest that ship with it",
	},
	{
		entry: "v26-gcm256-sha256-tlscrypt-udp", neighbour: "v26-gcm256-sha256-plain-udp",
		axis:     "wrap",
		isolates: "the tls-crypt wrap, against an entry already known to connect",
	},
	// Certificate checks, compression and failover. Four of the six hang off
	// v24-gcm256-sha256-plain-udp, the classic-derivation isolate: it is the
	// plainest thing in the table that connects, so nothing sits in front of
	// the axis under test.
	{
		entry: "v24-gcm256-sha256-plain-udp-x509name", neighbour: "v24-gcm256-sha256-plain-udp",
		axis: "certcheck",
		isolates: "verify-x509-name against the CN the server certificate carries — " +
			"the control half of the pair, and it must connect",
	},
	{
		entry: "v24-gcm256-sha256-plain-udp-x509name-bad", neighbour: "v24-gcm256-sha256-plain-udp-x509name",
		axis: "certcheck",
		isolates: "the same check against a CN the certificate does not carry. " +
			"This pair is the only thing that separates a client performing the check " +
			"from one ignoring it — an ignoring client passes both halves alone",
	},
	{
		entry: "v24-gcm256-sha256-plain-udp-nscerttype", neighbour: "v24-gcm256-sha256-plain-udp",
		axis: "certcheck",
		isolates: "ns-cert-type, which no deployed profile was seen to carry, so this " +
			"entry is the capability's only vehicle",
	},
	{
		entry: "v24-gcm256-sha256-plain-udp-cafile", neighbour: "v24-gcm256-sha256-plain-udp",
		axis: "ca",
		isolates: "certificate verification's other half: a CA named by path rather than " +
			"inlined, which is how a whole provider's profiles ship theirs",
	},
	{
		entry: "v24-gcm256-sha256-plain-tcp", neighbour: "v24-gcm256-sha256-plain-udp",
		axis: "proto",
		isolates: "the transport at the version that forces the classic derivation, and the " +
			"anchor the failover isolate needs",
	},
	{
		entry: "v24-gcm256-sha256-plain-tcp-multiremote", neighbour: "v24-gcm256-sha256-plain-tcp",
		axis: "remotes",
		isolates: "a second remote reached only by failing over from a dead first " +
			"one, which no single-remote entry can distinguish from connecting normally",
	},
	{
		entry: "v24-cbc256-sha1-complzoyes-udp", neighbour: "v24-cbc256-sha1-complzo-udp",
		axis: "compression",
		isolates: "a server that genuinely compresses, against one that only frames. " +
			"It separates a wrong framing byte from an inability to cope with a compressed " +
			"payload, which have the same symptom and different fixes",
	},
}

// TestLadderIsolatesDifferByExactlyOneAxis asserts that each isolate really is
// one axis from the neighbour it is paired with. Reading the table cannot
// establish it: seven of the nine axes are zero-valued in these literals, so an
// entry that varies two axes looks exactly like one that varies one.
func TestLadderIsolatesDifferByExactlyOneAxis(t *testing.T) {
	for _, tc := range ladderIsolates {
		t.Run(tc.entry, func(t *testing.T) {
			e, ok := testenv.Entry(tc.entry)
			if !ok {
				t.Fatalf("Entry(%q) not found; the ladder isolate is gone", tc.entry)
			}
			n, ok := testenv.Entry(tc.neighbour)
			if !ok {
				t.Fatalf("Entry(%q) not found; %q has nothing to be an isolate of",
					tc.neighbour, tc.entry)
			}
			diff := axisDiff(e, n)
			if len(diff) != 1 || diff[0] != tc.axis {
				t.Fatalf("%s vs %s differs on %v, want exactly [%s]; "+
					"the pair no longer isolates %s",
					tc.entry, tc.neighbour, diff, tc.axis, tc.isolates)
			}
			t.Logf("%s is one axis (%s) from %s — isolates %s",
				tc.entry, tc.axis, tc.neighbour, tc.isolates)
		})
	}
}

// TestMatrixForPartitionsByVersion checks MatrixFor against Matrix.
func TestMatrixForPartitionsByVersion(t *testing.T) {
	total := 0
	for _, v := range testenv.ServerVersions() {
		sub := testenv.MatrixFor(v)
		if len(sub) == 0 {
			t.Errorf("MatrixFor(%s) is empty; every version needs at least one entry", v)
		}
		for _, e := range sub {
			if e.Version != v {
				t.Errorf("MatrixFor(%s) returned entry %q for version %s", v, e.Name, e.Version)
			}
		}
		total += len(sub)
	}
	if total != len(testenv.Matrix()) {
		t.Errorf("MatrixFor covers %d entries, Matrix has %d", total, len(testenv.Matrix()))
	}
}

// TestMatrixIsACopy verifies Matrix hands out a copy, so a caller cannot
// corrupt the table for every other test in the process.
func TestMatrixIsACopy(t *testing.T) {
	first := testenv.Matrix()
	if len(first) == 0 {
		t.Fatal("empty matrix")
	}
	original := first[0].Name
	first[0].Name = "clobbered"
	if again := testenv.Matrix(); again[0].Name != original {
		t.Errorf("Matrix returned a view of the package table: entry 0 is now %q", again[0].Name)
	}
}

// TestStartMatrixSkipsUnimplemented verifies that an unimplemented entry is
// reported as ErrUnimplemented without ever invoking Docker, which is what lets
// an enumerating test skip rather than fail on a machine with no daemon.
func TestStartMatrixSkipsUnimplemented(t *testing.T) {
	e := testenv.MatrixEntry{
		Name:          "synthetic-unimplemented",
		Version:       testenv.V24,
		Cipher:        testenv.CipherAES256CBC,
		Digest:        testenv.DigestSHA256,
		Unimplemented: "synthetic reason for the test",
	}
	if got := e.SkipReason(); got != "synthetic reason for the test" {
		t.Errorf("SkipReason() = %q", got)
	}

	srv, err := testenv.StartMatrix(e)
	if srv != nil {
		t.Fatal("StartMatrix returned a server for an unimplemented entry")
	}
	if !errors.Is(err, testenv.ErrUnimplemented) {
		t.Fatalf("StartMatrix error = %v, want ErrUnimplemented", err)
	}
	if !strings.Contains(err.Error(), "synthetic reason for the test") {
		t.Errorf("error %q does not carry the skip reason", err)
	}
}

// TestCuratedEntriesAreImplemented asserts that nothing in the curated set is
// silently unimplemented. Skipping is an escape hatch for entries added ahead
// of rig support, not a resting state for the whole table.
func TestCuratedEntriesAreImplemented(t *testing.T) {
	implemented := 0
	for _, e := range testenv.Matrix() {
		if r := e.SkipReason(); r != "" {
			t.Logf("entry %s is not implemented: %s", e.Name, r)
			continue
		}
		implemented++
	}
	if implemented != len(testenv.Matrix()) {
		t.Errorf("%d/%d curated entries are implemented", implemented, len(testenv.Matrix()))
	}
}

// testProfileOptions returns placeholder PKI material for generator tests. The
// values are obvious non-secrets; a real run generates them per server.
func testProfileOptions() testenv.ClientProfileOptions {
	return testenv.ClientProfileOptions{
		Remote:         "198.51.100.7",
		Port:           1194,
		CACertPEM:      "TEST-CA-PEM\n",
		ClientCertPEM:  "TEST-CLIENT-CERT-PEM\n",
		ClientKeyPEM:   "TEST-CLIENT-KEY-PEM\n",
		StaticKey:      "TEST-STATIC-KEY\n",
		CAFile:         testenv.MatrixCAFile,
		DeadRemotePort: 1195,
	}
}

// TestServerAndClientConfigsAgree is the matrix's core invariant: both sides
// are generated from one MatrixEntry, so they cannot drift on cipher, digest,
// control-channel wrapping, compression framing, transport or renegotiation.
func TestServerAndClientConfigsAgree(t *testing.T) {
	for _, e := range testenv.Matrix() {
		t.Run(e.Name, func(t *testing.T) {
			srv := e.ServerConfig()
			cli := e.ClientProfile(testProfileOptions())

			if !strings.Contains(srv, string(e.Cipher)) {
				t.Errorf("server config does not name cipher %s", e.Cipher)
			}
			if !strings.Contains(cli, string(e.Cipher)) {
				t.Errorf("client profile does not name cipher %s", e.Cipher)
			}
			if !hasDirective(srv, "auth "+string(e.Digest)) {
				t.Errorf("server config missing %q", "auth "+string(e.Digest))
			}
			if !hasDirective(cli, "auth "+string(e.Digest)) {
				t.Errorf("client profile missing %q", "auth "+string(e.Digest))
			}

			// Transport: both ends must name the same protocol family.
			if e.Proto == testenv.ProtoTCP {
				if !strings.Contains(srv, "proto tcp") {
					t.Error("server config is not TCP")
				}
				if !strings.Contains(cli, "proto tcp") {
					t.Error("client profile is not TCP")
				}
			} else {
				if !strings.Contains(srv, "proto udp") {
					t.Error("server config is not UDP")
				}
				if !strings.Contains(cli, "proto udp") {
					t.Error("client profile is not UDP")
				}
			}

			// Control-channel wrapping, including the key-direction
			// complement that makes tls-auth work at all.
			switch e.Wrap {
			case testenv.WrapPlain:
				for _, d := range []string{"tls-auth", "tls-crypt", "key-direction"} {
					if strings.Contains(srv, d) {
						t.Errorf("plain entry: server config contains %q", d)
					}
					if strings.Contains(cli, d) {
						t.Errorf("plain entry: client profile contains %q", d)
					}
				}
			case testenv.WrapTLSAuthKD0:
				if !hasDirective(srv, "tls-auth /etc/openvpn/ta.key 1") {
					t.Error("server should be at key-direction 1 when the client is at 0")
				}
				if !hasDirective(cli, "key-direction 0") {
					t.Error("client should be at key-direction 0")
				}
			case testenv.WrapTLSAuthKD1:
				if !hasDirective(srv, "tls-auth /etc/openvpn/ta.key 0") {
					t.Error("server should be at key-direction 0 when the client is at 1")
				}
				if !hasDirective(cli, "key-direction 1") {
					t.Error("client should be at key-direction 1")
				}
			case testenv.WrapTLSCrypt:
				if !hasDirective(srv, "tls-crypt /etc/openvpn/ta.key") {
					t.Error("server config missing tls-crypt")
				}
				if !strings.Contains(cli, "<tls-crypt>") {
					t.Error("client profile missing inline tls-crypt block")
				}
				if strings.Contains(cli, "key-direction") {
					t.Error("tls-crypt takes no key-direction")
				}
			}

			// Authentication. The server's hook and the client's
			// auth-user-pass directive come from the same field, so an
			// entry cannot demand credentials at one end only.
			switch e.Auth {
			case testenv.AuthCert:
				if hasDirectivePrefix(srv, "auth-user-pass-verify") {
					t.Error("cert-only entry: server config has an auth-user-pass-verify hook")
				}
				if hasDirectivePrefix(srv, "script-security") {
					t.Error("cert-only entry: server config raises script-security for no script")
				}
				if hasDirectivePrefix(cli, "auth-user-pass") {
					t.Error("cert-only entry: client profile asks for credentials")
				}
			case testenv.AuthUserPass:
				if !hasDirective(srv, "script-security 2") {
					t.Error("userpass entry: the server needs script-security 2 to run the hook")
				}
				if !hasDirective(srv, "auth-user-pass-verify "+testenv.ServerAuthVerifyPathForTest+" via-file") {
					t.Error("userpass entry: server config missing the via-file hook")
				}
				if !hasDirectivePrefix(srv, "tmp-dir") {
					t.Error("userpass entry: via-file needs a tmp-dir to write into")
				}
				if !hasDirectivePrefix(cli, "auth-user-pass") {
					t.Error("userpass entry: client profile does not ask for credentials")
				}
			}

			// Compression framing must be byte-identical on both ends.
			switch e.Compression {
			case testenv.CompNone:
				for _, d := range []string{"comp-lzo", "compress"} {
					if hasDirectivePrefix(srv, d) {
						t.Errorf("uncompressed entry: server config has %q", d)
					}
					if hasDirectivePrefix(cli, d) {
						t.Errorf("uncompressed entry: client profile has %q", d)
					}
				}
			case testenv.CompLZO:
				if !hasDirective(srv, "comp-lzo") || !hasDirective(cli, "comp-lzo") {
					t.Error("comp-lzo entry: both ends must carry comp-lzo")
				}
			case testenv.CompLZOForced:
				// "yes", not the bare directive: bare is adaptive, and an
				// entry whose purpose is a compressed payload cannot leave
				// that to the peer's heuristic.
				if !hasDirective(srv, "comp-lzo yes") || !hasDirective(cli, "comp-lzo yes") {
					t.Error("forced comp-lzo entry: both ends must carry comp-lzo yes")
				}
			case testenv.CompStub:
				sd := directiveWithPrefix(srv, "compress")
				cd := directiveWithPrefix(cli, "compress")
				if sd == "" || sd != cd {
					t.Errorf("stub compression differs: server %q, client %q", sd, cd)
				}
			}

			// Renegotiation.
			switch e.Reneg {
			case testenv.RenegDefault:
				if hasDirectivePrefix(srv, "reneg-sec") || hasDirectivePrefix(cli, "reneg-sec") {
					t.Error("default reneg entry should set no reneg-sec")
				}
			case testenv.RenegSec30:
				if !hasDirective(srv, "reneg-sec 30") || !hasDirective(cli, "reneg-sec 30") {
					t.Error("reneg30 entry: both ends must set reneg-sec 30")
				}
			case testenv.RenegServerInitiated:
				if !hasDirective(srv, "reneg-sec 30") {
					t.Error("server-initiated reneg: server must set reneg-sec 30")
				}
				if !hasDirective(cli, "reneg-sec 0") {
					t.Error("server-initiated reneg: client must set reneg-sec 0")
				}
			}

			// Address family.
			if e.Family != testenv.AFInet && !hasDirectivePrefix(srv, "server-ipv6") {
				t.Error("IPv6 entry: server config must push an IPv6 tunnel")
			}
			if e.Family == testenv.AFInet && hasDirectivePrefix(srv, "server-ipv6") {
				t.Error("IPv4 entry: server config must not push an IPv6 tunnel")
			}

			// Certificate checks are entirely client-side, so what is
			// asserted is that the directive the axis names is the one
			// emitted and that no other entry picks one up by accident.
			switch e.CertCheck {
			case testenv.CertCheckNone:
				for _, d := range []string{"verify-x509-name", "ns-cert-type"} {
					if hasDirectivePrefix(cli, d) {
						t.Errorf("entry with no certificate check carries %q", d)
					}
				}
			case testenv.CertCheckX509NameMatch:
				if !hasDirective(cli, "verify-x509-name "+testenv.MatrixServerCN+" name") {
					t.Error("matching entry must name the server certificate's own CN")
				}
			case testenv.CertCheckX509NameMismatch:
				if !hasDirective(cli, "verify-x509-name "+testenv.MatrixWrongServerCN+" name") {
					t.Error("mismatching entry must name a CN no matrix certificate carries")
				}
				if strings.Contains(cli, testenv.MatrixServerCN) {
					t.Error("mismatching entry names the real CN; it would connect and prove nothing")
				}
			case testenv.CertCheckNSCertType:
				if !hasDirective(cli, "ns-cert-type server") {
					t.Error("ns-cert-type entry must ask for the server type")
				}
			}

			// The CA source. An inline block and a file reference are
			// mutually exclusive: OpenVPN takes the inline one, so an entry
			// carrying both would silently stop testing the file path.
			switch e.CASource {
			case testenv.CAInline:
				if !strings.Contains(cli, "<ca>") {
					t.Error("inline-CA entry has no <ca> block")
				}
				if hasDirectivePrefix(cli, "ca") {
					t.Error("inline-CA entry also names a ca file")
				}
			case testenv.CAFile:
				if !hasDirective(cli, "ca "+testenv.MatrixCAFile) {
					t.Errorf("file-CA entry must name %q", testenv.MatrixCAFile)
				}
				if strings.Contains(cli, "<ca>") {
					t.Error("file-CA entry also inlines its CA; inline wins and the file " +
						"reference would never be read")
				}
			}

			// Remotes, in file order. OpenVPN tries them in the order they
			// are written, so an entry that put the live one first would
			// connect without ever failing over.
			remotes := directivesWithPrefix(cli, "remote")
			switch e.Remotes {
			case testenv.RemoteSingle:
				if len(remotes) != 1 {
					t.Errorf("single-remote entry has %d remote lines: %v", len(remotes), remotes)
				}
			case testenv.RemoteDeadFirst:
				if len(remotes) != 2 {
					t.Fatalf("dead-first entry has %d remote lines, want 2: %v", len(remotes), remotes)
				}
				if !strings.HasSuffix(remotes[0], " 1195") {
					t.Errorf("first remote %q is not the dead port", remotes[0])
				}
				if !strings.HasSuffix(remotes[1], " 1194") {
					t.Errorf("second remote %q is not the live port", remotes[1])
				}
			}
		})
	}
}

// TestClientProfileEmbedsPKI checks that the generated profile carries every
// piece of key material rather than naming a file for it. The one exception is
// the CAFile axis, and even there only the CA moves out — it is the only part of
// the material that is not secret.
func TestClientProfileEmbedsPKI(t *testing.T) {
	opts := testProfileOptions()
	for _, e := range testenv.Matrix() {
		cli := e.ClientProfile(opts)
		want := []string{
			"<cert>", "</cert>", "TEST-CLIENT-CERT-PEM",
			"<key>", "</key>", "TEST-CLIENT-KEY-PEM",
			"remote 198.51.100.7 1194",
			"remote-cert-tls server",
		}
		if e.CASource == testenv.CAInline {
			want = append(want, "<ca>", "</ca>", "TEST-CA-PEM")
		}
		for _, w := range want {
			if !strings.Contains(cli, w) {
				t.Errorf("%s: client profile missing %q", e.Name, w)
			}
		}
		if e.CASource == testenv.CAFile && strings.Contains(cli, "TEST-CA-PEM") {
			t.Errorf("%s: file-CA profile inlines the CA anyway", e.Name)
		}
		if e.Wrap != testenv.WrapPlain && !strings.Contains(cli, "TEST-STATIC-KEY") {
			t.Errorf("%s: client profile missing the static key", e.Name)
		}
		// Whatever else moves out of the profile, the private key never
		// does. There is no axis for it and there should not be one.
		if hasDirectivePrefix(cli, "key") || hasDirectivePrefix(cli, "cert") {
			t.Errorf("%s: client profile names a cert or key file", e.Name)
		}
	}
}

// TestCredentialsCannotDrift pins that the server's hook and the client's
// credentials file are generated from one pair of constants, so they cannot come
// to disagree about the password. A drift would not look like a bug: it would
// look like the server correctly rejecting a bad password.
func TestCredentialsCannotDrift(t *testing.T) {
	script := testenv.AuthVerifyScriptForTest()
	for _, want := range []string{testenv.MatrixUsername, testenv.MatrixPassword} {
		if !strings.Contains(script, want) {
			t.Errorf("the auth-user-pass-verify hook does not check %q", want)
		}
	}
	if !strings.HasPrefix(script, "#!/bin/sh\n") {
		t.Error("the hook has no shebang; openvpn execve()s it directly")
	}

	// The --auth-user-pass <file> form reads exactly two lines, in this
	// order. A file with them the other way round authenticates nothing and
	// says only "AUTH_FAILED".
	body := testenv.CredentialsFileBodyForTest()
	if want := testenv.MatrixUsername + "\n" + testenv.MatrixPassword + "\n"; body != want {
		t.Errorf("credentials file = %q, want %q", body, want)
	}
}

// TestUserPassProfileFormsMatchTheirReader checks the one place the Auth axis
// generates two different things: our client reads its credentials from an API
// and gets the bare directive, while a stock OpenVPN client in a container has
// no terminal to prompt on and must be given a file.
func TestUserPassProfileFormsMatchTheirReader(t *testing.T) {
	e, ok := testenv.Entry("v24-gcm256-sha256-plain-udp-userpass")
	if !ok {
		t.Fatal("the auth-user-pass isolate is gone")
	}

	bare := e.ClientProfile(testProfileOptions())
	if !hasDirective(bare, "auth-user-pass") {
		t.Errorf("without CredentialsFile the profile should carry the bare directive; got:\n%s", bare)
	}

	opts := testProfileOptions()
	opts.CredentialsFile = testenv.ClientCredentialsPathForTest
	withFile := e.ClientProfile(opts)
	if !hasDirective(withFile, "auth-user-pass "+testenv.ClientCredentialsPathForTest) {
		t.Errorf("with CredentialsFile the profile should name the file; got:\n%s", withFile)
	}

	// A cert-only entry ignores the option entirely rather than emitting a
	// directive its server would not understand.
	certOnly, ok := testenv.Entry("v24-gcm256-sha256-plain-udp")
	if !ok {
		t.Fatal("the classic-derivation isolate is gone")
	}
	if p := certOnly.ClientProfile(opts); hasDirectivePrefix(p, "auth-user-pass") {
		t.Error("CredentialsFile leaked an auth-user-pass directive into a cert-only profile")
	}
}

// TestClientUnsupportedEntriesExplainThemselves guards the marker that keeps
// "the rig cannot start this" and "our client cannot drive this" apart. An
// entry carrying both is a contradiction: Unimplemented means StartMatrix
// refuses it, so the ClientUnsupported reason is a claim nothing has checked.
func TestClientUnsupportedEntriesExplainThemselves(t *testing.T) {
	for _, e := range testenv.Matrix() {
		if e.ClientUnsupported == "" {
			continue
		}
		if e.Unimplemented != "" {
			t.Errorf("%s is both Unimplemented and ClientUnsupported; the rig cannot "+
				"prove an entry it refuses to start", e.Name)
		}
	}
}

// TestForcedLZOIsOnAVersionThatCompresses guards the one entry whose value
// depends on a server behaviour rather than on a server directive. `comp-lzo
// yes` is accepted by 2.4 and 2.5 alike and only 2.4 acts on it: 2.5 and 2.6
// never compress on send without `allow-compression yes`, which nothing here
// emits (docker/COMPRESSION-VECTORS.md). An entry moved to 2.5 would still
// start and still connect, and would stop being what ErrCompressed is measured
// against.
func TestForcedLZOIsOnAVersionThatCompresses(t *testing.T) {
	forced := 0
	for _, e := range testenv.Matrix() {
		if e.Compression != testenv.CompLZOForced {
			continue
		}
		forced++
		if e.Version != testenv.V24 {
			t.Errorf("%s forces comp-lzo on OpenVPN %s, which accepts the directive and "+
				"never compresses on send; it needs 2.4, or `allow-compression yes` in "+
				"the generated server config, which ServerConfig does not emit",
				e.Name, e.Version)
		}
	}
	if forced == 0 {
		t.Error("no entry forces compression; the client's ErrCompressed has nothing " +
			"real to detect")
	}
}

// TestReferenceRejectsNamesARealRule guards the third marker on MatrixEntry,
// the one that can go wrong quietly: Unimplemented and ClientUnsupported cause
// a skip, while ReferenceRejects causes an assertion, so a value naming a rule
// that does not exist asserts something no log can ever satisfy.
func TestReferenceRejectsNamesARealRule(t *testing.T) {
	known := map[string]bool{}
	for _, name := range testenv.OracleRuleNames() {
		known[name] = true
	}
	if !known["cert-verify-failed"] {
		t.Fatal("OracleRuleNames does not include cert-verify-failed; the rule set moved")
	}

	rejecting := 0
	for _, e := range testenv.Matrix() {
		if e.ReferenceRejects == "" {
			continue
		}
		rejecting++
		if !known[e.ReferenceRejects] {
			t.Errorf("%s: ReferenceRejects = %q, which is not a rule "+
				"ClassifyReferenceLog can ever report", e.Name, e.ReferenceRejects)
		}
		if e.ReferenceRejects == "connected" {
			t.Errorf("%s: an entry cannot be expected to be refused by connecting", e.Name)
		}
		if e.Unimplemented != "" {
			t.Errorf("%s is both Unimplemented and ReferenceRejects; StartMatrix refuses "+
				"the entry, so nothing can ever check the refusal", e.Name)
		}
	}
	if rejecting == 0 {
		t.Error("no entry expects to be refused; the verify-x509-name mismatch isolate " +
			"is the reason this marker exists and it has gone")
	}
}

// TestNSCertTypeEntryGetsTheExtension checks the one place an axis reaches into
// the PKI. A server certificate issued without the extension fails the check, so
// the entry would be green only in the sense that the client refused. The
// complement matters as much: every other entry must be issued without it, or a
// client that never reads the extension is indistinguishable from one that
// does.
func TestNSCertTypeEntryGetsTheExtension(t *testing.T) {
	hasNSCertType := func(t *testing.T, pemBlock string) bool {
		t.Helper()
		blk, _ := pem.Decode([]byte(pemBlock))
		if blk == nil {
			t.Fatal("server certificate is not PEM")
		}
		cert, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			t.Fatalf("parse server certificate: %v", err)
		}
		for _, ext := range cert.Extensions {
			if ext.Id.Equal(testenv.NSCertTypeOIDForTest) {
				// 0x40 is NS_SSL_SERVER, and OpenSSL caches the first
				// content byte as ex_nscert. Six unused bits, then the
				// byte.
				if want := []byte{0x03, 0x02, 0x06, 0x40}; !bytes.Equal(ext.Value, want) {
					t.Errorf("nsCertType value = % x, want % x (the SSL-server bit)",
						ext.Value, want)
				}
				return true
			}
		}
		return false
	}

	e, ok := testenv.Entry("v24-gcm256-sha256-plain-udp-nscerttype")
	if !ok {
		t.Fatal("the ns-cert-type entry is gone; it is the capability's only vehicle")
	}
	pki, err := testenv.NewMatrixPKIForTest(e)
	if err != nil {
		t.Fatalf("NewMatrixPKIForTest: %v", err)
	}
	if !hasNSCertType(t, pki.ServerCertPEM) {
		t.Error("the ns-cert-type entry's server certificate has no Netscape " +
			"certificate-type extension, so the check would fail for the wrong reason")
	}

	plain, ok := testenv.Entry("v24-gcm256-sha256-plain-udp")
	if !ok {
		t.Fatal("the classic-derivation isolate is gone")
	}
	other, err := testenv.NewMatrixPKIForTest(plain)
	if err != nil {
		t.Fatalf("NewMatrixPKIForTest: %v", err)
	}
	if hasNSCertType(t, other.ServerCertPEM) {
		t.Error("an entry that does not ask for ns-cert-type was issued the extension " +
			"anyway; the ns-cert-type entry would then prove nothing")
	}
}

// TestServerConfigReferencesBundlePaths checks the server config only points at
// the paths the container entrypoint actually unpacks.
func TestServerConfigReferencesBundlePaths(t *testing.T) {
	for _, e := range testenv.Matrix() {
		srv := e.ServerConfig()
		for _, want := range []string{
			"ca /etc/openvpn/ca.crt",
			"cert /etc/openvpn/server.crt",
			"key /etc/openvpn/server.key",
			"dh none",
		} {
			if !hasDirective(srv, want) {
				t.Errorf("%s: server config missing %q", e.Name, want)
			}
		}
		if !hasDirective(srv, "port 1194") {
			t.Errorf("%s: server config must listen on the container port", e.Name)
		}
	}
}

// hasDirective reports whether cfg has a line exactly equal to want.
func hasDirective(cfg, want string) bool {
	for _, line := range strings.Split(cfg, "\n") {
		if strings.TrimSpace(line) == want {
			return true
		}
	}
	return false
}

// hasDirectivePrefix reports whether cfg has a non-comment line whose first
// token is name.
func hasDirectivePrefix(cfg, name string) bool {
	return directiveWithPrefix(cfg, name) != ""
}

// directiveWithPrefix returns the first non-comment line in cfg whose first
// token is name, or "".
func directiveWithPrefix(cfg, name string) string {
	if all := directivesWithPrefix(cfg, name); len(all) > 0 {
		return all[0]
	}
	return ""
}

// directivesWithPrefix returns every non-comment line in cfg whose first token
// is name, in file order. Order matters for `remote`: OpenVPN dials them in the
// order they are written.
func directivesWithPrefix(cfg, name string) []string {
	var out []string
	for _, line := range strings.Split(cfg, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if line == name || strings.HasPrefix(line, name+" ") {
			out = append(out, line)
		}
	}
	return out
}
