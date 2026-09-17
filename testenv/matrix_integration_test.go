//go:build docker

// Integration tests for the server matrix. These need a Docker daemon and the
// pinned server images:
//
//	make matrix-images
//	go test -v -tags=docker -timeout 600s ./testenv
//
// They assert on the rig, not on our client: a real OpenVPN server of each
// pinned version comes up on demand, and the client profile generated alongside
// it works.
package testenv_test

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openlawsvpn/go-openlawsvpn/diag"
	"github.com/openlawsvpn/go-openlawsvpn/testenv"
)

// matrixStartBudget is the per-entry start budget. Image builds are not part
// of it — they are `make matrix-images`.
const matrixStartBudget = 10 * time.Second

// referenceClientTimeout bounds how long a stock OpenVPN client is given to
// complete its handshake against a matrix server.
const referenceClientTimeout = 30 * time.Second

// requireDocker skips the test when there is no usable Docker daemon, so a
// developer without one still gets a clear message rather than a failure.
func requireDocker(t *testing.T) {
	t.Helper()
	if err := exec.Command("docker", "version").Run(); err != nil {
		t.Skipf("no usable Docker daemon: %v", err)
	}
}

// startEntry starts a matrix entry, registers teardown, and fails on anything
// other than a clean start or a documented skip.
func startEntry(t *testing.T, e testenv.MatrixEntry) *testenv.MatrixServer {
	t.Helper()

	start := time.Now()
	srv, err := testenv.StartMatrix(e)
	elapsed := time.Since(start)

	switch {
	case errors.Is(err, testenv.ErrUnimplemented):
		t.Skipf("matrix entry not implemented yet: %v", err)
	case errors.Is(err, testenv.ErrImageMissing):
		t.Fatalf("%v", err)
	case err != nil:
		t.Fatalf("StartMatrix(%s): %v", e.Name, err)
	}

	t.Logf("started %s in %s (image %s, addr %q, addr6 %q)",
		e.Name, elapsed.Round(time.Millisecond), srv.Image, srv.Addr, srv.Addr6)

	t.Cleanup(func() {
		id := srv.ContainerID
		if err := srv.Stop(); err != nil {
			t.Errorf("Stop(%s): %v", e.Name, err)
			return
		}
		// "Tears down cleanly" means the container is actually gone, not
		// merely stopped.
		if err := exec.Command("docker", "inspect", id).Run(); err == nil {
			t.Errorf("container %s still exists after Stop", id[:12])
		}
	})
	return srv
}

// TestMatrixOnePerVersion asserts one entry per pinned server version comes up
// and tears down cleanly.
func TestMatrixOnePerVersion(t *testing.T) {
	requireDocker(t)

	for _, v := range testenv.ServerVersions() {
		entries := testenv.MatrixFor(v)
		if len(entries) == 0 {
			t.Fatalf("no matrix entries for OpenVPN %s", v)
		}
		e := entries[0]
		t.Run(string(v), func(t *testing.T) {
			srv := startEntry(t, e)

			logs, err := srv.Logs()
			if err != nil {
				t.Fatalf("Logs: %v", err)
			}
			pinned, _ := testenv.PinnedVersion(v)
			if !strings.Contains(logs, "OpenVPN "+pinned) {
				t.Errorf("server log does not report OpenVPN %s; got:\n%s", pinned, testenv.TailLines(logs, 10))
			}
			if !strings.Contains(logs, "Initialization Sequence Completed") {
				t.Error("server log lacks the readiness marker")
			}
			if srv.DialAddr() == "" {
				t.Error("server exposes no dialable address")
			}
			assertNoKeyMaterial(t, "server", logs)
		})
	}
}

// TestMatrixNamedEntryStartTime asserts the start budget: a named entry starts
// from a Go test in under ten seconds, with image builds out of the timed path.
func TestMatrixNamedEntryStartTime(t *testing.T) {
	requireDocker(t)

	const name = "v24-cbc256-sha512-tlsauth-kd1-udp"
	e, ok := testenv.Entry(name)
	if !ok {
		t.Fatalf("Entry(%q) not found", name)
	}

	start := time.Now()
	srv, err := testenv.StartMatrix(e)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("StartMatrix(%s): %v", name, err)
	}
	defer srv.Stop() //nolint:errcheck

	t.Logf("%s started in %s", name, elapsed.Round(time.Millisecond))
	if elapsed > matrixStartBudget {
		t.Errorf("start took %s, budget is %s", elapsed.Round(time.Millisecond), matrixStartBudget)
	}
}

// TestMatrixReferenceClient proves the rig actually serves: a stock OpenVPN
// client of the same pinned version, in a throwaway container, completes a full
// handshake using the profile generated from the same matrix entry. An entry
// carrying ReferenceRejects is asserted the other way round and just as
// strictly — it must fail, and through the named rule, because "did not
// connect" is also what a server that never came up produces. An entry the rig
// cannot bring up is skipped with its reason.
func TestMatrixReferenceClient(t *testing.T) {
	requireDocker(t)

	// Every entry, not a sample: the server config and the client profile are
	// generated from the same entry, and a sample would prove it only for the
	// sampled axes.
	for _, e := range testenv.Matrix() {
		t.Run(e.Name, func(t *testing.T) {
			if reason := e.SkipReason(); reason != "" {
				t.Skipf("not implemented: %s", reason)
			}
			srv := startEntry(t, e)

			// The host-side profile is generated from the same entry as the
			// container's and names the address this server actually came up
			// on, so it has to be a profile a client could dial.
			if profile := srv.ClientProfile(); !strings.Contains(profile, "remote ") {
				t.Error("generated client profile has no remote")
			}

			res, err := srv.CheckWithReferenceClient(referenceClientTimeout)
			if errors.Is(err, testenv.ErrUnimplemented) {
				t.Skipf("reference client check not available: %v", err)
			}
			if err != nil {
				t.Fatalf("CheckWithReferenceClient: %v", err)
			}

			if e.ReferenceRejects != "" {
				if res.Connected {
					t.Fatalf("the reference client connected to an entry designed to be "+
						"refused (%s); the check it exists to fail is not being made\n"+
						"client log:\n%s", e.ReferenceRejects, testenv.TailLines(res.Log, 30))
				}
				if res.Classification.Rule != e.ReferenceRejects {
					t.Errorf("refused by rule %q (%s at %s), want %q; the entry failed, "+
						"but not for the reason it was built to fail\nclient log:\n%s",
						res.Classification.Rule, res.Classification.Class,
						res.Classification.Stage, e.ReferenceRejects, testenv.TailLines(res.Log, 30))
				}
				t.Logf("%s refused as designed: %s at %s via %s", e.Name,
					res.Classification.Class, res.Classification.Stage, res.Classification.Rule)
				assertNoKeyMaterial(t, "reference client", res.Log)
				return
			}

			if !res.Connected {
				t.Fatalf("reference client did not connect (%s at %s via %s); client log:\n%s",
					res.Classification.Class, res.Classification.Stage,
					res.Classification.Rule, testenv.TailLines(res.Log, 30))
			}
			// The client config is fully inline, so its container log is the
			// place key material would leak; tests print it on failure.
			assertNoKeyMaterial(t, "reference client", res.Log)
		})
	}
}

// TestMatrixCredentialsAreChecked runs the Auth entry a second time with a
// password the hook must reject, and asks the reference oracle's classifier what
// happened: connecting with the right password is also satisfied by a hook that
// returns success unconditionally or is never invoked. diag.ClassAuth at
// diag.StageAuth is the verdict wrong credentials are required to produce.
func TestMatrixCredentialsAreChecked(t *testing.T) {
	requireDocker(t)

	const name = "v24-gcm256-sha256-plain-udp-userpass"
	e, ok := testenv.Entry(name)
	if !ok {
		t.Fatalf("Entry(%q) not found", name)
	}
	srv := startEntry(t, e)

	profile, err := srv.ContainerProfile()
	if err != nil {
		t.Fatalf("ContainerProfile: %v", err)
	}

	opts := srv.OracleOptions()
	opts.Timeout = referenceClientTimeout
	// The right username, so the run cannot be explained by the server
	// having failed to find the file or read it.
	opts.Files = map[string]string{
		testenv.MatrixCredentialsFile: testenv.MatrixUsername + "\nnot-the-password\n",
	}

	res, err := testenv.RunOracle(context.Background(), profile, opts)
	if err != nil {
		t.Fatalf("RunOracle: %v", err)
	}
	t.Logf("wrong password: %s", res)

	if res.Connected {
		t.Fatalf("the reference client connected with the wrong password; "+
			"the entry does not check credentials at all\nclient log:\n%s", testenv.TailLines(res.Log, 25))
	}
	if res.Class != diag.ClassAuth || res.Stage != diag.StageAuth {
		t.Errorf("wrong password classified as %s at %s, want %s at %s; "+
			"a credentials failure that looks like anything else makes the sweep "+
			"unreadable\nclient log:\n%s",
			res.Class, res.Stage, diag.ClassAuth, diag.StageAuth, testenv.TailLines(res.Log, 25))
	}
	assertNoKeyMaterial(t, "oracle client", res.Log)
}

// TestCertificateChecksAreActuallyPerformed reads the reference client's log for
// the line it prints when it performs the check, and the mismatching entry's for
// the line it prints when it fails one: connecting is also satisfied by a build
// that silently ignores the directive. The `ns-cert-type` half is the only
// evidence that capability has, and it rests on a certificate extension the rig
// itself has to issue.
func TestCertificateChecksAreActuallyPerformed(t *testing.T) {
	requireDocker(t)

	for _, tc := range []struct {
		entry   string
		wantLog string
		why     string
	}{
		{
			entry: "v24-gcm256-sha256-plain-udp-x509name",
			// ssl_verify.c prints this only when --verify-x509-name is set
			// and the subject or CN matched.
			wantLog: "VERIFY X509NAME OK",
			why:     "the name was matched rather than the directive ignored",
		},
		{
			entry:   "v24-gcm256-sha256-plain-udp-x509name-bad",
			wantLog: "VERIFY X509NAME ERROR",
			why:     "the name was checked and did not match, which is the entry's purpose",
		},
		{
			entry: "v24-gcm256-sha256-plain-udp-nscerttype",
			// Printed only when --ns-cert-type is set and the Netscape
			// certificate-type extension carried the SSL-server bit: the
			// directive was honoured and the rig issued the extension.
			wantLog: "VERIFY OK: nsCertType=SERVER",
			why:     "the legacy extension was found and checked",
		},
	} {
		t.Run(tc.entry, func(t *testing.T) {
			e, ok := testenv.Entry(tc.entry)
			if !ok {
				t.Fatalf("Entry(%q) not found", tc.entry)
			}
			srv := startEntry(t, e)

			res, err := srv.CheckWithReferenceClient(referenceClientTimeout)
			if err != nil {
				t.Fatalf("CheckWithReferenceClient: %v", err)
			}
			if !strings.Contains(res.Log, tc.wantLog) {
				t.Fatalf("the reference client log does not carry %q, so it cannot be "+
					"said that %s\nclient log:\n%s", tc.wantLog, tc.why, testenv.TailLines(res.Log, 30))
			}
			t.Logf("%s: %s — %s", tc.entry, tc.wantLog, tc.why)
		})
	}
}

// TestMultiRemoteEntryReallyFailsOver reads the log for the first remote's
// refusal and requires it before the connection. Connecting alone is also
// satisfied by a profile whose first remote happened to be alive, which would
// report failover green while nothing had failed over.
func TestMultiRemoteEntryReallyFailsOver(t *testing.T) {
	requireDocker(t)

	const name = "v24-gcm256-sha256-plain-tcp-multiremote"
	e, ok := testenv.Entry(name)
	if !ok {
		t.Fatalf("Entry(%q) not found; the failover isolate is gone", name)
	}
	srv := startEntry(t, e)

	if srv.DeadPort == 0 {
		t.Fatal("no dead port was reserved; the first remote would be the live one")
	}
	if srv.DeadPort == srv.Port {
		t.Fatal("the dead port is the live port")
	}

	res, err := srv.CheckWithReferenceClient(referenceClientTimeout)
	if err != nil {
		t.Fatalf("CheckWithReferenceClient: %v", err)
	}
	if !res.Connected {
		t.Fatalf("reference client did not connect through the second remote (%s at %s); "+
			"client log:\n%s", res.Classification.Class, res.Classification.Stage, testenv.TailLines(res.Log, 30))
	}

	// The container profile's dead remote is ContainerPort+1, and nothing in
	// the container's network namespace listens on it — so a TCP connect
	// there is refused, unambiguously, which is why this entry is TCP.
	refusedAt := strings.Index(res.Log, "Connection refused")
	if refusedAt < 0 {
		t.Fatalf("the reference client never had a connection refused, so the first "+
			"remote answered and nothing failed over; client log:\n%s", testenv.TailLines(res.Log, 30))
	}
	connectedAt := strings.Index(res.Log, "Initialization Sequence Completed")
	if connectedAt < 0 {
		t.Fatal("connected, but the readiness marker is not in the log")
	}
	if refusedAt > connectedAt {
		t.Error("the refusal came after the connection; the first remote was not the dead one")
	}
	t.Logf("%s: first remote refused, second remote connected", name)
}

// TestCAFileEntryIsUsableFromDisk proves the file-referenced CA entry is a
// working pair rather than a profile naming a file nobody writes. The host-side
// profile and the reference client's are generated from one entry but resolve
// their CA differently: a bare base name beside the profile here, an absolute
// path inside the container there, whose entrypoint runs openvpn from /.
func TestCAFileEntryIsUsableFromDisk(t *testing.T) {
	requireDocker(t)

	const name = "v24-gcm256-sha256-plain-udp-cafile"
	e, ok := testenv.Entry(name)
	if !ok {
		t.Fatalf("Entry(%q) not found; the file-CA half of certificate verification is gone", name)
	}
	srv := startEntry(t, e)

	dir := t.TempDir()
	path, err := srv.WriteClientProfile(dir)
	if err != nil {
		t.Fatalf("WriteClientProfile: %v", err)
	}
	body, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("read profile: %v", err)
	}
	if !strings.Contains(string(body), "ca "+testenv.MatrixCAFile) {
		t.Errorf("host-side profile does not name %q:\n%s", testenv.MatrixCAFile, body)
	}
	if strings.Contains(string(body), "BEGIN CERTIFICATE") && strings.Contains(string(body), "<ca>") {
		t.Error("host-side profile inlines its CA as well; inline wins and the file " +
			"reference would never be read")
	}

	// The file the profile names has to be there, beside it, and has to be
	// this run's CA — not a stale one from another server.
	caPath := filepath.Join(dir, testenv.MatrixCAFile)
	ca, err := os.ReadFile(filepath.Clean(caPath))
	if err != nil {
		t.Fatalf("the profile names a CA file that was not written: %v", err)
	}
	if string(ca) != srv.PKI.CACertPEM {
		t.Error("the CA beside the profile is not this server's")
	}

	// The container's copy resolves by absolute path, and the reference
	// client proves the whole arrangement serves.
	container, err := srv.ContainerProfile()
	if err != nil {
		t.Fatalf("ContainerProfile: %v", err)
	}
	if !strings.Contains(container, "ca "+testenv.ClientCAPathForTest) {
		t.Errorf("container profile does not name %q; a relative name would not "+
			"resolve, because the entrypoint runs openvpn from /",
			testenv.ClientCAPathForTest)
	}

	res, err := srv.CheckWithReferenceClient(referenceClientTimeout)
	if err != nil {
		t.Fatalf("CheckWithReferenceClient: %v", err)
	}
	if !res.Connected {
		t.Fatalf("reference client did not connect with a file-referenced CA (%s at %s); "+
			"client log:\n%s", res.Classification.Class, res.Classification.Stage, testenv.TailLines(res.Log, 30))
	}
}

// TestForcedLZOTurnsAdaptiveCompressionOff reads OpenVPN's own state dump: at
// verb 4 the server prints its compression settings, and COMP_F_ADAPTIVE is bit
// 0 of comp.flags — bare `comp-lzo` gives 1, `comp-lzo yes` gives 0. Bare is
// adaptive, so the peer stops compressing whenever its heuristic says so, and an
// entry that exists to put a compressed payload on the wire cannot leave that to
// a heuristic. The pair is asserted rather than the value alone, because a flag
// that stopped being printed would read as success.
func TestForcedLZOTurnsAdaptiveCompressionOff(t *testing.T) {
	requireDocker(t)

	// comp.alg = 2 is LZO in OpenVPN 2.4's compression table; both entries
	// must be on it, or the flag comparison is between two different
	// algorithms.
	const wantAlg = "comp.alg = 2"

	flagsFor := func(t *testing.T, entry string) string {
		t.Helper()
		e, ok := testenv.Entry(entry)
		if !ok {
			t.Fatalf("Entry(%q) not found", entry)
		}
		srv := startEntry(t, e)
		logs, err := srv.Logs()
		if err != nil {
			t.Fatalf("Logs: %v", err)
		}
		if !strings.Contains(logs, wantAlg) {
			t.Fatalf("%s: server did not report %q; the entry is not on the LZO path\n%s",
				entry, wantAlg, testenv.TailLines(logs, 30))
		}
		for _, line := range strings.Split(logs, "\n") {
			if i := strings.Index(line, "comp.flags = "); i >= 0 {
				return strings.TrimSpace(line[i+len("comp.flags = "):])
			}
		}
		t.Fatalf("%s: server log has no comp.flags line; the evidence this test "+
			"rests on has moved\n%s", entry, testenv.TailLines(logs, 30))
		return ""
	}

	adaptive := flagsFor(t, "v24-cbc256-sha1-complzo-udp")
	forced := flagsFor(t, "v24-cbc256-sha1-complzoyes-udp")

	if adaptive == forced {
		t.Fatalf("both LZO entries report comp.flags = %s; `comp-lzo yes` is not "+
			"turning adaptive compression off and the forced entry duplicates its "+
			"neighbour", adaptive)
	}
	if forced != "0" {
		t.Errorf("the forced entry reports comp.flags = %s, want 0 (COMP_F_ADAPTIVE clear)", forced)
	}
	t.Logf("comp.flags: bare comp-lzo = %s (adaptive), comp-lzo yes = %s (always compress)",
		adaptive, forced)
}

// TestMatrixStopIsIdempotent verifies Stop can be called more than once, which
// the defer-plus-Cleanup pattern in tests relies on.
func TestMatrixStopIsIdempotent(t *testing.T) {
	requireDocker(t)

	e, _ := testenv.Entry("v26-gcm256-sha256-tlscrypt-udp")
	srv, err := testenv.StartMatrix(e)
	if err != nil {
		t.Fatalf("StartMatrix: %v", err)
	}
	if err := srv.Stop(); err != nil {
		t.Fatalf("first Stop: %v", err)
	}
	if err := srv.Stop(); err != nil {
		t.Fatalf("second Stop: %v", err)
	}
}

// TestMatrixRestartKeepsTheAddress proves the rig can break a link and repair
// it, which is what a reconnect test needs. The property is not that a container
// can be restarted but that the server coming back is the same server at the
// same address, the client under test holding a profile that names one remote.
// Three things are checked in the order a client meets them: nothing answers
// while the link is broken, the address afterwards is the one from before, and a
// stock client still handshakes against the replacement with the profile
// generated for the original. TCP, because a refused connect is unambiguous
// where a datagram going nowhere is not.
func TestMatrixRestartKeepsTheAddress(t *testing.T) {
	requireDocker(t)

	const name = "v24-gcm256-sha256-plain-tcp"
	e, ok := testenv.Entry(name)
	if !ok {
		t.Fatalf("Entry(%q) not found", name)
	}
	srv := startEntry(t, e)

	before := srv.ContainerID
	addr := srv.Addr
	if before == "" || addr == "" {
		t.Fatalf("started server has no container (%q) or no address (%q)", before, addr)
	}

	if err := srv.Interrupt(); err != nil {
		t.Fatalf("Interrupt: %v", err)
	}
	if srv.ContainerID != "" {
		t.Errorf("Interrupt left a container id: %q", srv.ContainerID)
	}
	if conn, err := net.DialTimeout("tcp", addr, 2*time.Second); err == nil {
		conn.Close() //nolint:errcheck
		t.Fatalf("%s still answers with the container removed: the link did not break", addr)
	}

	if err := srv.Resume(); err != nil {
		t.Fatalf("Resume: %v", err)
	}
	if srv.ContainerID == "" {
		t.Fatal("Resume produced no container")
	}
	if srv.ContainerID == before {
		t.Error("Resume reported the removed container's id")
	}
	if srv.Addr != addr {
		t.Errorf("address after Resume = %q, want %q: the client's remote must still resolve",
			srv.Addr, addr)
	}

	// A second Resume is a programming error, not a no-op: it would leak a
	// container that Stop would never remove.
	if err := srv.Resume(); err == nil {
		t.Error("a second Resume was accepted, which would leak a container")
	}

	// Restart is the pair in one call, for a caller that does not need the
	// link down for a measurable while. The address has to survive it too, and
	// the reference client below runs against a server replaced twice.
	replaced := srv.ContainerID
	if err := srv.Restart(); err != nil {
		t.Fatalf("Restart: %v", err)
	}
	if srv.ContainerID == replaced {
		t.Error("Restart kept the previous container")
	}
	if srv.Addr != addr {
		t.Errorf("address after Restart = %q, want %q", srv.Addr, addr)
	}

	res, err := srv.CheckWithReferenceClient(referenceClientTimeout)
	if err != nil {
		t.Fatalf("CheckWithReferenceClient after Resume: %v", err)
	}
	if !res.Connected {
		t.Fatalf("the reference client did not connect to the replacement (%s at %s); "+
			"the restart did not preserve the configuration or the PKI; client log:\n%s",
			res.Classification.Class, res.Classification.Stage, testenv.TailLines(res.Log, 30))
	}
	t.Logf("%s: restarted at %s and still serving the original profile", name, addr)
}

// TestMatrixLeavesNoStrays checks that nothing labelled as a matrix artefact is
// still around. It runs last in this file, after every other matrix test has
// completed its cleanup.
func TestMatrixLeavesNoStrays(t *testing.T) {
	requireDocker(t)

	for _, what := range []struct {
		name string
		args []string
	}{
		{"containers", []string{"ps", "-a", "--filter", "label=" + testenv.MatrixLabel, "--format", "{{.ID}} {{.Image}} {{.Status}}"}},
		{"networks", []string{"network", "ls", "--filter", "label=" + testenv.MatrixLabel, "--format", "{{.Name}}"}},
	} {
		out, err := exec.Command("docker", what.args...).Output()
		if err != nil {
			t.Fatalf("docker %s: %v", what.name, err)
		}
		if s := strings.TrimSpace(string(out)); s != "" {
			t.Errorf("stray matrix %s left behind:\n%s", what.name, s)
		}
	}
}

// assertNoKeyMaterial fails if a captured container log carries key material.
// Matrix keys are throwaway, but logs are printed on failure and aggregated into
// reports, so they must stay clean.
func assertNoKeyMaterial(t *testing.T, what, log string) {
	t.Helper()
	for _, marker := range []string{"PRIVATE KEY", "OpenVPN Static key"} {
		if strings.Contains(log, marker) {
			t.Errorf("%s log contains %q", what, marker)
		}
	}
}
