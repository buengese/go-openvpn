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
	"errors"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/openlawsvpn/go-openlawsvpn/testenv"
)

// matrixStartBudget is the per-entry start budget. Image builds are not part
// of it — they are `make matrix-images`.
const matrixStartBudget = 10 * time.Second

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
