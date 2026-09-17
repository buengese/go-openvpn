//go:build docker

// Integration tests for the reference oracle. These need a Docker daemon and
// the pinned matrix images:
//
//	make matrix-images
//	go test -v -tags=docker -timeout 600s -run TestOracle ./testenv
//
// They assert on the oracle, not on our client: its job is to make stock
// openvpn's verdict legible and comparable without disturbing the host.
package testenv_test

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/openlawsvpn/go-openlawsvpn/diag"
	"github.com/openlawsvpn/go-openlawsvpn/testenv"
)

// oracleTestWindow shortens openvpn's handshake window for the tests. The
// failure classes that end in a timeout are the slowest thing here and the
// verdict is identical at 10s and at 60s.
const oracleTestWindow = 10 * time.Second

// oracleTestTimeout bounds one oracle run in the tests, comfortably above the
// handshake window plus container start.
const oracleTestTimeout = 45 * time.Second

// runOracle runs the oracle with the test's shortened windows and fails the
// test if the oracle itself could not run. A config that does not connect is a
// result, not a failure.
func runOracle(t *testing.T, config string, opts testenv.OracleOptions) testenv.OracleResult {
	t.Helper()
	opts.HandshakeWindow = oracleTestWindow
	opts.Timeout = oracleTestTimeout

	res, err := testenv.RunOracle(context.Background(), config, opts)
	if err != nil {
		t.Fatalf("RunOracle: %v", err)
	}
	t.Logf("%s\n  rule=%s evidence=%q\n  detail=%s", res, res.Rule, res.Evidence, res.Detail)
	assertNoKeyMaterial(t, "oracle client", res.Log)
	return res
}

// TestOracleConnectsAgainstMatrixEntry asserts that against a matrix entry the
// oracle reports "connected". One entry per pinned server version, so a
// version-specific classification bug cannot hide.
func TestOracleConnectsAgainstMatrixEntry(t *testing.T) {
	requireDocker(t)

	for _, v := range testenv.ServerVersions() {
		entries := testenv.MatrixFor(v)
		if len(entries) == 0 {
			t.Fatalf("no matrix entries for OpenVPN %s", v)
		}
		e := entries[0]
		t.Run(e.Name, func(t *testing.T) {
			srv := startEntry(t, e)
			profile, err := srv.ContainerProfile()
			if err != nil {
				t.Fatalf("ContainerProfile: %v", err)
			}

			res := runOracle(t, profile, srv.OracleOptions())
			if !res.Connected {
				t.Fatalf("oracle did not report connected: %s\nclient log:\n%s",
					res, testenv.TailLines(res.Log, 25))
			}
			if res.Rule != "connected" {
				t.Errorf("Rule = %q, want %q", res.Rule, "connected")
			}
			if res.Stage != diag.StageKeys {
				t.Errorf("Stage = %s, want %s", res.Stage, diag.StageKeys)
			}
			if res.Ambiguous {
				t.Error("a completed initialization sequence is not ambiguous")
			}
		})
	}
}

// TestOracleRecordsOpenVPNVersion asserts that the openvpn --version actually
// used is recorded in the output — the host binary is a different, much newer
// build than any pinned image, and it is the one a naive oracle would run.
func TestOracleRecordsOpenVPNVersion(t *testing.T) {
	requireDocker(t)

	e, ok := testenv.Entry("v24-cbc256-sha512-tlsauth-kd1-udp")
	if !ok {
		t.Fatal("matrix entry not found")
	}
	srv := startEntry(t, e)
	profile, err := srv.ContainerProfile()
	if err != nil {
		t.Fatalf("ContainerProfile: %v", err)
	}

	res := runOracle(t, profile, srv.OracleOptions())

	pinned, _ := testenv.PinnedVersion(e.Version)
	if res.Release != pinned {
		t.Errorf("Release = %q, want the pinned %q", res.Release, pinned)
	}
	if !strings.Contains(res.Banner, "OpenVPN "+pinned) {
		t.Errorf("Banner = %q, want it to name OpenVPN %s", res.Banner, pinned)
	}
	if res.Image != srv.Image {
		t.Errorf("Image = %q, want %q", res.Image, srv.Image)
	}

	t.Logf("openvpn that arbitrated: %s", res.Banner)
	t.Logf("openvpn on this host:    %s", res.HostBanner)
	if res.HostBanner != "" && !strings.Contains(res.HostBanner, pinned) {
		t.Logf("host binary is a different build from the one that ran — " +
			"exactly the confusion the container avoids")
	}
	if res.Preamble == nil {
		t.Error("the appended preamble is not recorded, so the verdict is not reproducible")
	}
	t.Logf("appended to the config: %s", strings.Join(res.Preamble, "; "))

	// The zero-value options must also produce a recorded, pinned version:
	// nothing in the oracle ever falls back to whatever openvpn is on PATH.
	zero := runOracle(t, profile, testenv.OracleOptions{})
	wantDefault, _ := testenv.PinnedVersion(testenv.DefaultOracleVersion)
	if zero.Release != wantDefault {
		t.Errorf("zero-value options ran %q, want the default pin %q", zero.Release, wantDefault)
	}
	if res.HostBanner != "" && zero.Release == releaseOf(res.HostBanner) {
		t.Error("the oracle appears to have run the host binary")
	}
}

// releaseOf pulls the release out of a version banner, for the assertion that
// the oracle did not run the host's openvpn.
func releaseOf(banner string) string {
	fields := strings.Fields(banner)
	if len(fields) < 2 {
		return ""
	}
	return fields[1]
}

// TestOracleClassifiesCorruptedConfigs puts each corruption through the live
// rig. Each is one a human reading the openvpn output would describe
// differently, and the test insists the classifier agrees.
func TestOracleClassifiesCorruptedConfigs(t *testing.T) {
	requireDocker(t)

	udpEntry, _ := testenv.Entry("v24-cbc256-sha512-tlsauth-kd1-udp")
	tcpEntry, _ := testenv.Entry("v25-cbc256-sha256-tlsauth-kd1-tcp")
	udp := startEntry(t, udpEntry)
	tcp := startEntry(t, tcpEntry)

	udpProfile, err := udp.ContainerProfile()
	if err != nil {
		t.Fatalf("ContainerProfile: %v", err)
	}
	tcpProfile, err := tcp.ContainerProfile()
	if err != nil {
		t.Fatalf("ContainerProfile: %v", err)
	}
	udpIP, err := udp.ContainerIP()
	if err != nil {
		t.Fatalf("ContainerIP: %v", err)
	}
	tcpIP, err := tcp.ContainerIP()
	if err != nil {
		t.Fatalf("ContainerIP: %v", err)
	}

	cases := []struct {
		name      string
		config    string
		opts      testenv.OracleOptions
		rule      string
		class     diag.Class
		stage     diag.Stage
		ambiguous bool
	}{
		{
			// The CA in the profile did not sign the server's certificate.
			name:   "bad CA",
			config: replaceInlineBlock(t, udpProfile, "ca", tcp.PKI.CACertPEM),
			opts:   udp.OracleOptions(),
			rule:   "cert-verify-failed", class: diag.ClassTLS, stage: diag.StageTLS,
		},
		{
			// A TCP port with nothing behind it.
			name: "unreachable remote, refused",
			config: strings.Replace(tcpProfile,
				fmt.Sprintf("remote %s %d", tcpIP, testenv.ContainerPort),
				fmt.Sprintf("remote %s 9", tcpIP), 1),
			opts: tcp.OracleOptions(),
			rule: "connect-failed", class: diag.ClassNetwork, stage: diag.StageDial,
		},
		{
			// A name that does not resolve.
			name:   "unreachable remote, unresolvable",
			config: strings.Replace(udpProfile, "remote "+udpIP+" ", "remote no-such-host.invalid ", 1),
			opts:   udp.OracleOptions(),
			rule:   "resolve-failed", class: diag.ClassNetwork, stage: diag.StageDial,
		},
		{
			// The right server, the wrong tls-auth key, over TCP: the
			// server drops the unauthenticated packet and, having a stream
			// to close, closes it.
			name:   "wrong tls-auth key over TCP",
			config: replaceInlineBlock(t, tcpProfile, "tls-auth", udp.PKI.StaticKey),
			opts:   tcp.OracleOptions(),
			rule:   "transport-reset", class: diag.ClassCrypto, stage: diag.StageReset,
			ambiguous: true,
		},
		{
			// A directive stock openvpn will not accept.
			name:   "unparseable config",
			config: udpProfile + "\nthis-is-not-an-openvpn-directive 1\n",
			opts:   udp.OracleOptions(),
			rule:   "config-rejected", class: diag.ClassConfig, stage: diag.StageParse,
		},
	}

	classes := map[string]diag.Class{}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := runOracle(t, tc.config, tc.opts)
			if res.Connected {
				t.Fatalf("a corrupted config connected: %s", res)
			}
			if res.Rule != tc.rule {
				t.Errorf("Rule = %q, want %q\nclient log:\n%s", res.Rule, tc.rule, testenv.TailLines(res.Log, 25))
			}
			if res.Class != tc.class {
				t.Errorf("Class = %s, want %s", res.Class, tc.class)
			}
			if res.Stage != tc.stage {
				t.Errorf("Stage = %s, want %s", res.Stage, tc.stage)
			}
			if res.Ambiguous != tc.ambiguous {
				t.Errorf("Ambiguous = %v, want %v", res.Ambiguous, tc.ambiguous)
			}
			if res.Evidence == "" {
				t.Error("no evidence line recorded; the verdict cannot be checked by hand")
			}
			classes[tc.name] = res.Class
		})
	}

	// The point of the exercise: these three must not collapse.
	distinct := map[diag.Class]string{}
	for _, name := range []string{"bad CA", "unreachable remote, refused", "wrong tls-auth key over TCP"} {
		c, ok := classes[name]
		if !ok {
			continue // its subtest already failed
		}
		if other, dup := distinct[c]; dup {
			t.Errorf("%q and %q both classify as %s", name, other, c)
		}
		distinct[c] = name
	}
}

// TestOracleUDPBlindSpotIsRealAndRecorded runs the two corruptions the
// classifier cannot separate and asserts they are inseparable on the live rig,
// not merely in the captured fixtures. On UDP a server that drops an
// unauthenticated control packet and a server that is not there produce the same
// log — silence, then the handshake window expiring — so the oracle reports
// ClassNetwork with Ambiguous set and names both causes in Detail.
//
// "A server that is not there" has to be an address the container's packets
// leave for and nothing answers. A blackhole that the local stack refuses
// instead — no route to the documentation range, which is how some hosts are
// wired — is a different log and a correct, different verdict, and the
// demonstration cannot be made on such a host. It says so rather than
// asserting the rule name a route would have produced.
func TestOracleUDPBlindSpotIsRealAndRecorded(t *testing.T) {
	requireDocker(t)

	udpEntry, _ := testenv.Entry("v24-cbc256-sha512-tlsauth-kd1-udp")
	other, _ := testenv.Entry("v25-cbc256-sha256-tlsauth-kd1-udp")
	udp := startEntry(t, udpEntry)
	spare := startEntry(t, other)

	profile, err := udp.ContainerProfile()
	if err != nil {
		t.Fatalf("ContainerProfile: %v", err)
	}
	udpIP, err := udp.ContainerIP()
	if err != nil {
		t.Fatalf("ContainerIP: %v", err)
	}

	wrongKey := runOracle(t,
		replaceInlineBlock(t, profile, "tls-auth", spare.PKI.StaticKey), udp.OracleOptions())
	blackhole := runOracle(t,
		strings.Replace(profile, "remote "+udpIP+" ", "remote 192.0.2.1 ", 1), udp.OracleOptions())

	// The half that is about this client's rig rather than the host's routing:
	// a server that drops our control packet answers nothing, and that is
	// reported as an ambiguous network failure at reset.
	if wrongKey.Rule != "no-peer-reply" {
		t.Errorf("wrong tls-auth key: Rule = %q, want %q\nclient log:\n%s",
			wrongKey.Rule, "no-peer-reply", testenv.TailLines(wrongKey.Log, 20))
	}
	if wrongKey.Class != diag.ClassNetwork || wrongKey.Stage != diag.StageReset {
		t.Errorf("wrong tls-auth key: verdict = %s@%s, want network@reset", wrongKey.Class, wrongKey.Stage)
	}
	if !wrongKey.Ambiguous {
		t.Error("the wrong-key verdict must be marked Ambiguous")
	}

	if blackhole.Rule == "connect-failed" {
		t.Skipf("this host has no route to the documentation range, so the blackholed "+
			"remote is refused locally and classifies as %s/%s rather than going quiet. "+
			"The blind spot needs an endpoint that swallows packets; the wrong-key half "+
			"above still holds.", blackhole.Class, blackhole.Rule)
	}
	if blackhole.Rule != "no-peer-reply" {
		t.Errorf("blackholed remote: Rule = %q, want %q\nclient log:\n%s",
			blackhole.Rule, "no-peer-reply", testenv.TailLines(blackhole.Log, 20))
	}
	if blackhole.Class != diag.ClassNetwork || blackhole.Stage != diag.StageReset {
		t.Errorf("blackholed remote: verdict = %s@%s, want network@reset", blackhole.Class, blackhole.Stage)
	}
	if !blackhole.Ambiguous {
		t.Error("the blackhole verdict must be marked Ambiguous")
	}
	if wrongKey.Rule != blackhole.Rule || wrongKey.Class != blackhole.Class {
		t.Errorf("the two are distinguishable on this rig: %s/%s against %s/%s; the "+
			"documented blind spot would have closed",
			wrongKey.Class, wrongKey.Rule, blackhole.Class, blackhole.Rule)
	}
}

// TestOracleLeavesHostNetworkingUnchanged proves that obtaining a verdict cannot
// disturb the machine it was obtained on. The config is given
// --redirect-gateway, so the reference client really does tear down its default
// route, and the assertion is that the host's routing table and resolver come
// back byte-identical.
func TestOracleLeavesHostNetworkingUnchanged(t *testing.T) {
	requireDocker(t)

	e, _ := testenv.Entry("v26-gcm256-sha256-tlscrypt-udp")
	srv := startEntry(t, e)
	profile, err := srv.ContainerProfile()
	if err != nil {
		t.Fatalf("ContainerProfile: %v", err)
	}

	before := hostNetworkState(t)

	opts := srv.OracleOptions()
	// Make the client do the dangerous thing on purpose.
	opts.Directives = []string{"redirect-gateway def1", "dhcp-option DNS 10.8.0.1"}
	res := runOracle(t, profile, opts)

	if !res.Connected {
		t.Fatalf("the reference client did not connect, so it never installed routes; "+
			"the assertion would be vacuous: %s\nclient log:\n%s", res, testenv.TailLines(res.Log, 25))
	}
	// Without positive evidence that the client rewrote its own default
	// route, "the host is unchanged" proves nothing.
	routeMarkers := []string{"net_route_v4_add", "route add", "ROUTE_GATEWAY", "redirect-gateway"}
	installed := false
	for _, m := range routeMarkers {
		if strings.Contains(res.Log, m) {
			t.Logf("client installed routes in its own namespace (log mentions %q)", m)
			installed = true
			break
		}
	}
	if !installed {
		t.Fatalf("the client log shows no route change, so this assertion is vacuous; "+
			"expected one of %v in:\n%s", routeMarkers, testenv.TailLines(res.Log, 30))
	}

	after := hostNetworkState(t)
	for name, got := range after {
		if want := before[name]; got != want {
			t.Errorf("%s changed across the oracle run\n--- before ---\n%s\n--- after ---\n%s",
				name, want, got)
		}
	}
	t.Logf("host routing and resolver unchanged across a run that redirected the "+
		"client's default gateway (%d snapshots compared)", len(after))
}

// hostNetworkState snapshots everything the oracle is forbidden to touch.
func hostNetworkState(t *testing.T) map[string]string {
	t.Helper()
	state := map[string]string{}
	for name, args := range map[string][]string{
		"ip route":    {"route"},
		"ip -6 route": {"-6", "route"},
		"ip rule":     {"rule", "show"},
	} {
		out, err := exec.Command("ip", args...).Output()
		if err != nil {
			t.Skipf("cannot snapshot %q: %v", name, err)
		}
		state[name] = string(out)
	}
	resolv, err := exec.Command("cat", "/etc/resolv.conf").Output()
	if err == nil {
		state["/etc/resolv.conf"] = string(resolv)
	}
	return state
}

// TestOracleProducesTheFourCellVerdict exercises the type a sweep consumes: a
// verdict pairing our outcome with stock openvpn's. Our side is supplied
// directly rather than by running the client, because the oracle does not
// depend on the client.
func TestOracleProducesTheFourCellVerdict(t *testing.T) {
	requireDocker(t)

	e, _ := testenv.Entry("v24-cbc256-sha512-tlsauth-kd1-udp")
	srv := startEntry(t, e)
	profile, err := srv.ContainerProfile()
	if err != nil {
		t.Fatalf("ContainerProfile: %v", err)
	}
	res := runOracle(t, profile, srv.OracleOptions())
	if !res.Connected {
		t.Fatalf("reference client did not connect: %s", res)
	}

	// The cell a config our client cannot drive lands in: we fail where
	// stock openvpn connects.
	ours := testenv.ClientOutcome{Class: diag.ClassUnsupported, Stage: diag.StageAuth}
	v := testenv.Compare(ours, res)
	if v.Cell != testenv.CellOurGap {
		t.Errorf("cell = %s, want %s", v.Cell, testenv.CellOurGap)
	}
	if !v.Cell.GeneratesWork() {
		t.Error("our-gap must be the cell that generates work")
	}
	t.Logf("%s", v)

	// And the cell a working client lands in.
	v = testenv.Compare(testenv.ClientOutcome{Connected: true}, res)
	if v.Cell != testenv.CellWorkingAsIntended {
		t.Errorf("cell = %s, want %s", v.Cell, testenv.CellWorkingAsIntended)
	}
	t.Logf("%s", v)
}

// TestOracleRejectsBadExtraFiles checks the input validation that keeps a
// caller-supplied credentials file from escaping the bundle. The rejection has
// to be the validation's, not the environment's: on a host without the matrix
// images every name would otherwise fail with ErrImageMissing and the test would
// pass while proving nothing.
func TestOracleRejectsBadExtraFiles(t *testing.T) {
	requireDocker(t)

	for _, name := range []string{"../escape", "sub/dir", "client.conf", ""} {
		_, err := testenv.RunOracle(context.Background(), "client\n", testenv.OracleOptions{
			Files: map[string]string{name: "x"},
		})
		if err == nil {
			t.Errorf("extra file %q was accepted", name)
			continue
		}
		if errors.Is(err, testenv.ErrImageMissing) {
			t.Errorf("extra file %q was refused for want of an image, not for being invalid: %v", name, err)
		}
	}
}

// replaceInlineBlock swaps the body of an inline <tag>...</tag> block in a
// profile, which is how the corruptions above are built.
func replaceInlineBlock(t *testing.T, profile, tag, body string) string {
	t.Helper()
	open := strings.Index(profile, "<"+tag+">")
	closing := strings.Index(profile, "</"+tag+">")
	if open < 0 || closing < 0 || closing < open {
		t.Fatalf("profile has no <%s> block", tag)
	}
	if !strings.HasSuffix(body, "\n") {
		body += "\n"
	}
	return profile[:open] + "<" + tag + ">\n" + body + profile[closing:]
}
