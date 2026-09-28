// SPDX-License-Identifier: LGPL-2.1-or-later

// Turning a reference client's log into a verdict, and recording which
// openvpn produced it.

package testenv

import (
	"os/exec"
	"regexp"
	"strings"
	"sync"

	"github.com/buengese/go-openvpn/diag"
)

// Classification
//
// Every substring below was captured from a real run of the pinned 2.4, 2.5 and
// 2.6 clients against the server matrix, not read out of the manual. The rules
// are ordered most-specific first and the first match wins.
// ---------------------------------------------------------------------------

// classifyRule is one entry in the classification table.
type classifyRule struct {
	// name is the stable rule identifier reported as Classification.Rule.
	name string
	// class and stage are the verdict.
	class diag.Class
	stage diag.Stage
	// anyOf fires the rule: the log must contain at least one of these.
	anyOf []string
	// requires must all be present for the rule to fire.
	requires []string
	// excludes must all be absent for the rule to fire.
	excludes []string
	// detail explains the verdict, including the alternatives.
	detail string
	// ambiguous marks a rule whose evidence more than one cause produces.
	ambiguous bool
}

// oracleRules is the classification table, most specific first.
var oracleRules = []classifyRule{
	{
		// openvpn refused the file before opening a socket. On 2.6 this is
		// also how a legacy directive the newer build dropped shows up,
		// which is why it must not be confused with a dead endpoint.
		name:  "config-rejected",
		class: diag.ClassConfig,
		stage: diag.StageParse,
		// "Unrecognized option or missing or extra parameter" is deliberately
		// NOT keyed on by itself: a profile carrying "setenv FORWARD_COMPATIBLE
		// 1" downgrades an unknown directive from fatal to a warning and openvpn
		// carries on to the real outcome. The fatal form always arrives prefixed
		// with "Options error:", and keying on the bare sentence masks an
		// AUTH_FAILED behind a config verdict.
		anyOf: []string{
			"Options error:",
			"Cannot load CA certificate file",
			"Cannot load certificate file",
			"Cannot load private key file",
			"Error opening configuration file",
		},
		detail: "stock openvpn refused the profile before opening a socket; " +
			"on a newer build this is also how a directive it no longer accepts appears",
	},
	{
		// The rig, not the config. Reported separately so a broken
		// container is never counted as a dead endpoint.
		name:  "local-tun",
		class: diag.ClassLocal,
		stage: diag.StageParse,
		anyOf: []string{
			"Cannot open TUN/TAP dev",
			"Cannot allocate TUN/TAP dev",
			"ERROR: Cannot open TUN/TAP",
		},
		detail: "the client container could not create a tun device; " +
			"it needs --cap-add=NET_ADMIN and --device=/dev/net/tun",
	},
	{
		name:   "auth-rejected",
		class:  diag.ClassAuth,
		stage:  diag.StageAuth,
		anyOf:  []string{"AUTH_FAILED", "SIGTERM[soft,auth-failure]"},
		detail: "the server accepted the handshake and then rejected the credentials",
	},
	{
		name:   "resolve-failed",
		class:  diag.ClassNetwork,
		stage:  diag.StageDial,
		anyOf:  []string{"RESOLVE: Cannot resolve host address"},
		detail: "the remote hostname did not resolve",
	},
	{
		// Certificate verification is a trust problem, not a credential
		// problem, and openvpn names it explicitly.
		name:  "cert-verify-failed",
		class: diag.ClassTLS,
		stage: diag.StageTLS,
		anyOf: []string{
			"VERIFY ERROR",
			"VERIFY X509NAME ERROR",
			"VERIFY KU ERROR",
			"VERIFY EKU ERROR",
			"certificate verify failed",
		},
		detail: "the client rejected the server's certificate chain: wrong or missing CA, " +
			"an expired certificate, or a name or key-usage mismatch",
	},
	{
		name:  "connect-failed",
		class: diag.ClassNetwork,
		stage: diag.StageDial,
		anyOf: []string{
			"Connection refused",
			"Network is unreachable",
			"No route to host",
			"Connection timed out",
			"ECONNREFUSED",
		},
		detail: "the transport never came up: nothing is listening, or the path is filtered",
	},
	{
		// The peer accepted the TCP connection and then hung up before a
		// single control packet was accepted. A tls-auth or tls-crypt key
		// mismatch looks exactly like this, because the server drops the
		// unauthenticated packet and, on TCP, closes the stream.
		name:     "transport-reset",
		class:    diag.ClassCrypto,
		stage:    diag.StageReset,
		requires: []string{"TCP connection established with"},
		anyOf: []string{
			"Connection reset, restarting",
			"SIGUSR1[soft,connection-reset]",
		},
		detail: "the peer accepted the TCP connection and closed it before the control channel opened; " +
			"a tls-auth or tls-crypt key mismatch produces exactly this, and so would a " +
			"non-OpenVPN service on the port",
		ambiguous: true,
	},
	{
		// The peer answered — "TLS: Initial packet from" means a control
		// packet passed the control-channel authentication — but the TLS
		// handshake never finished. The commonest cause is the server
		// rejecting our client certificate, which it does silently.
		name:     "tls-stalled-after-reply",
		class:    diag.ClassTLS,
		stage:    diag.StageTLS,
		requires: []string{"TLS: Initial packet from"},
		anyOf:    []string{"TLS key negotiation failed to occur within"},
		detail: "the peer answered and the control channel opened, but TLS never completed; " +
			"typically the server rejected our client certificate, though control-channel " +
			"MTU blackholing looks the same",
		ambiguous: true,
	},
	{
		// Nothing acceptable ever came back. This is where a dead endpoint
		// and a control-channel key mismatch become genuinely
		// indistinguishable on UDP: the server drops the unauthenticated
		// packet and, having no connection to reset, says nothing at all.
		name:     "no-peer-reply",
		class:    diag.ClassNetwork,
		stage:    diag.StageReset,
		anyOf:    []string{"TLS key negotiation failed to occur within"},
		excludes: []string{"TLS: Initial packet from"},
		detail: "no acceptable control packet ever came back: a dead or filtered endpoint and a " +
			"tls-auth or tls-crypt key mismatch are indistinguishable here on UDP",
		ambiguous: true,
	},
	{
		// Catch-all for TLS failures the specific rules above did not name.
		name:  "tls-failed",
		class: diag.ClassTLS,
		stage: diag.StageTLS,
		anyOf: []string{
			"TLS Error: TLS handshake failed",
			"TLS_ERROR:",
			"SIGUSR1[soft,tls-error]",
			"SIGTERM[soft,tls-error]",
		},
		detail: "the TLS handshake failed for a reason the specific rules do not name",
	},
	{
		// Last resort before "unclassified": openvpn said it was giving up.
		name:      "fatal-error",
		class:     diag.ClassConfig,
		stage:     diag.StageParse,
		anyOf:     []string{"Exiting due to fatal error"},
		detail:    "stock openvpn exited with a fatal error that matched no specific rule",
		ambiguous: true,
	},
}

// connectedRule is the rule name ClassifyReferenceLog reports for a client that
// completed its initialization sequence. It is not in oracleRules, because
// connecting is decided before the table is consulted.
const connectedRule = "connected"

// OracleRuleNames returns every rule name ClassifyReferenceLog can report, in
// no particular order.
//
// Classification.Rule is documented as stable and safe to aggregate on, so a
// name recorded elsewhere in the tree — MatrixEntry.ReferenceRejects, a
// report's vocabulary — can be checked against the set that exists rather than
// the set someone remembered.
func OracleRuleNames() []string {
	out := make([]string, 0, len(oracleRules)+3)
	out = append(out, connectedRule, "oracle-timeout", "unclassified")
	for _, r := range oracleRules {
		out = append(out, r.name)
	}
	return out
}

// ClassifyReferenceLog turns a stock OpenVPN client's log into a diag verdict.
//
// timedOut says whether the oracle's own deadline expired with the client still
// running; it only matters when no rule matched, in which case the run is
// reported as a network timeout at whatever stage the log proves was reached.
//
// It is pure text processing with no Docker dependency, which is what lets the
// rules be tested against captured logs in the ordinary unit suite.
func ClassifyReferenceLog(log string, timedOut bool) Classification {
	if strings.Contains(log, matrixReadyMarker) {
		return Classification{
			Connected: true,
			Stage:     diag.StageKeys,
			Rule:      connectedRule,
			Evidence:  firstLineContaining(log, matrixReadyMarker),
			Detail: "the client completed its initialization sequence: handshake, auth, push " +
				"and key derivation all succeeded",
		}
	}

	for _, r := range oracleRules {
		if !containsAll(log, r.requires) || containsAny(log, r.excludes) {
			continue
		}
		hit, ok := firstMatch(log, r.anyOf)
		if !ok {
			continue
		}
		return Classification{
			Class:     r.class,
			Stage:     r.stage,
			Rule:      r.name,
			Evidence:  firstLineContaining(log, hit),
			Detail:    r.detail,
			Ambiguous: r.ambiguous,
		}
	}

	if timedOut {
		return Classification{
			Class: diag.ClassNetwork,
			Stage: furthestStage(log),
			Rule:  "oracle-timeout",
			Detail: "the reference client was still running when the oracle's own timeout " +
				"expired, and its log named no failure",
			Ambiguous: true,
		}
	}
	return Classification{
		Class: diag.ClassLocal,
		Stage: furthestStage(log),
		Rule:  "unclassified",
		Detail: "the reference client stopped without logging anything the rules recognise; " +
			"read the log by hand and add a rule",
		Ambiguous: true,
	}
}

// stageMarkers maps a log marker to the stage its presence proves, ordered from
// furthest to nearest. Every marker is emitted at verb 3, which the oracle
// preamble pins.
var stageMarkers = []struct {
	marker string
	stage  diag.Stage
}{
	{matrixReadyMarker, diag.StageKeys},
	{"Peer Connection Initiated with", diag.StageAuth},
	{"VERIFY OK: depth=0", diag.StageTLS},
	{"TLS: Initial packet from", diag.StageReset},
	{"TCP connection established with", diag.StageDial},
	{"UDP link remote:", diag.StageDial},
	{"TCP_CLIENT link remote:", diag.StageDial},
}

// furthestStage returns the furthest stage the log proves the client reached.
func furthestStage(log string) diag.Stage {
	for _, m := range stageMarkers {
		if strings.Contains(log, m.marker) {
			return m.stage
		}
	}
	return diag.StageParse
}

// containsAll reports whether every substring is present. An empty list is
// trivially satisfied.
func containsAll(log string, subs []string) bool {
	for _, s := range subs {
		if !strings.Contains(log, s) {
			return false
		}
	}
	return true
}

// containsAny reports whether any substring is present. An empty list is never
// satisfied.
func containsAny(log string, subs []string) bool {
	_, ok := firstMatch(log, subs)
	return ok
}

// firstMatch returns the substring from subs that occurs earliest in log.
// Taking the earliest rather than the first listed keeps the reported evidence
// on the line that actually caused the failure when a rule lists several
// spellings of the same event.
func firstMatch(log string, subs []string) (string, bool) {
	best, at := "", -1
	for _, s := range subs {
		i := strings.Index(log, s)
		if i >= 0 && (at < 0 || i < at) {
			best, at = s, i
		}
	}
	return best, at >= 0
}

// logTimestamp matches the two timestamp prefixes the pinned builds emit:
// 2.4's "Sun Aug 30 18:35:22 2026 us=920690 " and 2.5/2.6's
// "2026-08-30 18:24:21 ".
var logTimestamp = regexp.MustCompile(
	`^(?:[A-Z][a-z]{2} [A-Z][a-z]{2} +\d+ \d{2}:\d{2}:\d{2} \d{4}(?: us=\d+)?|\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+`)

// firstLineContaining returns the first log line holding sub, with its leading
// timestamp stripped so the text is stable enough to assert on.
func firstLineContaining(log, sub string) string {
	for _, line := range strings.Split(log, "\n") {
		if strings.Contains(line, sub) {
			return strings.TrimSpace(logTimestamp.ReplaceAllString(strings.TrimSpace(line), ""))
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// Which openvpn ran
// ---------------------------------------------------------------------------

// openvpnBannerPattern matches an openvpn version banner anywhere in a line.
// The release must carry all three components: openvpn's own prose mentions its
// version mid-sentence — the --max-routes deprecation notice reads "... unlimited
// as of OpenVPN 2.4. This option ..." — and a two-component form matches that,
// recording a release of "2.4." instead of "2.4.12". bannerLinePattern
// additionally requires the line to look like a real banner.
var openvpnBannerPattern = regexp.MustCompile(`OpenVPN (\d+\.\d+\.\d+[^\s]*) `)

// bannerLinePattern recognises the line openvpn prints at startup: the version,
// then either a build tag or an architecture triple, then "built on".
var bannerLinePattern = regexp.MustCompile(`OpenVPN \d+\.\d+\.\d+\S* .*(built on|\[SSL)`)

// openvpnBanner extracts the version banner from a log, preferring the line
// openvpn itself printed over the one the image entrypoint echoes.
func openvpnBanner(log string) string {
	var fallback string
	for _, line := range strings.Split(log, "\n") {
		i := openvpnBannerPattern.FindStringIndex(line)
		if i == nil || !bannerLinePattern.MatchString(line) {
			continue
		}
		banner := strings.TrimSpace(line[i[0]:])
		if strings.Contains(line[:i[0]], "entrypoint:") {
			if fallback == "" {
				fallback = banner
			}
			continue
		}
		return banner
	}
	return fallback
}

// releaseFromBanner extracts the exact release, for example "2.6.22", from a
// version banner. It returns the empty string when the banner is unparseable.
func releaseFromBanner(banner string) string {
	m := openvpnBannerPattern.FindStringSubmatch(banner)
	if m == nil {
		return ""
	}
	return m[1]
}

// imageOpenVPNBanner asks an image for its openvpn version directly. It is the
// fallback for a run whose log carried no banner at all.
func imageOpenVPNBanner(image string) string {
	out, _ := exec.Command("docker", "run", "--rm", //nolint:errcheck // banner is best effort
		"--entrypoint", "openvpn", image, "--version").CombinedOutput()
	return openvpnBanner(string(out))
}

// hostBannerOnce caches the host lookup: it never changes within a process and
// a great many oracle runs would otherwise each fork openvpn.
var hostBannerOnce struct {
	sync.Once
	banner string
}

// hostOpenVPNBanner returns the first line of the host's `openvpn --version`,
// or the empty string when the host has no openvpn.
//
// The oracle never runs the host binary — the whole point of the container is
// that the version is pinned. It is recorded only so a "we connect, stock
// openvpn does not" verdict can be checked against the obvious explanation,
// which is that the two are different builds.
func hostOpenVPNBanner() string {
	hostBannerOnce.Do(func() {
		path, err := exec.LookPath("openvpn")
		if err != nil {
			return
		}
		out, _ := exec.Command(path, "--version").CombinedOutput() //nolint:errcheck // openvpn --version exits nonzero on some builds
		for _, line := range strings.Split(string(out), "\n") {
			if strings.HasPrefix(line, "OpenVPN ") {
				hostBannerOnce.banner = strings.TrimSpace(line)
				return
			}
		}
	})
	return hostBannerOnce.banner
}

// ---------------------------------------------------------------------------
