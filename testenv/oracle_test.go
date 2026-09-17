package testenv_test

import (
	"strings"
	"testing"
	"time"

	"github.com/openlawsvpn/go-openlawsvpn/diag"
	"github.com/openlawsvpn/go-openlawsvpn/testenv"
)

// The logs below were captured verbatim from the pinned 2.4.12, 2.5.11 and
// 2.6.22 clients against the server matrix, trimmed of certificate bodies and
// repeated retry cycles. They are the classifier's fixtures, so a change in
// openvpn's wording fails the unit suite without needing Docker.
const (
	logConnected = `entrypoint: OpenVPN 2.4.12 x86_64-pc-linux-gnu [SSL (OpenSSL)] [LZO] [LZ4] [EPOLL] [MH/PKTINFO] [AEAD] built on Aug 30 2026
Sun Aug 30 18:38:26 2026 OpenVPN 2.4.12 x86_64-pc-linux-gnu [SSL (OpenSSL)] [LZO] [LZ4] [EPOLL] [MH/PKTINFO] [AEAD] built on Aug 30 2026
Sun Aug 30 18:38:26 2026 library versions: OpenSSL 1.1.1w  11 Sep 2023, LZO 2.10
Sun Aug 30 18:38:26 2026 UDP link remote: [AF_INET]172.28.0.2:1194
Sun Aug 30 18:38:26 2026 TLS: Initial packet from [AF_INET]172.28.0.2:1194, sid=2a5ba0f7 09fa0d0a
Sun Aug 30 18:38:26 2026 VERIFY OK: depth=0, CN=matrix-server
Sun Aug 30 18:38:26 2026 [matrix-server] Peer Connection Initiated with [AF_INET]172.28.0.2:1194
Sun Aug 30 18:38:27 2026 TUN/TAP device tun0 opened
Sun Aug 30 18:38:27 2026 Initialization Sequence Completed`

	// A CA that does not sign the server's certificate.
	logBadCA = `entrypoint: OpenVPN 2.4.12 x86_64-pc-linux-gnu [SSL (OpenSSL)] [LZO] [LZ4] [EPOLL] [MH/PKTINFO] [AEAD] built on Aug 30 2026
Sun Aug 30 18:26:53 2026 OpenVPN 2.4.12 x86_64-pc-linux-gnu [SSL (OpenSSL)] [LZO] [LZ4] [EPOLL] [MH/PKTINFO] [AEAD] built on Aug 30 2026
Sun Aug 30 18:26:53 2026 UDP link remote: [AF_INET]172.28.0.2:1194
Sun Aug 30 18:26:53 2026 TLS: Initial packet from [AF_INET]172.28.0.2:1194, sid=35f9b29b 8ea9c90b
Sun Aug 30 18:26:53 2026 VERIFY ERROR: depth=1, error=self signed certificate in certificate chain: CN=openlawsvpn-matrix-ca, serial=1
Sun Aug 30 18:26:53 2026 OpenSSL: error:1416F086:SSL routines:tls_process_server_certificate:certificate verify failed
Sun Aug 30 18:26:53 2026 TLS_ERROR: BIO read tls_read_plaintext error
Sun Aug 30 18:26:53 2026 TLS Error: TLS object -> incoming plaintext read error
Sun Aug 30 18:26:53 2026 TLS Error: TLS handshake failed
Sun Aug 30 18:26:53 2026 SIGUSR1[soft,tls-error] received, process restarting`

	// A hostname that does not resolve.
	logResolveFailed = `entrypoint: OpenVPN 2.4.12 x86_64-pc-linux-gnu [SSL (OpenSSL)] [LZO] [LZ4] [EPOLL] [MH/PKTINFO] [AEAD] built on Aug 30 2026
Sun Aug 30 18:38:27 2026 OpenVPN 2.4.12 x86_64-pc-linux-gnu [SSL (OpenSSL)] [LZO] [LZ4] [EPOLL] [MH/PKTINFO] [AEAD] built on Aug 30 2026
Sun Aug 30 18:38:48 2026 RESOLVE: Cannot resolve host address: no-such-host.invalid:1194 (Name or service not known) (I would have retried this name query if you had specified the --resolv-retry option.)
Sun Aug 30 18:38:48 2026 Exiting due to fatal error`

	// A TCP port with nothing listening.
	logConnectionRefused = `entrypoint: OpenVPN 2.5.11 x86_64-pc-linux-gnu [SSL (OpenSSL)] [LZO] [LZ4] [EPOLL] [MH/PKTINFO] [AEAD] built on Aug 30 2026
2026-08-30 18:24:21 OpenVPN 2.5.11 x86_64-pc-linux-gnu [SSL (OpenSSL)] [LZO] [LZ4] [EPOLL] [MH/PKTINFO] [AEAD] built on Aug 30 2026
2026-08-30 18:24:21 Attempting to establish TCP connection with [AF_INET]172.28.0.3:9 [nonblock]
2026-08-30 18:24:21 TCP: connect to [AF_INET]172.28.0.3:9 failed: Connection refused
2026-08-30 18:24:21 SIGUSR1[connection failed(soft),init_instance] received, process restarting`

	// A wrong tls-auth key over TCP: the server drops the unauthenticated
	// packet and closes the stream.
	logTLSAuthMismatchTCP = `entrypoint: OpenVPN 2.5.11 x86_64-pc-linux-gnu [SSL (OpenSSL)] [LZO] [LZ4] [EPOLL] [MH/PKTINFO] [AEAD] built on Aug 30 2026
2026-08-30 18:25:22 OpenVPN 2.5.11 x86_64-pc-linux-gnu [SSL (OpenSSL)] [LZO] [LZ4] [EPOLL] [MH/PKTINFO] [AEAD] built on Aug 30 2026
2026-08-30 18:25:22 Outgoing Control Channel Authentication: Using 256 bit message hash 'SHA256' for HMAC authentication
2026-08-30 18:25:22 Attempting to establish TCP connection with [AF_INET]172.28.0.3:1194 [nonblock]
2026-08-30 18:25:22 TCP connection established with [AF_INET]172.28.0.3:1194
2026-08-30 18:25:22 TCP_CLIENT link remote: [AF_INET]172.28.0.3:1194
2026-08-30 18:25:22 Connection reset, restarting [0]
2026-08-30 18:25:22 SIGUSR1[soft,connection-reset] received, process restarting`

	// A wrong tls-auth key over UDP. Byte-for-byte the same shape as a
	// blackholed remote: the server has nothing to reset and says nothing.
	logTLSAuthMismatchUDP = `entrypoint: OpenVPN 2.4.12 x86_64-pc-linux-gnu [SSL (OpenSSL)] [LZO] [LZ4] [EPOLL] [MH/PKTINFO] [AEAD] built on Aug 30 2026
Sun Aug 30 18:27:24 2026 OpenVPN 2.4.12 x86_64-pc-linux-gnu [SSL (OpenSSL)] [LZO] [LZ4] [EPOLL] [MH/PKTINFO] [AEAD] built on Aug 30 2026
Sun Aug 30 18:27:24 2026 Outgoing Control Channel Authentication: Using 512 bit message hash 'SHA512' for HMAC authentication
Sun Aug 30 18:27:24 2026 UDP link remote: [AF_INET]172.28.0.2:1194
Sun Aug 30 18:28:24 2026 TLS Error: TLS key negotiation failed to occur within 60 seconds (check your network connectivity)
Sun Aug 30 18:28:24 2026 TLS Error: TLS handshake failed
Sun Aug 30 18:28:24 2026 SIGUSR1[soft,tls-error] received, process restarting`

	// A blackholed UDP remote (TEST-NET-1).
	logBlackholedUDP = `entrypoint: OpenVPN 2.4.12 x86_64-pc-linux-gnu [SSL (OpenSSL)] [LZO] [LZ4] [EPOLL] [MH/PKTINFO] [AEAD] built on Aug 30 2026
Sun Aug 30 18:35:40 2026 us=101042 OpenVPN 2.4.12 x86_64-pc-linux-gnu [SSL (OpenSSL)] [LZO] [LZ4] [EPOLL] [MH/PKTINFO] [AEAD] built on Aug 30 2026
Sun Aug 30 18:35:40 2026 us=102799 UDP link remote: [AF_INET]192.0.2.1:1194
Sun Aug 30 18:35:55 2026 us=261268 TLS Error: TLS key negotiation failed to occur within 15 seconds (check your network connectivity)
Sun Aug 30 18:35:55 2026 us=261336 TLS Error: TLS handshake failed
Sun Aug 30 18:35:55 2026 us=261595 SIGTERM[soft,tls-error] received, process exiting`

	// A client certificate the server would not accept: our own verification
	// of the server succeeded, then the handshake stalled.
	logClientCertRejected = `entrypoint: OpenVPN 2.4.12 x86_64-pc-linux-gnu [SSL (OpenSSL)] [LZO] [LZ4] [EPOLL] [MH/PKTINFO] [AEAD] built on Aug 30 2026
Sun Aug 30 18:35:24 2026 us=368784 OpenVPN 2.4.12 x86_64-pc-linux-gnu [SSL (OpenSSL)] [LZO] [LZ4] [EPOLL] [MH/PKTINFO] [AEAD] built on Aug 30 2026
Sun Aug 30 18:35:24 2026 us=370693 UDP link remote: [AF_INET]172.28.0.2:1194
Sun Aug 30 18:35:24 2026 us=371025 TLS: Initial packet from [AF_INET]172.28.0.2:1194, sid=13741aeb a04eede7
Sun Aug 30 18:35:24 2026 us=373331 VERIFY OK: depth=0, CN=matrix-server
Sun Aug 30 18:35:39 2026 us=689209 TLS Error: TLS key negotiation failed to occur within 15 seconds (check your network connectivity)
Sun Aug 30 18:35:39 2026 us=689275 TLS Error: TLS handshake failed
Sun Aug 30 18:35:39 2026 us=689567 SIGTERM[soft,tls-error] received, process exiting`

	// Wrong credentials against a server running auth-user-pass-verify.
	logAuthFailed = `entrypoint: OpenVPN 2.4.12 x86_64-pc-linux-gnu [SSL (OpenSSL)] [LZO] [LZ4] [EPOLL] [MH/PKTINFO] [AEAD] built on Aug 30 2026
Sun Aug 30 18:35:22 2026 us=918904 OpenVPN 2.4.12 x86_64-pc-linux-gnu [SSL (OpenSSL)] [LZO] [LZ4] [EPOLL] [MH/PKTINFO] [AEAD] built on Aug 30 2026
Sun Aug 30 18:35:22 2026 us=920367 UDP link remote: [AF_INET]172.28.0.4:1194
Sun Aug 30 18:35:22 2026 us=920690 TLS: Initial packet from [AF_INET]172.28.0.4:1194, sid=0355e3a4 435df01c
Sun Aug 30 18:35:22 2026 us=923217 VERIFY OK: depth=0, CN=matrix-server
Sun Aug 30 18:35:22 2026 us=928292 [matrix-server] Peer Connection Initiated with [AF_INET]172.28.0.4:1194
Sun Aug 30 18:35:23 2026 us=957517 SENT CONTROL [matrix-server]: 'PUSH_REQUEST' (status=1)
Sun Aug 30 18:35:23 2026 us=958108 AUTH: Received control message: AUTH_FAILED
Sun Aug 30 18:35:23 2026 us=958346 SIGTERM[soft,auth-failure] received, process exiting`

	// A directive this build does not know, with nothing to downgrade it:
	// openvpn prefixes the sentence with "Options error:", which is what
	// the config-rejected rule keys on, and never opens a socket.
	logUnknownDirective = `entrypoint: OpenVPN 2.4.12 x86_64-pc-linux-gnu [SSL (OpenSSL)] [LZO] [LZ4] [EPOLL] [MH/PKTINFO] [AEAD] built on Aug 30 2026
Options error: Unrecognized option or missing or extra parameter(s) in /etc/openvpn/client.conf:94: tls-crypt-v2 (2.4.12)
Use --help for more information.`

	// A truncated inline CA block.
	logBadPEM = `entrypoint: OpenVPN 2.4.12 x86_64-pc-linux-gnu [SSL (OpenSSL)] [LZO] [LZ4] [EPOLL] [MH/PKTINFO] [AEAD] built on Aug 30 2026
Sun Aug 30 18:38:27 2026 OpenVPN 2.4.12 x86_64-pc-linux-gnu [SSL (OpenSSL)] [LZO] [LZ4] [EPOLL] [MH/PKTINFO] [AEAD] built on Aug 30 2026
Sun Aug 30 18:38:27 2026 OpenSSL: error:0907400D:PEM routines:PEM_X509_INFO_read_bio:ASN1 lib
Sun Aug 30 18:38:27 2026 Cannot load CA certificate file [[INLINE]] (no entries were read)
Sun Aug 30 18:38:27 2026 Exiting due to fatal error`

	// The container was started without --device=/dev/net/tun.
	logNoTun = `entrypoint: OpenVPN 2.6.22 x86_64-pc-linux-gnu [SSL (OpenSSL)] [LZO] [LZ4] [EPOLL] [MH/PKTINFO] [AEAD] built on Aug 30 2026
2026-08-30 18:40:00 OpenVPN 2.6.22 x86_64-pc-linux-gnu [SSL (OpenSSL)] [LZO] [LZ4] [EPOLL] [MH/PKTINFO] [AEAD] built on Aug 30 2026
2026-08-30 18:40:00 UDP link remote: [AF_INET]172.28.0.2:1194
2026-08-30 18:40:01 ERROR: Cannot open TUN/TAP dev /dev/net/tun: No such file or directory (errno=2)
2026-08-30 18:40:01 Exiting due to fatal error`

	// A real 2.4.12 log from a live baseline run, carrying two things this
	// file pins. A profile with "setenv FORWARD_COMPATIBLE 1" downgrades an
	// unknown directive from fatal to a warning and openvpn carries on to the
	// real outcome, so config-rejected must not key on the bare sentence. And
	// the --max-routes deprecation notice names a version mid-sentence; see
	// TestOracleBannerParsing.
	downgradedOptionLog = `Sun Aug 30 23:55:16 2026 Unrecognized option or missing or extra parameter(s) in /c.ovpn:18: data-ciphers (2.4.12)
Sun Aug 30 23:55:16 2026 DEPRECATED OPTION: --max-routes option ignored.The number of routes is unlimited as of OpenVPN 2.4. This option will be removed in a future version, please remove it from your configuration.
Sun Aug 30 23:55:16 2026 Unrecognized option or missing or extra parameter(s) in /c.ovpn:26: block-outside-dns (2.4.12)
Sun Aug 30 23:55:16 2026 OpenVPN 2.4.12 x86_64-pc-linux-gnu [SSL (OpenSSL)] [LZO] [LZ4] [EPOLL] [MH/PKTINFO] [AEAD] built on Aug 30 2026
Sun Aug 30 23:55:48 2026 VERIFY OK: depth=0, CN=SERVER1049
Sun Aug 30 23:55:49 2026 SENT CONTROL [SERVER1049]: 'PUSH_REQUEST' (status=1)
Sun Aug 30 23:55:50 2026 AUTH: Received control message: AUTH_FAILED,911/ERROR #911: Your account has been suspended.
Sun Aug 30 23:55:51 2026 SIGTERM[soft,exit-with-notification] received, process exiting`
)

// TestClassifyReferenceLog is the classifier's contract. Every fixture is a
// real capture, so a change in openvpn's wording fails here rather than
// silently mis-bucketing a sweep.
func TestClassifyReferenceLog(t *testing.T) {
	for _, tc := range []struct {
		name      string
		log       string
		timedOut  bool
		connected bool
		rule      string
		class     diag.Class
		stage     diag.Stage
		ambiguous bool
		evidence  string
	}{
		{
			name: "connected", log: logConnected, connected: true,
			rule: "connected", stage: diag.StageKeys,
			evidence: "Initialization Sequence Completed",
		},
		{
			name: "bad CA", log: logBadCA,
			rule: "cert-verify-failed", class: diag.ClassTLS, stage: diag.StageTLS,
			evidence: "VERIFY ERROR: depth=1, error=self signed certificate in certificate chain: CN=openlawsvpn-matrix-ca, serial=1",
		},
		{
			name: "unresolvable remote", log: logResolveFailed,
			rule: "resolve-failed", class: diag.ClassNetwork, stage: diag.StageDial,
		},
		{
			name: "connection refused", log: logConnectionRefused,
			rule: "connect-failed", class: diag.ClassNetwork, stage: diag.StageDial,
			evidence: "TCP: connect to [AF_INET]172.28.0.3:9 failed: Connection refused",
		},
		{
			name: "wrong tls-auth key over TCP", log: logTLSAuthMismatchTCP,
			rule: "transport-reset", class: diag.ClassCrypto, stage: diag.StageReset,
			ambiguous: true,
			evidence:  "Connection reset, restarting [0]",
		},
		{
			name: "wrong tls-auth key over UDP", log: logTLSAuthMismatchUDP,
			rule: "no-peer-reply", class: diag.ClassNetwork, stage: diag.StageReset,
			ambiguous: true,
		},
		{
			name: "blackholed UDP remote", log: logBlackholedUDP,
			rule: "no-peer-reply", class: diag.ClassNetwork, stage: diag.StageReset,
			ambiguous: true,
		},
		{
			name: "server rejected our client certificate", log: logClientCertRejected,
			rule: "tls-stalled-after-reply", class: diag.ClassTLS, stage: diag.StageTLS,
			ambiguous: true,
		},
		{
			name: "credentials rejected", log: logAuthFailed,
			rule: "auth-rejected", class: diag.ClassAuth, stage: diag.StageAuth,
			evidence: "AUTH: Received control message: AUTH_FAILED",
		},
		{
			name: "unknown directive", log: logUnknownDirective,
			rule: "config-rejected", class: diag.ClassConfig, stage: diag.StageParse,
		},
		{
			// The unknown-option warning must not shadow the answer that
			// follows it: the credentials were rejected, and that is what
			// the run has to be reported as.
			name: "unknown option downgraded to a warning", log: downgradedOptionLog,
			rule: "auth-rejected", class: diag.ClassAuth, stage: diag.StageAuth,
			evidence: "AUTH: Received control message: " +
				"AUTH_FAILED,911/ERROR #911: Your account has been suspended.",
		},
		{
			name: "malformed inline CA", log: logBadPEM,
			rule: "config-rejected", class: diag.ClassConfig, stage: diag.StageParse,
			evidence: "Cannot load CA certificate file [[INLINE]] (no entries were read)",
		},
		{
			name: "no tun device in the container", log: logNoTun,
			rule: "local-tun", class: diag.ClassLocal, stage: diag.StageParse,
		},
		{
			name: "oracle timeout with a silent log", log: logConnected[:strings.Index(logConnected, "TLS:")],
			timedOut: true,
			rule:     "oracle-timeout", class: diag.ClassNetwork, stage: diag.StageDial,
			ambiguous: true,
		},
		{
			name: "nothing recognisable", log: "some other program entirely\n",
			rule: "unclassified", class: diag.ClassLocal, stage: diag.StageParse,
			ambiguous: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := testenv.ClassifyReferenceLog(tc.log, tc.timedOut)
			if got.Connected != tc.connected {
				t.Errorf("Connected = %v, want %v", got.Connected, tc.connected)
			}
			if got.Rule != tc.rule {
				t.Errorf("Rule = %q, want %q", got.Rule, tc.rule)
			}
			if !tc.connected && got.Class != tc.class {
				t.Errorf("Class = %s, want %s", got.Class, tc.class)
			}
			if got.Stage != tc.stage {
				t.Errorf("Stage = %s, want %s", got.Stage, tc.stage)
			}
			if got.Ambiguous != tc.ambiguous {
				t.Errorf("Ambiguous = %v, want %v", got.Ambiguous, tc.ambiguous)
			}
			if tc.evidence != "" && got.Evidence != tc.evidence {
				t.Errorf("Evidence = %q, want %q", got.Evidence, tc.evidence)
			}
			if got.Detail == "" {
				t.Error("Detail is empty; every verdict must explain itself")
			}
		})
	}
}

// TestClassifyDistinguishesCorruptions states as a table that three
// corruptions a human would describe differently must not collapse into one
// class.
func TestClassifyDistinguishesCorruptions(t *testing.T) {
	classes := map[string]diag.Class{
		"bad CA":                      testenv.ClassifyReferenceLog(logBadCA, false).Class,
		"unreachable remote":          testenv.ClassifyReferenceLog(logConnectionRefused, false).Class,
		"wrong tls-auth key over TCP": testenv.ClassifyReferenceLog(logTLSAuthMismatchTCP, false).Class,
	}
	seen := map[diag.Class]string{}
	for name, c := range classes {
		if other, dup := seen[c]; dup {
			t.Errorf("%q and %q both classify as %s; the classifier is collapsing them", name, other, c)
		}
		seen[c] = name
	}
	t.Logf("bad CA=%s, unreachable=%s, wrong tls-auth (TCP)=%s",
		classes["bad CA"], classes["unreachable remote"], classes["wrong tls-auth key over TCP"])
}

// TestClassifyDocumentsTheUDPBlindSpot pins the one place the classifier
// genuinely cannot separate two causes, so that it is a recorded property
// rather than a surprise. On UDP a server that drops an unauthenticated control
// packet is indistinguishable from a server that is not there: neither replies.
// Both are reported as ClassNetwork with Ambiguous set.
func TestClassifyDocumentsTheUDPBlindSpot(t *testing.T) {
	wrongKey := testenv.ClassifyReferenceLog(logTLSAuthMismatchUDP, false)
	blackhole := testenv.ClassifyReferenceLog(logBlackholedUDP, false)

	if wrongKey.Rule != blackhole.Rule || wrongKey.Class != blackhole.Class {
		t.Fatalf("the UDP blind spot has changed: wrong key %s/%s, blackhole %s/%s — "+
			"if openvpn now distinguishes them, split the rule and update this test",
			wrongKey.Rule, wrongKey.Class, blackhole.Rule, blackhole.Class)
	}
	if !wrongKey.Ambiguous {
		t.Error("the shared verdict must be marked Ambiguous")
	}
	for _, want := range []string{"tls-auth", "filtered"} {
		if !strings.Contains(wrongKey.Detail, want) {
			t.Errorf("Detail does not mention %q: %s", want, wrongKey.Detail)
		}
	}
}

// TestOracleBannerParsing checks that the version actually used is recovered
// from a log, in each of the three shapes a captured log comes in.
func TestOracleBannerParsing(t *testing.T) {
	const synthetic = "OpenVPN 2.6.22 x86_64-pc-linux-gnu [SSL (OpenSSL)] built on Aug 30 2026"
	if got := testenv.ReleaseFromBannerForTest(synthetic); got != "2.6.22" {
		t.Errorf("release = %q, want %q", got, "2.6.22")
	}

	for _, tc := range []struct {
		name    string
		log     string
		release string
		absent  string
	}{
		{
			// The entrypoint echoes the banner before openvpn runs, so both
			// lines are present and openvpn's own is the one that counts.
			name: "openvpn's own line beats the entrypoint echo",
			log:  logConnected, release: "2.4.12", absent: "entrypoint:",
		},
		{
			// A log where openvpn never got far enough to print its own
			// banner still has to yield a version.
			name: "the entrypoint echo is the fallback",
			log:  logUnknownDirective, release: "2.4.12",
		},
		{
			// The notice reads "... unlimited as of OpenVPN 2.4. This
			// option ...", which a two-component version pattern matches,
			// recording the arbiter as "2.4." rather than "2.4.12". The
			// four-cell verdict leans on that field to explain a
			// surprising cell.
			name: "a version inside deprecation prose is not a banner",
			log:  downgradedOptionLog, release: "2.4.12", absent: "unlimited as of",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			banner := testenv.OpenVPNBannerForTest(tc.log)
			if want := "OpenVPN " + tc.release + " "; !strings.HasPrefix(banner, want) {
				t.Errorf("banner = %q, want it to start %q", banner, want)
			}
			if tc.absent != "" && strings.Contains(banner, tc.absent) {
				t.Errorf("banner = %q, want it to carry no %q", banner, tc.absent)
			}
			if got := testenv.ReleaseFromBannerForTest(banner); got != tc.release {
				t.Errorf("release = %q, want %q", got, tc.release)
			}
		})
	}
}

// TestCompareFourCells walks the whole four-cell verdict table, and with it the
// property the Agreement type promises: the class decides whether the two
// clients agree, and the stage never does. Cell and agreement are asserted on
// one Compare call per row, so a row cannot land in the right cell while
// agreeing for the wrong reason.
func TestCompareFourCells(t *testing.T) {
	const release = "2.6.22"
	ours := func(c diag.Class, s diag.Stage) testenv.ClientOutcome {
		return testenv.ClientOutcome{Class: c, Stage: s}
	}
	refFail := func(c diag.Class, s diag.Stage) testenv.OracleResult {
		return testenv.OracleResult{
			Classification: testenv.Classification{Class: c, Stage: s},
			Release:        release,
		}
	}
	connected := testenv.ClientOutcome{Connected: true}
	refOK := testenv.OracleResult{
		Classification: testenv.Classification{Connected: true},
		Release:        release,
	}

	for _, tc := range []struct {
		name      string
		ours      testenv.ClientOutcome
		ref       testenv.OracleResult
		cell      testenv.Cell
		works     bool
		agreement testenv.Agreement
		agrees    bool
	}{
		{
			name: "both connected",
			ours: connected, ref: refOK,
			cell: testenv.CellWorkingAsIntended, works: false,
			agreement: testenv.AgreementBothConnected, agrees: true,
		},
		{
			// The only cell that generates work: stock openvpn can drive the
			// config and we cannot.
			name: "our gap",
			ours: ours(diag.ClassUnsupported, diag.StageAuth), ref: refOK,
			cell: testenv.CellOurGap, works: true,
			agreement: testenv.AgreementSplit, agrees: false,
		},
		{
			name: "surprising",
			ours: connected, ref: refFail(diag.ClassNetwork, diag.StageDial),
			cell: testenv.CellSurprising, works: false,
			agreement: testenv.AgreementSplit, agrees: false,
		},
		{
			name: "both fail, same class and stage",
			ours: ours(diag.ClassNetwork, diag.StageDial),
			ref:  refFail(diag.ClassNetwork, diag.StageDial),
			cell: testenv.CellBadConfigOrDeadEndpoint, works: false,
			agreement: testenv.AgreementSameClass, agrees: true,
		},
		{
			// The stage differs and the two still agree — the row a
			// comparison keyed on the stage would get wrong.
			name: "both fail, same class, different stage",
			ours: ours(diag.ClassAuth, diag.StagePush),
			ref:  refFail(diag.ClassAuth, diag.StageAuth),
			cell: testenv.CellBadConfigOrDeadEndpoint, works: false,
			agreement: testenv.AgreementSameClass, agrees: true,
		},
		{
			// And the mirror image: one stage, two classes, no agreement.
			name: "both fail, different class, same stage",
			ours: ours(diag.ClassTLS, diag.StageTLS),
			ref:  refFail(diag.ClassCrypto, diag.StageTLS),
			cell: testenv.CellBadConfigOrDeadEndpoint, works: false,
			agreement: testenv.AgreementDifferentClass, agrees: false,
		},
		{
			name: "both fail, different class and stage",
			ours: ours(diag.ClassUnsupported, diag.StageAuth),
			ref:  refFail(diag.ClassNetwork, diag.StageDial),
			cell: testenv.CellBadConfigOrDeadEndpoint, works: false,
			agreement: testenv.AgreementDifferentClass, agrees: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := testenv.Compare(tc.ours, tc.ref)
			if v.Cell != tc.cell {
				t.Errorf("cell = %s, want %s", v.Cell, tc.cell)
			}
			if v.Cell.GeneratesWork() != tc.works {
				t.Errorf("%s: GeneratesWork = %v, want %v", v.Cell, v.Cell.GeneratesWork(), tc.works)
			}
			if v.Cell.Action() == "" {
				t.Errorf("%s: no action recorded", v.Cell)
			}
			if v.Agreement != tc.agreement {
				t.Errorf("agreement = %s, want %s", v.Agreement, tc.agreement)
			}
			if v.Agreement.Agrees() != tc.agrees {
				t.Errorf("%s.Agrees() = %v, want %v", v.Agreement, v.Agreement.Agrees(), tc.agrees)
			}
			if v.Agreement.String() == "" {
				t.Error("agreement has no stable token")
			}

			s := v.String()
			if !strings.Contains(s, release) {
				t.Errorf("verdict does not name the openvpn that arbitrated: %s", v)
			}
			// Whatever the verdict, both stages stay readable. Agreement is
			// the thing that stops being keyed on the stage; the report is
			// not the thing that stops mentioning it.
			if !tc.ours.Connected && !strings.Contains(s, tc.ours.Stage.String()) {
				t.Errorf("rendered verdict drops our stage %s: %s", tc.ours.Stage, s)
			}
			if !tc.ref.Connected && !strings.Contains(s, tc.ref.Stage.String()) {
				t.Errorf("rendered verdict drops the reference stage %s: %s", tc.ref.Stage, s)
			}
		})
	}
}

// TestCredentialRejectionReadsAsAgreement guards the trap where two clients that
// agree about a wrong password get reported as disagreeing. Both report it as
// ClassAuth at different stages, and always will: OpenVPN sends AUTH_FAILED in
// place of PUSH_REPLY, so our client says StagePush and ClassifyReferenceLog
// reads the same rejection off stock openvpn's log as StageAuth. The classes
// agree, so the verdict agrees and the rendered line says so — while still
// naming both stages.
func TestCredentialRejectionReadsAsAgreement(t *testing.T) {
	ours := testenv.ClientOutcome{Class: diag.ClassAuth, Stage: diag.StagePush}
	ref := testenv.OracleResult{
		Classification: testenv.Classification{
			Class: diag.ClassAuth, Stage: diag.StageAuth, Rule: "auth-rejected",
		},
		Release: "2.4.12",
	}

	v := testenv.Compare(ours, ref)
	if v.Cell != testenv.CellBadConfigOrDeadEndpoint {
		t.Errorf("cell = %s, want %s", v.Cell, testenv.CellBadConfigOrDeadEndpoint)
	}
	if v.Agreement != testenv.AgreementSameClass {
		t.Errorf("agreement = %s, want %s", v.Agreement, testenv.AgreementSameClass)
	}
	if !v.Agreement.Agrees() {
		t.Error("a credential rejection both clients called auth must read as agreement")
	}

	// The rendering is where the trap actually bit.
	s := v.String()
	if strings.Contains(s, "classes differ") {
		t.Errorf("rendered verdict reports a disagreement: %s", s)
	}
	if !strings.Contains(s, "both fail auth") {
		t.Errorf("rendered verdict does not say the two agree: %s", s)
	}
	for _, want := range []string{"push", "auth", "2.4.12"} {
		if !strings.Contains(s, want) {
			t.Errorf("rendered verdict dropped %q, which a reader needs: %s", want, s)
		}
	}
}

// TestOracleRuleNamesAreComplete checks the exported rule-name set against the
// rules that actually fire, using logs the classifier is already tested on.
func TestOracleRuleNamesAreComplete(t *testing.T) {
	known := map[string]bool{}
	for _, name := range testenv.OracleRuleNames() {
		if name == "" {
			t.Error("OracleRuleNames contains an empty name")
		}
		if known[name] {
			t.Errorf("OracleRuleNames repeats %q", name)
		}
		known[name] = true
	}
	for _, log := range []string{downgradedOptionLog, ""} {
		got := testenv.ClassifyReferenceLog(log, false)
		if !known[got.Rule] {
			t.Errorf("ClassifyReferenceLog reported rule %q, which OracleRuleNames omits", got.Rule)
		}
	}
	if got := testenv.ClassifyReferenceLog("", true); !known[got.Rule] {
		t.Errorf("the timeout rule %q is missing from OracleRuleNames", got.Rule)
	}
}

// TestClientOutcomeFromReport covers the entry point our own client's result
// arrives through, including the nil report a client that never produced one
// would hand over.
func TestClientOutcomeFromReport(t *testing.T) {
	if got := testenv.ClientOutcomeFromReport(nil); got.Connected {
		t.Error("a nil report must read as 'did not connect'")
	}
	r := &diag.SessionReport{}
	r.Outcome = diag.Outcome{Succeeded: false, Class: diag.ClassUnsupported, Stage: diag.StageAuth}
	got := testenv.ClientOutcomeFromReport(r)
	if got.Connected || got.Class != diag.ClassUnsupported || got.Stage != diag.StageAuth {
		t.Errorf("ClientOutcomeFromReport = %+v", got)
	}
}

// TestOracleOptionDefaults checks the zero value is usable and that the
// preamble records exactly what was appended.
func TestOracleOptionDefaults(t *testing.T) {
	pre := testenv.OracleOptions{}.Preamble()
	want := []string{"verb 3", "tls-exit", "connect-retry-max 1", "hand-window 30", "resolv-retry 0", "cd /etc/openvpn"}
	if strings.Join(pre, "|") != strings.Join(want, "|") {
		t.Errorf("preamble = %v, want %v", pre, want)
	}
	pre = testenv.OracleOptions{HandshakeWindow: 12 * time.Second}.Preamble()
	if pre[3] != "hand-window 12" {
		t.Errorf("hand-window = %q, want %q", pre[3], "hand-window 12")
	}
}

// TestOracleResultStringNamesTheBinary guards the requirement that the openvpn
// actually used is visible in the output.
func TestOracleResultStringNamesTheBinary(t *testing.T) {
	r := testenv.OracleResult{
		Classification: testenv.Classification{Class: diag.ClassAuth, Stage: diag.StageAuth, Rule: "auth-rejected"},
		Release:        "2.4.12",
		Elapsed:        1500 * time.Millisecond,
	}
	s := r.String()
	for _, want := range []string{"2.4.12", "auth", "auth-rejected"} {
		if !strings.Contains(s, want) {
			t.Errorf("OracleResult.String() = %q, missing %q", s, want)
		}
	}
}
