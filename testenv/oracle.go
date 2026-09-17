package testenv

// The reference oracle.
//
// A dead endpoint looks exactly like a missing feature from the outside, so the
// arbiter is stock `openvpn` itself: run it against the same config in a
// throwaway container, classify its outcome into the diag vocabulary, and
// compare with ours. Exactly one cell of the resulting four — "we fail, stock
// openvpn connects" — generates work.
//
// Two properties are load-bearing and are asserted by the integration tests:
//
//   - The stock client runs in a container, so it has its own network
//     namespace, and never touches the host's routing table or resolver even
//     when the config under test pushes redirect-gateway and DNS.
//   - The openvpn binary that ran is recorded. "We connect, openvpn doesn't" is
//     most often a local binary far newer than the pinned matrix builds, so the
//     oracle never runs the host binary and records its version for contrast.

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/openlawsvpn/go-openlawsvpn/diag"
)

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

// DefaultOracleVersion is the pinned OpenVPN build RunOracle uses when
// OracleOptions.Version is empty.
//
// 2.4 rather than the newest, because the two ways of being wrong are not
// symmetric: a client too new for the config refuses it outright and the config
// lands in the "both fail" cell, silently excluded as a bad config that hides
// one of our gaps, while one too old fails where we succeed and lands in the
// "surprising" cell, which gets investigated. 2.4 also forces the classic PRF
// path a pre-2.6 deployment needs. A ClassConfig verdict at StageParse is the
// first of those — the reference client refused the profile itself — and is the
// signal to re-run with a newer Version rather than a statement about the
// endpoint.
const DefaultOracleVersion = V24

// DefaultOracleTimeout bounds one oracle run end to end, including container
// start. It has to exceed the handshake window with room for several remotes.
const DefaultOracleTimeout = 120 * time.Second

// DefaultOracleHandshakeWindow is the value given to openvpn's --hand-window,
// which is how long the client waits for the control channel to come up before
// declaring "TLS key negotiation failed to occur within N seconds". OpenVPN's
// own default is 60s; halving it halves the cost of the commonest failure mode
// without changing its classification, since the timeout is the verdict either
// way, only sooner.
const DefaultOracleHandshakeWindow = 30 * time.Second

// OracleOptions configures a reference-oracle run. The zero value is usable and
// selects DefaultOracleVersion, DefaultOracleTimeout and
// DefaultOracleHandshakeWindow.
type OracleOptions struct {
	// Version selects which pinned OpenVPN build runs the config. It names a
	// matrix image, so the exact upstream release is reproducible. Empty
	// means DefaultOracleVersion.
	Version ServerVersion

	// Timeout bounds the whole run. Zero means DefaultOracleTimeout. On
	// expiry the run is reported with TimedOut set rather than as an error.
	Timeout time.Duration

	// HandshakeWindow becomes openvpn's --hand-window. Zero means
	// DefaultOracleHandshakeWindow. Shortening it only makes a stalled
	// handshake fail sooner; it does not change the class.
	HandshakeWindow time.Duration

	// Network is the Docker network to attach the client container to. Empty
	// means the default bridge; use MatrixServer.OracleOptions to reach a
	// matrix server that sits on a throwaway network.
	Network string

	// Files are extra files placed beside the config inside the container,
	// keyed by base name. The config references them as /etc/openvpn/<name>;
	// a name containing a path separator, and "client.conf", are rejected.
	Files map[string]string

	// Directives are appended after the oracle preamble, so they win over both
	// the config and the preamble. Use sparingly: each one is a way the thing
	// being judged differs from the thing that was handed in.
	Directives []string
}

// withDefaults returns a copy with every zero field filled in.
func (o OracleOptions) withDefaults() OracleOptions {
	if o.Version == "" {
		o.Version = DefaultOracleVersion
	}
	if o.Timeout <= 0 {
		o.Timeout = DefaultOracleTimeout
	}
	if o.HandshakeWindow <= 0 {
		o.HandshakeWindow = DefaultOracleHandshakeWindow
	}
	return o
}

// Preamble returns the directives the oracle appends to every config it runs.
// They bound the run without changing its outcome: stock openvpn retries
// forever by default, so without them a dead endpoint costs the full timeout
// and a config error costs nothing but looks the same.
//
//	verb 3             a floor and a ceiling on log detail, so the classifier
//	                   sees the same lines whatever the config asked for
//	tls-exit           exit on TLS failure instead of restarting the attempt
//	connect-retry-max  try each remote once
//	hand-window        how long to wait for the control channel
//	resolv-retry 0     resolve once; do not spin on a dead name
//	cd                 resolve a relative file reference beside the config
//
// The applied list is reported in OracleResult.Preamble, so a verdict can always
// be reproduced by hand.
//
// The last is the exception: it does not bound the run. OpenVPN resolves a
// relative "ca ca.example.crt" against the process's working directory rather
// than the directory the config was read from, and the container starts in "/".
// Files stages material beside the config, so without this the reference client
// fails to open a CA sitting next to it and the oracle judges its own staging
// instead of the profile.
func (o OracleOptions) Preamble() []string {
	o = o.withDefaults()
	return []string{
		"verb 3",
		"tls-exit",
		"connect-retry-max 1",
		fmt.Sprintf("hand-window %d", int(o.HandshakeWindow.Seconds())),
		"resolv-retry 0",
		"cd " + oracleConfDir,
	}
}

// oracleConfDir is where the image entrypoint unpacks the config and every
// file staged beside it. It matches CONF_DIR in
// docker/openvpn-server/entrypoint.sh.
const oracleConfDir = "/etc/openvpn"

// ---------------------------------------------------------------------------
// Result
// ---------------------------------------------------------------------------

// Classification is what a stock OpenVPN client's log says happened, expressed
// in the diag vocabulary. It is derived purely from text, so it can be produced
// and tested without Docker.
//
// When Connected is true the remaining failure fields are meaningless — Class
// in particular, whose zero value is a real class. This mirrors diag.Outcome,
// where Class is only defined once Succeeded is false.
type Classification struct {
	// Connected reports whether the client logged
	// "Initialization Sequence Completed".
	Connected bool
	// Class is the diag class the failure falls into.
	Class diag.Class
	// Stage is the furthest connection stage the log proves was reached.
	Stage diag.Stage
	// Rule names the classification rule that fired, for example
	// "auth-rejected". It is stable and safe to aggregate on.
	Rule string
	// Evidence is the log line the rule keyed on, with the leading
	// timestamp stripped. Empty when no rule matched.
	Evidence string
	// Detail explains the verdict in one sentence, including what else could
	// produce the same evidence.
	Detail string
	// Ambiguous marks a verdict that more than one root cause produces. It is
	// not a confidence score: the log genuinely does not separate the
	// possibilities named in Detail, and a human reading it could not either.
	Ambiguous bool
}

// OracleResult is one reference-oracle run: what stock openvpn did with the
// config, and which openvpn did it.
type OracleResult struct {
	// Classification is the verdict derived from the client's log.
	Classification

	// Image is the exact image tag that ran, for example
	// "openlawsvpn-test/openvpn-server:2.6.22".
	Image string
	// Banner is the openvpn version banner from the run, for example
	// "OpenVPN 2.6.22 x86_64-pc-linux-gnu [SSL (OpenSSL)] ... built on ...".
	// This is the authoritative record of which binary produced the verdict.
	Banner string
	// Release is the exact upstream release parsed out of Banner, for
	// example "2.6.22".
	Release string
	// HostBanner is the host's own `openvpn --version` first line, or empty
	// when the host has no openvpn. The oracle never runs it: it is recorded
	// for contrast, the usual explanation for "we connect, openvpn does not".
	HostBanner string

	// Preamble is the directive list the oracle appended to the config.
	Preamble []string
	// Elapsed is how long the client ran.
	Elapsed time.Duration
	// TimedOut reports that the oracle's own Timeout expired with the client
	// still running. The classification is then whatever the partial log
	// supports.
	TimedOut bool
	// Log is the client container's complete log.
	Log string
}

// String renders the result as one line, always naming the openvpn that ran.
func (r OracleResult) String() string {
	head := "connected"
	if !r.Connected {
		head = fmt.Sprintf("%s at %s", r.Class, r.Stage)
	}
	if r.Ambiguous {
		head += " (ambiguous)"
	}
	return fmt.Sprintf("stock openvpn %s: %s [rule=%s, %s]",
		r.Release, head, r.Rule, r.Elapsed.Round(time.Millisecond))
}

// ---------------------------------------------------------------------------
// Running the oracle
// ---------------------------------------------------------------------------

// oracleConfigName is the file the oracle writes the config under test to,
// inside the container. It matches the name the image entrypoint expects for a
// client run.
const oracleConfigName = "client.conf"

// RunOracle runs stock openvpn against config in a throwaway container and
// classifies what it did.
//
// config is a complete .ovpn profile, used as given except for the appended
// preamble (see OracleOptions.Preamble), which bounds the run without changing
// its outcome and is reported in the result.
//
// A failure to connect is not an error: it is the result. An error means the
// oracle itself could not run — no Docker, no image, a bad Files entry — and
// the returned result is then not meaningful. The error wraps ErrImageMissing
// when the pinned image has not been built and ErrUnimplemented when no image
// is pinned for the requested version.
func RunOracle(ctx context.Context, config string, opts OracleOptions) (OracleResult, error) {
	opts = opts.withDefaults()

	var res OracleResult
	image, ok := ImageFor(opts.Version)
	if !ok {
		return res, fmt.Errorf("%w: no matrix image is pinned for OpenVPN %s",
			ErrUnimplemented, opts.Version)
	}
	// Validation first, and the image check second: a bad Files entry is the
	// caller's mistake and costs nothing to detect, where a missing image is
	// the environment's. In the other order every name, valid ones included,
	// comes back as ErrImageMissing on a host that has not built the images.
	files, err := oracleFiles(config, opts)
	if err != nil {
		return res, err
	}

	if err := requireImage(image); err != nil {
		return res, err
	}

	run, err := runReferenceClient(ctx, referenceClientSpec{
		image:   image,
		network: opts.Network,
		files:   files,
		timeout: opts.Timeout,
	})
	if err != nil {
		return res, err
	}

	res = OracleResult{
		Classification: ClassifyReferenceLog(run.log, run.timedOut),
		Image:          image,
		Banner:         run.banner,
		HostBanner:     hostOpenVPNBanner(),
		Preamble:       opts.Preamble(),
		Elapsed:        run.elapsed,
		TimedOut:       run.timedOut,
		Log:            run.log,
	}
	if res.Banner == "" {
		// The entrypoint prints the banner before openvpn starts, so this
		// should be unreachable. Ask the image directly rather than report
		// a run with no recorded version.
		res.Banner = imageOpenVPNBanner(image)
	}
	res.Release = releaseFromBanner(res.Banner)
	return res, nil
}

// oracleFiles builds the container bundle: the config under test with the
// preamble appended, plus any extra files the caller supplied.
func oracleFiles(config string, opts OracleOptions) ([]bundleFile, error) {
	// Preamble returns a fresh slice, so appending to it cannot alias.
	directives := append(opts.Preamble(), opts.Directives...)
	files := []bundleFile{{oracleConfigName, appendDirectives(config, directives), 0o600}}

	names := make([]string, 0, len(opts.Files))
	for name := range opts.Files {
		switch {
		case name == "":
			return nil, fmt.Errorf("testenv: oracle: empty extra file name")
		case name == oracleConfigName:
			return nil, fmt.Errorf("testenv: oracle: extra file may not be named %q", oracleConfigName)
		case strings.ContainsAny(name, `/\`) || name == ".." || strings.HasPrefix(name, "."):
			return nil, fmt.Errorf("testenv: oracle: extra file name %q must be a plain base name", name)
		}
		names = append(names, name)
	}
	sort.Strings(names) // deterministic bundles
	for _, name := range names {
		files = append(files, bundleFile{name, opts.Files[name], 0o600})
	}
	return files, nil
}

// appendDirectives appends the oracle preamble to a profile, fenced by comments
// so that a config dumped from a failing run can be read back.
func appendDirectives(config string, directives []string) string {
	if len(directives) == 0 {
		return config
	}
	var b strings.Builder
	b.WriteString(config)
	if !strings.HasSuffix(config, "\n") {
		b.WriteByte('\n')
	}
	b.WriteString("\n# --- appended by testenv.RunOracle: bounds the run, not the verdict ---\n")
	for _, d := range directives {
		b.WriteString(d)
		b.WriteByte('\n')
	}
	b.WriteString("# --- end testenv.RunOracle ---\n")
	return b.String()
}

// ---------------------------------------------------------------------------
