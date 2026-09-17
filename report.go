// SPDX-License-Identifier: LGPL-2.1-or-later

package vpn

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"maps"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/openlawsvpn/go-openlawsvpn/device"
	"github.com/openlawsvpn/go-openlawsvpn/diag"
	"github.com/openlawsvpn/go-openlawsvpn/internal/control"
	"github.com/openlawsvpn/go-openlawsvpn/internal/datachannel"
	"github.com/openlawsvpn/go-openlawsvpn/internal/keymethod2"
	"github.com/openlawsvpn/go-openlawsvpn/internal/prf"
	"github.com/openlawsvpn/go-openlawsvpn/internal/tlsverify"
	"github.com/openlawsvpn/go-openlawsvpn/profile"
	"github.com/openlawsvpn/go-openlawsvpn/routing"
)

// sessionRecorder accumulates the diag.SessionReport for one connection
// attempt.
//
// It owns its own mutex rather than borrowing Client.mu, which is held across
// unrelated work on the connect path while the rekey loop, the two
// data-channel goroutines and Client.Report all reach the report.
type sessionRecorder struct {
	mu  sync.Mutex
	rep diag.SessionReport

	// started guards the StageParse boundary, which several entry points can
	// reach for the same attempt (Connect, dialAndAuthenticate, bringUpTunnel).
	started bool
	// startErr is the StageParse outcome, replayed to every later caller of
	// beginAttempt within the same attempt.
	startErr error
	// failed records that an outcome has already been written. The first
	// failure of an attempt is the one that explains it; later cascading
	// errors must not overwrite it.
	failed bool
}

// newSessionRecorder returns a recorder holding an empty report.
func newSessionRecorder() *sessionRecorder {
	return &sessionRecorder{}
}

// edit runs fn with exclusive access to the report under construction.
func (r *sessionRecorder) edit(fn func(*diag.SessionReport)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	fn(&r.rep)
}

// enter appends a stage record stamped with the current time.
func (r *sessionRecorder) enter(s diag.Stage) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rep.Stages = append(r.rep.Stages, diag.StageRecord{Stage: s, EnteredAt: time.Now()})
}

// complete stamps the duration of the most recent record for s. A record left
// with a zero duration is one the attempt never came back out of, which is how
// a report distinguishes "failed here" from "passed through here".
func (r *sessionRecorder) complete(s diag.Stage) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.stampLocked(r.lastLocked(s))
}

// fail records derr against its stage and, if this is the first failure of the
// attempt, writes the outcome.
func (r *sessionRecorder) fail(derr *diag.Error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if i := r.lastLocked(derr.Stage); i >= 0 {
		r.stampLocked(i)
		if r.rep.Stages[i].Err == "" {
			r.rep.Stages[i].Err = derr.Error()
		}
	}
	if r.failed {
		return
	}
	r.failed = true
	r.rep.Outcome = diag.Outcome{
		Class:      derr.Class,
		Stage:      derr.Stage,
		Feature:    derr.Feature,
		ErrorChain: diag.ErrorChain(derr),
	}
}

// rewind discards the outcome one failed remote wrote, so that the next
// remote of a failover can write its own.
//
// Only the outcome is rewound: the stage timeline keeps every stage of every
// remote, and the endpoint records keep the class the rewound outcome carried.
// fail is first-wins, so without this the first failure would latch and a
// profile whose second remote connects would report a working tunnel with a
// failed outcome.
func (r *sessionRecorder) rewind() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.failed = false
	r.rep.Outcome = diag.Outcome{}
}

// note records err against stage s without ending the attempt. It is for
// failures the client recovers from — a rekey that did not complete leaves the
// session running on the previous key.
func (r *sessionRecorder) note(s diag.Stage, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	i := r.lastLocked(s)
	if i < 0 {
		return
	}
	r.stampLocked(i)
	if r.rep.Stages[i].Err == "" {
		r.rep.Stages[i].Err = err.Error()
	}
}

// succeed marks the attempt as having reached a working tunnel. A failure
// already recorded wins: an attempt that failed and then partially recovered
// is still an attempt that failed.
func (r *sessionRecorder) succeed() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failed {
		return
	}
	r.rep.Outcome = diag.Outcome{Succeeded: true, Stage: diag.StageData}
}

// lastLocked returns the index of the most recent record for stage s, or -1
// when the attempt never entered it. r.mu must be held.
func (r *sessionRecorder) lastLocked(s diag.Stage) int {
	for i := len(r.rep.Stages) - 1; i >= 0; i-- {
		if r.rep.Stages[i].Stage == s {
			return i
		}
	}
	return -1
}

// stampLocked fills in the duration of stage record i if it does not have one
// yet. r.mu must be held.
func (r *sessionRecorder) stampLocked(i int) {
	if i < 0 || r.rep.Stages[i].Duration != 0 {
		return
	}
	// A stage that measures as zero would read as "never finished". Round up
	// so that a genuinely instantaneous stage still records as completed.
	d := time.Since(r.rep.Stages[i].EnteredAt)
	if d <= 0 {
		d = time.Nanosecond
	}
	r.rep.Stages[i].Duration = d
}

// snapshot returns an independent copy of the report with counters filled in.
// The copy shares no mutable memory with the recorder, so a caller may hold it
// while the session keeps running.
func (r *sessionRecorder) snapshot(counters diag.Counters) *diag.SessionReport {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rep.Counters = counters
	out := r.rep
	out.Stages = slices.Clone(r.rep.Stages)
	out.Profile.Gaps = slices.Clone(r.rep.Profile.Gaps)
	out.Profile.Directives = slices.Clone(r.rep.Profile.Directives)
	out.TLS.Chain = slices.Clone(r.rep.TLS.Chain)
	out.Push.UnknownOptions = slices.Clone(r.rep.Push.UnknownOptions)
	out.Push.Parsed = maps.Clone(r.rep.Push.Parsed)
	out.Outcome.ErrorChain = slices.Clone(r.rep.Outcome.ErrorChain)
	return &out
}

// ---- Client-side recording -----------------------------------------------

// Report returns the diagnostics record of the most recent connection attempt.
// It is valid as soon as New returns and stays valid after Connect returns,
// whether Connect succeeded or failed, and equally after the two-phase
// Phase1ForTest / ConnectPhase2 and SetRelayPhase2 / ConnectPhase2 paths. The
// furthest stage reached is the last entry in Stages; a stage with a zero
// Duration is one the attempt did not come back out of.
//
// The returned report is a snapshot and is safe to retain while the session
// continues. It carries unredacted credential material: marshal
// SessionReport.Redacted, never the report itself.
//
// Reconnect starts a fresh report for each attempt, so this describes the last
// attempt only; Attempts keeps the others.
func (c *Client) Report() *diag.SessionReport {
	return c.recorder().snapshot(c.counters())
}

// recorder returns the recorder for the current attempt, creating one if the
// client has not started an attempt yet.
func (c *Client) recorder() *sessionRecorder {
	if rec := c.rec.Load(); rec != nil {
		return rec
	}
	fresh := newSessionRecorder()
	if c.rec.CompareAndSwap(nil, fresh) {
		return fresh
	}
	return c.rec.Load()
}

// counters snapshots the data-channel tallies for the report.
func (c *Client) counters() diag.Counters {
	return diag.Counters{
		BytesSent:       c.bytesSent.Load(),
		BytesRecv:       c.bytesRecv.Load(),
		PacketsSent:     c.packetsSent.Load(),
		PacketsRecv:     c.packetsRecv.Load(),
		DecryptFailures: c.decryptFailures.Load(),
		Retransmits:     c.retransmits.Load(),
		Rekeys:          c.rekeys.Load(),
		// Replays is deliberately left at zero: the sliding window lives in
		// internal/datachannel and reports a replay as an ordinary decrypt
		// error, so the two cannot be told apart from here.

		ControlForeignSession: c.controlForeignSession.Load(),
	}
}

// enterStage records a stage transition and emits it as an EventStage.
func (c *Client) enterStage(s diag.Stage) {
	c.recorder().enter(s)
	c.emit(Event{Type: EventStage, Stage: s, Message: "vpn: stage " + s.String()})
}

// completeStage stamps the duration of a stage the attempt has come back out
// of.
func (c *Client) completeStage(s diag.Stage) {
	c.recorder().complete(s)
}

// failStage records cause as the failure of stage s and returns the typed
// error to propagate. Every stage boundary funnels its errors through this, so
// a caller of Connect never receives an error without a class and a stage.
func (c *Client) failStage(class diag.Class, s diag.Stage, cause error, detail string) *diag.Error {
	derr := diag.Wrap(class, s, cause, detail)
	c.recorder().fail(derr)
	return derr
}

// failUnsupported is failStage for a capability we have not built. feature
// names the directive or protocol element as it appears on the wire.
func (c *Client) failUnsupported(s diag.Stage, feature, detail string) *diag.Error {
	derr := diag.Unsupported(s, feature, detail)
	c.recorder().fail(derr)
	return derr
}

// Preflight runs the StageParse boundary — profile fingerprint, endpoint and
// credential registration — without opening a socket, and returns the error the
// attempt would fail with, or nil.
//
// The boundary is shared with Connect and is idempotent: calling Preflight and
// then Connect on the same Client runs it once and replays its result.
func (c *Client) Preflight() error {
	return c.beginAttempt()
}

// profileDirectiveNames projects the parser's directive records down to bare
// keywords for the session report. Only the names travel: arguments carry
// hostnames, user names and file paths.
func profileDirectiveNames(p *profile.Profile) []string {
	if len(p.Directives) == 0 {
		return nil
	}
	names := make([]string, 0, len(p.Directives))
	for _, d := range p.Directives {
		names = append(names, d.Name)
	}
	return names
}

// beginAttempt starts the session report for a connection attempt and runs the
// StageParse boundary: profile fingerprint, endpoint, and registration of the
// profile's own credential material for redaction.
//
// It is idempotent within an attempt and replays its result. Connect,
// dialAndAuthenticate and bringUpTunnel all call it, because the mobile, relay
// and integration-test callers drive the phases directly.
func (c *Client) beginAttempt() error {
	rec := c.recorder()
	rec.mu.Lock()
	if rec.started {
		err := rec.startErr
		rec.mu.Unlock()
		return err
	}
	rec.started = true
	rec.mu.Unlock()

	// The attempt is this recorder's, and the slot is opened before the
	// boundary below can end it: a profile refused at StageParse is an
	// attempt that was made and explains itself, not an absence of one.
	c.registerAttempt(rec)

	c.enterStage(diag.StageParse)

	p := c.prof
	rec.edit(func(r *diag.SessionReport) {
		r.Profile.Fingerprint = profileFingerprint(p)
		r.Profile.Directives = profileDirectiveNames(p)
		r.Endpoint.Host = p.Remote
		r.Endpoint.Port = p.Port
		r.Endpoint.Proto = p.Proto.String()
		r.Endpoint.Remotes = len(p.Remotes)
		r.SetClientCertPEM(string(p.Cert))
		r.SetClientKeyPEM(string(p.Key))
	})

	// A profile with no usable CA is refused here, before any socket is
	// opened: dialing anyway would build a tunnel with an empty trust store
	// and no verification.
	if _, err := tlsverify.RootCAs(p); err != nil {
		derr := c.failStage(diag.ClassConfig, diag.StageParse, err,
			"no CA to verify the server against")
		rec.mu.Lock()
		rec.startErr = derr
		rec.mu.Unlock()
		return derr
	}

	// A profile whose method has nothing to present is refused: there is
	// nothing to put in the key-method-2 packet. It is ClassConfig, not
	// ClassAuth — no server rejected anything.
	if missing := c.authMethodFor(p).missing(missingForAnyEntry); missing != "" {
		derr := c.failStage(diag.ClassConfig, diag.StageParse, nil, missing)
		rec.mu.Lock()
		rec.startErr = derr
		rec.mu.Unlock()
		return derr
	}

	c.completeStage(diag.StageParse)
	return nil
}

// noteSessionFailure records the reason an established session ended. The
// stage is always StageData — the session was already carrying data — and the
// class distinguishes a server that revoked the session from a link that went
// away. A connection that fails during setup gets its outcome from the stage
// boundary that failed; this covers the ones that fail afterwards.
func (c *Client) noteSessionFailure(err error) {
	if err == nil {
		return
	}
	class, detail := diag.ClassNetwork, "session ended"
	var expired *control.SessionExpiredError
	var pushed *control.ServerPushedSignal
	switch {
	case errors.As(err, &expired):
		class = diag.ClassAuth
	case errors.As(err, &pushed):
		// Not a failure of ours and not the link's: the peer said so.
		class, detail = diag.ClassPeerClosed, "server pushed "+pushed.Directive()
	}
	c.recorder().fail(diag.Wrap(class, diag.StageData, err, detail))
}

// markDataFlow records the first plaintext packet in one direction. StageData
// completes only once plaintext has moved both ways; until then it stays open
// and the report shows the tunnel as reached but not proven.
func (c *Client) markDataFlow(outbound bool) {
	if outbound {
		if c.sawPlaintextTx.Swap(true) {
			return
		}
	} else if c.sawPlaintextRx.Swap(true) {
		return
	}
	if c.sawPlaintextTx.Load() && c.sawPlaintextRx.Load() {
		c.completeStage(diag.StageData)
	}
}

// recordDial stores what the transport turned out to be: the address the
// hostname resolved to and how long the connect took.
func (c *Client) recordDial(conn net.Conn, rtt time.Duration) {
	var resolved string
	if ra := conn.RemoteAddr(); ra != nil {
		if h, _, err := net.SplitHostPort(ra.String()); err == nil {
			resolved = h
		}
	}
	c.recorder().edit(func(r *diag.SessionReport) {
		if resolved != "" {
			r.Endpoint.ResolvedIP = resolved
		}
		r.Endpoint.DialRTT = rtt
	})
}

// recordTLS stores the control-channel TLS session summary, including the
// EKMAvailable measurement instrument, and the summary of the certificate the
// profile presents.
func (c *Client) recordTLS(cs tls.ConnectionState) {
	info := tlsInfo(cs)
	clientCert := clientCertSummary(c.prof.Cert)
	c.recorder().edit(func(r *diag.SessionReport) {
		// Preserve the PEM fields the StageParse boundary already registered
		// for redaction; tlsInfo does not know about them.
		info.ClientCertPEM = r.TLS.ClientCertPEM
		info.ClientKeyPEM = r.TLS.ClientKeyPEM
		info.ClientCert = clientCert
		r.TLS = info
	})
}

// recordAdvertised stores what the client is about to tell the server in its
// key-method-2 packet, and registers the credentials it carries so that they
// are scrubbed out of the report and out of every error string in it.
//
// The AWS flow's fixed "N/A" is filtered out by reportableUsername: diag
// scrubs by substring with no minimum length, so registering three characters
// would blank every incidental "N/A" in the report's free text.
func (c *Client) recordAdvertised(username, password string) {
	// The dialed remote's transport, not the profile's: the tunnel options
	// string carries a link-mtu that differs by 22 bytes between the two, and
	// what the report says we advertised has to be what we advertised.
	adv := advertisedInfo(c.activeProto(), c.prof.TunMTU, c.advertisedDataChannel(), c.DataV2)
	reported := reportableUsername(username)
	c.recorder().edit(func(r *diag.SessionReport) {
		r.Advertised = adv
		r.SetCredentials(reported, password)
	})
}

// recordServerOpts stores the server's own options string from its
// key-method-2 packet. An empty string is ignored so that a second exchange's
// packet that could not be parsed does not erase what the first one captured.
func (c *Client) recordServerOpts(opts string) {
	if opts == "" {
		return
	}
	c.recorder().edit(func(r *diag.SessionReport) { r.ServerOpts = opts })
}

// recordPush stores the PUSH_REPLY — raw, parsed, and the options this client
// does not handle — together with what the two sides ended up negotiating. It
// also registers any pushed auth-token for redaction. opts may be nil when the
// reply failed to parse, in which case only the raw and per-keyword views are
// recorded.
func (c *Client) recordPush(raw string, opts *routing.PushOptions, peerID uint32) {
	parsed := pushParsedOptions(raw)
	unknown := pushUnknownOptions(raw)
	params, _, _ := c.negotiateDataChannel(opts) //nolint:errcheck // an unsupported cipher is reported by its own stage failure
	negotiated := negotiatedInfo(opts, peerID, params)
	c.recorder().edit(func(r *diag.SessionReport) {
		r.Push.Raw = raw
		r.Push.Parsed = parsed
		r.Push.UnknownOptions = unknown
		if opts == nil {
			return
		}
		r.Negotiated = negotiated
		if opts.AuthToken != "" {
			r.SetAuthToken(opts.AuthToken)
		}
		// Registered here rather than where the device records them:
		// Parsed carries them from this moment on, Redacted can only
		// remove a value from it that it knows is a secret, and
		// recordDevice runs only after the backend opens.
		if opts.Ifconfig != nil && opts.Ifconfig.Local != nil {
			r.AddSecret(opts.Ifconfig.Local.String())
		}
		if opts.Ifconfig6 != nil && opts.Ifconfig6.Local != nil {
			r.AddSecret(opts.Ifconfig6.Local.String())
		}
	})
}

// ---- Report population helpers -------------------------------------------

// profileFingerprint is a stable identifier for a parsed profile.
//
// It hashes the fields that decide how the connection behaves plus digests of
// the CA and client certificate, so two attempts against the same profile
// share it and the result carries no hostname, certificate or credential in
// recoverable form. The private key is not hashed at all: it contributes
// nothing a certificate digest does not, and leaving it out keeps key material
// off this path entirely.
func profileFingerprint(p *profile.Profile) string {
	if p == nil {
		return ""
	}
	h := sha256.New()
	fmt.Fprintf(h, "remote=%s\nport=%d\nproto=%s\ncipher=%s\nauth=%s\n",
		p.Remote, p.Port, p.Proto.String(), p.Cipher, p.Auth)
	fmt.Fprintf(h, "reneg-sec=%d\nreneg-bytes=%d\ntun-mtu=%d\nmssfix=%d/%t\n",
		p.RenegSec, p.RenegBytes, p.TunMTU, p.MSSFix, p.MSSFixSet)
	// The match type is part of the fingerprint because it is part of the
	// directive: the same name asks for three different checks depending on
	// it, and two profiles that differ only there are not the same profile.
	fmt.Fprintf(h, "random-hostname=%t\nverify-x509-name=%s/%s\nforce-saml=%t\n",
		p.RandomHostname, p.VerifyX509Name, p.VerifyX509NameMatch, p.Federated)
	caSum := sha256.Sum256(p.CA)
	certSum := sha256.Sum256(p.Cert)
	fmt.Fprintf(h, "ca=%x\ncert=%x\n", caSum[:8], certSum[:8])
	return hex.EncodeToString(h.Sum(nil))
}

// advertisedInfo describes what the client tells the server in its
// key-method-2 packet: the peer-info block and the tunnel options string, with
// IV_PROTO and IV_CIPHERS pulled out for aggregation. adv is the same
// advertisement keymethod2.SendAuth is given, so the reported IV_PROTO is the
// one that went out.
func advertisedInfo(proto profile.Proto, tunMTU int, params datachannel.Params, adv DataV2Advertisement) diag.AdvertisedInfo {
	block := peerInfoFor(adv)
	a := diag.AdvertisedInfo{
		PeerInfo: block,
		Options:  keymethod2.TunnelOptions(tunnelParams(proto, tunMTU, params)),
	}
	for line := range strings.SplitSeq(block, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		switch key {
		case "IV_PROTO":
			if n, err := strconv.ParseUint(value, 10, 32); err == nil {
				a.IVProto = uint32(n)
			}
		case "IV_CIPHERS":
			a.IVCiphers = value
		}
	}
	return a
}

// tlsInfo summarises a completed control-channel TLS session.
func tlsInfo(cs tls.ConnectionState) diag.TLSInfo {
	info := diag.TLSInfo{
		Version:     tls.VersionName(cs.Version),
		CipherSuite: tls.CipherSuiteName(cs.CipherSuite),
	}
	// EKMAvailable is a measurement instrument, not a client input. The export
	// succeeds only when the session can produce RFC 5705 keying material at
	// all — TLS 1.3, or TLS 1.2 with extended master secret — which is a strong
	// proxy for a peer new enough to offer "key-derivation tls-ekm". Probing
	// with the real label and a short length consumes nothing.
	if _, err := cs.ExportKeyingMaterial(prf.ExporterLabel, nil, 32); err == nil {
		info.EKMAvailable = true
	}
	for _, cert := range cs.PeerCertificates {
		info.Chain = append(info.Chain, certSummary(cert))
	}
	return info
}

// certSummary reduces a certificate to identifiers and validity. It never
// carries key material, so it survives redaction intact.
func certSummary(cert *x509.Certificate) diag.CertSummary {
	sum := sha256.Sum256(cert.Raw)
	s := diag.CertSummary{
		Subject:            cert.Subject.String(),
		Issuer:             cert.Issuer.String(),
		NotBefore:          cert.NotBefore,
		NotAfter:           cert.NotAfter,
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		PublicKeyAlgorithm: cert.PublicKeyAlgorithm.String(),
		SHA256:             hex.EncodeToString(sum[:]),
		DNSNames:           slices.Clone(cert.DNSNames),
	}
	if cert.SerialNumber != nil {
		s.SerialNumber = cert.SerialNumber.String()
	}
	return s
}

// clientCertSummary summarises the client certificate a profile embeds, or nil
// when the profile has none or the PEM does not decode. It carries identifiers
// only, so it survives redaction while the PEM beside it does not.
func clientCertSummary(pemBytes []byte) *diag.CertSummary {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil
	}
	s := certSummary(cert)
	return &s
}

// pushHandledOptions is the set of PUSH_REPLY keywords this client acts on.
//
// The bulk of it is what routing.ParsePushReply switches on (routing/push.go).
// Three more are handled elsewhere in the client and belong here too:
//
//	peer-id      parsePeerID       (datapath.go)
//	tun-mtu      effectiveTunMTU   (datapath.go)
//	dhcp-option  dns.ParsePushReply (dns/dns.go)
//
// Anything outside this set lands in Push.UnknownOptions. Keep it in step with
// those parsers: a keyword that gains a handler and is not added here quietly
// stops being reported, and one removed from a parser but left here hides a
// regression.
var pushHandledOptions = map[string]struct{}{
	// routing.ParsePushReply
	"topology":         {},
	"route-gateway":    {},
	"ifconfig":         {},
	"route":            {},
	"cipher":           {},
	"compress":         {},
	"comp-lzo":         {},
	"ifconfig-ipv6":    {},
	"route-ipv6":       {},
	"redirect-gateway": {},
	"ping":             {},
	"ping-restart":     {},
	"mssfix":           {},
	"protocol-flags":   {},
	"key-derivation":   {},
	"inactive":         {},
	"auth-token":       {},
	// handled outside routing
	"peer-id":     {},
	"tun-mtu":     {},
	"dhcp-option": {},
}

// pushParsedOptions maps each pushed keyword to the argument text of every
// occurrence, in the order received. A directive pushed twice yields two
// entries, because a server repeating "route" is the normal case.
func pushParsedOptions(raw string) map[string][]string {
	out := make(map[string][]string)
	for _, field := range routing.PushFields(raw) {
		keyword, args, _ := strings.Cut(field, " ")
		out[strings.ToLower(keyword)] = append(out[strings.ToLower(keyword)], strings.TrimSpace(args))
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// pushUnknownOptions returns every pushed directive whose keyword this client
// does not handle, deduplicated by keyword and in the order first seen.
func pushUnknownOptions(raw string) []string {
	var out []string
	seen := make(map[string]struct{})
	for _, field := range routing.PushFields(raw) {
		keyword, _, _ := strings.Cut(field, " ")
		keyword = strings.ToLower(keyword)
		if _, ok := pushHandledOptions[keyword]; ok {
			continue
		}
		if _, ok := seen[keyword]; ok {
			continue
		}
		seen[keyword] = struct{}{}
		out = append(out, field)
	}
	return out
}

// negotiatedInfo describes what the two sides settled on for the data channel.
//
// params is what the client resolved the two sides down to, so the report
// records the cipher, digest and wire format actually installed rather than
// re-deriving them here and risking a second answer.
func negotiatedInfo(opts *routing.PushOptions, peerID uint32, params datachannel.Params) diag.NegotiatedInfo {
	n := diag.NegotiatedInfo{PeerID: peerID}
	if opts == nil {
		return n
	}
	n.Cipher = opts.Cipher
	if n.Cipher == "" {
		n.Cipher = params.Spec.Name
	}
	// The digest comes from params rather than from the push, for the same
	// reason the cipher falls back to it: params is what was installed, and a
	// server that pushes no `auth` leaves the profile's — or OpenVPN's SHA1
	// default — in force. An AEAD cipher authenticates its own output and
	// resolves no digest, so the field stays empty there rather than reporting
	// a value nothing used.
	if params.Spec.UsesDigest() {
		n.Digest = params.Digest.String()
	}
	// The wire format sits with the rest of what was negotiated rather than
	// beside the peer-id it is chosen from: PeerID alone cannot carry it,
	// since 0 is both "the server pushed peer-id 0" and "the server pushed
	// none", and those are the two formats. It is written only for an attempt
	// that had a push to read.
	n.WireFormat = params.Wire.String()
	switch opts.KeyDerivation {
	case routing.KeyDerivationTLSEKM:
		n.KeyDerivation = "tls-ekm"
	case routing.KeyDerivationOpenVPNPRF:
		n.KeyDerivation = "prf"
	}
	return n
}

// recordDevice records which backend carried the tunnel, and the addresses it
// was given. The addresses are pushed internal ones, so Redacted blanks them;
// the backend identity survives and qualifies every timing in the report.
func (c *Client) recordDevice(backend device.Backend, dev device.Device, push *routing.PushOptions) {
	info := diag.DeviceInfo{
		Kind: string(backendKind(backend)),
		Name: dev.Name(),
		MTU:  dev.MTU(),
	}
	if push != nil {
		// Already registered as secrets by recordPush, which sees them one
		// stage earlier and has to, because Push.Parsed holds them from then.
		if push.Ifconfig != nil && push.Ifconfig.Local != nil {
			info.IPv4 = push.Ifconfig.Local.String()
		}
		if push.Ifconfig6 != nil && push.Ifconfig6.Local != nil {
			info.IPv6 = push.Ifconfig6.Local.String()
		}
	}
	c.recorder().edit(func(r *diag.SessionReport) { r.Device = info })
}

// kindNamer is implemented by a backend that can name itself in a session
// report. It is an optional interface rather than a method on device.Backend
// because the seam is a contract about producing a Device, not about
// diagnostics, and because a type switch here could never name the netstack
// backend, which the core must not import.
type kindNamer interface {
	Kind() device.Kind
}

// backendKind names a backend for the session report. A backend that does not
// name itself is reported as "other" rather than guessed at.
func backendKind(backend device.Backend) device.Kind {
	if k, ok := backend.(kindNamer); ok {
		return k.Kind()
	}
	return device.Kind("other")
}

// recordEMSExportFallback notes in the report that this session's key block
// came from the captured material rather than from crypto/tls: it counts the
// endpoints asking for an export their own TLS session cannot safely support.
func (c *Client) recordEMSExportFallback() {
	c.recorder().edit(func(r *diag.SessionReport) { r.TLS.EMSExportFallback = true })
}
