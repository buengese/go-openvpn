// SPDX-License-Identifier: LGPL-2.1-or-later

//go:build docker

// The interop ladder: a server nobody here configured carries our packets, in
// every negotiated shape the client has to speak.
//
// OpenVPN 2.4 and 2.5 have no TLS keying-material exporter, so the classic key
// derivation is the only one available there. Each entry differs from a
// neighbour by exactly one axis, which
// testenv.TestLadderIsolatesDifferByExactlyOneAxis asserts.
package e2e

import (
	"testing"
)

// ladderPort is where the in-container responder listens for this file. Every
// subtest gets a fresh container, so one port serves the whole ladder.
const ladderPort = 8081

// ladderEntries is the ladder, in the order it isolates things. wantWrap is the
// load-bearing column: a wrap is configured rather than negotiated, so a bug
// that failed to install one would leave a working plain tunnel and a green
// test.
var ladderEntries = []struct {
	entry     string
	step      string
	isolates  string
	wantWrap  string
	wantDeriv string
	wantCiph  string
}{
	// --- the anchors: 2.6, nothing in the way -----------------------------
	// 2.6 offers EKM, GCM and a plain control channel, so these two are what
	// everything below is measured against, differing only in transport.
	{
		entry: "v26-gcm256-sha256-plain-udp", step: "anchor",
		isolates:  "nothing wrapped, nothing credentialled, the exporter derivation",
		wantWrap:  "none",
		wantDeriv: "tls-ekm", wantCiph: "AES-256-GCM",
	},
	{
		entry: "v26-gcm256-sha512-plain-tcp", step: "anchor (tcp)",
		isolates:  "the transport, and nothing else, against v26-gcm256-sha256-plain-udp",
		wantWrap:  "none",
		wantDeriv: "tls-ekm", wantCiph: "AES-256-GCM",
	},

	// --- the classic key derivation, and the cipher breadth behind it ----
	// The first row differs from the 2.6 anchor only in the key derivation;
	// the rest walk one axis at a time into CBC cipher and digest breadth.
	{
		entry: "v24-gcm256-sha256-plain-udp", step: "classic derivation",
		isolates:  "the key derivation, and nothing else, against v26-gcm256-sha256-plain-udp",
		wantWrap:  "none",
		wantDeriv: "prf", wantCiph: "AES-256-GCM",
	},
	{
		entry: "v24-cbc256-sha256-plain-udp", step: "cipher breadth",
		isolates:  "the CBC data path, one axis from the entry above",
		wantWrap:  "none",
		wantDeriv: "prf", wantCiph: "AES-256-CBC",
	},
	{
		entry: "v24-cbc256-sha512-plain-udp", step: "digest breadth",
		isolates:  "the digest, one axis from the entry above",
		wantWrap:  "none",
		wantDeriv: "prf", wantCiph: "AES-256-CBC",
	},
	{
		entry: "v25-gcm256-sha256-plain-udp", step: "server-series breadth",
		isolates:  "the 2.5 series, one axis from the derivation isolate",
		wantWrap:  "none",
		wantDeriv: "prf", wantCiph: "AES-256-GCM",
	},
	{
		entry: "v25-gcm128-sha256-plain-udp", step: "key-length breadth",
		isolates:  "the AEAD key length, one axis from the entry above",
		wantWrap:  "none",
		wantDeriv: "prf", wantCiph: "AES-128-GCM",
	},
	{
		entry: "v24-cbc128-sha1-plain-udp", step: "deployed breadth",
		isolates: "AES-128-CBC with SHA1 — two axes from the CBC chain rather than one. " +
			"It is here because deployed profiles ask for it, not because it " +
			"isolates anything",
		wantWrap:  "none",
		wantDeriv: "prf", wantCiph: "AES-128-CBC",
	},

	// --- plain, ±credentials ---------------------------------------------
	// Plain on purpose: behind a wrapped control channel "the password was
	// wrong" and "no reply ever came" produce the same silence.
	{
		entry: "v24-gcm256-sha256-plain-udp-userpass", step: "+credentials",
		isolates:  "credentials, and nothing else, against v24-gcm256-sha256-plain-udp",
		wantWrap:  "none",
		wantDeriv: "prf", wantCiph: "AES-256-GCM",
	},
}

// TestNegotiatedShapesCarryTraffic drives every entry of the ladder through one
// body, fetched from an address that exists only on the tunnel subnet inside
// the server container. One body for every entry is the point: anything the
// fetch did differently between two would be a difference the ladder cannot
// attribute to an axis.
func TestNegotiatedShapesCarryTraffic(t *testing.T) {
	for _, tc := range ladderEntries {
		t.Run(tc.entry, func(t *testing.T) {
			t.Logf("%s — isolates: %s", tc.step, tc.isolates)
			srv, tun := startMatrixTunnel(t, tc.entry)

			// Assert before fetching: a tunnel that carried HTTP over a control
			// channel we failed to wrap is still a tunnel that carried HTTP.
			rep := tun.Report()
			if got := rep.Negotiated.TLSWrap; got != tc.wantWrap {
				t.Fatalf("control-channel wrap = %q, want %q: this entry must "+
					"exercise that wrap or it proves nothing", got, tc.wantWrap)
			}
			if got := rep.Negotiated.KeyDerivation; got != tc.wantDeriv {
				t.Fatalf("key derivation = %q, want %q: this entry must exercise "+
					"that derivation or it proves nothing", got, tc.wantDeriv)
			}
			if got := rep.Negotiated.Cipher; got != tc.wantCiph {
				t.Errorf("cipher = %q, want %q", got, tc.wantCiph)
			}

			fetchThroughTunnel(t, srv, tun, ladderPort, "through-the-tunnel")
			data := assertCarriedBothWays(t, tun)

			// One line, every negotiated parameter.
			rep = tun.Report()
			t.Logf("%s: wrap=%s derivation=%s cipher=%s StageData=%s sent=%d recv=%d",
				tc.entry, rep.Negotiated.TLSWrap, rep.Negotiated.KeyDerivation,
				rep.Negotiated.Cipher, data.Duration,
				rep.Counters.BytesSent, rep.Counters.BytesRecv)
		})
	}
}
