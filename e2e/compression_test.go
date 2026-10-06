// SPDX-License-Identifier: LGPL-2.1-or-later

//go:build docker

// Compression: a data channel that survives its profile's compression setting,
// and a peer that really compressed decompressed rather than misread.
//
// A peer with a compression directive frames every data packet and drops what
// it cannot parse, so the framing is the difference between a tunnel and a
// silence. Matrix entries one axis apart separate the three claims below.
package e2e

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

// compressionEntries is the framing ladder: one entry per wire framing this
// client has to produce, each carrying the mode its own profile declares.
//
// wantCompression is load-bearing: no OpenVPN 2 server pushes a compression
// option, so the profile is the only source and a client reading only the
// PUSH_REPLY concludes "none" and frames nothing.
var compressionEntries = []struct {
	entry           string
	directive       string
	framing         string
	wantCompression string
}{
	{
		entry: "v24-cbc256-sha1-complzo-udp", directive: "comp-lzo",
		framing:         "one byte prepended: 0xFA ‖ plain",
		wantCompression: "comp-lzo",
	},
	{
		entry: "v25-cbc128-sha256-compstub-udp", directive: "compress stub-v2",
		framing:         "no byte at all, unless the packet begins 0x50",
		wantCompression: "compress stub-v2",
	},
	{
		entry: "v26-gcm256-sha256-compstub-udp", directive: "compress stub-v2",
		framing:         "no byte at all, unless the packet begins 0x50",
		wantCompression: "compress stub-v2",
	},
}

// incompressibleBody returns n bytes of base64-encoded randomness, safe to
// embed in the responder's Perl string. A 2.4 server with a bare `comp-lzo`
// attempts LZO on anything over 100 bytes, so a compressible body would leave
// the framing unproven.
func incompressibleBody(t *testing.T, n int) string {
	t.Helper()
	raw := make([]byte, n)
	if _, err := rand.Read(raw); err != nil {
		t.Fatalf("read random bytes: %v", err)
	}
	return base64.RawStdEncoding.EncodeToString(raw)[:n]
}

// TestCompressionFramingCarriesTraffic fetches through a data channel that has
// a framing byte to get right in both directions, from an address that exists
// only on the tunnel subnet inside the server container.
func TestCompressionFramingCarriesTraffic(t *testing.T) {
	for _, tc := range compressionEntries {
		t.Run(tc.entry, func(t *testing.T) {
			t.Logf("%s — %s", tc.directive, tc.framing)
			srv, tun := startMatrixTunnel(t, tc.entry)

			// Assert before fetching: a tunnel that carried HTTP with the
			// framing switched off is still a tunnel that carried HTTP,
			// against a server that also switched it off.
			rep := tun.Report()
			if got := rep.Negotiated.Compression; got != tc.wantCompression {
				t.Fatalf("negotiated compression = %q, want %q: this entry's own profile "+
					"carries %q and nothing is pushed, so a %q here means the profile "+
					"directive was not read", got, tc.wantCompression, tc.directive, got)
			}

			fetchThroughTunnel(t, srv, tun, 8084, incompressibleBody(t, 1024))
			data := assertCarriedBothWays(t, tun)

			rep = tun.Report()
			if rep.Counters.DecryptFailures > 0 {
				t.Errorf("%d packets failed to decrypt or unwrap; a framing this client "+
					"cannot place is counted here", rep.Counters.DecryptFailures)
			}
			t.Logf("%s: compression=%s StageData=%s sent=%d recv=%d",
				tc.entry, rep.Negotiated.Compression, data.Duration,
				rep.Counters.BytesSent, rep.Counters.BytesRecv)
		})
	}
}

// TestCompressedPayloadIsDecompressed drives the one matrix entry that puts a
// genuinely compressed payload on the wire: `comp-lzo yes`, so adaptive
// compression is off. The body is a long run of one byte, because LZO still
// emits the uncompressed marker when compression would not shrink the payload.
func TestCompressedPayloadIsDecompressed(t *testing.T) {
	const entry = "v24-cbc256-sha1-complzoyes-udp"
	srv, tun := startMatrixTunnel(t, entry)

	if got := tun.Report().Negotiated.Compression; got != "comp-lzo" {
		t.Fatalf("negotiated compression = %q, want %q; without the LZO framing this "+
			"entry cannot produce a compressed payload", got, "comp-lzo")
	}

	// Several full segments, each far past COMPRESS_THRESHOLD.
	fetchThroughTunnel(t, srv, tun, 8085, strings.Repeat("A", 4096))
	assertCarriedBothWays(t, tun)

	rep := tun.Report()
	if rep.Counters.Decompressed == 0 {
		t.Fatal("the fetch succeeded and no packet was decompressed, so the server never " +
			"compressed one: this entry is not exercising the decompressor. Check that it " +
			"is still `comp-lzo yes` on 2.4 — 2.5 and 2.6 never compress on send without " +
			"allow-compression yes")
	}
	if rep.Counters.DecryptFailures > 0 {
		t.Errorf("%d packets failed to decrypt or decompress", rep.Counters.DecryptFailures)
	}
	t.Logf("%s: decompressed=%d recv=%d", entry, rep.Counters.Decompressed, rep.Counters.PacketsRecv)
}

// probePayload is a full-MTU-ish payload, large enough that a peer's
// compressor has something to work with and small enough not to fragment.
const probePayload = 1200

// TestPingProbeDistinguishesACompressingPeer is the instrument check for
// Tunnel.Ping used as a compression probe, and a 2x2: only the compressing
// peer given something worth compressing may show a decompressed packet, and
// every payload must cross.
func TestPingProbeDistinguishesACompressingPeer(t *testing.T) {
	for _, tc := range []struct {
		entry string
		// wantCompressed is whether a repetitive payload should come back
		// compressed.
		wantCompressed bool
	}{
		{"v24-cbc256-sha1-complzo-udp", true},
		{"v26-gcm256-sha256-plain-udp", false},
	} {
		t.Run(tc.entry, func(t *testing.T) {
			_, tun := startMatrixTunnel(t, tc.entry)
			gw, err := tun.Gateway()
			if err != nil {
				t.Fatalf("Gateway: %v", err)
			}
			random := make([]byte, probePayload)
			if _, err := rand.Read(random); err != nil {
				t.Fatal(err)
			}
			// Repetitive first: 2.4's adaptive compression switches itself off
			// for a minute after a sample that did not compress.
			for i, p := range []struct {
				name         string
				payload      []byte
				compressible bool
			}{
				{"repetitive", bytes.Repeat([]byte("A"), probePayload), true},
				{"random", random, false},
			} {
				before := tun.Report().Counters.Decompressed
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				_, err := tun.Ping(ctx, gw, p.payload, uint16(i+1))
				cancel()
				if err != nil {
					t.Fatalf("%s payload to %s: %v", p.name, gw, err)
				}
				got := tun.Report().Counters.Decompressed - before
				if want := tc.wantCompressed && p.compressible; (got > 0) != want {
					t.Errorf("%s payload: %d packets decompressed, want compressed=%v",
						p.name, got, want)
				}
			}
		})
	}
}
