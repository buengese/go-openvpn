// SPDX-License-Identifier: LGPL-2.1-or-later

//go:build docker

// Compression: a data channel that survives its profile's compression setting,
// and a peer that really compressed refused rather than misread.
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
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/buengese/go-openvpn/diag"
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

// TestCompressedPayloadIsUnsupportedNotCorruption drives the one matrix entry
// that puts a genuinely compressed payload on the wire: `comp-lzo yes`, so
// adaptive compression is off. The body is a long run of one byte, because LZO
// still emits the uncompressed marker when compression would not shrink the
// payload. What must happen is a refusal: no codec is linked, so the blob
// behind a 0x66 marker would carry garbage into the tunnel.
func TestCompressedPayloadIsUnsupportedNotCorruption(t *testing.T) {
	const entry = "v24-cbc256-sha1-complzoyes-udp"
	srv, tun := startMatrixTunnel(t, entry)

	if got := tun.Report().Negotiated.Compression; got != "comp-lzo" {
		t.Fatalf("negotiated compression = %q, want %q; without the LZO framing this "+
			"entry cannot produce a compressed payload to refuse", got, "comp-lzo")
	}

	// Maximally compressible, and long enough to span several full segments
	// so that at least one is far past COMPRESS_THRESHOLD.
	body := strings.Repeat("A", 4096)
	const port = 8085
	startResponder(t, srv, port, body)

	// Not fetchThroughTunnel: the fetch is expected to fail, and a fetch that
	// succeeds is itself the diagnosis rather than an ordinary mismatch.
	client := &http.Client{
		Transport: &http.Transport{DialContext: tun.DialContext},
		Timeout:   20 * time.Second,
	}
	url := fmt.Sprintf("http://%s:%d/", serverTunIP, port)
	resp, err := client.Get(url)
	if err == nil {
		got, readErr := io.ReadAll(resp.Body)
		resp.Body.Close() //nolint:errcheck
		if readErr == nil && string(got) == body {
			t.Fatalf("the fetch succeeded and returned all %d bytes, so the server never "+
				"compressed a packet: this entry is not exercising the branch it exists "+
				"for. Check that it is still `comp-lzo yes` on 2.4 — 2.5 and 2.6 never "+
				"compress on send without allow-compression yes", len(body))
		}
	}

	// The session must have ended as unsupported, at the data stage, naming
	// the algorithm. Poll: the refusal happens on the receive path, and the
	// fetch above may return before the report is written.
	var rep *diag.SessionReport
	deadline := time.Now().Add(20 * time.Second)
	for {
		rep = tun.Report()
		if rep.Outcome.Class == diag.ClassUnsupported || time.Now().After(deadline) {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}

	if rep.Outcome.Class != diag.ClassUnsupported {
		t.Fatalf("outcome = %s at %s (%v), want %s: a peer that compressed a payload we "+
			"cannot decompress must end the session, not be counted as %d dropped packets",
			rep.Outcome.Class, rep.Outcome.Stage, rep.Outcome.ErrorChain,
			diag.ClassUnsupported, rep.Counters.DecryptFailures)
	}
	if rep.Outcome.Stage != diag.StageData {
		t.Errorf("stage = %s, want %s: the payload arrived through a finished tunnel",
			rep.Outcome.Stage, diag.StageData)
	}
	if !strings.Contains(rep.Outcome.Feature, "lzo") {
		t.Errorf("feature = %q, want it to name the algorithm the peer used; a sweep has "+
			"to be able to attribute this to a directive rather than to a byte",
			rep.Outcome.Feature)
	}
	t.Logf("%s: outcome=%s at %s feature=%q chain=%v",
		entry, rep.Outcome.Class, rep.Outcome.Stage, rep.Outcome.Feature, rep.Outcome.ErrorChain)
}

// probePayload is a full-MTU-ish payload, large enough that a peer's
// compressor has something to work with and small enough not to fragment.
const probePayload = 1200

// TestPingProbeDistinguishesACompressingPeer is the instrument check for
// Tunnel.Ping used as a compression probe, and a 2x2 rather than a single case:
// only the compressing peer given something worth compressing may fail, and the
// random payload against the same server is what proves the tunnel was
// otherwise fine.
func TestPingProbeDistinguishesACompressingPeer(t *testing.T) {
	for _, tc := range []struct {
		entry string
		// wantCompressed is whether a repetitive payload should come back
		// compressed, ending the connection as ClassUnsupported.
		wantCompressed bool
	}{
		{"v24-cbc256-sha1-complzo-udp", true},
		{"v26-gcm256-sha256-plain-udp", false},
	} {
		t.Run(tc.entry, func(t *testing.T) {
			// Random first, in its own tunnel: a peer that compresses ends
			// the connection, so the two payloads cannot share one.
			t.Run("random payload always crosses", func(t *testing.T) {
				_, tun := startMatrixTunnel(t, tc.entry)
				gw, err := tun.Gateway()
				if err != nil {
					t.Fatalf("Gateway: %v", err)
				}
				payload := make([]byte, probePayload)
				if _, err := rand.Read(payload); err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				defer cancel()
				rtt, err := tun.Ping(ctx, gw, payload, 1)
				if err != nil {
					t.Fatalf("random payload to %s: %v — incompressible bytes give even a "+
						"compressing peer nothing to compress, so this must cross", gw, err)
				}
				if rtt <= 0 {
					t.Errorf("rtt = %v, want a positive round trip", rtt)
				}
			})

			t.Run("repetitive payload", func(t *testing.T) {
				_, tun := startMatrixTunnel(t, tc.entry)
				gw, err := tun.Gateway()
				if err != nil {
					t.Fatalf("Gateway: %v", err)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				defer cancel()
				_, err = tun.Ping(ctx, gw, bytes.Repeat([]byte("A"), probePayload), 1)

				rep := tun.Report()
				if !tc.wantCompressed {
					if err != nil {
						t.Fatalf("repetitive payload to a peer that does not compress: %v", err)
					}
					return
				}
				if err == nil {
					t.Fatal("repetitive payload crossed a comp-lzo peer intact; the probe " +
						"measures nothing if a compressing peer never compresses")
				}
				if rep.Outcome.Class != diag.ClassUnsupported || rep.Outcome.Stage != diag.StageData {
					t.Errorf("outcome = %s/%s, want %s/%s — a compressed payload is a "+
						"capability we lack, not a transport fault",
						rep.Outcome.Class, rep.Outcome.Stage, diag.ClassUnsupported, diag.StageData)
				}
				if rep.Outcome.Feature == "" {
					t.Error("outcome names no feature; the algorithm is the actionable half")
				}
				t.Logf("compressing peer detected: %s/%s feature=%q",
					rep.Outcome.Class, rep.Outcome.Stage, rep.Outcome.Feature)
			})
		})
	}
}
