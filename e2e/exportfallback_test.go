// SPDX-License-Identifier: LGPL-2.1-or-later

//go:build docker

// The EMS export fallback runs where it is needed, and nowhere else. The session
// it exists for — TLS 1.2 without RFC 7627 EMS — has no matrix vehicle, so what
// the matrix proves is the other direction, on a 2.6 entry pushing tls-ekm.
package e2e

import (
	"testing"
)

// TestEKMSessionsTakeTheGoPath asserts that an ordinary exporter session never
// touches the fallback.
func TestEKMSessionsTakeTheGoPath(t *testing.T) {
	const entry = "v26-gcm256-sha256-plain-udp"
	srv, tun := startMatrixTunnel(t, entry)

	rep := tun.Report()
	if got := rep.Negotiated.KeyDerivation; got != "tls-ekm" {
		t.Fatalf("key derivation = %q, want tls-ekm: this entry must push the "+
			"exporter path or the test proves nothing", got)
	}
	// EKMAvailable is the report's own probe, made with the same label at the
	// TLS stage: the export was available, so the fallback had no business
	// running.
	if !rep.TLS.EKMAvailable {
		t.Errorf("ekm_available is false on a session that derived keys by tls-ekm")
	}
	if rep.TLS.EMSExportFallback {
		t.Fatalf("the key block came from the captured session material on a %s "+
			"session crypto/tls exports from; the fallback is for the sessions "+
			"where it refuses, not for every session", rep.TLS.Version)
	}

	// And the keys work, which is the only thing that distinguishes a correct
	// export from a plausible one.
	fetchThroughTunnel(t, srv, tun, 8087, "ems-go-path")

	t.Logf("%s: %s / %s derivation=%s ekm_available=%t ems_fallback=%t",
		entry, rep.TLS.Version, rep.TLS.CipherSuite, rep.Negotiated.KeyDerivation,
		rep.TLS.EKMAvailable, rep.TLS.EMSExportFallback)
}
