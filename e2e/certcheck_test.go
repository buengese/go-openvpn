//go:build docker

// The two certificate checks OpenVPN makes on top of the chain —
// verify-x509-name and ns-cert-type — driven against the matrix entries built
// for them. The matching and mismatching verify-x509-name entries are a pair
// and only the pair proves anything: a client that ignores the directive
// connects to both.
package e2e

import (
	"context"
	"strings"
	"testing"
	"time"

	vpn "github.com/buengese/go-openvpn"
	"github.com/buengese/go-openvpn/diag"
	"github.com/buengese/go-openvpn/profile"
	"github.com/buengese/go-openvpn/testenv"
)

// attemptMatrix runs one attempt against a matrix entry and returns the session
// report. Connect is allowed to fail on the TUN device: every stage under test
// is complete before a device is opened.
func attemptMatrix(t *testing.T, entry string) *diag.SessionReport {
	t.Helper()

	e, ok := testenv.Entry(entry)
	if !ok {
		t.Fatalf("no matrix entry %q", entry)
	}
	if e.ClientUnsupported != "" {
		t.Skipf("%s: %s", entry, e.ClientUnsupported)
	}
	srv, err := testenv.StartMatrix(e)
	if err != nil {
		t.Skipf("StartMatrix: %v", err)
	}
	defer srv.Stop() //nolint:errcheck

	p, err := profile.ParseString(srv.ClientProfile())
	if err != nil {
		t.Fatalf("ParseString: %v", err)
	}

	c := vpn.New(p)
	c.PreflightMode = diag.PreflightAdvisory
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	_ = c.Connect(ctx)
	c.Disconnect()        //nolint:errcheck
	c.WaitForDisconnect() //nolint:errcheck
	return c.Report()
}

// completed reports whether the attempt entered the stage and left it without
// an error, which is the only way to say "TLS succeeded" from a report: an
// attempt that fails later still has a StageTLS record.
func completed(rep *diag.SessionReport, stage diag.Stage) bool {
	for _, s := range rep.Stages {
		if s.Stage == stage {
			return s.Err == ""
		}
	}
	return false
}

// TestVerifyX509NameAgainstTheMatrix checks both directions against a real
// server: the matching entry completes the handshake and the mismatching one is
// refused ClassTLS at StageTLS. The two differ in one field of one directive,
// so a difference in outcome can be attributed to the check.
func TestVerifyX509NameAgainstTheMatrix(t *testing.T) {
	t.Run("matching CN connects", func(t *testing.T) {
		rep := attemptMatrix(t, "v24-gcm256-sha256-plain-udp-x509name")
		if !completed(rep, diag.StageTLS) {
			t.Fatalf("TLS did not complete against a certificate whose CN matches "+
				"verify-x509-name: outcome=%s/%s", rep.Outcome.Class, rep.Outcome.Stage)
		}
		t.Logf("furthest=%s outcome=%s/%s", furthestStage(rep),
			rep.Outcome.Class, rep.Outcome.Stage)
	})

	t.Run("mismatching CN is refused at TLS", func(t *testing.T) {
		rep := attemptMatrix(t, "v24-gcm256-sha256-plain-udp-x509name-bad")
		if completed(rep, diag.StageTLS) {
			t.Fatal("TLS completed against a certificate whose CN does not match " +
				"verify-x509-name; the directive is not being honoured")
		}
		if rep.Outcome.Class != diag.ClassTLS {
			t.Errorf("class = %s, want %s", rep.Outcome.Class, diag.ClassTLS)
		}
		if rep.Outcome.Stage != diag.StageTLS {
			t.Errorf("stage = %s, want %s", rep.Outcome.Stage, diag.StageTLS)
		}
		// The refusal must name the directive rather than being any TLS
		// failure at all — a server that never started would also not
		// complete the handshake.
		if !errorChainMentions(rep, "verify-x509-name") {
			t.Errorf("the refusal does not name verify-x509-name: %v", rep.Outcome.ErrorChain)
		}
	})
}

// TestNSCertTypeAgainstTheMatrix drives the only vehicle ns-cert-type has: the
// matrix issues the Netscape certificate-type extension for this entry alone,
// so a client that never reads the extension and one that finds it present are
// told apart here and nowhere else.
func TestNSCertTypeAgainstTheMatrix(t *testing.T) {
	rep := attemptMatrix(t, "v24-gcm256-sha256-plain-udp-nscerttype")
	if !completed(rep, diag.StageTLS) {
		t.Fatalf("TLS did not complete against a certificate carrying the Netscape "+
			"certificate-type extension: outcome=%s/%s %v",
			rep.Outcome.Class, rep.Outcome.Stage, rep.Outcome.ErrorChain)
	}
	t.Logf("furthest=%s outcome=%s/%s", furthestStage(rep),
		rep.Outcome.Class, rep.Outcome.Stage)
}

// TestUncheckedEntriesStillConnect is the control for both tests above: an
// entry carrying neither directive must behave exactly as it did, so a
// regression in the verifier cannot be mistaken for one in the checks.
func TestUncheckedEntriesStillConnect(t *testing.T) {
	rep := attemptMatrix(t, "v24-gcm256-sha256-plain-udp")
	if !completed(rep, diag.StageTLS) {
		t.Fatalf("TLS did not complete against the entry the checks hang off: "+
			"outcome=%s/%s %v", rep.Outcome.Class, rep.Outcome.Stage, rep.Outcome.ErrorChain)
	}
}

// furthestStage is the deepest stage the attempt entered.
func furthestStage(rep *diag.SessionReport) diag.Stage {
	var furthest diag.Stage
	for _, s := range rep.Stages {
		if s.Stage > furthest {
			furthest = s.Stage
		}
	}
	return furthest
}

// errorChainMentions reports whether any link of the failure names the text.
func errorChainMentions(rep *diag.SessionReport, text string) bool {
	for _, s := range rep.Outcome.ErrorChain {
		if strings.Contains(s, text) {
			return true
		}
	}
	return false
}
