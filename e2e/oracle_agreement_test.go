// SPDX-License-Identifier: LGPL-2.1-or-later

//go:build docker

// A credential rejection reads as agreement, even though the two clients name
// different stages: OpenVPN sends AUTH_FAILED in place of PUSH_REPLY, so
// StagePush is genuinely where our client is, while ClassifyReferenceLog reads
// the same rejection off stock openvpn's log as StageAuth. Both halves are
// measured against a real server rather than claimed from the code.
package e2e

import (
	"context"
	"strings"
	"testing"
	"time"

	vpn "github.com/openlawsvpn/go-openlawsvpn"
	"github.com/openlawsvpn/go-openlawsvpn/diag"
	"github.com/openlawsvpn/go-openlawsvpn/netstack"
	"github.com/openlawsvpn/go-openlawsvpn/profile"
	"github.com/openlawsvpn/go-openlawsvpn/testenv"
)

// wrongPassword is a password the matrix's auth hook cannot accept. The
// username stays right, so a rejection cannot be explained by the server having
// failed to read the file at all.
const wrongPassword = "not-the-matrix-password"

// TestCredentialRejectionAgreesAcrossClients runs both clients against one
// server with one wrong password and compares what they said. Nothing here is a
// fixture: the stages the two report are measured, and if either ever moves the
// test says so rather than passing on a hard-coded pair.
func TestCredentialRejectionAgreesAcrossClients(t *testing.T) {
	const name = "v24-gcm256-sha256-plain-udp-userpass"
	e, ok := testenv.Entry(name)
	if !ok {
		t.Fatalf("no matrix entry %q; the credentials isolate is what makes this measurable", name)
	}
	srv, err := testenv.StartMatrix(e)
	if err != nil {
		t.Skipf("StartMatrix: %v", err)
	}
	t.Cleanup(func() { _ = srv.Stop() })

	// --- our client, with the wrong password ----------------------------
	p, err := profile.ParseString(srv.ClientProfile())
	if err != nil {
		t.Fatalf("ParseString: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	tun, rep, err := netstack.ConnectWithReport(ctx, p, netstack.Options{
		CredentialsFn: func(context.Context) (vpn.Credentials, error) {
			return vpn.Credentials{
				Username: testenv.MatrixUsername,
				Password: wrongPassword,
			}, nil
		},
	})
	if tun != nil {
		_ = tun.Close()
	}
	if err == nil {
		t.Fatal("our client connected with the wrong password; the entry is not " +
			"checking credentials and nothing below means anything")
	}
	ours := testenv.ClientOutcomeFromReport(rep)
	t.Logf("our client: %s at %s (%v)", ours.Class, ours.Stage, err)
	if ours.Class != diag.ClassAuth {
		t.Fatalf("our client called a wrong password %s at %s, want %s; the comparison "+
			"below is about the stage, and it only holds if the class is right",
			ours.Class, ours.Stage, diag.ClassAuth)
	}

	// --- stock openvpn, with the same wrong password ---------------------
	container, err := srv.ContainerProfile()
	if err != nil {
		t.Fatalf("ContainerProfile: %v", err)
	}
	opts := srv.OracleOptions()
	opts.Timeout = 60 * time.Second
	opts.Files[testenv.MatrixCredentialsFile] = testenv.MatrixUsername + "\n" + wrongPassword + "\n"

	ref, err := testenv.RunOracle(context.Background(), container, opts)
	if err != nil {
		t.Fatalf("RunOracle: %v", err)
	}
	t.Logf("stock openvpn: %s", ref)
	if ref.Connected {
		t.Fatalf("stock openvpn connected with the wrong password\nlog:\n%s", testenv.TailLines(ref.Log, 25))
	}
	if ref.Class != diag.ClassAuth {
		t.Fatalf("stock openvpn called a wrong password %s at %s, want %s\nlog:\n%s",
			ref.Class, ref.Stage, diag.ClassAuth, testenv.TailLines(ref.Log, 25))
	}

	// --- the asymmetry, re-measured --------------------------------------
	//
	// Logged rather than asserted as an equality: the point is not that the
	// stages must differ forever, it is that the comparison must not care.
	if ours.Stage == ref.Stage {
		t.Logf("the two stages now agree (%s); §7.8's asymmetry has gone, and "+
			"comparing on class remains correct", ours.Stage)
	} else {
		t.Logf("§7.8 confirmed: ours %s at %s, stock openvpn %s at %s — "+
			"same class, different stage", ours.Class, ours.Stage, ref.Class, ref.Stage)
	}

	// --- the comparison, and how it renders -----------------------------
	v := testenv.Compare(ours, ref)
	if v.Agreement != testenv.AgreementSameClass || !v.Agreement.Agrees() {
		t.Errorf("agreement = %s (Agrees=%v), want %s: both clients called it %s",
			v.Agreement, v.Agreement.Agrees(), testenv.AgreementSameClass, ours.Class)
	}
	if v.Cell != testenv.CellBadConfigOrDeadEndpoint {
		t.Errorf("cell = %s, want %s", v.Cell, testenv.CellBadConfigOrDeadEndpoint)
	}

	rendered := v.String()
	t.Logf("rendered verdict: %s", rendered)
	if strings.Contains(rendered, "classes differ") {
		t.Errorf("the rendered verdict reports a disagreement on a credential "+
			"rejection both clients called %s: %s", ours.Class, rendered)
	}
	if !strings.Contains(rendered, "both fail "+ours.Class.String()) {
		t.Errorf("the rendered verdict does not say the two agree: %s", rendered)
	}
	// Agreement is keyed on the class; the report still names both stages. A
	// reader who wants to know where each client stopped is not served by a
	// line that hides it.
	for _, want := range []string{ours.Stage.String(), ref.Stage.String()} {
		if !strings.Contains(rendered, want) {
			t.Errorf("the rendered verdict drops stage %q: %s", want, rendered)
		}
	}
}
