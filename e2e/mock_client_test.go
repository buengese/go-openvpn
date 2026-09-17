// SPDX-License-Identifier: LGPL-2.1-or-later

//go:build mockserver

// A whole tunnel, end to end, in an unprivileged process, against the mock
// server rather than the Docker matrix. It lives here because netstack imports
// vpn and never the other way round.
//
// Run with:
//
//	go test -v -tags=mockserver ./e2e/
package e2e

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	vpn "github.com/openlawsvpn/go-openlawsvpn"
	"github.com/openlawsvpn/go-openlawsvpn/diag"
	"github.com/openlawsvpn/go-openlawsvpn/netstack"
	"github.com/openlawsvpn/go-openlawsvpn/profile"
	"github.com/openlawsvpn/go-openlawsvpn/testenv"
)

// TestMockServerCompletesUnprivileged is the claim the userspace backend rests
// on, in its smallest form: the exchange reaches a working tunnel with no
// privilege, and the report names the backend that carried it. StageData
// completes only when a packet has gone each way (see markDataFlow), and the
// mock's traffic is all keepalives — so its duration stays zero.
func TestMockServerCompletesUnprivileged(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("this test is only meaningful unprivileged; re-run as a normal user")
	}

	// The mock server is given a CA and the profile is given the same one: the
	// client has no InsecureSkipVerify fallback, so a profile with no CA does
	// not open a socket at all.
	pki, err := testenv.NewMockPKI(t.TempDir())
	if err != nil {
		t.Fatalf("generate mock PKI: %v", err)
	}
	srv, err := testenv.Start(testenv.Config{Binary: buildMockServer(t), CertDir: pki.Dir})
	if err != nil {
		t.Fatalf("start mock server: %v", err)
	}
	defer func() { _ = srv.Stop() }()
	time.Sleep(200 * time.Millisecond)

	host, port := splitAddr(t, srv.TCPAddr)
	c := vpn.New(&profile.Profile{Remote: host, Port: port, Proto: profile.ProtoTCP, CA: pki.CAPEM})
	c.Device = netstack.NewBackend()
	// A profile with no client certificate is FlowUserPass, and a FlowUserPass
	// profile with no CredentialsFn is refused at StageParse before it dials.
	// The mock checks nothing.
	c.CredentialsFn = func(context.Context) (vpn.Credentials, error) {
		return vpn.Credentials{Username: "mock", Password: "mock"}, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	if err := c.Connect(ctx); err != nil {
		t.Fatalf("Connect with the netstack backend should need no privilege: %v", err)
	}
	defer func() {
		c.Disconnect()        //nolint:errcheck
		c.WaitForDisconnect() //nolint:errcheck
	}()

	rep := c.Report()
	if rep == nil {
		t.Fatal("Report returned nil")
	}
	if !rep.Outcome.Succeeded {
		t.Errorf("outcome: succeeded=false class=%s stage=%s chain=%v",
			rep.Outcome.Class, rep.Outcome.Stage, rep.Outcome.ErrorChain)
	}

	var data *diag.StageRecord
	for i := range rep.Stages {
		if rep.Stages[i].Stage == diag.StageData {
			data = &rep.Stages[i]
		}
	}
	if data == nil {
		t.Fatalf("no StageData record; stages reached: %s", stageNames(rep))
	}
	// Deliberately not asserted: data.Duration > 0. The only traffic here is
	// keepalives, which are dropped before markDataFlow.

	// The device block names the backend that carried it, and its addresses
	// are blanked by redaction.
	if rep.Device.Kind != string(netstackKind) {
		t.Errorf("device kind = %q, want %q", rep.Device.Kind, netstackKind)
	}
	if rep.Device.MTU == 0 || rep.Device.Name == "" {
		t.Errorf("device identity incomplete: %+v", rep.Device)
	}
	if rep.Device.IPv4 == "" {
		t.Error("device recorded no assigned address")
	}
	if red := rep.Redacted(); red.Device.IPv4 == rep.Device.IPv4 {
		t.Errorf("redaction left the pushed address in place: %q", red.Device.IPv4)
	}

	t.Logf("stages: %s", stageNames(rep))
	t.Logf("device: kind=%s name=%s mtu=%d", rep.Device.Kind, rep.Device.Name, rep.Device.MTU)
	t.Logf("StageData duration: %s (zero is expected: keepalives are not user data)", data.Duration)
}

// netstackKind is the Kind the netstack backend reports itself as.
const netstackKind = "netstack"

func stageNames(rep *diag.SessionReport) string {
	var names []string
	for _, s := range rep.Stages {
		names = append(names, s.Stage.String())
	}
	return strings.Join(names, " → ")
}
