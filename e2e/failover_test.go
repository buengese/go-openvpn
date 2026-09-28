// SPDX-License-Identifier: LGPL-2.1-or-later

//go:build docker

// Remote failover: a profile whose first remote is a black hole connects
// through its second, and the transport that is dialed is the dialed remote's
// own. It lives here because it needs the userspace backend to reach the data
// stage without privilege, and netstack imports vpn and never the other way
// round.
package e2e

import (
	"context"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/buengese/go-openvpn/diag"
	"github.com/buengese/go-openvpn/netstack"
	"github.com/buengese/go-openvpn/profile"
	"github.com/buengese/go-openvpn/testenv"
)

// multiRemoteEntry is the failover isolate: two remotes, the first of them a
// port nothing is listening on. It is TCP because on UDP nothing is
// unambiguously dead.
const multiRemoteEntry = "v24-gcm256-sha256-plain-tcp-multiremote"

// mixedTransportProfile rewrites the entry's generated profile so that the
// profile-level --proto and the *dialed* remote's transport deliberately
// disagree: "proto udp" plus a tcp-client third field on the live remote. The
// dead first remote is left bare and inherits the profile's UDP, so it fails as
// an ICMP port-unreachable on the first read rather than at connect.
func mixedTransportProfile(t *testing.T, raw string) string {
	t.Helper()
	out := regexp.MustCompile(`(?m)^proto .*\n`).ReplaceAllString(raw, "proto udp\n")
	if out == raw {
		t.Fatal("generated profile carried no proto directive to rewrite")
	}
	var b strings.Builder
	seen := 0
	for line := range strings.SplitSeq(out, "\n") {
		if strings.HasPrefix(line, "remote ") {
			seen++
			if seen == 2 {
				line = strings.TrimRight(line, " ") + " tcp-client"
			}
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	if seen != 2 {
		t.Fatalf("generated profile carried %d remote lines, want 2", seen)
	}
	return b.String()
}

// TestFailoverConnectsThroughTheSecondRemote asserts four things at once,
// because they are only separable on paper: a profile whose first remote is a
// black hole connects through its second; the report names both, with a class
// for the first; the dialed remote's own transport is what is dialed and what
// everything downstream is framed against; and HTTP crosses in both directions,
// which is what makes the third an assertion rather than a hope.
func TestFailoverConnectsThroughTheSecondRemote(t *testing.T) {
	e, ok := testenv.Entry(multiRemoteEntry)
	if !ok {
		t.Fatalf("no entry %s; the failover isolate is gone", multiRemoteEntry)
	}
	srv, err := testenv.StartMatrix(e)
	if err != nil {
		t.Skipf("StartMatrix: %v", err)
	}
	defer srv.Stop() //nolint:errcheck

	if srv.DeadPort == 0 || srv.DeadPort == srv.Port {
		t.Fatalf("dead port %d, live port %d: the first remote is not dead",
			srv.DeadPort, srv.Port)
	}

	p, err := profile.ParseString(mixedTransportProfile(t, srv.ClientProfile()))
	if err != nil {
		t.Fatalf("ParseString: %v", err)
	}
	if p.Proto != profile.ProtoUDP {
		t.Fatalf("Profile.Proto = %v, want udp — the profile and the dialed remote "+
			"must disagree for this test to test the seam", p.Proto)
	}
	if len(p.Remotes) != 2 {
		t.Fatalf("got %d remotes, want 2", len(p.Remotes))
	}
	if p.Remotes[0].Port != srv.DeadPort || p.Remotes[0].Proto != profile.ProtoUDP {
		t.Fatalf("first remote = %+v, want the dead port on the profile's udp", p.Remotes[0])
	}
	if p.Remotes[1].Port != srv.Port || p.Remotes[1].Proto != profile.ProtoTCP {
		t.Fatalf("second remote = %+v, want the live port on its own tcp", p.Remotes[1])
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	tun, rep, connErr := netstack.ConnectWithReport(ctx, p, netstack.Options{})
	if tun != nil {
		defer tun.Close() //nolint:errcheck
	}
	if connErr != nil {
		t.Fatalf("Connect through the second remote: %v (outcome %s at %s)",
			connErr, rep.Outcome.Class, rep.Outcome.Stage)
	}
	if !rep.Outcome.Succeeded {
		t.Fatalf("outcome = %s/%s, want a completed tunnel — the first remote's "+
			"failure was not rewound", rep.Outcome.Class, rep.Outcome.Stage)
	}

	// The report names both endpoints, with a class for the first.
	if len(rep.Endpoint.Attempts) != 2 {
		t.Fatalf("Endpoint.Attempts = %+v, want one record per remote tried",
			rep.Endpoint.Attempts)
	}
	first, second := rep.Endpoint.Attempts[0], rep.Endpoint.Attempts[1]
	if first.Index != 0 || first.Port != srv.DeadPort || first.Proto != "udp" {
		t.Errorf("first attempt = %+v, want index 0 on the dead udp port %d",
			first, srv.DeadPort)
	}
	if first.Succeeded {
		t.Error("the first attempt claims success against a port nothing is listening on")
	}
	if first.Class != diag.ClassNetwork {
		t.Errorf("first attempt class = %s, want %s — a dead endpoint",
			first.Class, diag.ClassNetwork)
	}
	if first.Err == "" {
		t.Error("the first attempt records no reason; the point of the list is to say why")
	}
	if second.Index != 1 || second.Port != srv.Port || second.Proto != "tcp" {
		t.Errorf("second attempt = %+v, want index 1 on the live tcp port %d",
			second, srv.Port)
	}
	if !second.Succeeded {
		t.Error("the second attempt is not marked as the one that connected")
	}

	// The scalar Endpoint fields follow the endpoint that carried the session,
	// not the first line of the profile.
	if rep.Endpoint.Port != srv.Port || rep.Endpoint.Proto != "tcp" {
		t.Errorf("Endpoint = port %d proto %q, want the remote that connected (%d/tcp)",
			rep.Endpoint.Port, rep.Endpoint.Proto, srv.Port)
	}
	if rep.Endpoint.Remotes != 2 {
		t.Errorf("Endpoint.Remotes = %d, want 2", rep.Endpoint.Remotes)
	}
	t.Logf("%s: remote 0 (udp/%d) %s at %s; remote 1 (tcp/%d) connected",
		multiRemoteEntry, srv.DeadPort, first.Class, first.Stage, srv.Port)

	// And the framing. On TCP the length prefix is mandatory, so a UDP-framed
	// writer would not have got this far, and a UDP-framed reader would return
	// packets sliced across frame boundaries rather than erroring.
	fetchThroughTunnel(t, srv, tun, 8085, "failover-second-remote")
	assertCarriedBothWays(t, tun)
}

// TestSingleRemoteEntryDialsOnce is the negative control for the test above: a
// single-remote profile's report must carry exactly one endpoint record, or the
// test above would be satisfied by a client that dialed everything twice.
func TestSingleRemoteEntryDialsOnce(t *testing.T) {
	const entry = "v24-gcm256-sha256-plain-tcp"
	_, tun := startMatrixTunnel(t, entry)

	rep := tun.Report()
	if len(rep.Endpoint.Attempts) != 1 {
		t.Fatalf("Endpoint.Attempts = %+v, want exactly one: a single-remote "+
			"profile must dial once and only once", rep.Endpoint.Attempts)
	}
	a := rep.Endpoint.Attempts[0]
	if !a.Succeeded || a.Index != 0 || a.Proto != "tcp" {
		t.Errorf("the one attempt = %+v, want a successful index 0 on tcp", a)
	}
	if rep.Endpoint.Remotes != 1 {
		t.Errorf("Endpoint.Remotes = %d, want 1", rep.Endpoint.Remotes)
	}
}
