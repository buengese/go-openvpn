// SPDX-License-Identifier: LGPL-2.1-or-later

//go:build docker

// The remote line's third field decides the transport, not the profile's
// --proto. It lives here because it needs the userspace backend to reach the
// data stage without privilege, and netstack imports vpn and never the other
// way round.

package e2e

import (
	"context"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/openlawsvpn/go-openlawsvpn/diag"
	"github.com/openlawsvpn/go-openlawsvpn/netstack"
	"github.com/openlawsvpn/go-openlawsvpn/profile"
	"github.com/openlawsvpn/go-openlawsvpn/testenv"
)

// protoLine matches the generated profile's --proto directive, which these
// tests remove so that the remote line is the only statement of transport.
var protoLine = regexp.MustCompile(`(?m)^proto .*\n`)

// remoteOnlyTransport rewrites a generated matrix profile into the shape real
// profiles ship: no --proto directive at all, and the transport carried in the
// third field of the remote line. third may be empty, which produces a profile
// that states no transport anywhere and inherits OpenVPN's UDP default.
func remoteOnlyTransport(t *testing.T, raw, third string) string {
	t.Helper()
	out := protoLine.ReplaceAllString(raw, "")
	if out == raw {
		t.Fatalf("generated profile carried no proto directive to remove")
	}
	var b strings.Builder
	replaced := false
	for line := range strings.SplitSeq(out, "\n") {
		if strings.HasPrefix(line, "remote ") && !replaced {
			line = strings.TrimRight(line, " ")
			if third != "" {
				line += " " + third
			}
			replaced = true
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	if !replaced {
		t.Fatal("generated profile carried no remote line")
	}
	return b.String()
}

// TestRemoteProtocolFieldDecidesTheTransport runs the two shapes against a real
// OpenVPN server, differing in the third field of the remote line and in
// nothing else. The negative control is the point: a parser that discards the
// third field dials UDP for both, the server answers with an ICMP
// port-unreachable, and the attempt fails ClassNetwork at reset — which is what
// a dead endpoint looks like from the outside.
func TestRemoteProtocolFieldDecidesTheTransport(t *testing.T) {
	e, ok := testenv.Entry("v24-cbc256-sha256-tlscrypt-tcp")
	if !ok {
		t.Fatal("no entry v24-cbc256-sha256-tlscrypt-tcp")
	}
	srv, err := testenv.StartMatrix(e)
	if err != nil {
		t.Skipf("StartMatrix: %v", err)
	}
	defer srv.Stop() //nolint:errcheck

	raw := srv.ClientProfile()

	for _, tc := range []struct {
		name      string
		third     string
		wantProto profile.Proto
		wantConn  bool
	}{
		{
			name:      "tcp-client in the third field",
			third:     "tcp-client",
			wantProto: profile.ProtoTCP,
			wantConn:  true,
		},
		{
			name:      "no third field falls back to the UDP default",
			third:     "",
			wantProto: profile.ProtoUDP,
			wantConn:  false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := profile.ParseString(remoteOnlyTransport(t, raw, tc.third))
			if err != nil {
				t.Fatalf("ParseString: %v", err)
			}
			if p.Proto != tc.wantProto {
				t.Fatalf("Proto = %v, want %v", p.Proto, tc.wantProto)
			}
			if len(p.Remotes) != 1 {
				t.Fatalf("got %d remotes, want 1", len(p.Remotes))
			}
			if p.Remotes[0].ProtoSet != (tc.third != "") {
				t.Errorf("ProtoSet = %v, want %v", p.Remotes[0].ProtoSet, tc.third != "")
			}

			ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
			defer cancel()
			// The userspace backend, so the run needs no privilege and the
			// data stage is reachable as an ordinary user.
			tun, rep, connErr := netstack.ConnectWithReport(ctx, p, netstack.Options{})
			if tun != nil {
				defer tun.Close() //nolint:errcheck
			}
			t.Logf("%-38s proto=%v connected=%v stage=%s wrap=%s", tc.name, p.Proto,
				rep.Outcome.Succeeded, rep.Outcome.Stage, rep.Negotiated.TLSWrap)

			if tc.wantConn {
				if connErr != nil {
					t.Fatalf("Connect over the remote's own tcp-client: %v", connErr)
				}
				if !rep.Outcome.Succeeded {
					t.Errorf("outcome = %s/%s, want a completed tunnel",
						rep.Outcome.Class, rep.Outcome.Stage)
				}
				if rep.Negotiated.TLSWrap != "tls-crypt" {
					t.Errorf("TLSWrap = %q, want tls-crypt — this entry exists to exercise it",
						rep.Negotiated.TLSWrap)
				}
				if rep.Endpoint.Proto != "tcp" {
					t.Errorf("Endpoint.Proto = %q, want tcp", rep.Endpoint.Proto)
				}
				return
			}

			// The control: dialing UDP at a TCP-only endpoint must fail, and
			// must fail the way the live sweep saw it fail.
			if connErr == nil {
				t.Fatal("Connect over UDP succeeded against a TCP-only server")
			}
			if rep.Outcome.Class != diag.ClassNetwork {
				t.Errorf("class = %s, want %s — the failure the sweep read as a dead endpoint",
					rep.Outcome.Class, diag.ClassNetwork)
			}
		})
	}
}
