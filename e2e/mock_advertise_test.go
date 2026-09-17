// SPDX-License-Identifier: LGPL-2.1-or-later

//go:build mockserver

// What the client advertises, read off the wire and checked against what it
// reports advertising.
//
// The two are computed by different functions — keymethod2.SendAuth is handed
// ivProtoFor(adv), the report's Advertised block comes from advertisedInfo — so
// a session sending IV_PROTO=0 on the wire could report 30.
//
// Run with:
//
//	go test -tags=mockserver ./e2e/ -run TestAdvertisement
package e2e

import (
	"context"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	vpn "github.com/openlawsvpn/go-openlawsvpn"
	"github.com/openlawsvpn/go-openlawsvpn/netstack"
	"github.com/openlawsvpn/go-openlawsvpn/profile"
	"github.com/openlawsvpn/go-openlawsvpn/testenv"
)

// TestAdvertisementOnTheWireMatchesTheReport connects under each
// DataV2Advertisement and checks the IV_PROTO the server received against the
// one the report claims was sent. The mock server logs the client's peer-info
// block verbatim, which is the one reading taken on the far side of the socket.
func TestAdvertisementOnTheWireMatchesTheReport(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("the netstack backend is the point here; re-run as a normal user")
	}

	pki, err := testenv.NewMockPKI(t.TempDir())
	if err != nil {
		t.Fatalf("generate mock PKI: %v", err)
	}

	for _, tc := range []struct {
		name string
		adv  vpn.DataV2Advertisement
		want uint32
	}{
		// 30 is keymethod2.IVProtoImplemented: DATA_V2, REQUEST_PUSH,
		// TLS_KEY_EXPORT and AUTH_PENDING. What this test owns is that the
		// wire and the report agree on whatever it is.
		{"default", 0, 30},
		{"withheld", vpn.WithholdDataV2, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// One server per subtest, so AuthEvents holds exactly the one
			// auth packet this connection sent. Sharing a server would make
			// the assertion depend on event ordering across subtests.
			srv, err := testenv.Start(testenv.Config{
				Binary:      buildMockServer(t),
				CertDir:     pki.Dir,
				NoKeepalive: true,
			})
			if err != nil {
				t.Fatalf("start mock server: %v", err)
			}
			defer func() { _ = srv.Stop() }()

			host, port := splitAddr(t, srv.TCPAddr)
			c := vpn.New(&profile.Profile{
				Remote: host, Port: port, Proto: profile.ProtoTCP, CA: pki.CAPEM,
			})
			c.Device = netstack.NewBackend()
			c.DataV2 = tc.adv
			c.CredentialsFn = func(context.Context) (vpn.Credentials, error) {
				return vpn.Credentials{Username: "mock", Password: "mock"}, nil
			}

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if err := c.Connect(ctx); err != nil {
				t.Fatalf("connect: %v", err)
			}
			defer func() {
				c.Disconnect()        //nolint:errcheck
				c.WaitForDisconnect() //nolint:errcheck
			}()

			auth := srv.AuthEvents()
			if len(auth) != 1 {
				t.Fatalf("server logged %d auth packets, want 1", len(auth))
			}
			onWire, ok := ivProtoFromPeerInfo(auth[0].PeerInfo)
			if !ok {
				t.Fatalf("no IV_PROTO in the peer-info block the server received: %q",
					auth[0].PeerInfo)
			}

			rep := c.Report()
			if rep == nil {
				t.Fatal("Report returned nil")
			}
			reported := rep.Advertised.IVProto

			if onWire != tc.want {
				t.Errorf("IV_PROTO on the wire = %d, want %d", onWire, tc.want)
			}
			// The assertion this test exists for. The two above could both be
			// satisfied by one path while the other lied.
			if reported != onWire {
				t.Errorf("report claims IV_PROTO=%d, the server received %d — "+
					"advertisedInfo and ivProtoFor have diverged, and every consumer of "+
					"the report is now describing a connection that did not happen",
					reported, onWire)
			}
			// The whole block, not just the one field: it is what the report
			// publishes as PeerInfo and it comes from the same second path.
			if got := rep.Advertised.PeerInfo; got != auth[0].PeerInfo {
				t.Errorf("report's peer-info block differs from the one received:\nreport: %q\nwire:   %q",
					got, auth[0].PeerInfo)
			}
		})
	}
}

// ivProtoFromPeerInfo pulls the IV_PROTO value out of a peer-info block of
// newline-separated KEY=VALUE pairs. Parsing it back rather than comparing
// whole strings is what lets the test name the field that disagreed.
func ivProtoFromPeerInfo(block string) (uint32, bool) {
	for line := range strings.SplitSeq(block, "\n") {
		value, found := strings.CutPrefix(strings.TrimSpace(line), "IV_PROTO=")
		if !found {
			continue
		}
		n, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return 0, false
		}
		return uint32(n), true
	}
	return 0, false
}
