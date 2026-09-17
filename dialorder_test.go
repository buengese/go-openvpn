// SPDX-License-Identifier: LGPL-2.1-or-later

package vpn

import (
	"testing"

	"github.com/openlawsvpn/go-openlawsvpn/profile"
)

// remoteShapes are the ways a profile can name its endpoints. The dial order is
// a function of these and of nothing else, so they are written here rather than
// read off a directory: a file on disk would prove the same thing and hide what
// is being varied.
var remoteShapes = []struct {
	name string
	body string
}{
	{"one remote", "remote vpn.example.test 1194\n"},
	{"several remotes", "remote vpn1.example.test 1194\nremote vpn2.example.test 1194\n" +
		"remote vpn3.example.test 443\n"},
	{"a transport on each remote", "remote vpn1.example.test 1194 udp\n" +
		"remote vpn2.example.test 443 tcp-client\n"},
	{"an address rather than a name", "remote 203.0.113.9 1194\n"},
	// remote-random with somewhere to shuffle to, and without. The second is
	// the common shape and the one where a shuffle would be unobservable.
	{"shuffled, several remotes", "remote vpn1.example.test 1194\nremote vpn2.example.test 1194\n" +
		"remote vpn3.example.test 1194\nremote-random\n"},
	{"shuffled, one remote", "remote vpn.example.test 1194\nremote-random\n"},
}

// TestDialOrderReachesEveryRemote is the check on failover: whatever a profile
// says, the loop reaches every endpoint it names, exactly once, and a profile
// that did not ask to be shuffled is dialed in the order it was written.
//
// It asserts the client's dial order rather than the parser's list. profile's
// own suite proves the remotes survive parsing; this proves they are dialed.
func TestDialOrderReachesEveryRemote(t *testing.T) {
	for _, tt := range remoteShapes {
		t.Run(tt.name, func(t *testing.T) {
			p, err := profile.ParseString("client\ndev tun\n" + tt.body)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			order := New(p).dialOrder()
			if len(order) != len(p.Remotes) {
				t.Fatalf("dial order has %d targets for %d remotes; failover must reach every one",
					len(order), len(p.Remotes))
			}

			// A permutation of the profile's remotes: a shuffle that dropped
			// an endpoint would be worse than no shuffle.
			seen := map[profile.Remote]int{}
			for _, target := range order {
				seen[target.Remote]++
				if target.Index < 0 || target.Index >= len(p.Remotes) {
					t.Errorf("dial target index %d is outside the profile's %d remotes",
						target.Index, len(p.Remotes))
				}
			}
			for _, rem := range p.Remotes {
				if seen[rem] != 1 {
					t.Errorf("a remote in the profile is dialed %d times", seen[rem])
				}
			}

			if p.RemoteRandom {
				return
			}
			// No shuffle was asked for, so file order is what is dialed.
			for i, target := range order {
				if target.Index != i {
					t.Errorf("remote %d is dialed at position %d without --remote-random",
						target.Index, i)
					break
				}
			}
		})
	}
}
