// SPDX-License-Identifier: LGPL-2.1-or-later

// Say only what we can do.
//
// A server acts on both of the things the client tells it about itself: it
// selects a cipher from the advertised IV_CIPHERS list and then speaks it, and
// it checks the options string against its own configuration.

package vpn

import (
	"fmt"
	"strings"
	"testing"

	"github.com/openlawsvpn/go-openlawsvpn/internal/crypto"
	"github.com/openlawsvpn/go-openlawsvpn/internal/datachannel"
	"github.com/openlawsvpn/go-openlawsvpn/internal/keymethod2"
	"github.com/openlawsvpn/go-openlawsvpn/profile"
	"github.com/openlawsvpn/go-openlawsvpn/routing"
)

// TestIVCiphersIsHonest keeps the advertised cipher list to ciphers this client
// can actually speak: a server selects from IV_CIPHERS and then speaks what it
// selected, so a name with no implementation behind it is a connection that
// handshakes and then carries nothing.
func TestIVCiphersIsHonest(t *testing.T) {
	// Derived rather than transcribed: a hand-written copy that happens to
	// agree with the table today is not the same property.
	t.Run("generated from the cipher table", func(t *testing.T) {
		got := ivCiphersFromPeerInfo(t)
		want := crypto.CipherNames()
		if len(got) != len(want) {
			t.Fatalf("IV_CIPHERS has %d entries, the cipher table has %d:\n got %v\nwant %v",
				len(got), len(want), got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("IV_CIPHERS[%d] = %q, table has %q", i, got[i], want[i])
			}
		}
	})

	t.Run("every entry builds a data channel", func(t *testing.T) {
		advertised := ivCiphersFromPeerInfo(t)
		if len(advertised) == 0 {
			t.Fatal("peerInfo advertises no ciphers")
		}
		for _, name := range advertised {
			spec, ok := crypto.LookupCipher(name)
			if !ok {
				t.Errorf("IV_CIPHERS advertises %q, which the cipher table cannot construct", name)
				continue
			}
			// Constructible in name is not enough: build one.
			params, feature, err := datachannel.ResolveParams(name, "SHA256")
			if err != nil {
				t.Errorf("IV_CIPHERS advertises %q but datachannel.ResolveParams fails (%s): %v",
					name, feature, err)
				continue
			}
			if _, err := params.NewChannel(7, 0, make([]byte, 256)); err != nil {
				t.Errorf("IV_CIPHERS advertises %q (keylen %d) but the channel will not build: %v",
					name, spec.KeyLen, err)
			}
		}
	})

	// The one exclusion worth naming. CHACHA20-POLY1305 is out of scope and
	// would pass the two subtests above the day someone adds a table entry
	// for it without an implementation.
	t.Run("chacha is not advertised", func(t *testing.T) {
		for _, name := range ivCiphersFromPeerInfo(t) {
			if strings.Contains(strings.ToUpper(name), "CHACHA") {
				t.Errorf("IV_CIPHERS advertises %q, which is out of scope and unimplemented", name)
			}
		}
	})
}

// TestTunnelOptionsNameTheRealCipherAndDigest covers the options string for
// each cipher shape. keysize is in bits and follows the cipher's key length; an
// AEAD cipher reports auth as [null-digest] because it authenticates its own
// output, and a CBC cipher names the digest that will really compute its tags.
func TestTunnelOptionsNameTheRealCipherAndDigest(t *testing.T) {
	for _, tc := range []struct {
		name         string
		cipher       string
		digest       string
		wantCipher   string
		wantAuth     string
		wantKeysize  int
		wantProtoStr string
	}{
		{"gcm256 default digest", "AES-256-GCM", "", "AES-256-GCM", "[null-digest]", 256, "UDPv4"},
		{"gcm128", "AES-128-GCM", "SHA256", "AES-128-GCM", "[null-digest]", 128, "UDPv4"},
		{"cbc256 sha512", "AES-256-CBC", "SHA512", "AES-256-CBC", "SHA512", 256, "UDPv4"},
		{"cbc128 sha1", "AES-128-CBC", "SHA1", "AES-128-CBC", "SHA1", 128, "UDPv4"},
		// A CBC profile with no auth directive. The parser supplies OpenVPN's
		// SHA1 default, and the advertisement has to say SHA1 or the server
		// agrees to something else.
		{"cbc256 implied sha1", "AES-256-CBC", "", "AES-256-CBC", "SHA1", 256, "UDPv4"},
		{"cbc192 sha256", "AES-192-CBC", "SHA256", "AES-192-CBC", "SHA256", 192, "UDPv4"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			params, feature, err := datachannel.ResolveParams(tc.cipher, tc.digest)
			if err != nil {
				t.Fatalf("datachannel.ResolveParams(%q, %q): %s: %v", tc.cipher, tc.digest, feature, err)
			}
			got := keymethod2.TunnelOptions(tunnelParams(profile.ProtoUDP, 1500, params))
			for _, want := range []string{
				"cipher " + tc.wantCipher,
				"auth " + tc.wantAuth,
				fmt.Sprintf("keysize %d", tc.wantKeysize),
				"proto " + tc.wantProtoStr,
				"key-method 2",
				"tls-client",
			} {
				if !strings.Contains(got, want) {
					t.Errorf("options string %q does not contain %q", got, want)
				}
			}
		})
	}
}

func TestBuildTunnelOptionsUsesConfiguredMTU(t *testing.T) {
	tests := []struct {
		name  string
		proto profile.Proto
		mtu   int
		want  string
	}{
		{
			name:  "udp",
			proto: profile.ProtoUDP,
			mtu:   1400,
			want:  "link-mtu 1421,tun-mtu 1400,proto UDPv4",
		},
		{
			name:  "tcp",
			proto: profile.ProtoTCP,
			mtu:   1400,
			want:  "link-mtu 1443,tun-mtu 1400,proto TCPv4_CLIENT",
		},
		{
			name:  "default",
			proto: profile.ProtoUDP,
			mtu:   0,
			want:  "link-mtu 1521,tun-mtu 1500,proto UDPv4",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params, _, err := datachannel.ResolveParams("AES-256-GCM", "")
			if err != nil {
				t.Fatalf("datachannel.ResolveParams: %v", err)
			}
			if got := keymethod2.TunnelOptions(tunnelParams(tt.proto, tt.mtu, params)); !strings.Contains(got, tt.want) {
				t.Errorf("keymethod2.TunnelOptions(%v, %d) = %q, want substring %q", tt.proto, tt.mtu, got, tt.want)
			}
		})
	}
}

// TestAdvertisedOptionsFollowTheProfile is the same property one level up: the
// string a real client sends is built from its own profile, not from a
// constant.
func TestAdvertisedOptionsFollowTheProfile(t *testing.T) {
	for _, tc := range []struct{ cipher, auth, wantCipher, wantAuth string }{
		{"AES-256-GCM", "SHA256", "AES-256-GCM", "[null-digest]"},
		{"AES-256-CBC", "SHA512", "AES-256-CBC", "SHA512"},
		{"AES-128-CBC", "SHA1", "AES-128-CBC", "SHA1"},
	} {
		t.Run(tc.cipher+"/"+tc.auth, func(t *testing.T) {
			c := New(&profile.Profile{
				Remote: "vpn.example.com", Port: 1194, Proto: profile.ProtoUDP,
				Cipher: tc.cipher, Auth: tc.auth, AuthSet: true, CA: testCAPEM(t),
			})
			got := keymethod2.TunnelOptions(tunnelParams(c.prof.Proto, c.prof.TunMTU, c.advertisedDataChannel()))
			if !strings.Contains(got, "cipher "+tc.wantCipher) {
				t.Errorf("options %q does not name cipher %q", got, tc.wantCipher)
			}
			if !strings.Contains(got, "auth "+tc.wantAuth) {
				t.Errorf("options %q does not name auth %q", got, tc.wantAuth)
			}
		})
	}
}

// TestAdvertisedOptionsSurviveAnUnsupportedCipher pins the fallback: a profile
// naming a cipher the table has no entry for still produces a well-formed
// advertisement, because refusing here would fail the attempt at StageAuth. The
// refusal belongs at StageKeys, with ClassUnsupported naming the cipher.
func TestAdvertisedOptionsSurviveAnUnsupportedCipher(t *testing.T) {
	c := New(&profile.Profile{
		Remote: "vpn.example.com", Port: 1194, Proto: profile.ProtoUDP,
		Cipher: "BF-CBC", Auth: "SHA1", AuthSet: true, CA: testCAPEM(t),
	})
	got := keymethod2.TunnelOptions(tunnelParams(c.prof.Proto, c.prof.TunMTU, c.advertisedDataChannel()))
	if !strings.Contains(got, "cipher AES-256-GCM") {
		t.Errorf("options %q did not fall back to the default cipher", got)
	}

	// And the refusal does happen, at the right stage, naming the cipher.
	_, feature, err := c.negotiateDataChannel(&routing.PushOptions{})
	if err == nil {
		t.Fatal("an unsupported profile cipher was accepted")
	}
	if feature != "cipher BF-CBC" {
		t.Errorf("feature = %q, want %q", feature, "cipher BF-CBC")
	}
}

// TestPushedValuesOutrankTheProfile covers the NCP direction: whatever the
// profile asked for, the server's PUSH_REPLY decides.
func TestPushedValuesOutrankTheProfile(t *testing.T) {
	c := New(&profile.Profile{
		Remote: "vpn.example.com", Port: 1194,
		Cipher: "AES-256-GCM", Auth: "SHA256", AuthSet: true, CA: testCAPEM(t),
	})
	params, feature, err := c.negotiateDataChannel(&routing.PushOptions{
		Cipher: "AES-128-CBC", Auth: "SHA512",
	})
	if err != nil {
		t.Fatalf("%s: %v", feature, err)
	}
	if params.Spec.Name != "AES-128-CBC" {
		t.Errorf("cipher = %q, want the pushed AES-128-CBC", params.Spec.Name)
	}
	if params.Digest != crypto.DigestSHA512 {
		t.Errorf("digest = %v, want the pushed SHA512", params.Digest)
	}
}

// ---- what the report says was advertised ----------------------------------

// TestAdvertisedInfoMatchesPeerInfo checks that the advertised block the report
// carries is the one actually sent, and that the default advertisement is the
// block every other reader sees.
func TestAdvertisedInfoMatchesPeerInfo(t *testing.T) {
	params, _, err := datachannel.ResolveParams("AES-256-GCM", "")
	if err != nil {
		t.Fatalf("datachannel.ResolveParams: %v", err)
	}
	adv := advertisedInfo(profile.ProtoTCP, 1500, params)
	if adv.IVProto != 30 {
		t.Errorf("IV_PROTO: got %d, want 30", adv.IVProto)
	}
	if !strings.Contains(adv.IVCiphers, "AES-256-GCM") {
		t.Errorf("IV_CIPHERS: got %q", adv.IVCiphers)
	}
	if adv.PeerInfo != peerInfo {
		t.Error("PeerInfo does not match the constant that is sent")
	}
	if adv.Options != keymethod2.TunnelOptions(tunnelParams(profile.ProtoTCP, 1500, params)) {
		t.Error("Options does not match the string that is sent")
	}
}

// ---- what is deliberately not advertised -----------------------------------

// ivCiphersFromPeerInfo pulls the advertised cipher list out of the peer-info
// block that is actually sent, rather than out of the table it is built from.
func ivCiphersFromPeerInfo(t *testing.T) []string {
	t.Helper()
	for line := range strings.SplitSeq(peerInfo, "\n") {
		if after, ok := strings.CutPrefix(line, "IV_CIPHERS="); ok {
			return strings.Split(after, ":")
		}
	}
	t.Fatal("peerInfo carries no IV_CIPHERS line")
	return nil
}
