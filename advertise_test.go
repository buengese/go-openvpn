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

	"github.com/buengese/go-openvpn/internal/crypto"
	"github.com/buengese/go-openvpn/internal/datachannel"
	"github.com/buengese/go-openvpn/internal/keymethod2"
	"github.com/buengese/go-openvpn/profile"
	"github.com/buengese/go-openvpn/routing"
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
	def := peerInfoFor(AdvertiseDataV2)
	if def != peerInfo {
		t.Error("the default advertisement is not the block every other reader sees")
	}
	if got := ivProtoFromPeerInfo(t, def); got != keymethod2.IVProtoImplemented {
		t.Errorf("IV_PROTO = %d, want %d", got, keymethod2.IVProtoImplemented)
	}

	params, _, err := datachannel.ResolveParams("AES-256-GCM", "")
	if err != nil {
		t.Fatalf("datachannel.ResolveParams: %v", err)
	}
	adv := advertisedInfo(profile.ProtoTCP, 1500, params, AdvertiseDataV2)
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

// TestWithholdDataV2AdvertisesNoExtensions covers the lever: it sends
// IV_PROTO=0 rather than 30-minus-the-bit, because 2.4 and 2.5 push a peer-id
// whenever the *value* is 2 or more however the DATA_V2 bit is set. Nothing
// else in the block may move — a lost IV_CIPHERS would make the isolate measure
// a cipher failure instead of a wire format.
func TestWithholdDataV2AdvertisesNoExtensions(t *testing.T) {
	def := peerInfoFor(AdvertiseDataV2)
	withheld := peerInfoFor(WithholdDataV2)

	got := ivProtoFromPeerInfo(t, withheld)
	if got != keymethod2.IVProtoNoExtensions {
		t.Errorf("IV_PROTO = %d, want %d", got, keymethod2.IVProtoNoExtensions)
	}
	if got >= 2 {
		t.Errorf("IV_PROTO = %d, which push.c:prepare_push_reply answers with a peer-id "+
			"on 2.4 and 2.5 however the DATA_V2 bit is set", got)
	}
	if got&keymethod2.IVProtoDataV2 != 0 {
		t.Error("IV_PROTO_DATA_V2 is still claimed, so 2.6 would assign a peer-id too")
	}

	// The rest of the block is untouched: same lines, one value different.
	if strings.Count(withheld, "\n") != strings.Count(def, "\n") {
		t.Error("the withheld block has a different number of lines")
	}
	if !strings.Contains(withheld, "IV_CIPHERS=") {
		t.Error("the withheld block lost IV_CIPHERS")
	}
	if !strings.Contains(withheld, "IV_NCP=2") {
		t.Error("the withheld block lost IV_NCP, which is what carries cipher negotiation")
	}
}

// TestWithholdDataV2IsReportedAsSent keeps the report honest about the
// advertisement it went out with. A report showing the default block beside a
// P_DATA_V1 connection would describe a server that does not exist.
func TestWithholdDataV2IsReportedAsSent(t *testing.T) {
	params, _, err := datachannel.ResolveParams("AES-256-CBC", "SHA256")
	if err != nil {
		t.Fatalf("datachannel.ResolveParams: %v", err)
	}
	adv := advertisedInfo(profile.ProtoUDP, 1500, params, WithholdDataV2)
	if adv.IVProto != keymethod2.IVProtoNoExtensions {
		t.Errorf("reported IV_PROTO = %d, want %d", adv.IVProto, keymethod2.IVProtoNoExtensions)
	}
	if adv.PeerInfo != peerInfoFor(WithholdDataV2) {
		t.Error("the reported peer-info block is not the one that was sent")
	}
}

// ---- what is deliberately not advertised -----------------------------------

// TestExitNotifyIsNotOnTheControlChannelAdvertisement guards the constraint the
// implementation rests on: the older OCC form is used *because* IV_PROTO does
// not claim CC_EXIT_NOTIFY. Adding bit 7 (128) to the advertisement would let a
// server select the control-channel form and stop reading the OCC message,
// while the teardown still looked clean.
func TestExitNotifyIsNotOnTheControlChannelAdvertisement(t *testing.T) {
	const ivProtoCCExitNotify = 1 << 7

	advertised := ivProtoFromPeerInfo(t, peerInfo)
	if advertised&ivProtoCCExitNotify != 0 {
		t.Fatalf("IV_PROTO=%d sets CC_EXIT_NOTIFY (%d): a server may select the "+
			"control-channel exit form, which this client does not implement, and "+
			"stop acting on sendExitNotify's OCC message",
			advertised, ivProtoCCExitNotify)
	}
}

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

// ivProtoFromPeerInfo reads IV_PROTO out of a rendered peer-info block, which
// is where a server reads it from too.
func ivProtoFromPeerInfo(t *testing.T, block string) uint32 {
	t.Helper()
	for line := range strings.SplitSeq(block, "\n") {
		if after, ok := strings.CutPrefix(line, "IV_PROTO="); ok {
			var v uint32
			for _, r := range after {
				if r < '0' || r > '9' {
					t.Fatalf("IV_PROTO is not a number: %q", after)
				}
				v = v*10 + uint32(r-'0')
			}
			return v
		}
	}
	t.Fatal("peer-info block carries no IV_PROTO line")
	return 0
}
