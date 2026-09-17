// SPDX-License-Identifier: LGPL-2.1-or-later
//
// advertise.go: what the client advertises about itself to the server.

package vpn

import (
	"github.com/openlawsvpn/go-openlawsvpn/internal/datachannel"
	"github.com/openlawsvpn/go-openlawsvpn/internal/keymethod2"
	"github.com/openlawsvpn/go-openlawsvpn/profile"
)

// peerInfo is the IV_* capability advertisement a normal connection sends. It
// is rendered once, so the block every reader of this variable sees is the one
// that goes on the wire. What the bits mean, and the rule that IV_PROTO may
// advertise only implemented features, are on keymethod2.PeerInfo.
var peerInfo = keymethod2.PeerInfo(keymethod2.IVProtoImplemented)

// tunnelParams renders the negotiated data-channel parameters as the plain
// values the options string is built from. keymethod2 takes values rather than
// datachannel.Params so that the wire format does not depend on the cipher
// table; this is the one place the two meet, and the [null-digest] rule lives
// on the keymethod2 side.
func tunnelParams(proto profile.Proto, tunMTU int, params datachannel.Params) keymethod2.TunnelParams {
	tp := keymethod2.TunnelParams{
		Proto:       proto,
		TunMTU:      tunMTU,
		CipherName:  params.Spec.Name,
		KeySizeBits: params.Spec.KeyLen * 8,
	}
	if params.Spec.UsesDigest() {
		tp.AuthName = params.Digest.String()
	}
	return tp
}
