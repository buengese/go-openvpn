# Instrumented patch set: PRF known-answer vector capture

Selected with `--build-arg PATCH_DIR=patches-prfdebug`, which only
`../build-prfdebug.sh` passes. It tags the result
`openlawsvpn-test/openvpn-server:2.4.12-prfdebug`.

`001-prfdebug-key-expansion.patch` instruments `generate_key_expansion()` in
`src/openvpn/ssl.c` so that every derivation prints, in hex, both peers' key
material, both session IDs, the 48-byte master secret and the 256-byte key
block. That is the ground truth behind `internal/prf/testdata/vectors.json`.

**Never build this into the stock matrix tag.** An image built from this set
prints data-channel keys into its container log on every handshake, and those
logs are captured and printed on failure by the matrix tests.

The patch is written against OpenVPN 2.4.12 and used only there;
`generate_key_expansion()` changed after 2.4, so 2.5/2.6 would need a rewrite in
a patch directory of their own.

Full procedure: [`../../PRF-VECTORS.md`](../../PRF-VECTORS.md).
