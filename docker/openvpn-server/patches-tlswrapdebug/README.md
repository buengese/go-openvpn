# Instrumented patch set: control-channel wrap vector capture

Selected with `--build-arg PATCH_DIR=patches-tlswrapdebug`, which only
`../build-tlswrapdebug.sh` passes. It tags the result
`openlawsvpn-test/openvpn-server:2.4.12-tlswrapdebug`.

`001-tlswrapdebug-control-channel.patch` instruments two places in OpenVPN
2.4.12:

- `write_control_auth()` in `src/openvpn/ssl.c` — every outgoing control packet
  is dumped at each stage of the wrap. For `tls-auth` that is `plain`
  (unwrapped), `preswap` (what `openvpn_encrypt()` produced, whose tail past
  the HMAC is exactly the byte string that was HMAC'd) and `wire`. For
  `tls-crypt` it is `plainhdr`, `plainbody` and `wire`.
- `init_key_ctx()` in `src/openvpn/crypto.c` — the cipher and HMAC key bytes
  actually installed into each direction's context, tagged with the log prefix
  that names it (`Outgoing`/`Incoming Control Channel Authentication` for
  `--tls-auth`, `… Encryption` for `--tls-crypt`). The capture locates those
  bytes inside the 256-byte static key rather than assuming an offset, so the
  key-direction mapping is measured.

That is the ground truth behind `internal/wrap/testdata/vectors.json`.

**Never build this into the stock matrix tag.** An image built from this set
prints the control-channel key material and every control packet in the clear
into its container log, and those logs are captured and printed on failure by
the matrix tests. It also prints the *data*-channel keys, because
`init_key_ctx()` is shared.

The patch is written against OpenVPN 2.4.12 and used only there.
`write_control_auth()` grew a `tls_wrap_ctx` indirection and `tls-crypt-v2`
handling after 2.4, so 2.5/2.6 would need a rewrite in a patch directory of
their own — the wire formats these vectors record are unchanged across 2.4–2.6,
which is why one series is enough.

Full procedure: [`../../TLS-WRAP-VECTORS.md`](../../TLS-WRAP-VECTORS.md).
