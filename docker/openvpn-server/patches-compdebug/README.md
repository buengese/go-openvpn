# Instrumented patch set: compression framing vector capture

Selected with `--build-arg PATCH_DIR=patches-compdebug`, which only
`../build-compdebug.sh` passes. It tags the results
`openlawsvpn-test/openvpn-server:{2.4.12,2.5.11,2.6.22}-compdebug`.

`001-compdebug-framing.patch` instruments one place in `src/openvpn/comp.c`:

- `comp_init()` — after the algorithm's own `compress_init()` runs, the two
  function pointers in the per-context copy of `struct compress_alg` are
  replaced with trampolines that dump the buffer on both sides of the framing:

  ```
  COMPDEBUG <alg> <flags> <compress|decompress> <pre-hex> <post-hex>
  ```

  `<alg>` is OpenVPN's own name for the algorithm (`stub`, `stubv2`, `lzo`,
  `lz4`, `lz4v2`) and `<flags>` is `compctx->flags` as `options.c` computed it,
  so `COMP_F_SWAP` is recorded rather than inferred from the directive.

That is the ground truth behind `internal/compress/testdata/vectors.json`.

Three properties of that choice are the reason it is one hunk rather than eight:

- **One insertion point covers every algorithm.** The dispatch is through
  function pointers, so hooking the pointers reaches `comp-lzo`, `compress`,
  `compress lz4`, `compress lz4-v2` and `compress stub-v2` without touching
  `compstub.c`, `lzo.c` or `comp-lz4.c` at all.
- **One patch covers all three series.** `comp_init()` is byte-identical in
  2.4.12, 2.5.11 and 2.6.22, and so are `struct compress_alg` and
  `struct compress_context`. The patch applies to all three with zero fuzz.
- **Both stages arrive on one line.** The compression layer sees OCC probes,
  keepalive pings and the capture's own packets interleaved; pairing a
  "before" line with the "after" line belonging to it would be a guess.

The originals are kept in a table keyed on `alg.name`, which the hook does not
overwrite, so a process that ends up with two different algorithms still
dispatches each context to its own implementation.

**Never build this into a stock matrix tag.** An image built from this set
prints every tunnelled IP packet in the clear into its container log, and those
logs are captured and printed on failure by the matrix tests.

Full procedure: [`../../COMPRESSION-VECTORS.md`](../../COMPRESSION-VECTORS.md).
