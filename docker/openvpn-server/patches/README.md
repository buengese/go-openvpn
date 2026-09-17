# OpenVPN source patches

Every `*.patch` in this directory is applied with `patch -p1` to the unpacked
OpenVPN release tarball during the image build, before `./configure`, for
whichever directory the `PATCH_DIR` build arg names.

**This directory stays empty on purpose.** `PATCH_DIR` defaults to it, so the
matrix images `build.sh` produces — the ones `testenv.StartMatrix` resolves —
are stock upstream builds.

The key-derivation capture landed its `generate_key_expansion()`
instrumentation in a *sibling* directory, `../patches-prfdebug/`, selected with `--build-arg
PATCH_DIR=patches-prfdebug` and tagged `:2.4.12-prfdebug`. That patch makes
every handshake print the 256-byte data-channel key block into the container
log; applying it here would have made the whole matrix leak key material into
the logs that tests capture and print on failure. See
[`../../PRF-VECTORS.md`](../../PRF-VECTORS.md).

The control-channel wrap capture did the same in
`../patches-tlswrapdebug/`, tagged `:2.4.12-tlswrapdebug`. It prints the
`tls-auth`/`tls-crypt` key material and every control packet, plain and
wrapped. See [`../../TLS-WRAP-VECTORS.md`](../../TLS-WRAP-VECTORS.md).

The compression-framing capture did it again for the data channel in
`../patches-compdebug/`, tagged `:{2.4.12,2.5.11,2.6.22}-compdebug`. It prints
every tunnelled IP packet in the clear, on both sides of the framing. It is the
first of the three to be built for all three series, because the framing a peer
sends depends on its version as much as on its directive. See
[`../../COMPRESSION-VECTORS.md`](../../COMPRESSION-VECTORS.md).

Keeping patches in-tree rather than applying them by hand is what makes a
capture reproducible: rebuilding from a clean checkout reproduces the same
instrumented server.

Rules:

- One concern per patch; name it `NNN-what-it-does.patch` so the apply order is
  obvious (the shell glob sorts lexically).
- Patches must apply cleanly to **every** pinned series they are used with. The
  three series are built from the same Dockerfile, so a patch that only applies
  to 2.4 must live in its own `patches-*` directory and be built with an image
  tag of its own. That is what `patches-prfdebug/` and `patches-tlswrapdebug/`
  are. `patches-compdebug/` is the other case: it is used with all three, and it
  applies to all three with zero fuzz because `comp_init()` did not change.
- `patch -p1 --batch --forward` is used, so a patch that is already applied is
  skipped rather than prompting, but a patch that does not apply fails the
  build. That is intentional: a silently unpatched image would produce vectors
  that look valid and are not.

After adding a patch, rebuild with `make matrix-images` (or, for an alternate
set, the script that passes its `PATCH_DIR`) — Docker layer caching keys on the
patch-directory copy, so the source download is reused and only the compile
re-runs.
