# OpenVPN source patches

Every `*.patch` in this directory is applied with `patch -p1` to the unpacked
OpenVPN release tarball during the image build, before `./configure`, for
whichever directory the `PATCH_DIR` build arg names.

**This directory stays empty on purpose.** `PATCH_DIR` defaults to it, so the
matrix images `build.sh` produces — the ones `testenv.StartMatrix` resolves —
are stock upstream builds.

Keeping patches in-tree rather than applying them by hand is what makes a
capture reproducible: rebuilding from a clean checkout reproduces the same
instrumented server.

Rules:

- One concern per patch; name it `NNN-what-it-does.patch` so the apply order is
  obvious (the shell glob sorts lexically).
- Patches must apply cleanly to **every** pinned series they are used with. The
  three series are built from the same Dockerfile, so a patch that only applies
  to 2.4 must live in its own `patches-*` directory and be built with an image
  tag of its own.
- `patch -p1 --batch --forward` is used, so a patch that is already applied is
  skipped rather than prompting, but a patch that does not apply fails the
  build. That is intentional: a silently unpatched image would produce vectors
  that look valid and are not.

After adding a patch, rebuild with `make matrix-images` (or, for an alternate
set, the script that passes its `PATCH_DIR`) — Docker layer caching keys on the
patch-directory copy, so the source download is reused and only the compile
re-runs.
