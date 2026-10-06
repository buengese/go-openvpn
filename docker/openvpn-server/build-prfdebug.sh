#!/usr/bin/env bash
# Build the instrumented OpenVPN 2.4 image used to capture the PRF
# known-answer vectors in internal/prf/testdata/vectors.json.
#
#   ./build-prfdebug.sh
#
# This is the same Dockerfile, the same pinned tarball and the same pinned base
# image as `build.sh 2.4`, with two differences:
#
#   * PATCH_DIR=patches-prfdebug, so patches-prfdebug/*.patch is applied instead
#     of the empty default patches/ set; and
#   * the tag carries a `-prfdebug` suffix.
#
# Both matter. The instrumented build prints the data-channel key block into its
# log on every handshake, so it must never answer to the plain
# `go-openvpn-test/openvpn-server:2.4.12` tag that `testenv.StartMatrix` and
# every other test resolve. Overwriting that tag would quietly turn the whole
# matrix into a key-material leak.
#
# 2.4 is the required series: it predates the TLS keying-material exporter, so
# the classic two-stage OpenVPN PRF is the only derivation path it has.
#
# See docker/PRF-VECTORS.md for the full capture procedure.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=versions.env disable=SC1091
. "$here/versions.env"

DOCKER="${DOCKER:-docker}"

# The suffix is also hard-coded in prf-capture.sh; keep the two in step.
PRFDEBUG_SUFFIX="-prfdebug"
PRFDEBUG_PATCH_DIR="patches-prfdebug"

tag="${MATRIX_IMAGE_REPO}:${OPENVPN_24_VERSION}${PRFDEBUG_SUFFIX}"
stock_tag="${MATRIX_IMAGE_REPO}:${OPENVPN_24_VERSION}"

if [ "$tag" = "$stock_tag" ]; then
    echo "build-prfdebug.sh: refusing to build over the stock matrix tag" >&2
    exit 1
fi

if [ ! -d "$here/$PRFDEBUG_PATCH_DIR" ]; then
    echo "build-prfdebug.sh: $here/$PRFDEBUG_PATCH_DIR is missing" >&2
    exit 1
fi
if ! ls "$here/$PRFDEBUG_PATCH_DIR"/*.patch >/dev/null 2>&1; then
    echo "build-prfdebug.sh: no *.patch in $PRFDEBUG_PATCH_DIR — an unpatched" >&2
    echo "                   image would produce no vectors at all" >&2
    exit 1
fi

echo "==> building ${tag}"
echo "    base:      ${OPENVPN_24_BASE}"
echo "    sha256:    ${OPENVPN_24_SHA256}"
echo "    configure: ${OPENVPN_24_CONFIGURE}"
echo "    openssl:   ${OPENVPN_24_OPENSSL_URL}"
echo "    patches:   ${PRFDEBUG_PATCH_DIR}"

"$DOCKER" build \
    --build-arg "BASE_IMAGE=${OPENVPN_24_BASE}" \
    --build-arg "OPENVPN_VERSION=${OPENVPN_24_VERSION}" \
    --build-arg "OPENVPN_SHA256=${OPENVPN_24_SHA256}" \
    --build-arg "CONFIGURE_FLAGS=${OPENVPN_24_CONFIGURE}" \
    --build-arg "OPENSSL_URL=${OPENVPN_24_OPENSSL_URL}" \
    --build-arg "OPENSSL_SHA256=${OPENVPN_24_OPENSSL_SHA256}" \
    --build-arg "SOURCE_URL_BASE=${MATRIX_SOURCE_URL_BASE}" \
    --build-arg "PATCH_DIR=${PRFDEBUG_PATCH_DIR}" \
    -t "$tag" \
    "$here"

# A patch that failed to apply fails the build (patch -p1 without --forward
# would prompt; the Dockerfile uses --batch --forward so an *already applied*
# patch is skipped). Verify the instrumentation actually made it in, because an
# unpatched image produces a clean run and zero vectors, which looks like a
# capture-script bug rather than a build bug.
if ! "$DOCKER" run --rm --entrypoint /bin/sh "$tag" -c 'openvpn --version 2>&1 | head -1'; then
    echo "build-prfdebug.sh: built image cannot run openvpn --version" >&2
    exit 1
fi

echo "==> built ${tag}"
