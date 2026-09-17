#!/usr/bin/env bash
# Build the instrumented OpenVPN images used to capture the compression framing
# known-answer vectors in internal/compress/testdata/vectors.json.
#
#   ./build-compdebug.sh            # build 2.4, 2.5 and 2.6
#   ./build-compdebug.sh 2.4        # build only the named series
#
# These are the same Dockerfile, the same pinned tarballs (SHA-256 verified)
# and the same pinned base images as `build.sh`, with two differences:
#
#   * PATCH_DIR=patches-compdebug, so patches-compdebug/*.patch is applied
#     instead of the empty default patches/ set; and
#   * every tag carries a `-compdebug` suffix.
#
# Both matter. The instrumented build prints every tunnelled IP packet in the
# clear on both sides of the compression framing, into its container log. It
# must never answer to the plain `openlawsvpn-test/openvpn-server:<ver>` tags
# that `testenv.StartMatrix` and every other test resolve. Overwriting one of
# those would quietly turn the whole matrix into a plaintext traffic leak.
#
# Unlike the tls-wrap capture, this one needs all three series. The framing a
# peer sends is a property of its OpenVPN version as much as of its directive:
# 2.4 compresses by default and 2.5/2.6 do not, and `comp-lzo` is refused
# outright by 2.6. One series would have measured one third of the answer.
# The patch itself is series-agnostic — comp_init() is byte-identical across
# 2.4.12, 2.5.11 and 2.6.22 — so a single patch directory covers all three.
#
# See docker/COMPRESSION-VECTORS.md for the full capture procedure.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=versions.env disable=SC1091
. "$here/versions.env"

DOCKER="${DOCKER:-docker}"

# The suffix is also hard-coded in comp-capture.sh; keep the two in step.
COMPDEBUG_SUFFIX="-compdebug"
COMPDEBUG_PATCH_DIR="patches-compdebug"

# The format string the instrumentation emits. Grepped out of the built binary
# below, because an unpatched image completes handshakes perfectly and prints
# nothing, which looks like a capture-script bug rather than a build bug.
COMPDEBUG_MARKER='COMPDEBUG %s %u %s %s %s'

if [ ! -d "$here/$COMPDEBUG_PATCH_DIR" ]; then
    echo "build-compdebug.sh: $here/$COMPDEBUG_PATCH_DIR is missing" >&2
    exit 1
fi
if ! ls "$here/$COMPDEBUG_PATCH_DIR"/*.patch >/dev/null 2>&1; then
    echo "build-compdebug.sh: no *.patch in $COMPDEBUG_PATCH_DIR — an" >&2
    echo "                    unpatched image would produce no vectors at all" >&2
    exit 1
fi

series_list=("$@")
if [ ${#series_list[@]} -eq 0 ]; then
    series_list=(2.4 2.5 2.6)
fi

build_one() {
    local series="$1"
    local key version sha base flags tag stock_tag

    key="${series//./}"
    eval "version=\${OPENVPN_${key}_VERSION:-}"
    eval "sha=\${OPENVPN_${key}_SHA256:-}"
    eval "base=\${OPENVPN_${key}_BASE:-}"
    eval "flags=\${OPENVPN_${key}_CONFIGURE:-}"

    if [ -z "$version" ]; then
        echo "build-compdebug.sh: unknown OpenVPN series '$series' (no OPENVPN_${key}_VERSION in versions.env)" >&2
        return 1
    fi

    tag="${MATRIX_IMAGE_REPO}:${version}${COMPDEBUG_SUFFIX}"
    stock_tag="${MATRIX_IMAGE_REPO}:${version}"

    if [ "$tag" = "$stock_tag" ]; then
        echo "build-compdebug.sh: refusing to build over the stock matrix tag" >&2
        return 1
    fi

    echo "==> building ${tag}"
    echo "    base:      ${base}"
    echo "    sha256:    ${sha}"
    echo "    configure: ${flags}"
    echo "    patches:   ${COMPDEBUG_PATCH_DIR}"

    "$DOCKER" build \
        --build-arg "BASE_IMAGE=${base}" \
        --build-arg "OPENVPN_VERSION=${version}" \
        --build-arg "OPENVPN_SHA256=${sha}" \
        --build-arg "CONFIGURE_FLAGS=${flags}" \
        --build-arg "SOURCE_URL_BASE=${MATRIX_SOURCE_URL_BASE}" \
        --build-arg "PATCH_DIR=${COMPDEBUG_PATCH_DIR}" \
        -t "$tag" \
        "$here"

    # A patch that fails to apply fails the build (the Dockerfile uses
    # `patch --batch --forward`, so an already-applied patch is skipped rather
    # than prompting). Verify the instrumentation actually made it in.
    if ! "$DOCKER" run --rm --entrypoint /bin/sh "$tag" \
            -c "grep -qa '${COMPDEBUG_MARKER}' /usr/sbin/openvpn"; then
        echo "build-compdebug.sh: built image ${tag} carries no COMPDEBUG format" >&2
        echo "                    string — the patch did not take" >&2
        return 1
    fi

    if ! "$DOCKER" run --rm --entrypoint /bin/sh "$tag" -c 'openvpn --version 2>&1 | head -1'; then
        echo "build-compdebug.sh: built image ${tag} cannot run openvpn --version" >&2
        return 1
    fi

    echo "==> built ${tag}"
}

for s in "${series_list[@]}"; do
    build_one "$s"
done

echo
echo "compdebug images:"
"$DOCKER" images "${MATRIX_IMAGE_REPO}" --format '  {{.Repository}}:{{.Tag}}  {{.ID}}  {{.CreatedSince}}' \
    | grep -- "${COMPDEBUG_SUFFIX}"
