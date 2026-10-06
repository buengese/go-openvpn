#!/usr/bin/env bash
# Build the pinned OpenVPN server images used by the e2e test matrix.
#
#   ./build.sh            # build 2.4, 2.5 and 2.6
#   ./build.sh 2.4 2.6    # build only the named series
#
# Images are tagged with their exact upstream version, never "latest":
#   go-openvpn-test/openvpn-server:2.4.12
#
# testenv.StartMatrix refuses to run if the tag for an entry's series is absent
# and tells you to run `make matrix-images`.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=versions.env disable=SC1091
. "$here/versions.env"

DOCKER="${DOCKER:-docker}"

series_list=("$@")
if [ ${#series_list[@]} -eq 0 ]; then
    series_list=(2.4 2.5 2.6)
fi

build_one() {
    local series="$1"
    local key version sha base flags openssl_url openssl_sha tag

    key="${series//./}"
    eval "version=\${OPENVPN_${key}_VERSION:-}"
    eval "sha=\${OPENVPN_${key}_SHA256:-}"
    eval "base=\${OPENVPN_${key}_BASE:-}"
    eval "flags=\${OPENVPN_${key}_CONFIGURE:-}"
    eval "openssl_url=\${OPENVPN_${key}_OPENSSL_URL:-}"
    eval "openssl_sha=\${OPENVPN_${key}_OPENSSL_SHA256:-}"

    if [ -z "$version" ]; then
        echo "build.sh: unknown OpenVPN series '$series' (no OPENVPN_${key}_VERSION in versions.env)" >&2
        return 1
    fi

    tag="${MATRIX_IMAGE_REPO}:${version}"
    echo "==> building ${tag}"
    echo "    base:      ${base}"
    echo "    sha256:    ${sha}"
    echo "    configure: ${flags}"
    echo "    openssl:   ${openssl_url:-distro}"

    "$DOCKER" build \
        --build-arg "BASE_IMAGE=${base}" \
        --build-arg "OPENVPN_VERSION=${version}" \
        --build-arg "OPENVPN_SHA256=${sha}" \
        --build-arg "CONFIGURE_FLAGS=${flags}" \
        --build-arg "OPENSSL_URL=${openssl_url}" \
        --build-arg "OPENSSL_SHA256=${openssl_sha}" \
        --build-arg "SOURCE_URL_BASE=${MATRIX_SOURCE_URL_BASE}" \
        -t "$tag" \
        "$here"

    echo "==> built ${tag}"
}

for s in "${series_list[@]}"; do
    build_one "$s"
done

echo
echo "matrix images:"
"$DOCKER" images "${MATRIX_IMAGE_REPO}" --format '  {{.Repository}}:{{.Tag}}  {{.ID}}  {{.CreatedSince}}'
