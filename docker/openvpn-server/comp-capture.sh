#!/usr/bin/env bash
# Capture data-channel compression framing known-answer vectors
# for internal/compress.
#
#   ./comp-capture.sh                       # write internal/compress/testdata/vectors.json
#   ./comp-capture.sh -o /tmp/vectors.json  # write somewhere else
#   ./comp-capture.sh -k                    # keep containers on failure
#
# For each row in RUNS below this drives one real OpenVPN handshake between two
# containers of the instrumented images built by build-compdebug.sh, pushes four
# probe datagrams through the finished tunnel, and records what the compression
# layer consumed and produced on *both* peers:
#
#   comp-lzo             framed = 0xFA || plain              (not compressed)
#                        framed = 0x66 || LZO(plain)         (compressed)
#   compress (bare)      framed = 0xFB || plain[1:] || plain[0]
#   compress lz4         framed = 0xFB || plain[1:] || plain[0]
#                        framed = 0x69 || LZ4(plain) swapped (compressed)
#   compress lz4-v2      framed = plain                      (not compressed)
#                        framed = 0x50 0x01 || LZ4(plain)    (compressed)
#   compress stub-v2     framed = plain                      (no byte at all)
#
# None of that is assumed. The script records the two buffers the compression
# layer actually had, and then *checks* the decomposition above against them,
# refusing to emit a vector whose structure does not hold. Every check is a
# check on our reading, not on OpenVPN.
#
# Both directions are captured because they are different questions. The marker
# a peer *sends* is what our Unwrap must accept; the marker it *accepts* is what
# our Wrap must send. Each vector is confirmed twice — once from the sender's
# compress() call and once from the receiver's decompress() call — and the two
# dumps must agree or the vector is not written.
#
# Nothing sensitive reaches the host. The PKI is generated inside a container
# and handed to the peers as a base64 tar in the environment, exactly as
# testenv.StartMatrix does it, and the recorded packets are UDP datagrams full
# of 'A' that this script generated. Unlike the wrap vectors there is no key
# material in the output at all. See docker/COMPRESSION-VECTORS.md.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$here/../.." && pwd)"
# shellcheck source=versions.env disable=SC1091
. "$here/versions.env"

DOCKER="${DOCKER:-docker}"
COMPDEBUG_SUFFIX="-compdebug"
NET="openlawsvpn-compcapture-$$"
LABEL="com.openlawsvpn.testenv=comp-capture"
OUT="$repo_root/internal/compress/testdata/vectors.json"
PATCH="docker/openvpn-server/patches-compdebug/001-compdebug-framing.patch"
KEEP=0
READY="Initialization Sequence Completed"
READY_TIMEOUT=60

# The server's tun address under `server 10.99.0.0 255.255.255.0` with
# `topology subnet`. The client's is read off its own tun0 rather than assumed.
SERVER_TUN="10.99.0.1"

# Probe sizes. The small one is below OpenVPN's COMPRESS_THRESHOLD (100 bytes,
# src/openvpn/comp.h) so no algorithm will even attempt to compress it; the
# large one is far above it and is a run of a single byte, so any algorithm that
# is willing to compress will succeed. That pair is what separates "this peer
# does not compress" from "this peer did not compress *this* packet".
SMALL_FILL=0
LARGE_FILL=1200

while getopts "o:kh" opt; do
    case "$opt" in
        o) OUT="$OPTARG" ;;
        k) KEEP=1 ;;
        h) sed -n '2,40p' "$0"; exit 0 ;;
        *) exit 64 ;;
    esac
done

# One row per handshake: name|series|directive|mode.
#
# `directive` is what goes into both peers' configs verbatim; `mode` is the
# family it belongs to and is what the Go test feeds to compress.ParseMode.
#
# comp-lzo is captured on 2.4 and 2.5 only: a 2.6 server refuses it unless
# compression is re-enabled, which is exactly why MatrixEntry.SkipReason exists.
#
# 2.4 gets `comp-lzo yes` rather than a bare `comp-lzo` on purpose. A bare
# comp-lzo is COMP_F_ADAPTIVE, and an adaptive compressor's decision depends on
# what it has seen; `yes` is flags=0, which always attempts. The compressed
# vectors have to be reproducible.
#
# lz4 and lz4-v2 are captured even though nothing requires them: which byte
# announces a compressed payload is a question about ModeLZ4's marker
# specifically, and `compress lz4` is the only directive that puts 0x69 on the
# wire. Settling it without them means reasoning by analogy from comp-lzo,
# which is the failure mode this capture exists to avoid.
RUNS=(
    "v24-complzo|2.4|comp-lzo yes|comp-lzo"
    "v25-complzo|2.5|comp-lzo|comp-lzo"
    "v24-compress|2.4|compress|compress"
    "v24-lz4|2.4|compress lz4|compress lz4"
    "v24-lz4v2|2.4|compress lz4-v2|compress lz4-v2"
    "v25-stubv2|2.5|compress stub-v2|compress stub-v2"
    "v26-stubv2|2.6|compress stub-v2|compress stub-v2"
)

containers=()

cleanup() {
    local rc=$?
    if [ "$KEEP" = 1 ] && [ "$rc" != 0 ]; then
        echo "comp-capture: -k given, leaving ${#containers[@]} container(s) and network $NET" >&2
        return
    fi
    if [ ${#containers[@]} -gt 0 ]; then
        "$DOCKER" rm -f "${containers[@]}" >/dev/null 2>&1 || true
    fi
    "$DOCKER" network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT

die() { echo "comp-capture: $*" >&2; exit 1; }

# series_version <series> — the pinned version for 2.4 / 2.5 / 2.6.
series_version() {
    local key="${1//./}" v
    eval "v=\${OPENVPN_${key}_VERSION:-}"
    [ -n "$v" ] || die "unknown OpenVPN series '$1' (no OPENVPN_${key}_VERSION in versions.env)"
    printf '%s' "$v"
}

series_image() {
    printf '%s:%s%s' "$MATRIX_IMAGE_REPO" "$(series_version "$1")" "$COMPDEBUG_SUFFIX"
}

# ---------------------------------------------------------------------------
# Preconditions
# ---------------------------------------------------------------------------

"$DOCKER" info >/dev/null 2>&1 || die "no reachable Docker daemon"
[ -c /dev/net/tun ] || die "/dev/net/tun is missing on the host; both containers need it"

series_used=()
for run in "${RUNS[@]}"; do
    IFS='|' read -r _ series _ _ <<<"$run"
    case " ${series_used[*]-} " in *" $series "*) ;; *) series_used+=("$series") ;; esac
done

for series in "${series_used[@]}"; do
    img="$(series_image "$series")"
    "$DOCKER" image inspect "$img" >/dev/null 2>&1 \
        || die "image $img is absent — run: bash $here/build-compdebug.sh"
    # Refuse to run against a stock image. An unpatched build carries traffic
    # perfectly and prints nothing, which looks like a script bug.
    "$DOCKER" run --rm --entrypoint /bin/sh "$img" \
        -c "grep -qa 'COMPDEBUG %s %u %s %s %s' /usr/sbin/openvpn" \
        || die "$img does not contain the COMPDEBUG instrumentation — rebuild with build-compdebug.sh"
done

# ---------------------------------------------------------------------------
# Throwaway PKI, generated inside a container
# ---------------------------------------------------------------------------

pki_script='
set -eu
cd "$(mktemp -d)"
cat > ext.cnf <<EOF
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
EOF
cat > ext-server.cnf <<EOF
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
EOF
gen() {
    openssl req -nodes -newkey rsa:2048 -sha256 \
        -subj "/CN=$1" -keyout "$1.key" -out "$1.csr" 2>/dev/null
    openssl x509 -req -in "$1.csr" -CA ca.crt -CAkey ca.key -CAcreateserial \
        -days 1 -sha256 -extfile "$2" -out "$1.crt" 2>/dev/null
}
openssl req -x509 -nodes -newkey rsa:2048 -sha256 -days 1 \
    -subj "/CN=openlawsvpn-comp-capture-ca" -keyout ca.key -out ca.crt 2>/dev/null
gen server ext-server.cnf
gen client ext.cnf
echo "SERVERPKI $(tar -cf - ca.crt server.crt server.key | base64 -w0)"
echo "CLIENTPKI $(tar -cf - ca.crt client.crt client.key | base64 -w0)"
'

echo "==> generating throwaway PKI (in-container; nothing is written to the host)"
pki_out="$("$DOCKER" run --rm --entrypoint /bin/sh "$(series_image 2.4)" -c "$pki_script")"
server_pki="$(printf '%s\n' "$pki_out" | sed -n 's/^SERVERPKI //p')"
client_pki="$(printf '%s\n' "$pki_out" | sed -n 's/^CLIENTPKI //p')"
[ -n "$server_pki" ] && [ -n "$client_pki" ] || die "PKI generation produced no output"

"$DOCKER" network create --label "$LABEL" "$NET" >/dev/null \
    || die "could not create docker network $NET"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# bundle_with <image> <pki-b64> <config-name> <config-text>
#
# Appends one config file to a role's PKI tar, in a container, so the config and
# the key are only ever adjacent inside a container filesystem.
bundle_with() {
    "$DOCKER" run --rm --entrypoint /bin/sh \
        -e "PKI_B64=$2" -e "CONF_NAME=$3" -e "CONF_BODY=$4" "$1" -c '
set -eu
d="$(mktemp -d)"
printf "%s" "$PKI_B64" | base64 -d | tar -xf - -C "$d"
printf "%s" "$CONF_BODY" > "$d/$CONF_NAME"
tar -cf - -C "$d" . | base64 -w0
'
}

# wait_ready <container> — poll the log for OpenVPN's own readiness line.
#
# COMPDEBUG lines are filtered out of the diagnostic tail: they are thousands of
# hex characters each and a failure here is never about them.
wait_ready() {
    local c="$1" i=0 log
    while [ "$i" -lt "$((READY_TIMEOUT * 2))" ]; do
        log="$("$DOCKER" logs "$c" 2>&1 || true)"
        case "$log" in *"$READY"*) return 0 ;; esac
        if [ "$("$DOCKER" inspect -f '{{.State.Running}}' "$c" 2>/dev/null)" != "true" ]; then
            echo "--- $c exited ---" >&2
            printf '%s\n' "$log" | { grep -v COMPDEBUG || true; } | tail -25 >&2
            return 1
        fi
        sleep 0.5
        i=$((i + 1))
    done
    echo "--- $c timed out waiting for '$READY' ---" >&2
    "$DOCKER" logs "$c" 2>&1 | { grep -v COMPDEBUG || true; } | tail -25 >&2
    return 1
}

# tun_addr <container> — the container's tun0 IPv4 address.
tun_addr() {
    "$DOCKER" exec "$1" ip -4 -o addr show dev tun0 2>/dev/null \
        | awk '{print $4}' | cut -d/ -f1
}

# hexof <string> — lowercase hex of an ASCII string.
hexof() {
    printf '%s' "$1" | od -An -v -tx1 | tr -d ' \n'
}

# hexcut <hex> <byte-offset> [<byte-length>] — substring by byte position.
hexcut() {
    if [ $# -ge 3 ]; then
        printf '%s' "${1:$(( $2 * 2 )):$(( $3 * 2 ))}"
    else
        printf '%s' "${1:$(( $2 * 2 ))}"
    fi
}

# send_probe <container> <dst-ip> <marker> <fill-bytes>
#
# One UDP datagram to a closed port. Nothing has to answer it: the packet has
# already crossed the compression layer by the time it leaves the sender, which
# is the only thing being measured. bash's /dev/udp is used because the runtime
# image has no ping and adding one would mean rebuilding the stock matrix
# images, which another suite is entitled to assume are unchanged.
send_probe() {
    local c="$1" dst="$2" marker="$3" fill="$4" payload
    payload="$marker"
    if [ "$fill" -gt 0 ]; then
        payload="$marker$(head -c "$fill" /dev/zero | tr '\0' 'A')"
    fi
    "$DOCKER" exec -e "P=$payload" -e "D=$dst" "$c" \
        bash -c 'printf "%s" "$P" > /dev/udp/$D/9' >/dev/null 2>&1
}

# find_dump <log> <compress|decompress> <marker-hex> <pre|post>
#
# The first COMPDEBUG line for that direction whose named stage contains the
# marker, as "alg flags pre post". First, not last: a marker is unique to one
# datagram, so there is only ever one, but taking the first keeps a re-sent
# probe from pairing a later attempt's bytes with an earlier one's.
find_dump() {
    printf '%s\n' "$1" | awk -v dir="$2" -v m="$3" -v which="$4" '
        $1 == "COMPDEBUG" && $4 == dir {
            hay = (which == "pre" ? $5 : $6)
            if (index(hay, m) > 0) { print $2, $3, $5, $6; exit }
        }'
}

json_vectors=()
n_compressed=0

# check_framing <label> <alg> <flags> <plain> <framed>
#
# Sets V_COMPRESSED and V_MARKER, or dies. This is the decomposition claim in
# the header of this file, checked against the bytes rather than trusted.
V_COMPRESSED=""
V_MARKER=""
check_framing() {
    local label="$1" alg="$2" flags="$3" plain="$4" framed="$5"
    local swap=$(( flags & 4 ))   # COMP_F_SWAP, src/openvpn/comp.h
    local head swapped prepended

    head="$(hexcut "$framed" 0 1)"
    swapped="fb$(hexcut "$plain" 1)$(hexcut "$plain" 0 1)"
    prepended="fa$plain"
    V_COMPRESSED=false
    V_MARKER="$head"

    case "$alg" in
        lzo)
            [ "$swap" = 0 ] || die "$label: lzo with COMP_F_SWAP set (flags=$flags); lzo_compress_init() asserts it is never set"
            case "$head" in
                fa) [ "$framed" = "$prepended" ] || die "$label: framed is not NO_COMPRESS_BYTE || plain
  plain:  $plain
  framed: $framed" ;;
                66) V_COMPRESSED=true
                    [ "$(hexcut "$framed" 1)" != "$plain" ] \
                        || die "$label: LZO_COMPRESS_BYTE over an unchanged payload" ;;
                *)  die "$label: unexpected lzo framing byte 0x$head" ;;
            esac
            ;;
        stub)
            if [ "$swap" != 0 ]; then
                [ "$framed" = "$swapped" ] || die "$label: framed is not NO_COMPRESS_BYTE_SWAP || plain[1:] || plain[0]
  plain:  $plain
  framed: $framed"
            else
                [ "$framed" = "$prepended" ] || die "$label: framed is not NO_COMPRESS_BYTE || plain
  plain:  $plain
  framed: $framed"
            fi
            ;;
        lz4)
            [ "$swap" != 0 ] || die "$label: lz4 without COMP_F_SWAP (flags=$flags); lz4_compress() always swaps"
            case "$head" in
                fb) [ "$framed" = "$swapped" ] || die "$label: framed is not NO_COMPRESS_BYTE_SWAP || plain[1:] || plain[0]
  plain:  $plain
  framed: $framed" ;;
                69) V_COMPRESSED=true
                    [ "$(hexcut "$framed" 1)" != "$(hexcut "$plain" 1)$(hexcut "$plain" 0 1)" ] \
                        || die "$label: LZ4_COMPRESS_BYTE over an unchanged payload" ;;
                *)  die "$label: unexpected lz4 framing byte 0x$head" ;;
            esac
            ;;
        stubv2|lz4v2)
            if [ "$(hexcut "$framed" 0 2)" = "5001" ] && [ "$alg" = lz4v2 ]; then
                V_COMPRESSED=true
                V_MARKER="5001"
            elif [ "$(hexcut "$plain" 0 1)" = "50" ]; then
                # compv2_escape_data_ifneeded(); see COMPRESSION-VECTORS.md §5.
                [ "$framed" = "500a$plain" ] || die "$label: a 0x50-leading packet was not escaped as recorded
  plain:  $plain
  framed: $framed"
                V_MARKER="500a"
            else
                [ "$framed" = "$plain" ] || die "$label: v2 framing changed a packet it should have passed through
  plain:  $plain
  framed: $framed"
                V_MARKER=""
            fi
            ;;
        *)
            die "$label: unknown compression algorithm '$alg'"
            ;;
    esac
}

# capture_one <run> <mode> <version> <direction> <tag> <fill>
#             <src-container> <dst-ip> <sender> <receiver> <dst-container>
#
# Sends one probe and records the vector, cross-checking the sender's compress()
# dump against the receiver's decompress() dump.
#
# <tag> names the direction as well as the size, and it has to. A UDP datagram
# to a closed port draws an ICMP port-unreachable, and Linux packs as much of
# the offending datagram into that error as fits in 576 bytes — the probe's
# marker included. So the reply to a client probe is a server-to-client packet
# carrying the *client* probe's marker, and a marker shared between the two
# directions matches the echo before it matches the probe. The first run of this
# capture recorded four ICMP errors and called them server-originated packets;
# the framing was still right, which is exactly why it was not obvious.
capture_one() {
    local run="$1" mode="$2" version="$3" dir="$4" tag="$5" fill="$6"
    local src="$7" dst_ip="$8" srcname="$9" dstname="${10}" dstc="${11}"
    local marker mhex i sdump rdump salg sflags spre spost ralg rflags rpre rpost

    for i in 1 2 3 4 5 6; do
        marker="OLVCOMP-$run-$tag-$i"
        mhex="$(hexof "$marker")"
        send_probe "$src" "$dst_ip" "$marker" "$fill" \
            || die "$run/$tag: could not send the probe datagram"
        sleep 1
        sdump="$(find_dump "$("$DOCKER" logs "$src" 2>&1)" compress "$mhex" pre)"
        rdump="$(find_dump "$("$DOCKER" logs "$dstc" 2>&1)" decompress "$mhex" post)"
        if [ -n "$sdump" ] && [ -n "$rdump" ]; then
            break
        fi
        sdump=""
        rdump=""
    done
    [ -n "$sdump" ] || die "$run/$tag: the sender's compression layer never saw the probe"
    [ -n "$rdump" ] || die "$run/$tag: the receiver's compression layer never saw the probe"

    read -r salg sflags spre spost <<<"$sdump"
    read -r ralg rflags rpre rpost <<<"$rdump"

    # Two independent dumps of the same datagram, from two processes in two
    # containers. If they disagree the packet on the wire is not what either
    # side thinks it is, and no vector is worth writing.
    [ "$spre" = "$rpost" ] \
        || die "$run/$tag: the receiver did not recover the packet the sender framed
  sender pre:    $spre
  receiver post: $rpost"
    [ "$spost" = "$rpre" ] \
        || die "$run/$tag: the receiver did not see the bytes the sender produced
  sender post:  $spost
  receiver pre: $rpre"

    check_framing "$run/$tag" "$salg" "$sflags" "$spre" "$spost"
    if [ "$V_COMPRESSED" = true ]; then
        n_compressed=$(( n_compressed + 1 ))
    fi

    json_vectors+=("$(cat <<EOF
    {
      "name": "$run-$tag",
      "mode": "$mode",
      "directive": "$RUN_DIRECTIVE",
      "alg": "$salg",
      "comp_flags": $sflags,
      "swap": $( [ $(( sflags & 4 )) = 0 ] && echo false || echo true ),
      "openvpn_version": "$version",
      "sender": "$srcname",
      "receiver": "$dstname",
      "direction": "$dir",
      "compressed": $V_COMPRESSED,
      "framing_byte": "$V_MARKER",
      "plain": "$spre",
      "framed": "$spost"
    }
EOF
)")
    local sz=$(( ${#spre} / 2 )) fz=$(( ${#spost} / 2 ))
    printf '    %-10s %-18s alg=%-6s flags=%-2s %4d -> %4d bytes  byte=%-4s compressed=%s\n' \
        "$tag" "$dir" "$salg" "$sflags" "$sz" "$fz" "${V_MARKER:-none}" "$V_COMPRESSED"
}

# ---------------------------------------------------------------------------
# Capture
# ---------------------------------------------------------------------------

captured_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

for run in "${RUNS[@]}"; do
    IFS='|' read -r name series RUN_DIRECTIVE mode <<<"$run"
    version="$(series_version "$series")"
    image="$(series_image "$series")"
    echo "==> capturing $name  (openvpn $version, '$RUN_DIRECTIVE')"

    sname="compcap-s-$$-$name"
    cname="compcap-c-$$-$name"

    # No cipher, digest or wrap is pinned. Compression framing sits above all
    # three, 2.6 removed --ncp-disable outright, and a config that has to be
    # spelled three ways per series is a config that will rot. What is pinned is
    # the compression directive, which is the whole subject.
    server_conf="dev tun
topology subnet
server 10.99.0.0 255.255.255.0
proto udp
port 1194
ca /etc/openvpn/ca.crt
cert /etc/openvpn/server.crt
key /etc/openvpn/server.key
dh none
$RUN_DIRECTIVE
keepalive 10 60
verb 3"

    client_conf="client
dev tun
proto udp
remote $sname 1194
nobind
ca /etc/openvpn/ca.crt
cert /etc/openvpn/client.crt
key /etc/openvpn/client.key
remote-cert-tls server
$RUN_DIRECTIVE
verb 3"

    server_bundle="$(bundle_with "$image" "$server_pki" server.conf "$server_conf")"
    client_bundle="$(bundle_with "$image" "$client_pki" client.conf "$client_conf")"

    "$DOCKER" run -d --name "$sname" --label "$LABEL" --network "$NET" \
        --cap-add=NET_ADMIN --device=/dev/net/tun \
        -e "OVPN_BUNDLE_B64=$server_bundle" "$image" >/dev/null
    containers+=("$sname")
    wait_ready "$sname" || die "$name: server never became ready"

    "$DOCKER" run -d --name "$cname" --label "$LABEL" --network "$NET" \
        --cap-add=NET_ADMIN --device=/dev/net/tun \
        -e "OVPN_CONFIG=client.conf" -e "OVPN_BUNDLE_B64=$client_bundle" \
        "$image" >/dev/null
    containers+=("$cname")
    wait_ready "$cname" || die "$name: client never connected"

    client_tun="$(tun_addr "$cname")"
    server_tun="$(tun_addr "$sname")"
    [ -n "$client_tun" ] || die "$name: the client has no tun0 address"
    [ "$server_tun" = "$SERVER_TUN" ] \
        || die "$name: server tun0 is $server_tun, expected $SERVER_TUN"

    before=${#json_vectors[@]}
    capture_one "$name" "$mode" "$version" client-to-server c2s-small "$SMALL_FILL" \
        "$cname" "$server_tun" client server "$sname"
    capture_one "$name" "$mode" "$version" client-to-server c2s-large "$LARGE_FILL" \
        "$cname" "$server_tun" client server "$sname"
    capture_one "$name" "$mode" "$version" server-to-client s2c-small "$SMALL_FILL" \
        "$sname" "$client_tun" server client "$cname"
    capture_one "$name" "$mode" "$version" server-to-client s2c-large "$LARGE_FILL" \
        "$sname" "$client_tun" server client "$cname"
    [ ${#json_vectors[@]} -gt "$before" ] || die "$name: produced no vectors at all"

    "$DOCKER" rm -f "$cname" "$sname" >/dev/null 2>&1 || true
    containers=()
done

[ "$n_compressed" -gt 0 ] \
    || die "no vector carries a genuinely compressed payload; compress.ErrCompressed would have nothing to detect"

# ---------------------------------------------------------------------------
# Emit
# ---------------------------------------------------------------------------

mkdir -p "$(dirname "$OUT")"
{
    cat <<EOF
{
  "_comment": [
    "OpenVPN data-channel compression framing known-answer vectors",
    "for internal/compress.",
    "Generated by docker/openvpn-server/comp-capture.sh; do not hand-edit.",
    "Every 'plain' is a UDP datagram of 'A' this capture generated inside a",
    "throwaway container. There is no key material and no corpus text here.",
    "See docker/COMPRESSION-VECTORS.md to regenerate."
  ],
  "provenance": {
    "captured_at": "$captured_at",
    "openvpn_versions": ["$OPENVPN_24_VERSION", "$OPENVPN_25_VERSION", "$OPENVPN_26_VERSION"],
    "openvpn_sha256": {
      "$OPENVPN_24_VERSION": "$OPENVPN_24_SHA256",
      "$OPENVPN_25_VERSION": "$OPENVPN_25_SHA256",
      "$OPENVPN_26_VERSION": "$OPENVPN_26_SHA256"
    },
    "image_suffix": "$COMPDEBUG_SUFFIX",
    "patch": "$PATCH",
    "instrumented_function": "comp_init() in src/openvpn/comp.c, which installs a trampoline over compress_alg.compress and .decompress",
    "capture_method": "two containers of the instrumented image complete a real handshake; four UDP probe datagrams are pushed through the finished tunnel in both directions, and the compression layer's buffer is dumped on both sides of the framing on both peers, then cross-checked against the other peer's dump",
    "layout": [
      "comp-lzo          framed = 0xFA || plain,               or 0x66 || LZO(plain) when the peer compressed",
      "compress (bare)   framed = 0xFB || plain[1:] || plain[0]  — COMP_ALG_STUB with COMP_F_SWAP",
      "compress lz4      framed = 0xFB || plain[1:] || plain[0], or 0x69 || (LZ4(plain) swapped the same way)",
      "compress lz4-v2   framed = plain,                        or 0x50 0x01 || LZ4(plain)",
      "compress stub-v2  framed = plain — no framing byte at all unless plain[0] is 0x50",
      "0x69 is LZ4_COMPRESS_BYTE and 0xFA is NO_COMPRESS_BYTE: src/openvpn/comp.h"
    ]
  },
  "vectors": [
EOF
    for i in "${!json_vectors[@]}"; do
        printf '%s' "${json_vectors[$i]}"
        if [ "$i" -lt "$(( ${#json_vectors[@]} - 1 ))" ]; then printf ',\n'; else printf '\n'; fi
    done
    cat <<EOF
  ]
}
EOF
} > "$OUT"

echo
echo "==> wrote ${#json_vectors[@]} vector(s) to $OUT ($n_compressed genuinely compressed)"
