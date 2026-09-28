#!/usr/bin/env bash
# Capture OpenVPN key-method-2 known-answer vectors for internal/prf.
#
#   ./prf-capture.sh                       # write internal/prf/testdata/vectors.json
#   ./prf-capture.sh -o /tmp/vectors.json  # write somewhere else
#   ./prf-capture.sh -k                    # keep containers on failure
#
# For each cipher/digest combination below this drives one real OpenVPN 2.4.12
# handshake between two containers of the instrumented image built by
# build-prfdebug.sh, and records what generate_key_expansion() actually consumed
# and produced:
#
#   master    = TLS1_PRF(client.pre_master, "OpenVPN master secret",
#                        client.random1 ‖ server.random1)              ->  48 B
#   key_block = TLS1_PRF(master,            "OpenVPN key expansion",
#                        client.random2 ‖ server.random2
#                        ‖ client_sid ‖ server_sid)                    -> 256 B
#
# Both peers run the instrumented build, so both dump. The two dumps are
# compared: a vector is only recorded when the client and the server independently
# arrived at the same 256-byte key block. That is the check that catches a
# mis-transcribed field, because a wrong field would have to be wrong identically
# on both sides.
#
# No key material reaches the host filesystem. The throwaway PKI is generated
# inside a container and handed to the server and client containers as a
# base64 tar in the environment, exactly as testenv.StartMatrix does it. The
# only thing written out is vectors.json, which holds ephemeral session values
# from a local throwaway server — see docker/PRF-VECTORS.md.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$here/../.." && pwd)"
# shellcheck source=versions.env disable=SC1091
. "$here/versions.env"

DOCKER="${DOCKER:-docker}"
IMAGE="${MATRIX_IMAGE_REPO}:${OPENVPN_24_VERSION}-prfdebug"
NET="go-openvpn-prfcapture-$$"
LABEL="net.bngs.goopenvpn.testenv=prf-capture"
OUT="$repo_root/internal/prf/testdata/vectors.json"
KEEP=0
READY="Initialization Sequence Completed"
READY_TIMEOUT=60

while getopts "o:kh" opt; do
    case "$opt" in
        o) OUT="$OPTARG" ;;
        k) KEEP=1 ;;
        h) sed -n '2,32p' "$0"; exit 0 ;;
        *) exit 64 ;;
    esac
done

# One row per vector: name|cipher|digest|proto. The key block itself does not
# depend on the cipher or the digest — the PRF output is 256 bytes whatever
# consumes it — so these combinations are provenance, not separate algorithms:
# they record which negotiated parameters were live when each vector was taken,
# and they cover the cipher and digest shapes deployed in the wild.
COMBOS=(
    "aes256cbc-sha512|AES-256-CBC|SHA512|udp"
    "aes128cbc-sha256|AES-128-CBC|SHA256|udp"
    "aes256cbc-sha1|AES-256-CBC|SHA1|udp"
    "aes256gcm-sha256|AES-256-GCM|SHA256|tcp"
)

containers=()

cleanup() {
    local rc=$?
    if [ "$KEEP" = 1 ] && [ "$rc" != 0 ]; then
        echo "prf-capture: -k given, leaving ${#containers[@]} container(s) and network $NET" >&2
        return
    fi
    if [ ${#containers[@]} -gt 0 ]; then
        "$DOCKER" rm -f "${containers[@]}" >/dev/null 2>&1 || true
    fi
    "$DOCKER" network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT

die() { echo "prf-capture: $*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Preconditions
# ---------------------------------------------------------------------------

"$DOCKER" info >/dev/null 2>&1 || die "no reachable Docker daemon"

if ! "$DOCKER" image inspect "$IMAGE" >/dev/null 2>&1; then
    die "image $IMAGE is absent — run: bash $here/build-prfdebug.sh"
fi

# Refuse to run against a stock image. An unpatched build completes the
# handshake perfectly and prints nothing, which looks like a script bug.
if ! "$DOCKER" run --rm --entrypoint /bin/sh "$IMAGE" \
        -c 'grep -qa "PRFDEBUG %s %s" /usr/sbin/openvpn'; then
    die "$IMAGE does not contain the PRFDEBUG instrumentation — rebuild with build-prfdebug.sh"
fi

[ -c /dev/net/tun ] || die "/dev/net/tun is missing on the host; both containers need it"

# ---------------------------------------------------------------------------
# Throwaway PKI, generated inside a container and never written to the host
# ---------------------------------------------------------------------------

# Emits: two lines, "SERVERPKI <base64 tar>" and "CLIENTPKI <base64 tar>".
# Each tar holds only what that role needs, so the client tar carries no
# server key and vice versa.
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
    -subj "/CN=go-openvpn-prf-capture-ca" -keyout ca.key -out ca.crt 2>/dev/null
gen server ext-server.cnf
gen client ext.cnf
echo "SERVERPKI $(tar -cf - ca.crt server.crt server.key | base64 -w0)"
echo "CLIENTPKI $(tar -cf - ca.crt client.crt client.key | base64 -w0)"
'

echo "==> generating throwaway PKI (in-container; nothing is written to the host)"
pki_out="$("$DOCKER" run --rm --entrypoint /bin/sh "$IMAGE" -c "$pki_script")"
server_pki="$(printf '%s\n' "$pki_out" | sed -n 's/^SERVERPKI //p')"
client_pki="$(printf '%s\n' "$pki_out" | sed -n 's/^CLIENTPKI //p')"
[ -n "$server_pki" ] && [ -n "$client_pki" ] || die "PKI generation produced no output"

"$DOCKER" network create --label "$LABEL" "$NET" >/dev/null \
    || die "could not create docker network $NET"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# bundle_with <pki-b64> <config-name> <config-text>
#
# Appends one config file to a role's PKI tar. Done in a container so the
# config and the keys are only ever adjacent inside the container filesystem.
bundle_with() {
    "$DOCKER" run --rm --entrypoint /bin/sh \
        -e "PKI_B64=$1" -e "CONF_NAME=$2" -e "CONF_BODY=$3" "$IMAGE" -c '
set -eu
d="$(mktemp -d)"
printf "%s" "$PKI_B64" | base64 -d | tar -xf - -C "$d"
printf "%s" "$CONF_BODY" > "$d/$CONF_NAME"
tar -cf - -C "$d" . | base64 -w0
'
}

# wait_ready <container> — poll the log for OpenVPN's own readiness line.
wait_ready() {
    local c="$1" i=0 log
    while [ "$i" -lt "$((READY_TIMEOUT * 2))" ]; do
        log="$("$DOCKER" logs "$c" 2>&1 || true)"
        case "$log" in *"$READY"*) return 0 ;; esac
        if [ "$("$DOCKER" inspect -f '{{.State.Running}}' "$c" 2>/dev/null)" != "true" ]; then
            echo "--- $c exited ---" >&2
            printf '%s\n' "$log" | tail -25 >&2
            return 1
        fi
        sleep 0.5
        i=$((i + 1))
    done
    echo "--- $c timed out waiting for '$READY' ---" >&2
    "$DOCKER" logs "$c" 2>&1 | tail -25 >&2
    return 1
}

# field <log> <tag> — the hex payload of the last "PRFDEBUG <tag> <hex>" line.
field() {
    printf '%s\n' "$1" | sed -n "s/.*PRFDEBUG $2 \\([0-9a-f]*\\)$/\\1/p" | tail -1
}

# ---------------------------------------------------------------------------
# Capture
# ---------------------------------------------------------------------------

captured_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
vectors=()

for combo in "${COMBOS[@]}"; do
    IFS='|' read -r name cipher digest proto <<<"$combo"
    echo "==> capturing $name  (cipher=$cipher digest=$digest proto=$proto)"

    sname="prfcap-s-$$-$name"
    cname="prfcap-c-$$-$name"

    # ncp-disable pins the cipher: without it 2.4 negotiates AES-256-GCM
    # regardless of what the config asked for, and the recorded cipher would
    # not be the cipher that ran.
    server_conf="dev tun
topology subnet
server 10.99.0.0 255.255.255.0
proto $proto
port 1194
ca /etc/openvpn/ca.crt
cert /etc/openvpn/server.crt
key /etc/openvpn/server.key
dh none
cipher $cipher
auth $digest
ncp-disable
keepalive 5 30
verb 3"

    client_conf="client
dev tun
proto $proto
remote $sname 1194
nobind
ca /etc/openvpn/ca.crt
cert /etc/openvpn/client.crt
key /etc/openvpn/client.key
remote-cert-tls server
cipher $cipher
auth $digest
ncp-disable
verb 3"

    server_bundle="$(bundle_with "$server_pki" server.conf "$server_conf")"
    client_bundle="$(bundle_with "$client_pki" client.conf "$client_conf")"

    "$DOCKER" run -d --name "$sname" --label "$LABEL" --network "$NET" \
        --cap-add=NET_ADMIN --device=/dev/net/tun \
        -e "OVPN_BUNDLE_B64=$server_bundle" "$IMAGE" >/dev/null
    containers+=("$sname")
    wait_ready "$sname" || die "$name: server never became ready"

    "$DOCKER" run -d --name "$cname" --label "$LABEL" --network "$NET" \
        --cap-add=NET_ADMIN --device=/dev/net/tun \
        -e "OVPN_CONFIG=client.conf" -e "OVPN_BUNDLE_B64=$client_bundle" \
        "$IMAGE" >/dev/null
    containers+=("$cname")
    wait_ready "$cname" || die "$name: client never connected"

    slog="$("$DOCKER" logs "$sname" 2>&1)"
    clog="$("$DOCKER" logs "$cname" 2>&1)"

    pre_master="$(field "$slog" client_pre_master)"
    crandom1="$(field "$slog" client_random1)"
    crandom2="$(field "$slog" client_random2)"
    srandom1="$(field "$slog" server_random1)"
    srandom2="$(field "$slog" server_random2)"
    csid="$(field "$slog" client_sid)"
    ssid="$(field "$slog" server_sid)"
    master="$(field "$slog" master)"
    key_block="$(field "$slog" key_block)"

    for v in pre_master crandom1 crandom2 srandom1 srandom2 csid ssid master key_block; do
        [ -n "${!v}" ] || die "$name: server log carried no PRFDEBUG $v"
    done
    [ "${#pre_master}" = 96 ]  || die "$name: pre_master is ${#pre_master} hex chars, want 96"
    [ "${#crandom1}" = 64 ]    || die "$name: client_random1 is ${#crandom1} hex chars, want 64"
    [ "${#crandom2}" = 64 ]    || die "$name: client_random2 is ${#crandom2} hex chars, want 64"
    [ "${#srandom1}" = 64 ]    || die "$name: server_random1 is ${#srandom1} hex chars, want 64"
    [ "${#srandom2}" = 64 ]    || die "$name: server_random2 is ${#srandom2} hex chars, want 64"
    [ "${#csid}" = 16 ]        || die "$name: client_sid is ${#csid} hex chars, want 16"
    [ "${#ssid}" = 16 ]        || die "$name: server_sid is ${#ssid} hex chars, want 16"
    [ "${#master}" = 96 ]      || die "$name: master is ${#master} hex chars, want 96"
    [ "${#key_block}" = 512 ]  || die "$name: key_block is ${#key_block} hex chars, want 512"

    # Cross-check: the client derived the same block from the same inputs.
    for f in client_pre_master client_random1 client_random2 \
             server_random1 server_random2 client_sid server_sid master key_block; do
        sv="$(field "$slog" "$f")"
        cv="$(field "$clog" "$f")"
        [ -n "$cv" ] || die "$name: client log carried no PRFDEBUG $f"
        [ "$sv" = "$cv" ] || die "$name: peers disagree on $f
  server: $sv
  client: $cv"
    done
    echo "    server and client agree on all nine fields"

    vectors+=("$(cat <<EOF
    {
      "name": "$name",
      "cipher": "$cipher",
      "digest": "$digest",
      "proto": "$proto",
      "client_pre_master": "$pre_master",
      "client_random1": "$crandom1",
      "client_random2": "$crandom2",
      "server_random1": "$srandom1",
      "server_random2": "$srandom2",
      "client_session_id": "$csid",
      "server_session_id": "$ssid",
      "master_secret": "$master",
      "key_block": "$key_block"
    }
EOF
)")

    "$DOCKER" rm -f "$cname" "$sname" >/dev/null 2>&1 || true
    containers=()
done

# ---------------------------------------------------------------------------
# Emit
# ---------------------------------------------------------------------------

mkdir -p "$(dirname "$OUT")"
{
    cat <<EOF
{
  "_comment": [
    "OpenVPN key-method-2 known-answer vectors for internal/prf.",
    "Generated by docker/openvpn-server/prf-capture.sh; do not hand-edit.",
    "Every value is ephemeral session material from a throwaway local server.",
    "See docker/PRF-VECTORS.md to regenerate."
  ],
  "provenance": {
    "captured_at": "$captured_at",
    "openvpn_version": "$OPENVPN_24_VERSION",
    "openvpn_sha256": "$OPENVPN_24_SHA256",
    "base_image": "$OPENVPN_24_BASE",
    "configure_flags": "$OPENVPN_24_CONFIGURE",
    "image": "$IMAGE",
    "patch": "docker/openvpn-server/patches-prfdebug/001-prfdebug-key-expansion.patch",
    "instrumented_function": "generate_key_expansion() in src/openvpn/ssl.c",
    "capture_method": "two containers of the instrumented image complete a real handshake; the dump is taken from the server, whose key_source2 holds both peers' material, and cross-checked against the client's own dump",
    "derivation": [
      "master    = TLS1_PRF(client_pre_master, 'OpenVPN master secret', client_random1 || server_random1) -> 48 B",
      "key_block = TLS1_PRF(master, 'OpenVPN key expansion', client_random2 || server_random2 || client_session_id || server_session_id) -> 256 B",
      "TLS1_PRF is the TLS 1.0 split PRF: P_MD5(S1, seed) XOR P_SHA1(S2, seed), S1/S2 being the two halves of the secret, each ceil(len/2) bytes"
    ]
  },
  "vectors": [
EOF
    for i in "${!vectors[@]}"; do
        printf '%s' "${vectors[$i]}"
        if [ "$i" -lt "$((${#vectors[@]} - 1))" ]; then printf ',\n'; else printf '\n'; fi
    done
    cat <<EOF
  ]
}
EOF
} > "$OUT"

echo
echo "==> wrote ${#vectors[@]} vector(s) to $OUT"
