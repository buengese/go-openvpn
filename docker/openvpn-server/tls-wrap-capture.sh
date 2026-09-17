#!/usr/bin/env bash
# Capture tls-auth and tls-crypt control-channel known-answer vectors
# for internal/wrap.
#
#   ./tls-wrap-capture.sh                       # write internal/wrap/testdata/vectors.json
#   ./tls-wrap-capture.sh -o /tmp/vectors.json  # write somewhere else
#   ./tls-wrap-capture.sh -k                    # keep containers on failure
#
# For each row below this drives one real OpenVPN 2.4.12 handshake between two
# containers of the instrumented image built by build-tlswrapdebug.sh, and
# records what write_control_auth() actually consumed and produced on *both*
# peers:
#
#   tls-auth   wire = opcode|key_id ‖ session_id ‖ HMAC ‖ pid ‖ time ‖ rest
#              HMAC = H(Ka,  pid ‖ time ‖ opcode|key_id ‖ session_id ‖ rest)
#
#   tls-crypt  wire = opcode|key_id ‖ session_id ‖ pid ‖ time ‖ tag ‖ ct
#              tag  = HMAC-SHA256(Ka, opcode|key_id ‖ session_id ‖ pid ‖ time
#                                     ‖ plaintext)
#              ct   = AES-256-CTR(Ke, IV = tag[0:16], plaintext)
#
# The two orderings differ — the HMAC input is not the wire order — which is
# the single fact these vectors exist to pin down. The capture never assumes
# either one: it records the buffer OpenVPN handed to its own HMAC and then
# *checks* the decomposition above against it, refusing to emit a vector whose
# structure does not hold.
#
# The key halves are measured the same way. The instrumented init_key_ctx()
# prints the bytes it installed; this script locates them inside the 256-byte
# static key and records the offset it found, so key-direction is a
# measurement rather than a reading.
#
# No key material other than the throwaway static key reaches the host
# filesystem. The PKI is generated inside a container and handed to the server
# and client containers as a base64 tar in the environment, exactly as
# testenv.StartMatrix does it. The static key is in vectors.json by design: it
# is an input to the known-answer test, it was generated inside a container for
# this capture alone, and it authenticates nothing that outlives the run.
# See docker/TLS-WRAP-VECTORS.md.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$here/../.." && pwd)"
# shellcheck source=versions.env disable=SC1091
. "$here/versions.env"

DOCKER="${DOCKER:-docker}"
IMAGE="${MATRIX_IMAGE_REPO}:${OPENVPN_24_VERSION}-tlswrapdebug"
NET="openlawsvpn-tlswrapcapture-$$"
LABEL="com.openlawsvpn.testenv=tls-wrap-capture"
OUT="$repo_root/internal/wrap/testdata/vectors.json"
PATCH="docker/openvpn-server/patches-tlswrapdebug/001-tlswrapdebug-control-channel.patch"
KEEP=0
READY="Initialization Sequence Completed"
READY_TIMEOUT=60

while getopts "o:kh" opt; do
    case "$opt" in
        o) OUT="$OPTARG" ;;
        k) KEEP=1 ;;
        h) sed -n '2,39p' "$0"; exit 0 ;;
        *) exit 64 ;;
    esac
done

# One row per handshake: name|wrap|client-key-direction|digest.
#
# The key direction is the *client's*, matching how a .ovpn profile reads it;
# the server is configured with the opposite, which is what
# testenv/matrix_axes.go's WrapTLSAuthKD0 / WrapTLSAuthKD1 do. tls-crypt has no
# key-direction option at all — the direction follows from which peer is the
# server — so its row carries "-".
#
# tls-auth is captured on both digests and both directions because the two
# axes are independent and both are cheap; tls-crypt fixes AES-256-CTR and
# HMAC-SHA256 and has nothing to vary.
RUNS=(
    "tlsauth-kd0-sha1|auth|0|SHA1"
    "tlsauth-kd1-sha1|auth|1|SHA1"
    "tlsauth-kd0-sha256|auth|0|SHA256"
    "tlsauth-kd1-sha256|auth|1|SHA256"
    "tlscrypt|crypt|-|SHA256"
)

# Opcodes captured per side, first occurrence of each. The client opens with a
# HARD_RESET, which has no ack array and no message packet id; everything after
# it does, and P_ACK_V1 has an ack array and no payload. Three shapes, and the
# wrap has to be right for all of them.
CLIENT_OPCODES="7 5 4"
SERVER_OPCODES="8 5 4"

opcode_name() {
    case "$1" in
        4) echo "P_CONTROL_V1" ;;
        5) echo "P_ACK_V1" ;;
        7) echo "P_CONTROL_HARD_RESET_CLIENT_V2" ;;
        8) echo "P_CONTROL_HARD_RESET_SERVER_V2" ;;
        *) echo "P_UNKNOWN_$1" ;;
    esac
}

# opcode_slug <opcode> — the short form used in a vector's name. The full
# opcode name has a field of its own; a name is for reading a test failure by.
opcode_slug() {
    case "$1" in
        4) echo "control" ;;
        5) echo "ack" ;;
        7|8) echo "hardreset" ;;
        *) echo "opcode$1" ;;
    esac
}

containers=()

cleanup() {
    local rc=$?
    if [ "$KEEP" = 1 ] && [ "$rc" != 0 ]; then
        echo "tls-wrap-capture: -k given, leaving ${#containers[@]} container(s) and network $NET" >&2
        return
    fi
    if [ ${#containers[@]} -gt 0 ]; then
        "$DOCKER" rm -f "${containers[@]}" >/dev/null 2>&1 || true
    fi
    "$DOCKER" network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT

die() { echo "tls-wrap-capture: $*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Preconditions
# ---------------------------------------------------------------------------

"$DOCKER" info >/dev/null 2>&1 || die "no reachable Docker daemon"

if ! "$DOCKER" image inspect "$IMAGE" >/dev/null 2>&1; then
    die "image $IMAGE is absent — run: bash $here/build-tlswrapdebug.sh"
fi

# Refuse to run against a stock image. An unpatched build completes the
# handshake perfectly and prints nothing, which looks like a script bug.
if ! "$DOCKER" run --rm --entrypoint /bin/sh "$IMAGE" \
        -c 'grep -qa "TLSWRAPDEBUG %s %s%s%s" /usr/sbin/openvpn'; then
    die "$IMAGE does not contain the TLSWRAPDEBUG instrumentation — rebuild with build-tlswrapdebug.sh"
fi

[ -c /dev/net/tun ] || die "/dev/net/tun is missing on the host; both containers need it"

# ---------------------------------------------------------------------------
# Throwaway PKI and static key, generated inside a container
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
    -subj "/CN=openlawsvpn-tls-wrap-capture-ca" -keyout ca.key -out ca.crt 2>/dev/null
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

# new_static_key — 256 random bytes as lowercase hex, generated in a container.
# A fresh key per run, so no two runs share a secret and a copy-paste between
# vectors cannot go unnoticed.
new_static_key() {
    "$DOCKER" run --rm --entrypoint /bin/sh "$IMAGE" -c 'openssl rand -hex 256'
}

# static_key_file <hex> — the hex rendered as an OpenVPN "Static key V1" file,
# the same 16 lines of 32 hex characters testenv/matrix_server.go writes.
static_key_file() {
    printf '#\n# 2048 bit OpenVPN static key\n#\n'
    printf -- '-----BEGIN OpenVPN Static key V1-----\n'
    printf '%s' "$1" | fold -w 32
    printf -- '\n-----END OpenVPN Static key V1-----\n'
}

# bundle_with <pki-b64> <config-name> <config-text> <ta-key-text>
#
# Appends one config file and the static key to a role's PKI tar. Done in a
# container so the config and the keys are only ever adjacent inside the
# container filesystem.
bundle_with() {
    "$DOCKER" run --rm --entrypoint /bin/sh \
        -e "PKI_B64=$1" -e "CONF_NAME=$2" -e "CONF_BODY=$3" -e "TA_BODY=$4" "$IMAGE" -c '
set -eu
d="$(mktemp -d)"
printf "%s" "$PKI_B64" | base64 -d | tar -xf - -C "$d"
printf "%s" "$CONF_BODY" > "$d/$CONF_NAME"
printf "%s" "$TA_BODY" > "$d/ta.key"
chmod 600 "$d/ta.key"
tar -cf - -C "$d" . | base64 -w0
'
}

# wait_ready <container> — poll the log for OpenVPN's own readiness line.
#
# The TLSWRAPDEBUG lines are filtered out of the diagnostic tail: they are
# thousands of hex characters each and they are key material, and a failure
# here is never about them.
wait_ready() {
    local c="$1" i=0 log
    while [ "$i" -lt "$((READY_TIMEOUT * 2))" ]; do
        log="$("$DOCKER" logs "$c" 2>&1 || true)"
        case "$log" in *"$READY"*) return 0 ;; esac
        if [ "$("$DOCKER" inspect -f '{{.State.Running}}' "$c" 2>/dev/null)" != "true" ]; then
            echo "--- $c exited ---" >&2
            printf '%s\n' "$log" | { grep -v TLSWRAPDEBUG || true; } | tail -25 >&2
            return 1
        fi
        sleep 0.5
        i=$((i + 1))
    done
    echo "--- $c timed out waiting for '$READY' ---" >&2
    "$DOCKER" logs "$c" 2>&1 | { grep -v TLSWRAPDEBUG || true; } | tail -25 >&2
    return 1
}

# first_match <log> <sed-expression> — the first capture, or empty.
#
# `| head -1` would be the obvious spelling and is wrong here: head closes the
# pipe on the first line, sed takes SIGPIPE, and `set -o pipefail` turns that
# into a silent exit 141 out of the whole capture. Take everything and cut in
# the shell instead.
first_match() {
    local all
    all="$(printf '%s\n' "$1" | sed -n "$2")"
    printf '%s' "${all%%$'\n'*}"
}

# stage <log> <mode> <opcode> <stage> — the hex of the FIRST matching dump.
#
# Retransmissions re-run the wrap with a fresh replay packet id, so every stage
# of one vector must come from the same pass: first of each, never last.
stage() {
    first_match "$1" "s/^TLSWRAPDEBUG $2 $3 $4 \\([0-9a-f]*\\)\$/\\1/p"
}

# keyctx <log> <cipher|hmac> <Outgoing|Incoming> <name> — the installed key bytes.
keyctx() {
    first_match "$1" "s/^TLSWRAPDEBUG keyctx $2 \\([0-9a-f]*\\) $3 $4\$/\\1/p"
}

# offset_in <haystack-hex> <needle-hex> — byte offset of needle in haystack, or
# empty when it is not there. This is what turns "which half of the key does
# key-direction 1 use" from a reading of the reference into a measurement.
offset_in() {
    local hay="$1" needle="$2" pre
    [ -n "$needle" ] || { echo ""; return; }
    pre="${hay%%"$needle"*}"
    if [ "${#pre}" -ge "${#hay}" ]; then echo ""; return; fi
    if [ $(( ${#pre} % 2 )) -ne 0 ]; then echo ""; return; fi
    echo $(( ${#pre} / 2 ))
}

# hexcut <hex> <byte-offset> [<byte-length>] — substring by byte position.
hexcut() {
    if [ $# -ge 3 ]; then
        printf '%s' "${1:$(( $2 * 2 )):$(( $3 * 2 ))}"
    else
        printf '%s' "${1:$(( $2 * 2 ))}"
    fi
}

json_vectors=()

# emit_auth <name> <sender> <opcode> <digest> <kd> <static> <hmackey> <plain> <preswap> <wire>
#
# Decomposes one tls-auth packet and refuses to record it unless the recorded
# bytes actually have the structure this file's header claims. Every check here
# is a check on our reading, not on OpenVPN.
emit_auth() {
    local name="$1" sender="$2" opcode="$3" digest="$4" kd="$5"
    local static="$6" hmackey="$7" plain="$8" preswap="$9" wire="${10}"
    local hlen tag auth_input pid tim rebuilt off

    hlen=$(( ${#hmackey} / 2 ))
    tag="$(hexcut "$preswap" 0 "$hlen")"
    auth_input="$(hexcut "$preswap" "$hlen")"
    pid="$(hexcut "$auth_input" 0 4)"
    tim="$(hexcut "$auth_input" 4 4)"

    [ "$(hexcut "$auth_input" 8)" = "$plain" ] \
        || die "$name/$sender/op$opcode: HMAC input tail is not the plain packet
  this is the field-order claim failing, not a transcription error
  auth_input: $auth_input
  plain:      $plain"

    # opcode|key_id ‖ session_id (9 bytes) ‖ HMAC ‖ pid ‖ time ‖ rest
    rebuilt="$(hexcut "$plain" 0 9)$tag$pid$tim$(hexcut "$plain" 9)"
    [ "$rebuilt" = "$wire" ] \
        || die "$name/$sender/op$opcode: wire layout does not decompose
  rebuilt: $rebuilt
  wire:    $wire"

    off="$(offset_in "$static" "$hmackey")"
    [ -n "$off" ] \
        || die "$name/$sender/op$opcode: the installed HMAC key is not a slice of the static key"

    json_vectors+=("$(cat <<EOF
    {
      "name": "$name-$sender-$(opcode_slug "$opcode")",
      "wrap": "tls-auth",
      "digest": "$digest",
      "key_direction": $kd,
      "sender": "$sender",
      "opcode": $opcode,
      "opcode_name": "$(opcode_name "$opcode")",
      "static_key": "$static",
      "hmac_key": "$hmackey",
      "hmac_key_offset": $off,
      "cipher_key": "",
      "cipher_key_offset": -1,
      "plain": "$plain",
      "auth_input": "$auth_input",
      "tag": "$tag",
      "replay_packet_id": "$pid",
      "replay_timestamp": "$tim",
      "wire": "$wire"
    }
EOF
)")
}

# emit_crypt <name> <sender> <opcode> <static> <cipherkey> <hmackey> <plainhdr> <plainbody> <wire>
emit_crypt() {
    local name="$1" sender="$2" opcode="$3"
    local static="$4" cipherkey="$5" hmackey="$6"
    local hdr="$7" body="$8" wire="$9"
    local plain pid tim tag ct auth_input coff hoff

    plain="$hdr$body"
    [ "${#hdr}" = 18 ] || die "$name/$sender/op$opcode: tls-crypt header is ${#hdr} hex chars, want 18"

    pid="$(hexcut "$wire" 9 4)"
    tim="$(hexcut "$wire" 13 4)"
    tag="$(hexcut "$wire" 17 32)"
    ct="$(hexcut "$wire" 49)"
    auth_input="$hdr$pid$tim$body"

    [ "$(hexcut "$wire" 0 9)" = "$hdr" ] \
        || die "$name/$sender/op$opcode: wire does not start with the plain header"
    [ "${#ct}" = "${#body}" ] \
        || die "$name/$sender/op$opcode: ciphertext is ${#ct} hex chars, plaintext is ${#body}
  AES-256-CTR is a stream mode; a length change means the layout is misread"

    coff="$(offset_in "$static" "$cipherkey")"
    hoff="$(offset_in "$static" "$hmackey")"
    [ -n "$coff" ] && [ -n "$hoff" ] \
        || die "$name/$sender/op$opcode: an installed key is not a slice of the static key"

    json_vectors+=("$(cat <<EOF
    {
      "name": "$name-$sender-$(opcode_slug "$opcode")",
      "wrap": "tls-crypt",
      "digest": "SHA256",
      "key_direction": null,
      "sender": "$sender",
      "opcode": $opcode,
      "opcode_name": "$(opcode_name "$opcode")",
      "static_key": "$static",
      "hmac_key": "$hmackey",
      "hmac_key_offset": $hoff,
      "cipher_key": "$cipherkey",
      "cipher_key_offset": $coff,
      "plain": "$plain",
      "auth_input": "$auth_input",
      "tag": "$tag",
      "replay_packet_id": "$pid",
      "replay_timestamp": "$tim",
      "wire": "$wire"
    }
EOF
)")
}

# ---------------------------------------------------------------------------
# Capture
# ---------------------------------------------------------------------------

captured_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

for run in "${RUNS[@]}"; do
    IFS='|' read -r name wrap client_kd digest <<<"$run"
    echo "==> capturing $name  (wrap=$wrap client-key-direction=$client_kd digest=$digest)"

    sname="tlswrapcap-s-$$-$name"
    cname="tlswrapcap-c-$$-$name"

    static_hex="$(new_static_key)"
    [ "${#static_hex}" = 512 ] || die "$name: static key is ${#static_hex} hex chars, want 512"
    ta_body="$(static_key_file "$static_hex")"

    if [ "$wrap" = auth ]; then
        # The server takes the opposite direction, as testenv/matrix.go does.
        server_kd=$(( 1 - client_kd ))
        server_wrap="tls-auth /etc/openvpn/ta.key $server_kd"
        client_wrap="tls-auth /etc/openvpn/ta.key $client_kd"
        kd_json="$client_kd"
    else
        server_wrap="tls-crypt /etc/openvpn/ta.key"
        client_wrap="tls-crypt /etc/openvpn/ta.key"
        kd_json="null"
    fi

    # ncp-disable pins the cipher: without it 2.4 negotiates AES-256-GCM
    # regardless of what the config asked for. --auth is what selects the
    # tls-auth HMAC as well as the data-channel one (init.c, do_init_crypto_tls
    # -> tls_auth_key_type.digest = md_kt_get(options->authname)), so it has to
    # be pinned for the recorded digest to be the digest that ran.
    server_conf="dev tun
topology subnet
server 10.99.0.0 255.255.255.0
proto udp
port 1194
ca /etc/openvpn/ca.crt
cert /etc/openvpn/server.crt
key /etc/openvpn/server.key
dh none
cipher AES-256-CBC
auth $digest
ncp-disable
$server_wrap
keepalive 5 30
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
cipher AES-256-CBC
auth $digest
ncp-disable
$client_wrap
verb 3"

    server_bundle="$(bundle_with "$server_pki" server.conf "$server_conf" "$ta_body")"
    client_bundle="$(bundle_with "$client_pki" client.conf "$client_conf" "$ta_body")"

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

    if [ "$wrap" = auth ]; then
        key_name="Control Channel Authentication"
    else
        key_name="Control Channel Encryption"
    fi

    before=${#json_vectors[@]}
    for side in client server; do
        if [ "$side" = client ]; then
            log="$clog"; opcodes="$CLIENT_OPCODES"
        else
            log="$slog"; opcodes="$SERVER_OPCODES"
        fi

        # The sender's own outgoing key. The peer's incoming key is the same
        # bytes; recording the outgoing one per sender covers both, and the
        # capture cross-checks that it does.
        out_hmac="$(keyctx "$log" hmac Outgoing "$key_name")"
        [ -n "$out_hmac" ] || die "$name/$side: no outgoing $key_name HMAC key in the log"
        if [ "$side" = client ]; then peer="$slog"; else peer="$clog"; fi
        peer_in_hmac="$(keyctx "$peer" hmac Incoming "$key_name")"
        [ "$out_hmac" = "$peer_in_hmac" ] \
            || die "$name/$side: the peer's incoming HMAC key differs from this side's outgoing key
  out: $out_hmac
  in:  $peer_in_hmac"

        out_cipher=""
        if [ "$wrap" = crypt ]; then
            out_cipher="$(keyctx "$log" cipher Outgoing "$key_name")"
            [ -n "$out_cipher" ] || die "$name/$side: no outgoing $key_name cipher key in the log"
        fi

        for op in $opcodes; do
            if [ "$wrap" = auth ]; then
                plain="$(stage "$log" auth "$op" plain)"
                preswap="$(stage "$log" auth "$op" preswap)"
                wire="$(stage "$log" auth "$op" wire)"
                if [ -z "$plain" ] || [ -z "$preswap" ] || [ -z "$wire" ]; then
                    echo "    $side opcode $op ($(opcode_name "$op")) not sent; skipping"
                    continue
                fi
                emit_auth "$name" "$side" "$op" "$digest" "$kd_json" \
                    "$static_hex" "$out_hmac" "$plain" "$preswap" "$wire"
            else
                hdr="$(stage "$log" crypt "$op" plainhdr)"
                body="$(stage "$log" crypt "$op" plainbody)"
                wire="$(stage "$log" crypt "$op" wire)"
                if [ -z "$hdr" ] || [ -z "$wire" ]; then
                    echo "    $side opcode $op ($(opcode_name "$op")) not sent; skipping"
                    continue
                fi
                emit_crypt "$name" "$side" "$op" \
                    "$static_hex" "$out_cipher" "$out_hmac" "$hdr" "$body" "$wire"
            fi
            echo "    $side opcode $op ($(opcode_name "$op")) recorded"
        done
    done
    [ ${#json_vectors[@]} -gt "$before" ] || die "$name: produced no vectors at all"

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
    "OpenVPN tls-auth / tls-crypt control-channel known-answer vectors",
    "for internal/wrap.",
    "Generated by docker/openvpn-server/tls-wrap-capture.sh; do not hand-edit.",
    "static_key is a throwaway 2048-bit key generated inside a container for one",
    "capture; everything else is ephemeral session material from a local server.",
    "See docker/TLS-WRAP-VECTORS.md to regenerate."
  ],
  "provenance": {
    "captured_at": "$captured_at",
    "openvpn_version": "$OPENVPN_24_VERSION",
    "openvpn_sha256": "$OPENVPN_24_SHA256",
    "base_image": "$OPENVPN_24_BASE",
    "configure_flags": "$OPENVPN_24_CONFIGURE",
    "image": "$IMAGE",
    "patch": "$PATCH",
    "instrumented_function": "write_control_auth() in src/openvpn/ssl.c and init_key_ctx() in src/openvpn/crypto.c",
    "capture_method": "two containers of the instrumented image complete a real handshake; every outgoing control packet is dumped plain, mid-wrap and on the wire, on both peers, and the key bytes each direction installed are located inside the static key rather than assumed",
    "layout": [
      "tls-auth  wire = opcode|key_id(1) || session_id(8) || hmac(N) || packet_id(4) || timestamp(4) || ack_array || [message_packet_id(4) || payload]",
      "tls-auth  hmac = HMAC(Ka, packet_id(4) || timestamp(4) || opcode|key_id(1) || session_id(8) || ack_array || [message_packet_id(4) || payload])",
      "tls-auth  Ka   = static_key[hmac_key_offset : hmac_key_offset+digest_size]; offset 64 for key-direction 0 outgoing, 192 for key-direction 1 outgoing",
      "tls-crypt wire = opcode|key_id(1) || session_id(8) || packet_id(4) || timestamp(4) || tag(32) || ciphertext",
      "tls-crypt tag  = HMAC-SHA256(Ka, opcode|key_id(1) || session_id(8) || packet_id(4) || timestamp(4) || plaintext)",
      "tls-crypt ct   = AES-256-CTR(Ke, IV = tag[0:16], plaintext), plaintext being everything in the plain packet after the 9-byte header",
      "the tls-auth HMAC input order is not the wire order: swap_hmac() exchanges the leading hmac||packet_id||timestamp with the opcode||session_id that follows it"
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
echo "==> wrote ${#json_vectors[@]} vector(s) to $OUT"
