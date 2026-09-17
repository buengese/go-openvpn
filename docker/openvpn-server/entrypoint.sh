#!/bin/sh
# Entrypoint for the OpenVPN server matrix image.
#
# The whole configuration — server.conf (or client.conf), the ephemeral PKI, and
# for an AuthUserPass entry the auth-user-pass-verify hook and the credentials
# file — arrives as a single base64-encoded tar in OVPN_BUNDLE_B64, written by
# testenv.StartMatrix. Nothing is baked into the image and nothing is bind
# mounted, so no key material ever touches the repository or a shared volume.
#
# OVPN_CONFIG selects which unpacked file to run; it defaults to server.conf.
# The matrix's reference-client self-check sets it to client.conf and runs the
# same image as a client.
set -eu

CONF_DIR=/etc/openvpn
CONF_NAME="${OVPN_CONFIG:-server.conf}"
mkdir -p "$CONF_DIR"

if [ -n "${OVPN_BUNDLE_B64:-}" ]; then
    printf '%s' "$OVPN_BUNDLE_B64" | base64 -d | tar -xf - -C "$CONF_DIR"
fi

if [ ! -f "$CONF_DIR/$CONF_NAME" ]; then
    echo "entrypoint: no $CONF_DIR/$CONF_NAME — set OVPN_BUNDLE_B64" >&2
    exit 64
fi

if [ ! -c /dev/net/tun ]; then
    mkdir -p /dev/net
    if ! mknod /dev/net/tun c 10 200 2>/dev/null; then
        echo "entrypoint: /dev/net/tun is missing — run with --device=/dev/net/tun" >&2
        exit 65
    fi
    chmod 0600 /dev/net/tun
fi

# testenv ships the auth-user-pass-verify hook with mode 0755, but a tar
# extracted under a umask or by a non-root user can arrive without it. OpenVPN
# execve()s the hook directly, so a lost execute bit fails the connection at
# exactly the point a wrong password does — an unattributable auth failure.
# Re-asserting the mode costs nothing and removes the ambiguity.
if [ -f "$CONF_DIR/auth-verify.sh" ]; then
    chmod 0755 "$CONF_DIR/auth-verify.sh"
fi

echo "entrypoint: $(openvpn --version 2>&1 | head -1)"
echo "entrypoint: ----- $CONF_NAME -----"
# Inline secret blocks are stripped: the log is captured by tests and printed on
# failure, and must never carry key material, even throwaway material.
sed -e '/^$/d' \
    -e '/^<key>$/,/^<\/key>$/d' \
    -e '/^<tls-auth>$/,/^<\/tls-auth>$/d' \
    -e '/^<tls-crypt>$/,/^<\/tls-crypt>$/d' \
    "$CONF_DIR/$CONF_NAME"
echo "entrypoint: ----- end $CONF_NAME -----"

exec openvpn --config "$CONF_DIR/$CONF_NAME"
