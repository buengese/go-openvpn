# Agent context for go-openlawsvpn

## What this repo is

A pure Go implementation of the OpenVPN3 client protocol — the same protocol
used by openvpn3-core (C++). `go build` / `gomobile bind` produce a fully static
binary and an Android `.aar` with no C toolchain.

**This is not a clean-room implementation, and must not be treated as one.**
[`docs/openvpn3-reference-policy.md`](docs/openvpn3-reference-policy.md) governs
all protocol work here: we consult the openvpn3 source as the authoritative
description of the OpenVPN wire protocol, taken under the MPL-2.0 branch of its
dual license. Transliterating an openvpn3 function is permitted (§3.2) as a
derivative work carrying attribution, and a provenance citation is **required**
(§3.3) on anything learned from openvpn3:

```go
// Reference: openvpn3-core ssl/proto.hpp KeyContext::init_data_channel() line ~2297
```

`grep -rn 'Reference: openvpn' --include=*.go .` finds the existing ones. Do not
strip them and do not avoid reading openvpn3 — read the policy first, then cite
what you read.

This repo **is** the engine. The old C++/openvpn3-core stack it once aimed to
replace is now fully retired and archived (see "Status" below).

## The other documents

AGENTS.md is context, not the authority on any of these. Read the one that
covers what you are about to change:

| Document | Authoritative on |
|---|---|
| [`docs/openvpn3-reference-policy.md`](docs/openvpn3-reference-policy.md) | how openvpn3 may be read and cited |
| [`docs/ci-relay.md`](docs/ci-relay.md) | `openlawsvpn-cli` relay mode in CI |

## Parent project context

**openlawsvpn** is an open-source AWS Client VPN client with SAML/SSO support.
This repo is the current engine for all platforms:
- Linux/macOS CLI: this repo (`cmd/cli`)
- Linux desktop app (GTK GUI + D-Bus daemon + RPM/AUR packaging): https://github.com/openlawsvpn/openlawsvpn-linux (consumes this module)
- Android client: https://github.com/openlawsvpn/openlawsvpn-android-go (consumes the `.aar`)
- Website: https://openlawsvpn.com

Consumers pin the engine via a `go-openlawsvpn.version` file and consume the
gomobile `.aar` produced by `aar.yml`.

### Status

The protocol is fully implemented and tested against a real AWS Client VPN
endpoint. Working end-to-end on Linux and macOS (CLI), on Android and iOS (via
the gomobile bindings) and on the Linux desktop through openlawsvpn-linux.
Verify the current release with
`git tag --list 'v*' --sort=-v:refname | head -1`; do not copy a version from
prose. The desktop packages (COPR, AUR) are released from openlawsvpn-linux on
its own versions.

### Releasing

The library's version is its tag; no file in the tree carries it. Move the
entries under `Unreleased` in `CHANGELOG.md` to the new version and date,
create a fresh empty `Unreleased` section, commit, then tag `vX.Y.Z`. The
release workflows (`release.yml`, `aar.yml`, `xcframework.yml`) run on the
tag. The desktop app, its RPM spec and its PKGBUILD are versioned and released
from openlawsvpn-linux.

### Retired / archived — do NOT treat as current

- `openlawsvpn/openlawsvpn` (archived) — old C++/openvpn3-core engine + Linux CLI.
- `openlawsvpn/openlawsvpn-android` (archived) — old Kotlin+JNI/NDK app.

There is no longer a `libopenlawsvpn` C library, no JNI, no NDK, and no
openvpn3-core *dependency* anywhere in the shipping stack. Reading the openvpn3
*source* remains current practice — see "What this repo is" above.

## Why Go

- `CGO_ENABLED=0` — fully static binary, zero native dependencies
- `gomobile bind` — produces `.aar` for Android without NDK/CMake
- Single codebase covers Linux CLI, Android, future iOS
- F-Droid compatible — no prebuilt blobs, `./gradlew assembleRelease` is self-contained
- Easier auditing, fuzzing (`go test -fuzz`), and contribution

## Goals (in priority order)

1. **Correctness over completeness** — every packet exchange must be byte-exact
   with what openvpn3-core expects. The mock server is the oracle.
2. **Android via gomobile** — `gomobile bind` produces an `.aar` that drops into
   `openlawsvpn-android-go` with no NDK changes.
3. **Linux static binary** — `CGO_ENABLED=0 go build` produces a binary with
   zero runtime dependencies.
4. **F-Droid compatibility** — no download-at-build-time, no prebuilt blobs.

## Non-goals

- OpenVPN server implementation
- OpenVPN 2.x legacy static-key mode
- Windows support
- WireGuard or other protocols

## SAML / CRV1 flow (the AWS-specific part)

AWS Client VPN uses a non-standard SAML challenge called CRV1:

```
Phase 1:
  Client → Server: TLS ClientHello + OpenVPN HARD_RESET
  Server → Client: AUTH_FAILED,CRV1:R,<state_id>::<saml_url>
  (connection pauses)

  App opens saml_url in browser.
  Browser → http://127.0.0.1:35001 : POST SAMLResponse=<base64>
  (AWS hardcodes ACS URL to 127.0.0.1:35001)

Phase 2:
  Client → Server: new TLS session with key-method password="CRV1::<state_id>::<saml_token>"
  Server → Client: PUSH_REPLY with ifconfig, route, etc.
  Tunnel is up.
```

Key detail: AWS hardcodes AssertionConsumerServiceURL = http://127.0.0.1:35001.
This is true across all AWS regions and IdPs (Okta, Azure AD, Google Workspace).

The ACS server now lives in this repo's `auth/saml` package (Go). The old Kotlin
reference implementation in the archived `openlawsvpn-android` repo is obsolete.

## OpenVPN3 protocol reference

Key concepts an AI agent must know:

**Control channel (reliable transport)**
- Runs over TLS, but TLS runs inside OpenVPN's own reliable layer (not raw TCP TLS)
- Packet layout (`internal/framing/control.go`). There is no `peer_id` on the
  control channel — that field belongs to P_DATA_V2 — and the ack array comes
  **before** the packet id, not after:

  ```
  [opcode<<3 | key_id   1 B ]
  [session_id           8 B ]   the sender's own
  [ack_array_len        1 B ]
  [ack_array        4 B each]   present only when ack_array_len > 0
  [remote_session_id    8 B ]   present only when ack_array_len > 0
  [packet_id            4 B ]   absent on P_ACK_V1
  [payload                  ]   absent on P_ACK_V1 and on the resets
  ```

- Opcodes are the **top 5 bits** of the first byte; the low 3 are the key_id, so
  a literal first byte is `opcode<<3 | key_id` (`framing.FirstByte`). The
  constants in `internal/framing/opcodes.go` are the unshifted opcodes — never
  mix them with a shifted byte:

  | Constant | Value |
  |---|---|
  | `P_CONTROL_SOFT_RESET_V1` | `0x03` |
  | `P_CONTROL_V1` | `0x04` |
  | `P_ACK_V1` | `0x05` |
  | `P_DATA_V1` | `0x06` |
  | `P_CONTROL_HARD_RESET_CLIENT_V2` | `0x07` |
  | `P_CONTROL_HARD_RESET_SERVER_V2` | `0x08` |
  | `P_DATA_V2` | `0x09` |
- Reliable layer: sequence numbers + sliding window + retransmit (matches reliable.hpp in openvpn3-core)
- TLS bytes are fragmented across P_CONTROL_V1 packets, reassembled in order

**Key derivation** (`internal/prf`)

Read `internal/prf/prf.go` before touching this. A previous implementation here
computed HMAC-SHA256 over the TLS session's master secret and hello randoms,
passed a green test suite, and was wrong. That is *not* what OpenVPN does, and
it is what this section used to describe.

The TLS session contributes nothing to the classic derivation. Each peer sends a
`key_source2` structure *through* the control channel — the client's carries a
48-byte pre-master and two 32-byte randoms, the server's the two randoms alone
— and both sides run two stages over the union:

```
master    = TLS1PRF(client.PreMaster, "OpenVPN master secret",
                    client.Random1 ‖ server.Random1)            ->  48 B
key_block = TLS1PRF(master,           "OpenVPN key expansion",
                    client.Random2 ‖ server.Random2
                    ‖ clientSessionID ‖ serverSessionID)        -> 256 B
```

- `TLS1PRF` is the **TLS 1.0 MD5+SHA1 split PRF of RFC 2246 §5** — P_MD5 over
  the first half of the secret XORed with P_SHA1 over the second half. Not
  HMAC-SHA256, and not the TLS 1.2 single-digest PRF.
- The two stages consume **disjoint** randoms: Random1 seeds the master secret,
  Random2 seeds the key expansion. Feeding the same pair to both still produces
  plausible-looking bytes.
- Labels are raw ASCII with no terminating NUL. Session IDs are the two peers'
  8-byte control-channel session IDs, client first.
- The output is **256 bytes, not 64** — four 64-byte slots reached through
  `prf.Split`: cipher-encrypt, hmac-encrypt, cipher-decrypt, hmac-decrypt, named
  for this client's NORMAL direction. A slot is 64 bytes whatever consumes it;
  AES-256 takes the first 32, an HMAC-SHA1 key the first 20, a GCM nonce tail the
  first 8. The trailing bytes are unused, not spare.
- Under GCM the "HMAC" slots are not unused: they supply the 8-byte implicit IV.

**The 2.6+ alternative:** a server that pushes `key-derivation tls-ekm` (or
`tls-ekm` inside `protocol-flags`) selects RFC 5705 exported keying material
instead — `ExportKeyingMaterial` with label `EXPORTER-OpenVPN-datakeys`, same
256 bytes, same `prf.Split`. `routing/push.go` parses the switch;
`internal/prf/capture.go` implements it. AWS Client VPN and openvpn3-core 3.x
use this path. Only known-answer vectors (`internal/prf/testdata/vectors.json`,
captured from a real OpenVPN 2.4.12 peer) distinguish a correct derivation from
a convincing wrong one — length and determinism tests do not.

**Data channel** (`internal/datachannel`, `internal/crypto`)

The IV is **not on the wire**. Only the 4-byte packet id is; the IV is rebuilt
from it at both ends.

```
P_DATA_V2, GCM:  [op<<3|key_id 1B][peer_id 3B][packet_id 4B][GCM tag 16B][ciphertext]
P_DATA_V2, CBC:  [op<<3|key_id 1B][peer_id 3B][HMAC N B][IV 16B][ciphertext]
P_DATA_V1:       the same two bodies with no peer_id at all
```

- `N` is the negotiated digest's output length — 20 for SHA1, 32 for SHA256, 64
  for SHA512 — and is not a constant.
- **IV construction is a concatenation, not a XOR** (`internal/crypto/cipher.go`,
  `GCMCipher`): `iv = packet_id (4 B, big-endian) ‖ implicit_iv (8 B)`. The
  implicit IV is the nonce tail taken from the key block's HMAC slot. The XOR
  form in openvpn3-core `crypto/data_epoch.cpp` is a *different* nonce belonging
  to the epoch-key data v3 format, which this client does not implement.
- GCM AAD is the header: 8 bytes for P_DATA_V2 (opcode+peer_id+packet_id),
  4 for P_DATA_V1 (the packet id alone; `aeadHeaderLen` is 0 there). Under CBC
  the P_DATA_V2 header is not authenticated at all and the packet id lives in
  the first 4 plaintext bytes.
- Which of V1/V2 a channel speaks is fixed at construction and never revisited:
  a server that pushes no peer-id gets P_DATA_V1 (`datachannel.WireFormat`).
- Replay protection: a **64-bit** sliding window on the packet id
  (`replayWindowSize`), matching stock OpenVPN's `--replay-window` default
  rather than openvpn3-core's 2048-bit one.
- Key renegotiation: `reneg-sec` defaults to 3600 s
  (`datachannel.DefaultRenegSec`). There is **no default byte threshold** —
  `DefaultRenegBytes` is 0, meaning no byte-limit renegotiation unless the
  profile sets `reneg-bytes`.

**PUSH_REPLY parsing**
- After auth: server sends PUSH_REPLY with comma-separated options
- Critical options: `ifconfig`, `route`, `dhcp-option DNS`, `redirect-gateway`, `cipher`, `compress`
- Example: `PUSH_REPLY,ifconfig 10.0.0.6 10.0.0.5,route 10.0.0.0 255.255.0.0,dhcp-option DNS 10.0.0.2`

## C++ reference files (current — the authoritative protocol description)

> The shipping engine is pure Go and links none of this. But openvpn3 is not
> "historical background": under
> [`docs/openvpn3-reference-policy.md`](docs/openvpn3-reference-policy.md) it is
> the authoritative description of the wire protocol, and the right first move
> when a protocol question comes up. Cite what you read (§3.3).

All in openvpn3-core (https://github.com/OpenVPN/openvpn3):

| File | What to learn from it |
|---|---|
| `client/ovpncli.cpp` | Full client state machine — Phase 1, Phase 2, CRV1 parsing |
| `ssl/sslctx.hpp` | TLS setup, cert loading, SNI |
| `reliable/reliable.hpp` | Reliable control channel — seq numbers, ACK, window |
| `crypto/crypto_aead.hpp` | Data channel AEAD and the GCM nonce (`set_tail`) — this is the IV construction this client implements. `crypto/data_epoch.cpp` is the *data v3* epoch-key nonce and is **not**: see `internal/crypto/cipher.go` |
| `transport/tcplink.hpp` + `udplink.hpp` | Framing: 2-byte length prefix (TCP), raw (UDP) |
| `ssl/tlsprf.hpp` + `openssl/crypto/tls1prf.hpp` | Classic key derivation: both labels, and the `EVP_md5_sha1()` digest choice. These, not `prf/prfplus.hpp`, are what `internal/prf` cites |
| `tun/builder/base.hpp` | TUN callback interface (what gomobile must expose) |

## Legacy libopenlawsvpn C API (historical — the Go API replaced this)

> This C API no longer exists in any shipping component. It is kept to document
> the semantics the Go `Client` mirrors. Today the surface is the Go `Client`
> struct plus the gomobile `MobileClient`/`MobileCallbacks` in `client_mobile.go`.

```c
// Allocate a new VPN client for the given .ovpn config file path.
// Returns a handle (opaque integer) or -1 on error.
long clientNew(const char* config_path, void* callbacks);

// Phase 1: connect and get the SAML challenge.
// Returns JSON: {"saml_url": "...", "state_id": "...", "remote_ip": "..."}
// Blocks on the calling thread until Phase 1 completes or fails.
const char* clientConnectPhase1(long handle);

// Phase 2: complete connection with the SAML token.
// Returns NULL on success, error string on failure.
// Blocks until the tunnel is established.
const char* clientConnectPhase2(long handle, const char* saml_token);

// Signal disconnect. Non-blocking — clientWaitForDisconnect() waits for teardown.
void clientDisconnect(long handle);

// Block until the client has fully torn down. Call before clientFree().
void clientWaitForDisconnect(long handle);

// Free all resources. Must only be called after clientWaitForDisconnect() returns.
void clientFree(long handle);

// Callbacks (set before clientNew):
typedef void (*tun_establish_fn)(int fd, const char* ifconfig_json);
typedef int  (*socket_protect_fn)(int fd);
typedef void (*log_fn)(const char* message);
```

The Go `Client` struct exposes equivalent semantics via `Connect(ctx)`,
`Disconnect()`, `Stats()`, and the `SAMLTokenFn` / `MobileCallbacks` hooks.

## Repository layout

```
go-openlawsvpn/
  AGENTS.md         — this file (agent/contributor context)
  README.md         — user-facing docs, build instructions, known limitations
  client.go         — top-level Client: Connect, Disconnect, Stats, rekey loop
  client_tun_linux.go   — Linux TUN setup (openNativeTUN)
  client_tun_android.go — Android TUN setup (VpnService fd)
  client_mobile.go  — gomobile API: MobileClient, MobileCallbacks
  profile/          — .ovpn parser
  auth/saml/        — CRV1 SAML challenge handling, ACS server, token TTL
  tun/              — TUN device (Linux + Android via gomobile)
  routing/          — PUSH_REPLY parser, netlink route management (IPv4+IPv6)
  dns/              — DNS push: resolv.conf / systemd-resolved
  internal/
    framing/        — wire format, opcodes, 2-byte length prefix
    reliable/       — control channel reliable transport (sliding window)
    ctls/           — TLS over control channel (crypto/tls via net.Pipe)
    prf/            — OpenVPN key derivation PRF (HMAC-SHA256) + TLS-EKM
    crypto/         — data channel cipher suite (AES-256-GCM / CBC)
    datachannel/    — encrypt/decrypt pipeline, replay window, key rotation
    compress/       — lz4-v2 / comp-lzo uncompressed stub framing
    mssfix/         — software TCP MSS clamping (SYN/SYN-ACK rewrite)
  mock/mockserver/  — pure-Go mock OpenVPN3 server (no openvpn3-core dependency)
  testenv/          — integration test harness (starts mock server in-process)
  cmd/cli/          — Linux CLI with SAML flow and reconnect loop
  cmd/relay-server/ — relay server binary
```

## Development rules

- Every exported function and type must have a doc comment.
- Integration tests must be tagged `//go:build integration` and must pass against the mock server.
- Unit tests (`go test ./...`) must pass with no network access.
- No CGo anywhere — `CGO_ENABLED=0` must build cleanly.
- Protocol constants go in `internal/framing/opcodes.go` with comments citing the openvpn3-core source line.
- When in doubt about protocol behaviour: read openvpn3-core source first, then write a test against the mock server.

## Where to start

The protocol is fully implemented and tested against a real AWS Client VPN
endpoint. Start by reading:

1. `client.go` — top-level state machine; `Connect`, `connectPhase1`,
   `connectPhase2`, `rekeyLoop`, `tunToWire`, `wireToTun`
2. `internal/framing/opcodes.go` — all wire-format opcodes with openvpn3-core
   source references
3. `mock/mockserver/main.go` — the in-process mock server used by integration
   tests; run with `go run ./mock/mockserver` to observe the full handshake

To run integration tests against the local mock:
```bash
go test -v -tags=integration -timeout 120s .
```

To build and run the CLI (requires root for TUN):
```bash
go build -o /tmp/openlawsvpn-cli ./cmd/cli
sudo /tmp/openlawsvpn-cli -config path/to/profile.ovpn
```

**NOTE:** The CLI uses `-config <path>` as a named flag. There is no positional argument and no `connect` subcommand.
