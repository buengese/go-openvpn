# go-openlawsvpn

Pure-Go OpenVPN3 client protocol implementation — AWS Client VPN + SAML/CRV1 flow.

Zero C dependencies. `CGO_ENABLED=0` builds a fully static binary.
`gomobile bind` produces an `.aar` for Android without NDK or CMake.
See [CHANGELOG.md](CHANGELOG.md) for project-wide release notes.

## Status

Working end-to-end on Linux and macOS (CLI), on Android and iOS (via the
gomobile bindings), and on the Linux desktop through
[openlawsvpn-linux](https://github.com/openlawsvpn/openlawsvpn-linux), which
consumes this module. Find the current release with
`git tag --list 'v*' --sort=-v:refname | head -1`. The `.aar` build pipeline is in
`.github/workflows/aar.yml`. The desktop packages (RPM via COPR, Arch via
the AUR) are released from openlawsvpn-linux.

> **AWS support boundary:** AWS documents SAML-based Client VPN connections as
> supported only with the AWS-provided client. This repository implements the
> compatible CRV1 wire flow as an unsupported third-party client. Use the
> AWS-provided client when AWS-supported operation is required.

### Components

| Component | Description |
|---|---|
| `cmd/cli` | `openlawsvpn-cli` — CLI client with SAML flow, reconnect loop, and relay agent mode (`-relay`) |
| `cmd/relay-server` | Local relay server for dev/testing without hitting production |

## Build

```bash
# Linux CLI (direct, no daemon)
CGO_ENABLED=0 go build -o openlawsvpn-cli ./cmd/cli
sudo ./openlawsvpn-cli -config your.ovpn

# Add "verb 4" to the profile to log the verified server certificate.

# Public relay demo.
sudo ./openlawsvpn-cli -relay default -daemon \
  -logfile /tmp/vpn.log -pidfile /tmp/vpn.pid

# Private relay token (CI/CD headless auth); token file must be mode 0600.
sudo ./openlawsvpn-cli -relay-token-file /run/user/$UID/openlawsvpn-relay-token \
  -daemon -logfile /tmp/vpn.log -pidfile /tmp/vpn.pid

# Android .aar (requires gomobile + Android NDK)
gomobile bind -o go-openlawsvpn.aar -target android -androidapi 31 \
    github.com/openlawsvpn/go-openlawsvpn
```

With `verb 4`, the client logs the verified server certificate during every
TLS handshake in an OpenSSL-like format: subject, issuer, serial number,
validity period, DNS names, and SHA-256 fingerprint. This is the certificate
used to authenticate the VPN server; it is not the user's SAML or client
certificate.

## Test

```bash
# Unit tests (no network):
go test -race ./...

# Integration tests (runs local mock server — no Docker required):
go test -v -tags=integration -timeout 120s .
```

## CI / CD

| Workflow | Trigger | What it does |
|---|---|---|
| **CI** (`ci.yml`) | push / PR to `main` | Go builds, race tests, and vet |
| **Build AAR** (`aar.yml`) | push tag `v*` or manual | builds `go-openlawsvpn.aar` via `gomobile bind`, publishes GitHub Release, opens a version-bump PR on `openlawsvpn-android-go` |
| **Release** (`release.yml`) | push tag `v*` or manual | builds static `cli` binaries for amd64 / arm64 / ppc64le, attaches them to the GitHub Release |
| **VPN Integration** (`vpn-integration.yml`) | manual | integration run against a live endpoint |

### Publishing a new release

The library's version is its tag; no file in the tree carries it. Move the
`Unreleased` entries in `CHANGELOG.md` to the new version and date, add a
fresh empty `Unreleased` section, commit, then tag:

```bash
git tag vX.Y.Z
git push origin vX.Y.Z
```

The `aar.yml` workflow builds the AAR, attaches it (with SHA-256) to the GitHub
Release, then triggers `bump-aar.yml` on `openlawsvpn-android-go` — which opens a
PR bumping the pinned AAR version automatically.

**Cross-repo auth:** writes use the `openlawsvpn-ci` GitHub App via
`actions/create-github-app-token` — secrets `CI_APP_ID` / `CI_APP_PRIVATE_KEY`.
There is no `ANDROID_GO_PAT` PAT.

## Known limitations

### OpenVPN-PRF key derivation (plain OpenVPN 2.x)

AWS Client VPN always negotiates TLS-EKM (`key-derivation tls-ekm` in
PUSH_REPLY), so key derivation is fully correct for that use case.

Plain OpenVPN 2.x servers that do **not** push `key-derivation tls-ekm` use
the OpenVPN-PRF method, which requires the TLS `ServerRandom` (the 32-byte
random from the server's `ServerHello`). Go's `crypto/tls` does not expose
this value in `ConnectionState`, so the fallback path substitutes zeros. The
TLS handshake and authentication succeed, but the derived data-channel keys
will be wrong — packets fail to decrypt and no traffic flows.

No fix is possible without forking `crypto/tls`. Track the upstream Go
proposal if plain OpenVPN 2.x support without EKM becomes a requirement.

### SAML assertion is single-use

AWS Client VPN SAML assertions are cryptographically bound to the original
`AuthnRequest` ID. The server marks the assertion consumed on first use.
Retrying Phase 2 with the same token returns `AUTH_FAILED,Invalid username
or password` even within the token's TTL.

For reconnects: if the server's CRV1 session is still alive the client can
reconnect with the cached token. If the session has expired (`AUTH_FAILED`),
the user must complete the browser SAML flow again.

## License

LGPL-2.1-or-later with usage exception.
See [LICENSE](LICENSE) and [LICENSE_USAGE_EXCEPTION](LICENSE_USAGE_EXCEPTION) for details.
