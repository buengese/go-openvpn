# go-openvpn

Pure-Go implementation of the OpenVPN client protocol — certificate,
username/password, and AWS Client VPN's federated SAML/CRV1 authentication.

Zero C dependencies. `CGO_ENABLED=0` builds a fully static binary.
`gomobile bind` produces an `.aar` for Android without NDK or CMake.
See [CHANGELOG.md](CHANGELOG.md) for project-wide release notes.

## Status

Working end-to-end on Linux and macOS (CLI), on Android and iOS (via the
gomobile bindings), and on the Linux desktop through
[go-openvpn-linux](https://github.com/buengese/go-openvpn-linux), which
consumes this module. Find the current release with
`git tag --list 'v*' --sort=-v:refname | head -1`. The `.aar` build pipeline is in
`.github/workflows/aar.yml`. The desktop packages (RPM via COPR, Arch via
the AUR) are released from go-openvpn-linux.

> **AWS support boundary:** AWS documents SAML-based Client VPN connections as
> supported only with the AWS-provided client. This repository implements the
> compatible CRV1 wire flow as an unsupported third-party client. Use the
> AWS-provided client when AWS-supported operation is required.

### Components

| Component | Description |
|---|---|
| `cmd/cli` | `go-openvpn-cli` — CLI client with `-auth-user-pass`, the SAML browser flow, a reconnect loop, and relay agent mode (`-relay`) |
| `cmd/relay-server` | Local relay server for dev/testing without hitting production |

## Use as a library

```go
p, err := profile.ParsePath("/etc/openvpn/client.ovpn")
if err != nil {
	log.Fatal(err)
}
c := vpn.New(p)

// Whatever the profile authenticates with, supply that and nothing else:
// a cert-only profile needs no callback at all.
c.CredentialsFn = func(ctx context.Context) (vpn.Credentials, error) {
	return vpn.Credentials{Username: user, Password: pass}, nil
}
c.SAMLTokenFn = func(ctx context.Context, ch vpn.SAMLChallenge) (string, error) {
	// open ch.URL in a browser and return the SAMLResponse it posts back
	return awaitSAMLResponse(ctx, ch.URL)
}

if err := c.Connect(ctx); err != nil {
	log.Fatal(err)
}
defer c.Disconnect()
```

With no file to parse, describe the tunnel instead. `Spec.Build` renders the
directives a profile would have carried and runs them through the same
assembler the parser uses, so there is no value it can produce that a file
could not:

```go
p, err := profile.Spec{
	Remotes: []profile.Endpoint{{Host: "vpn.example.com", Port: 1194}},
	Proto:   "udp",
	CA:      caPEM,
	Cert:    certPEM,
	Key:     keyPEM,
	Cipher:  "AES-256-GCM",
}.Build()
if err != nil {
	log.Fatal(err)
}

// From here on p is a *profile.Profile like any other, so the rest is the
// snippet above.
c := vpn.New(p)
if err := c.Connect(ctx); err != nil {
	log.Fatal(err)
}
defer c.Disconnect()
```

However a connection ends, `c.Report()` describes the attempt: the stages it
reached, the class of the failure that stopped it, and what the peer
negotiated. `Redacted()` is the only marshallable form — credentials,
certificates and pushed options are scrubbed before serialisation.

## Build

```bash
# Linux CLI (direct, no daemon)
CGO_ENABLED=0 go build -o go-openvpn-cli ./cmd/cli
sudo ./go-openvpn-cli -config your.ovpn

# Add "verb 4" to the profile to log the verified server certificate.

# Public relay demo.
sudo ./go-openvpn-cli -relay default -daemon \
  -logfile /tmp/vpn.log -pidfile /tmp/vpn.pid

# Private relay token (CI/CD headless auth); token file must be mode 0600.
sudo ./go-openvpn-cli -relay-token-file /run/user/$UID/go-openvpn-relay-token \
  -daemon -logfile /tmp/vpn.log -pidfile /tmp/vpn.pid

# Android .aar (requires gomobile + Android NDK)
gomobile bind -o go-openvpn.aar -target android -androidapi 31 \
    github.com/buengese/go-openvpn
```

With `verb 4`, the client logs the verified server certificate during every
TLS handshake in an OpenSSL-like format: subject, issuer, serial number,
validity period, DNS names, and SHA-256 fingerprint. This is the certificate
used to authenticate the VPN server; it is not the user's SAML or client
certificate.

## Test

```bash
# The default gate — no build tag, no Docker, no root:
make test

# End-to-end against the local mock server — no Docker either:
make test-mock
```

The other passes — mobileapi, docker, privileged and soak — each have their own
`make` target; `make test` runs the mobileapi one as well, because it needs
nothing. There is no `integration` tag: [docs/testing.md](docs/testing.md)
lists every pass, the one command that runs it, and what it costs.

## CI / CD

| Workflow | Trigger | What it does |
|---|---|---|
| **CI** (`ci.yml`) | push / PR to `main` or `dev` | Go builds, race tests, and vet; also drives the CLI against the mock server on ubuntu and macOS, with and without `redirect-gateway` |
| **Build AAR** (`aar.yml`) | push tag `v*` or manual | builds `go-openvpn.aar` via `gomobile bind`, publishes GitHub Release, opens a version-bump PR on `openlawsvpn-android-go` |
| **Build xcframework** (`xcframework.yml`) | push tag `v*` or manual | builds `go-openvpn.xcframework` for ios / iossimulator / macos, attaches the zip and its SHA-256 to the GitHub Release, dispatches a `bump-xcframework` event to `openlawsvpn-ios` |
| **Release** (`release.yml`) | push tag `v*` or manual | builds the static `cli` binary for linux amd64 / arm64 / ppc64le and darwin arm64 / amd64, GPG-signs and attests each, attaches them to the GitHub Release |
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

**Cross-repo auth:** writes use the `go-openvpn-ci` GitHub App via
`actions/create-github-app-token` — secrets `CI_APP_ID` / `CI_APP_PRIVATE_KEY`.
There is no `ANDROID_GO_PAT` PAT.

## Known limitations

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
