# go-openvpn

Pure-Go library implementing the OpenVPN client protocol — certificate,
username/password, and federated SAML authentication over AWS Client VPN's
CRV1 exchange.

Zero C dependencies. `CGO_ENABLED=0` builds a fully static binary.
`gomobile bind` produces an `.aar` for Android without NDK or CMake.
Based on [go-openlawsvpn](https://github.com/openlawsvpn/go-openlawsvpn).
See [CHANGELOG.md](CHANGELOG.md) for release notes.

## Status

Working end-to-end on Linux and macOS through `cmd/cli`, and on Android and iOS
through the gomobile bindings; `make check-platforms` builds every supported
target. Find the current release with
`git tag --list 'v*' --sort=-v:refname | head -1`.

> **AWS support boundary:** AWS documents SAML-based Client VPN as supported
> only with the AWS-provided client. The CRV1 flow here is a third-party
> implementation of the same wire protocol.

## AI Disclosure

Very significant parts of this libraries code where produced by generative AI with openvpn3 as a direct reference (See [reference policy](docs/openvpn3-reference-policy.md)). All code was reviewed by human and extensively tested however the goal of this project was producing an openvpn client good enough for a measurement tool. As such it's not nearly as battle tested or as thoroughly reviewed for security issues as openvpn3 or openvpn.

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

// Every log line comes through EventFn, so nothing reaches a destination you
// did not choose. StderrEvents is the ready-made sink; a consumer with
// structured logging writes its own instead.
c.EventFn = vpn.StderrEvents

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

Before dialling, `caps.Inspect` grades a parsed profile against what the client
implements, so a directive nobody has considered fails during preflight rather
than mid-handshake.

However a connection ends, `c.Report()` describes the attempt: the stages it
reached, the class of the failure that stopped it, and what the peer
negotiated. `Redacted()` is the only marshallable form — credentials,
certificates and pushed options are scrubbed before serialisation.

## Build

```bash
# Static CLI
CGO_ENABLED=0 go build -o go-openvpn-cli ./cmd/cli
sudo ./go-openvpn-cli -config your.ovpn

# Relay agent mode. A private token file must be mode 0600.
sudo ./go-openvpn-cli -relay default -daemon -logfile /tmp/vpn.log
sudo ./go-openvpn-cli -relay-token-file /run/user/$UID/go-openvpn-relay-token -daemon

# Android .aar (requires gomobile + Android NDK)
gomobile bind -o go-openvpn.aar -target android -androidapi 31 \
    github.com/buengese/go-openvpn
```

With `verb 4` in the profile, every TLS handshake logs the verified server
certificate OpenSSL-style: subject, issuer, serial, validity, DNS names and
SHA-256 fingerprint. It goes through `EventFn` like every other log line, so it
lands wherever the consumer sends it. That is the certificate the server is
authenticated by, not the user's own.

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
| **CI** (`ci.yml`) | push / PR to `main`, `dev` | builds, race tests, vet, and the CLI against the mock server on ubuntu and macOS, with and without `redirect-gateway` |
| **Build AAR** (`aar.yml`) | tag `v*` or manual | `gomobile bind` to `go-openvpn.aar`, attaches it and its SHA-256 to the Release, opens a version-bump PR on `openlawsvpn-android-go` |
| **Build xcframework** (`xcframework.yml`) | tag `v*` or manual | `go-openvpn.xcframework` for ios / iossimulator / macos, zip and SHA-256 on the Release, dispatches `bump-xcframework` to `openlawsvpn-ios` |
| **Release** (`release.yml`) | tag `v*` or manual | static `cli` binaries for linux amd64 / arm64 / ppc64le and darwin arm64 / amd64, each GPG-signed and attested |
| **VPN Integration** (`vpn-integration.yml`) | manual | integration run against a live endpoint |

The library's version is its tag; no file in the tree carries it. To release,
move the `Unreleased` entries in `CHANGELOG.md` under the new version and date,
add a fresh empty `Unreleased`, commit, then `git tag vX.Y.Z && git push origin
vX.Y.Z`. Cross-repo writes use the `go-openvpn-ci` GitHub App via
`actions/create-github-app-token` — secrets `CI_APP_ID` / `CI_APP_PRIVATE_KEY`.

## Known limitations

**A SAML assertion is single-use.** AWS binds the assertion to the original
`AuthnRequest` ID and marks it consumed on first use, so retrying with the same
token returns `AUTH_FAILED,Invalid username or password` even inside the token's
TTL. A reconnect succeeds while the server's CRV1 session is still alive; once
that has expired, the browser flow has to run again.

## License

LGPL-2.1-or-later with usage exception.
See [LICENSE](LICENSE) and [LICENSE_USAGE_EXCEPTION](LICENSE_USAGE_EXCEPTION) for details.
