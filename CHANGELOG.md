# Changelog

All notable user-facing changes to go-openvpn are documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and releases follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-10-08

go-openvpn is no longer only an AWS Client VPN client. It now connects to stock
OpenVPN 2.4, 2.5 and 2.6 servers and to the profiles commercial providers
publish: the classic key derivation, CBC ciphers, `tls-auth` and `tls-crypt`,
username and password, compression, several remotes with failover, and the
directives such profiles carry. All of it is tested against stock OpenVPN in
the Docker matrix. Every attempt now produces a diagnostic report, and the
tunnel can run fully in userspace. The module is renamed and the desktop app
has moved out; see Breaking changes.

### Breaking changes

- The module is `github.com/buengese/go-openvpn`; update every import path.
  The CLI is `go-openvpn-cli`, environment variables are `GO_OPENVPN_*`, and
  the gomobile artifacts are `go-openvpn.aar` and `go-openvpn.xcframework`
  (inner framework `Go-Openvpn.framework`). `x-openlawsvpn-flow` is still
  read; new profiles should say `x-go-openvpn-flow`.
- `Client.TUNSetup` is replaced by `Client.Device`, a `device.Backend`. A host
  that supplied a descriptor sets `fd.Backend{Establish: …}`; nil still means
  the kernel backend.
- A nil `EventFn` on `Client` or `netstack.Options` is silent. Set
  `EventFn: vpn.StderrEvents` for the old output.
- `dns.Apply(cfg, ifName, logf)` returns `(Backend, backupPath, error)`; it
  chooses the backup path itself and logs through `logf`.
- Authentication flow names: `Profile.ForceSAMLFlow` is `Profile.Federated`,
  `DetectFlow()` is `AuthFlow()`, `FlowAWSSSO` is `FlowFederated`, and
  `FlowCertAuth` is the zero value. `AuthFlow()` no longer infers SAML from an
  AWS hostname; the client applies `saml.IsAWSEndpoint` when it authenticates.
- Removed: `routing.PushOptions.RedirectGateway6` (use `RedirectsIPv6()`),
  `Client.ResetForTest`, `Client.ConnectPhase2Reuse` (use `ConnectPhase2`),
  and from `auth/saml` the AWS second-exchange helpers
  (`BuildPhase2Username`, `CompletePhase2`, …) and the control-message types
  (`MsgKind`, `SessionMonitor`, …), which are now internal.

### Added

Servers and profiles:

- Classic OpenVPN key derivation, for every server before 2.6, and an RFC 5705
  exporter for TLS 1.2 without Extended Master Secret, which `crypto/tls`
  refuses and OpenSSL performs.
- AES-128, AES-192 and AES-256 in GCM and CBC, CBC with HMAC-SHA1, SHA256 or
  SHA512. The `auth` digest defaults to SHA1, as in OpenVPN; a pushed `auth`
  wins.
- `tls-auth` and `tls-crypt`, with a control-channel replay window.
- The `P_DATA_V1` wire format, for servers that push no peer-id.
- Compression: all four OpenVPN framings (`comp-lzo`, `compress`,
  `compress lz4`, `compress lz4-v2`/`stub-v2`), `allow-compression`, and LZO
  decompression through `github.com/buengese/go-lzo`. Nothing is compressed on
  send; an LZ4-compressed payload ends the session as unsupported.
- Username and password: `Client.CredentialsFn` (also on `netstack.Options`)
  and `MobileClient.SetCredentials` for Android and iOS.
- Several `remote` lines, tried in order (shuffled with `remote-random`), each
  with its own port and protocol; `udp4`, `tcp6-client` and the other address
  family spellings parse.
- File-referenced `ca`, `cert` and `key`, read from the profile's directory
  and confined to it: `profile.ParseFileIn` and `profile.ParseFileInFS`.
- Server certificate checks: `verify-x509-name` in all three match types,
  `ns-cert-type server` and `remote-cert-tls server`.
- Directives now read: `ping`, `ping-restart` (0 disables the timer),
  `ping-exit`, `keepalive`, `hand-window`, the `mssfix` mode and
  `explicit-exit-notify`; from the server, `tun-mtu`, `auth` and
  `push-continuation`.

Embedding:

- `device`: the tunnel-device seam, with `device/kernel` (kernel TUN, routes,
  host DNS) and `device/fd` (a descriptor the host owns).
- `netstack`: a userspace tunnel on a gVisor stack that needs no privileges and
  touches no host state, with `Tunnel.Reconnect`, `Tunnel.Lifetime()` and an
  ICMP `Net.Ping` that can tell whether a peer compresses.
- `profile.Spec`: build a profile in code (`Build`), store it as JSON, recover
  one from a parsed profile (`Profile.Spec()`) and write it out as `.ovpn`
  (`Render`). A stored Spec holds key material.
- `saml.ACSServer.Close()` and `vpn.StderrEvents`.

Diagnostics:

- The `diag` package: typed error classes, connection stages and a redacted
  `SessionReport` for every attempt, through `Client.Report()`,
  `Client.Attempts()` and `diag.Error.Report()`. It records the negotiated
  parameters, every endpoint tried and the data-channel counters.
- `Client.Preflight()`: what a profile asks for that the client cannot honour,
  reported before dialling.
- `diag.ClassServerBusy`: `AUTH_FAILED,TEMP` is retried after the backoff the
  server names.

### Changed

- `Reconnect` works for every authentication flow, resuming from the held
  credentials or SAML assertion, and retries only what a retry can fix: network
  and TLS failures, not configuration or unsupported features.
- Server certificates are verified as OpenVPN verifies them: the chain against
  the profile's CA, plus `serverAuth` with `remote-cert-tls server`. The
  hostname is no longer matched against the certificate's SANs, and
  `verify-x509-name` no longer sets SNI.
- `redirect-gateway` adds `0.0.0.0/1` and `128.0.0.0/1` (four prefixes for
  IPv6) instead of replacing the default route, and honours `local`,
  `autolocal`, `ipv6` and `!ipv4`.
- `mssfix N` bounds the whole encapsulated packet, as in OpenVPN, so the clamp
  is smaller: 1336 rather than 1360 for `mssfix 1400` with AES-GCM over UDP.
- The options string and `IV_CIPHERS` describe the cipher and digest actually
  in use. The AWS literals `N/A` and `ACS::35001` are sent only on the AWS SAML
  flow.
- The `go` directive is 1.25.5, the floor `gvisor.dev/gvisor` sets.
- The test matrix images build on Debian trixie; run `make matrix-images`
  again.

### Fixed

- Connect and Disconnect races: a Disconnect while Connected was announced
  could hang `WaitForDisconnect` or panic a later `Reconnect`; teardown could
  panic on a closed channel; a failing `SAMLTokenFn` leaked the connection.
- `Disconnect` no longer reports a spurious error on a tunnel carrying traffic.
- A renegotiation the server starts is answered instead of dropped.
- A mid-session `AUTH_FAILED`, `RESTART` or `HALT` is noticed on certificate
  and password profiles too, instead of after the ping-restart timeout.
- The SAML ACS server no longer loses port 35001 to itself on
  re-authentication, and the browser reliably gets the success page.
- The first `remote` line is dialled rather than the last, and its protocol
  field is read.
- A pushed `route` via `net_gateway` or `remote_host` no longer fails the whole
  `PUSH_REPLY`.
- IPv6: gateway lookup no longer truncates IPv6 next hops, and the macOS/iOS
  utun no longer drops inbound IPv6.
- `dns.Apply` no longer leaves an empty backup file per attempt.
- A truncated key-method-2 packet from the server is a protocol error rather
  than parsed from what had arrived.
- The relay agent bounds frame sizes before allocating; the local relay server
  no longer leaks a goroutine per connection.
- Receiving a UDP packet no longer allocates 64 KiB.

### Security

- A profile with no usable CA is refused before dialling instead of connecting
  without verifying the server.
- A SAML callback port held by another process is reported as
  `saml.ErrACSPortBusy`, and the CLI no longer offers to take a pasted
  assertion in that case.

---

The releases below were published as `github.com/openlawsvpn/go-openlawsvpn`,
under that module's version numbers.

## [1.2.3] - 2026-08-19

### Fixed

- Detect AWS Client VPN's normalized Phase 2 authentication rejection after a
  network interruption and require a fresh SAML flow instead of retrying the
  cached CRV1 credentials indefinitely.
- Stop the CLI's temporary SAML stdin listener after ACS authentication
  completes, preventing later Enter presses from reopening a stale SAML URL.

### Compatibility

- Brief network interruptions that do not cause AWS to terminate the active
  session can retain the existing TUN interface and tunnel routes, so access
  resumes without a new SAML flow. This is an observed effect of the existing
  liveness/reconnect handling, not a guaranteed AWS session-resumption feature.

## [1.2.2] - 2026-08-17

### Security

- Remove SAML assertions, CRV1 state identifiers, authentication-message
  contents, credential prefixes, and SAML URLs from generic logs and errors.
- Clear cached SAML assertions, CRV1 state, backend affinity, server-issued
  authentication tokens, and TLS secret references after explicit disconnect
  or terminal connection failure. Controlled transient reconnects retain only
  the credentials they require.
- Restrict the localhost SAML ACS callback to bounded form POSTs containing a
  base64-decodable, well-formed SAML protocol `Response`; add HTTP timeouts and
  defensive response headers.
- Clear temporary authentication-packet byte buffers after TLS writes.
- Add protected file and file-descriptor inputs for SAML assertions and private
  relay bearer tokens.

### Added

- Add `BuildPhase2Password` and `WritePhase2Credential` helpers using the
  correct OpenVPN key-method password terminology.
- Add CI policy validation for licenses declared by resolved Rust dependencies.
- Generate and install the exact Rust dependency/license inventory for Arch
  GUI packages; RPM packages continue to generate it with `%cargo_license`.
- Emit a one-time AWS SAML compatibility notice directing users to the AWS VPN
  Client when AWS-supported operation is required.
- Add credential-disclosure, ACS-validation, teardown, and relay CLI
  compatibility regression tests.

### Changed

- Display the maintained GTK open-source notice in the GUI and ship it in RPM
  and Arch GUI packages.
- Explicit `Disconnect` now clears cached authentication material. Internal
  transient-failure reconnects continue to preserve short-lived credentials.
- Authentication failures and unexpected control messages report only their
  non-sensitive message classification.
- `StateWaitingSAML` no longer copies the SAML URL into its generic event
  message; callers continue to receive it through the typed SAML challenge.
- Mock-server authentication events now expose credential type and length
  metadata instead of credential values or prefixes.
- Remove the retired C++ mock stub, superseded capability drop-in, and obsolete
  local mock profile.

### Deprecated

- Deprecate the `-saml-token` command-line argument in favor of
  `-saml-token-file` or `-saml-token-fd`. Daemon mode requires the file form.
- Deprecate `BuildPhase2Username` and `WritePhase2Credentials`; compatibility
  wrappers remain available.

### Compatibility

- `-relay <token>` remains supported in foreground and daemon modes. The public
  `default` organisation selector is not secret; protected token-file inputs
  are optional for private organisation bearer tokens.
- The stricter ACS parser intentionally rejects opaque or malformed demo
  values. Demo integrations must submit a well-formed mock SAML response before
  this release ships.
- The mock-server authentication-event JSON no longer contains `password` or
  `password_prefix`; test tooling should use `credential_kind` and
  `password_len`.

## [1.2.1] - 2026-07-31

### Added

- Support AWS SAML profiles using the `auth-federate` directive.
- Add `verb 4` diagnostics for the verified TLS server certificate, including
  subject, issuer, serial number, validity, DNS names, and SHA-256 fingerprint.

### Fixed

- Honor configured tunnel MTUs.
- Apply OpenVPN 2-compatible default MSS clamping.

## [1.2.0] - 2026-07-30

### Added

- Support full and split DNS from pushed options and profile directives.

### Fixed

- Configure full and split DNS for VPC-private resources on iOS.
- Refresh the GTK profile list immediately after deleting a profile.

[Unreleased]: https://github.com/buengese/go-openvpn/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/buengese/go-openvpn/releases/tag/v1.0.0
[1.2.3]: https://github.com/openlawsvpn/go-openlawsvpn/compare/v1.2.2...v1.2.3
[1.2.2]: https://github.com/openlawsvpn/go-openlawsvpn/compare/v1.2.1...v1.2.2
[1.2.1]: https://github.com/openlawsvpn/go-openlawsvpn/compare/v1.2.0...v1.2.1
[1.2.0]: https://github.com/openlawsvpn/go-openlawsvpn/compare/v1.1.9...v1.2.0
