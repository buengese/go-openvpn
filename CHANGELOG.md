# Changelog

All notable user-facing changes to go-openlawsvpn are documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and releases follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `diag.ClassServerBusy` and `diag.Error.RetryAfter`: a server that answers
  `PUSH_REQUEST` with `AUTH_FAILED,TEMP` has declined this attempt and asked us
  back, which is neither a credential rejection nor a protocol fault. It now has
  its own class, carries the backoff the server named, and is retried — see
  Fixed below.
- New exported `diag` package: the diagnostics vocabulary for connection
  attempts — typed error classes, connection stages, capability gaps, and a
  `SessionReport` that redacts credentials, certificates and pushed options
  before serialisation. Every connection attempt now produces one, on success
  and on failure alike, reachable through `Client.Report()`.
- Data-channel breadth: AES-128, AES-192 and AES-256 in both GCM and CBC, with
  CBC authenticated by HMAC-SHA1, HMAC-SHA256 or HMAC-SHA512.
- A control-channel replay window, separate from the reliable layer's own
  sequence numbers. Replayed and stale-timestamped control packets are rejected
  and counted in `diag.Counters` rather than dropped silently.

### Changed

- `mssfix N` is read as a link budget rather than as an MTU. The directive
  bounds the whole encapsulated packet, so `internal/mssfix.MaxMSS` subtracts
  the transport prefix, the opcode and peer-id, the packet id, the cipher's tag
  or IV and digest, any compression byte and the inner IP and TCP headers before
  clamping — deriving 1336 from `mssfix 1400` for AES-GCM over UDP with a
  peer-id, where the old `ClampToMTU` subtracted the inner headers alone and
  clamped to 1360. The number a profile gets therefore changes.

### Removed

- The Linux desktop app — the GTK GUI, the D-Bus system daemon and the RPM/AUR
  packaging — moved to its own repository,
  [openlawsvpn-linux](https://github.com/openlawsvpn/openlawsvpn-linux), with
  its history, its security architecture document and its version scripts.
  This module is the engine and `openlawsvpn-cli`; the desktop app consumes it
  as a dependency, the way the Android and iOS apps do, and builds the CLI it
  packages from this module. Nothing in this tree carries a version any more:
  the release tag is the version, and the release workflows no longer check it
  against a spec, a PKGBUILD or a Cargo manifest.

### Fixed

- The compression framing bytes were inverted, and the client announced
  `0x69` — *this payload is LZ4-compressed* — over plaintext on every packet of
  a `compress lz4` session. `0x69` means compressed and `0xFA` means not; both
  are now read from a peer's own captured bytes.
- Data-channel keys for AES-CBC were taken from the wrong halves of the key
  block, transposing the transmit and receive HMAC keys. The mapping now exists
  in one place and both cipher modes read it.
- The server's key-method-2 packet is now read field by field instead of being
  drained into a fixed buffer, so a truncated packet is reported as a protocol
  error rather than parsed from whatever had arrived.
- The relay agent allocated whatever a frame header declared. `readMessage` read
  the WebSocket length field and called `make` on it before a single payload
  byte arrived, so ten bytes on the wire could ask for a gigabyte the peer never
  had to send. A frame, and a fragmented message in total, is now bounded before
  anything is allocated. The same reader truncated 64-bit lengths to their low
  32 bits, turning a declared 2^32 into a zero-length frame and 2^32+n into an
  n-byte one, which then desynchronised it against the stream.
- The local relay server refused its own agent's registration. It demanded
  `token`, `agent_id` and `hostname` as URL query parameters, answering 400
  before the upgrade, while the agent sends them in its first text frame.

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

[Unreleased]: https://github.com/openlawsvpn/go-openlawsvpn/compare/v1.2.3...HEAD
[1.2.3]: https://github.com/openlawsvpn/go-openlawsvpn/compare/v1.2.2...v1.2.3
[1.2.2]: https://github.com/openlawsvpn/go-openlawsvpn/compare/v1.2.1...v1.2.2
[1.2.1]: https://github.com/openlawsvpn/go-openlawsvpn/compare/v1.2.0...v1.2.1
[1.2.0]: https://github.com/openlawsvpn/go-openlawsvpn/compare/v1.1.9...v1.2.0
