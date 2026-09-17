# Changelog

All notable user-facing changes to go-openlawsvpn are documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and releases follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `saml.ACSServer.Close()`: releases the ACS listener on 127.0.0.1:35001 and
  drops any connection still open on it. `NewACSServer` binds the port so the
  caller learns it is unavailable before opening a browser, but a caller that
  then abandoned the attempt before reaching `Wait` had no way to give the port
  back, and it stayed bound for the life of the process. `Close` is idempotent
  and may be called while a `Wait` is parked.
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
- `Profile.TLSAuth`, `Profile.TLSCrypt` and `Profile.KeyDirection`: the inline
  `<tls-auth>` and `<tls-crypt>` bodies are now parsed as 2048-bit static keys.
  An absent `key-direction` is a distinct value from 0, because OpenVPN treats
  it as a third behaviour rather than a default. The key material is redacted
  from every rendering of a profile by construction.
- `Profile.Remotes`: every `remote` line is now retained, in file order, as a
  host, a port and an optional per-remote protocol. `Profile.Remote`, `Port`
  and `Proto` remain and are the first entry.
- `profile.ParseProto`, the single normaliser for both places a profile names a
  transport. The address-family spellings — `udp4`, `tcp6-client` and the rest
  — now parse instead of being rejected, reduced to the transport they name.
- `netstack.Net.Ping` and `netstack.Net.Gateway`: an ICMP echo through the
  tunnel, and the peer's own tunnel-side address to send it to. The payload is
  chosen by the caller and echoed back verbatim, which makes it a measurement
  rather than a reachability check — a peer that compresses the reply can be
  detected no other way, because a tunnel carrying incompressible traffic looks
  exactly like one whose peer never compresses. IPv4 only.
- The `device` package: the tunnel-device seam. `device.Backend` turns the
  parameters a server pushed into a `device.Device` — raw IP packets, no framing
  — so the client core no longer knows whether they reach a kernel interface or
  a descriptor a host handed it, and everything privileged lives behind a
  backend and is unwound in `Device.Close`. Two ship with it: `device/kernel`, a
  kernel TUN with netlink routes and host DNS, and `device/fd`, a descriptor
  whose host owns its addressing; `device.Kind` names which one a session used.
- The `netstack` package: a userspace tunnel backend, one gVisor network stack
  per tunnel inside this process. It implements `device.Backend` and
  `device.Device` over a gVisor channel endpoint, creating no interface,
  installing no route and rewriting no resolver, so several tunnels in one
  process cannot collide over an interface name, a route table or
  `/etc/resolv.conf`. Its `Net` mirrors the standard library's dialers, and it
  is the only backend that needs no privilege at all.
- `push-continuation` reassembly, in `routing.PushAccumulator`. A server whose
  reply does not fit OpenVPN's 1024-byte bundle splits it across several
  `PUSH_REPLY` messages, each but the last ending `push-continuation 2`; the
  client read the first and brought the tunnel up with whatever part of the
  configuration happened to fit. Fragments are now joined before anything is
  parsed, bounded at `routing.MaxPushFragments` — 64, because the reference
  bounds it not at all and the loop is peer-controlled.
- Pushed `tun-mtu` and pushed `auth` are read: `routing.PushOptions.TunMTU` and
  `routing.PushOptions.Auth`. Both were discarded before, so a server that sized
  the tunnel or chose the data-channel digest for the session was overruled by
  whatever the profile said. The pushed digest outranks the profile's, as
  OpenVPN does it, and the `auth` case matches the whole keyword so `auth-token`
  cannot land in it.

### Changed

- **Breaking:** `dns.Apply` is now
  `Apply(cfg *Config, ifName string) (Backend, string, error)`. It took a
  `backupPath` and returned `(Backend, error)`; the backup path is now chosen by
  whichever backend needs one and handed back as the second result, because only
  that backend knows whether it made a backup or what it was called.

- The `auth` digest now defaults to SHA1, matching OpenVPN, where it previously
  defaulted to SHA256. `Profile.AuthSet` distinguishes a profile that named a
  digest from one that did not.
- `redirect-gateway` installs two /1 routes, `0.0.0.0/1` and `128.0.0.0/1`,
  instead of replacing the host's default with its own `0.0.0.0/0`, and covers
  IPv6 with four prefixes rather than a `::/0`. Each wins by longest-prefix
  match over whatever default the host carries, so nothing is deleted and
  restored and an interrupted teardown cannot leave the host with no default at
  all. The flag words are read too, into `PushOptions.RedirectFlags`: `local`,
  `autolocal`, `ipv6` and `!ipv4` are acted on, the rest recorded and reported.
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
- **Breaking:** `routing.PushOptions.RedirectGateway6`. The `ipv6` flag word is
  now one bit of `PushOptions.RedirectFlags`, and `PushOptions.RedirectsIPv6()`
  reads it — a nil-safe method rather than a second field, because two ways to
  say one thing are two things that can disagree. A caller that tested the
  field calls the method.

### Fixed

- Re-authenticating against an AWS endpoint no longer loses the ACS port to
  itself. `saml.ACSServer.Wait` returned while a separate goroutine was still
  closing the listener, so the next `NewACSServer` — AWS hardcodes the callback
  to 127.0.0.1:35001, so there is no other port to take — could fail to bind and
  silently leave the user pasting the assertion by hand. `Wait` now releases the
  listener before it returns, on every path. In a loop that cancels and rebinds
  immediately, this failed 28 times in 100 and is now clean in 300.
- The browser gets the "Authentication successful" page. `Wait` tore the server
  down the moment the token reached it, from inside the handler and before the
  page had left the connection, so a user who had just authenticated could be
  shown a connection error instead. Measured at roughly 1 round in 1000; clean
  in 2000 now.
- The third field of a `remote` line — OpenVPN's per-remote protocol — is now
  read instead of discarded. A profile whose only statement of transport was
  `remote <host> <port> tcp-client` was dialed over UDP, and the resulting
  failure was indistinguishable from a dead endpoint. Such a profile had never
  established a session; sampled endpoints now connect.
- The endpoint dialed from a profile carrying several `remote` lines is now the
  first, as in OpenVPN, rather than the last. Each line used to overwrite the
  one above it.
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
- A `route` line whose gateway is `net_gateway` or `remote_host` no longer fails
  the whole `PUSH_REPLY`. `net.ParseIP` returned nil for the symbolic name and
  the parser raised `invalid gateway`, which ended the session at `StagePush`
  with a protocol error — one route the client could not place cost the whole
  configuration. The names are parsed into `Route.Symbolic`, and a route that
  asks to go around the tunnel is left out of the plan rather than sent to the
  tunnel's own gateway.
- `routing.LookupGateway` truncated every IPv6 next hop to its first four bytes.
  `parseRouteGateway` allocated a four-byte destination and copied the netlink
  `RTA_GATEWAY` attribute into it, and Go's `copy` stops at the shorter slice,
  so a 16-byte next hop became a bogus IPv4-shaped address with no error. The
  attribute is now walked with the standard library's own netlink parser and
  returned at its natural width, and the lookup takes either family instead of
  refusing anything that is not IPv4.
- The macOS utun labelled every packet AF_INET. A utun prepends a four-byte
  address family and injects by it rather than by reading the packet, so an
  IPv6 packet labelled AF_INET is dropped on its version nibble: with a pushed
  `ifconfig-ipv6` on the interface, a dual-stack tunnel sent IPv6 out and
  discarded everything that came back — a tunnel that connects, reports green
  and carries half its traffic. The header now follows the packet's version, and
  macOS and iOS share one copy of the framing in `tun/tun_utun.go`.
- `dns.Apply` no longer leaves an empty backup file in `TMPDIR` on every
  connection attempt. The caller created the temporary resolv.conf backup
  before calling `Apply`, unconditionally, and `Apply` wrote it only on the path
  that edits `/etc/resolv.conf` — so a host served by systemd-resolved or
  scutil, or pushed no DNS at all, collected a zero-byte
  `openlawsvpn-resolv-*.conf` per attempt, one per reconnect. The backup is now
  made by the one path that uses it, which is why `Apply` hands the path back.
- The relay agent allocated whatever a frame header declared. `readMessage` read
  the WebSocket length field and called `make` on it before a single payload
  byte arrived, so ten bytes on the wire could ask for a gigabyte the peer never
  had to send. A frame, and a fragmented message in total, is now bounded before
  anything is allocated. The same reader truncated 64-bit lengths to their low
  32 bits, turning a declared 2^32 into a zero-length frame and 2^32+n into an
  n-byte one, which then desynchronised it against the stream.
- The local relay server leaked a goroutine per connection and refused its own
  agent's registration. Its writer goroutine ranged over a channel that only the
  deferred `unregisterConn` closed, and that defer could not run until the
  handler returned, which was waiting on the writer — a circular wait leaking
  both goroutines and the hijacked `net.Conn` per dropped connection. And it
  demanded `token`, `agent_id` and `hostname` as URL query parameters, answering
  400 before the upgrade, while the agent sends them in its first text frame.

### Security

- A SAML assertion callback port this client cannot bind is now reported as
  that condition — `saml.ErrACSPortBusy`, a `local` failure at the `auth`
  stage — instead of as an unexplained listen error. AWS fixes the callback to
  `127.0.0.1:35001` and the ACS server now runs in the system daemon, where the
  port is not partitioned by user: whatever holds it receives the identity
  provider's POST, which carries the assertion.

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
