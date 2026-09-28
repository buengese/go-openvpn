# Changelog

All notable user-facing changes to go-openvpn are documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and releases follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- A username and password can now be supplied through a front door that could
  not take one. The library has driven `auth-user-pass` profiles since
  `CredentialsFn` was added, and the CLI since `-auth-user-pass`, but the
  gomobile binding had no way to pass one across the language boundary, so
  every provider that asks for a password was unreachable from Android and iOS.
  - `MobileClient.SetCredentials(username, password)` in the gomobile binding,
    a method rather than a callback because gomobile cannot bind a function
    value.

  `Connect` is unchanged, so certificate and SAML profiles are unaffected and
  existing callers keep working. The credentials answer every attempt, so a
  reconnect does not prompt again; an empty username or password is refused
  rather than presented to a server as a blank credential; and both halves are
  dropped when the session ends.
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
- `Client.Preflight()` and `Client.PreflightMode`: a capability preflight that
  reports what a profile asks for that the client cannot honour, without
  opening a socket. It refuses the connection by default; the advisory mode
  records the same gaps and continues, for measurement.
- Support for stock OpenVPN 2.4 and 2.5 servers. The client now performs the
  classic OpenVPN key derivation, so it connects to deployments that do not
  offer the TLS keying-material exporter — which is every OpenVPN server before
  2.6 and most commercial providers.
- Data-channel breadth: AES-128, AES-192 and AES-256 in both GCM and CBC, with
  CBC authenticated by HMAC-SHA1, HMAC-SHA256 or HMAC-SHA512.
- Support for `tls-auth` and `tls-crypt`. Both wraps authenticate every control
  packet including the opening reset, so a server using either previously
  dropped the client's first packet and never replied. Most commercial provider
  profiles require one or the other.
- Support for `auth-user-pass` through a new `Client.CredentialsFn` callback,
  also on `netstack.Options`. The callback is asked for a username and password
  once per attempt, before the key-method-2 packet is sent, and may block on a
  keychain or a user interface. A profile that needs credentials and has none
  fails before it dials, because dialing cannot help.
- A control-channel replay window, separate from the reliable layer's own
  sequence numbers. Replayed and stale-timestamped control packets are rejected
  and counted in `diag.Counters` rather than dropped silently.
- `profile.Spec` and `Spec.Build()`: a tunnel described programmatically, for a
  caller with a host, a port and a CA in hand and no file to parse. Every entry
  point takes a `*Profile`, and the only thing that produced a valid one was
  the text parser — filling the struct by hand skipped the defaults, the
  normalisers and the post-scan resolution, which is how a profile ends up
  dialling TCP because an enum's zero value says so. `Build` renders the
  directives a file would have carried and runs them through the same
  assembler, so there is no value it can produce that `ParseString` could not,
  and no second set of rules to keep in step. It refuses what a file could not
  have said, such as an argument with a space in it.
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
- Remote failover. A profile with several `remote` lines now tries them in
  order until one completes the handshake, each with its own protocol and port,
  shuffled first when the profile carries `remote-random`. A `Config` or
  `Unsupported` failure stops the loop, because a second endpoint cannot help
  with a profile the client cannot honour; `Network` and `TLS` move on.
- `EndpointInfo.Attempts` in the session report: one record per endpoint
  actually tried, with its protocol, port, dial time and the class it failed
  with. `EndpointInfo.Remotes` remains and now counts what the profile offered,
  which is a different question from what was tried.
- `netstack.Net.Ping` and `netstack.Net.Gateway`: an ICMP echo through the
  tunnel, and the peer's own tunnel-side address to send it to. The payload is
  chosen by the caller and echoed back verbatim, which makes it a measurement
  rather than a reachability check — a peer that compresses the reply can be
  detected no other way, because a tunnel carrying incompressible traffic looks
  exactly like one whose peer never compresses. IPv4 only.
- File-referenced `ca`, `cert` and `key`. A profile that names its certificate
  authority in a separate file — `ca ca.vpn.example.test.crt`, with no inline
  `<ca>` block — now has that file read, resolved against the profile's own
  directory and confined to it. A profile shaped that way was refused before a
  socket was opened, for want of anything to verify the server against. A
  profile carrying both an inline block and a file reference uses the block, as
  OpenVPN does.
- `profile.ParseFileIn`, which parses from a reader against a named directory.
  It is `ParsePath` for a caller that already holds the bytes and must keep the
  path out of its error messages. `ParseFile` and `ParseString` have no
  directory and refuse a file reference with `profile.ErrNoProfileDir`, which
  names the entry point that can read one; returning a profile with an empty
  trust store instead is the failure this replaces.
- `Profile.FileRefs`: which of the `ca`, `cert` and `key` directives named a
  file, and for each whether the file was read or an inline block superseded
  it. The name itself is not recorded.
- `verify-x509-name` is now checked. The server certificate's subject must
  match the value, in whichever of OpenVPN's three ways the directive's second
  argument asks for: `subject` compares the whole distinguished name, `name`
  compares the common name, and `name-prefix` requires the common name to start
  with the value. An omitted second argument means `subject`, which is
  OpenVPN's default. A mismatch is now refused during the TLS handshake instead
  of connecting.
- `Profile.VerifyX509NameMatch` and `profile.ParseX509NameMatch`: the
  directive's match type, which nothing parsed before. A type that is none of
  the three is refused when the profile is parsed rather than guessed at, as
  OpenVPN refuses it.
- `ns-cert-type server` is now checked. The server certificate must carry the
  legacy Netscape certificate-type extension with the SSL-server bit set; a
  certificate without the extension fails the check rather than passing it by
  default. Only the `server` form is read.
- Data-channel compression framing. A server configured for compression frames
  every data packet and drops what it cannot parse, so the framing decides
  whether the tunnel carries anything at all, and most provider profiles
  declare one. All four framings OpenVPN uses are now produced and
  accepted: `comp-lzo`'s prepended byte, the swapping form that bare `compress`
  and `compress lz4` use, and the two-byte v2 header of `compress lz4-v2` and
  `compress stub-v2`. Nothing is ever compressed on send.
- `Profile.Compression` and `Profile.AllowCompression`: the profile's own
  `comp-lzo`, `compress` and `allow-compression` directives are now read. They
  had no field at all, and an OpenVPN server does not push its compression
  setting, so a `comp-lzo` profile talking to a `comp-lzo` server previously
  agreed on nothing and sent unframed packets the server threw away.
  `allow-compression no` refuses a compressing algorithm from the profile and
  from the `PUSH_REPLY` alike, and permits a framing stub. The profile decides
  which framing is used and the peer decides whether there is one: a peer that
  declares no compression in its options string gets none, whatever the profile
  asks for, because the leading byte would otherwise be discarded and the
  tunnel would carry nothing.
- Support for the `P_DATA_V1` data-channel wire format, alongside `P_DATA_V2`.
  A server that pushes no peer-id speaks the older format, and the client now
  speaks it back: the format is chosen once, from the absence of a pushed
  peer-id, at the point the cipher and derivation are settled. It is never a
  preference and never a fallback after a failure, because by the time a data
  packet is wrong the peer has said nothing and the session is already broken.
  `diag.NegotiatedInfo.WireFormat` records which one was used. A server that
  pushes no peer-id had been completing its handshake and carrying nothing,
  counted as connected because nothing measured the difference.
- An RFC 5705 keying-material exporter for TLS 1.2, used only where Go's own
  refuses: a peer that pushes `key-derivation tls-ekm` and then negotiates TLS
  1.2 without RFC 7627 Extended Master Secret. `crypto/tls` declines that
  combination by policy and OpenSSL performs it, so stock openvpn connects
  where this client failed `crypto` at `keys`. The refusal is detected from the
  ServerHello rather than from Go's error text, which is not part of its API and
  covers a second, unrelated case. `diag.TLSInfo.EMSExportFallback` records when
  it was used.
- `netstack.Tunnel.Lifetime()`: how long a tunnel has been up, how many
  renegotiations and reconnects it has been through, and the last transient
  failure it recovered from. For a consumer holding a tunnel open rather than
  measuring a handshake — a session whose renegotiations have been failing
  reads as healthy on every other counter.
- Support for `explicit-exit-notify`, and `Profile.ExplicitExitNotify` behind
  it. A deliberate `Disconnect` over UDP now sends the OCC exit notification —
  once per the directive's optional retry count, defaulting to one — so the
  server frees the session immediately instead of holding it to its own
  keepalive timeout. Nothing is sent on a transport failure, over TCP, or from
  a profile that did not ask. It also matters for a measurement run: an
  endpoint left holding a dead session per attempt is one that starts
  rate-limiting.

- `Client.Attempts()`: one record per attempt of the current or most recent
  `Reconnect`, in order, each carrying its own `diag.SessionReport`. `Report()`
  still answers for the most recent attempt; the reason an earlier attempt
  failed used to be overwritten by whatever happened next, which is the one
  thing a caller wanted from a reconnect loop.
- `netstack.Tunnel.Reconnect` and `netstack.Options.MaxReconnects`: a tunnel
  can now be re-established after the link under it fails, from the front door.
  The stack that comes back is a new one — a netstack tunnel's addresses come
  from the `PUSH_REPLY` — so the `Tunnel` is repointed at it and connections
  dialled through the old one are gone.
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
- The liveness and handshake directives a profile states are read instead of
  ignored — `ping`, `ping-restart`, `ping-exit`, `keepalive`, `hand-window` and
  `mssfix`'s second word — into `Profile.PingInterval`, `PingTimeout`,
  `PingExit`, `HandWindowSec` and `MSSFixMode`. `keepalive N M` sets both timers
  and outranks a `ping` or `ping-restart` anywhere in the file, with no
  server-side doubling. The keepalive loop and the rekey hand-window read them
  per value, ahead of the pushed figure and the built-in default.

### Changed

- **Breaking:** the project is renamed. The Go module is
  `github.com/buengese/go-openvpn` and every import path moves with it; the
  repository lives at <https://github.com/buengese/go-openvpn>. An importer has
  to update its import paths — there is no compatibility alias for the old
  module path.

  The names the module produces move too. The CLI is `go-openvpn-cli`, and the
  variables it and the test suite read are `GO_OPENVPN_*` rather than
  `OPENLAWSVPN_*`. The gomobile artifacts are `go-openvpn.aar` and
  `go-openvpn.xcframework`, whose inner framework gomobile now names
  `Go-Openvpn.framework`, so the Android and iOS apps have to be pointed at the
  new file and framework names. Containers the test matrix starts are labelled
  `net.bngs.goopenvpn.testenv`, and the images it builds are
  `go-openvpn-test/openvpn-server` — a local repository, so `make
  matrix-images` has to run again before the matrix tests will find them.

  Nothing on the wire changed and no profile stops working. The
  `x-openlawsvpn-flow` directive is still recognised — `x-go-openvpn-flow` is
  the spelling new profiles should use, and both sit in the capability registry
  — and the relay and demo endpoints are untouched.

- **Breaking:** `dns.Apply` is now
  `Apply(cfg *Config, ifName string) (Backend, string, error)`. It took a
  `backupPath` and returned `(Backend, error)`; the backup path is now chosen by
  whichever backend needs one and handed back as the second result, because only
  that backend knows whether it made a backup or what it was called.

- **Breaking:** `Client.TUNSetup` is now `Client.Device`, a `device.Backend`.
  The callback was `func(ifconfigJSON string, mtu int) (*tun.Device, error)`: it
  returned a descriptor and the client core then did the privileged work itself
  — addressing, routes, DNS — and unwound it in its own cleanup. A backend owns
  all of that behind `Open` and unwinds it in `Device.Close`. A host that
  supplied a `TUNSetup` sets a `fd.Backend{Establish: …}` instead, and a nil
  `Device` still means the kernel backend.

- **Breaking:** `Profile.ForceSAMLFlow` is now `Profile.Federated`, and
  `Profile.DetectFlow()` is now `Profile.AuthFlow()`. The old names described
  a SAML override bolted onto a client that assumed AWS; the new ones name what
  the profile says — it authenticates against an identity provider — and what
  the method answers.
- **Breaking:** `Profile.AuthFlow()` reads the profile and nothing else. It
  used to answer "federated" for a remote whose hostname matched
  `cvpn-endpoint-*.amazonaws.com`, which put one vendor's endpoint naming
  inside the file-format parser. The rule now lives with the method that needs
  it, as `saml.IsAWSEndpoint`, and the client applies it when choosing how to
  authenticate — so an AWS profile missing its `auth-federate` line still
  connects, and a profile means what it says.
- **Breaking:** the `profile.AuthFlow` constants are reordered so that
  `FlowCertAuth` is the zero value, followed by `FlowUserPass` and
  `FlowFederated`. A flow variable nobody set now means an ordinary OpenVPN
  profile rather than one vendor's federated flow. Nothing persists these
  numbers; code that names the constants is unaffected. `AuthFlow` also gained
  a `String()`, so a flow in a log line or a test failure says which it is.
- **Breaking:** `profile.FlowAWSSSO` is now `profile.FlowFederated`. Its own
  `String()` already answered `"federated"`, and the flow is what the profile
  asks for rather than who serves it: `auth-federate` is an OpenVPN directive
  any server can carry, and `x-openlawsvpn-flow saml` exists so that one does.
  This completes the rename above — the constant was the last name in the
  package still asserting whose endpoint it was.
- `Reconnect` now works for every authentication flow. It reconnected only the
  AWS SSO flow, from a cached SAML assertion, and answered every other profile
  with `ErrReauthRequired` — a certificate-only profile was told to run a
  browser flow it does not have. Each flow now resumes from its own state: the
  AWS flow from the assertion, its CRV1 state id and the Phase 1 IP, and the
  other two from the credentials already held, so a dropped link does not put a
  second prompt in front of the user.
- `Reconnect` retries a failure only when a second attempt could resolve it,
  reading the class rather than counting: `Network` and `TLS` are retried,
  `Config` and `Unsupported` are not, and a rejected credential stops the loop
  unless it came from `CredentialsFn`, which may be asked once for a different
  one. It previously retried everything but a rejected credential, so an
  unsupported cipher was dialled again on a doubling backoff until
  `MaxReconnects` ran out — by default, forever.
- Server certificates are now verified the way OpenVPN verifies them — the
  chain against the profile's CA, plus the `serverAuth` extended key usage when
  the profile carries `remote-cert-tls server`. The endpoint hostname is no
  longer matched against the certificate's subject alternative names, because
  OpenVPN performs no such check and it rejected valid provider endpoints that
  stock openvpn connects to.
- `verify-x509-name` no longer sets the TLS server name. It matches a subject
  DN, not a SAN, and using it for SNI conflated the two. Profiles that relied
  on that coincidence now send their own endpoint hostname as SNI.
- The `auth` digest now defaults to SHA1, matching OpenVPN, where it previously
  defaulted to SHA256. `Profile.AuthSet` distinguishes a profile that named a
  digest from one that did not.
- The options string sent to the server, and the advertised `IV_CIPHERS` list,
  now describe the cipher, digest and key size actually in use. `IV_CIPHERS`
  previously advertised AES-192-GCM and CHACHA20-POLY1305, neither of which the
  client could perform.
- A profile carrying both a client certificate and `auth-user-pass` is now
  treated as needing credentials. It was previously read as certificate-only
  and could never present a password.
- The AWS Client VPN literals `N/A` and `ACS::35001` are sent only on the AWS
  SSO flow. Every other flow previously sent them too; a certificate-only
  profile now sends empty credentials, as stock OpenVPN does.
- A server we cannot authenticate to is reported as a crypto failure at the
  reset stage rather than as a network timeout. A wrapped server and a dead one
  were previously indistinguishable.
- The capability registry reports `tls-auth`, `tls-crypt`, `key-direction` and
  the bare form of `auth-user-pass` as supported. The file-argument forms stay
  fatal: nothing reads the file, and proceeding would report the server's
  refusal as a wrong password.
- The capability registry reports `remote-cert-tls server` as supported. The
  client has required the server certificate's serverAuth extended key usage
  since the certificate verifier was rewritten, but the registry still described
  the directive as unread, which understated what most profiles would get.
- The capability registry reports a `ca`, `cert` or `key` file reference as
  supported when the file was read and as ignored when an inline block
  superseded it, in place of the flat "not read" it reported before. It was the
  last row that routinely graded a real provider profile fatal.
- The capability registry reports `compress` and `allow-compression` as
  supported, and `comp-lzo` as degraded rather than "not read". The framing is
  applied in every case; the distinction is the codec, which only `comp-lzo`,
  `compress lzo`, `compress lz4` and `compress lz4-v2` can meet.
- `diag.NegotiatedInfo.Compression` reports the compression actually in force
  rather than the pushed directive, and names it as a `.ovpn` file does —
  `comp-lzo`, `compress`, `compress stub-v2`. It previously reported `none` for
  every profile-declared mode, because nothing but the `PUSH_REPLY` was read.
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
  [go-openvpn-linux](https://github.com/buengese/go-openvpn-linux), with
  its history, its security architecture document and its version scripts.
  This module is the engine and `go-openvpn-cli`; the desktop app consumes it
  as a dependency, the way the Android and iOS apps do, and builds the CLI it
  packages from this module. Nothing in this tree carries a version any more:
  the release tag is the version, and the release workflows no longer check it
  against a spec, a PKGBUILD or a Cargo manifest.
- **Breaking:** `routing.PushOptions.RedirectGateway6`. The `ipv6` flag word is
  now one bit of `PushOptions.RedirectFlags`, and `PushOptions.RedirectsIPv6()`
  reads it — a nil-safe method rather than a second field, because two ways to
  say one thing are two things that can disagree. A caller that tested the
  field calls the method.
- `vpn.Client.ResetForTest` and `vpn.Client.ConnectPhase2Reuse`. `ResetForTest`
  restored the first exchange's state so that a SAML assertion could be
  presented a second time; nothing in the tree called it, under any build tag,
  and `Reconnect` now reseeds that state itself from the method's own resumption
  copy. `ConnectPhase2Reuse` was a second name for `ConnectPhase2`'s one-line
  body — the two were identical calls to the same bring-up — and had no caller
  outside the tests. Use `ConnectPhase2`, whose documentation now describes what
  it does rather than which of the two callers it was written for.
- Six exported functions from `auth/saml` that encoded the AWS second exchange
  as though it were the only one: `BuildPhase2Username`, `CompletePhase2`,
  `ParsePhase2Credential`, `WrapAuthFailed`, `WritePhase2Credential` and
  `WritePhase2Credentials`. What they did is now the authentication method's,
  reached through `vpn.Client` rather than by assembling packets by hand.
- The stock control-channel vocabulary from `auth/saml`: `MsgKind` and its four
  `MsgKind*` constants, `ControlMessage`, `SessionExpiredError`,
  `SessionMonitor`, `ClassifyMsg`, `ParseControlMsg`, `ReadControlMsg`,
  `HandlePhase1` and `NewSessionMonitor`. None of it is SAML-specific — it is
  how any OpenVPN server talks on the control channel — and it now lives in
  `internal/control`, which cannot be imported from outside this module. A
  consumer that needs any of this reaches for the root package's API —
  `vpn.Client`'s event stream and `Report()` carry what these reported.

### Fixed

- A server that ends an established session is noticed on every connection, not
  only on federated ones. Certificate and username/password profiles — every
  non-AWS provider — authenticate in one exchange, and that path handed the
  session monitor a replay of the `PUSH_REPLY` rather than the connection it
  came off, so the monitor reached end-of-stream before the first data packet
  and watched nothing for the rest of the session. A mid-session `AUTH_FAILED`,
  `RESTART` or `HALT` went unread: the tunnel went quiet and the disconnect
  waited on the keepalive or ping-restart timer, which then reported it as a
  network fault tens of seconds later. As a consequence `diag.ClassPeerClosed`
  — the class for a peer that ended a working session on purpose — is now
  reachable on these profiles, where it previously could not be produced at
  all, and a revoked session is reported as `auth` rather than `network`.
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
- A temporary rejection is no longer treated as a protocol fault. A server
  answering `PUSH_REQUEST` with `AUTH_FAILED,TEMP` — what a busy server sends —
  was classified `protocol`, which got both following decisions wrong at once:
  the client gave up after one attempt in a few milliseconds against a server
  that had asked for a five-second backoff, while a multi-remote profile burned
  every remaining endpoint on it. The server's backoff is now honoured, capped
  by the existing ceiling.
- Three crashes and a leak in teardown: `Connect` racing `Disconnect` could
  panic with "close of closed channel"; a peer still sending data during a
  teardown could panic with "send on closed channel"; the TLS master secret was
  read and zeroed without synchronisation; and a `SAMLTokenFn` that returned an
  error left the connection and four goroutines running, with the client stuck
  and unable to connect again.
- `Disconnect` and `WaitForDisconnect` no longer report an error on a tunnel
  that was carrying traffic when it was closed. A goroutine woken by its own
  teardown was recording the resulting write failure as the session's outcome:
  measured at 18 spurious errors in 50 closes under load, and none in 50 idle,
  which is why no test had seen it. A genuine transport failure is still
  reported — the rule is stated in terms of the cancelled context and never in
  terms of the error, because the two produce identical error text.
- A renegotiation started by the *server* is now answered instead of dropped.
  A `P_CONTROL_SOFT_RESET_V1` arriving for a key_id with no control session
  was discarded, so against a server that also renegotiates on a short timer
  the client lost the race about two times in five and then waited out its own
  30-second deadline for a packet it had already thrown away. Measured at 8
  failures in 20 before, and 0 in 20 after.
- `diag.NegotiatedInfo.Digest` is now filled in. The field was declared and
  never written, so every session report claimed no data-channel digest had
  been negotiated — including on CBC connections, where the digest decides the
  HMAC key length and the tag length on the wire. It now records the digest the
  connection actually installed, and stays empty for an AEAD cipher, which
  resolves none.
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
- A payload a peer genuinely compressed is refused, naming the algorithm,
  instead of being handed to the tunnel as an IP packet. The client links no
  codec, so it previously stripped the marker and passed a compressed blob on
  as though it were a packet: the tunnel came up, the session report was green,
  and the traffic was garbage.
- A profile with no usable certificate authority is now a configuration error
  raised before any socket is opened, instead of silently disabling certificate
  verification for that connection.
- Data-channel keys for AES-CBC were taken from the wrong halves of the key
  block, transposing the transmit and receive HMAC keys. The mapping now exists
  in one place and both cipher modes read it.
- The server's key-method-2 packet is now read field by field instead of being
  drained into a fixed buffer, so a truncated packet is reported as a protocol
  error rather than parsed from whatever had arrived.
- Key renegotiation derives its keys through the same code as the initial
  handshake. It previously carried a second copy that would have installed
  AES-GCM keys on a CBC connection.
- A control packet that fails authentication is dropped and counted instead of
  ending the session. On UDP the previous behaviour let any packet from any
  source tear down an established connection.
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
  `go-openvpn-resolv-*.conf` per attempt, one per reconnect. The backup is now
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
  provider's POST, which carries the assertion. `go-openvpn-cli` no longer
  answers a lost bind by prompting for a pasted assertion, which asked the user
  to complete, by hand, a login whose credential had already gone elsewhere; it
  refuses and names the port so the holder can be found. The paste route is
  unchanged when the bind succeeds.

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

[Unreleased]: https://github.com/buengese/go-openvpn/compare/v1.2.3...HEAD
[1.2.3]: https://github.com/openlawsvpn/go-openlawsvpn/compare/v1.2.2...v1.2.3
[1.2.2]: https://github.com/openlawsvpn/go-openlawsvpn/compare/v1.2.1...v1.2.2
[1.2.1]: https://github.com/openlawsvpn/go-openlawsvpn/compare/v1.2.0...v1.2.1
[1.2.0]: https://github.com/openlawsvpn/go-openlawsvpn/compare/v1.1.9...v1.2.0
