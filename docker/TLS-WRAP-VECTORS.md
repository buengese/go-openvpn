# Capturing OpenVPN control-channel wrap known-answer vectors

Version: 1.0
Applies to: `internal/wrap/testdata/vectors.json`
License: LGPL-2.1-or-later

How `internal/wrap/testdata/vectors.json` was produced, and how to produce it
again from a clean checkout. It is the `tls-auth`/`tls-crypt` analogue of
[`PRF-VECTORS.md`](PRF-VECTORS.md), and it exists for the same reason.

---

## 1. Why

`tls-auth` authenticates every control packet with an HMAC. `tls-crypt`
authenticates *and* encrypts them. Both are configured, never negotiated, and
both apply to the opening `HARD_RESET` — so against a wrapped server our first
packet is dropped and no reply ever comes. Between them they are the largest
gate left: most commercial provider profiles configure one or the other.

The risk is not that the wraps are hard. It is that they are easy to get
*plausibly* wrong. `tls-auth` puts the HMAC and the replay header in one order
on the wire and hashes them in a different one:

```
wire  = opcode|key_id ‖ session_id ‖ hmac ‖ packet_id ‖ timestamp ‖ rest
input = packet_id ‖ timestamp ‖ opcode|key_id ‖ session_id ‖ rest
```

and `tls-crypt`, which looks like the same shape, hashes them in the *wire*
order instead. Neither choice looks wrong from the packet layout. Both produce
a tag of the right length, and a wrong one is indistinguishable from a dead
server — which is exactly the failure mode these vectors exist to make
diagnosable.

`internal/prf` carried confident, correct-looking openvpn3 citations while
implementing an entirely different algorithm, and only a captured vector found
it ([`../docs/openvpn3-reference-policy.md`](../docs/openvpn3-reference-policy.md)
§3.4). These vectors were captured **before either wrap was implemented**, so
both wraps are measured against a real OpenVPN peer rather than against their
own reading of the reference.

### Provenance of the protocol facts

Per [`../docs/openvpn3-reference-policy.md`](../docs/openvpn3-reference-policy.md)
§3.3, everything below is cited, and — §3.4 — verified rather than trusted.
These are readings of the **OpenVPN 2.4.12 release tarball this rig pins**
(SHA-256 `66952d9c…5dee`, verified during the image build). Line numbers drift,
so each row names a function. No openvpn3 source was consulted for this
capture: every fact here is either read from the pinned 2.4.12 source or
measured from the capture, and §6 says which of them the capture independently
confirms.

| Fact | Where |
|---|---|
| Opcode is the top 5 bits of the first byte, key id the low 3 | `src/openvpn/ssl.h`, `P_OPCODE_SHIFT` / `P_KEY_ID_MASK` |
| Session IDs are 8 bytes | `src/openvpn/session_id.h`, `SID_SIZE` |
| Ack array is a 1-byte count, that many 4-byte ids, then the *remote* session id when the count is non-zero | `src/openvpn/reliable.c`, `reliable_ack_write()` |
| `tls-auth` wire order: opcode and session id stay at the front; the HMAC and the replay header follow them | `src/openvpn/ssl.c`, `write_control_auth()` and `swap_hmac()` |
| `tls-auth` HMAC input order: the replay header is *prepended* before the HMAC is taken, so it precedes the opcode and session id in the digest | `src/openvpn/crypto.c`, `openvpn_encrypt_v1()`, the `/* No Encryption */` branch |
| Long-form packet id is a 4-byte counter then a 4-byte POSIX time, both big-endian, in that order | `src/openvpn/packet_id.c`, `packet_id_write()` |
| `tls-auth` uses the long form | `src/openvpn/init.c`, `do_init_crypto_tls()` (`CO_PACKET_ID_LONG_FORM` on `tls_wrap.opt`) |
| `tls-auth`'s digest is `--auth`, and its key type carries no cipher at all | `src/openvpn/init.c`, `do_init_crypto_tls_c1()` |
| `tls-crypt` wire order: opcode ‖ session id ‖ packet id ‖ timestamp ‖ tag ‖ ciphertext | `src/openvpn/tls_crypt.c`, `tls_crypt_wrap()`; offsets in `src/openvpn/tls_crypt.h`, `TLS_CRYPT_OFF_PID` / `_OFF_TAG` / `_OFF_CT` |
| `tls-crypt`'s tag covers the header, the replay header and the plaintext, in that (wire) order | `src/openvpn/tls_crypt.c`, `tls_crypt_wrap()` — `hmac_ctx_update(dst)` then `hmac_ctx_update(src)` |
| `tls-crypt`'s CTR IV is the leading 16 bytes of the tag | same function, `cipher_ctx_reset(ctx->cipher, tag)` |
| `tls-crypt` fixes AES-256-CTR and HMAC-SHA256 | `src/openvpn/tls_crypt.c`, `tls_crypt_kt()` |
| A 2048-bit static key is two 128-byte slots, each 64 cipher bytes then 64 HMAC bytes, filled linearly from the hex file | `src/openvpn/crypto.h`, `struct key` / `struct key2`; `src/openvpn/crypto.c`, `read_key_file()` |
| `--key-direction 0` sends with slot 0 and receives with slot 1; `1` is the reverse; absent means slot 0 in both directions | `src/openvpn/crypto.c`, `key_direction_state_init()` and `init_key_ctx_bi()` |
| Only the leading `digest_size` (resp. `cipher_length`) bytes of a slot's field are installed as the key | `src/openvpn/crypto.c`, `init_key_ctx()` |
| `tls-crypt` has no `--key-direction`: the server is always `KEY_DIRECTION_NORMAL` and the client always `KEY_DIRECTION_INVERSE` | `src/openvpn/tls_crypt.c`, `tls_crypt_init_key()` |

---

## 2. What was captured

`internal/wrap/testdata/vectors.json` holds **30 vectors** — 24 `tls-auth` and
6 `tls-crypt` — from five real handshakes. Each records one outgoing control
packet and every input the wrap consumed to produce it.

| Field | Meaning |
|---|---|
| `wrap` | `tls-auth` or `tls-crypt` |
| `digest` | the control-channel HMAC; `tls-crypt` fixes SHA256 |
| `key_direction` | the **client's** `--key-direction`, as a `.ovpn` spells it; `null` for `tls-crypt`. The server ran the complement |
| `sender` | `client` or `server` — which peer produced this packet, and therefore which half of the key is in play |
| `opcode`, `opcode_name` | 7/8 `HARD_RESET`, 5 `P_ACK_V1`, 4 `P_CONTROL_V1` |
| `static_key` | the shared 256-byte key, fresh per capture run |
| `hmac_key`, `hmac_key_offset` | the HMAC key bytes OpenVPN installed for the sender's *outgoing* direction, and where in `static_key` they were found |
| `cipher_key`, `cipher_key_offset` | the same for `tls-crypt`'s Ke; empty and `-1` for `tls-auth`, which installs no cipher |
| `plain` | the complete unwrapped packet: `opcode\|key_id ‖ session_id ‖ ack_array ‖ [message_packet_id ‖ payload]` |
| `auth_input` | the byte string that went into the HMAC, verbatim |
| `tag` | the `tls-auth` HMAC, or the `tls-crypt` tag |
| `replay_packet_id`, `replay_timestamp` | the wrap's own replay header, 4 bytes each |
| `wire` | the answer: the bytes handed to the socket |

`auth_input` is the field that makes a failure attributable. For `tls-auth` it
is not reconstructed — it is lifted out of the buffer `openvpn_encrypt()` left
behind, whose tail past the HMAC *is* what OpenVPN hashed. A wrong tag with a
right `auth_input` is a key-selection bug; a wrong `auth_input` is a field-order
bug; and without the intermediate there is nothing to bisect a 20-byte mismatch
against. `cipher_key` plays the same role for `tls-crypt`: the known-answer
tests assert Ke and Ka before they touch the cipher, so a mismatch is
attributable to key derivation rather than to AES-CTR.

### The five runs

| Run | Wrap | Client `key-direction` | Digest | Vectors |
|---|---|---:|---|---:|
| `tlsauth-kd0-sha1` | tls-auth | 0 | SHA1 | 6 |
| `tlsauth-kd1-sha1` | tls-auth | 1 | SHA1 | 6 |
| `tlsauth-kd0-sha256` | tls-auth | 0 | SHA256 | 6 |
| `tlsauth-kd1-sha256` | tls-auth | 1 | SHA256 | 6 |
| `tlscrypt` | tls-crypt | — | SHA256 | 6 |

Six per run: three packet shapes from each of the two peers.

- **`HARD_RESET`** — the opening packet. Ack array empty, message packet id 0.
- **`P_ACK_V1`** — an ack array and *no* message packet id at all.
- **`P_CONTROL_V1`** — an ack array, a message packet id and a TLS payload;
  287 bytes from the client, up to 1144 from the server.

Three shapes because a wrap that is right for one and wrong for another fails
after the handshake has visibly started, which is the expensive place to find
out. Real profiles ship `key-direction 1`, but direction 0 exists in the matrix
and costs one run, so both are here.

### The key halves, measured

The capture does not assume where in the static key each direction's material
lives: the instrumented `init_key_ctx()` prints the bytes it installed, and the
script *searches* the 256-byte key for them, failing if it cannot find them.
What it found, on every vector:

| Wrap | Sender's direction | Ke | Ka |
|---|---|---|---|
| `tls-auth`, `--key-direction 0` | slot 0 | — | `static_key[64 : 64+digest_size]` |
| `tls-auth`, `--key-direction 1` | slot 1 | — | `static_key[192 : 192+digest_size]` |
| `tls-crypt`, server | slot 0 | `static_key[0:32]` | `static_key[64:96]` |
| `tls-crypt`, client | slot 1 | `static_key[128:160]` | `static_key[192:224]` |

That agrees exactly with `key_direction_state_init()` + `init_key_ctx()` read
from the source, which is the point of measuring it.

**`tls-crypt`'s Ke and Ka are not adjacent.** The obvious reading — "take 32
bytes for the cipher and the next 32 for the HMAC" — is wrong twice over: the
split is by the 64-byte fields of `struct key`, so 32 bytes sit unused between
them, and the client uses the *second* slot even though `tls-crypt` has no
`key-direction` directive to say so. An implementation that reuses `tls-auth`'s
direction handling for `tls-crypt` picks the right slot for exactly one of the
two peers.

### Two smaller facts worth having in front of you

- The wrap's replay counter **starts at 1**, not 0, and is a different ID space
  from the reliability layer's message packet id inside `plain`. In the
  captured `HARD_RESET`s the two are `1` and `0` respectively, side by side in
  the same packet. The two must not be conflated.
- Overhead is `digest_size + 8` for `tls-auth` and `40` for `tls-crypt`. So
  `tls-auth` with SHA256 and `tls-crypt` cost the same 40 bytes, and a
  `Overhead()` that is right for one of them can still be wrong for SHA1's 28.

### Is committing this safe?

Yes. `static_key` is a 2048-bit key generated inside a container by
`openssl rand`, used by one handshake between two throwaway containers, and
discarded — a fresh one per run, so no two runs share a secret. Everything else
is ephemeral session material from a local server whose PKI was also generated
in a container and never written to the host. Nothing here is a credential,
nothing came from the provider corpus, and no host key material is written at
any point. Corpus material and credentials never enter this repository; this
file is committed on the same terms as `internal/prf/testdata/vectors.json`,
because nothing in it is a secret that outlives the throwaway containers that
produced it.

---

## 3. How to regenerate

Needs Docker, `/dev/net/tun` on the host, and outbound network for the first
build (the OpenVPN tarball and the Debian base image).

```sh
make tls-wrap-vectors
```

That is the whole procedure. It runs the two steps below in order.

### 3.1 Build the instrumented image

```sh
bash docker/openvpn-server/build-tlswrapdebug.sh
```

Produces `openlawsvpn-test/openvpn-server:2.4.12-tlswrapdebug` from the same
Dockerfile, the same pinned tarball (SHA-256 verified) and the same pinned base
image as the stock matrix build, with two differences:

- `--build-arg PATCH_DIR=patches-tlswrapdebug` selects
  `docker/openvpn-server/patches-tlswrapdebug/` instead of the empty default
  `patches/`, so `001-tlswrapdebug-control-channel.patch` is applied; and
- the tag carries a `-tlswrapdebug` suffix.

**Both matter.** The instrumented build prints the control-channel key material
and every control packet, plaintext and wrapped, into its log — and, because
`init_key_ctx()` is shared with the data channel, the data-channel keys as well.
It must never answer to the plain `openlawsvpn-test/openvpn-server:2.4.12` tag
that `testenv.StartMatrix` and every other test resolve. `build-tlswrapdebug.sh`
refuses to run if the suffix ever computes to the stock tag, refuses if the
patch directory is empty, and — after the build — greps the resulting binary for
the instrumentation's format string, because an unpatched image completes
handshakes perfectly and prints nothing, which looks like a capture-script bug
rather than a build bug.

2.4 is used because the existing patch set targets it and both wire formats are
unchanged across 2.4–2.6; `tls-crypt` was introduced in 2.4.0, so 2.4.12 speaks
both wraps. Unlike the PRF capture, nothing here depends on the series: there is
no keying-material exporter in this story.

### 3.2 Run the capture

```sh
bash docker/openvpn-server/tls-wrap-capture.sh          # -> internal/wrap/testdata/vectors.json
bash docker/openvpn-server/tls-wrap-capture.sh -o /tmp/v.json
bash docker/openvpn-server/tls-wrap-capture.sh -k       # keep containers on failure
```

Per run it:

1. generates a throwaway PKI and a fresh 2048-bit static key **inside a
   container** — the same mechanism `testenv.StartMatrix` uses, so no PKI
   material ever touches the host filesystem;
2. starts a server container and waits for OpenVPN's own
   `Initialization Sequence Completed`;
3. starts a client container of the same instrumented image, configured with
   the complementary key direction, and waits for the same line;
4. reads the `TLSWRAPDEBUG` lines out of `docker logs` for **both** peers,
   taking the *first* dump of each opcode — retransmissions re-run the wrap with
   a fresh replay packet id, so every stage of one vector has to come from the
   same pass;
5. checks the decomposition of every packet before recording it (§3.3);
6. locates the installed key bytes inside the static key and records the offset;
7. tears both containers down.

Server and client configs use `ncp-disable`. Without it OpenVPN 2.4 negotiates
AES-256-GCM regardless of what the config asked for. `--auth` is what selects
the `tls-auth` HMAC as well as the data-channel one, so it has to be pinned for
the recorded digest to be the digest that ran.

Config file paths in the generated configs are absolute (`/etc/openvpn/ta.key`).
OpenVPN resolves relative paths against the process working directory, not
against the directory the config was read from.

### 3.3 What the capture refuses to record

Every check below is a check on *our* reading, not on OpenVPN. A vector that
fails one of them is not written out, and the script exits non-zero saying which
claim broke:

- `auth_input` must equal `packet_id ‖ timestamp ‖ plain` (`tls-auth`) — this is
  the field-order claim, and it is checked against the buffer OpenVPN actually
  hashed;
- `wire` must equal `plain[:9] ‖ tag ‖ packet_id ‖ timestamp ‖ plain[9:]`
  (`tls-auth`) or `plain[:9] ‖ packet_id ‖ timestamp ‖ tag ‖ ciphertext`
  (`tls-crypt`);
- the `tls-crypt` ciphertext must be exactly as long as the plaintext, since
  AES-256-CTR is a stream mode;
- the sender's outgoing key must be byte-identical to the peer's incoming key
  for the same direction — a cross-check between two independent dumps, so a
  mis-transcribed key would have to be wrong identically on both sides;
- the installed key must be findable inside the static key at an even byte
  offset.

---

## 4. The patch

`docker/openvpn-server/patches-tlswrapdebug/001-tlswrapdebug-control-channel.patch`
touches two files.

**`src/openvpn/ssl.c`, `write_control_auth()`** — every outgoing control packet
is dumped at each stage of the wrap:

| Stage | `tls-auth` | `tls-crypt` |
|---|---|---|
| `plain` | the packet with opcode and session id prepended, before `openvpn_encrypt()` | — |
| `plainhdr` / `plainbody` | — | the 9-byte header written into `work`, and the body still in `buf` |
| `preswap` | what `openvpn_encrypt()` produced: `hmac ‖ everything it hashed` | — |
| `wire` | after `swap_hmac()` | after `tls_crypt_wrap()` |

`preswap` is the whole reason to instrument rather than to packet-capture. Its
tail past the HMAC is precisely the byte string OpenVPN hashed, so the field
order is *recorded* rather than inferred from a wire capture that shows only the
other ordering. `tls-crypt` needs no equivalent because its digest input is in
wire order, which the wire already shows; the capture reconstructs it and the
Go tests check the reconstruction against the tag.

`tls-crypt` builds its output in a second buffer, so its plain packet exists in
two pieces at that point and never in one. The capture joins `plainhdr` and
`plainbody` and says so; the join is checked, because `wire` must open with the
same 9 bytes.

**`src/openvpn/crypto.c`, `init_key_ctx()`** — the cipher and HMAC key bytes
actually installed into each direction's context, tagged with the log prefix
that names it (`Outgoing`/`Incoming Control Channel Authentication` for
`--tls-auth`, `… Encryption` for `--tls-crypt`). One function covers both wraps
and both directions, which is why the key-half table in §2 is a measurement.

### Why the dumper bypasses `msg()`

It writes to `stderr` directly. `msg()` formats into a buffer of `ERR_BUF_SIZE`
(1280 without PKCS#11) and then formats *again* to prepend the per-instance
peer address, so a long line is silently clipped somewhere past 1200 characters
— and where exactly depends on how long the tag and the peer's address are.

That truncates precisely the vectors worth having, the full `P_CONTROL_V1`
packets, and it truncates two stages of the same packet at two *different*
points. The first run of this capture reported that the HMAC input tail was 28
bytes shorter than the plain packet, which reads as a wire-format discovery and
is a logging limit. It is called out here so the next person to extend the patch
does not reintroduce it.

### Applying it to other series

The patch is written against 2.4.12 and is only used there. `patches/` (the
default set the matrix images build with) stays empty. `write_control_auth()`
grew a `tls_wrap_ctx` indirection and `tls-crypt-v2` handling after 2.4, so a
2.5 or 2.6 instrumented build would need the patch rewritten rather than
re-based, in its own `patches-*` directory with its own tag suffix. The wire
formats recorded here are unchanged across 2.4–2.6, which is why one series is
enough.

---

## 5. How the vectors are used

`internal/wrap/vectors_test.go` holds four tests. None of them needs Docker;
`go test ./...` runs them from the committed JSON. None of them implements
either wrap: they read the vectors and check them, and the wraps themselves are
measured against the same file by `tlsauth_kat_test.go` and
`tlscrypt_kat_test.go` (§7).

- **`TestVectorsAreWellFormed`** — guards the testdata: field lengths, unique
  names and wire bytes, a fresh static key per run, complete provenance, and a
  floor of ≥6 vectors spanning both wraps, both key directions, both digests,
  and both a `HARD_RESET` and a payload-carrying packet for each wrap.
- **`TestVectorsDecomposeAsRecorded`** — pins the wire layout into the
  repository. The capture script checks the same decompositions before writing,
  so this cannot fail on fresh data; it is here so that a hand-edit, a truncated
  field or a re-capture against a different series shows up as a structural
  failure rather than as an inscrutable tag mismatch three units later.
- **`TestVectorsCarryTheAnswerTheyClaim`** — recomputes every tag from
  `auth_input` and every `tls-crypt` ciphertext from Ke and the tag-derived IV.
  This establishes that the recorded answer is *reachable*; without it §6 would
  only be showing that a set of wrong answers are all wrong, with no evidence
  that a right one exists.
- **`TestVectorsDiscriminateFieldOrderAndKeySelection`** — §6.

A fifth, **`TestKeyDirectionSelectsHalvesConsistently`**, states the key-half
rule from §2 as an assertion over all 30 vectors, so an implementation can be
read off a passing test rather than off this document.

---

## 6. The discrimination evidence

A vector that a wrong implementation also satisfies proves nothing. That is what
this capture had to establish, so here is what was checked and what it ruled
out.

For every vector, each construction below was computed under the *right* key
(when the ordering was on trial) or over the *right* input (when the key
selection was on trial), and compared against the recorded answer. **All 30
vectors ruled out every one of them.**

| Wrong construction | tls-auth | tls-crypt |
|---|---:|---:|
| Hash in **wire order** (header before the replay header) | 24/24 | *this is the correct order here* |
| Hash in **`tls-auth`'s order** (replay header first) | *this is the correct order here* | 6/6 |
| Replay header **appended** rather than prepended | 24/24 | 6/6 |
| Header **omitted** from the digest | 24/24 | 6/6 |
| Replay header **omitted** from the digest | 24/24 | 6/6 |
| Packet id and timestamp **swapped** | 24/24 | 6/6 |
| Session id omitted, opcode kept | 24/24 | 6/6 |
| Key from the **other direction's** HMAC half | 24/24 | 6/6 |
| Key from the **cipher half** of the same slot | 24/24 | 6/6 |
| Key from `static_key[0:]` regardless of direction | 24/24 | 6/6 |
| The **whole 64-byte** HMAC field rather than its digest-sized prefix | 24/24 | 6/6 |
| IV = the **trailing** 16 bytes of the tag | — | 6/6 |
| IV = the replay header, zero-padded | — | 6/6 |
| IV = zero | — | 6/6 |
| Ke from the other slot | — | 6/6 |
| Ka used as Ke | — | 6/6 |

And not narrowly. Across all 25 rows the wrong answer differed from the right
one in 47–53% of its bits — the half you get from two unrelated digests, not
the one or two you would get from an off-by-one. There are no near misses here
to argue about, which is what makes a failure in either wrap informative
rather than ambiguous.

The first two rows are the ones that matter most, and they are why both wraps
had to be captured rather than one. The `tls-auth` and `tls-crypt` digest inputs
carry the *same fields* in *different orders*; implementing the second wrap by
analogy with the first produces a tag of the right length from the right key
over the right bytes, and it is wrong. Nothing short of a captured answer
separates them.

The mutation check, run against the committed file:

- flipping one nibble of a recorded tag fails
  `TestVectorsCarryTheAnswerTheyClaim` ("1 of 20 bytes differ") and
  `TestVectorsDecomposeAsRecorded` ("wire is not header ‖ hmac ‖ packet_id ‖
  timestamp ‖ rest: 1 of 315 bytes differ, first at offset 9");
- rewriting one `auth_input` into the wire order fails
  `TestVectorsCarryTheAnswerTheyClaim` with "20 of 20 bytes differ".

What this does **not** rule out: an implementation that is wrong in a way no
vector exercises. Absent `key-direction` (slot 0 in both directions) has no
vector, because no corpus config and no matrix entry produces one;
`internal/wrap` implements it from the pinned source and says in a comment that
it is untested against a real peer. `tls-crypt-v2` is not covered at all. And
nothing here tests *unwrapping* a hostile packet — the replay window has its own
tests in `internal/wrap/replay_test.go`.

---

## 7. What the vectors assert about the wraps

The known-answer tests built on this file are
`internal/wrap/tlsauth_kat_test.go` and `internal/wrap/tlscrypt_kat_test.go`.
They are in the **external** test package (`wrap_test`), so they reuse
`vectors_test.go`'s `loadVectors`, the `vector` type and `mustHex` directly
while `wrap.go` stays free to define `headerLen`, `mac` and the rest without
colliding with them; the two unexported seams they need come from
`export_test.go`. A known-answer test that needs an unexported seam belongs in
a second file in `package wrap`; one that only needs the exported constructors
can sit in `wrap_test` beside `vectors_test.go` and reuse its loader directly.
What follows is what each assertion is for.

### 7.1 Wrap

For every vector, `Wrap(plain)` must produce `wire` exactly.

`Wrap` generates the replay packet id and timestamp itself, so it cannot
reproduce a recorded packet without being told what they were.
`wrap.SetReplayHeaderForTest` is that seam, set from `replay_packet_id` and
`replay_timestamp` before the call. A seam is cheaper than making the
known-answer test assert something weaker, and the alternative — asserting only
the tag — leaves the byte order of the wire itself untested.

```
key       := StaticKey(static_key)
direction := key_direction        // the client's; use the complement when sender == "server"
digest    := digest               // SHA1 or SHA256; tls-crypt takes neither
w         := NewTLSAuth(key, direction, digest)   // or NewTLSCrypt(key)
wrap.SetReplayHeaderForTest(w, replay_packet_id, replay_timestamp)
got := w.Wrap(plain)
assert got == wire
```

Half the vectors have `sender == "server"`. Those are not a client's outgoing
packets, and a `tls-auth` vector is reproduced by a wrapper built with the
*sender's* direction — for a server-sent packet, the complement of the
`key_direction` the vector records. See 7.2 for what a client does with them.

### 7.2 Unwrap

For every vector with `sender == "server"`, a wrapper built the way a *client*
builds one must accept `wire` and return `plain`:

```
w := NewTLSAuth(key, direction, digest)   // direction as the client configures it
got := w.Unwrap(wire)
assert got == plain
```

This is the direction that matters operationally — it is how the first server
reply is validated — and it exercises the receive key half, which no `Wrap`
assertion touches. The recorded timestamps are in the past, and that costs
nothing: the replay window compares each packet against the *peer's* own highest
timestamp rather than against the local clock, which is what OpenVPN does and
what lets a vector captured at any time be replayed without a clock seam.

For every vector with `sender == "client"`, the same wrapper must *reject*
`wire`, because a client's own outgoing packet is authenticated under the send
key and the receive key is the other half. That is one line, and it is the
cheapest available test that the two halves are not being confused.

### 7.3 Intermediates, asserted before the cipher

The derived keys are asserted before AES is reached, so a `tls-crypt` mismatch
is attributable to key selection rather than to the cipher. The vectors carry
them:

```
Ke == static_key[cipher_key_offset : cipher_key_offset+32]   == cipher_key
Ka == static_key[hmac_key_offset   : hmac_key_offset+32]     == hmac_key
```

and for `tls-auth`, `Ka == hmac_key` where `len(hmac_key)` is the digest size —
20 for SHA1, 32 for SHA256, always the *leading* bytes of a 64-byte field.
`TestKeyDirectionSelectsHalvesConsistently` states the offsets; a wrapper that
disagrees with it disagrees with a real server.

### 7.4 Overhead

`Overhead()` must be `len(wire) - len(plain)` for every vector: `digest_size + 8`
for `tls-auth`, `40` for `tls-crypt`. SHA1's 28 is the one that catches a
hard-coded 40.

### 7.5 What not to assert

Do not assert the replay packet id or the timestamp against a live `Wrap` — they
are a counter and a clock. Assert them only through the seam above. And do not
reuse these vectors as replay-window tests: the recorded ids all start at 1 and
climb, which is the *accepting* case; rejecting a replay needs its own test, and
has one in `internal/wrap/replay_test.go`.

---

## 8. Cleaning up

`make matrix-clean` removes matrix containers, networks and images, including
the `-tlswrapdebug` tag. The capture script removes its own containers and
network on the way out, and on failure too unless `-k` is given. Its label is
`com.openlawsvpn.testenv=tls-wrap-capture`, distinct from the matrix's, so
`TestMatrixLeavesNoStrays` neither sees it nor is confused by it.
