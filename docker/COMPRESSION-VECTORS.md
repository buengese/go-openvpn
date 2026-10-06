# Capturing OpenVPN data-channel compression framing known-answer vectors

Version: 1.0
Applies to: `internal/compress/testdata/vectors.json`
License: LGPL-2.1-or-later

How `internal/compress/testdata/vectors.json` was produced, and how to produce
it again from a clean checkout. It is the compression analogue of
[`TLS-WRAP-VECTORS.md`](TLS-WRAP-VECTORS.md) and
[`PRF-VECTORS.md`](PRF-VECTORS.md), and it exists for the same reason.

---

## 1. Why a reading of the header was not enough

Most provider profiles declare compression. The client never compresses on send,
and decompresses only LZO, but all of them need the *framing* to be right,
because a server that frames every data packet expects one back and drops what
it cannot parse. When these vectors were captured, `comp-lzo` was the matrix's
only entry that timed out, and it is the commonest form a profile asks for.

The risk is not that the framing is hard. It is that it is easy to get
*plausibly* wrong, and that a wrong answer is invisible. A misplaced framing
byte produces packets that decrypt cleanly, pass every authentication check and
mean nothing; the tunnel comes up, the session report is green, and the traffic
is garbage.

When these vectors were captured, `internal/compress` had two of these constants
inverted:

```go
//	0x69 — data is NOT compressed (lz4 stub byte, used as a pass-through)
//	0xfa — data IS lz4-compressed (not implemented; never sent by this client)
```

against OpenVPN's `src/openvpn/comp.h`, which reads the other way round. **The
bytes agree with `comp.h`.** §6 has the measurement. But the vectors found two
further things that no amount of reading one constant would have:

- `compress lz4` does not prepend its byte at all. It **swaps**: the framing
  byte replaces the payload's first byte, which moves to the tail. So even a
  corrected constant, prepended, would still have been wrong.
- Bare `compress` is `COMP_ALG_STUB` with `COMP_F_SWAP`, which is a third
  framing again, and one `internal/compress` had no mode for.

That is why these vectors were captured rather than read off the header. It is
the third time this project has met a confident constant with no ground truth
behind it, after `internal/prf` and the `tls-auth` HMAC field order, and the
answer both previous times was the same one.

### Provenance of the protocol facts

Per [`../docs/openvpn3-reference-policy.md`](../docs/openvpn3-reference-policy.md)
§3.3 everything below is cited, and — §3.4 — verified rather than trusted. These
are readings of the **OpenVPN 2.4.12, 2.5.11 and 2.6.22 release tarballs this
rig pins** (SHA-256 in `openvpn-server/versions.env`, verified during each image
build). Line numbers drift, so each row names a function. No openvpn3 source was
consulted for this capture: every fact here is either read from a pinned tarball
or measured from the capture, and §6 says which of them the capture
independently confirms.

| Fact | Where |
|---|---|
| `LZO_COMPRESS_BYTE 0x66`, `LZ4_COMPRESS_BYTE 0x69`, `NO_COMPRESS_BYTE 0xFA`, `NO_COMPRESS_BYTE_SWAP 0xFB` | `src/openvpn/comp.h` |
| `COMP_ALGV2_INDICATOR_BYTE 0x50`, `COMP_ALGV2_UNCOMPRESSED_BYTE 0`, `COMP_ALGV2_LZ4_BYTE 1` | `src/openvpn/comp.h` |
| `COMP_F_SWAP` is `1<<2`: "initial command byte is swapped with last byte in buffer to preserve payload alignment" | `src/openvpn/comp.h` |
| Nothing below 100 bytes is even offered to a compressor | `src/openvpn/comp.h`, `COMPRESS_THRESHOLD` |
| `comp-lzo` is `COMP_ALG_LZO` with flags 0 (`yes`) or `COMP_F_ADAPTIVE` (bare or `adaptive`) | `src/openvpn/options.c`, `add_option()`, the `comp-lzo` case |
| Bare `compress` is `COMP_ALG_STUB` with `COMP_F_SWAP`; `compress stub-v2` is `COMP_ALGV2_UNCOMPRESSED`; `compress lz4` is `COMP_ALG_LZ4` with `COMP_F_SWAP`; `compress lz4-v2` is `COMP_ALGV2_LZ4` | same function, the `compress` case |
| `comp-lzo` never swaps — `lzo_compress_init()` asserts `!(flags & COMP_F_SWAP)` | `src/openvpn/lzo.c` |
| `lzo_compress()` prepends `LZO_COMPRESS_BYTE` when compression helped and `NO_COMPRESS_BYTE` otherwise | `src/openvpn/lzo.c` |
| `stub_compress()` swaps under `COMP_F_SWAP` and prepends `NO_COMPRESS_BYTE` without it | `src/openvpn/compstub.c` |
| `lz4_compress()` **always** swaps, whether or not it compressed; only the leading byte differs | `src/openvpn/comp-lz4.c` |
| `lz4v2_compress()` prepends `0x50 0x01` when it compressed, and otherwise adds nothing | `src/openvpn/comp-lz4.c` |
| `stubv2_compress()` adds nothing at all unless the packet's first byte is `0x50` | `src/openvpn/compstub.c`, via `compv2_escape_data_ifneeded()` |
| 2.4 compresses on send by default; 2.5 and 2.6 require `allow-compression yes` (`COMP_F_ALLOW_COMPRESS`) | `src/openvpn/lzo.c`, `lzo_compression_enabled()`, in each series |
| 2.6 refuses `comp-lzo` unless compression is re-enabled | `src/openvpn/comp.c`, `check_compression_settings_valid()` |

---

## 2. What was captured

`internal/compress/testdata/vectors.json` holds **28 vectors** from seven real
handshakes. Each records one data packet crossing the compression layer, in one
direction, confirmed twice.

| Field | Meaning |
|---|---|
| `name` | run, direction and probe size |
| `mode` | the compression family as a `.ovpn` or a PUSH_REPLY spells it — this is what `compress.ParseMode` is fed |
| `directive` | the exact line both peers' configs carried |
| `alg` | OpenVPN's own name for the algorithm that ran: `lzo`, `stub`, `stubv2`, `lz4`, `lz4v2` |
| `comp_flags` | `compctx->flags` as `options.c` computed it |
| `swap` | `COMP_F_SWAP`, restated |
| `openvpn_version` | the release both peers ran |
| `sender`, `receiver`, `direction` | which peer produced `framed` and which one accepted it |
| `compressed` | whether the sender actually compressed this payload |
| `framing_byte` | the leading framing byte, empty when the framing adds none |
| `plain` | the IP packet |
| `framed` | the payload as it appeared inside the data channel |

### The seven runs

| Run | Version | Directive | Vectors |
|---|---|---|---:|
| `v24-complzo` | 2.4.12 | `comp-lzo yes` | 4 |
| `v25-complzo` | 2.5.11 | `comp-lzo` | 4 |
| `v24-compress` | 2.4.12 | `compress` | 4 |
| `v24-lz4` | 2.4.12 | `compress lz4` | 4 |
| `v24-lz4v2` | 2.4.12 | `compress lz4-v2` | 4 |
| `v25-stubv2` | 2.5.11 | `compress stub-v2` | 4 |
| `v26-stubv2` | 2.6.22 | `compress stub-v2` | 4 |

Four per run: a probe **below** `COMPRESS_THRESHOLD` and one far above it that
is a run of a single byte, in **each direction**.

Both sizes, because a peer that never compresses and a peer that declined to
compress *this* packet are different peers, and only the large probe separates
them — that is how the 2.4/2.5 difference in §6 was measured rather than
assumed. Both directions, because the marker a peer sends is what our `Unwrap`
must accept and the marker it accepts is what our `Wrap` must send, and those
are different questions.

`comp-lzo` stops at 2.5 because a 2.6 server refuses it outright unless
compression is re-enabled — the same reason `MatrixEntry.SkipReason` gives, and
the reason the matrix exercises `comp-lzo` on 2.4 and 2.5 only.

### Why `lz4` and `lz4-v2` are here at all

The framings that had to be covered are `comp-lzo`, bare `compress` and
`compress stub-v2`. `compress lz4` and `compress lz4-v2` are extra, and they are
the two runs that actually settle the inverted constants: `ModeLZ4` is the mode
whose constant was under suspicion, and `compress lz4` is the only directive
that puts `0x69` on a wire. Settling that without them would have meant
reasoning by analogy from `comp-lzo`, which is the failure mode this whole
capture exists to avoid.

### Is committing this safe?

Yes, and more plainly than for the wrap vectors. Every `plain` is a UDP datagram
of `'A'` that the capture generated inside a throwaway container and sent to a
closed port; every `framed` is that datagram after a local OpenVPN framed it.
There is **no key material in this file at all** — unlike
[`TLS-WRAP-VECTORS.md`](TLS-WRAP-VECTORS.md), which had to argue for a throwaway
static key, this capture records no keys, no session material and no
certificates. Nothing came from the provider corpus, and the PKI that carried
the handshakes was generated inside a container and never written to the host.

---

## 3. How to regenerate

Needs Docker, `/dev/net/tun` on the host, and outbound network for the first
build (three OpenVPN tarballs and two Debian base images).

```sh
make comp-vectors
```

That is the whole procedure. It runs the two steps below in order.

### 3.1 Build the instrumented images

```sh
bash docker/openvpn-server/build-compdebug.sh          # 2.4, 2.5 and 2.6
bash docker/openvpn-server/build-compdebug.sh 2.4      # one series
```

Produces `go-openvpn-test/openvpn-server:{2.4.12,2.5.11,2.6.22}-compdebug` from
the same Dockerfile, the same pinned tarballs (SHA-256 verified) and the same
pinned base images as the stock matrix build, with two differences:

- `--build-arg PATCH_DIR=patches-compdebug` selects
  `docker/openvpn-server/patches-compdebug/` instead of the empty default
  `patches/`, so `001-compdebug-framing.patch` is applied; and
- every tag carries a `-compdebug` suffix.

**Both matter.** The instrumented build prints every tunnelled IP packet in the
clear into its log. It must never answer to a plain
`go-openvpn-test/openvpn-server:<ver>` tag that `testenv.StartMatrix` and every
other test resolve. `build-compdebug.sh` refuses to run if a suffix ever
computes to a stock tag, refuses if the patch directory is empty, and — after
each build — greps the resulting binary for the instrumentation's format string,
because an unpatched image carries traffic perfectly and prints nothing, which
looks like a capture-script bug rather than a build bug.

Unlike the wrap capture, all three series are built. The wraps are unchanged
across 2.4–2.6 and one series was enough; compression is not. 2.4 compresses on
send by default and 2.5 does not, 2.6 refuses `comp-lzo` outright, and those
differences are the answer rather than noise around it.

### 3.2 Run the capture

```sh
bash docker/openvpn-server/comp-capture.sh          # -> internal/compress/testdata/vectors.json
bash docker/openvpn-server/comp-capture.sh -o /tmp/v.json
bash docker/openvpn-server/comp-capture.sh -k       # keep containers on failure
```

Per run it:

1. generates a throwaway PKI **inside a container** — the same mechanism
   `testenv.StartMatrix` uses, so no PKI material ever touches the host
   filesystem; it is generated once and reused, because unlike the wrap capture
   nothing here is keyed;
2. starts a server container and waits for OpenVPN's own
   `Initialization Sequence Completed`;
3. starts a client container of the same instrumented image and waits for the
   same line;
4. reads both peers' tun addresses off `ip addr` rather than assuming them;
5. pushes four UDP probe datagrams through the finished tunnel — small and
   large, in both directions — using `bash`'s `/dev/udp`, because the runtime
   image has no `ping` and adding one would mean rebuilding the stock matrix
   images that another suite is entitled to assume are unchanged;
6. locates each probe in **both** peers' logs by a marker unique to that probe,
   and cross-checks the sender's `compress()` dump against the receiver's
   `decompress()` dump;
7. checks the decomposition of every packet before recording it (§3.4);
8. tears both containers down.

No cipher, digest or wrap is pinned in the generated configs. Compression
framing sits above all three, 2.6 removed `--ncp-disable` outright, and a config
that has to be spelled three ways per series is a config that will rot.

2.4's `comp-lzo` run uses `comp-lzo yes` rather than a bare `comp-lzo` on
purpose. A bare `comp-lzo` is `COMP_F_ADAPTIVE`, and an adaptive compressor's
decision depends on what it has already seen; `yes` is flags 0, which always
attempts. A compressed vector has to be reproducible. 2.5's run is deliberately
the bare form, because 2.5's default is exactly what a corpus config will meet.

### 3.3 The ICMP trap

A UDP datagram to a closed port draws an ICMP port-unreachable, and Linux packs
as much of the offending datagram into that error as fits in 576 bytes — the
probe's marker included. So the reply to a client probe is a *server-to-client*
packet carrying the *client* probe's marker.

The first run of this capture used one marker per size for both directions, and
recorded four ICMP errors as though they were server-originated packets. Every
structural check passed, both peers' dumps agreed, and the framing bytes were
correct — the vectors were simply about a different packet than the label said.
Markers now name the direction. It is written down here because the failure was
invisible except in the packet lengths.

### 3.4 What the capture refuses to record

Every check below is a check on *our* reading, not on OpenVPN. A vector that
fails one of them is not written out, and the script exits non-zero saying which
claim broke:

- the receiver's `decompress()` output must equal the sender's `compress()`
  input, and the receiver's input must equal the sender's output — two
  independent dumps from two processes in two containers, so a mis-transcribed
  packet would have to be wrong identically on both sides;
- `lzo` must never carry `COMP_F_SWAP`, and `lz4` must always carry it;
- an uncompressed `lzo` framing must be exactly `0xFA ‖ plain`;
- an uncompressed swapping framing must be exactly
  `0xFB ‖ plain[1:] ‖ plain[0]`;
- a v2 framing must leave the packet byte-identical, unless it is the
  compressed `0x50 0x01` form;
- a compressed framing must not carry an unchanged payload under a
  compressed marker;
- at least one vector across the whole capture must be genuinely compressed,
  or the decompressor would have nothing real to decode.

---

## 4. The patch

`docker/openvpn-server/patches-compdebug/001-compdebug-framing.patch` touches
one function in one file.

**`src/openvpn/comp.c`, `comp_init()`** — after the algorithm's own
`compress_init()` runs, the two function pointers in the per-context copy of
`struct compress_alg` are replaced with trampolines that dump the buffer on both
sides of the framing:

```
COMPDEBUG <alg> <flags> <compress|decompress> <pre-hex> <post-hex>
```

Three properties of that choice are why it is one hunk rather than eight:

- **One insertion point covers every algorithm.** The dispatch is already
  through function pointers, so hooking the pointers reaches `comp-lzo`,
  `compress`, `compress lz4`, `compress lz4-v2` and `compress stub-v2` without
  touching `compstub.c`, `lzo.c` or `comp-lz4.c` at all — and it cannot miss a
  path, because there is no other way in.
- **One patch covers all three series.** `comp_init()` is byte-identical in
  2.4.12, 2.5.11 and 2.6.22, and so are `struct compress_alg` and
  `struct compress_context`. The patch applies to all three with zero fuzz.
  This is the opposite of the wrap patch's situation, where
  `write_control_auth()` grew a `tls_wrap_ctx` indirection after 2.4 and a 2.5
  build would have needed a rewrite.
- **Both stages arrive on one line.** The compression layer sees OCC probes,
  keepalive pings and the capture's own packets interleaved; pairing a "before"
  line with the "after" line that belongs to it would be a guess. One call, one
  line, no pairing — which is a stronger position than the wrap capture's, where
  the stages genuinely are separate buffers.

`<flags>` is `compctx->flags` as `options.c` computed it, so `COMP_F_SWAP` is
recorded rather than inferred from the directive. That matters: the same
`stub_compress()` produces two different framings depending on one bit, and the
bit is not visible in the directive a corpus config writes.

The originals are kept in a small table keyed on `alg.name`, which the hook does
not overwrite, so a process that ends up with two different algorithms still
dispatches each context to its own implementation rather than through whichever
one initialised first.

### Why the dumper bypasses `msg()`

Same reason as the wrap patch, and it is worth restating because the next person
to extend either will hit it. `msg()` formats into a buffer of `ERR_BUF_SIZE`
(1280 without PKCS#11) and then formats *again* to prepend the per-instance peer
address, so a long line is silently clipped somewhere past 1200 characters — and
where exactly depends on how long the tag and the peer's address are. A
full-MTU packet is 3000 hex characters. A silently truncated vector is worse
than a missing one, because it still looks like a vector.

---

## 5. Two upstream oddities the capture met

Neither affects the vectors. Both are recorded here so the next reader does not
rediscover them.

**`compv2_escape_data_ifneeded()` writes the wrong byte.** When a packet's first
byte collides with `COMP_ALGV2_INDICATOR_BYTE` it prepends a two-byte header,
and the second byte it writes is `COMP_ALGV2_UNCOMPRESSED` — the *algorithm id*,
10 — where `stubv2_decompress()` checks for `COMP_ALGV2_UNCOMPRESSED_BYTE`,
which is 0. The two do not agree. This is present identically in 2.4.12, 2.5.11
and 2.6.22.

It is unreachable in practice: the first byte of an IPv4 packet is `0x45` and of
an IPv6 packet `0x6…`, never `0x50`, so no kernel produces a packet that
triggers the escape. **No vector covers it**, because no probe this rig can send
would. `internal/compress` therefore encodes the escape from the *decoder's*
constant — a peer that ever sends the escape will send whatever its own encoder
writes, and ours has to be readable by theirs, not by itself — accepts either
byte on the way in, and says in a comment that the branch is untested against a
real peer.

**2.5 and 2.6 do not compress on send by default.** `lzo_compression_enabled()`
requires `COMP_F_ALLOW_COMPRESS`, which only `allow-compression yes` sets, so a
2.5 server with `comp-lzo` frames every packet `0xFA` no matter how compressible
it is — §6 measures exactly that on a 1259-byte run of `'A'`. 2.4 has no such
gate. So the same directive against two servers one release apart produces a
compressed payload from one and never from the other, and an implementation
tested only against 2.5 would never meet a compressed payload at all.

---

## 6. What the bytes say

This is what the capture was taken for. Every row was measured, in both
directions, from a real peer.

| Directive | Version | Payload | Framing byte | Layout |
|---|---|---|---|---|
| `comp-lzo yes` | 2.4.12 | not compressed | `0xFA` | `0xFA ‖ plain` |
| `comp-lzo yes` | 2.4.12 | **compressed** | `0x66` | `0x66 ‖ LZO(plain)` |
| `comp-lzo` | 2.5.11 | not compressed | `0xFA` | `0xFA ‖ plain` |
| `compress` | 2.4.12 | not compressed | `0xFB` | `0xFB ‖ plain[1:] ‖ plain[0]` |
| `compress lz4` | 2.4.12 | not compressed | `0xFB` | `0xFB ‖ plain[1:] ‖ plain[0]` |
| `compress lz4` | 2.4.12 | **compressed** | `0x69` | `0x69 ‖ LZ4(plain) swapped the same way` |
| `compress lz4-v2` | 2.4.12 | not compressed | none | `plain`, unchanged |
| `compress lz4-v2` | 2.4.12 | **compressed** | `0x50 0x01` | `0x50 0x01 ‖ LZ4(plain)` |
| `compress stub-v2` | 2.5.11, 2.6.22 | not compressed | none | `plain`, unchanged |

**The inversion is confirmed.** `0x69` is `LZ4_COMPRESS_BYTE` and appears only
on payloads a peer genuinely compressed; `0xFA` is `NO_COMPRESS_BYTE` and
appears only on payloads it did not. The implementation these vectors were
captured against had them exactly the wrong way round, and in `ModeLZ4` it sent
`0x69` — *this payload is lz4-compressed* — on every packet, over plaintext.

The vectors say two further things that reading the one constant did not reach:

- **`compress lz4` swaps.** `lz4_compress()` moves the payload's first byte to
  the tail whether or not it compressed. A corrected constant, prepended, is
  still wrong — and wrong in a way that shifts every subsequent byte by one,
  which is the shape of corruption that looks like a decryption failure.
- **Bare `compress` is a third framing.** It is `COMP_ALG_STUB` with
  `COMP_F_SWAP` — `0xFB` and a swap — and the `ParseMode` of the day returned
  `ModeNone` for it, so a profile asking for it sent an unframed packet to a
  peer that would reject it.

### The discrimination evidence

Run against the implementation the capture found, **20 of the 28 vectors
failed**. The 8 that passed are all `compress stub-v2`, and they passed for an
unrelated reason: that path sends no framing byte at all, so the constant is
never reached.

Representative failures, as the test reported them:

```
v24-lz4-c2s-small
  Wrap(1, plain) = 6945000037a3ff40… (56 bytes)
    want         fb000037a3ff4000… (56 bytes)
    first difference at byte 0: got 0x69, want 0xfb
  Unwrap(1, framed): compress: lz4: unexpected stub byte 0xfb

v24-lz4-c2s-large
  Unwrap(1, <compress lz4 payload, 72 bytes>) returned 71 bytes and no error;
  want a compressed-payload error naming lz4. This is the silent corruption
  this framing exists to prevent: those 71 bytes are a compressed blob about to
  be handed to the tunnel as an IP packet

v24-complzo-c2s-small
  Wrap(2, plain) = 4500003bec1a4000… (59 bytes)
    want         fa4500003bec1a40… (60 bytes)
    first difference at byte 0: got 0x45, want 0xfa

v24-compress-c2s-small
  Wrap(0, plain) = 4500003c43524000… (60 bytes)
    want         fb00003c43524000… (61 bytes)
    first difference at byte 0: got 0x45, want 0xfb
```

The second one is the whole argument for capturing these rather than reading
them. `Unwrap` does not merely return the wrong bytes: it returns **no error**,
having stripped `0x69` as though it meant "not compressed", and hands 71 bytes
of LZ4 stream to the tunnel as an IP packet. Nothing downstream would notice.

What this does **not** rule out: an implementation wrong in a way no vector
exercises. `compv2_escape_data_ifneeded()` has no vector (§5) and neither does
`compress stub` in its non-swapping form or `comp-lzo no`, because no probe this
rig can send reaches them. `allow-compression` is not exercised either;
`EffectiveMode` and `allow-compression no` are covered by unit tests in
`internal/compress` instead. And nothing here tests a *hostile* framing byte: a
peer that sends `0x00` should be refused, and that too is a unit test rather
than a captured vector.

---

## 7. How the vectors are used

`internal/compress/vectors_test.go` holds three tests. None of them needs
Docker; `go test ./...` runs them from the committed JSON.

- **`TestVectorsAreWellFormed`** — guards the testdata: field consistency,
  unique names, IPv4 packets, and a floor of ≥6 vectors spanning all three
  required modes on all five required version/mode pairs, both directions for
  each mode, both framings, and at least one genuinely compressed payload.
- **`TestVectorsDecomposeAsRecorded`** — pins §6's layout table into the
  repository. The capture script checks the same decompositions before writing,
  so this cannot fail on fresh data; it is here so that a hand-edit, a truncated
  field or a re-capture against a different series shows up as a structural
  failure rather than as an inscrutable byte mismatch in the known-answer test
  below.
- **`TestCompressReproducesCapturedFraming`** — the known-answer test. §6 is
  what it printed the first time it was run; all 28 vectors now pass in both
  directions against `internal/compress`. The compressed `comp-lzo yes`
  payloads must decompress to the captured packet exactly, and fail one byte
  short of it.

`mode := compress.ParseMode(v.Mode)` in that last test is deliberate. It feeds
the vector through the parser rather than around it, because a framing that is
right for a `Mode` the parser never produces is not right for anything. Four of
the seven runs parsed to a `Mode` that did not describe them, which is why the
package carries seven modes rather than three. Keep the parser in the path.

---

## 8. Cleaning up

`make matrix-clean` removes matrix containers, networks and images, including
the `-compdebug` tags. The capture script removes its own containers and network
on the way out, and on failure too unless `-k` is given. Its label is
`net.bngs.goopenvpn.testenv=comp-capture`, distinct from the matrix's and from the
other two captures', so `TestMatrixLeavesNoStrays` neither sees it nor is
confused by it.
