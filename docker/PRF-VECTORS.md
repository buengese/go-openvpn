# Capturing OpenVPN PRF known-answer vectors

Version: 1.0
Applies to: `internal/prf/testdata/vectors.json`
License: LGPL-2.1-or-later

How `internal/prf/testdata/vectors.json` was produced, and how to produce it
again from a clean checkout.

---

## 1. Why

When these vectors were captured, `internal/prf` derived data-channel keys with
HMAC-SHA256 over the *TLS session's* master secret and hello randoms. OpenVPN
does neither. Both peers exchange their own key material inside the
already-encrypted control channel and derive from it in two stages:

```
master    = TLS1_PRF(client.pre_master, "OpenVPN master secret",
                     client.random1 ‖ server.random1)                ->  48 B

key_block = TLS1_PRF(master,            "OpenVPN key expansion",
                     client.random2 ‖ server.random2
                     ‖ client_sid ‖ server_sid)                      -> 256 B
```

`TLS1_PRF` is the TLS 1.0 split PRF — `P_MD5(S1, seed) XOR P_SHA1(S2, seed)`,
where `S1` and `S2` are the two halves of the secret, each `ceil(len/2)` bytes
so they overlap by one byte when the secret has odd length. It is not
HMAC-SHA256.

That is a different algorithm over different inputs, and it blocked all 575
corpus configs. The self-consistency tests in `internal/prf/prf_test.go` assert
output length, determinism and label-sensitivity — every one of which a
plausible wrong PRF also satisfies. Known-answer vectors taken from a real peer
are the only test that can tell the two apart, so the derivation is measured
against an actual OpenVPN server rather than against its own reasoning.

### Provenance of the protocol facts

Per [`../docs/openvpn3-reference-policy.md`](../docs/openvpn3-reference-policy.md)
§3.3, everything above is cited, and — §3.4 — verified rather than trusted.
These are readings of the OpenVPN 2.4.12 release tarball this rig pins:

| Fact | Where |
|---|---|
| Two-stage derivation, both labels, argument order | `src/openvpn/ssl.c`, `generate_key_expansion()` |
| Seed layout: `label ‖ client_seed ‖ server_seed ‖ client_sid ‖ server_sid` | `src/openvpn/ssl.c`, `openvpn_PRF()` |
| MD5+SHA1 split PRF, halves overlapping on odd lengths | `src/openvpn/ssl.c`, `tls1_PRF()` and `tls1_P_hash()` |
| `KEY_EXPANSION_ID` is `"OpenVPN"`, so labels are `"OpenVPN master secret"` / `"OpenVPN key expansion"` | `src/openvpn/ssl.h` |
| `pre_master` 48 B, `random1`/`random2` 32 B each | `src/openvpn/ssl_common.h`, `struct key_source` |
| Session IDs are 8 bytes | `src/openvpn/session_id.h`, `SID_SIZE` |
| Key block is 256 B: two `struct key` of 64 B cipher + 64 B hmac | `src/openvpn/crypto.h`, `struct key` / `struct key2` |
| Only the client generates a `pre_master` | `src/openvpn/ssl.c`, `key_source2_randomize_write()` |
| Which side is `client_sid` and which is `server_sid` | `src/openvpn/ssl.c`, `tls_session_generate_data_channel_keys()` |

The openvpn3 sources for the same construction — `openvpn/ssl/tlsprf.hpp`
`TLSPRF::gen_exp()`, `openvpn/openssl/crypto/tls1prf.hpp`, and
`openvpn/crypto/static_key.hpp` — describe it from the other implementation. The
vectors here are the empirical confirmation that both readings are right.

---

## 2. What was captured

`internal/prf/testdata/vectors.json` holds four vectors. Each records every
input to and both outputs of one real handshake:

| Field | Bytes | Meaning |
|---|---:|---|
| `client_pre_master` | 48 | client's pre-master secret |
| `client_random1`, `server_random1` | 32 each | stage-one seed |
| `client_random2`, `server_random2` | 32 each | stage-two seed |
| `client_session_id`, `server_session_id` | 8 each | stage-two seed tail |
| `master_secret` | 48 | stage-one output |
| `key_block` | 256 | stage-two output — the answer |

`master_secret` is recorded even though only `key_block` is the deliverable. It
localises a failure to one stage: a wrong `key_block` with a right `master` is a
stage-two bug, and the two stages differ only in their seed.

The four vectors were captured against the cipher and digest shapes deployed
profiles were seen to use. The vector files are captured artefacts and keep the
parameters they were taken with:

| Vector | Cipher | Digest | Proto |
|---|---|---|---|
| `aes256cbc-sha512` | AES-256-CBC | SHA512 | udp |
| `aes128cbc-sha256` | AES-128-CBC | SHA256 | udp |
| `aes256cbc-sha1` | AES-256-CBC | SHA1 | udp |
| `aes256gcm-sha256` | AES-256-GCM | SHA256 | tcp |

Which providers deploy which shape, and how many configs each accounts for, is
a property of a corpus rather than of these vectors: it changes whenever the
corpus does, and the capability matrix the provider-sweep tool writes is where it is
recorded. Earlier revisions of this table carried those counts and went stale
twice over, naming providers that had left.

The SHA1 row earns its place regardless of any count: a profile with no `auth`
directive takes OpenVPN's SHA1 default rather than a modern one, which is the
same dependency `datachannel.ResolveParams` names.

**The key block does not depend on the cipher or the digest.** The PRF emits the
same 256 bytes whatever consumes them; cipher and digest only decide how those
bytes are sliced afterwards. The combinations are therefore provenance, not four
different algorithms — they record which negotiated parameters were live when
each vector was taken, and they prove the derivation is invariant across the
shapes the corpus actually deploys. The vectors differ from one another because
the session material is fresh per handshake, not because the parameters changed.

### Is committing this safe?

Yes. Every value is ephemeral session material from a throwaway local server
whose PKI was generated inside a container, used for one handshake, and
destroyed. Nothing is reused, nothing is a credential, and no host key material
is written at any point. Corpus material and credentials never enter this
repository; these vectors are committed because nothing in them is a secret that
outlives the throwaway container that produced it.

---

## 3. How to regenerate

Needs Docker, `/dev/net/tun` on the host, and outbound network for the first
build (the OpenVPN tarball and the Debian base image).

```sh
make prf-vectors
```

That is the whole procedure. It runs the two steps below in order.

### 3.1 Build the instrumented image

```sh
bash docker/openvpn-server/build-prfdebug.sh
```

Produces `openlawsvpn-test/openvpn-server:2.4.12-prfdebug` from the same
Dockerfile, the same pinned tarball (SHA-256 verified) and the same pinned base
image as the stock matrix build, with two differences:

- `--build-arg PATCH_DIR=patches-prfdebug` selects
  `docker/openvpn-server/patches-prfdebug/` instead of the empty default
  `patches/`, so `001-prfdebug-key-expansion.patch` is applied; and
- the tag carries a `-prfdebug` suffix.

**Both matter.** The instrumented build prints the data-channel key block into
its log on every handshake. It must never answer to the plain
`openlawsvpn-test/openvpn-server:2.4.12` tag that `testenv.StartMatrix` and
every other test resolve — overwriting that tag would quietly turn the entire
test matrix into a key-material leak. `build-prfdebug.sh` refuses to run if the
suffix ever computes to the stock tag, and refuses if the patch directory is
empty, because an unpatched image completes handshakes perfectly and prints
nothing, which looks like a capture-script bug rather than a build bug.

2.4 is the required series: it predates the TLS keying-material exporter, so the
classic two-stage PRF is the only derivation path it has. A 2.6 server would
negotiate `key-derivation tls-ekm` and capture the wrong thing.

### 3.2 Run the capture

```sh
bash docker/openvpn-server/prf-capture.sh          # -> internal/prf/testdata/vectors.json
bash docker/openvpn-server/prf-capture.sh -o /tmp/v.json
bash docker/openvpn-server/prf-capture.sh -k       # keep containers on failure
```

Per cipher/digest row it:

1. generates a throwaway PKI **inside a container** and emits it as a base64 tar
   — the same mechanism `testenv.StartMatrix` uses, so no key material ever
   touches the host filesystem;
2. starts a server container and waits for OpenVPN's own
   `Initialization Sequence Completed`;
3. starts a client container of the same instrumented image and waits for the
   same line;
4. reads the `PRFDEBUG` lines out of `docker logs`;
5. checks every field's length, and checks that the client's independent dump
   agrees with the server's on all nine fields;
6. appends the vector and tears both containers down.

Server and client configs use `ncp-disable`. Without it OpenVPN 2.4 negotiates
AES-256-GCM regardless of what the config asked for, and the recorded cipher
would not be the cipher that ran.

Config file paths in the generated configs are absolute (`/etc/openvpn/ca.crt`).
OpenVPN resolves relative paths against the process working directory, not
against the directory the config was read from.

---

## 4. The patch

`docker/openvpn-server/patches-prfdebug/001-prfdebug-key-expansion.patch` adds a
hex dumper to `src/openvpn/ssl.c` and calls it from `generate_key_expansion()`,
immediately after the second `openvpn_PRF()` call and before `fixup_key()` — so
`key_block` is the raw PRF output, not a parity-adjusted variant. (`fixup_key()`
only alters DES keys, but capturing before it removes the question.)

Nine lines are emitted per derivation, each `PRFDEBUG <tag> <hex>`, bracketed by
`PRFDEBUG begin role=server|client` and `PRFDEBUG end`.

### Why only the server needs patching

The server's view is complete. `struct key_source2` holds both peers'
contributions: the client's `pre_master`, `random1` and `random2` arrive in the
key-method-2 packet and land in `key_src->client` (`key_method_2_read()`), while
`key_src->server` is filled locally (`key_source2_randomize_write()`). Both
session IDs are passed in by `tls_session_generate_data_channel_keys()`. So one
patched server captures every input.

The capture runs a patched **client** as well, but not out of necessity — it is
the cross-check. Both peers derive the same block from the same inputs, so the
two independent dumps must agree, and a vector is only recorded when they do.
A mis-transcribed field would have to be wrong identically on both sides to slip
through.

### Applying it to other series

The patch is written against 2.4.12 and is only used there. `patches/` (the
default set the matrix images build with) stays empty. If a 2.5 or 2.6
instrumented build is ever needed, note that `generate_key_expansion()`'s
signature changed after 2.4 — the patch will need rewriting, not just re-basing,
and it should live in its own `patches-*` directory with its own tag suffix.

---

## 5. How the vectors are used

`internal/prf/vectors_test.go` holds two tests:

- **`TestKeyMethod2Vectors`** — the real check. Feeds the recorded inputs to
  `prf.DeriveMasterSecret` and `prf.DeriveKeyBlock` and compares both against
  the recorded answers. Each vector runs as two nested subtests, so a failure
  names the stage it happened in — which is the whole reason `master_secret` is
  recorded at all.
- **`TestVectorsAreWellFormed`** — guards the testdata: field lengths, distinct
  key blocks, complete provenance, and a floor of at least three vectors across
  at least two cipher/digest combinations, so a later edit cannot quietly narrow
  the ground truth.

Neither needs Docker; `go test ./...` runs them from the committed JSON.

### The signature the vectors ask for

The recorded inputs do not fit a TLS-shaped `ExpandKeys(masterSecret,
clientRandom, serverRandom)`, and they were not bent to. `internal/prf` takes
the key-method-2 material in the shape the peers exchange it:

```go
// KeySource is one peer's contribution to the key-method-2 exchange.
type KeySource struct {
	PreMaster []byte // 48 bytes, client only
	Random1   []byte // 32 bytes, seeds the master secret
	Random2   []byte // 32 bytes, seeds the key expansion
}

func DeriveKeyBlock(client, server KeySource, clientSessionID, serverSessionID []byte) ([]byte, error)
func DeriveMasterSecret(client, server KeySource) ([]byte, error)
```

`prf.Split` keeps the job of cutting a key block into the four 64-byte slots at
offsets 0, 64, 128 and 192, but takes the block rather than TLS material.

---

## 6. Cleaning up

`make matrix-clean` removes matrix containers, networks and images, including
the `-prfdebug` tag. The capture script removes its own containers and network
on the way out, and on failure too unless `-k` is given.
