# Using openvpn3 as a Reference

Version: 1.0
Applies to: all protocol work in `go-openvpn`
License: LGPL-2.1-or-later

---

## Summary

We consult the openvpn3 source as the authoritative description of the OpenVPN
wire protocol. **We take openvpn3 under the MPL-2.0 branch of its dual license,
never under AGPL-3.0-only.** This document records that election, the reasoning
behind it, and the working rules that follow from it.

This is the project's engineering position, not legal advice. It has not had
formal review.

---

## 1. The licensing facts

| | |
|---|---|
| This repository | LGPL-2.1-or-later, plus `LICENSE_USAGE_EXCEPTION` |
| openvpn3 | `SPDX-License-Identifier: MPL-2.0 OR AGPL-3.0-only WITH openvpn3-openssl-exception` |
| Exhibit B marker | Absent from every openvpn3 source file |

The third row is the one that matters. MPL-2.0 lets a licensor mark a file
"Incompatible With Secondary Licenses" (Exhibit B), which would block the route
described below. No openvpn3 source file carries that marker — the only
occurrence of the phrase anywhere in the tree is the boilerplate text inside
`LICENSES/MPL-2.0.txt` itself.

## 2. Why the MPL branch works for us

MPL-2.0 §3.3 permits distributing covered software under a *Secondary License*.
MPL-2.0 §1.12 defines Secondary License as GPL-2.0-or-later, LGPL-2.1-or-later,
or AGPL-3.0-or-later.

This repository is LGPL-2.1-or-later. So openvpn3 code taken under the MPL
branch may be incorporated and distributed under our existing license, provided
attribution is preserved.

The AGPL branch offers no such route and would impose network-copyleft
obligations that conflict with both this repository's license and its usage
exception. **Do not read openvpn3 with the intent of relying on the AGPL
grant, and do not copy from any openvpn3 fork that is AGPL-only.**

## 3. Working rules

### 3.1 Protocol facts are free

Wire formats, packet layouts, opcode values, algorithm identifiers, key
derivation labels, constant values, and the sequence of a handshake are facts
about a protocol. They are not copyrightable expression. Reading openvpn3 to
learn that the classic key expansion label is `"OpenVPN key expansion"`, or
that the GCM auth tag precedes the ciphertext on the wire, and then writing an
independent Go implementation, needs no license grant at all.

Most of what we take from openvpn3 falls in this category.

### 3.2 Transliterated structure is a derivative work

If a Go function follows a specific openvpn3 function's structure — its
decomposition, its ordering, its variable naming, its control flow — closely
enough that it reads as a translation rather than an independent implementation,
treat it as a derivative work. That is permitted under MPL-2.0, but it carries
obligations:

- Preserve the OpenVPN Inc. copyright notice in the Go file's header
- Note MPL-2.0 as the origin license for that file's derived portion
- Keep the citation (see 3.3) specific enough to identify what was derived

When in doubt, prefer writing from the protocol facts rather than from the
C++ structure. It is usually better Go anyway.

### 3.3 Cite provenance, always

The codebase already does this well, and the convention should continue:

```go
// Reference: openvpn3-core ssl/proto.hpp KeyContext::init_data_channel() line ~2297
```

These citations serve three purposes: they let the next reader verify a claim
against the source, they document which parts of the protocol we believe we
understand and from where, and they are the evidence trail for §3.2. Include
the file path and a symbol name; line numbers drift, so treat them as
approximate and prefer naming the function.

### 3.4 Verify before trusting

Citations are only as good as the reading behind them. The classic key
derivation in `internal/prf` carried confident references to openvpn3 while
implementing a completely different algorithm — wrong PRF, wrong inputs — and
the tests passed because they only asserted output length and determinism. A
citation is a claim to be checked, not a guarantee.

Where a derivation or wire format is security-relevant, back the citation with
a known-answer test vector captured from a real OpenVPN peer.

## 4. Open question: LGPL-2.1 and static linking

Separate from the openvpn3 question, and unresolved: LGPL-2.1's relinking
requirement is a known friction point for statically linked iOS applications.
If a third-party mobile client built on this library is a goal, an added
exception covering static linking is likely needed.

That is a conversation for the copyright holders and does not gate any
protocol work. Recorded here so it is not forgotten.

---

## References

- openvpn3 licensing: `LICENSE.md` and `LICENSES/` in the openvpn3 tree
- MPL-2.0 §1.12 (Secondary License), §3.3 (Distribution of a Larger Work)
- This repository: `LICENSE`, `LICENSE_USAGE_EXCEPTION`
