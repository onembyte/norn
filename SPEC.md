# Norn — Specification v1

Written **2026-09-18** (plan part 4). Status: **v1**, frozen 2026-09-20.

Frozen means: a second implementation may be written against this document and
the vectors beside it, and neither will change under it. One normative change
has been made since, dated and decided: §11's fork handling and §11.1's
evidence version 2 (D-072 (a), 2026-10-09); a version-1 evidence file is still
read exactly as before. Every cross-reference
resolves and no open items remain. What
changed on the way to v1 is in `BUILD-LOG.md`; the decisions behind it are in
`DECISIONS.md`, numbered and dated.
§12.1 lists what is vectored and what is not. It does **not** claim every MUST is vectored — several are not, and they are named there.
The companion documents — `GOSSIP.md`, `ENFORCEMENT.md` and `ENROLLMENT.md` —
are **informative**: they narrate distribution, enforcement operation and
enrollment ceremony, and no rule lives in them (D-064). What a second
implementation needs is in this document and the vectors beside it, and a
companion that disagrees is the companion that is wrong.

Norn reuses these specifications verbatim. Where this document states a rule more narrowly than one of them — a profile, a closed set, an exact count — its rule governs, as §4.0's profile of RFC 8949, §6's three-line checkpoint body and §16.2's profile of BIP-350 do; where they otherwise conflict, they win (cold gate run 17, D12). In particular §7 and §10 are Norn's profile of `c2sp.org/signed-note`, `tlog-checkpoint` and `tlog-cosignature`, and govern where they are stricter:
every line from a trusted key verifies, that key fixes the line's exact length,
the base64 is canonical, and the note is UTF-8 (D-074 c). The specifications:

- `c2sp.org/tlog-tiles` — log storage and read API
- `c2sp.org/tlog-checkpoint` — signed tree heads
- `c2sp.org/signed-note` — signature line format
- `c2sp.org/tlog-cosignature` — witness cosignatures (v1)
- `c2sp.org/tlog-witness` — witness HTTP protocol
- `c2sp.org/tlog-policy` — witness quorum policy (§9.1)
- `c2sp.org/tlog-proof` (v1) — self-contained inclusion proof bundles. Referenced for comparison only: §8.1 is Norn's own format and is **not** claimed byte-compatible
- RFC 6962 §2.1 — Merkle tree hashing (SHA-256)
- RFC 6962 §2.1.1 — the Merkle audit path, which is the inclusion proof §8.1
  carries
- RFC 6962 §2.1.2 — the Merkle consistency proof §11.1 carries. Both sections
  define a proof and the node order it is in; neither gives a procedure for
  checking one
- RFC 9162 §2.1.3.2 and RFC 9162 §2.1.4.2 — verifying an inclusion proof and
  verifying consistency between two tree heads: the procedures §8.1 and §11.1 check those
  proofs with, not restated here. A list with more or fewer hashes than the
  procedure consumes is not the proof, and is refused (cold gate run 16, M3)
- RFC 8949 §4.2.1 — deterministic CBOR ("core deterministic encoding")
- RFC 4648 §6 — base32, for `origin` (§2, §9.1). The alphabet is given in §2
  because this document also uses a *different* base32 in §9.3
- BIP-350 — bech32m, the text form of an enrollment request (§16.2). §16.2
  states Norn's choices within it and nothing else about it
- RFC 8032 — Ed25519 · RFC 7748 — X25519
- RFC 4291 §2.2 — IPv6 address text, the grammar of a grant's addresses (§4.0) ·
  RFC 5952 — the canonical IPv6 text a grant is written and compared in (§4.0)

Referenced but **not** reused: BIP-173, whose 90-character limit §16.2
explains does not apply here.

---

## 1. Terms and notation

- **Network**: one Norn deployment, identified by `net_id`.
- **Log**: an append-only Merkle tree of **entries**, served per tlog-tiles.
- **Entry**: one CBOR-encoded, signed statement (§4).
- **State**: the result of replaying all entries of the log in order (§5).
- **Proven set**: the `active` devices in state, each with a proof bundle (§8).
- `H(x)` = SHA-256. `‖` = concatenation. `b64` = standard base64 with padding.
- Key ID `kid(pk)` = first 8 bytes of `H(pk)`, lowercase hex (16 chars). Used inside entries.
  (Signed-note key IDs on checkpoints and cosignatures follow *their* specs and are unrelated.)

## 2. Identifiers

| Name | Form | Rule |
|---|---|---|
| `net_id` | 16 random bytes | generated at genesis; never changes |
| `origin` | `norn/` + **RFC 4648 §6** base32 of `net_id`, lowercased, padding stripped — alphabet `abcdefghijklmnopqrstuvwxyz234567` | checkpoint origin line; the log key's signed-note name MUST equal it. Note this document also uses *Crockford* base32, in §9.3 only. The two alphabets are given in full, in both places, because they differ and a reader who assumes one is the other produces an origin no log will match. |
| `device_id` | UTF-8 string, 1–64 bytes, `[a-z0-9][a-z0-9.-]*` | unique among `active` devices; MAY be reused after `revoke` |

## 3. Keys

| Key | Algorithm | Held by | Signs |
|---|---|---|---|
| Log key | Ed25519 | log operator | checkpoints, receipts |
| Witness key | Ed25519 | each witness | cosignatures |
| Root key | Ed25519 | root signer (cold) | governance entries |
| Signer key | Ed25519 | signer (warm) | device-lifecycle entries |
| Device identity key | Ed25519 | device | proof of possession, `rotate`, self-`revoke` |
| WireGuard key | X25519 | device | WireGuard handshakes only — **never signs anything** |

Every key above is Ed25519 and every signature in this protocol is verified
under §3.1's NORN-ED25519-v1; the WireGuard key is X25519 and is never a signing
key.

### 3.1 NORN-ED25519-v1

Every signature here — a log key over a checkpoint (§6) or a receipt (§7), a
witness key over a cosignature (§10), a root, signer or device key over an
entry (§4), a device key over an enrollment request (§16) — is Ed25519
(RFC 8032), PureEdDSA with no context string and no prehash, verified under one
predicate, **NORN-ED25519-v1**. RFC 8032 permits two verification equations and
leaves to the implementation what to do with a non-canonical encoding or a point
of small order, and libraries differ exactly there. A transparency log is two
verifiers agreeing about the state, so this document names one answer, and a
verifier MUST NOT accept what this predicate refuses, whatever its library
accepts, and MUST NOT refuse what it accepts (D-072 (c), 2026-10-09).

Let `p = 2²⁵⁵ − 19`, `B` the base point, `L = 2²⁵² +
27742317777372353535851937790883648493` its order, and `O` the identity.

1. **A valid point** is 32 bytes that are the canonical encoding
   (RFC 8032 §5.1.3) of a point of order exactly `L` on edwards25519: the
   encoded `y` is below `p`, the sign bit is 0 when `x` is 0, the bytes decode to a point on
   the curve, and that point is not the identity and has no component of order
   2, 4 or 8 — `[L]P = O` and `P ≠ O`. The two canonical clauses are implied
   by the order clause — every `y` at or above `p` decodes, read leniently, off
   the curve or to a point of non-prime order, and `x` is 0 only at the
   identity and the point of order 2 — and are stated because libraries decode
   differently; no artifact can isolate them, so `genesis/24-root-noncanonical`
   and `trust-bad/47-witness-noncanonical-point` pin this item, not the clause
   they were named for (run 14, L3). An honest key `[s]B` and an honest
   `R = [r]B` always satisfy this; what it excludes are the encodings on which
   libraries disagree. A verifier may check it as libsodium's
   `crypto_core_ed25519_is_valid_point` does, or by decoding, re-encoding and
   comparing the bytes, then computing `[L]P`.
2. **A public key** — a root, signer or log key, a witness key, a `device_pk` —
   MUST be a valid point wherever a key is admitted: a genesis, `root_add`,
   `signer_add`, `log_key` or `enroll` entry, a `rotate`'s incoming
   `device_pk`, and every verifier key a `policy` entry's text carries (§5), an
   enrollment request (§16), and a trust file's `log_key` and `witnesses` (§9).
   The policy that fork evidence carries (§11.1) is parsed the same way, though
   its keys enter no state: a policy parses one way everywhere (D-079).
   A key that is not is refused as `decode` at its entry type's body step
   (§5.1, §5.2) — for a governance entry that step follows the root quorum, so
   an under-signed one is `threshold` first — and where a request is decoded
   (§16); it makes a trust file invalid. One rule throughout: every key that
   enters a verifier's state is a valid point where it enters (D-075).
3. **A signature** `R ‖ S` (64 bytes) verifies under a key `A` — itself a
   valid point, since item 2 admits no other — over a message
   `M` only if `R` is a valid point; `S`, read as a little-endian integer,
   MUST be less than `L` — below `L`, not merely with its top bits
   clear, and not reduced by the verifier; and with `k = SHA-512(R ‖ A ‖ M)` read
   little-endian and reduced mod `L`, `[S]B = R + [k]A`. With `A` and `R` both
   of order exactly `L`, the cofactored and the cofactorless equations agree —
   `[8]([S]B − R − [k]A) = O` holds exactly when `[S]B − R − [k]A = O`, because
   that difference lies in the prime-order subgroup, where only `O` is killed by
   8 — so a verifier may compute either; the cofactorless one,
   RFC 8032 §5.1.7's second form, is the definition.
4. **What it rejects, by name.** The C2SP CCTV Ed25519 set
   (`testdata/vectors/ed25519-cctv/`, 914 vectors) enumerates the edges.
   NORN-ED25519-v1 rejects every vector in the C2SP CCTV Ed25519 set that
   carries a flag — `low_order_A`, `low_order_R`, `non_canonical_A` and
   `non_canonical_R` (not a valid point); `low_order_component_A` and
   `low_order_component_R` (a component of order 2, 4 or 8, so not of order
   exactly `L`: the one class ed25519-dalek's `verify_strict` still accepts, and
   the one on which the two equations part, which is why it is excluded here);
   and with them every `low_order_residue` and `reencoded_k` vector, each of
   which also carries one of those — and accepts the one vector that carries
   none (number 305). No CCTV vector has `S ≥ L`; Norn's own vectors cover that
   edge (§12.1).
5. **Signing** is RFC 8032 §5.1.6, unchanged: a conforming signer produces
   nothing this predicate refuses.

## 4. Entries

### 4.0 Encoding profile (normative — the byte-level contract)

All Norn **CBOR** structures — entries, enrollment requests, trust files,
proof bundles (§8.1) and fork evidence (§11.1) —
use **RFC 8949 §4.2.1 Core Deterministic Encoding** with these restrictions.
The canonical *state* is JSON, not CBOR, and is governed by §14 instead; it is
keyed by `device_id` and by 32-byte WireGuard keys, neither of which would fit
the map-key cap below:

**The profile is an allow-list** (D-074 h). A Norn CBOR item is an unsigned
integer (major type 0), a byte string (2), a text string (3), an array (4), a
map (5), or one of the two simple values `false` (20) and `true` (21) of major
type 7, as the single bytes `0xf4` and `0xf5` — and **nothing else**. Every
other item is refused by the decoder,
before any schema looks at it: negative integers (major type 1), tags (6),
floats (major type 7 with a 2-, 4- or 8-byte argument), `null` (22),
`undefined` (23), every other simple value (0–19, and 32–255 in the two-byte
form), `0xf8` followed by any byte below 32 — `0xf8 0x14` and `0xf8 0x15`
included — which RFC 8949 §3.3 makes not well-formed, and any indefinite
length. The rows below restate this type by type and
add what each permitted item must also satisfy.

| Rule | Requirement |
|---|---|
| Integers | major type 0 only; shortest form; ≤ 2⁶³−1. **No negative integers.** |
| Floats, tags, `undefined`, indefinite-length items | **forbidden** (see the note on over-determination below) |
| `null` | **forbidden** — an OPTIONAL field is *absent*, never `null` |
| Booleans | valid CBOR items; schemas MUST reject them outside `params.rotate_needs_signer` |
| Simple values | only `false` (20) and `true` (21), as `0xf4` and `0xf5`; **every other simple value is forbidden**, whichever form encodes it, and so are these two in the two-byte form, `0xf8 0x14` and `0xf8 0x15`, which is not well-formed (`entries-hostile/bare-simple`, `fork/bad-simple-size`) |
| Byte strings | definite length; fixed sizes where stated (`net` 16, `pk` 32, `sig` 64) |
| Text strings | definite length; valid UTF-8; every **map key** is a text string of 1–23 bytes |
| Maps | definite length; keys **strictly increasing** in §4.1's order — the same comparison is what forbids a duplicate key; unknown keys → reject |
| Arrays | definite length |

**Shortest form means every argument, not only integers.** RFC 8949 §4.2.1
requires the preferred serialization of each head's argument, which is the
integer's value *and* the **length header** of a byte string, text string,
array or map: a 13-byte text string is `0x6D …`, never `0x78 0x0D …`, and a
map of three pairs is `0xA3`, never `0xB8 0x03`. The rule is stated in the
Integers row above because that is where a value's own encoding is described,
and it is restated here because a reader implements from the row and the rows
are field by field. Reading it as a rule about integers alone gives one
logical entry several legal encodings. Since D-070 a decodable entry's
duplicate key is its `content_hash`, which a second encoding of the same
content shares — but a second encoding that this profile refuses never reaches
that check, and the rule is what makes it refuse: a reader that admits it has
two leaves that both replay, which is the route the consume-the-whole-input
rule in §4.1 exists to close.
`log/*-bad-cbor-nonshortest` patches an integer and
`log/*-bad-cbor-nonshortest-length` patches a text-string header; a reader
that refuses the first and accepts the second holds the narrow rule.

**A note on testing these rules.** The *type* bans — floats, negative integers,
`undefined` — are belt-and-braces: no Norn field has a type that would accept
such a value, so an implementation with a typed model rejects them anyway and a
vector cannot tell the two reasons apart. The *encoding* bans are the ones that
bite, because a lenient decoder produces a **valid entry** from them.

A negative for one of those rules must fail for that rule **and nothing else**,
which takes care, because the patch usually lands inside the signature
preimage. Two constructions are used, and one of them must hold for every such
vector:

1. **The patch canonicalises away.** A stripped tag, a joined indefinite
   string, a resolved duplicate key, reordered signatures — a lenient decoder
   lands back on the control entry, so its original signatures still verify.
2. **The patch cannot canonicalise** — invalid UTF-8, an integer above 2⁶³−1,
   an oversized map key — so the entry is **re-signed over the patched
   preimage**. Without this the vector is rejected for its broken signature and
   the rule it names is never reached.

Each such vector ships beside the unpatched control it is a patch of
(`profile-base`, `labelcap-base`, `two-sig-base`).

Derived values:

| Name | Definition |
|---|---|
| `kid(pk)` | lowercase hex of `SHA-256(pk)[0:8]` — 16 ASCII chars, as a text string |
| entry bytes | the full envelope **with** `sigs`, deterministically encoded |
| `entry_hash` | `SHA-256` of the entry **as received**, byte for byte. The byte key of every entry that reaches §5.1 step 1, accepted or not, and the name an entry is found by (`norn-log`'s resubmission check, the entries mirror). Not of a re-encoded canonical form: an entry that never decodes must still have one |
| `content_hash` | `SHA-256` of the signature preimage below — the content key of an entry that **does** decode, recorded only once replay **applies** it (D-070, D-078). `sigs` lies outside every signature, so an entry's bytes can change while its signed content, and every valid signature on it, stay the same: keyed on bytes, a copy of a past entry with one unresolvable signature added, a surplus one dropped or a role relabelled was a new entry whose original signatures still counted, and it applied again. A refused entry records only its bytes: a copy with its signatures stripped, appended before the genuine entry, would otherwise cancel it (cold gate run 15, H2) |
| leaf hash | `SHA-256(0x00 ‖ entry bytes)` (RFC 6962 §2.1) |
| signature preimage | the 14-byte prefix `norn/entry/v1\n` (13 ASCII characters and one `0x0A`), then the envelope encoded **without** the `sigs` key |

`sigs` is an array of maps `{"kid","role","sig"}` sorted by `kid` bytewise, with no
repeated `kid`. Signing does not change the preimage, so signatures can be added by
different parties in any order and the result is still canonical.

`v`, `t`, `net`, `ts`, `body` and `sigs` are all **mandatory**; `after` and `prev`
are the only optional keys (§4.4). Omitting any mandatory key is `decode`.

**Bodies are closed schemas too**, exactly like the envelope: §4.3's table lists
every key each type may carry, and a body with an unknown key — or missing a
required one — is `decode`. `params` is the one type whose permitted keys are
the §4.5 parameter names rather than a fixed list.

CBOR does not canonicalise array order, so the sorted-and-unique requirement on
`sigs` is a **schema** rule checked during envelope validation (§5.1 step 3),
not something the encoding profile can enforce. The two layers are distinct and
a decoder will not catch it.

Each element of `sigs` is itself a **closed map** of exactly `{kid, role, sig}`;
a fourth key is `decode`. "Well-formed `sigs`" in §5.1 step 3 means precisely:
that closedness, `kid` matching its field constraint, `role` within the enum,
`sig` exactly 64 bytes, and the array sorted by `kid` with no repeats.

A decoder MUST consume the **whole** input: bytes after the item are a
violation of the profile, not padding to skip. This is the difference between
reading one item and validating a document, and it is load-bearing — a
signature covers the decoded envelope, so appending a byte to an entry leaves
every signature valid while changing its bytes. A decoder that stops at the
end of the item hands replay a second encoding of the same governance entry;
since D-070 the duplicate key of a decodable entry is its signed content, which
the byte does not change, but a reader whose decoder stops early has already
left the profile, and `60-bad-trailing-byte` must be `decode`, not `dup-entry`.

A decoder MUST bound its own resource use. Two limits, both normative:

- **Nesting depth is at most 8**, counted in **containers**. The top-level map
  is depth 1; a map or array inside it is depth 2. **A scalar does not add
  depth** — the limit exists to bound recursion, and a scalar recurses no
  further, so the depth of a value is the number of maps and arrays enclosing
  it. An `enroll`'s embedded request (§16.1) is a byte string whose contents
  are parsed separately, and its own nesting **restarts at 1**: the two
  documents are decoded by two calls, and a limit that leaked across them would
  make an entry's validity depend on the shape of something it merely carries.
  An **entry** reaches depth 3 at most: the envelope map is 1, its `sigs` array
  is 2, and each `{kid, role, sig}` element is 3 — every signed entry in the
  suite is that deep. A **request** reaches depth 2: its own map, and `labels`
  inside it. Both are far under the limit, which is why the limit is vectored
  only by `entries-hostile/` — no valid artifact comes near it.
- **`MAX_ENTRY_BYTES` is 65535**, and an **entry** is at most that many bytes —
  as is an enrollment request, which travels inside one. It does **not** bound
  the other CBOR artifacts that cite this section: a proof bundle (§8.1), a
  trust file (§9.1) and fork evidence (§11.1) each wrap or exceed an entry, and
  each states its own bound. Every one of them is bounded; none shares this
  number. Not
  65536: §6 frames entries in `tlog-tiles` entry bundles behind a **uint16**
  length prefix, so 65535 is the largest entry that can be served at all. A
  limit above it would admit an entry that is valid and unpublishable, and an
  encoder that truncated the length to fit would produce a bundle that decodes
  as a different log.

Neither limit is reachable by a valid entry; they exist so that a hostile input
cannot exhaust a verifier, and both are vectored in `entries-hostile/`.

The `sigs` key is **mandatory**; an entry with no signatures carries `sigs: []`,
which is well-formed and is rejected later by an authorisation rule rather than
by `decode`. **Which rule is decided by §5.1's ordering for that type, and is
not restated here** — an entry with no signatures still carries everything
else, and what it fails on depends on which check that type reaches first. An
unsigned `enroll`, for instance, is `threshold` and not `no-device-sig`: the
embedded request is still signed by the device, so the device-signature check
passes and the signer count is what fails. `log/bad-enroll-empty-sigs` and
`log/bad-empty-sigs` vector the two shapes.

Field constraints (violations → reason `decode` — **except at index 0**, where
every failure is `bad-genesis` and aborts replay, per §5.1's entry-0 list):

| Field | Constraint |
|---|---|
| `device_id` | matches `^[a-z0-9][a-z0-9.-]{0,63}$` **as a whole** — `\A…\z`, every byte of the string. An engine whose `$` also matches before a final newline accepts `nas2\n`; §2's rule is over the string, and both implementations here refuse it (cold gate run 14, H2) |
| `name`, `reason` | UTF-8, 1–64 / 0–256 bytes |
| `text` (`note`, `policy`) | UTF-8, ≤ 4096 bytes |
| `labels` | map text→text; ≤ 32 entries; keys 1–23 bytes (the map-key cap above — a longer key is unencodable); values ≤ 256 bytes, the empty value included; a `labels` map, when present, MUST carry at least one pair; `labels: {}` is refused as a schema fault; absence is the one encoding of "no labels" |
| `roots`, `signers` at genesis | arrays of 32-byte `pk`, no duplicates, no key in both; `len(roots) ≥ root_thr ≥ 1`; `len(signers) ≥ signer_thr ≥ 1` |
| `kid` (in `sigs`, and in `signer_remove`/`root_remove` bodies) | exactly 16 characters matching `^[0-9a-f]{16}$`. A malformed `kid` is a schema violation (`decode`), **not** a `kid` that merely fails to resolve — that distinction matters because the two produce different reason codes. |
| `sigs` array | sorted by `kid` and free of repeats (§4.0); an unsorted or repeating array is `decode` |

Reserved label keys (D-026, D-073): `ip` — a comma-separated CIDR list;
`endpoint` — `host:port`. During request checking and replay these values are
opaque text: their hint syntax MUST NOT be validated, and a string that does not
match the described format MUST NOT by itself invalidate the request or its
embedded request in an `enroll` entry. The label map's ordinary UTF-8, type,
and byte-length constraints still apply.

The `ip` label is the device's **grant**: the prefixes the signers authorised
it to source. A node derives the grant from the label alone — the label split
on commas, each part trimmed and parsed as an IPv4 or IPv6 prefix, masked to
its prefix, duplicates removed, sorted as text — and a label that is absent or
does not parse **as a whole** is **no grant**: a bound with a hole in it is not
the bound the signers signed, so the parts that did parse count for nothing.
An IPv4-mapped IPv6 prefix is no grant either, because implementations render
one differently and a grant is compared as text. The grant bounds the peer's
allowed-ips under `params.routes = "granted"` (§13.1); `proven/cases.json`'s
`grants` gives every active device's. `endpoint` remains a hint a control
plane may override: reachability is not authorization. A `rotate` keeps the
device's labels and so its grant; changing a grant is a `revoke` and a new
`enroll`, as changing any label is.

**What parses (D-077).** A part is `<address>/<length>` and nothing else, once
U+0020 is removed from both of its ends and nothing else is. The address is a
dotted quad — four decimal octets 0–255, none with a leading zero — or an IPv6
address as RFC 4291 §2.2 writes it: groups of one to four hexadecimal digits in
either case, at most one `::`, a dotted quad allowed in place of the last 32
bits, and no zone. The length is decimal without a leading zero, at most 32
for a dotted quad and 128 for IPv6. A bare address, a netmask or hostmask in
place of the length, a zone, a leading zero, any other whitespace or any other
byte makes the whole label no grant. The grant is each masked prefix in
canonical text: the dotted quad, or the IPv6 address in RFC 5952 form with
every group in lowercase hexadecimal (an embedded dotted quad is written as
two groups), then `/` and the length. `proven/grant-labels.json` has one case
per form (cold gate run 14, H1).

### 4.1 Envelope

An entry is the deterministic CBOR encoding of:

```
{
  "v":    1,                      # format version
  "t":    <type string>,          # §4.3
  "net":  <bytes16 net_id>,
  "ts":   <uint unix seconds>,    # signer's clock; advisory
  "after":<uint>,                 # OPTIONAL — log size the signer observed (§4.4)
  "prev": <uint>,                 # OPTIONAL — version of the object this entry changes (§4.4)
  "body": { ... },                # per type
  "sigs": [ {"kid": <hex16>, "role": <"root"|"signer"|"device">, "sig": <bytes64>}, ... ]
}
```

Map keys MUST be sorted per RFC 8949 §4.2.1: **bytewise lexicographic order of
their encoded form**, i.e. of the CBOR text-string item including its header, not
of the key string itself. Since every Norn map key is 1–23 bytes (§4.0) its header
is a single byte `0x60 + length`, so this is equivalent to "shorter key first,
then bytewise" — but it is **not** equivalent to sorting the bare key strings,
which would order an entry `after, body, net, prev, sigs, t, ts, v` instead of the
correct `t, v, ts, net, body, prev, sigs, after`. Canonical JSON (§14) does sort bare
strings; the two orders are independent and MUST NOT be conflated.

Keys are **strictly increasing**, and that is the whole of it: two equal keys are not a
sorted pair, they are a duplicate, and one comparison — each key's encoded
form greater than the one before it — refuses both. Stated instead as
"sorted" plus a separate "no duplicate keys", the two rules hide each other's
gaps: a reader with no duplicate test still refuses the one duplicated-key
vector, because equal keys are not increasing, and a reader who reads
"sorted" as non-decreasing still refuses it, because of the duplicate test.
A reader holding the lax half of **both** — non-decreasing order and last key
wins, which is what a lenient CBOR decoder does by default — accepts a map
with a key in it twice, and the value the entry carries is then whichever copy
the decoder happened to keep.

Unknown keys MUST cause rejection (this is a *closed* schema).

### 4.2 Signature preimage

Each signature in `sigs` is Ed25519 over:

```
"norn/entry/v1\n" ‖ CBOR(envelope with "sigs" omitted)
```

The domain prefix prevents cross-protocol reuse of signer keys. Signatures MUST be
verified against the key the `kid` resolves to in the state *before* this entry.

### 4.3 Types and bodies

| `t` | body | required signatures |
|---|---|---|
| `genesis` | `name` (string), `roots` ([pk]), `root_thr` (uint), `signers` ([pk]), `signer_thr` (uint), `params` (§4.5, **OPTIONAL** — absent means the §4.5 defaults) | ≥ `root_thr` of `roots` |
| `enroll` | `request` (bytes — a §16 enrollment request, verbatim) | ≥ `signer_thr` signers. The device's consent is the **embedded request**, not a signature on this envelope (§4.3). The request's `ts` is **not** constrained against the entry's, in either direction: a device is headless, its clock is advisory (§4.1), and a request may sit in a queue or arrive from a device whose clock runs ahead. A verifier that compares the two rejects entries this document accepts |
| `rotate` | `device_id`, `wg_pk` (new), `device_pk` (new, OPTIONAL) | the *current* device key; **and the incoming `device_pk` too when the body carries one** (proof of possession, D-032) — one valid signature for each *distinct* key among the two, so an incoming key that is the current key needs its one signature and no other (D-077); plus ≥ `signer_thr` signers if `params.rotate_needs_signer` |
| `revoke` | `device_id`, `reason` (string, **OPTIONAL** — absent is equivalent to `""`) | ≥ `signer_thr` signers, **or** the device itself, **or** ≥ `root_thr` roots |
| `signer_add` | `pk` | ≥ `root_thr` roots |
| `signer_remove` | `kid` | ≥ `root_thr` roots |
| `signer_thr` | `thr` (uint) | ≥ `root_thr` roots |
| `root_add` | `pk` | ≥ `root_thr` roots |
| `root_remove` | `kid` | ≥ `root_thr` roots; MUST leave ≥ `root_thr` roots. "And ≥ 1 root" follows from that and `root_thr ≥ 1` (§5.1 entry-0 step 6), so it is **implied, not a second test** — an implementation checking only the threshold is conforming |
| `root_thr` | `thr` (uint) | ≥ `root_thr` roots (the *old* threshold) |
| `params` | partial §4.5 map | ≥ `root_thr` roots |

| `note` | `text` (string ≤ 4096) | any 1 signer or root; **no state effect** |
| `log_key` | `pk` (bytes32), `overlap` (uint s) | ≥ `root_thr` roots — log-key rotation; `overlap` obliges the log to keep signing with the old key (§9.4) |
| `policy` | `text` (verbatim tlog-policy) | ≥ `root_thr` roots — replaces witness policy in state |

`thr` is a plain uint **here**, deliberately. Its range — `1 … len(set)` — is a
**replay** decision, not a schema one (§5.2's `bad-thr`): the value is a
well-formed uint either way, so an implementation that enforced `≥ 1` as a
field constraint would return `decode` where `bad-thr` is required. `log/69-bad-thr-zero`
and the value-above-the-set case vector both halves.

Signature counting: a key contributes at most once; a key counts only for the role
it currently holds; a device key counts only for its own `device_id` — for
`enroll` that is the `device_pk` **inside the embedded request** (§4.3).

#### Why `enroll` embeds a request instead of carrying a device signature

Every other entry a device is party to — `rotate`, self-`revoke` — is built **by**
the device, so it can sign that envelope itself. `enroll` is the exception: the
envelope is built by a *signer*, who chooses `ts` and `after`, and the device is
headless and one-way. It prints a request and is never heard from again
(§16). A device signature over that envelope would require a
return channel to the device, which is the thing the design exists to avoid.

So the body is the request itself, byte for byte. This is **stronger** than a
signature over the envelope, not a substitute for one: a device signature over an
envelope proves the device saw *some* envelope, while an embedded request proves
the device consented to exactly this `device_id`, `device_pk`, `wg_pk`, `labels`
and `expires` — and the signer cannot alter any of them without destroying the
proof. Meanwhile `ts` and `after` stay with the signer, the only party that knows
the log. Each side keeps one job: the device says what it wants and proves it
holds its key; the signer decides, and places the entry in the log.

The request's `ts` is **not** constrained against the entry's. They are two
clocks in two places, both advisory (§4.1), and a rule relating them would fail
on skew rather than on misbehaviour.

### 4.4 `after` and `prev` — ordering guards

**`after`.** If present, the entry is valid only at log index ≥ `after`. A signer sets it to the
log size it observed when signing. It stops a log operator from inserting a signed
entry *earlier* than the signer intended (e.g. moving a `revoke` before a later
`enroll` of the same id). Inserting it *later* is delay, which receipts (§7) and
staleness (part 6) catch — and which `prev` below turns into a refusal when the
delay outlives the state the entry was signed against. RECOMMENDED for every entry.

**`prev` — the version guard (D-077).** Every entry that changes state is an
authenticated compare-and-swap on the **object** it changes. The objects, the
entries that change each, and where the state records each one's version (§5.3):

| object | changed by | version |
|---|---|---|
| a device record, one per `device_id` | `enroll`, `rotate`, `revoke` | the record's `version`: the index of the last accepted entry naming that `device_id` |
| the signer set with its threshold | `signer_add`, `signer_remove`, `signer_thr` | `versions.signers` |
| the root set with its threshold | `root_add`, `root_remove`, `root_thr` | `versions.roots` |
| `params` | `params` | `versions.params` |
| the witness policy | `policy` | `versions.policy` |
| the log keys | `log_key` | `versions.log_key` |

A version is the index of the last accepted entry that changed the object; the
genesis sets every member of `versions` to 0 and creates no device record.
`prev` carries the version the submitter authorised the change against, and
replay refuses the entry as `stale-state` (§5.1, §5.2) unless `prev` is exactly
the object's current version: **present and equal** where the object exists,
**absent** where it does not — which is only an `enroll` of a `device_id` that
no accepted entry has ever named. `note` changes nothing and carries no `prev`;
a `note` with one is `decode`, and a `genesis` with one is `bad-genesis`.

Why: a signature binds the transition's target and nothing about its source. An
entry the log received and withheld stays valid, and without `prev` it lands
whenever the log chooses — after later legitimate changes to the same object.
A withheld `wg_pk` rotation then lands under a stable `device_pk` and sets the
device back to a stale key; a signed `signer_add` whose first copy was withheld
reinstates a key the roots have since removed; a `log_key` entry reinstates a
superseded log key, which since D-078 is `dup-key` as well; a signer-authorised `revoke` lands after the id was
re-enrolled and revokes the new device; an `enroll` lands after a second
revocation and re-admits it. `dup-entry` (§5.1 step 1) catches only a byte
copy or a copy of an applied entry, and the current-key check only a device
whose identity key changed.
With `prev`, a withheld entry is stale the moment anything else changes its
object, and the submitter re-signs against the version it can see. An index is
the version rather than a hash of the record: it is monotonic, it names the
exact event, and it binds the whole record, because any change to any field of
the record is itself an entry that advances it.

`after` and `prev` are different guards: `after` places the entry no earlier
than a point in the whole log, `prev` demands one object's exact version.
`prev` is what stops a stale authorisation; `after` remains for ordering across
objects.

### 4.5 `params`

| key | type | default | meaning |
|---|---|---|---|
| `checkpoint_interval` | uint s | 60 | T_c — max time between checkpoints |
| `staleness` | uint s | 600 | S — checkpoint age before `degraded` |
| `mmd` | uint s | 60 | max merge delay promised by receipts |
| `rotate_needs_signer` | bool | false | whether `rotate` needs a signer countersignature |
| `routes` | text | `"granted"` | whether a peer's installed allowed-ips are bounded by its grant (`"granted"`, §13.1) or taken from the endpoint provider as given (`"advisory"`, D-026's original reading) |

The witness policy is deliberately **not** a parameter (D-034). It has exactly
two homes: `norn.trust.policy`, which a node is provisioned with, and the
`policy` entry type, which supersedes it inside the log. A third copy in `params`
would let two verifiers disagree about the quorum that guards the log.

`routes` is the one text-valued parameter and its value set is closed: a
`params` entry or a genesis that gives it any text but `granted` or `advisory`,
or a value that is not text, is refused (`decode`, or `bad-genesis` at entry
0), so two verifiers can never hold two readings of whether routes are bounded
(D-073).

## 5. Replay — the state machine

Replay is the pure function

```
replay(anchor, entries[]) → state
```

where `entries[]` are the raw entry byte strings in log order and **`anchor`**
holds four fields of the verifier's trust file (§9):

| field | type | source |
|---|---|---|
| `net` | 16 bytes | `norn.trust.net` |
| `genesis_hash` | 32 bytes | `norn.trust.genesis_hash` |
| `log_key` | text | `norn.trust.log_key` |
| `policy` | text | `norn.trust.policy` |

The last two are read by one rule only — the log/witness key invariant at a
`policy` or `log_key` entry (§5.1, D-077 (6)), which needs the log's initial key
and the witnesses in force before any `policy` entry — and are not copied into
the state. Nothing else is trusted a priori. In particular `state.net` is copied from the
**anchor**, not from the genesis entry, so a log that fails to produce a genesis
still yields a state identified with the right network.

### 5.1 Procedure

Entry 0 is handled once, then every later entry runs the same numbered list.
The order is **normative**: several vectors are simultaneously wrong in more
than one way, so the first matching step decides the reason code. The five
vectors that carry the weight are `log/99-bad-precedence-decode-before-unknown-type`
(step 3 before step 4), `log/100-bad-precedence-decode-before-after` (step 3
before step 6 — a reader that decodes leniently, reads `after` and applies the
envelope schema afterwards answers `after` where this document says `decode`),
`log/101-bad-precedence-after-before-threshold` (step 6 before step 7, for a
`note`; `log-order/08-signer-add-after-before-threshold` holds the same pair
for a governance entry),
`log/102-bad-precedence-threshold-before-dup-id` and
`log/103-bad-precedence-threshold-before-dup-wg` (step 7 before step 8). An
ordering with no such vector is still normative, merely untested: an
implementation MUST follow it, and the suite cannot yet tell one that does not
(cold gate run 13, D4).

Replay of an **empty** list of entries yields the zero state of §5.3 with
`size` 0 and `rejected` empty: there is nothing to reject.

**Entry 0 (genesis).** In order — though unlike §5.2's ordering, **every failure here is `bad-genesis`**, so no artifact distinguishes one arrangement of these steps from another. The order below is the one that reads most naturally; it is not a guarantee, and §12.1 records it as unvectored.

1. Its `entry_hash` joins §5.1 step 1's first seen set, and when step 8 applies it, its `content_hash` joins the second (D-078).
2. Decode per §4.0 and check the envelope per §4.1. Any failure → **abort** (`bad-genesis`).
3. `t` MUST be `genesis`, and `net` MUST equal `anchor.net` → else **abort** (`bad-genesis`).
4. `leaf_hash` MUST equal `anchor.genesis_hash` → else **abort** (`bad-genesis`).
5. `after`, if present, MUST be 0, and `prev` MUST be absent → else **abort** (`bad-genesis`).
6. Body checks: `roots` and `signers` are non-empty arrays of distinct 32-byte
   keys, disjoint from each other; `1 ≤ root_thr ≤ len(roots)`;
   `1 ≤ signer_thr ≤ len(signers)`; `params`, if present, is **non-empty**, has only §4.5
   keys, and each value has the §4.5 type. The same three rules a `params` **entry**
   gets in §5.1 — an empty map trivially "has only §4.5 keys", so saying only that
   admits one.
   Any failure → **abort** (`bad-genesis`).
7. **Bootstrap:** genesis signatures are counted against the `roots` and
   `root_thr` *in its own body* — there is no earlier state to resolve them
   against. Fewer than `root_thr` valid `root` signatures → **abort** (`bad-genesis`).
8. Otherwise the state is initialised from the body and `size` becomes 1.

"Abort" means replay stops immediately: `rejected` holds exactly
`{index: 0, reason: "bad-genesis"}` and `size` is 0. The state is still
serialised in full per §5.3 — every field present, at its zero value, with
`net` from the anchor and `params` at the §4.5 defaults. A log whose entry 0 is
unusable has nothing to verify later entries against.

**Entries 1…n.** For each, in order:

1. **Duplicate check** (D-070, D-078). Replay keeps two seen sets, and an
   `entry_hash` and a `content_hash` are never compared with each other. Every
   entry that reaches this step adds its `entry_hash` to the first, **whether
   or not it is later rejected** (D-031). An entry that replay **applies** adds
   its `content_hash` to the second when it is applied; the hash is the one of
   an entry steps 2 and 3 accept — it decodes per §4.0 and its envelope passes
   §4.1, `net` included. An entry whose `entry_hash` is in the first set, or
   that decodes and whose `content_hash` is in the second → reject
   (`dup-entry`). So an applied entry is applied once: a copy of it under any
   other signature list is `dup-entry` here, before any later rule can judge
   it, and so is a byte copy of any entry. But a **refused** entry burns
   nothing but its bytes. A copy with its signatures stripped, appended before
   the genuine entry, is refused, and the genuine entry is judged on its own
   (cold gate run 15, H2); keyed on content whatever its outcome, the copy
   cancelled it, and a revoke never applied. An entry's own preimage, appended
   as an entry, never decodes and hashes to that entry's content, which is
   why the two kinds of key stay apart (H1).
2. Decode per §4.0 → on failure reject (`decode`).
3. Envelope check per §4.1: exactly the permitted keys, **every member of the
   type §4.1 gives it** (`t` text, `ts`, `after` and `prev` uint, `body` a map), `v` = 1,
   `net` = `anchor.net`, well-formed `sigs` → on failure reject (`decode`). The
   types are this step's, not a later one's: a numeric `t` is `decode`, not
   `unknown-type`, and a non-map `body` is `decode` even on an under-signed
   governance entry, which step 7 would otherwise refuse as `threshold`.
4. `t` not in §4.3 → reject (`unknown-type`).
5. `t` = `genesis` → reject (`dup-genesis`).
6. `after` present and > index → reject (`after`).
7. Count valid signatures per role (§5.2). For the governance types
   (`signer_add`, `signer_remove`, `signer_thr`, `root_add`, `root_remove`,
   `root_thr`, `log_key`, `policy`, `params`): fewer than `root_thr` valid
   `root` signatures → reject (`threshold`). For `note`: no valid `signer` or
   `root` signature → reject (`threshold`).
8. Apply the type rule below. Each rule's checks run in the order written.

Note the consequence for the governance types: step 7's root-quorum check runs
**before** step 8, so an under-signed governance entry with a malformed body is
`threshold`, not `decode`. For `enroll`, `rotate` and `revoke` the signature
checks live inside step 8, after that rule's own body validation.

| `t` | checks, in order | effect |
|---|---|---|
| `enroll` | body closed and `request` present · the request decodes under §16.1 and its `net` equals the entry's (`decode`) · the request's signature verifies under its **own** `device_pk` (`no-device-sig`) · valid `signer` count ≥ `signer_thr` (`threshold`) · `prev` is the `device_id`'s record `version`, or absent when no accepted entry has ever named the id (`stale-state`) · `device_id` not currently `active` (`dup-id`) · `wg_pk` not in `active_wg` (`dup-wg`) | add the device `active`, with the `device_id`, `device_pk`, `wg_pk`, `labels` and `expires` **from the request**, its `version` this index |
| `rotate` | body well-formed and closed, its `device_pk` when present a valid point (§3.1) (`decode`) · `device_id` known (`unknown-device`) · currently `active` (`not-active`) · valid `device` signature by the device's **current** `device_pk` (`no-device-sig`) · if `params.rotate_needs_signer`, signer count ≥ `signer_thr` (`threshold`) · `prev` is the record's `version` (`stale-state`) · new `wg_pk` not active **for another device** (`dup-wg`) · if the body carries `device_pk`, a valid `device` signature by **that** key as well — the same signature when it is the current key (`no-device-sig`) | replace `wg_pk`, and `device_pk` if the body carries one; `version` becomes this index |
| `revoke` | body well-formed and closed (`decode`) · `device_id` known (`unknown-device`) · currently `active` (`not-active`) · authorised by signers, roots **or** the device itself (`threshold`) · `prev` is the record's `version` (`stale-state`) | `status` = `revoked`, drop from `active_wg`; `version` becomes this index |
| `signer_add`, `root_add` | body well-formed and closed (`decode`) · `prev` is `versions.signers` or `versions.roots` (`stale-state`) · `kid(pk)` not already a root or signer (`dup-key`) | add to that role; that version becomes this index |
| `signer_remove` | body well-formed and closed (`decode`) · `prev` is `versions.signers` (`stale-state`) · `kid` is a signer (`unknown-key`) | remove; `versions.signers` becomes this index. **No quorum invariant** — removing a compromised signer key MUST always be possible, including the last one (D-028). A network left with fewer signers than `signer_thr` cannot enrol until roots add one; that is recoverable, an unremovable stolen key is not. |
| `root_remove` | body well-formed and closed (`decode`) · `prev` is `versions.roots` (`stale-state`) · `kid` is a root (`unknown-key`) · removing it leaves ≥ `root_thr` roots and ≥ 1 root (`root-invariant`) | remove; `versions.roots` becomes this index |
| `signer_thr`, `root_thr` | body well-formed and closed (`decode`) · `prev` is `versions.signers` or `versions.roots` (`stale-state`) · `1 ≤ thr ≤ len(set)` (`bad-thr`) | set the threshold; that version becomes this index |
| `log_key` | body well-formed and closed (`decode`) · `pk` 32 bytes, `overlap` a uint (`decode`) · `prev` is `versions.log_key` (`stale-state`) · `pk` is not the public key of any witness the policy in force names — `policy` when it is non-empty, else `anchor.policy` — compared as public-key bytes (`dup-key`, §9.1's invariant) · `pk` is not an active log key — `anchor.log_key` or any `pk` in `log_keys` — compared as public-key bytes (`dup-key`, D-078): learned keys are never retired (§9.4), so a second row would give a key every node already trusts a second `since_index` and `overlap` | **append** `{pk, overlap, since_index}` to `log_keys`; `versions.log_key` becomes this index |
| `policy` | body well-formed and closed (`decode`) · `text` ≤ 4096 bytes (`decode`) · `text` MUST parse as `c2sp.org/tlog-policy`, every verifier key it carries a valid point (§3.1) (`decode`) · `prev` is `versions.policy` (`stale-state`) · no witness the text names has the public key of an active log key — `anchor.log_key` or any `pk` in `log_keys` — compared as public-key bytes (`dup-key`, §9.1's invariant) | replace `policy`; `versions.policy` becomes this index |
| `params` | body well-formed and closed (`decode`) · non-empty, only §4.5 keys, each of the right type (`decode`) · `prev` is `versions.params` (`stale-state`) | **merge** into `params`; `versions.params` becomes this index |
| `note` | body well-formed and closed (`decode`) · `text` ≤ 4096 bytes (`decode`) · `prev` absent (`decode`) | none |

Every accepted entry that changes state sets the version of the object it
changed to its own index (§4.4), and `prev` is checked after the signatures
that authorise the entry and before the checks on the set it joins — for
`rotate`, after the current key's signature and any signer threshold and before
`dup-wg`, the proof of possession on an incoming key staying last, where
`log/111-bad-rotate-dupwg-and-no-new-key-sig` pins it — so `stale-state` names
an entry authorised against a state that has since moved: the withheld entry
§4.4 describes, not an unauthorised one.

A rejected entry is appended to `state.rejected` as `{index, reason}` and
changes nothing else. `size` becomes `index + 1` whether the entry was accepted
or rejected. Replay never aborts after entry 0.

`since_index` records the index of the entry that last **changed the device's
status**: `enroll` sets it, `revoke` sets it, `rotate` leaves it alone.

Entries whose `expires` has passed are treated as `revoked` at **evaluation
time** (§5.3), not at replay, so the state itself stays clock-independent.

### 5.2 Reason codes (closed list; part of the vectors)

| code | meaning |
|---|---|
| `decode` | CBOR/profile violation, unknown key, wrong `v`, wrong `net`, field constraint |
| `unknown-type` | `t` not in §4.3 |
| `bad-genesis` | index 0 is not `genesis` or its leaf hash ≠ `trust.genesis_hash` (**aborts replay**) |
| `dup-genesis` | `genesis` at index > 0 |
| `dup-entry` | the entry's `entry_hash` was already seen, or it decodes and its `content_hash` is an applied entry's (§5.1 step 1, D-078) |
| `after` | `after` > index |
| `threshold` | fewer valid signatures of the required role than the threshold |
| `no-device-sig` | `enroll`/`rotate` lacks a required valid signature by a device key — for `enroll` that is the **embedded request's own** signature (§4.3), for `rotate` a signature on the envelope. **Not `revoke`** — a `revoke` may be authorised by signers, roots *or* the device, so a `revoke` carrying none of the three is `threshold` (§5.1). |
| `dup-id` | `enroll` with a `device_id` that is currently `active` |
| `dup-wg` | a `wg_pk` that is already active. For `enroll` that means active for **any** device — a `device_id` may be reused after revocation, but a live key may not. For `rotate` it means active for **another** device: re-presenting the device's own key is how an identity key rotates alone (D-032). |
| `unknown-device` | `rotate`/`revoke` names a `device_id` never enrolled |
| `not-active` | `rotate`/`revoke` on a device that is already `revoked` |
| `dup-key` | `signer_add`/`root_add` of a `pk` whose `kid` already exists in either role; a `policy` naming as a witness a key that is an active log key; a `log_key` whose `pk` an active witness holds or that is already an active log key (§9.1's invariant, D-077 (6), D-078) — a key entering a role whose set must stay disjoint from another |
| `unknown-key` | `signer_remove`/`root_remove` of a `kid` not in that role |
| `root-invariant` | `root_remove` would leave `< root_thr` roots or `< 1` root. **Removals only** — a `root_thr`/`signer_thr` value outside `1 … len(set)` is `bad-thr`, because the *value* is wrong rather than the resulting set (D11). |
| `bad-thr` | a `signer_thr`/`root_thr` value of 0, or one exceeding the size of the set it applies to. This is a **replay** decision, not a schema one: the value is a well-formed uint, so it is never `decode`. |
| `stale-state` | `prev` is not the current version of the object the entry changes (§4.4): absent where the object exists, present where none does, or another index. The entry was authorised against a state that is no longer current and is refused whole; the submitter re-signs against the version it can see. Checked after the signatures that authorise the entry (§5.1), so it names an entry authorised against a state that has since moved |

Signature counting, precisely: a signature `{kid, role, sig}` is *valid* iff
`kid` names a key this entry may be signed by **in that role**, and Ed25519
verification of `sig` over the preimage succeeds. For `signer` and `root` that
key is whatever the state **before this entry** holds in that role. For
`device` it is the `device_pk` of the device this entry names:

- on `enroll`, the `device_pk` inside the **embedded request** (§4.3) — an
  `enroll` body carries no other key;
- on `rotate`, the device's **current** `device_pk` from the state, **and** the
  incoming `device_pk` the body carries, when it carries one — one valid
  signature for each *distinct* key among the two. An incoming key that is the
  current key is one key: its one signature serves as both, and the entry is a
  `wg_pk` rotation (D-077 (3)). An incoming key that differs is not in the state
  before the entry, which is the whole point of §5.1's proof of possession: a
  signature by it is valid, and D-032 requires it;
- otherwise, the device's `device_pk` from the state.

Invalid signatures are ignored, not fatal; only the count of valid ones per
role matters.

### 5.3 Canonical state schema (normative)

Two implementations MUST produce byte-identical canonical JSON (§14) of this
structure for every vector. Every field below is **always present**, including
when the entry that produced it omitted the corresponding optional field.

| field | type | meaning |
|---|---|---|
| `name` | string | `genesis.body.name`; `""` if replay aborted |
| `net` | 16 bytes | copied from `anchor.net` |
| `size` | uint | entries consumed: `last index + 1`, or `0` if replay aborted at entry 0 |
| `root_thr` | uint | current root threshold; `0` before genesis |
| `signer_thr` | uint | current signer threshold; `0` before genesis |
| `roots` | map `kid` → 32 bytes | current root keys |
| `signers` | map `kid` → 32 bytes | current signer keys |
| `params` | map | §4.5 defaults, overlaid by `genesis.body.params`, then by each `params` entry |
| `policy` | string | text of the most recent `policy` entry; `""` if none |
| `log_keys` | array of `{overlap, pk, since_index}` | one per `log_key` entry, in log order. `since_index` is the **index of that `log_key` entry** — not a log size. A node may use the key once it has replayed that far (§9.4). The trust file's initial log key is **not** listed: it is not in the log. |
| `devices` | map `device_id` → device | see below |
| `active_wg` | map `wg_pk` → `device_id` | exactly the `wg_pk` of every `active` device |
| `versions` | map of five uints: `signers`, `roots`, `params`, `policy`, `log_key` | each the index of the last accepted entry that changed that object (§4.4); all 0 after genesis, and 0 if replay aborted |
| `rejected` | array of `{index, reason}` | in index order |

A device record:

| field | type | meaning |
|---|---|---|
| `device_pk` | 32 bytes | current identity key |
| `wg_pk` | 32 bytes | current WireGuard key |
| `status` | `"active"` \| `"revoked"` | |
| `since_index` | uint | index of the entry that last changed `status` (§5.1) |
| `version` | uint | index of the last accepted entry naming this `device_id` — its `enroll`, `rotate` or `revoke` — the value a `prev` must match (§4.4) |
| `labels` | map string → string | `{}` when the enrolment carried none |
| `expires` | uint | `0` when the enrolment carried none, meaning no expiry |

A device record holds only what its **most recent** `enroll` established:
re-enrolling a `device_id` after revocation replaces the record wholesale, so
labels and expiry from the earlier enrolment do not survive.

`active_wg` is derived, not independent: it MUST equal
`{d.wg_pk: id for id, d in devices if d.status == "active"}`. It is serialised
because a verifier needs the reverse lookup and a second implementation must be
shown to agree on it.

**Evaluation time `T` (normative).** `expires` is never applied during replay,
so the state above is the same on every node regardless of any clock. It is
applied when a verifier turns that state into a proven set (§10), against a
clock that is **the log's witnesses, never the local one** (A11): a machine
whose time is wrong, or has been set wrong, must not be able to decide who is on
the network.

`T` is the **quorum time** of the checkpoint the state was replayed from: the
newest instant such that the witnesses whose cosignature timestamp is at or
after it satisfy the policy (§9). The timestamp is the 8-byte big-endian field
of the witness's signature line, laid out in §7. A `tlog-checkpoint` body carries no timestamp
of its own — the `tlog-cosignature` lines are the only timestamps in the
artifact, and `T` is the only value derived from them.

The policy is the one under which this checkpoint was accepted: the trust
policy for a first read, or the most recently replayed policy for a reader that
already has one (§9.4). A `policy` entry in this checkpoint's replay range MUST
NOT change this checkpoint's `T`; it takes effect when the reader checks the
next checkpoint.

Three things that decision needs and the rest of this document does not supply:

- **Only a cosignature that verifies contributes a timestamp**, and only from a
  witness the policy names. An unverified line is not evidence of anything, and
  §10 already refuses the whole checkpoint over one — but a reader computing
  `T` must not count it even in the moment before that refusal.
- **A witness counts once.** Two verifying lines from the same witness with
  different timestamps are its newest; a witness cannot meet a threshold by
  answering twice. This selects among lines that **verify**, and says nothing
  about one that does not: a witness with one good line and one bad one is
  refused by §10 like any other, and a reader that takes its newest verifying
  line and looks no further accepts a checkpoint the previous section refuses.
  `checkpoints-bad/12-second-line-from-one-witness` is that reader's vector.
  The **tie-break itself** — which of two *verifying* lines a witness counts at
  — is `served-twice-cosigned/`, where one witness answers twice, both lines
  verify, and the oldest-line reading lands on a different instant.
- **Under `quorum none` there is no clock.** Not because the policy is
  satisfied at no instant — it is satisfied at *every* instant, and a reader
  taking the definition literally gets an unbounded `T` and drops every device
  with an `expires`. It is because a policy that requires nobody has nobody
  vouching for the time either, and `T` is a corroborated instant or it is
  nothing.

A device is expired exactly when `expires != 0 && expires <= T`; an `expires`
equal to `T` **has** passed. When no instant satisfies a policy that requires
witnesses, or the policy is `quorum none` and requires nobody (the bullet above),
there is **no clock**, and expiry is not judged at all: the device keeps the
status replay gave it. Norn fails towards the last state a quorum vouched for, rather than dropping
devices on a number nobody signed.

## 6. The log

- Layout, tiles, entry bundles, and `checkpoint` exactly per `tlog-tiles`. Tile height 8 (width 256), as torchwood requires.
- A checkpoint body is exactly three lines (`c2sp.org/tlog-checkpoint`): the origin, the tree size in decimal with **no leading zeroes** and at most 2⁶³−1 — §4.0's bound on every integer, and one bound for every decimal line a note carries (D-076); a larger size is malformed, `checkpoint` (`checkpoints-bad/33-size-above-2-63`) —, and the root as **standard base64 with padding, 32 bytes once decoded** — any other decoded length is an error, and so is base64 the line's own length does not account for. The root MUST use canonical RFC 4648 §3.5 encoding: unused pad bits MUST be zero, so decoding and re-encoding MUST reproduce the exact line. A different final character that decodes to the same root is invalid. `0124` and `124` are the same number and two spellings of one head. The length bound is not decoration: a reader that skips it and also skips the rebuild below accepts a head that is not a SHA-256 root at all, and the two rules are the only ones that look at that line (cold gate run 10, D11).
- Leaf hash = `H(0x00 ‖ entry_bytes)` (RFC 6962 §2.1). An entry bundle is each entry's length as a **big-endian** uint16 followed by that many bytes, repeated — the framing `c2sp.org/tlog-tiles` defines, and the reason §4.0's `MAX_ENTRY_BYTES` is 65535 rather than 65536. A partial bundle holds **exactly** the number of entries its path declares.
- **The paths, restated.** `c2sp.org/tlog-tiles` defines them and this document does not vary them — but it restates them here for the same reason §7 restates the note framing and §9.1 the policy grammar: a verifier cannot be written without them, and a reader holding this document and the vectors has no other copy. A hash tile at level `L` covering index group `N` is `tile/<L>/<N>`, and an entry bundle is `tile/entries/<N>`, where `<N>` is the tile's index written in **three-digit groups, most significant first, joined by `/`** — `0`, `1000` and `1234567` are `000`, `x001/000` and `x001/x234/567`, with every group but the last prefixed `x`. A tile that is not yet full is **partial**: its path gains `.p/<W>`, where `<W>` is how many of the 256 entries it holds. So a log of 162 entries serves its only hash tile at `tile/0/000.p/162` and its only bundle at `tile/entries/000.p/162` — both of which this suite ships, and every concrete path written here is one a reader can open. When a tile fills, the `.p/<W>` suffix goes away and the path is the bare group; the next tile starts again at width 1. A log MAY delete a partial tile or bundle once the full one is available (`c2sp.org/tlog-tiles`), so a verifier that cannot fetch `tile/<L>/<N>.p/<W>` MAY fetch `tile/<L>/<N>` and use its first `W` hashes, and likewise the full entry bundle for a missing `tile/entries/<N>.p/<W>`; what it uses is compared with the tree it rebuilt exactly as the partial path would have been, so nothing is weaker for it (D-079). Tile height is 8, so width is 256 and level `L` covers 256^(L+1) leaves.
- A verifier rebuilds the tree from the **entry bundles** and compares its head with the signed checkpoint; that comparison is what binds the entries to the head. The served `tile/<L>/…` hashes MUST also agree with the tree it rebuilt. They are not needed to reach the head, and checking them is not optional: a node serves the tiles it fetched onward to its peers (§15), so a node that accepted tiles it never checked would pass on a lie it had the means to catch.
- The checkpoint is a `tlog-checkpoint` note: `origin` line = §2 `origin`, size, root; **no extension lines**. Signed by the log key; cosigned by witnesses per `tlog-cosignature` v1.
- The log MUST issue a new checkpoint after every append and at least every `checkpoint_interval`.
- **Log operator validation is optional and non-binding.** A log SHOULD refuse entries that fail §5 against its own replay, to keep the log tidy — but verifiers MUST NOT rely on it (`THREAT-MODEL.md` G3).
- Additional paths (Norn-specific, ignored by generic tooling):
  - `<prefix>/add` — submission (§7)
  - `<prefix>/anchors/<size>.ots` — OpenTimestamps proof for the checkpoint at `size` (D-009; advisory). The stamped value is `SHA-256` of the note's leading bytes **through the newline that terminates the blank separator line** — the three body lines **plus the blank line**, four `0x0A` in all, and no signature line. Not the three-line body of the bullet above, which is also §7's *signed text* and stops one `0x0A` earlier: those are two different byte ranges and the word "body" is not enough to pick one. `anchors/cases.json` gives the digest and names the bytes that produce it, so this is checkable without parsing OpenTimestamps. Not the signed note: cosignatures are appended as witnesses answer, so a note-level digest would stop matching the moment one replied — and the log's signature adds nothing to a claim about *when* the tree existed, since the log is the party the anchor exists to constrain.
  - `<prefix>/norn.trust` — a *copy* of the trust file, for convenience only; never authoritative (G6)

## 7. Submission and receipts

`POST <prefix>/add` with body = entry bytes (`Content-Type: application/cbor`).

Response `200` body is a signed note (`c2sp.org/signed-note`) by the log key:

```
norn/receipt/v1
<origin>
<b64 leaf hash>
<uint deadline unix seconds>       # = now + params.mmd, canonical decimal
```

The `deadline` line is **canonical decimal**, exactly as §6's size line is: no
leading zeroes, no sign, and at most 2⁶³−1 — §4.0's bound on every integer, one bound for every decimal line a note carries (D-076); a larger deadline is `deadline` (`receipt-bad/deadline-above-2-63.note`). §7 sells a receipt as "non-repudiable proof of log
misbehaviour", which means two parties will one day compare two copies of one,
and a number with two spellings is a comparison with two answers. The rule was
stated for the checkpoint three sections earlier and left implicit here, which
is an asymmetry with no reason behind it (cold gate run 11, D4).

The note framing is `c2sp.org/signed-note`, restated here so an implementer needs
nothing else (D22). These rules are **verified against `golang.org/x/mod/sumdb/note`**,
the canonical implementation the transparency ecosystem uses: it accepts the
verifier keys and the receipt this suite ships, unchanged, and opens notes this
spec's rules produce. They differ in one place, where the text ends: that library
ends it at the *last* blank line, this document at the first (the first bullet
below), and the two answer differently only for a note with a second blank line.

- The **signed text** is everything up to **and including** the newline that ends
  the last text line. It does **not** include the blank separator line. A note's
  text lines are non-empty, so **the **first** blank line ends the text**, and
  every line after it belongs to the signature block. The text is at least one
  line: a note whose first line is blank has an empty first text line and is
  `note`, refused before any signature is checked (D-078). A reader that ends the text
  at the *last* blank line, as `golang.org/x/mod/sumdb/note` does, reads the same
  text from every note without a second blank line. A note with one between two
  signature lines tells them apart, by code: here it carries an empty signature
  line and is `note`; there the lines before it join the text, no trusted line
  verifies, and it is `log-signature` (§12.1).
- The text is followed by one blank line, then one signature line per signer. **Every signature line, including the last, ends in one `0x0A`—exactly one**. A block that stops is unterminated; a second `0x0A` after the final signature creates a forbidden blank line (`checkpoints-bad/23-extra-final-newline`). Neither may be repaired by trimming trailing newlines.
- A signature line is `\u2014 ` (em dash U+2014, then one space), the key name, one
  space, then base64 of a payload that begins with a 4-byte `key_id`. A key name
  **contains no space**, so the line splits at its **first** space and everything
  after it is the payload. A reader that split at the *last* space would refuse
  the same lines, as `note`: a name holding a space does not frame (the name rule
  below), so the first space is where the name ends, not a choice between two
  answers. The payload is **standard base64 **with padding****
  (RFC 4648 §4, the `+/` alphabet, `=` to a multiple of four); unpadded base64
  decodes to the same bytes and is not this encoding. The payload MUST use
  canonical RFC 4648 §3.5 encoding: unused pad bits MUST be zero, and decoding
  then re-encoding MUST reproduce the exact payload text. An alternate final
  character that decodes to the same bytes is malformed note framing. **What
  follows the key id depends on the algorithm the key was published under**,
  and this document uses two:
  - **algorithm `0x01`**, a plain Ed25519 note signature (the log's, and a
    receipt's): `key_id ‖ signature` — 4 + 64 = 68 bytes, signed over the note
    text.
  - **algorithm `0x04`**, a `c2sp.org/tlog-cosignature` v1 line (every
    witness's): `key_id ‖ timestamp ‖ signature` — 4 + 8 + 64 = 76 bytes. The
    timestamp is an unsigned 64-bit **big-endian** count of seconds since the
    Unix epoch, at most 2⁶³−1 — the bound on every decimal line, and it is one
    in the cosigned message below (D-077); a listed witness's line whose
    timestamp is above it fails that witness's check, `cosignature`, before its
    signature is verified. It is the only timestamp in the artifact: §5.3's `T` is
    derived from these eight bytes and from nothing else. The signature is
    **not** over the note text. It is over
    `"cosignature/v1\n" ‖ "time " ‖ <timestamp as decimal, no leading zeroes> ‖ "\n" ‖ <note text>`
    — two newline-terminated header lines, then the whole note text through
    its final newline, with no signature lines.
- **Framing is every line's; length is the matched key's.** The note framing
  asks of every signature line only what needs no key: the prefix, a name,
  and canonical padded base64 that decodes to at least the 4-byte `key_id`.
  What follows the key id is judged by the trusted key whose name and key id
  the line matches. A line that matches no trusted key is ignored whatever its length:
  it may be a cosignature on an algorithm this document does not use, and
  refusing it would stop a Norn reader accepting the checkpoints every other
  reader of a shared log accepts (§10, D-074 c).
- **A signature line's name** is one or more characters, none of them `+` and
  none a Unicode white-space character — U+0009–U+000D, U+0020, U+0085, U+00A0,
  U+1680, U+2000–U+200A, U+2028, U+2029, U+202F, U+205F and U+3000, the whole
  property, written out so that no implementation consults its own table — as
  `c2sp.org/signed-note` requires. A line whose name is empty or breaks this
  rule does not frame, and the note is `note`. "Ignored" is said only of a line
  that has framed: a well-formed line whose name and key id match no trusted
  key (D-077).
- The decoded payload is **exactly** that length for the matched key, never a
  prefix or the other algorithm's supported length, and never "at least": a
  verifier that reads the first 68 bytes and ignores what follows accepts
  unboundedly many byte-distinct forms of one checkpoint, every one of which
  verifies. Two nodes gossiping that head then disagree about its bytes, and
  everything keyed on them — a cache, a de-duplication set, §6's
  OpenTimestamps digest over the body — is keyed on something an attacker
  chooses. A wrong length under a matched key is a failure of that key's
  check, not of the framing: one byte appended to the log's 68
  (`checkpoints-bad/20-signature-payload-too-long`) and a 76-byte payload
  under the log's `0x01` key are both `log-signature` failures, not `note`
  framing failures, and MUST be refused even if another line from that key verifies (`checkpoints-bad/24-log-key-other-algorithm-length`, D14c, §10.1). The same holds for a listed witness: a 68-byte payload under its name and cosignature key id is a `cosignature` failure, not a line to skip (`checkpoints-bad/28-witness-key-other-algorithm-length`).
- The signed text and every signature line MUST be valid UTF-8, and MUST NOT contain an ASCII control character below U+0020 other than the line feeds that end lines — a carriage return included — as `c2sp.org/signed-note` requires. A note that is not is malformed note framing, refused as `note` before any key is looked for: a reader that decodes the text before it verifies must see the bytes this one does (D-074 c, D-077).
- A note carries **at least one signature line**. A block with none is a
  malformed note rather than an unsigned one, and §10.1 refuses it as `note` —
  the framing — before any signature is looked for: there is nothing to verify
  until the lines are found. `checkpoints-bad/01-unsigned` is that file. A
  reader that goes looking for a trusted signature first refuses it too, as
  `log-signature`, which is how the suite tells the two orders apart.
- `key_id` = `SHA-256(name ‖ 0x0A ‖ alg ‖ pk)[0:4]`, with `alg` the algorithm
  byte above. The algorithm is part of the id, so the same public key published
  under `0x01` and `0x04` is two different verifiers — §9.1 turns that into a
  rule about which key may appear where. Note also that the id binds the
  **name**, so the same key under two names has two ids.
- A restatement is only as useful as it is complete. §9.1 restates the policy
  grammar because a verifier cannot be written without it; the same is true of
  the cosignature line, and until v1 this list described only the note
  signature and called itself sufficient. A reader who believed it parsed every
  witness line as malformed and could not verify the served checkpoint.
- A verifier key string is `<name>+<key_id as 8 lowercase hex digits>+<base64(alg ‖ pk)>`.
  Split it on `+` **at most twice**: standard base64 contains `+`. The key id
  is lowercase: `BEA4A666` is not `bea4a666` spelled another way, it is a
  malformed key. **A key name is one or more ASCII bytes from `0x21` to `0x7E`, `+` excluded** —
  no space, no control character, nothing outside ASCII (D-074 f). It is a
  grammar rather than a whitespace predicate because the Unicode tables two
  implementations consult disagree — one counts U+001C–U+001F as space, the
  other does not — and a name one accepts and the other refuses splits them on
  the same trust file. Every name Norn issues, an origin or `norn-witness/…`,
  is already inside it. The grammar is a verifier key's. A signature line's
  name follows the looser rule above — any characters but `+` and white space —
  so a stranger's well-formed line under a name outside this grammar, a
  non-ASCII one say, is still ignored (`served-stranger-name/`). The
  verifier-key data MUST be canonical RFC 4648 base64: `alg ‖ pk` is 33 bytes,
  and 33 bytes encode to 44 base64 characters without padding or unused pad
  bits. Decoding and re-encoding MUST reproduce the exact data text; a carriage
  return or line feed inside it is invalid even if a decoder ignores it.

### Checking a receipt

Given a signed receipt, the log keys the verifier trusts for the anchored
origin (§9.4: the trust file's, plus every `log_key` of a state it has
accepted) and that origin, the submitted entry's leaf hash when checking an
immediate submission response, and an optional
trusted checking time, a reader MUST check in this order. The first failed
step decides the refusal code; codes are closed, so no other receipt refusal
code is valid:

1. Split the signed note. Malformed framing, including an absent final line
   feed, an extra blank line, or no signature line, is `note`.
2. The note MUST verify under a log key the verifier trusts: the signature
   line's key name and key id select the key — no key is tried against a line
   that does not name it — and lines naming no trusted key are ignored. No line
   selecting a trusted key, a bad signature, or a signature payload of the
   wrong length for the selected key is `log-signature`.
3. Require exactly four signed-text lines. The first line MUST be
   `norn/receipt/v1`; otherwise refuse as `receipt`.
4. The origin line MUST equal the anchored origin; otherwise `origin`.
5. The leaf hash MUST be standard base64 and decode to exactly 32 bytes;
   unused pad bits in the leaf hash MUST be zero (RFC 4648 §3.5), and
   decoding then re-encoding MUST reproduce the exact line. Otherwise refuse as
   `leaf-hash`.
6. The deadline MUST be canonical decimal and parse as an unsigned Unix
   timestamp, with no leading zeroes or sign; otherwise `deadline`.
7. When the submitted entry's leaf hash is available:
   the submitted entry's leaf hash MUST equal the receipt's leaf hash; otherwise
   `entry`. A caller inspecting a stored receipt without its submitted entry
   may omit this binding.
8. A nonzero checking time at or after the deadline MUST refuse the receipt as
   `expired`. A zero time skips this local expiry judgment. The monitor judges
   missed inclusion against witness time; a leaf absent from every checkpoint
   cosigned after the deadline is evidence of log misbehaviour (A2).

| Code | Refusal condition |
|---|---|
| `note` | signed-note framing is malformed |
| `log-signature` | the note does not verify under the anchored log key |
| `receipt` | signed-text line count or first-line header is wrong |
| `origin` | the receipt origin differs from the anchored origin |
| `leaf-hash` | the leaf hash is not canonical standard base64 or is not 32 bytes |
| `deadline` | the unsigned timestamp is invalid, not canonical decimal, or above 2⁶³−1 (D-076) |
| `entry` | the receipt's leaf hash differs from the submitted entry |
| `expired` | the deadline has passed at the supplied checking time |

Semantics: *the log promises the entry will be included in a checkpoint of some size
issued no later than `deadline`.* A receipt whose leaf is absent from every
checkpoint cosigned after `deadline` is non-repudiable proof of log misbehaviour
(A2). Submitters MUST keep receipts until inclusion is verified.

Errors: `400` malformed, `409` rejected by the log's own replay (with the §5 reason
code; advisory), `429` rate-limited.

## 8. Proof bundles — what a node holds per peer

For each `active` device the node stores a **proof bundle**: the signed
checkpoint, the entry's index, the entry itself, and the inclusion proof that
ties them together. The bundle is self-contained, so it can be checked by
someone holding only `norn.trust` — which is what makes it useful in an alarm,
an audit trail, or a bug report.

Holding `norn.trust` means holding the log key it names. After the roots rotate
the key in the log (§9.4), a bundle made after a rotation is checkable by a
reader that has replayed the log through the rotation, or holds a trust file
issued since; one holding only an older `norn.trust` sees `log-signature`,
which is the truth — that reader does not yet trust the key the bundle is
signed with. Receipts (§7) are checked the same way. Retiring a log key is a
trust-file change, not something a reader infers from the log (D-072 (d),
D-074 (a)).

### 8.1 Bundle format (normative)

Deterministic CBOR per §4.0, a closed map of exactly these six keys. A bundle
is **not signed**: its authority is the signed checkpoint inside it, which is
why there is no domain prefix here — there is nothing for one to separate.

| key | type | meaning |
|---|---|---|
| `v` | uint | `1` |
| `device` | text | the `device_id` this bundle proves, in §2's grammar, as §16.1 requires of a request; a label outside it is `bundle` (D-079) |
| `index` | uint | the entry's index in the log |
| `entry` | bytes | the entry itself, so the bundle stands alone |
| `proof` | array of 32-byte strings | the RFC 6962 §2.1.1 audit path — the inclusion proof — leaf to root, verified per RFC 9162 §2.1.3.2: exactly the hashes that procedure consumes |
| `checkpoint` | text | the signed checkpoint note, verbatim |

Checking a bundle: **verify its checkpoint per §10** — this network's origin,
a log signature and a satisfied witness quorum,
under the log keys the verifier trusts (§9.4: the trust file's, plus every
`log_key` of a state it has accepted) and the policy of that state, the
signature line's key name and key id selecting the key — then confirm
`SHA-256(0x00 ‖ entry)` and `proof` reach that checkpoint's root at `index` for
that size, then confirm that **`device` is the `device_id` the `entry` names**
— for an `enroll`, the id inside the embedded request; for the other device
types, the `device_id` in the body — and apply the rules below.

That last step is not bookkeeping. The inclusion proof binds the *entry* to the
log and says nothing about the label beside it, so without it a bundle reading
`device: "nas"` around another device's entry proves exactly as much as an
honest one, and a consumer keying on `device` believes something no proof
established. The id an `enroll` names is the one its request decodes to under
§16.1: an entry whose request does not decode, or whose body names no
`device_id`, names no device, and a bundle around it is `binding` whatever its
label says (D-079).

The quorum is not optional here, and saying "verify the checkpoint note" was
not enough. §8 sells a bundle as self-contained, checkable by somebody holding
only `norn.trust`; a checkpoint carrying no corroboration proves only that the
log said so, which is the one thing a transparency log may not be believed
about on its own. §11.1 asks exactly the same three questions of the
checkpoints inside fork evidence, and for the same reason.

**`MAX_ENTRY_BYTES` does not apply to a bundle.** §4.0's cap is §6's uint16
entry framing and belongs to entries: a bundle *wraps* an entry that may
itself be 65535 bytes, so the largest legal bundle is necessarily larger than
the largest legal entry. A reader still MUST bound what it decodes — an
unbounded parse is what §4.0's limits exist to prevent — but the bound is this
artifact's, not the entry's.

**`MAX_BUNDLE_BYTES` is 81919**: `MAX_ENTRY_BYTES` plus 16384 for the
checkpoint, the inclusion proof and the map framing around them. A bundle
larger than this MUST be refused on length, before anything it declares is
allocated.

> **This is Norn's own format, and v1 says so rather than deferring it again.**
> The shape is the same as `c2sp.org/tlog-proof` — checkpoint, index, inclusion
> proof — and byte compatibility with it was never established, so v1 does not
> claim it. A later version may adopt that format outright; what it may not do
> is what earlier drafts did, which is name a specification the bytes had never
> been checked against.

A node MUST establish a peer's proven identity and current key from the first
three checks below. It separately classifies the age of the verified view with
condition 4:

1. the bundle's checkpoint verifies under the node's trust policy (§9), and
2. the bundle's checkpoint is consistent with the node's stored checkpoint, and
3. replay of the log up to that checkpoint yields the device as `active`, and
   the key the node installs for it is **the `wg_pk` replay gives**: the
   device's current key in the §5.3 state, never the key written in the
   bundle's entry, and
4. the checkpoint's freshness is classified: **`elapsed > params.staleness`**
   makes it stale. `elapsed` is the checkpoint's **age** as §15 defines it —
   the node's estimate of now minus this checkpoint's quorum time (§5.3) — and
   never the monotonic time since the node learned this checkpoint: the two
   agree only while the held head carries the newest quorum time the node has
   seen, and a grown head cosigned by slower witnesses would otherwise look
   younger than the node already knows the world to be (D-074 (b)). The
   comparisons here and in the ladder below are `>`, compared as durations, not
   rounded: an age exactly `S` is fresh, exactly `S_hard` has not crossed it.
   `CLOCK_SKEW` (§15) changes none of these states.

A stale view does not undo the proof of a device's identity. In particular,
degraded retains the last verified set and alarms; `hard_stale` makes the
enforcer's desired set empty only when the node's own `S_hard` is configured
(§13). An `unknown` view has no clock with which to judge expiry or staleness.

Condition 4 is where A11 looks contradictory and is not. §5.3 forbids the local
clock from supplying an *instant*, because a machine whose time is wrong must
not be able to decide who is on the network. It does not forbid the local clock
from supplying a *duration*: a node's estimate of now is the quorum time it was
given plus the monotonic time elapsed since, and monotonic time cannot be set
wrong — only paused. A node that has never seen a quorum time has no estimate,
and under §5.3 judges no expiry at all.

**The four freshness states (normative).** Condition 4 is a yes/no on one
checkpoint; a node also has to say *how* stale it is, and `detect/staleness.json`
ships that table beside these vectors. The ladder is here rather than in
`GOSSIP.md` for the same reason §11.1's evidence format is: a reader holding the
specification and the suite must be able to reproduce it.

Let `elapsed` be condition 4's monotonic duration, `S` be `params.staleness`
(§4.5), and `S_hard` be this node's own hard limit. Then the state is the
**first row, read top to bottom, whose condition holds**:

| state | when |
|---|---|
| `unknown` | no witness has vouched for any instant, so there is no `elapsed` to measure. A node in this state reports `unknown` and MUST NOT report `fresh` |
| `hard_stale` | `S_hard` is configured **and** `elapsed > S_hard` |
| `fresh` | `elapsed ≤ S` — the boundary is fresh, because condition 4 makes `elapsed > S` the violation |
| `degraded` | otherwise |

**The states are tested in the order given, and the first whose condition holds
is the answer.** The order is load-bearing rather than editorial, because
`fresh` and `hard_stale` are both true whenever `S_hard < elapsed ≤ S` — and
**`hard_stale` is tested before `fresh`**, so a node whose own limit is tighter
than the network's goes hard-stale at its own limit. The alternative reading
makes `S_hard` unreachable whenever `S` is at or above it, and `S` is
`params.staleness`, which a **root quorum can raise**: testing `fresh` first
would let the roots lift every node's local hard stop out of reach without
touching a single node's configuration. A limit the network can raise is not a
local limit, which is the whole of why this one is not a `params` key (D-034,
and D-060 for this ordering). `detect/staleness.json`'s `hard-below-staleness`
is the only case that separates the two readings.

`S` is the log's, so the whole network agrees when a view is too old to trust.
**`S_hard` is the node's own and is opt-in**: zero means not configured, and a
node that was never configured for it stays `degraded` for ever rather than
going `hard_stale`. That asymmetry is deliberate — crossing `S_hard` drops every
peer, so a log unreachable over a weekend must not take a network down by
itself. It is a local decision for the same reason the witness policy is not a
`params` key (D-034).

**And what the bundle's own entry proves.** It proves that this entry — an
enrolment, a rotation, or whatever its type is — is in the log at that index, in
a tree this checkpoint commits to. It does **not** prove that replay accepted that
entry: §10.1's bundle steps never replay, so a bundle around an entry replay
rejected passes them, and only the log through `index` says which. It does
**not** prove the device's *current* key. §5.3
leaves `since_index` on the entry that made the device active, so a `rotate`
does not move it: for any device that has ever rotated, the bundle that proves
it is older than its key, and that is the normal case rather than an edge one.
A reader that required the bundle's `wg_pk` to equal the replayed one would
drop every rotated peer, quietly, in the ordinary course of operation.
`proofs/nas.bundle` proves `nas`'s enrolment at index 1, and its entry carries
the key `116f00fa…`; replay gives `2a955fd2…`, the key `nas` rotated to at
`log/35-rotate-nas`. `proofs/cases.json` lists under `installs` the key a node
installs for each device whose bundle ships, and `proven/cases.json`'s
`bundles` map gives both keys for every active device, `nas` proven in all four
cases (cold gate run 11, D14).

Because the node replays the whole log, condition 3 is what actually decides;
the bundle is the portable, offline-checkable evidence that goes in alerts and
audit output.

## 9. Trust file — `norn.trust`

The only thing a verifier trusts a priori (guarantee G6, no TOFU). Delivered out
of band; deterministic CBOR per §4.0 is **authoritative**, and the TOML rendering
below exists for humans.

### 9.1 CBOR fields (normative)

| key | type | meaning |
|---|---|---|
| `version` | uint | `1` |
| `net` | 16 bytes | the network id; `state.net` and every entry's `net` must equal it |
| `origin` | text | MUST equal `norn/` + lowercase unpadded **RFC 4648** base32 of `net` (§2) |
| `name` | text, 1–64 bytes | human label for the network |
| `genesis_hash` | 32 bytes | the **leaf hash** `SHA-256(0x00 ‖ entry0)` (§4.0), not the entry hash |
| `log_key` | text | signed-note verifier key for the log (algorithm `0x01`); MUST parse as one, MUST NOT be a cosignature key, and its note name MUST equal `origin` |
| `log_urls` | array of text, ≥ 1 | where to fetch checkpoint and tiles. **Each URL is non-empty**: an array holding `""` satisfies "≥ 1" and names nowhere. Norn does not parse URL syntax here; the values are passed to the application that fetches the log |
| `witnesses` | array of `{name, key, url?}`, **≥ 1** | `url`, when present, is text; empty text is allowed. It is not URI-validated. `key` is a **cosignature** verifier key — `c2sp.org/tlog-cosignature` algorithm `0x04`, not a note key's `0x01` — and MUST parse as one; **a witness `name` is 1–64 bytes** of the policy grammar's name rule below, and unique within the file — bounded like the network `name` above, and for the same reason: it is a label an operator reads. A verifier key **declares** its own id, so a reader MUST **recompute** `SHA-256(name ‖ 0x0A ‖ alg ‖ pk)[0:4]` and refuse the file when the declared id differs: an id taken on trust binds nothing, and everything below rests on it binding. The algorithm is part of the key id, so the same public key published under the two algorithms is **two different verifiers**: a file naming a witness with a note key names a key no witness will ever sign with. And no witness `key`'s public key equals `log_key`'s (D-077 (6)): active log keys and active witness keys are disjoint at every state, so that the log can never be its own witness and a quorum is never met by the log alone; the comparison is on the validated public-key bytes, never on names, ids or text, it runs again at every `policy` and `log_key` entry (§5.1), and a trust file that fails it is invalid. A file with no witnesses MUST be rejected: with nothing to cosign, the policy's quorum can never be met, so the anchor could never accept a checkpoint. |
| `policy` | text | verbatim `c2sp.org/tlog-policy`; MUST parse, and MUST name **exactly** the witnesses `witnesses` lists, with the same keys. **The same key** means the same verifier key — name, algorithm and public key — compared as canonical text, so a policy that names a listed witness's public key under another key name names a different key, and the file is refused (`trust-bad/48-policy-witness-key-renamed`, D-074 d): §10 matches a cosignature line by name **and** key id, so a node that took the policy's key would match none of that witness's real cosignatures. This is not the grammar's `keys` row below, which compares parsed public keys so that one key cannot count twice under two names: that row is about duplicates inside a policy, this one about whether the file's two halves describe one verifier. The two are not redundant: `witnesses` is where a node learns a witness's name and address, `policy` is where it learns whether that witness counts — so a file where they differ configures a quorum over parties the node cannot reach, or lists parties nothing requires, and either way the operator believes they set something they did not. Counting is not checking: a cosignature line whose name **and** key id match a witness the policy lists must verify whether or not its quorum reaches that witness (§10.1 step 6), so a listed witness's bad line refuses a head even when the quorum is met without it. A `log` line, if the policy carries one, is subject to the same argument: **it MUST be `norn.trust.log_key`**, and a `log` line is compared the same way, as verifier-key text. A file whose two halves name different logs is the same operator error, and the only one of the two a verifier ever uses is `log_key`. The correspondence is on the **set** of names: a witness listed twice is refused by the uniqueness rule above, not by this one, and an implementation that strikes each name off as it matches conflates the two — it then refuses a duplicate here and passes the suite without the uniqueness rule at all. Optional policy URLs have application-specific meaning under C2SP: Norn does not validate their URI syntax or require them to equal `log_urls` or `witnesses[].url`. Its length is bounded only by `MAX_TRUST_BYTES`: §4.0's 4096-byte cap is on the `text` of a `note` or `policy` **entry**, so a trust policy longer than 4096 bytes is valid, and can never be republished as a `policy` entry (D-080) |
| `anchor` | `{type, max_lag, mode}`, OPTIONAL | It is a closed map. All three members are required **when `anchor` is present**, and no other member is permitted. `max_lag` is **uint seconds**. The two text members are not symmetric: **an unknown `type` is ignored**, not refused — anchoring is advisory (D-009), so a reader that cannot check `"roughtime"` simply does not check it and the rest of the file stands — while **`mode` MUST be `"advisory"`**, because guessing what an unrecognised enforcement mode means is how a node enforces something nobody asked for. A reader that refuses an unknown `type`, or accepts an unknown `mode`, is wrong in opposite directions |

Unknown keys MUST cause rejection. The fingerprint (§9.3) is taken over these
bytes, so a wrong field name or type changes it.

**`MAX_TRUST_BYTES` is 65536**. A trust file is keys, URLs, a witness list and
a policy — it does not wrap an entry, and nothing in it scales with the log. A
file larger than this MUST be refused on length, before anything it declares is
allocated.

**The policy grammar.** `policy` is `c2sp.org/tlog-policy` verbatim and is not
redefined here, but a verifier cannot be written without it, so its four
directives are restated. Every directive line, including the final line, ends
in ASCII line feed (`0x0A`); fields are separated by ASCII spaces and tabs
**only**:

```
log     <vkey> [<url>]
witness <name> <vkey> [<url>]
group   <name> all|any|<k> <name>...
quorum  <name>
```

Every `<vkey>` MUST be parsed as a C2SP verifier key. Its declared key ID MUST equal the recomputed ID for its key name, algorithm byte and 32-byte Ed25519 public key. A `log` vkey MUST use algorithm `0x01`; a `witness` vkey MUST use algorithm `0x04`. Key names follow §7's ASCII grammar — one or more bytes `0x21`–`0x7E`, `+` excluded — and the key ID is lowercase hex (D-074 f). The verifier-key data MUST be canonical RFC 4648 base64 (D-062), with its exact text reproduced by standard re-encoding. The 33-byte data has no unused pad bits; embedded carriage returns and line feeds are invalid.

Both policy URLs are **optional in the grammar and present in every Norn
policy** — omitting them parses, and a second implementation that stops
reading a line after the key will silently accept a policy it has misread.
C2SP makes their meaning application-specific. Norn does not parse URI syntax
or compare a policy URL with `log_urls` or `witnesses[].url`; the key and name
correspondence rules above still apply. A `group` names
previously-defined witnesses or groups (`any` is `k = 1`, `all` is `k = n`,
otherwise `1 ≤ k ≤ n` in decimal); there is **exactly one** `quorum` line, and
it names a witness, a group, or the reserved name `none`.

The `witness` directive is matched on **its own `<name>`** — the same short name
the `witnesses` array carries (`pi`), never the note name inside the verifier
key (`norn-witness/pi`). This is what §9.1 means by naming exactly the same
witnesses: the names must correspond one-to-one, and so must the keys.

**The rest of the grammar, stated because a restatement that leaves it out is
not enough to write an agreeing verifier.** Cold-model gate run 8 flipped nine
readings of this section and every one passed the suite; six of them were
places the two implementations in this repository already disagreed.
`policies/` vectors each rule from both sides:

| rule | |
|---|---|
| blank lines | a line that is empty, or holds only spaces and tabs, is **ignored** |
| comments | a line whose **first character other than ASCII space or tab** is `#` is ignored **in its entirety**; a `#` anywhere else in a line is **an ordinary character**, not the start of a trailing comment. So `\t# note` is a comment, and `quorum pi # note` is a `quorum` line with two names — refused by the field count below, not read as `quorum pi`. If `c2sp.org/tlog-policy` has no comments then a Norn policy carrying one is text other tooling will refuse — worth knowing, and the reason it is written down here rather than left to each reader |
| line endings | Every directive line, including the final line, ends in ASCII line feed — and so does every other line, a comment or a blank line too, because a line is delimited before its kind is known. A missing final line feed is an error whatever the last line holds (`policies/bad-final-comment-no-lf`, D-076) |
| field separators and controls | ASCII space (`0x20`) and tab (`0x09`) separate fields, in runs. The only allowed ASCII control bytes are tab and line feed; all other bytes `0x00–0x08`, `0x0B–0x1F` and `0x7F` are an error anywhere, including comments. **That set is closed**: `0x0B` (`\v`), `0x0C` (`\f`) and `0x0D` (`\r`) are errors; carriage return is forbidden, as are the other listed controls. Bytes `0x80–0xFF` are content, not separators; this includes every other Unicode whitespace character included (U+00A0) and U+2028. Norn's CBOR text must still be valid UTF-8 (§4.0). |
| field count | each directive takes **exactly the fields its production above allows** — `quorum` one, `witness` two or three, `log` one or two, `group` a name, a threshold and one or more members — and a line with more is an **error**. Stated because it was doing the work of the rule above it: with the stray whitespace in an optional URL, a reader that treats `\v` as a separator sees a four-field `witness` and refuses it *here*, so the separator rule could be deleted and every vector stayed green (cold gate run 10, D9) |
| leading whitespace | spaces and tabs before the keyword are not part of it |
| trailing whitespace | spaces and tabs after the last field are not part of it and add no field (D-080) |
| names | A witness or group name follows §7's key-name grammar — one or more bytes `0x21`–`0x7E`, `+` excluded — and is at most 64 bytes, in every policy: a trust file's and a `policy` entry's alike (D-078). Stated because the grammar never said which bytes a name may hold: both implementations took `zürich`, a reader applying the key-name sentence above refused it, and a refused `policy` entry leaves two readers with different quorums (cold gate run 15, M1). Witness and group names share one namespace; each name is defined **once**, and a repeat is an error. `none` is predefined, cannot be defined, and is invalid as a group member. `all` and `any` are ordinary names outside the threshold position |
| order | lines may appear in **any order**: the `quorum` line may come before or after `witness`, `group` and `log` lines, and nothing else constrains where a directive sits. The one ordering rule is that names resolve **in order** — a `group` or `quorum` line names only what an **earlier** line defined (`policies/bad-forward-reference`, `policies/bad-quorum-forward-reference`) — and nothing defined later changes an earlier line: a name is defined once, so a later line that redefines a name an earlier line used is an error (`policies/bad-redefinition-after-use`), never a new meaning for the earlier line. `policies/directive-after-quorum` puts a `witness` line and a `group` line after the `quorum` line and MUST be accepted (D-074 e) |
| keys | a verifier key appears **once** in a policy, on whatever line. Keys are compared by their parsed underlying public key, not by vkey text, name or key ID; the same public key with another spelling is still a duplicate. This applies across `log` and `witness` lines. Under two witness names, one key could otherwise count twice toward a quorum. Two *different* keys held by one operator cannot be detected here or anywhere else, and are two witnesses as far as any policy can tell |
| `group` members | each **previously defined**, and **no member twice** — `group home 2 pi pi` would otherwise be met by one witness. The predefined `none` MUST NOT appear as a group member. `group` requires one or more members; its empty-member vector is refused by the field-count row. |
| `group` thresholds | `all` is `n`, `any` is 1, and a count is **canonical decimal** with `1 ≤ k ≤ n`; the inclusive upper threshold `k = n` is valid. `0` is met by nobody, so a policy carrying it accepts an **uncosigned** head; `02` and `2` are the same number and two spellings of one quorum |
| keywords | the four directives, `all` and `any` are **lowercase**. Nothing here is case-folded |
| nested groups | a `group` may name a `group`. It counts as **one** member of the outer group, met or not met as its own threshold decides |
| `log` lines | **not required**, and **more than one is allowed**: a policy naming a log's old and new key is what a rotation looks like from outside (`two-log-lines`; the log's `policy-two-log-lines` replays one). Duplicate public keys are refused. A Norn **trust file**'s policy carries at most one, because a `log` line that is present must name `norn.trust.log_key` (§9.1's `policy` row). That limit is the trust file's, not the grammar's: a `policy` entry (§5.1) has no such correspondence. Norn takes the log key it verifies with from `log_key`, never from here |
| `quorum` | exactly one line, naming a previously-defined witness, a previously-defined group, or the predefined `none` quorum |


### 9.2 TOML rendering

```toml
# Norn trust file for norn-testnet
# fingerprint = Y2KM-WGEJ-5GCD-X3HA
# Compare the fingerprint out of band before trusting this file.

version      = 1
net          = "6e6f726e2d746573746e65742d303031"   # hex
origin       = "norn/nzxxe3rnorsxg5domv2c2mbqge"
name         = "norn-testnet"
genesis_hash = "f168d197a35cc00bc320f27ee248efa6394e139312c3343cfe154bc5b24183d3" # hex
log_key      = "norn/nzxxe3rnorsxg5domv2c2mbqge+bea4a666+…"
log_urls     = ["https://log.norn.example/testnet", "http://10.0.0.155:8099/norn"]
policy       = "log norn/nzxxe3rnorsxg5domv2c2mbqge+bea4a666+AV6v97lmGyW99eHglI8syFAU2uY+/HuHHq0VYz9Rmio1 https://log.norn.example/testnet\nwitness pi norn-witness/pi+051d1c51+BHeagefoK0s3F5shdMl1Ahsd1ZCE9MC5F5gvM3cLTnZa http://10.0.0.153:8100\nwitness vps norn-witness/vps+46a6fd38+BIXCilOrHi0kMxynG/s1EyJ2aWFC1jZc4UlZRza6g8ou https://witness.example.net\nwitness friend norn-witness/friend+1404f742+BJjvlkRbihDdM/4Lb/YPiP+eoqk3VgrncrTgSXQNXr6B https://bastion.example.org/w\ngroup home 2 pi vps friend\nquorum home\n"
anchor       = { max_lag = 86400, mode = "advisory", type = "opentimestamps" }

[[witness]]
name = "pi"
key  = "norn-witness/pi+…"
url  = "http://10.0.0.153:8100"
```

Mapping the rendering back to the authoritative CBOR (§9.1):

- each `[[witness]]` TOML table is one element of the CBOR array under the key
  **`witnesses`** — singular in TOML, plural in CBOR. Array **order is
  significant**: it is part of the bytes the fingerprint covers, so two files
  differing only in witness order have different fingerprints;
- byte strings render as **lowercase hex** in TOML and stay raw bytes in CBOR;
  no field is ever base64 in the trust file;
- an absent optional member — a witness `url`, or the whole `anchor` table — is
  simply **omitted** from the CBOR map (§4.0: OPTIONAL means absent, never
  `null`). A present empty witness `url` is the text value `""` and remains
  present when rendered back to CBOR.

Building the CBOR from this rendering must reproduce `trust.cbor` byte for byte;
if it does not, the fingerprint will not match and the file must be rejected.

### 9.3 Fingerprint

The first **10 bytes** of `SHA-256(CBOR(trust))` — 80 bits — encoded in
**Crockford base32** (alphabet `0123456789ABCDEFGHJKMNPQRSTVWXYZ`, which omits
I, L, O and U), most-significant bit first, as 16 characters in four groups of
four joined by `-` (U+002D): `Y2KM-WGEJ-5GCD-X3HA` (D-029). The
`trust.fingerprint` file holds exactly that string followed by one `0x0A`.

80 bits is chosen so that an attacker who controls the delivery channel (threat
A10) cannot grind a substitute trust file with a matching fingerprint.

`nornd` MUST refuse to start without a trust file and MUST refuse one whose
`genesis_hash` does not match entry 0.

### 9.4 Rotation (normative)

The trust file holds the network's **initial** log key. It evolves inside the
log (D-020): a `log_key` entry publishes a new one, and doing so takes the root
quorum (§4.3), never the log's own signature.

**A checkpoint MUST be signed by `norn.trust.log_key`, or by a `pk` in
`log_keys` of a state this node has already accepted.** A node that has
accepted nothing has only the trust file's key. A learned key is the verifier key `<origin>+<id>+base64(0x01 ‖ pk)`:
named the origin, as the trust file's log key is (§2), with its id computed
from that name. A line signed by the same `pk` under any other name names no
trusted key and is ignored (§7), so a reader that matches learned keys by
public key alone accepts heads this document refuses (cold gate run 13, D11).

That ordering is the whole of the security argument, and it is why rotation is
not circular: reaching a state that names a key requires having already
accepted a checkpoint under a key the node held beforehand. **A stolen log key
therefore cannot name its own successor** — it can sign checkpoints, and it
cannot publish a `log_key` entry, because that needs the roots.

`since_index` is the index of the `log_key` entry itself, and the key is usable
by a node that has replayed that far. There is no separate activation index and
no waiting period on the verifier's side.

`overlap` is an obligation on the **log**, not a rule for a verifier. After
publishing a `log_key` entry the log MUST keep signing its checkpoints with the
superseded key for at least `overlap` seconds, so that a node whose trust file
predates the rotation can still bootstrap, replay, and learn the new key. A log
that stops early strands exactly those nodes — the ones least able to complain —
and a monitor watching the checkpoint's signature can see it happen.

A node keeps the trust file's key **alongside** what it has learned rather than
replacing it. A node whose trust file is current must never be worse off than
one whose trust file is stale.

The same is true of every key a `log_key` entry has taught it: a learned key is
**never retired**. Keys accumulate across rotations, so a log that resumes
signing with a superseded key — an exposure the rotation did not prevent —
still reaches every node that watched the rotation, and the exposure ends when
the log stops signing with that key, never by the passage of `overlap`.

**The witness policy rotates the same way and differs in one respect: it
replaces.** A `policy` entry supersedes `norn.trust.policy` for every checkpoint
a node accepts after replaying it; that policy computes §5.3's `T` for those
checkpoints too. It does not apply retroactively to the checkpoint that carried
it or to that checkpoint's `T`. Keys accumulate because an overlap is the
point; policies do not, because a policy is one document and two in force at
once is exactly the disagreement about the quorum that §4.5 refuses to allow.
Publishing one takes the root quorum (§4.3).

A node holding only the trust file uses its policy. The bootstrap is the same
as for keys and is what keeps it non-circular: accept under the policy you
have, replay, and use what the roots published from the next checkpoint on.

Two consequences worth stating rather than discovering:

- **Raising a quorum binds the nodes that were already watching.** A node that
  replayed the rotation will refuse a head that satisfies the old policy and
  not the new one. If it did not, raising a quorum would protect only the nodes
  that had not been paying attention.
- **The roots can lower it too, including to `quorum none`.** That is their
  prerogative — they are the network's authority — and it is visible: the
  policy is in the log, every monitor replays it, and §5.3 gives a node with no
  corroborated instant no clock at all.

## 10. Verifier procedure (normative outline)

The outline names the checks in the order §10.1's table numbers them, and that
table gives the code each refusal carries. Where a reader needs an order,
§10.1's table decides.

```
loop every T_g or on demand:
  cp := fetch checkpoint (log_urls or a proven peer)     # §15
  # The SIGNATURE decides first. A checkpoint signed by a key this anchor does
  # not trust is refused for that, whatever origin it names, and until the
  # signature has been checked there is no reason to believe any field in the
  # note. Two vectors share the words "wrong origin" and sit on either side of
  # this line: `checkpoints-bad/03-wrong-origin` is signed under ANOTHER
  # origin's name, so it is `log-signature` (§10.1); `proofs-bad/wrong-origin`
  # and `checkpoints-bad/10-wrong-body-origin` are signed by this network's own
  # key under its own name and name another log in the body, so they are
  # `origin`.
  # Signed by norn.trust.log_key, or by a key a state this node already
  # accepted names (§9.4). Never by a key learned from this checkpoint.
  # Every signature line whose name and key id match a trusted log key MUST
  # verify, and at least one such line MUST be present. Not "at least one
  # verifies": a checkpoint carrying a valid signature AND a forgery under the
  # same key is refused, exactly as a witness's two lines are below. The
  # canonical signed-note implementation does not impose this; Norn does.
  # A 76-byte payload under the log's `0x01` key fails here as
  # `log-signature`, even though that length is a valid frame for a cosignature.
  # Any length but 68 under the log's key fails here too: the framing takes
  # every length from a 4-byte key id up, and the matched key judges it.
  verify log signature (torchwood VerifyCheckpoint)     # norn.trust.log_key
                                                        # and norn.trust.policy:
                                                        # a checkpoint must be
                                                        # accepted before the log
                                                        # can be replayed, so
                                                        # acceptance cannot depend
                                                        # on anything the log says
  require cp's text is a tlog-checkpoint body (§6)      # exactly three lines
  require cp.origin == norn.trust.origin                # which log this is about
  verify witness policy: every cosignature LINE naming a witness the policy
      names must verify, and the quorum must be satisfied  # refuse otherwise
      # A line NAMES a witness the policy lists when its **name and key id**
      # both match that witness's verifier key -- the same test the log's own
      # line gets above. §7 makes the id bind the name, the algorithm and
      # the public key, so a line carrying a listed witness's name under some
      # other key names nobody: it is a stranger's line and is ignored, not a
      # listed witness's line that fails to verify. The other reading hands
      # anyone a veto -- cosign a head under a name you do not hold and every
      # node that matches on the name alone refuses it, including nodes that
      # have never heard of you. `served-name-collision/` is that checkpoint
      # and it MUST be accepted.
      # per line, not per witness: a witness that supplies one verifying line
      # and one that does not is refused, not counted. §5.3's "newest" rule
      # picks among lines that verify; it never excuses one that does not.
      # A 68-byte payload under a listed witness's name and key id fails here
      # as `cosignature`: once they match, the line is that witness's, and a
      # witness speaks in 76-byte cosignatures only (§7; SEC-027).
      # A line naming anyone the policy does NOT list is IGNORED, not refused
      # and not counted -- a witness cosigning a log this node's policy does
      # not name is normal in a shared log, and a reader that refuses over one
      # stops accepting checkpoints everybody else accepts. The log's own
      # signature line may appear anywhere in the block; order carries nothing.
  # The entries before any comparison: the branch comparison below is
  # recomputed from them, so they are fetched, framed and hashed first.
  entries := fetch the entry bundles cp.size implies    # TileFetcher / TileFS
                                                        # + PermanentCache
  require the bundles frame and hold cp.size entries    # §6
  require root(entries) == cp.root                      # the signed head
  if stored_cp exists:
      # Compare the two branches where BOTH can speak, and do it BEFORE the
      # size rule. A log that forks onto a SHORTER branch is otherwise filed
      # as an ordinary rollback: no evidence, no alarm, and the accusation
      # §11 rule 1 requires is never made. `detect/fork-on-a-shorter-branch`
      # is exactly that log, and it must come out `fork`, not `refuse`.
      at := min(cp.size, stored_cp.size)
      served := the root the SERVED branch has at `at`   # recomputed from the
                                                         # entries, never from
                                                         # a supplied proof
      mine   := stored_cp.root                    if at == stored_cp.size
                the root THIS NODE's branch had at `at`, otherwise
                # a node that does not hold `at` cannot tell a fork from a
                # rollback; it refuses below and MUST NOT accuse
      if served ≠ mine → FORK (§11)
      # Only now the size rule, and refusing is not accusing (§11.1).
      if cp.size < stored_cp.size → refuse without raising a fork
                                           # an earlier view undoes every
                                           # revocation made since, and is
                                           # signed and cosigned correctly
  require entries[0] is the genesis the anchor pins     # §5.1
  require every served hash tile == the rebuilt tree's  # byte for byte,
                                                        # length included
  state := replay(trust, entries[0:cp.size])
  T := the evaluation time of cp (§5.3)                  # witness time, never ours
  proven := { d ∈ state.devices : status == active && not expired(d, T) }
  store cp; hand proven to the enforcer                  # §§8.1, 15
```

### 10.1 Refusal codes (closed list; part of the vectors)

§5.2 gives replay a closed vocabulary, and that is what makes §5.1's order
observable: two refusals with different codes can be told apart, so the step
that decides between them can be tested. Everything above had no vocabulary,
so a verifier that checked the origin before the signature, or a bundle's
quorum before its inclusion proof, refused exactly the same files as one that
did not and no vector could see the difference (D-061, cold gate run 11 D10).
This is the verifier's list, and it is a **closed list**: an implementation reports one of
these codes and no other, and the first step whose check fails decides which.

**The verifier loop**, in the order the checks run:

| step | code | the refusal |
|---|---|---|
| 1 | `unserved` | the checkpoint is not served; for a partial path, `unserved` only when neither the partial path nor the full one is served (D-079). The same code for any file a later step needs and cannot fetch — an entry bundle (step 8), a hash tile (step 12) — reported at that step |
| 2 | `note` | the checkpoint is not a well-formed signed note (§7): no blank separator line, a signature line that does not frame, a payload that is not canonical padded base64 of at least a 4-byte key id, text or a line that is not UTF-8 or carries an ASCII control character other than a line-ending LF, a signature line whose name is empty or holds `+` or white space, an unterminated block, an extra blank line after the last signature line, or **no signature line at all**. Framing comes first because there is nothing to verify until the lines are found |
| 3 | `log-signature` | no line whose name and key id match a trusted log key (§9.4) verifies, or any line that matches does not. The matching key's algorithm fixes the signature length too: a 76-byte payload under the log's `0x01` key fails here, even beside a valid line from that key (`checkpoints-bad/24-log-key-other-algorithm-length`, D14c), and so does any other length but 68 (`checkpoints-bad/20-signature-payload-too-long`). **The signature decides before the origin**: a checkpoint signed by a key this anchor does not trust is refused as `log-signature`, whatever origin it names |
| 4 | `checkpoint` | the signed text is not a `tlog-checkpoint` body (§6): not exactly three lines, a size that is not canonical decimal or is above 2⁶³−1 (§6), a root that is not 32 bytes of standard padded base64 |
| 5 | `origin` | the body's origin line is not **equal** to `norn.trust.origin` — not a prefix of it, not a case variant of it |
| 6 | `cosignature` | a cosignature line whose name **and** key id match a listed witness does not verify — listed meaning named by the policy in force (§9.4), not a witness a `policy` entry has dropped that the trust file still lists — including one whose payload is not a cosignature's 76 bytes (`checkpoints-bad/28-witness-key-other-algorithm-length`) or whose timestamp is above 2⁶³−1 (§7, D-077) |
| 7 | `quorum` | the verifying lines from listed witnesses do not satisfy the policy |
| 8 | `entries` | the entry bundles the checkpoint's size implies do not frame (§6's big-endian uint16 length prefixes), or do not add up to that size. A zero-length frame **frames** — a uint16 length of 0 is a frame — and the empty entry it carries is §5.1's `decode`: a rejected entry in an accepted log, not this code. Bytes after the last frame a full bundle needs are either further frames, which do not add up, or a truncated one, which does not frame: this code either way (run 14, M2 and M3) |
| 9 | `head` | the tree rebuilt from the served entries does not hash to the signed root |
| 10 | `fork` | the served branch and this node's branch disagree where both can speak (§10, §11). The checkpoint is not accepted **and** §11 applies: this is the one code that is also an accusation |
| 10 | `rollback` | the served size is below the stored one and the branches agree where both speak — refused, **not** accused (§11.1). `fork` is decided first, which is why the two share a step |
| 11 | `genesis` | the served log has no entry 0, or its entry 0 is not the genesis the anchor pins: replaying it alone aborts with `bad-genesis` (§5.1). Nothing in such a log is a fact about this network, and its replay would be the empty state an enforcer installs |
| 12 | `tiles` | a served hash tile disagrees with the rebuilt tree — compared byte for byte, length included: a tile of width `W` is exactly 32 × `W` bytes, and a longer or shorter one disagrees whatever its first 32 × `W` bytes say (run 14, M3) |

**Why the head comes before the fork.** Step 10 compares the root the served
branch has at `at`, *recomputed from the served entries*. If those entries do
not even hash to the checkpoint they were served with, the comparison is
between this node's history and a pile of bytes nobody signed — and a
disagreement there would raise a fork against a log that did not sign two
histories, only served a broken one. Step 9 rules that out first, which is why
§10's outline fetches, frames and hashes the entries before its fork block.

**Why the genesis comes after the fork.** To a verifier that holds a head,
another history signed by the same log under the same origin is equivocation,
whatever its entry 0 says, and step 10 is where that is proven and accused; a
`genesis` refusal there would refuse the branch and lose the evidence. So a
verifier that holds a head first decides `fork` or `rollback` against it, and
only a log that passes that comparison — or a verifier with nothing to compare,
a node's first start, `norn verify`, a monitor — reaches step 11. An empty log
served to a node that holds a head is `rollback`; served to one that does not,
`genesis` (D-074 (g), as amended 2026-10-10).

**A bundle** (§8.1) is checked with the loop's codes for its checkpoint and
three of its own, in this order:

| step | code | the refusal |
|---|---|---|
| 1 | `bundle` | the bundle does not decode as §8.1's closed map, carries an unknown key, an unsupported version, or a `device` outside §2's grammar; or a `proof` element that is not exactly 32 bytes, as §8.1 types it (cold gate run 17, D8) |
| 2 | — | the checkpoint, as loop steps 2–7: `note`, `log-signature`, `checkpoint`, `origin`, `cosignature`, `quorum` |
| 3 | `inclusion` | the index is outside the tree, or the inclusion proof does not chain the entry's leaf hash to the signed root, or the proof carries more or fewer hashes than RFC 9162 §2.1.3.2 consumes |
| 4 | `binding` | the entry is not about the device the bundle names, or names none — an `enroll` whose request does not decode (§8.1's device↔entry binding) |

A `says` string in `cases.json` stays a semantic hint (§12). Where a case names
a code, the code is the contract.


## 11. Fork handling

A node that observes two valid, policy-satisfying checkpoints for the same origin
that are not consistent MUST:

1. write both checkpoints, the failed proof and the split (§11.1) to
   `fork/<unix>.evidence`,
2. consume no further authorization state from either branch: its stored
   checkpoint stays what it was, and no checkpoint is adopted under this
   anchor — forever, until an operator explicitly resets with a new trust
   file (KEYTRANS rule),
3. keep enforcing, in every cycle, the **frozen set**: the devices proven at
   the common prefix **and** proven at the head the node itself holds, each
   with the routes its enrollment granted as of the common prefix. The
   **common prefix**: the largest size at which both branches have the same
   root — the last state both agree on, and therefore the last one a node can
   call authorized once it knows the log signs whatever suits it. Relative to
   what the node was enforcing, the frozen set may only stay the same or
   shrink; it MUST never grow: whatever either branch added after the split
   is removed, and whatever this node's branch revoked after it stays out.
   `owner` and `watchdog` evict against the frozen set; `observe` reports it.
   A node that cannot establish the common prefix — the evidence claims none
   (`split` 0), or the node's own branch does not reach the split or does not
   have `split_root` there — MUST **fail closed**: its desired set is empty,
   as past `S_hard` (§13.2). A fork is cryptographic proof that the log and a
   witness quorum misbehaved; unlike staleness, which is usually an outage,
   it does not get the benefit of the doubt, and
4. raise a `FORK` alarm, critical, and repeat it on the degraded cadence
   (§13.2) until the reset, saying what it keeps enforcing and what it
   removed. A frozen node doing its job looks exactly like a healthy one
   otherwise.

A node that receives evidence from a peer (`GOSSIP.md` part 7) and checks it
per §11.1 is in the same position as the node that wrote it, and does the
same: it has the split from the file and its own branch from its mirror.
Before 2026-10-09 rule 3 read "keep its stored checkpoint and proven set
unchanged": a frozen watchdog then stopped evicting, and a split view's rogue
— enrolled on the victim's branch after the split, which is what a split view
is for — stayed connected after the node had proved the split (audit SEC-021;
D-072 (a)).

### 11.1 Evidence format (normative)

Evidence is the one artifact this protocol produces for **somebody else** — a
witness operator, a mailing list, a stranger — so it has to be checkable by a
reader who has the network's trust file and nothing else: no running log, no
connection, and **no reason to trust whoever handed them the file**. That is
why the format is here rather than in `GOSSIP.md`.

Deterministic CBOR per §4.0, a closed map of exactly these seven keys at
version 1, and of exactly eleven keys at version 2 — the four `split` keys
added. A node writes version 2. A reader MUST accept both: a version-1 file
proves a fork exactly as it did, and claims no common prefix.

| key | type | meaning |
|---|---|---|
| `version` | uint | `1` or `2` |
| `held` | text | the signed checkpoint the accuser was holding — the branch it can speak for, because it has the entries. When the branch the accuser stored is the **shorter** one, the branch it can speak for is the served one, whose entries it has just fetched: that head is `held`, its stored head is `conflicting`, and `size` is the stored size |
| `conflicting` | text | the signed checkpoint that could not be reconciled with it |
| `size` | uint | where the two disagree: the **conflicting** head's size |
| `held_root` | bytes (32) | what the held branch had at `size` |
| `proof` | array of bytes (32 each) | **RFC 6962 §2.1.2** consistency proof chaining (`size`, `held_root`) to `held`'s own head, in that document's node order and verified per RFC 9162 §2.1.4.2, and a list with more or fewer hashes than that procedure consumes does not chain — the algorithm is not restated here and a reader implementing their own ordering will reject sound evidence. **Empty when `size` equals `held`'s size**, where the two signatures say it alone |
| `split` | uint | **version 2.** The common prefix (§11 rule 3): the largest size at which both branches have the same root, as the accuser computed it from the two trees it held — the common entry prefix, since equal entries give equal roots. `split` 0 means no common prefix is claimed, and a reader then fails closed (§11 rule 3). An accuser can understate the split and never overstate it: the proofs below hold at every size up to the true split and at none above it. Understating hurts nobody the fork has not already hurt — a log and quorum able to sign a fork can fork at entry 1 — and is why no maximality proof is carried |
| `split_root` | bytes (32) | **version 2.** The root both branches had at `split`. All zero when `split` is 0 |
| `split_proof_held` | array of bytes (32 each) | **version 2.** RFC 6962 §2.1.2 consistency proof chaining (`split`, `split_root`) to `held`'s signed head. Empty when `split` equals `held`'s size, where the signature says it alone, and empty when `split` is 0 |
| `split_proof_conflicting` | array of bytes (32 each) | **version 2.** The same proof to `conflicting`'s signed head, with the same two empty cases |
| `policy` | text | the `tlog-policy` the **accuser** was verifying under, so a reader can see which witnesses were meant to prevent this. **Informational.** It MUST parse as `c2sp.org/tlog-policy`, every verifier key it carries a valid point (§3.1), else the file is `policy` — a closed schema with a stated grammar is part of the format, and a policy parses one way everywhere (D-079) — and a reader MUST NOT verify anything under it. The reader uses **its own** policy: the trust file's, or one it has replayed (§9.4). Verifying under the carried field hands the accuser the quorum rule, and an accuser writing `quorum none` then gets two uncosigned checkpoints accepted as proof of equivocation — which, by §11 rule 4, takes the network down until an operator installs a new trust file. This implementation did exactly that until cold-model gate run 7 |

A reader MUST, in this order:

1. verify **both** checkpoints per §10 — this network's origin, this network's
   log key, and a satisfied witness quorum **under the reader's own policy,
   never the one in the file**. A log signing two heads by itself is a log
   misbehaving in private; what makes a fork provable to a third party is that
   independent witnesses vouched for **both**.
2. check `size` is **not above `held`'s own size** — an accuser can only speak for a size
   its own branch reaches, and above that there is nothing to compare — then that
   `conflicting`'s size equals `size`,
3. check `proof` chains `held_root` at `size` to `held`'s signed head — or, when
   `size` is `held`'s own size, that `held_root` is the root `held` is signed
   over. `size` 0 never passes this step: no consistency proof starts at an
   empty tree, and every log has the same root there. Without this the reader
   is taking the accuser's word for the number that matters most,
4. **version 2 only:** check `split` is not above `size`, and when `split` is
   not 0, that `split_proof_held` chains (`split`, `split_root`) to `held`'s
   signed head and `split_proof_conflicting` chains it to `conflicting`'s —
   each as step 3 does, with the same empty-proof rule at a head's own size.
   A `split` that is 0 carries an all-zero `split_root` and two empty proofs.
   A file that fails here is refused as `proof`, before the roots are compared:
   every proof a file carries is checked before the file is read as a fork
   (D-076), so a file whose roots agree and whose split proof is bad is
   `proof`, not `consistent`, and a node that acted on an unproven split would
   be taking the accuser's word for which devices to keep, and
5. conclude a fork **only if `held_root` differs from `conflicting`'s root**. If
   they agree, the file proves nothing: a log and its own earlier self is not a
   fork, and a node MUST NOT publish that as an accusation.

A reader that refuses at any step MUST NOT conclude a fork. This is worth
stating separately because §11 rule 4 makes the conclusion **permanent** until
an operator installs a new trust file: a reader that skips a step accepts an
accusation any stranger can write, and takes the network down until a human
intervenes. Each step has a vector in `fork/` for that reason.

**Refusal codes (closed list).** Like §10.1, the evidence reader reports a
closed vocabulary of refusal codes, and the first step whose check fails decides
which. Two conforming readers that refuse the same file MUST refuse it for the
same reason, or a vector can only ask "refused?" and a reader that refuses
everything for the wrong reason passes. The codes describe the **file**. A reader whose own trust file cannot be used — its policy does not parse, or its log key does not — has nothing to check the file against: it checks its own configuration before it reads the file, and reports a fault there as its own, with no code. A `held` or `conflicting` refusal is a checkpoint failing §10, so a reader may report §10.1's code for that failure alongside it. The list, in the order the reader
checks:

| step | code | the refusal |
|---|---|---|
| 0 | `oversize` | the file is larger than `MAX_EVIDENCE_BYTES`; a reader accepts **from a stranger**, so the size bound is checked before any parse. It is the file's own length: a short file whose CBOR declares more than it holds is `cbor`, not `oversize`, since nothing it declares is allocated (cold gate run 17, D9) |
| 1 | `cbor` | the file is not valid deterministic CBOR (§4.0), or is not a map |
| 2 | `version` | the map's `version` is not `1` or `2` — absent, not a uint, or another number. Checked **before** the key set: a key set is only closed relative to a version, so a reader cannot judge the schema of a version it does not speak, and a file with `version: 3` and a key no version defines is `version`, not `schema` (`fork/bad-version-and-unknown-key`) |
| 3 | `schema` | the map is not the closed set of exactly seven keys (version 1) or eleven (version 2), or a value has the wrong type — for example, the `size` field is a boolean rather than a uint — which includes a `held_root` or a `proof` hash that is not **exactly 32 bytes**, as the table above types them. A wrong length is a schema fault, checked here, before any checkpoint is read |
| 4 | `policy` | the carried `policy` is not a well-formed `c2sp.org/tlog-policy`, or carries a verifier key that is not a valid point (§3.1). The field is **informational**, but a closed schema is part of the format |
| 5 | `held` | the held checkpoint fails any §10 check: note framing, log signature, checkpoint body, origin, cosignature, or quorum |
| 6 | `conflicting` | the conflicting checkpoint fails any §10 check. The held checkpoint is checked first, so a file wrong in both is refused as `held` |
| 7 | `size` | `size` is above the held checkpoint's own size, or the conflicting checkpoint's size does not equal `size` |
| 8 | `proof` | `size` is 0 — no consistency proof starts at an empty tree (RFC 6962 §2.1.2 defines one only for 0 < m < n) and every log has the same root there, so no file can show a disagreement at size 0; or the consistency proof does not chain `held_root` at `size` to the held checkpoint's signed head; or, where `size` equals the held size, `held_root` is not the root the held checkpoint is signed over — there is no proof to check, and this comparison is the only thing binding `held_root` to anything, so a reader that skips it proves a fork from one honest checkpoint and any 32 bytes; or a proof is carried where `size` equals the held size and §11.1 requires none; or, at version 2, `split` is above `size`, `split` is 0 with a `split_root` that is not all zero (step 4), a split proof does not chain `split_root` at `split` to its head, or a split proof is carried where none is required (step 4) — all of it before `consistent` below: every proof a file carries is checked before the file is read as a fork (D-076, `fork/bad-consistent-and-bad-split`) |
| 9 | `consistent` | `held_root` equals `conflicting`'s root at `size`; the file proves nothing, and a node MUST NOT publish it as an accusation |

**`MAX_EVIDENCE_BYTES` is 65536**. Two signed checkpoints, a root and a
consistency proof whose length is logarithmic in the tree — an evidence file
does not wrap an entry either. A file larger than this MUST be refused on
length. This matters more here than anywhere else in the document: evidence is
the one artifact a reader accepts **from a stranger**, so an unbounded parse of
it is a denial of service anybody can post.

Nothing in this procedure fetches anything, and no step takes the writer's
word. A node names its own files `<unix>.evidence`; `testdata/vectors/fork/`
ships the same bytes under stable names so they can be referred to.

## 12. Test vectors (deliverable of Phase 0/1)

Paths below are relative to the vector root, which ships as `testdata/vectors/`
in this repository and may be rooted anywhere when the suite is distributed.

**Three provenances, stated plainly.** The entry, state, trust and enrollment-request
vectors come from the Python reference implementation, and the Go code must match them. The
`served/`, `served-large/`, `proofs/`, `fork/` and `checkpoints-bad/` vectors come from the **Go**
implementation instead, because producing a tiled log requires one. `anchors/`
comes from `python-opentimestamps`, the reference implementation of a format
neither of Norn's owns — and they are validated against
libraries neither implementation wrote: `transparency-dev/formats` parses the
checkpoint, and `x/mod/sumdb/tlog` checks every inclusion proof. Nothing in the
suite is checked only against its own author.

**What `cases.json`'s `says` field is.** Every negative in this suite carries a
`says` string, and **`says` is a **semantic hint** — the rule the case is about,
in words, and **not the bytes your implementation must produce**.** What a
reader compares is the `codes` map wherever a manifest has one: replay's reason
codes (§5.2), a receipt's (§7), a checkpoint's and a bundle's (§10.1) and fork
evidence's (§11.1) are all closed lists. `says` stays a hint beside them, and
where a manifest gives no code the rule it names is what a reader checks. A
reader is expected to map each `says` onto its own error by hand,
once, and a suite runner that string-matches it is testing this repository's
phrasing rather than the document (cold gate run 11, D10, where a fresh reader
reverse-engineered its whole error vocabulary out of these files).

What `says` *is* for is the discipline it enforces on the suite itself: a
negative must be refused **for its own rule and nothing else**, and a phrase
naming that rule is how the generators and the placement guards check it.

| file | contents |
|---|---|
| `keys.json` | every test key: Ed25519 `{seed, public, kid}` by name, X25519 public keys by name, and `net` |
| `entries/NN-<type>.cbor` | one valid entry per type, canonical bytes |
| `entries/NN-<type>.json` | mirror: `{entry, entry_hash, leaf_hash, preimage_sha256, size}` where `size` is the byte length of the `.cbor`. The `entry` object mirrors the **CBOR**, so an optional field absent from the entry is absent here too — unlike `state.json`, where §5.3's schema fields are always emitted |
| `log/NN-<name>.cbor` | the replay fixture, **162 entries** in order. The file names are labels, not the order: **read the sequence from `manifest.json`**, never by globbing and sorting |
| `log/NN-<name>.reason` | beside each entry that must be rejected: its §5.2 reason code |
| `log/manifest.json` | `{"anchor": {"net", "genesis_hash", "log_key", "policy"}, "entries": [{"index", "name", "reason"}]}` — the replay input and expected outcome; `reason` is `""` for an accepted entry |
| `log-edges/` | a separate 13-entry replay fixture for run 14 boundaries, with the fixture genesis, a four-member anchor, `entries`, `codes` and `rules` in `manifest.json`, `state.json` and per-rejection `.reason` files; `log/` stays at 162 entries |
| `log-republish/` | a separate 18-entry replay fixture for D-078 and run 16: a stripped revoke and its genuine signed entry, a note preimage and its signed entry, applied-content and refused-byte copies, active log-key re-publications, policy name grammar, a two-byte/canonical boolean pair, a genesis content copy and policy text byte boundaries; `manifest.json` has its own four-member anchor, `entries`, `codes` and `rules` for every entry, with `state.json` and per-refusal `.reason` files; `log/` stays at 162 entries |
| `log-rules/` | a separate 26-entry replay fixture for runs 16 L8 and 17 D11: device-scoped revoke consent, mandatory governance prev and envelope ts, an empty label value, policy log-key pre-announcement and two replay orderings, with repairs; root restoration followed by uppercase signature kid, roots-only enroll and expires-zero request refusals beside their repairs; its own four-member anchor, `entries`, `codes`, `rules`, `state.json` and per-refusal `.reason` files; `log/` stays at 162 entries |
| `log-order/` | a separate 16-entry replay fixture for run 15, with the fixture genesis, an active device, signer-required rotation setup, 13 refusals, its own four-member anchor, `entries`, `codes`, `rules`, `state.json` and per-rejection `.reason` files; `log/` stays at 162 entries |
| `log-cas/` | a separate 33-entry replay fixture for D-077, with the fixture genesis, its own four-member anchor in `manifest.json`, `state.json`, per-rejection `.reason` files and `rules`/`codes` maps. It holds five withheld-authorisation stories, presence rules, the log/witness key invariant, five precedence cases and an accepted one-signature rotation under the current device key |
| `state.json` | canonical replay output for `log/` (§5.3) |
| `genesis/<NN-case>/` | 26 single-entry logs, including `23-root-order-eight` and `24-root-noncanonical`, each refused `bad-genesis`, one per way entry 0 can abort, each with its own `manifest.json` and `state.json`; an abort stops replay, so the cases cannot share a log. `cases.json` lists them |
| `genesis-good/<NN-case>/` | the other side: one single-entry log per genesis a reader **MUST accept**, each replaying to size 1 with nothing rejected and to its `state.json`. `cases.json` lists them |
| `trust-bad/<NN-case>.cbor` | 53 trust files, including `47-witness-noncanonical-point`, that decode cleanly but MUST be rejected as anchors; the file name says why, `cases.json` lists them. `55-log-key-small-order` isolates the trust log-key point check |
| `served/` | the fixture's 162 entries as a real **tlog-tiles directory**, with partial tile and bundle width 162: `tile/entries/…` bundles, `tile/<L>/…` hashes, and `checkpoint` — which **is** the signed note (§6), not an unsigned file with a signed sibling |
| `grown-log/` | a Go-generated 324-entry log, the 162-entry fixture appended twice, serving the unchanged signed and cosigned head at 162 over full `tile/0/000` and `tile/entries/000`, with their width-162 partial paths absent. `cases.json` serves this directory itself and lists five replacement or deletion cases with codes and rules (D-079) |
| `served-large/` | a Go-generated 300-entry served log; `cases.json` records its full and partial level-0 and level-1 tile paths and widths, plus a separate `paths` table for hash-tile and entry-bundle path functions at group boundaries beyond this log |
| `proofs/<device>.bundle` | one §8.1 proof bundle per active device, each proving the entry that made that device active; `cases.json` gives the origin, the log-key seed, the device list and, under `installs`, the key a node installs for each device (§8.1 condition 3) |
| `proofs/at-the-cap.bundle` | a valid bundle of exactly 81919 bytes (`MAX_BUNDLE_BYTES`), grown only with real cosignatures from the unlisted `stranger` key; `cases.json` names it under `at_the_cap` and requires acceptance |
| `proofs/nas-rotate.bundle` | the fixture's real `log/35-rotate-nas` in a bundle labelled `nas`, accepted through the body's `device_id`; `cases.json` lists it separately under `sound`, with `codes` and `rules`, leaving the activating-entry device list unchanged |
| `proofs/laptop-revoke.bundle` | the fixture's real `log/36-revoke-self-laptop` in a bundle labelled `laptop`, accepted through the body's `device_id`; `cases.json` lists it under `sound`, with `codes` and `rules`. Condition 3 installs nothing because replay leaves laptop revoked at the served checkpoint, so `installs` omits it |
| `proofs/right-edge.json` | a standalone RFC 6962 inclusion proof for the last leaf, index 126, of a 127-entry tree; it carries the entry bytes, leaf hash, root and path hashes |
| `trust.cbor` · `trust.toml` · `trust.fingerprint` | the trust anchor (§9), authoritative bytes, human rendering, and its fingerprint |
| `receipt.note` | a submission receipt: the signed note itself (§7) |
| `receipt-bad/<name>.note` | twenty-one receipts that MUST be refused, covering all eight closed §7 codes; the six `order-` cases each fail two adjacent steps. `cases.json` gives each code and the rule of the step that decides it. Body and signer negatives are re-signed; the extra-final-newline case is malformed note framing, and the expiry cases supply their checking time |
| `policies/<name>.txt` | §9.1's restated grammar, 65 whole policies: 15 accepted and 50 refused. `cases.json` marks each `accept` true or false, says which rule it is about and carries `evaluate` rows. `directive-after-quorum` accepts unused trailing directives; `bad-redefinition-after-use` refuses a later definition of a group the quorum already used |
| `log-empty/` | a log with **no entries**: `manifest.json` and the zero state §5.1 says it replays to. Not a `bad-genesis` abort — there is nothing to reject |
| `log-admission/` | a separate nine-entry replay log with the fixture genesis, root-signed `01-signer_add-mixed-order`, `02-root_add-mixed-order` and `03-log_key-mixed-order` (each `decode`), admitted `04-signer_add-honest` and `05-enroll-honest`, `06-rotate-mixed-order` signed by the current device key and cofactored-validly by the incoming key (`decode`), root-signed `07-policy-small-order` naming an order-8 witness key (`decode`), and admitted `08-policy-honest`; the same `manifest.json` and byte-identical replayed `state.json` contract as `log-empty/` |
| `trust-good/<name>.cbor` | trust files §9.1 **permits**, for the members it marks optional or leaves open. `cases.json` lists them |
| `requests/<name>.cbor` · `.txt` · `.json` | enrollment requests (§16): the request bytes, its bech32m text form, and a mirror `{request, preimage_sha256, text, size}`. `cases.json` lists them, each with a `form` — `canonical` for §16.2's lowercase form, or `uppercase` for the same request in the form §16.2 says a reader MUST also accept, which names the canonical case it duplicates |
| `requests-bad/<name>.txt` | 30 requests, including `small-order-device-pk`, `torsion-R-signature` and `S-plus-L-signature`, that MUST be refused — by the text layer, the CBOR profile, a field rule or signature verification. `cases.json` gives each case's reason |
| `receipt.json` | `{comment, origin, leaf_hash, deadline, text_sha256}`, where `text_sha256` is `SHA-256` of the **signed text** — through the newline ending the last text line, excluding the blank separator and the signature lines |
| `checkpoints-bad/<NN-case>.checkpoint` | 46 checkpoints, including `31-cosignature-S-plus-L` (`cosignature`), that MUST be refused, each served in place of `served/checkpoint` over the honest tiles. `cases.json` lists them, and its `signature_blind_accepts` names the ones a verifier that never calls Ed25519 accepts — six of the forty-six. That set is **computed** from the shipped files, not asserted |
| `entries-hostile/<name>.cbor` | 17 inputs that are not entries and never could be, including bare profile bans and §4.0's three resource limits — the entry size, the nesting depth and the map-key cap. `cases.json` says what each refusal must be about, and marks the cases that sit exactly **at** a limit and MUST be accepted |
| `proven/grant-labels.json` | a pure-function table with a `comment` and 43 `{label, grant, says}` cases: D-077 prefix grammar, U+0020-only trimming, canonical masked text, whole-label failure and IPv4-mapped refusals |
| `proven/cases.json` | the devices admitted at four evaluation times (§5.3), including the boundary where `expires` equals `T`; and under `grants`, every active device's §4.0 grant, which the evaluation time does not change |
| `fork/` | `evidence.cbor` and the `conflicting.checkpoint` it is about (§11.1), plus ten more sound files including `evidence-at-same-size.cbor` (the served held head and a different root at the same size, both signed and cosigned, with an empty proof). `cases.json` names all eleven under `sound` and codes all forty-two refusals, including `bad-simple-size` (`cbor`, a simple value outside §4.0's allow-list) and `bad-policy-unparseable-and-foreign-held` (`policy`, before `held`) |
| `anchors/` | OpenTimestamps proofs written by `python-opentimestamps`: `checkpoint-<size>.ots`, `sample.ots` over an arbitrary digest, and a calendar's reply. **`cases.json` states each proof's digest in hex and names the bytes that produce it** — for the checkpoint proof, `served/checkpoint` through the newline that terminates the blank separator line, which is the §6 range and *not* the three-line body. Without it a reader has to parse the OpenTimestamps container, a format this document does not describe, before it can tell which of two byte ranges was stamped |
| `proofs-bad/<name>.bundle` | twenty bundles that MUST be refused (§8.1), including `one-past-the-cap.bundle`: exactly 81920 bytes, otherwise sound, refused as `bundle`. `cases.json` gives the log key, code and rule for each refusal |
| `detect/` | the stored-checkpoint sequences §10 needs, each branch with its own tiles, plus `staleness.json` for §8.1's condition 4 |
| `served-genesis/` | §10.1's `genesis` for a reader that holds no checkpoint: `cases.json` serves `detect/other-genesis` (this network's log key, origin and witnesses over a history whose entry 0 is not the anchored genesis) and `detect/empty` (a cosigned head over no entries), each with its code and the §10.1 phrase that refuses it |
| `served-rotated/` | the served head signed by a published `log_key` (§9.4), with `cases.json` giving the key, its `since_index` and its `overlap`. Serve it over `served/`'s tiles |
| `proofs-rotated/` | `nas.bundle`, `proofs/nas.bundle` with its checkpoint signed by the published `log_key`, and `cases.json` giving that key and both answers: `log-signature` to a reader holding only `trust.cbor`, accepted by one that trusts the published key (§8, §8.1) |
| `receipt-rotated/` | `cases.json` naming `receipt-bad/untrusted-log-key.note` — the shipped receipt, signed by the published `log_key` — and the same two answers (§7, §8) |
| `served-superseded/` | the served head cosigned by two of three witnesses, for §9.4's policy half. Serve it over `served/`'s tiles |
| `unreached-witness/` | two heads over `served/`'s tiles under its own `trust.cbor`: the policy lists pi, vps and friend, while its quorum is pi and vps alone (2 of 2). `cases.json` codes `honest-head` as `accept` and `forged-friend` as `cosignature`, with a section and rule for each |
| `served-bad/` | §6's refusals for a served log, which is a directory rather than a file: each case names the path to replace or delete over an honest copy of the log named by `serve_over` (`served-large/` here) |
| `served-empty-entry/` | a four-entry log with one zero-length frame at index 2 among real entries: its checkpoint is accepted, replay rejects that entry as `decode`, and `state.json` is the expected replayed state; `cases.json` names both answers |
| `served-large-bad/` | three refusals over `served-large/`: `full-entry-bundle-trailing-bytes` adds bytes after the 256 frames of `tile/entries/000` (`entries`); `full-hash-tile-trailing-bytes` adds bytes after the 256 hashes of `tile/0/000` (`tiles`); `level-one-byte-changed` changes one byte at `tile/1/000.p/1` (`tiles`) |
| `served-rotated-wrong-name/` | the served head signed by `logkey2` as `elsewhere/log`; `cases.json` gives `fresh` and `informed` as `log-signature`, because the learned key is named the network origin (§9.4). Serve the checkpoint over `served/` |
| `served-rotated-earlier/` | a complete 20-entry log signed by `logkey2`, whose publication was at index 27 in `served/`; `cases.json` gives `fresh` as `log-signature` and `informed` as `accept`, with no activation index on the verifier's side (§9.4) |
| `dropped-witness/` | its `trust.cbor` still lists pi, vps and friend; replay `00-genesis.cbor` then root-signed `01-policy-drops-friend.cbor` on that anchor to replace the policy with pi and vps alone. `cases.json` checks the same `forged-friend.checkpoint` over `served/`: `friend-after-drop` is `accept` under the replayed policy and `friend-before-replay` is `cosignature` under the trust policy |
| `heads-run16/` | six Go-generated heads over `served/`'s honest tiles, with their own `trust.cbor`, `codes` and one-raw-line `rules` in `cases.json`: three accepted strangers, a three-byte payload (`note`), a policy-only log signer (`log-signature`) after replaying `00-genesis.cbor` and root-signed `01-policy-logkey3.cbor` (prev 0), and a forged pi line beside a short quorum (`cosignature`). The separate `requests` table carries `consumer_net` and two Go-generated signed requests, one accepted and one refused for another network; these semantic results have no closed refusal code (§16.1) |
| `replayed-policy/` | Go-generated `evidence.cbor` and `nas.bundle`, with only pi and vps cosigning their checkpoints. `cases.json` names fresh readers using `trust.cbor` (two of three: fork proved and bundle accepted) and informed readers that replayed `served/` (three of three: `held` and `quorum`), with codes and rules |
| `quorum-none/` | Go-generated `trust.cbor`, identical to the original except for `quorum none`, and `uncosigned.checkpoint`, the served head with every witness line removed. `cases.json` accepts that head and `../served/checkpoint` over `served/` tiles, giving the expected proven set including contractor with no quorum time |
| `genesis-unapplied/` | Go-generated one-entry tiled log and `trust.cbor` pinning that entry's leaf hash: fixture genesis with one of two root signatures removed. `cases.json` codes it `genesis`, beside the restored one-entry `sound/` log under the original trust (`accept`); checking only the pinned leaf hash would accept an empty set |
| `SHA256SUMS` | every file above, for a reader who has the suite and not its generators |

### 12.1 Coverage — what is and is not vectored

Stated precisely, because a suite that looks complete is worse than one that
admits its holes, and an inaccurate coverage claim is the same failure wearing a
different hat.

**Vectored, including negative cases.** Vectors are cited by **name**, never by
index: indices shift whenever a case is inserted, and every previous edition of
this table drifted out of date the moment one was.

| area | positive | negative |
|---|---|---|
| §11.1 split 0 requires an all-zero root (run 17, D4) | `fork/evidence.cbor`; restoring the zero split root with both split proofs empty proves the fork | `fork/bad-split-zero-with-a-root.cbor`: version 2, split 0, nonzero root, two empty split proofs: `proof` |
| §11.1 oversize measures the file (run 17, D9) | `fork/evidence.cbor` | `fork/bad-declared-length-past-the-file.cbor`: ten bytes whose text head declares 70,000 bytes: `cbor`, before schema, never `oversize` |
| §4.0 map keys have a one-byte floor (run 17, D11) | `fork/evidence.cbor`; removing only the empty-key pair restores it byte for byte | `fork/bad-empty-map-key.cbor`: the sound evidence plus one entry under the empty key: `cbor`, before `schema` |
| §10.1 bundle proof hashes are 32 bytes (run 17, D8) | `proofs/nas.bundle`; restoring the first hash recovers it byte for byte | `proofs-bad/short-proof-hash.bundle`: first proof hash cut to 31 bytes: `bundle`, before `inclusion` |
| §8.1 request point admission in binding (run 17, D11) | `proofs/nas.bundle`; real inclusion path, log signature and witness quorum on the negative's small tree | `proofs-bad/request-device-pk-small-order.bundle`: an enroll whose request carries an order-8 device_pk, labelled with its own id: `binding` |
| §8.1 undecodable request under its own id (run 17, D11) | `proofs/nas.bundle`; the negative's proof and served checkpoint remain genuine | `proofs-bad/pk-length-under-own-id.bundle`: unchanged `log/81-bad-pk-length` under probe: `binding`. Omitting the 32-byte rule alone still gives `binding`, because point admission also refuses the 31-byte key |
| §11.1 evidence uses the replayed policy (run 17, D11) | `replayed-policy/evidence.cbor`, fresh reader: fork proved under trust's two of three; `fork/evidence.cbor` proves it for either reader | `replayed-policy/evidence.cbor`, informed reader after replaying served: `held` under the roots' three of three |
| §8.1 bundle uses the replayed policy (run 17, D11) | `replayed-policy/nas.bundle`, fresh reader: accepted under trust's two of three; `proofs/nas.bundle` accepts for either reader | `replayed-policy/nas.bundle`, informed reader after replaying served: `quorum` under the roots' three of three |
| §9.1 quorum none accepts an uncosigned head (run 17, D11) | `quorum-none/uncosigned.checkpoint` over served tiles with `quorum-none/trust.cbor`: accepted, with the manifest's proven set including contractor | requiring any cosignature incorrectly refuses it as `quorum` |
| §13 quorum none supplies no expiry clock (run 17, D11) | `quorum-none/../served/checkpoint` with `quorum-none/trust.cbor`: accepted, no quorum time despite real cosignatures, contractor retained in the manifest's proven set | expiry against a wall clock drops contractor |
| §10.1 the anchored genesis must apply (run 17, D11) | `genesis-unapplied/sound/checkpoint`, original trust and restored fixture genesis: accepted | `genesis-unapplied/checkpoint`, its own trust and tiles: `genesis`; its pinned entry has only one of two required root signatures. A leaf-hash-only reader accepts an empty set |
| §11.1 carried policy point admission (D-079 (1)) | `fork/evidence.cbor`; restoring only the carried policy recovers it byte for byte | `fork/bad-policy-small-order-key.cbor` names an order-8 witness under pi with its id recomputed and quorum on pi: `policy`, step 4 |
| §8.1 bundle label grammar (D-079 (2)) | `proofs/nas.bundle`; restoring only the label recovers it byte for byte | `proofs-bad/device-not-a-device-id.bundle` labels the sound nas bundle `NAS`: `bundle`, step 1 |
| §8.1 an undecodable request names no device (D-079 (2)) | `proofs/nas.bundle` accepts; the refused entry's inclusion proof and served checkpoint remain sound | `proofs-bad/request-undecodable.bundle` proves `log/79-bad-device_id-uppercase` under the valid label `probe`: `binding`, step 4. The label also differs from the request's raw id `Probe`, so it shows the rule only to a reader that reports why (cold gate run 17, D11); `log/81-bad-pk-length` under its own id `probe` separates the two, and ships as `proofs-bad/pk-length-under-own-id.bundle` |
| §6 and §10.1 full tiles replace deleted partial paths (D-079 (3)) | `grown-log/older-head-over-full-tiles` accepts the older head at 162 over the grown log's full tile and bundle; `grown-log/corrupt-beyond-prefix` changes one byte in hash 200 and accepts | `grown-log/full-tile-gone` deletes `tile/0/000`: `unserved`; `grown-log/full-bundle-gone` deletes `tile/entries/000`: `unserved`; `grown-log/corrupt-within-prefix` changes one byte in hash 10: `tiles`. Both width-162 partial paths are absent throughout |
| §8.1 inclusion proof exact consumption (run 16, M3) | `proofs/nas.bundle`; removing the appended hash recovers it byte for byte | `proofs-bad/padded-proof.bundle` appends one 32-byte hash to the sound bundle: `inclusion` |
| §11.1 consistency proof exact consumption (run 16, M3) | `fork/evidence.cbor`; removing each appended hash recovers it byte for byte | `fork/bad-padded-proof.cbor` appends one 32-byte hash to `proof`; `fork/bad-padded-split-proof.cbor` appends one to `split_proof_held`, leaving the main proof sound: both `proof` at step 8 |
| §9.4 policy replacement and §10.1 listed witnesses (run 16, L2) | `dropped-witness/friend-after-drop`: replay its fixture genesis and root-signed policy with prev 0; the policy drops friend, whose forged line is now ignored, and pi and vps meet quorum: `accept` | `dropped-witness/friend-before-replay`: the same head under the same trust file without replay; friend is still named and its matching forged line is `cosignature` |
| §3.1 NORN-ED25519-v1 | `ed25519-cctv/` vector 305, the one that carries no flag; the honest root quorums and `log-admission/04-signer_add-honest`, `log-admission/05-enroll-honest` and `log-admission/08-policy-honest` | the other 913 in `ed25519-cctv/`, with the deciding flags in `cases.json`, executed by both implementations; Norn's own `genesis/23-root-order-eight` and `genesis/24-root-noncanonical` (`bad-genesis`), `requests-bad/small-order-device-pk`, `requests-bad/torsion-R-signature` (the cofactored equation holds), `requests-bad/S-plus-L-signature`, `log-admission/01-signer_add-mixed-order`, `log-admission/02-root_add-mixed-order` `log-admission/03-log_key-mixed-order`, `log-admission/06-rotate-mixed-order` (the cofactored equation holds, the cofactorless one fails) and `log-admission/07-policy-small-order` (`decode`), `trust-bad/47-witness-noncanonical-point` and `checkpoints-bad/31-cosignature-S-plus-L` (`cosignature`); no CCTV vector has `S ≥ L` |
| §4.0 encoding profile | every entry; controls `profile-base`, `labelcap-base`, `two-sig-base` | `bad-cbor-nonshortest` and `bad-cbor-nonshortest-length` (an integer and a length header: the two halves of the shortest-form rule), `bad-cbor-null`, `bad-cbor-unsorted-keys`, `bad-tag-wrapped-value`, `bad-indefinite-text`, `bad-indefinite-map`, `bad-duplicate-map-key`, `bad-invalid-utf8`, `bad-integer-too-large`. The 23-byte map-key cap has no *entry* case, because §4.3 put the device's claims in the request and a closed-schema check fires first on any other key — it is vectored at the decoder instead, in `entries-hostile/` |
| §4.3 `enroll` embeds the request | every `enroll` in the log; `enroll-unicode-labels`, `enroll-contractor` | **`bad-no-device-sig`** and **`bad-order-enroll`** (a request signed by a *signer*, not the device it names), **`bad-forged-device-sig`** (a request signature of the right shape and wrong), and `bad-device_id-uppercase`, `bad-device_id-leading-dot`, `bad-pk-length` — faults **inside** the request, inside an entry that is otherwise well formed and properly signed, so an implementation treating `request` as opaque bytes accepts all three |
| §4.0/§4.3 schemas | `enroll-laptop`, `enroll-unicode-labels` | `bad-kid-format`, `bad-missing-sigs`, `bad-empty-sigs`, `bad-unknown-role`, `bad-unknown-envelope-key`, `bad-unknown-body-key` (a `note`), `bad-rotate-unknown-body-key` and `bad-revoke-unknown-body-key` (each otherwise valid, so the extra key is the only refusal), `bad-device_id-uppercase`, `bad-device_id-leading-dot`, `bad-pk-length`, `bad-sig-length`, `bad-text-too-long`, `bad-unsorted-sigs` |
| §4.2 signatures, hashes, preimage | 16 entry mirrors | **`bad-forged-signer-sig`, `bad-forged-device-sig`** — syntactically perfect signatures that do not verify. Without these an implementation that never calls Ed25519 reproduces the whole manifest |
| §4.0 the whole input is consumed | — | `bad-trailing-byte`: an accepted `log_key` entry with one byte after it. Its signatures still verify and its `entry_hash` differs, so a decoder that stops at the end of the item applies the same governance entry twice |
| §9.4 the policy supersedes | `served-superseded/`: two of three cosignatures — enough for the trust file, short of what the roots published | the informed reader is the stricter one here: its `cases.json` states `fresh` `accept` and `informed` `quorum`, so a reader that refuses it for any other reason — `log-signature`, because it replaced the trust key — fails (cold gate run 13, D16) |
| §10 the stored checkpoint, §11's duties | `detect/`: accepting a head that grows, refusing one that shrinks **without** accusing, and proving a fork at the same size, on a shorter branch, and on a **longer** one (`detect/fork-on-a-longer-branch`: a grown head whose history differs below the stored size — the most ordinary equivocation there is, which a reader that compares only same-size or shorter heads accepts). Every case that is not accepted names its §10.1 code | the shorter-branch case is what a forking log looks like when it hides behind "a log does not shrink". It also pins §10's **order**: under a size-rule-first reading it comes out `refuse` rather than `fork`, so no evidence is written and no alarm is raised |
| §8.1 condition 4 | `detect/staleness.json`, including `elapsed` exactly on `staleness` | a node with no corroborated instant reports `unknown` rather than guessing |
| §9.4 rotation | `served-rotated/`: the same head under a key the roots published — refused by a reader holding only `trust.cbor`, accepted by one that has replayed the rotation | a key that vouched for itself is what the ordering forbids |
| §7, §8.1 receipts and bundles after a rotation (D-074 (a)) | `proofs-rotated/nas.bundle` and `receipt-rotated/`'s receipt, accepted by a reader that trusts the key the roots published | the same two artefacts refused as `log-signature` by a reader holding only `trust.cbor` — the case §8 calls the truth. The reference checks no bundle and no receipt (it writes them), so these are the Go verifier's and the cold verifier's |
| §10 the checkpoint's origin | `served/checkpoint` | `checkpoints-bad/10-wrong-body-origin`: signed by this network's key under this network's name, naming another log |
| §4.0 both limits, at the boundary | `entries-hostile/at-the-depth-limit` and `at-the-size-limit`, which MUST be accepted | `past-the-depth-limit` and `past-the-size-limit`, one step beyond each. Without the accepted half a decoder enforcing 4, 16 or 64 passes |
| §16.2 padding | `req-padding-base`: a valid 203-byte signed request whose bit length leaves one padding bit | `excess-padding` appends one zero 5-bit group, leaving six unused bits without adding a decoded byte; `non-zero-padding` sets a padding bit. Both are refused by §16.2 alone |
| §9.4 the anchor key is kept **alongside** | `served/checkpoint`, signed by `norn.trust.log_key`, which the log publishes **nowhere**: the two `log_key` entries name other keys entirely | a reader that *replaces* `log_keys` with the published ones cannot read the head the log is serving. Replacing is the weakening — it trusts only what the log said about itself. `served-rotated/cases.json`'s `informed_reads_served` states the answer — `accept` — which until cold gate run 13 (D16) this row claimed and no manifest asked |
| §4.1 `sigs` elements are a closed map | every entry | `bad-sigs-fourth-key`: a fourth key beside `kid`, `role` and `sig` |
| §4.1 `v` MUST be 1 | every entry | `bad-version-two`. No entry carried any other value, so a reader that never looked at `v` reproduced the manifest |
| §5.1 `rotate` on a revoked device | `rotate-nas` | `bad-rotate-revoked`: `laptop` is known and revoked, so it is `not-active` and not `unknown-device`. The only other `not-active` vector is a `revoke` |
| §5.1 `dup-key` is across **both** roles | `signer_add-recover` | `bad-root_add-existing-signer`: adding a current signer as a root. Every other dup-key vector re-added a key into the role it was already in |
| §4.0 the profile's banned items, at the decoder | the three `at-the-…-limit` cases | `bare-null`, `bare-undefined`, `bare-float`, `bare-simple`, `bare-negative-integer`, `bare-tag`, `bare-indefinite-text`, `bare-nontext-map-key` and `bare-invalid-utf8` — each a whole input with no schema above it, so the profile is the only thing that can refuse, and each refused for **its own** rule. The in-entry negatives cannot pin these: a lenient decoder hands the envelope check a malformed field and the reason is `decode` either way |
| §4.0 booleans are profile items; field types are schema | `fork/bad-bool-size.cbor` decodes as valid CBOR with `size: true` | `schema`: §11.1 requires `size` to be uint, so the decoded boolean is refused by the evidence schema |
| §4.0 simple values outside the allow-list | `fork/bad-bool-size.cbor` has `size: true`, a valid profile item refused as `schema` | `entries-hostile/bare-simple` is simple value 16 alone, refused only by the decoder; `fork/bad-simple-size.cbor` changes only `size` from `true` to simple value 16 and is refused as `cbor`, before the schema |
| §4.0 free text has no lower bound | `note-empty-text`, `revoke-empty-reason` and `revoke-no-reason` — all **accepted**. `text` is bounded above only, `reason` is 0–256, and §4.3 marks it OPTIONAL | a reader that requires one byte rejects entries this document accepts, which only a positive can show |
| §4.0 label-value byte cap | `req-label-at-cap`: one signed label value of exactly 256 UTF-8 bytes (128 `é`) | `oversize-label`: a validly signed 257-byte value (128 `é` plus `x`, 129 code points), refused by the byte cap; a character-counting reader accepts it |
| §4.0 resource limits | — | `entries-hostile/oversize-entry` (a header promising 65536 bytes, refused on length before anything is allocated) and `entries-hostile/deep-nesting` (200 nested arrays, deterministic throughout, so only the depth rule can refuse it) |
| §4.0 the map-key cap, at the decoder | `entries-hostile/at-the-key-limit` (23 bytes, MUST be accepted) | `past-the-key-limit`: a one-pair map with a 24-byte key and a uint value, so nothing but the cap can refuse it. `requests-bad/oversize-label-key` has a 24-byte label key and is refused by the decoder before the `labels` field rule |
| §4.4, §5.1 `prev` binds the source of every state change (D-077) | accepted transitions in `log-cas/`; `log-cas/32-rotate-same-device-key-one-signature` changes `wg_pk` under the current `device_pk` with one valid device signature; `state.json` and every fixture state carry §5.3's versions | five stale stories: `log-cas/03-stale-withheld-rotate`, `log-cas/06-stale-reinstated-signer`, `log-cas/09-stale-superseded-log-key`, `log-cas/12-stale-revoke-reenrolled-device`, `log-cas/16-stale-enroll-after-second-revocation`; presence: `log-cas/17-never-named-enroll-with-prev`, `log-cas/18-revoked-enroll-without-prev` (`stale-state`), `log-cas/19-note-with-prev` (`decode`) and `genesis/25-prev-present` (`bad-genesis`) |
| §2 and §4.0 whole-string device IDs; §3.1 request key admission | `log-edges/06-enroll-nas2` | `log-edges/01-enroll-device-id-newline` has a properly signed `nas2\n` request (`decode`); `log-edges/10-enroll-request-identity` admits no identity point (`decode`, before `no-device-sig`) |
| §4.0 inclusive integer and reason bounds | `log-edges/02-note-integer-at-the-cap` accepts ts = 2⁶³−1; `log-edges/09-revoke-reason-at-the-cap` accepts a signer-authorised 256-byte reason | — |
| §5.3 re-enrolment replaces the record | `log-edges/03-enroll-nas-with-label`, `log-edges/04-revoke-nas`, `log-edges/05-reenroll-nas-without-labels`: all accepted; `log-edges/state.json` carries `labels: {}` | — |
| §5.1 lifecycle body checks precede device lookup | `log-edges/12-note-after-refusals` shows replay continues | `log-edges/07-rotate-unknown-open-body` and `log-edges/08-revoke-unknown-open-body` have one extra body key for a never-enrolled ID: `decode`, before `unknown-device` |
| §9.1 witness algorithm, isolated from duplicate public keys | `policies/minimal` | `log-edges/11-policy-witness-note-key` is root-signed and `decode`; `policies/bad-witness-vkey-algorithm-distinct` uses a distinct valid 0x01 key without a log line, refused only by the witness algorithm rule. The existing `policies/bad-witness-vkey-algorithm` also repeats the log public key |
| §4.0 genesis name floor and closed body | `genesis-good/02-name-one-byte` accepts a one-byte name | `genesis/26-body-unknown-key` adds one extra body key: `bad-genesis` |
| §9.1 trust and witness name boundaries | `trust-good/name-at-the-cap`, `trust-good/name-one-byte`, `trust-good/witness-name-at-the-cap` and `trust-good/witness-name-one-byte`: 64-byte and one-byte labels; renamed witnesses correspond in the policy | `trust-bad/52-name-one-past-the-cap` is exactly 65 bytes; `trust-bad/26-name-too-long` is 66 bytes |
| §9.1 trust-level log algorithm without a policy log line | `trust.cbor` | `trust-bad/53-log-cosignature-without-policy-log` has a valid 0x04 log key and no policy log line, so only the trust-level algorithm rule refuses it |
| §7 receipt line count and origin equality | `receipt.note` | `receipt-bad/fifth-line.note` has five signed lines (`receipt`); `receipt-bad/origin-case-changed.note` changes one origin letter's case (`origin`). Both are re-signed by the log key |
| §4.0 grant grammar and trimming (D-077) | `proven/grant-labels.json`: U+0020 at either end; IPv6 case and zero compression, embedded dotted quads rendered as hexadecimal, masking and zero lengths | the same table: bare addresses, leading zeros, masks, zones, non-U+0020 whitespace, malformed addresses and lengths, empty parts and IPv4-mapped addresses before masking |
| §10.1 zero-length entry frames (run 14, M2) | `served-empty-entry/zero-length-entry`: accepted checkpoint with an empty frame between real entries; `served-empty-entry/state.json` rejects index 2 as `decode` | — |
| §10.1 full bundle and tile exactness (run 14, M3) | `served-large/` | `served-large-bad/full-entry-bundle-trailing-bytes` is `entries`; `served-large-bad/full-hash-tile-trailing-bytes` is `tiles`, including length in the byte comparison |
| §10.1 genesis precedes hash tiles (run 14, L1) | — | `served-genesis/other-genesis-missing-tile` serves `detect/other-genesis-missing-tile` and is `genesis` before `unserved`; `served-genesis/other-genesis-tampered-tile` serves `detect/other-genesis-tampered-tile` and is `genesis` before `tiles`; both hold no stored checkpoint |
| §10.1 adjacent checkpoint checks (run 14, L2) | `served/checkpoint` | `checkpoints-bad/34-four-lines-and-wrong-origin` is `checkpoint` before `origin`; `checkpoints-bad/35-wrong-origin-and-forged-pi` is `origin` before `cosignature`; `checkpoints-bad/36-no-quorum-and-size-163` is `quorum` before the missing entries can be fetched (`unserved`) |
| §7 LF note framing (run 14, L2) | `served/checkpoint` | `checkpoints-bad/37-crlf` changes all LF endings to CRLF and is `note` |
| §7 the first blank line ends the text (run 15, L1) | `served/checkpoint`; removing the inserted empty line restores it exactly | `checkpoints-bad/45-blank-line-between-signatures` inserts one empty line between two honest signature lines: `note` |
| §7 the text is at least one line (D-078) | `served/checkpoint`; removing the leading line feed restores it byte for byte and accepts | `checkpoints-bad/46-blank-first-line` prepends one line feed to the honest head: `note`, before any signature is checked |
| §9.1 listed witnesses outside the quorum; §10.1 step 6 (run 15, M2) | `unreached-witness/honest-head`: accepted under its valid trust, which lists pi, vps and friend but requires only pi and vps (2 of 2) | `unreached-witness/forged-friend` replaces friend's matching line with one signature byte changed: `cosignature`; restoring that line restores acceptance |
| §7 bounded cosignature time (D-077) | `served/checkpoint`; the bound itself, 2⁶³−1, is accepted in the cosignature unit test | `checkpoints-bad/38-cosignature-time-above-2-63` re-cosigns the honest head with listed witness pi at 2⁶³, signing its unsigned decimal message: `cosignature` before the cast or signature check |
| §7 signature name framing (D-077) | `served-stranger-name/` stays accepted; repairs change only the added name to `stranger`, leaving an ignored line | `checkpoints-bad/39-signature-name-empty`, `checkpoints-bad/40-signature-name-tab`, `checkpoints-bad/41-signature-name-nbsp` (U+00A0) and `checkpoints-bad/42-signature-name-plus` each append one stranger line to the honest head: `note` |
| §7 whole-note control-byte framing (D-077) | `served/checkpoint` | `checkpoints-bad/43-signature-name-nul` places NUL inside an added stranger's name: `note`. `checkpoints-bad/37-crlf` does not pin CR: CRLF endings leave no blank separator line, so it is `note` without this rule. Unit tests cover every byte below 0x20 except LF in signed text, names and payloads; `checkpoints-bad/44-carriage-return-in-signed-text.checkpoint` pins a CR before the root line's LF in otherwise frameable signed text, with the log and all three witnesses signing those exact bytes: `note` before any key is looked for. The reference checks the five stranger names on a note-only projection retaining the actual log signature and extra 68-byte line; it verifies no checkpoint or cosignature |
| §10.1 bundle version precedes its checkpoint (run 14, L2) | `proofs/nas.bundle` | `proofs-bad/wrong-version-and-untrusted-checkpoint` carries `v: 2` and a checkpoint signed by an untrusted key: `bundle` before `log-signature` |
| §11.1 adjacent evidence checks (run 14, L2) | `fork/evidence-v1.cbor` | `fork/bad-policy-unparseable-and-unknown-key` is `schema` before `policy`; `fork/bad-unverifiable-conflicting-and-size-mismatch` is `conflicting` before `size` |
| §11.1 size 0 with an empty held head (run 14, L4 c) | — | `fork/bad-size-zero-empty-held` carries two signed and cosigned size-0 heads with different roots and an empty held head: `proof`. The held root matches its head and the proof is empty, isolating the explicit size-0 rule |
| §9.4 learned key name and absence of an activation index (run 14, L2) | `served-rotated-earlier/`: an informed reader accepts the 20-entry head signed by the key published at index 27 | `served-rotated-wrong-name/`: both fresh and informed readers refuse as `log-signature`, because a learned key is named the origin |
| §4.0 two-byte booleans (run 16, M1) | `log-republish/14-params-canonical-true` accepts and sets `rotate_needs_signer` true in `log-republish/state.json`; replacing only the boolean encoding repairs its predecessor | `log-republish/13-params-two-byte-true` is the canonical entry with `true` written `f8 15`: `decode`, leaving the canonical content free to apply |
| §5.1 entry 0 records both seen sets (run 16, L1) | `log-republish/00-genesis`; the copied envelope is valid as an anchored genesis on its own | `log-republish/15-copy-genesis-extra-sig` adds one sorted unresolvable signature to that genesis, changing its `entry_hash` while preserving its `content_hash`: `dup-entry`, before `dup-genesis` |
| §9.1 trust log-key point admission (run 16, L4) | `trust.cbor`; replacing only the damaged public key repairs the file | `trust-bad/55-log-key-small-order` carries an order-8 `log_key` under the origin's name, with its id recomputed and no policy `log` line: invalid only by §3.1 item 2 |
| §5.1 refused bytes and applied content stay separate (D-078 (1)) | `log-republish/00-genesis`, `log-republish/01-enroll-nas`, `log-republish/03-revoke-genuine` and `log-republish/05-note-genuine`: the genuine revoke applies after its stripped copy and leaves nas revoked; the signed note applies after its own preimage; removing either refused predecessor preserves acceptance | `log-republish/02-revoke-stripped` (`threshold`), `log-republish/04-note-preimage` (`decode`), `log-republish/06-copy-applied-extra-sig` and `log-republish/07-copy-refused-bytes` (`dup-entry`): applied content still counts under another signature list, and refused bytes still count |
| §5.1 active log keys cannot be re-published (D-078 (3)) | `log-republish/09-log-key-new` learns a new public key | `log-republish/08-log-key-anchor` and `log-republish/10-log-key-learned` (`dup-key`): the anchor key and the learned key are already active; replacing only the public key and re-signing accepts |
| §9.1 policy names use the ASCII key-name grammar (D-078 (2)) | `policies/witness-name-at-the-cap` accepts exactly 64 ASCII bytes; `log-republish/12-policy-name-ascii` accepts zurich | `policies/bad-witness-name-not-ascii`, `policies/bad-group-name-plus` and `policies/bad-witness-name-one-past-the-cap` refuse zürich, a+b and 65 ASCII bytes; `trust-bad/54-witness-name-not-ascii` names zürich in both halves and is invalid; `log-republish/11-policy-name-not-ascii` is root-signed with the correct prev and is `decode`; repairing only each name accepts |
| §4.0 lowercase signature kid (run 17, D11) | `log-rules/21-note-without-surplus-kid.cbor` drops only the surplus signature and applies | `log-rules/20-note-uppercase-kid.cbor` retains the genuine signer and adds its uppercase kid as a surplus element: `decode` |
| §4.3 only signers authorise enroll (run 17, D11) | `log-rules/19-root-restore-known.cbor` restores root3 after entry 18; `log-rules/23-enroll-with-signer.cbor` adds one signer signature and applies | `log-rules/22-enroll-by-roots.cbor` carries a fresh signed request and all three current roots, with no signer: `threshold` |
| §16.1 present expires must follow ts (run 17, D11) | `log-rules/25-enroll-without-expires.cbor` omits only expires, re-signs the request and envelope, and applies | `log-rules/24-enroll-expires-zero.cbor` embeds a signed request with positive ts and expires 0: `decode` |
| §7 step 1 requires a signature line (run 17, D11) | `receipt.note` | `receipt-bad/no-signature-line.note` removes only the shipped receipt's signature lines, retaining the text and blank separator: `note` |
| §4.0 grants sort as text across families (run 17, D11) | `proven/grant-labels.json`: `9.0.0.0/8, 1::/16` gives `["1::/16", "9.0.0.0/8"]` | — |
| §4.0 RFC 4291 compression consumes at least one group (run 17, D11) | — | `proven/grant-labels.json`: `1:2:3:4:5:6:7::8/128` has eight explicit groups beside `::`, so the whole label gives no grant |
| §4.3 device-scoped revoke consent (run 16, L8) | `log-rules/00-genesis`, `log-rules/01-enroll-nas`, `log-rules/02-enroll-laptop`; `log-rules/04-revoke-nas-by-self` changes only the signing key and accepts | `log-rules/03-revoke-nas-by-laptop` carries only the other enrolled device's signature: `threshold` |
| §4.4 governance prev at version zero (run 16, L8) | `log-rules/06-signer-add-prev-zero` sets prev 0 and accepts | `log-rules/05-signer-add-without-prev` is root-signed at version 0: `stale-state` |
| §4.0 mandatory ts and empty label values (run 16, L8) | `log-rules/08-note-with-ts` repairs the missing member; `log-rules/09-enroll-empty-label-value` accepts a signed request whose label value is empty | `log-rules/07-note-without-ts` is signed over exactly the incomplete envelope: `decode` |
| §5.1 policy log-key pre-announcement (run 16, L8) | `log-rules/10-policy-preannounces-log-key` names an unpublished key on a log line; `log-rules/11-log-key-preannounced` publishes it: both accept | —; log-key disjointness covers policy witnesses |
| §5.1 content duplicates after envelope validation (run 16, L8) | sorting `log-rules/12-copy-enroll-unsorted-sigs` recovers `log-rules/01-enroll-nas` byte for byte; it accepts against the prefix before that enrollment | `log-rules/12-copy-enroll-unsorted-sigs` is `decode`; `log-rules/13-copy-enroll-sorted-sigs` is the repaired byte copy and is `dup-entry` |
| §5.1 root_remove unknown key before invariant (run 16, L8) | `log-rules/14-root-threshold-full` sets the threshold to all three roots; `log-rules/17-root-threshold-repaired` lowers it and `log-rules/18-root-remove-known` accepts | `log-rules/15-root-remove-unknown-before-invariant` is `unknown-key`; repairing only the kid gives `log-rules/16-root-remove-known-at-full-threshold`: `root-invariant` |
| §4.0 grant tie-break and deduplication (run 16, L8) | `proven/grant-labels.json`: `1:0:0:2:3:0:0:4/128` becomes `1::2:3:0:0:4/128`, compressing the first equal run; `10.0.0.1/8, 10.0.0.2/8` becomes exactly one `10.0.0.0/8` after masking | — |
| §7 signature matching by name and key id (run 16, L8) | `heads-run16/stranger-log-id` and `heads-run16/stranger-pi-id` append another name carrying the log's or pi's key id and accept over honest tiles | — |
| §7 framing minimum and C0 controls (run 16, L8) | `heads-run16/stranger-del` accepts DEL in a stranger's name; removing each extra line restores `served/checkpoint` | `heads-run16/stranger-three-bytes` is `note`: its canonical base64 decodes to only three bytes |
| §9.1 policy log lines publish no verification key (run 16, L8) | `served/checkpoint` accepts after the same genesis and root-signed policy replay | `heads-run16/policy-log-only` is `log-signature`: only `logkey3` signs, and the replayed policy names it only on a `log` line |
| §10.1 step 6 before step 7 (run 16, L8) | repairing pi alone leaves a genuine `quorum` refusal; restoring the other honest witness lines accepts | `heads-run16/forged-pi-without-quorum` is `cosignature`, with only a forged pi beside the log line |
| §10.1 every served hash tile (run 16, L8) | the honest `served-large/` level-1 tile accepts | `served-large-bad/level-one-byte-changed` is `tiles`: one byte differs at `tile/1/000.p/1`, with entries and head unchanged |
| §7 receipt origin equality (run 16, L8) | `receipt.note` | `receipt-bad/origin-extended.note` appends one origin character and re-signs with the log key: `origin` |
| §11.1 exact versioned evidence key sets (run 16, L8) | `fork/evidence.cbor` and `fork/evidence-v1.cbor` prove the fork | `fork/bad-v1-split-keys` carries all four version-2 split fields at version 1; `fork/bad-v2-without-split-keys` omits them at version 2: each `schema` |
| §8.1 a positive rotate binding (run 16, L8) | `proofs/nas-rotate` is `proofs/nas-rotate.bundle`, proving nas's real rotation under its own label: accepted | relabelling the same bundle is `binding`; `proofs-bad/rotate-entry-other-device` ships an earlier nas rotation under another label |
| §8.1 a positive revoke binding and condition 3 (run 16, L8) | `proofs/laptop-revoke` is `proofs/laptop-revoke.bundle`, proving laptop's accepted self-revoke at index 36: accepted as a bundle, nothing installed because replay leaves laptop revoked at size 162. `proofs/nas.bundle` still installs `installs[nas]`, the replayed key | relabelling the revoke bundle with another active device's id is `binding`; `proofs-bad/revoke-entry-other-device` ships that refusal |
| §16.1 a request consumer's network (run 16, L8) | `heads-run16/request-this-network` accepts with the manifest's `consumer_net` | `heads-run16/request-other-network` verifies its signature and is refused only for another network; both accept with their own network, and `requests-bad/` is unchanged |
| §5.1 adjacent replay checks and §3.1 policy log-key admission (run 15) | paired `log-order/` cases repair either fault alone and expose the other; every case accepts after its faults are repaired; `proven/grant-labels.json` sorts IPv4 prefixes as text, leaves a single zero group uncompressed and compresses two zero groups | `log-order/02-rotate-incoming-only` (`no-device-sig`); `log-order/04-rotate-threshold-before-prev`, `log-order/05-enroll-threshold-before-prev`, `log-order/07-revoke-threshold-before-prev` (`threshold`); `log-order/06-enroll-prev-before-dup-id`, `log-order/11-policy-prev-before-dup-key`, `log-order/12-signer-remove-prev-before-unknown-key`, `log-order/13-signer-thr-prev-before-bad-thr`, `log-order/14-log-key-prev-before-dup-key` (`stale-state`); `log-order/08-signer-add-after-before-threshold` (`after`); `log-order/09-params-body-before-prev`, `log-order/10-policy-parse-before-prev`, `log-order/15-policy-log-identity` (`decode`) |
| §5.1 `prev` check order | accepted entries in `log-cas/` | `log-cas/25-threshold-before-stale` (`threshold`), `log-cas/28-current-signature-before-stale` (`no-device-sig`), `log-cas/29-stale-before-incoming-proof`, `log-cas/30-stale-before-dup-key` and `log-cas/31-stale-before-dup-wg` (`stale-state`): two faults each, with the deciding check first |
| §9.1 log/witness public-key disjointness (D-077) | `log-cas/23-policy-spare-witness` | `log-cas/20-policy-witness-is-anchor-log-key`, `log-cas/21-policy-witness-is-learned-log-key`, `log-cas/22-log-key-is-trust-witness`, `log-cas/24-log-key-is-replayed-witness` (`dup-key`); `trust-bad/51-witness-key-is-log-key` invalidates the trust file even without a policy `log` line |
| §4.4 `after` at the boundary | `after-at-its-own-index`: a floor met exactly | `bad-after-by-one`: one past the index, the smallest violation there is |
| §5.1 the request's `net` | every `enroll` | `bad-request-net`: a properly signed request for another network, so only that check refuses it |
| §5.1 `dup-id` before `dup-wg` | — | `bad-dup-id-and-wg`: an active `device_id` *and* a WireGuard key active for another device |
| §5.1 the order **inside** `enroll` and `rotate` | — | `bad-enroll-request-net-and-sig` (the request's `net` decides before its signature), `bad-enroll-unsigned-request-no-signers` (the request's signature decides before the signer count — the case `bad-enroll-empty-sigs` cannot make, since its request *is* signed) and `bad-rotate-dupwg-and-no-new-key-sig` (`dup-wg` decides before the proof of possession on the incoming `device_pk`). Each is wrong in both of its two ways at once |
| §5.1 the first failing replay check decides | — | `log/99-bad-precedence-decode-before-unknown-type`, `log/100-bad-precedence-decode-before-after`, `log/101-bad-precedence-after-before-threshold`, `log/102-bad-precedence-threshold-before-dup-id` and `log/103-bad-precedence-threshold-before-dup-wg`: each carries two faults, so the earlier check determines its closed reason code. Five more order the pairs no entry reached until cold gate run 13 (D4): `log/149-bad-precedence-unknown-type-before-after` (step 4 before 6), `log/150-bad-precedence-dup-genesis-before-after` (5 before 6), `log/151-bad-precedence-note-threshold-before-body` (7 before 8, for `note`), `log/152-bad-precedence-revoke-not-active-before-threshold` (inside `revoke`) and `log/153-bad-precedence-net-before-threshold` (3 before 7) |
| §5.2 a `device` signature's `kid` resolves | — | `bad-device-sig-wrong-kid`: the signature verifies and its `kid` names another key. The preimage excludes `sigs`, so rewriting a `kid` leaves the signature intact |
| §5.2 a signature counts only **in its declared role** | — | `bad-role-mismatch` for the root/signer direction, and `bad-device-sig-wrong-role` for the device one: the device's key really did sign, under `role: "signer"`, where it resolves to nothing. An implementation that ignores the declared role accepts it |
| §4.0 the `kid` **body** rule | `signer_remove-below-threshold` | `bad-kid-format-in-body`: a `signer_remove` whose body `kid` is not `^[0-9a-f]{16}$` → `decode`, not `unknown-key`. `bad-kid-format` puts the malformed kid in `sigs`, which is the other half of the distinction this document draws |
| §4.0 `revoke`'s `reason` and `text` caps | `revoke-by-roots`; `note-text-at-the-cap`, exactly 4096 bytes | `bad-revoke-reason-too-long`: 257 bytes — one past the cap, in two-byte characters, so 129 characters and well under it counted that way; `bad-revoke-reason-at-the-cap`: exactly 256 bytes, which passes the body check and is refused by the next one, `unknown-device` — a reader whose cap is one byte too strict says `decode`. `bad-text-too-long` is the same shape for `note`'s 4096-byte cap: 4097 bytes, 2049 characters. `log-republish/16-policy-text-at-the-cap` accepts a parseable 4096-byte policy; `log-republish/17-policy-text-one-past-the-cap` is parseable at 4097 bytes and is `decode`, with two-byte comment padding in both (cold gate run 16, L5). Every cap was pinned from two bytes above until cold gate run 12 (D16), so a cap off by one in either direction passed |
| §4.0 the genesis `name` bound | the log's entry 0 | `genesis/14-name-too-long` and `15-name-empty` — both ends, because a reader enforcing only the cap and one enforcing only the floor are different implementations |
| §5.3 genesis `params` is **overlaid** | `state.json`'s `checkpoint_interval`, which the genesis body does not set and the §4.5 default supplies | a reader that *replaces* the defaults instead loses the key entirely |
| §4.3 the request's `ts` is unconstrained | `enroll-request-from-the-future`: an accepted `enroll` whose embedded request is dated ten days after the entry carrying it | the check a reader is most likely to add unasked |
| §4.4 `after` is a floor | `after-below-index` | `bad-after` |
| §5 replay, 15 of the 17 reason codes | the log | **114 rejecting entries** |
| §4.2 signatures resolve against the state **before** this entry | the whole log, every governance entry | `log/133-bad-root_add-counts-its-own-key`: `root_thr` is 3, two valid root signatures, and a third by the key in its own body. Under §4.2 that is two of three and the entry is `threshold`; under the other reading it is a root quorum that **bootstraps itself**. No other entry is signed by a key it adds, so `ResolveKeysAfterEntry` passed all 622 checks. §9.4 makes the same ordering argument for log keys — a stolen log key cannot name its own successor — and the root-key version was stated once and exercised by nothing (cold gate run 11, D8) |
| §5 `bad-genesis` | — | `genesis/`; it cannot appear in the log, since it aborts replay |
| §5.1 genesis | the log's entry 0; `genesis-good/01-name-at-the-cap`, a 64-byte `name` | **26 abort paths** in `genesis/`, one single-entry log each, including the honestly root-signed `23-root-order-eight` and `24-root-noncanonical`, whose keys alone abort them as `bad-genesis`. §4.0's 1–64 byte `name` is pinned at both ends and beside the top one: `15-name-empty`, `20-name-one-past-the-cap` (65 bytes in 33 characters — 32 two-byte and one ASCII — so a reader counting characters accepts it) and `14-name-too-long` (cold gate run 13, D17). Two of them are step 7's two halves: `18-bootstrap-sigs-wrong-role` varies the **role string** a signature declares, `19-bootstrap-sigs-from-signers` varies the **key set** it resolves against — signed only by keys the body lists under `signers`, each line declaring `root`. Step 6 requires the two sets disjoint, so a reader that bootstrap-resolves against `signers` too admits a network this one aborts on (cold gate run 10, D15) |
| §5.1 seen set, §4.3 roles | — | `bad-repeat-of-rejected`, `bad-one-of-two-signers`, `bad-role-mismatch`. Step 1's two stated properties are `bad-repeat-of-undecodable` (the key is recorded **before** the entry is decoded, so a copy of one that never decoded is `dup-entry` and not a second `decode`) and `bad-repeat-of-genesis` (entry 0's key is recorded too, so a byte copy of it is `dup-entry` and not `dup-genesis`). The key being the **signed content** of a decodable entry (D-070) is held by six entries: `bad-copy-enroll-spare-extra-sig`, `bad-copy-policy-extra-sig`, `bad-copy-rotate-nas-extra-sig` and `bad-copy-signer_add-signer3-extra-sig` (a past entry re-appended with one unresolvable signature), `bad-copy-enroll-spare-role-relabelled`, and `bad-copy-two-sig-base-surplus-dropped` — every one `dup-entry`, and under a byte key every one applied again (the first re-enrols a device revoked two entries later; the second rolls the quorum back). `two-sig-base` carries its own text so it stays the sigs-ordering control rather than becoming a duplicate of `profile-base` |
| §5.2 `bad-thr` | `signer_thr-2-of-2`: the bound is inclusive, a threshold equal to the set's size | both halves: `bad-thr-zero` and `bad-thr` (value above the set size) |
| §5.1 a `policy` entry is a policy | `policy-rotated`, which raises the quorum from 2 of 3 to 3 of 3; `policy-two-log-lines`, the same policy naming the log's original key and the first one its roots published | `bad-policy-unparseable`: text that is well-formed, under the size cap, and not a `tlog-policy`; `log-admission/07-policy-small-order` is otherwise valid policy text whose witness key is not a valid point (`decode`), followed by admitted `log-admission/08-policy-honest` |
| §4.3 `revoke`'s three authorisations | `revoke-by-roots`, `revoke-self-laptop` (the device authorising its own revocation, and the only signature on it) | `bad-revoke-neither-quorum`: one signer of two and two roots of three — short on every rule independently, and a quorum only if the counts are pooled |
| §5.1 uint fields refuse booleans; a rejected entry changes nothing (SEC-016) | the log's `signer_thr`, `root_thr` and `log_key` entries | `bad-signer_thr-bool`, `bad-root_thr-bool` and `bad-log_key-overlap-bool`: each fully root-signed, otherwise valid, and `decode`; coercing `true` to 1 accepts all three, while `state.json` keeps both thresholds and `log_keys` unchanged. `genesis/21-root-thr-bool` and `genesis/22-signer-thr-bool` are otherwise valid, root-signed entry-0 cases, each `bad-genesis` |
| §5.1 `params`: non-empty, §4.5 keys, right types; a rejected entry changes nothing | `params` entries in the log | `bad-params-mixed-validity` (`mmd` valid and first in key order, `staleness` a bool: a handler that writes as it validates has changed `mmd` by the time it rejects, and `state.json` shows it did not), `bad-params-empty`, `bad-params-unknown-key`, `bad-params-wrong-type` — a CBOR `true` where a uint belongs, which a loose decoder reads as 1 — and `bad-params-flag-as-uint`, the reverse: `rotate_needs_signer` given as `1`, which a reader that treats any truthy value as on accepts. The same key rule at entry 0 is `genesis/13-params-unknown-key`, where the two readings differ by the whole log: one aborts to the zero state, the other replays every entry |
| §14.1 key order above the BMP | `enroll-astral-labels`, whose labels carry one astral key and one private-use key: the only pair in the suite where UTF-8 bytewise order and UTF-16 code-unit order disagree | — |
| §5.3 state, incl. D-028 and `expires` | `state.json`, `enroll-contractor` | `signer_remove-below-threshold` accepted, then `signer_add-recover` |
| §5.3 a witness counts at its **newest** verifying line | `served-twice-cosigned/`: one witness answers twice and both lines verify, so the head is valid and only the tie-break decides. `cases.json` records the instant it must come out at, and the one an oldest-line reader would get instead | `checkpoints-bad/12-second-line-from-one-witness` cannot pin this — its second line does not verify, so §10's per-line rule refuses the checkpoint first |
| §5.3 the derivation of `T` | `served/checkpoint`, whose three witnesses cosign seven seconds apart, so the **newest** and the **oldest** are both separated from the answer; `proofs/cases.json` records the value `T` must come out as | — |
| §5.3 policy for the checkpoint's `T` | `served/checkpoint` is accepted under `trust.cbor`'s 2-of-3 policy, so `proofs/cases.json` records `checkpoint_quorum_time` 1760003607. The same checkpoint replays a 3-of-3 policy; `replayed_policy_quorum_time` 1760003600 pins the different, retroactive reading. It also separates the median from the k-th newest: `replayed_policy_quorum_time` is computed under a three-of-three policy, where the k-th newest is the oldest cosignature and the median is not, so a median reader gets 1760003607 and fails (cold gate run 13, D19) | — |
| §4.0 the grant, §4.5 `routes` | `proven/cases.json`'s `grants`: `router`'s label `10.9.1.5/24, fd00::5/64` becomes `10.9.1.0/24, fd00::/64` (masked, sorted as text), `nas` has none, and `badgrant`'s `10.9.2.0/24, nope` is no grant at all — a reader that keeps the part that parsed differs by a prefix a node would install. `log/156-params-routes-granted` names the default | `log/157-bad-params-routes-unknown-value` (`"open"`) and `log/158-bad-params-routes-wrong-type` (`1`): the value set is closed and the type is text, each `decode` |
| §5.3 evaluation time | `proven/cases.json`: the admitted set at four values of `T` — no clock, before, **exactly at**, and after the one deadline the fixture carries. `state.json` is clock-independent by design, and `quorum-none/` covers expiry with no quorum time | the `at-the-deadline` case, where `expires == T` and the device is **out** |
| §7 receipt, codes and check order | `receipt.note` | **21 `receipt-bad/` cases** cover all eight closed codes: `note` (extra final newline), `log-signature` (untrusted signer), `receipt` (wrong header), `origin`, `leaf-hash` (invalid data and non-zero pad bits), `deadline` (`leading-zero.note`), `entry`, and `expired` (checked at the deadline). Body and signer negatives are re-signed; the framing case cannot be, and expiry is a time-dependent check over the otherwise valid receipt. The leading-zero case closes cold gate run 11, D4: §6 fixed a checkpoint's size spelling while §7 left this deadline implicit, so `ReceiptDeadlineLax` passed all 622 checks. **The order** is held pair by pair (cold gate run 13, D4): until then every case failed one step, so a reader that swapped two adjacent steps passed. Each `order-` case fails steps *n* and *n*+1 and is refused for *n* — `order-log-signature-before-receipt` (signed by another key, wrong header), `order-receipt-before-origin`, `order-origin-before-leaf-hash`, `order-leaf-hash-before-deadline`, `order-deadline-before-entry` and `order-entry-before-expired` (another entry's hash, checked at the deadline) |
| §§6–7 every decimal note line is at most 2⁶³−1 (D-076) | `served/checkpoint` and `receipt.note` | `checkpoints-bad/33-size-above-2-63` changes only the honest size line to 9223372036854775808, re-signed and cosigned by all three witnesses, served over the honest tiles: `checkpoint`. `receipt-bad/deadline-above-2-63.note` changes only the shipped receipt's deadline to the same integer, re-signed by the log: `deadline` |
| §9.1 every policy line ends in LF (D-076) | `policies/minimal` | `policies/bad-final-comment-no-lf` appends `# note` without LF to the minimal policy; adding its missing delimiter makes the policy parse. A missing final line feed is an error whatever the last line holds |
| §11.1 every carried proof precedes the root comparison (D-076) | the version-2 `fork/evidence.cbor` | `fork/bad-consistent-and-bad-split` carries agreeing roots and a real common split whose held proof has one corrupted hash. Every proof a file carries is checked before the file is read as a fork: `proof`, before `consistent`. Repairing the held split proof gives `consistent`; making the roots differ still gives `proof` |
| §7 canonical receipt leaf-hash base64 | `receipt.note` uses canonical base64 for its 32-byte leaf hash | `receipt-bad/leaf-hash-nonzero-pad-bits.note` is correctly re-signed and decodes to the same hash as the good receipt; only its unused pad bits differ, so it MUST refuse as `leaf-hash`. `receipt-bad/leaf-hash-unpadded.note` is the same hash with its `=` dropped, which a lenient decoder reads as the same 32 bytes (cold gate run 13, D18) |
| §7 the note framing | `served/checkpoint` | `checkpoints-bad/13-ascii-dash-signature` (an ASCII hyphen for §7's em dash), `14-unterminated-signature-block` (the final line does not end in a newline), `15-size-leading-zero` (a size line that is not canonical decimal) and `16-two-log-signatures` — two lines under the log's key, one forged. **This implementation accepted the last two** until run 8 asked for them |
| §9.1 a verifier key's id binds its name, key and algorithm | `trust.cbor` | `37-log-key-id-mismatch` and `39-witness-key-id-mismatch`: the right name, the right key, the right algorithm and one hex digit of the id changed — the log key in one, a witness key in the other. Each carries the damaged key in the **policy** too, so the correspondence rule agrees and only the id check can refuse it. `37` did not until cold gate run 11 (D3) found this row claiming otherwise, and a loader that treats a declared id as an opaque label passed all 622 checks. The witness case closes D9's pair as well: an id is a *claim*, and "the id binds the name" is a property only while somebody recomputes it |
| §7 and §9.1 canonical verifier-key data | `trust.cbor` carries canonical 33-byte log and witness keys | `trust-bad/44-log-key-base64-cr`: one carriage return inside the `log_key` base64 is ignored by a lax decoder, leaving the same key and ID. Its policy omits the optional `log` line, so removing only the carriage return makes the anchor valid; canonical key parsing is the rule that refuses it |
| §5.1 an empty log | `log-empty/`: the zero state, `rejected` empty | a reader that treats *no* genesis as a *missing* one reports `bad-genesis` and differs by a whole field |
| §9.1 and §11.1's byte caps | `trust-good/at-the-cap` and `fork/evidence-at-the-cap`, each **exactly** 65536 bytes — accepted, and the evidence proves its fork | `trust-bad/38-oversize`, padded with **valid** `log_urls` whose count nothing bounds, and `fork/bad-oversize`, padded through a `witness` URL the policy grammar does not bound. Each is correct in every other respect, so only its size can refuse it, and each is refused **on length** before anything it declares is allocated. `trust-bad/41-one-past-the-cap` and `fork/bad-one-past-the-cap` are **exactly one byte** past, sound in every other respect: a reader whose cap is one byte too lax accepts the trust file and proves the fork. Every cap was pinned only far from the boundary until cold gate run 12 (D16) — and a decoder's own default limit is the trap: a 65536-byte file decoded under `MAX_ENTRY_BYTES` (65535) is refused one byte too early |
| §8.1's bundle byte cap | `proofs/at-the-cap`, **exactly** 81919 bytes (`MAX_BUNDLE_BYTES`), MUST be accepted. Real cosignatures from an unlisted witness grow only the checkpoint; §10 ignores those lines | `proofs-bad/one-past-the-cap`, **exactly** 81920 bytes, is sound in every other respect and MUST be refused as `bundle` (§10.1 step 1). Cold gate run 13 (D15) found that this slack isolates the cap, just as the trust and evidence fields above do. The CBOR decoder must use the bundle's 81919-byte limit, not its default `MAX_ENTRY_BYTES` (65535); a limit of 81918 refuses the positive one byte early |
| §9.1 `anchor` is OPTIONAL | `trust-good/no-anchor` — **accepted**. Every other trust file in the suite carries one, so a reader that required it rejected nothing | — |
| §9.1 open URL readings | `trust-good/url-fields-are-opaque` — **accepted** with an invalid URI spelling in `log_urls`, an explicitly empty witness URL, and a different policy URL. The empty field survives canonical re-encoding | `trust-bad/33-log-url-empty-string`: `log_urls` still has a non-empty constraint |
| §9.1 the members the table shows and never constrained | `trust-good/witness-without-url`, `trust-good/anchor-unknown-type`, and `trust-good/url-fields-are-opaque`, all **accepted**: a reader that requires an optional member, refuses an unknown anchor type, validates URL syntax, or requires URL correspondence refuses a file this document permits | `31-witness-open-schema`, `32-witness-name-too-long` (renamed in the policy too, so correspondence holds), `33-log-url-empty-string`, `34-anchor-missing-member`, `35-anchor-unknown-mode`, `36-policy-log-key-mismatch`, and `43-anchor-unknown-member`. An unknown anchor **type** is ignorable — anchoring is advisory (D-009) — where an unknown **mode** or member is not |
| §9 trust file, fingerprint | `trust.cbor` | **53 rejected anchors** in `trust-bad/`. **`15`** and **`16`** parse cleanly as verifier keys and are refused by the algorithm rule — the trust file's, and the policy grammar's again once the key enters the policy, so neither isolates the trust-level rule alone (run 14, L4); **`17`** and **`18`** are a witness the policy never names and a policy naming a witness the file does not list, each otherwise perfectly valid. The trust file's witness-name rule is in the same place: `32-witness-name-too-long` and `54-witness-name-not-ascii` are refused by it and again by the policy grammar once correspondence puts the name in the policy, so neither isolates it (cold gate run 17, D11) |
| §9.1 four rules that another rule used to decide | `trust.cbor` | `26-name-too-long` and `27-name-empty` (both ends of the 1–64 byte bound; `14` covers absent), `28-empty-log-urls` (present and empty, which is a different path from absent), `07-no-witnesses` — whose policy is `quorum none` and names no witnesses either, so only the explicit witness minimum can refuse it — and `08-duplicate-witness-name`, which lists all three witnesses *and* a byte-identical second `pi`, so names and keys correspond exactly and only uniqueness is broken |
| §9.1's three MUSTs about the **log key and origin** | `trust.cbor` | `11-log-key-name-mismatch` (the note name is not `origin`), `13-origin-only` (`origin` is the derived value plus one character, so a prefix check accepts it), and `16-log-key-is-a-cosignature-key`. Each carries its damaged key in its **policy** as well, so the `log`-line correspondence rule agrees and only the named rule can refuse it |
| §9.1 D10's three isolated rules | `trust.cbor` | `13-origin-only` is the derived origin plus one character; `42-witness-key-mismatch` keeps every witness name aligned and changes only the key; `43-anchor-unknown-member` carries the three required members and one unknown. Each otherwise valid file is refused only by the named rule |
| §14 canonical JSON | `state.json` and the `.json` mirrors of entry vectors, the files §14 governs — the suite's `cases.json` manifests, `detect/staleness.json` and `proofs/right-edge.json` are pretty-printed and are not §14 canonical, so read them with any JSON parser; `enroll-astral-labels`, whose `escapes` label carries every row of §14.2's tables into `state.json` — including U+2028 and U+2029, which §14.2 writes verbatim and a default JSON library escapes (cold gate run 12, D19) — and `enroll-unicode-labels` | — |
| §10 a bad cosignature is refused, not merely uncounted | `served/checkpoint` | `checkpoints-bad/11-forged-cosignature-with-quorum`: three named witnesses, two verifying, so the quorum is met without the third and §10 refuses it anyway. `08` cannot tell the two readings apart, because one valid line falls short either way |
| §10 the rule is per **line**, not per witness | `served/checkpoint`, one line per witness | `checkpoints-bad/12-second-line-from-one-witness`: all three verify and `friend` carries a second, newer line that does not. A reader taking each witness's newest *verifying* line sees a full quorum. `11` cannot stand in — there the bad line's witness has no good line, so declining to count it still leaves a quorum of two |
| §11.1 the proof is empty at the held size | `fork/evidence-at-same-size`: held is `served/checkpoint`; the conflicting head has the same size and a different root, signed by the log key and cosigned by all three witnesses. `held_root` equals held's signed root and the proof is empty. It MUST prove a fork; every previous same-size file was negative (cold gate run 13, D14) | `fork/bad-proof-at-same-size`: a consistency proof where the two signatures say it alone |
| §11.1 `held_root` matches `held` at the held size | — | `fork/bad-held-root-at-same-size`: both checkpoints verify, `size` equals `held`'s size and the proof is empty, but `held_root` differs from the signed root; the reader MUST refuse it as `proof` |
| §8.1 and §11.1 are closed maps, versioned, and bounded | `proofs/`, `fork/evidence.cbor` | `proofs-bad/open-schema` and `wrong-version`; `proofs-bad/device-not-in-entry`, where the proof, the entry and the checkpoint are all honest and only the **label** beside them is another device's — an inclusion proof binds the entry to the log and says nothing about a label. For evidence: `fork/bad-open-schema`, `bad-wrong-version` and `bad-size-above-held`, because an accuser can only speak for sizes its own branch reaches. **This implementation left the evidence map open and the device unbound** until run 8 asked |
| §11.1 the carried `policy` decides nothing | `fork/policy-not-the-readers.cbor`: sound evidence whose `policy` requires a witness that cosigned nothing — it MUST still prove the fork, because the reader verifies under its own | `fork/bad-policy-says-quorum-none`: two checkpoints no quorum cosigned, and a carried policy saying none is needed. A reader that trusts the field concludes a fork any stranger can write, and §11 rule 4 makes it permanent. `fork/bad-policy-unparseable` is the format half |
| §6 tile and entry-bundle path groups | `served-large/cases.json`'s `paths`: indices 0, 1, 255, 256, 999, 1000, 1001, 255999, 256000 and 1234567, each with level-0 hash paths at widths 256 and 44, a level-1 hash path at width 1, and a full entry-bundle path | —; the table reaches the non-final `x` prefixes without requiring a 256,000-entry served log (cold gate run 13, D18) |
| §9.1 trust origin case is exact | `trust.cbor` | `trust-bad/45-origin-case-changed`: one letter of the real `origin` changes case, and `log_key` is renamed to agree and carried into the policy, isolated the way `13-origin-only` is. The name and correspondence rules both agree, so only the exact derivation of `origin` from `net` refuses it; a reader comparing the derived origin case-insensitively accepts it. `trust-bad/46-log-key-name-case-changed` is the other half: `origin` honest, the log key's note name differing from it only in one letter's case, the policy agreeing, so only "its note name MUST equal `origin`" refuses it (cold gate run 13, D18) |
| §6 tiles and bundles | `served/`, read back to reproduce `state.json`; `served-large/`, a 300-entry log with a full and partial level-0 tile plus a level-1 tile; a forged head is `checkpoints-bad/04-forged-log-signature` and a fourth body line is `checkpoints-bad/09-extension-line` | `served-bad/`: a tampered entry bundle, a missing bundle, a tampered hash tile, a missing hash tile and a missing checkpoint (both `unserved`, step 1's code for a file a later step needs: a reader that skips a tile it cannot fetch, or calls an absent checkpoint malformed, passed until cold gate run 13, D18), `consistent-tampered-log` (entries and level-0 tile changed **together**), and `overfull-entry-bundle`, which decodes but holds one more entry than the final path and checkpoint imply (`entries`). The consistent case alone reaches the rebuild-and-compare rule; the other tamper cases can be refused by the tile rule, but §10.1 checks the head first (cold gate run 10, D11). The level-0 tile is partial index 1 on the 300-entry fixture, exercising the final-bundle path past 256 entries |
| §6 the anchor digest | `anchors/cases.json` names the bytes and gives the digest, and `checkpoint-<size>.ots` chains from it. Anchoring is **advisory** (D-009), so a reader computing the neighbouring byte range — the three-line body, which is also §7's signed text — never matches a stamp and never reports one, which is why the range is stated in hex rather than in a word both bullets use | no negative: a proof over the wrong digest simply fails to chain, and the failure is indistinguishable from an anchor for another tree. Run 11's `OTSDigestSignedText` variant is caught by the digest comparison alone |
| §6 canonical checkpoint-root base64 | `served/checkpoint` carries the canonical root | `checkpoints-bad/27-root-nonzero-pad-bits`: the root's final base64 character is changed only in unused pad bits, so it decodes to the same root and the log and witnesses still sign it; only canonical root encoding refuses it. `checkpoints-bad/29-root-unpadded` drops the root's `=`, re-signed and re-cosigned: a lenient decoder reads the same 32 bytes, and §6 requires the padded form (cold gate run 13, D18) |
| §7 note framing | `served/checkpoint` and `receipt.note`, both read with these rules | `checkpoints-bad/13-ascii-dash-signature`, `14-unterminated-signature-block`, `18-signature-name-with-space`, `19-signature-unpadded-base64`, `23-extra-final-newline`, and `32-signature-name-not-utf8` (a stranger's line, otherwise ignored, whose name is not UTF-8); `01-unsigned` pins the requirement for at least one signature line. The generated notes isolate the stated framing rules |
| §7 canonical signature payload base64 | `served/checkpoint` has a canonical log signature and witness cosignatures | `checkpoints-bad/25-signature-nonzero-pad-bits` and `checkpoints-bad/26-cosignature-nonzero-pad-bits`: each changes only unused pad bits, preserving the decoded valid signature bytes, and both MUST be refused as malformed note framing |
| §10.1 a matched log key with the other valid payload length | `served/checkpoint` | `checkpoints-bad/24-log-key-other-algorithm-length` appends a 76-byte line whose name and key ID match the log's `0x01` key. It is frameable as a note but fails the matched key's signature check, so its code is `log-signature`; the failure remains observable beside the checkpoint's good log signature. `20-signature-payload-too-long` is the log's own line one byte long: framed since D-074 (c), refused by the matched key, `log-signature` |
| §7 a line no trusted key matches is ignored whatever its length (D-074 c) | `served-unknown-algorithm/` — the served head plus one 70-byte line, a key id under an algorithm byte §7 does not use and 66 bytes, from a key nobody here holds. It MUST be **accepted**: the accepted stranger cosignature lines in the suite are 76 bytes, so a reader that framed only 68 and 76 passed them all and refused a shared log the day one witness used a third algorithm | `checkpoints-bad/32-signature-name-not-utf8`: a stranger's line the profile would ignore, refused as `note` because its name is not UTF-8 |
| §7 the key-name grammar is a verifier key's (D-074 f) | `served-stranger-name/` — the served head plus one cosignature line from a stranger whose name is not ASCII, a name §7's grammar refuses in a verifier key. The line is only matched against verifier keys and matches none, so it MUST be **accepted**: a reader that applied the grammar to every line it read would refuse heads every other reader accepts | `trust-bad/49-witness-key-id-uppercase` and `50-witness-key-name-not-ascii` — pi's key broken one way each, in the witness array and the policy alike. U+001C, the character the two implementations once disagreed on, has no trust-file vector: §9.1 forbids control bytes anywhere in policy text, and correspondence puts the key there, so such a file is refused by that rule too. The key-name tests in both implementations pin it at the verifier-key parser |
| §10.1 a matched witness key with the other valid payload length | `served/checkpoint` | `checkpoints-bad/28-witness-key-other-algorithm-length` appends a 68-byte line whose name and cosignature key ID match the listed witness `pi`. A reader that skips it as "not a cosignature" still counts three good lines and accepts; its code is `cosignature`, the witness side of `24` (SEC-027) |
| §8.1 a bundle's checkpoint is checked per §10 | `proofs/`, whose checkpoints carry the quorum | `proofs-bad/no-quorum` (the log's signature and nobody else's) and `proofs-bad/wrong-origin` (this network's key over another network's origin line) |
| §8.1 condition 3, the key a node installs | `proofs/cases.json`'s `installs`: for every device, the `wg_pk` replay gives. `nas` rotated after it enrolled, so `proofs/nas.bundle` proves an entry naming a key `nas` no longer uses and `installs` names the other one. A reader that requires the bundle's key to match installs nothing for `nas` (cold gate run 11, D14) | — |
| §8 proof bundles | `proofs/`, one per active device | `proofs-bad/`, **20 proof refusals**: `one-past-the-cap` (otherwise sound, refused on length), a wrong entry, a foreign checkpoint, a tampered proof, a checkpoint signed by a key the anchor does not name, one with no witness quorum and one whose checkpoint names another origin — each differing from a valid bundle in exactly one thing, except `no-quorum-tampered-proof` and `proofs-bad/wrong-version-and-untrusted-checkpoint`, which differ in two so that §10.1's order decides. `rotate-entry-other-device` and `revoke-entry-other-device` prove a real `rotate` and `revoke` under another device's label: §8.1 binds those through the body's `device_id`, and until cold gate run 12 (D20) every bundle proved an `enroll`, so a reader that bound only enrolments passed |
| §8.1 RFC 6962 inclusion proof's right edge | `proofs/right-edge.json`: the last leaf, index 126, of a 127-entry tree | —; this positive proof distinguishes the RFC right-edge rule from a parity-only inclusion reader (cold gate run 12, D13b) |
| §10 the signature decides before the origin | — | `proofs-bad/foreign-checkpoint` MUST be refused as `log-signature` and `proofs-bad/wrong-origin` as `origin`; `checkpoints-bad/03-wrong-origin`, signed under another origin's name, is `log-signature` too. A reader that checks the origin first answers `origin` for the first and the last |
| §10.1 and §11.1 the order of the checks | — | every negative in `checkpoints-bad/`, `served-bad/`, `proofs-bad/`, `fork/` and `detect/` names its code, and these fail two steps so the order decides — the codes make an ordering observable, and a file with both faults is what observes it: `checkpoints-bad/01-unsigned` is `note`, not `log-signature` (framing before signature); `checkpoints-bad/03-wrong-origin` and `proofs-bad/foreign-checkpoint` are `log-signature`, not `origin` (the signature decides before the origin); `checkpoints-bad/30-noncanonical-size-under-untrusted-signer` is `log-signature`, not `checkpoint` (the signature before the body — every other body fault in the directory is signed by the log, cold gate run 13, D4); `served-bad/tampered-entry-bundle` is `head`, not `tiles` (head before tiles); `detect/tampered-bundle-under-a-stored-head` is `head`, not `fork` (head before the branch comparison — a reader that compares first accuses an honest log over one corrupt byte, permanently); `proofs-bad/no-quorum-tampered-proof` is `quorum`, not `inclusion`, and `proofs-bad/wrong-entry` is `inclusion`, not `binding` (a bundle's checkpoint, then its proof, then its binding); `fork/bad-oversize-and-not-cbor` is `oversize`, not `cbor`; `fork/bad-version-and-unknown-key` is `version`, not `schema`; `fork/bad-short-held-root-and-size-above-held` is `schema`, not `size`; `fork/bad-policy-unparseable-and-foreign-held` is `policy`, not `held` (the carried policy does not parse and held is a foreign head; closed-code step 4 precedes step 5, cold gate run 13, D4); and `fork/bad-other-origin` is `held`, not `conflicting` |
| §10 verifier loop, steps 1–4 | `served/` verified end to end, **signature first** | `checkpoints-bad/01-unsigned`, `02-wrong-log-key`, `03-wrong-origin` and **`04-forged-log-signature`** — the last one being a signature of the right shape under the right key id that does not verify. Without it a verifier that never checks the log signature reproduces the whole suite |
| §10 the origin comparison is **equality** | `served/checkpoint` | `checkpoints-bad/21-origin-with-a-suffix` (this network's origin plus one base32 character) and `22-origin-case-changed` (the same origin, one letter in the other case), each signed and cosigned exactly as correctly as the real head, plus `trust-bad/40-log-key-name-suffix` for §9.1's "the log key's note name MUST equal `origin`". Every earlier origin negative used an **unrelated** origin, so a prefix match and a case-folded match both passed all 622 checks. §10 argues the cosignature match must be name **and** key id because a name-only match hands anyone a veto; this is that argument from the other side, where a loose match hands an attacker an acceptance (cold gate run 11, D7) |
| §10.1 steps 6 and 7, the witnesses' lines and their quorum | `served/checkpoint`, cosigned by all three witnesses | `checkpoints-bad/05-one-cosignature-short`, `06-no-cosignatures`, `07-unnamed-witness-only` and **`08-forged-cosignature`**, which carries two lines naming witnesses the policy lists, one of which does not verify: the quorum is met by counting and refused by checking. `quorum-none/uncosigned.checkpoint` supplies that second anchor and accepts without cosignatures |
| §10.1 step 6, **which** lines count as a listed witness's | `served-extra-witness/` (an unlisted **name**) and `served-name-collision/` (a listed name under an unlisted **key id**) — both MUST be accepted, and the second is the only file that separates matching on the name alone from matching on name and key id. Run 10's `V236_CosigNoKeyIDMatch` passed 236/236 without it | the negatives are `checkpoints-bad/08-forged-cosignature`, `11-forged-cosignature-with-quorum` and `12-second-line-from-one-witness`, where the line's name *and* id are the policy's and the signature is not |
| §4.0 reserved label hints | `requests/req-reserved-hints` accepts a correctly signed request with `ip = "not-a-cidr"` and `endpoint = "not-an-endpoint"`; accepted log entry `enroll-unicode-labels` carries both values through replay into `state.json` | —; request checking and replay do not validate advisory hint syntax |
| §16 enrollment requests | `requests/`, **9 request cases** including a 64-byte `device_id`, non-ASCII labels, the 203-byte padding control, the 256-byte label boundary, malformed reserved hints, an uppercase text form and `req-labels-at-the-cap` (32 labels) | `requests-bad/`, **30 request refusals** across all four layers, including §3.1's `small-order-device-pk`, `torsion-R-signature` and `S-plus-L-signature`, and **`forged-signature`** (structurally perfect, signed by another key), `oversize-label-key` (§4.0's map-key cap), `empty-label-key` (its floor, re-signed so only the key bound refuses it) and `empty-labels` (a present empty map, signed over it, so only §16.1's at-least-one-pair rule refuses it — D-072 (b)) |
| §11.1 fork evidence | `fork/evidence.cbor` and `fork/conflicting.checkpoint`: a second branch of this same network, diverging at entry 40, signed by the same log key and cosigned by the same witnesses. Checking it needs only `trust.cbor` | one per reader step: `fork/bad-other-origin` and `fork/bad-unverifiable-conflicting` (step 1, each half), `fork/bad-size-mismatch` (step 2), `fork/bad-forged-proof` (step 3 — both checkpoints verify and the sizes agree, so nothing but the proof can refuse it), and `fork/bad-consistent` (step 5: a log and its own earlier self) |
| §16.1's `expires > ts`, at the entry layer | every `enroll` | `bad-enroll-request-expires-at-ts`: an entry whose embedded request breaks §16.1. The only other vector for the rule is a *request*, and an `enroll` decodes its request under §16.1 too |
| §4.0's map-key cap in **bytes** | `entries-hostile/at-the-key-limit`: 23 bytes and 12 characters | `past-the-key-limit` is 24 bytes and 13 characters. Both were ASCII until run 9, so "23 bytes" and "23 characters" gave the same answer everywhere |
| §10.1 `genesis`, and that it comes after the comparison (D-074 (g), as amended 2026-10-10) | — | `served-genesis/another-genesis` and `served-genesis/empty`, both `genesis` to a reader holding no checkpoint; and the same two logs in `detect/`, served to a reader holding `earlier.checkpoint`: `another-genesis-under-a-held-head` is `fork` — the log signed two histories, and `genesis` must not hide that — and `empty-under-a-held-head` is `rollback`. The reference verifies no served log, so these are the Go verifier's and the cold verifier's; there is nothing in the reference to refuse them |
| §10 a reader that does not hold `at` | — | `detect/shorter-with-no-held-branch`: the same served branch as the fork case, read by a node holding the stored head and **not** the entries. It refuses and MUST NOT accuse. Inside §10's own loop the node always holds `at`; this clause is for a monitor handed a checkpoint, or a node restarted from its stored one |
| §10 a line the reader does not know | `served-extra-witness/`: the honest head plus one more line, from a witness the policy never names and the trust file does not list. It verifies under its own key, counts for nothing, and the head MUST be **accepted** | `07-unnamed-witness-only` cannot pin this: it is refused for want of a quorum either way, so it separates nothing |
| §8.1 `S_hard` unconfigured | `detect/staleness.json`'s `unconfigured-hard-stays-degraded` and `-still-fresh`, which carry `hard: 0` | every other case carries 3600, so a reader that read 0 as a limit of zero passed while dropping every peer — the outcome the asymmetry exists to prevent |
| §8.1 the freshness table is read in order | `detect/staleness.json`'s `hard-below-staleness`: `hard` 700, `staleness` 900, `elapsed` 800, where `fresh` and `hard_stale` both hold and only the order decides — and D-060 says `hard_stale`, so a node's own limit is one the roots cannot raise. `at-the-hard-boundary` (`elapsed` 700) is the same node sitting exactly on its limit, which is `fresh` because the rule is `> S_hard` like every other boundary here | every earlier case had `hard` above `staleness`, where the two rows cannot overlap, so a reader testing them in the other order passed the whole suite (cold gate run 11, D1). A parallel session answered D1 the other way and was reconciled to D-060; §8.1's table is now listed in evaluation order, which it was not before, and a guard checks the order rather than the words |
| §9.1 what a quorum **means** | the `evaluate` tables in `policies/cases.json`: a set of cosigner names and whether they satisfy the policy. `nested-group` is the one that separates a nested group from a flattened one — `outer` is `all` of **one** member, and that member is `any` of two, so `pi` alone satisfies it and a flattening reader needs both | `bad-duplicate-member` (met by one witness), `bad-k-zero` (met by **nobody**, so an uncosigned head passes) and `bad-k-leading-zero`. Parsing alone could not reach any of the three |
| §9.1 directive order and sequential names (D-074 e) | `policies/directive-after-quorum` puts an unused witness and group after `quorum`; every `evaluate` verdict is the same with those lines removed | `policies/bad-redefinition-after-use` redefines a group the quorum already used; removing that final line leaves a valid policy. `policies/bad-forward-reference` and `policies/bad-quorum-forward-reference` name only what a later line defines |
| §9.1 the restated tlog-policy grammar | Positives: policies/minimal, quorum-none-empty, reserved-words-as-names, threshold-at-size, nested-group, no-log-line, two-log-lines and high-bit-content cases. Negatives: missing final LF, CRLF and other ASCII controls, quorum forward reference, none definitions, shared-name collision, invalid vkeys or IDs, role-mismatched algorithms, duplicate public keys (including aliases and log/witness reuse), k above n, and the existing whitespace/comment/arity rules. Run 12 left all of these grammar readings open or unvectored. `bad-none-group-member` records the refusal. `bad-empty-group` has three fields and is refused by the **field count**, before the group-members rule can apply |
| §16.2 bech32m | the text form of every request, and `requests/req-minimal-upper` — the same request in the all-uppercase form §16.2 says a reader MUST accept, which is the one *positive* obligation the section carries and the form a QR code produces | `wrong-hrp`, `plain-bech32` (the same bytes under bech32's constant), `mixed-case`, `corrupt-character`. BIP-350's own vectors are in both implementations' unit tests |

**What is not vectored.** A suite that looks complete is worse than one that
admits its holes, so:

- §3.1's NORN-ED25519-v1 is vectored at every admission point item 2 names
  and executed by both implementations (the CCTV table and Norn's own
  edges, in the rows above), including a `rotate`'s incoming `device_pk` and a
  `policy` entry's witness key (D-075). A policy's optional `log` line carries
  the same point check, and `log-order/15-policy-log-identity` holds it (cold
  gate run 15, D1).
- Source-neutral checkpoint acquisition cannot be demonstrated by static vectors alone:
  the same `served/` and `detect/` bytes may arrive from a log
  or a proven peer. They pin §10's verification, fork and rollback outcomes;
  they do not encode who transported the bytes, polling cadence and endpoint access.
  The Go agent and gossip tests exercise those node behaviours, including a
  healthy direct log that serves a branch different from a proven peer's.
- §13's interface reconciliation and `proven.json` publication cannot be
  demonstrated by the static protocol vectors, §13.1's intersection of a
  peer's allowed-ips with its grant included. `detect/staleness.json` pins
  the §8.1 state labels and boundaries, while Go agent, reconciler and proven
  tests exercise owner, watchdog and observe behavior, failure semantics,
  and the published JSON shape.
- §16.3's key handling cannot be demonstrated by the static protocol vectors:
  an agent is a live process reached through a socket, a key file's permissions
  are local filesystem state, and confirmation prompts and submission polling
  are interactive. The Go `sshagent`, `keyfile`, `sign` and `submit` tests
  exercise them — against a real `ssh-agent` and real `ssh-keygen` where the
  tools exist — including an agent that answers with another key's signature
  and a root-role `--yes` a signer must refuse.
- The separate rule that the predefined name none cannot be a group member
  cannot be distinguished from the earlier-definition rule: none cannot be
  defined. The bad-none-group-member vector checks the required refusal outcome,
  but a reader that reports the name as undefined reaches the same observable
  result.
- A carriage return inside a **policy** verifier key cannot isolate key-data
  canonicality: §9.1's control-byte rule refuses it before the key parser.
  `trust-bad/44-log-key-base64-cr` exercises the shared key parser through the
  trust file's `log_key`. A verifier key encodes 33 bytes, so it has no unused
  base64 pad bits to vector.

- **OpenTimestamps attestations.** §6 and §12 state the anchor's digest
  contract — exactly which bytes are hashed — and `anchors/cases.json` pins it.
  The proof tree, its calendar reply and any Bitcoin attestation are
  `python-opentimestamps`'s format, which this document does not describe, so
  no reader is asked to validate them; anchoring is advisory (D-009).
- **§4.3's "a key contributes at most once".** `sigs` is sorted by `kid` with
  no repeats (§4.1), and `kid` is `SHA-256(pk)[0:8]` — a function of the key —
  so one key cannot appear twice in one entry and the de-duplication in
  signature counting never fires. Confirmed by deleting it: every check stays
  green. It is written down because a reader who counts signatures without it
  is relying on a rule two sections away, and that is worth saying once —
  and that rule **is** vectored: `log/134-bad-repeated-kid` carries one root's
  signature element three times and is `decode`. The two rules hide each
  other: a reader lax about both lets one root meet a three-root quorum, and
  until that entry shipped, nothing in the suite checked either (cold gate
  run 12, D1).
- **§5.3's "must not count it even **in the moment before that refusal**".**
  §10 refuses the whole checkpoint over an unverified line from a named
  witness, unconditionally and before `T` is used, so no conforming reader has
  such a moment. This implementation guards the clause at its API boundary —
  a refused checkpoint yields no cosignatures at all — but that is a property
  of one function's return value, not of any file: a second implementation
  that returned the timestamp and then ignored the error is indistinguishable
  from one that did not, on every artifact here.
- **The order of entry 0's steps (§5.1).** §5.2's ordering is observable
  because the first matching step decides the reason code; entry 0 has one
  reason code, `bad-genesis`, so its ordering decides nothing a file can see.
  Confirmed by rearranging four of the steps: every check stays green. §5.1
  now says so where the steps are listed, rather than leaving "in order" to
  imply the guarantee §5.2 gives.
- **§3.1's canonical clauses.** "`y` below `p`" and "the sign bit is 0 when
  `x` is 0" are implied by `[L]P = O ∧ P ≠ O` — checked by computation over
  every `y` in [p, 2²⁵⁵) and both `x = 0` points — so a reader that skips them
  and keeps the order clause is indistinguishable on every artifact,
  `genesis/24-root-noncanonical` and `trust-bad/47-witness-noncanonical-point`
  included, which pin item 1 as a whole (run 14, L3).
- **A **blank line inside a note's text**, as distinct from the one that ends
  it.** §7 says the first blank line ends the text because text lines are
  non-empty; a reader that took the *last* one would sign a different string.
  Every note text in Norn is a checkpoint body (three lines, §6) or a receipt
  (four, §7), so a text carrying a blank line has the wrong line count under
  **both** readings and is refused either way. A blank line placed **between two
  signature lines** is another matter: the readings refuse it with different
  codes, `note` and `log-signature` (§7), and
  `checkpoints-bad/45-blank-line-between-signatures` holds it as `note`
  (cold gate run 15, L1).
- **§10's "the root the SERVED branch has at `at` … recomputed from the
  entries, **never from a supplied proof**".** No shipped file supplies one: a
  `detect/` pair serves both branches with their own tiles, so a reader takes
  the root from the entries because there is nothing else to take it from. The
  clause is a real rule about a real attack — a peer that offers a proof of a
  root its entries do not produce — and nothing here distinguishes a reader
  that honours such a proof from one that ignores it. Reaching it needs a
  served log that carries a proof, which `tlog-tiles` does not serve.
- **§16.1's 32-byte `device_pk`.** At the request layer
  `requests-bad/short-device-pk` is refused by that rule, and a verifier that
  skipped it would fail anyway: a 31-byte key verifies nothing. At the entry
  layer `log/81-bad-pk-length` embeds such a request and is `decode`, and so it
  is for a reader without the length rule: §3.1's point admission refuses a
  31-byte key at the same step (cold gate run 17, D11, correcting run 16's L6).
  The rule is refused, and never isolated.
- **§5's `state.net` coming from the anchor rather than from the genesis
  entry.** Unobservable: entry 0 aborts whenever the two differ, so no file can
  tell the two readings apart. Recorded here because a reader will look.
- **`entry_hash` being over the bytes *as received* rather than a
  re-canonicalised form**, the byte key every entry records (D-078), and the
  only key of one that does not decode. §5.1 step 1's *ordering* is vectored — a copy
  of an entry that never decoded is `dup-entry` — but the received-versus-recanonical
  half cannot be: the only entry whose raw bytes differ from its canonical form
  violates §4.0, and is `decode` at step 2 before any hash of a canonical form
  could be taken. `60-bad-trailing-byte` is caught by the whole-input rule, not
  by the hash.
- **`MAX_ENTRY_BYTES` applied to an embedded request, as distinct from the
  entry.** §4.0 requires both, and a request travels *inside* an entry — so a
  request over the cap implies an entry over the cap, and the entry rule
  refuses it first. The two can never disagree, and no file can show the
  request rule doing the work.
- **§10's requirement that a witness key be a cosignature key, checked at
  *verification* rather than at the trust file.** Unreachable: §9.1 refuses a
  trust file whose witness publishes a note key, so no policy carrying one
  ever reaches the cosignature check. It is defence in depth, and no vector
  can tell an implementation that omits it from one that does not.
- **§5.2's `dup-wg` for `enroll` meaning "active for **any** device" rather
  than "for another device".** The two readings differ only when the key is
  active for the enrolling `device_id` itself — which requires that id to be
  `active`, which makes `dup-id` fire one step earlier. No entry can reach the
  difference, so the rule is refused-but-not-pinned by construction. Confirmed
  by mutation: the narrower reading reproduces the whole manifest.
- **Rules stated plainly that no vector holds yet (cold gate run 16, L8).**
  Each is a sentence above that a careful reader gets right, and each has an
  input a network can see on which a reader who got it wrong would differ;
  Go gives this document's answer on every one, and the reference on every one
  in the layers it implements. Every rule run 16 listed here is now vectored;
  the last two, a bundle around a `rotate` and one around a `revoke` (§8.1), by
  `proofs/nas-rotate.bundle` and `proofs/laptop-revoke.bundle`.
  Beyond the static suite: §11 rule 3's frozen set, §15's `CLOCK_SKEW` alarm and
  §13.2's restart rules are node behaviour, held by the Go tests.
- **Rules stated plainly that no vector holds yet (cold gate run 17, D11).**
  Every rule run 17 listed here is now vectored, each beside its repair or its
  sound twin: the uppercase `kid` surplus, the `enroll` signed by roots alone and
  the request with `expires` 0 in `log-rules/` (cases 20 to 25); the receipt with
  no signature line, `receipt-bad/no-signature-line.note`; the two grant forms in
  `proven/grant-labels.json`; evidence and a bundle under a replayed policy in
  `replayed-policy/`; the bundles around a small-order request key and around
  `log/81-bad-pk-length` under its own id in `proofs-bad/`; the empty map key,
  `fork/bad-empty-map-key.cbor`; `quorum none` in `quorum-none/`; and the genesis
  that does not apply in `genesis-unapplied/`.
- **D-080's rules, until row 6.5l-xv-i ships their vectors.** Go, the
  reference and the fourth cold build already give this document's answer on
  each: blanks after a policy line's last field add no field (§9.1, a
  `policies/` pair and a root-signed `policy` entry to come); a trust file's
  policy longer than 4096 bytes is valid (§9.1, a `trust-good/` file to come).
Everything else named in the table above ships, and the build fails if a path
cited here is missing or a directory here is not named.

Two caveats a second implementer should know, because a vector proves a format
and not a fact about the world:

- `served/checkpoint`'s cosignatures come from keys the generator holds. They
  prove the **format** is right, and the encoding is checked against
  `transparency-dev/formats` rather than against itself. That an **unmodified
  witness** will produce one is proven separately, by `internal/interop`
  driving the real `transparency-dev/witness` end to end.
- `fork/evidence.cbor` is a fork this project constructed. It proves the
  **artifact** is checkable by anybody holding `norn.trust`; it is not evidence
  that any log has ever equivocated.

## 13. Node enforcement and proven-set interface

The verifier hands the enforcer an in-memory set derived from the accepted
checkpoint and replay (§§8.1 and 10). The only keys that may enter the desired
WireGuard peer table are the current `wg_pk` values of devices that replay
marks active and that have not expired at the checkpoint's witness time (§5.3).
With no quorum time, expiry cannot be judged and active claims retain their
last verified status (§5.3).
An endpoint provider may supply `allowed_ips`, endpoints and keepalives for
those devices, but MUST NOT supply or authorize keys. Hints for unproven
devices are discarded and reported. Norn enforces by reading and changing the
interface's cryptokey routing table; it does not change WireGuard's packet or
handshake protocol, interface private key, listen port or fwmark.

### 13.1 Reconciliation modes

The modes are `observe`, `owner` and `watchdog`; an unknown mode MUST be
refused. The default is `observe`, which reads the peer table and NEVER writes
it. On every cycle it reports `UNPROVEN_PEER` for a table key outside the
desired set and `MISSING_PEER` for a proven key absent from the table. These
reports include the observed key and reachability details where available.

In `owner` mode Norn is the sole intended peer-table writer. It compares the
actual and desired keys and `allowed_ips` on every `T_poll` cycle (200 ms by
default) and after accepting a new proven set. If either differs, it replaces
the entire table with the desired peers (`ReplacePeers`), reports unproven
keys, and preserves an interface-learned endpoint where the provider supplied
none. If only an endpoint or keepalive differs, it refreshes existing peers
with `UpdateOnly`; roaming alone does not justify rewriting the table or
adding a key. A proven key missing from the table is installed by owner mode
and reported as `MISSING_PEER`.

In `watchdog` mode another program owns availability. On every `T_poll` cycle,
Norn removes each key outside the desired set, reports `UNPROVEN_PEER` on
observation, and reports `EVICTED_PEER` after a successful eviction. It reports a
missing proven key as `MISSING_PEER` but MUST NOT install it. A rogue key may
complete a handshake or send packets during the polling and reconfiguration
window; watchdog mode does not make that window zero. If the same key is
successfully evicted three times within 60 seconds by default, the node
reports `CONTROL_PLANE_FIGHT`. The default response is to keep evicting and
alarming. `quarantine` is an explicit alternative that takes the interface
out of service until operator intervention; a node configured for it MUST
refuse to start without a configured way to perform that action.

All three modes use the same verified identity and freshness rules. The
reconciler MUST be idempotent and MUST NOT widen the desired keys on a failed
verification. A backend used for `observe` needs only peer-table reads;
`owner` and `watchdog` additionally need their respective write operations.

**Routes (D-073).** Under `params.routes = "granted"`, the default, the
desired allowed-ips of a peer are the endpoint provider's, each masked, kept
only where it lies within a prefix of the peer's grant (§4.0); a provider's
prefix outside the grant is withheld and reported as a provider claim, so a
provider MAY narrow a grant and MUST NOT widen it. A peer with no grant is
installed with its key and no allowed-ips, and the node reports that once per
device. WireGuard's cryptokey routing makes a peer's allowed-ips its authority
to source those addresses, so the log is the authority on the **bound** a peer
may claim; it does not route. Under `"advisory"` the provider's prefixes are
installed as given. The endpoint and keepalive are the provider's in both.

### 13.2 Failure semantics

A missing or invalid trust file prevents startup in every mode. An effective
policy of `quorum none` — the trust file's, or one the roots published in the
log (§9.4) that the node restored — prevents startup in `owner` and `watchdog`
unless the node is configured with `allow_no_quorum`; `observe` always starts.
Under such a policy nobody corroborates a checkpoint and there is no clock
(§5.3), so a node that writes its interface on it does so on the log
operator's word alone, and the setting is how an operator says that is what
they meant (D-072 (e)). A policy lowered to `quorum none` while the node runs
does not stop it: it keeps enforcing, and an `owner` or `watchdog` node not so
configured repeats an alarm on the degraded cadence until it restarts, when the
rule above applies. If no checkpoint has verified since startup, a failed
verification leaves the interface untouched. After one has verified, an
unavailable or invalid log
leaves the last verified set in force and raises an alarm; ordinary
reconciliation still evicts intruders in `owner` and `watchdog`. A log that
has not advanced leaves the set in force; its age may trigger a freshness
alarm, and §15's independent clock-skew alarm may also apply.
The `degraded` state (§8.1) retains that set and repeats its alarm every five
minutes by default. With no local `S_hard`, it does not disconnect the node.

When a configured `S_hard` is exceeded, `hard_stale` makes the enforcer's
desired set empty: `owner` replaces the table with no peers, `watchdog`
evicts every peer, and `observe` reports the state without writing. A proven
fork (§11) freezes the node's authorization at the common prefix of the two
branches (§11): it adopts no further checkpoint under that anchor, keeps
enforcing only the devices proven both there and at its own held head — the
set shrinks, never grows, and is empty when no common prefix can be
established — and repeats the fork alarm until a new trust file.
If `nornd` stops, the WireGuard table keeps its last contents; a watchdog that
is not running cannot bound an external writer's rogue-key window.

A node's stored checkpoint (§10), the log keys and policy it learned from the
state it verified (§9.4), and the evidence of a fork it proved (§11) persist
across a restart and a reboot (D-069). At startup the persisted checkpoint is
verified again under the trust file, and under what its own entries publish
when a key or policy was rotated in the log; one that does not verify is
reported and ignored. Every candidate checkpoint is compared against the stored
checkpoint before anything is adopted, so an older head of the node's own log
is refused after a restart as it was before one. The restored checkpoint is
held, not enforced: as above, a node on which no checkpoint has verified since
startup leaves the interface untouched, and a restored checkpoint is not
enforced until a checkpoint verifies in the new process.

A node's witness clock persists as well (D-071): its estimate of witness-time
now is written to the state directory as it advances, and at startup the clock
is seeded from that estimate as an instant observed at monotonic zero, so a
checkpoint is never judged fresher after a restart than it was before one. A
node holding no stored checkpoint — a first start, or state that was lost —
treats its first verified checkpoint as uncorroborated: it asks its proven
peers in the same cycle, before enforcing, and in every cycle after until one
answers; a peer's checkpoint that verifies with the first as the stored
checkpoint corroborates it. With no peer answering the checkpoint is enforced
and the node reports it. A fork proven against a checkpoint the node enforced
uncorroborated makes the enforcer's desired set empty, as `hard_stale` does,
and freezes the node.

### 13.3 Published proven set

The in-memory set controls the enforcer. A node also publishes its last
verified view to `/run/norn/proven.json` for monitors and operators. The JSON
object has these members:

| member | value |
|---|---|
| `version` | integer `1` |
| `checkpoint` | object with `origin` (text), `size` (integer), `root` (lowercase hex), and `cosigned_at` (witness Unix seconds or `null`) |
| `freshness` | `fresh`, `degraded`, `hard_stale` or `unknown` (§8.1) |
| `age_seconds` | monotonic witness-time age in whole seconds, or `null` when no quorum time exists |
| `devices` | array of the last verified active, unexpired device claims; empty is `[]` |
| `written_at_local_clock` | local wall-clock Unix seconds, for detecting a stopped publisher only |

Each `devices` element has `device_id` (text), `wg_pk` (base64 WireGuard
public key), `labels` (text-to-text object), `grant` (array of CIDR text, the
§4.0 grant, masked and sorted; `[]` when the device has none), `expires` (Unix
seconds, or zero), `proof` (path to a §8.1 bundle), and `since_index`
(integer). The current key
comes from replay, not the bundle's historical entry. The node writes each
referenced proof bundle before atomically replacing `proven.json`, so a
published path resolves. A failed verification MUST NOT republish a new view.
`written_at_local_clock` MUST NOT be used to decide freshness, expiry or
membership. In `hard_stale`, `devices` still records the last verified claims
for inspection; §13.2 makes the enforcer's desired set empty. Consumers MUST
read `freshness` rather than infer enforcement from the array alone.

## 14. Canonical JSON (normative)

The serialisation used by `state.json` (§5.3) and by the `.json` mirrors of
entry vectors. §5.3 requires two implementations to produce **byte-identical**
output, so every rule below is normative; nothing here may be left to a JSON
library's defaults, because they differ.

### 14.1 Structure

| rule | requirement |
|---|---|
| whitespace | none anywhere: `,` between members, `:` between key and value, nothing else |
| object keys | sorted **ascending, bytewise over the UTF-8 encoding of the bare key string**, applied recursively to every object including `devices`, `labels`, `roots`, `signers`, `active_wg` |
| byte strings | **lowercase hex**, as a JSON string, never base64 (base64 appears only inside notes, §7) |
| integers | decimal, no sign, no leading zeroes, no exponent |
| booleans | `true` / `false` |
| absent members | a member the schema defines is always emitted (§5.3); see §4.0 for *entry* encoding, where the rule is the opposite |
| document end | the canonical form is followed by exactly one `0x0A`. A file that omits it does not match |

This key order is **not** the CBOR map order of §4.1, which sorts by encoded
form. The two are independent and are both normative in their own place.

### 14.2 String escaping

Strings are UTF-8. Exactly these characters are escaped, and no others:

| character | output |
|---|---|
| `"` U+0022 | `\"` |
| `\` U+005C | `\\` |
| backspace U+0008 | `\b` |
| tab U+0009 | `\t` |
| line feed U+000A | `\n` |
| form feed U+000C | `\f` |
| carriage return U+000D | `\r` |
| any other C0 control, U+0000–U+001F | `\u00xx`, **lowercase** hex |

Everything else is emitted verbatim as UTF-8. In particular:

- `/` is **not** escaped;
- `<`, `>`, `&` are **not** escaped (no HTML-safe escaping);
- U+007F DEL is **not** escaped — it is not a C0 control;
- non-ASCII is **not** escaped — no `\uXXXX` for characters above U+007F, and
  no surrogate pairs. An emoji is four UTF-8 bytes in the output.

These rules are load-bearing rather than cosmetic: `policy` and `note` text is
free-form UTF-8 up to 4096 bytes and lands verbatim in the canonical state, so
two implementations disagreeing about `<` or `é` would violate §5.3's MUST on
the first realistic policy. Vector `log/106-enroll-astral-labels` exercises every
row of both tables above: its `escapes` label holds the quote, the backslash, the
control characters, the solidus that MUST NOT be escaped and multi-byte UTF-8
including an astral character, and that value lands verbatim in `state.json`.

## 15. Distribution, freshness and gossip

Checkpoint source does not change trust. A candidate fetched from a
`norn.trust.log_urls` endpoint or a proven peer MUST pass the same §10 verifier
under the node's anchored origin, trusted log keys and current witness policy.
The source supplies bytes; it cannot choose the rule used to accept them.

The verifier MUST fetch the candidate's entry bundles, rebuild the tree and
check the served hash tiles before replaying or adopting its state (§§6 and
10). A node MUST NOT store a candidate checkpoint or hand its resulting proven
set to the enforcer until that verification and replay succeed. When it holds a
stored checkpoint, it MUST compare the two branches before applying the rollback rule:
the `fork-on-a-shorter-branch` case in `detect/cases.json` is a fork even though
the candidate is shorter, while `refuse-shrunk` is a consistent older head and
is refused without a fork accusation. If the node lacks its own branch at the comparison
size, it refuses the shorter candidate without accusing (§10). The source and
the order in which sources answer affect latency, not these outcomes.

The node's clock for freshness is witness time. For each verified checkpoint,
§5.3 defines its `quorum_time` as the latest instant at which its verifying
cosignatures satisfy the policy that accepted it. A `quorum none` policy has no
quorum time: freshness is `unknown`, not an assertion of recency. On verifying
a checkpoint with quorum time `q` at the local monotonic reading `m`, the node
records the pair. Each pair is a lower bound on witness time now: `q` plus the
monotonic elapsed time since `m`, since the quorum vouched for `q` no later
than `m`. The node's
estimate of now is **the largest of the lower bounds** it holds; a newer quorum
time does not replace a larger bound, and an older time MUST NOT move that
estimate backwards (D-074 (b): keeping only the newest quorum time let an
instant learned late replace a larger bound, and the held view then looked
younger than the node had already proven the world to be). The estimate
survives a restart: the node writes it to its state directory as it advances
and seeds the clock from it at startup, as an instant observed at monotonic
zero (§13.2, D-071). The **age** of a held checkpoint is this estimate minus
that checkpoint's quorum time. An age is never negative: the held checkpoint's
own pair is one of the bounds. The estimate is a bound, not the time: time the
machine was suspended, and time between the clock file's last write and the
next start, is not counted, so an age is a lower bound and the states err
toward `fresh` by at most that gap, until the next verified checkpoint raises
the estimate; a node SHOULD use a monotonic source that counts suspended time
where its platform offers one. The **freshness states and their ordered
thresholds are §8.1**, with `detect/staleness.json` as their table and
`detect/staleness.json`'s `observed` cases as the derivation of the age. Wall
time MUST NOT decide freshness or which devices are proven (§5.3).

`CLOCK_SKEW` is an advisory alarm only. On a verified direct log fetch with a
quorum time, the node compares its wall time with witness time using
`abs((wall - quorum_time) - age) > Δclock`; `age` is the monotonic witness-time
age of that fetched checkpoint. The default `Δclock` is 5 minutes, and equality
does not alarm. A checkpoint fetched from a peer MUST NOT trigger this clock
comparison: a peer may legitimately serve an older head. This alarm MUST NOT
change freshness, the proven set or the peer table.

Peer checkpoint gossip runs every `T_g = 30 seconds` by default. A node asks
up to `r = 3 random proven peers` for checkpoints, or all available proven
peers if fewer, even when the direct log is healthy: a healthy log can show
two nodes different quorum-valid branches. On an unusable or stale direct log
response, the node also asks proven peers immediately. While `degraded` or
`hard_stale`, it polls the log and available peer sources at least every
10 seconds if its ordinary polling interval is slower. Peers are selected
from the current proven set, never from unproven interface entries. All peer
bytes pass the source-neutral verification above. A node polls proven peers
for `GET /norn/evidence` on its own `T_g` cadence. Evidence polling runs
independently of checkpoint polling and regardless of whether its direct log
is healthy. The node MUST check received fork evidence under §11.1 prior to
entering the frozen state; evidence that fails that check is only a bad peer
response.

An implementation SHOULD bound each read from a peer, each round of asking
peers, and each verification of a log, so that a source that accepts a
request and never answers — or answers each request slowly — costs a cycle a
bounded wait and not the cycle. The bounds are implementation defaults, not
protocol; `GOSSIP.md` §6 gives `nornd`'s.

Each gossip server binds plain HTTP to its WireGuard interface address, with
the host derived from that interface. Its required read endpoints are:

| Endpoint | Response |
|---|---|
| `GET /norn/checkpoint` | The node's currently adopted cosigned checkpoint. |
| `GET /norn/tile/…` and `GET /norn/tile/entries/…` | The corresponding bytes in its verified mirror. |
| `GET /norn/evidence` | The newest fork evidence it holds, or 404 if none. |

`HEAD` MAY use the same read endpoints. The server MUST NOT list directories
or expose files outside the mirror and named evidence endpoint. The required
endpoints are read-only and MUST reject writes. An optional `POST /norn/hint`
MAY be supported as an untrusted nudge to pull data; its body proves nothing,
and a node MAY reject it entirely. The **fork evidence format is §11.1 of
this document**. The policy text in `norn.trust` is verbatim
`c2sp.org/tlog-policy`.

## 16. Enrollment requests and key handling

An **enrollment request** is what a device hands a signer: *this is the name I
claim, this is the WireGuard key I want in the peer table, and here is a
signature by my device key.* It is not a log entry, but it does reach the log:
an `enroll` entry carries it **verbatim** as its whole body, and that is where
the device's consent lives (§4.3). It exists so that the `enroll` entry a signer
builds can carry a `device_pk` the device has demonstrably used, and so that the
whole exchange fits through a phone camera (§16.2).

### 16.1 Request format (normative)

Deterministic CBOR per §4.0. Unknown keys MUST cause rejection — a closed schema,
exactly as §4.1.

| key | type | required | meaning |
|---|---|---|---|
| `v` | uint | ✓ | `1` |
| `ts` | uint | ✓ | device clock, unix seconds; advisory, as in §4.1 |
| `net` | bytes16 | ✓ | the network this request is for |
| `sig` | bytes64 | ✓ | Ed25519 by `device_pk` over the preimage below |
| `wg_pk` | bytes32 | ✓ | the X25519 WireGuard public key to enrol |
| `labels` | map text→text | | as `enroll` (§4.3), under the same §4.0 caps; a `labels` map, when present, MUST carry at least one pair; `labels: {}` is refused as a schema fault; absence is the one encoding of "no labels" |
| `expires` | uint | | requested expiry, unix seconds; MUST be > `ts` |
| `device_id` | text | ✓ | a §2 `device_id` |
| `device_pk` | bytes32 | ✓ | the device's Ed25519 identity key |

The signature preimage is

```
"norn/enroll-request/v1\n" ‖ CBOR(request with "sig" omitted)
```

One `sig`, not §4.1's `sigs` array, because a request carries exactly one
signature and the key that made it is **in the object**: there is no `kid` to
resolve against any state and nothing to count against a threshold. The domain
prefix differs from §4.2's, so a device signature over a request can never be
replayed as a signature over an entry.

**What the signature proves, and what it does not.** It proves possession of the
private half of `device_pk`, and it binds `device_id`, `wg_pk`, `labels` and
`expires` to that key. It does **not** prove possession of the WireGuard private
key: `wg_pk` is X25519, which by §3 never signs. A device can therefore request
enrolment of a WireGuard key it does not hold. The consequences are bounded and
worth stating rather than glossing: if that key is already active the resulting
entry is refused `dup-wg` (§5.2), and if it is not, the requester has enrolled a
key it cannot complete a handshake with — it has denied service to itself.
Proving possession of an X25519 key needs a key-exchange round trip and is
deliberately out of scope for v0.

A consumer MUST validate structure **and** verify `sig` before showing a request
to a human — *what you sign is what you see*, and a request displayed before its
signature is checked is a request an attacker chooses the text of. A consumer
MUST also refuse a request whose `net` is not the network it serves, before
showing it (D-078): the `enroll` that carried it would be refused as `decode`
(§5.1), so a human shown it would be asked to approve something that cannot
take effect here (cold gate run 15, L7).

### 16.2 Text form (normative)

bech32m (BIP-350), HRP `norn`, data = the request bytes regrouped from 8-bit to
5-bit groups, zero-padded to the next group boundary. A decoder MUST reject a
payload whose padding is 5 bits or more, or whose padding bits are not zero.

**This section states Norn's choices within bech32m and nothing more:
everything else in the encoding is BIP-350's** — the 32-character data charset,
the human-readable-part expansion, the generator polynomial and polymod, the
separator being the **last** `1` in the string, the six-character checksum, and
the printable-ASCII range a character may fall in. None of it is restated here,
and a reader who does not fetch BIP-350 cannot implement this section: the
checksum constant and the padding rule below are the only parts of it Norn
narrows.

- The checksum constant is `0x2bc830a3`. bech32 (constant `1`) MUST be rejected:
  the two encodings differ **only** in that constant, so accepting either would
  accept the very mutation the checksum exists to catch.
- The canonical form is **lowercase**. An all-uppercase form MUST also be
  accepted, because QR alphanumeric mode has no lowercase letters and a request
  is meant to cross a room on a phone screen. Mixed case MUST be rejected.
- **BIP-173's 90-character limit does not apply.** It is an address-sized bound;
  a Norn request is ~250 characters. The honest consequence: above 90 characters
  the BCH code no longer guarantees detection of up to four errors. It remains a
  strong integrity check, and it is not what protects the request — `sig` is. A
  corrupted request fails Ed25519 verification, which is the check that decides.
  The bound that does apply is §4.0's `MAX_ENTRY_BYTES` on the decoded payload.

### 16.3 Key handling (normative)

Signing keys are reached through the **ssh-agent protocol** — the one
abstraction under which a hardware token, a password manager and a software key
all look identical, so Norn defines no key store of its own. Ed25519 only, in
v0 (§3). The agent is found through `SSH_AUTH_SOCK`, and a reader that lists an
agent's keys treats the ones that are not Ed25519 as **skipped, not refused**:
an operator's agent holding an RSA key alongside the network's keys is normal,
not an attack. A signer MUST **verify every signature the agent returns**
against the key it asked for, before using it — an agent is a separate process
answering over a socket, and its answer is data, not proof.

A key that is not in an agent is a key **file**, and Norn invents no format:
the OpenSSH private-key format ("openssh-key-v1"), in its **unencrypted** mode.
An unattended device key — the key §4.3 has signing `rotate` and self-`revoke`,
on a headless machine where nobody can type a passphrase — lives in such a
file, so it MUST be mode 0600: a reader MUST refuse one **readable by other
users**. A passphrase-protected key
MUST be refused with the answer *load it into an ssh-agent with `ssh-add`*,
which converts the problem into the paragraph above. Both directions are
checkable against the real tools, and are: `ssh-keygen` reads what Norn writes,
and `ssh-add` loads it.

Threshold signing is append-only. A signer adding a signature to an entry that
already carries one MUST NOT rewrite `ts`, `after`, or the body: the existing
signatures cover exactly those bytes, and a signer who edits them signs a
different entry while wearing the others' authority. The new signature joins
`sigs` sorted by `kid` (§4.1); nothing else moves.

The **root ceremony** — creating root, signer and log keys, and the trust file
that carries their results — is a human procedure and **not normative**: §9.1
fixes what a trust file MUST contain, §5.1 fixes what entry 0 MUST look like,
and a node reads the ceremony's results, not its script. One commandment of it
is, because it is the one a tool can betray:
**`--yes` MUST NOT exist for the root role.** A root's authorization is the one
decision in this protocol that cannot be handed to a script, because a script
that can mint it is indistinguishable from a stolen key with better manners; a
signer tool MUST refuse the combination outright.

What remains in `ENROLLMENT.md` — the tiers, the ceremony's runbook, the
recovery stories — is **informative**: it explains why these rules read the
way they do, and no interoperable node needs it to decide anything.
