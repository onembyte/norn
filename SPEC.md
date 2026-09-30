# Norn — Specification v0 (draft)

Written **2026-09-18** (plan part 4). Status: **v1**, frozen 2026-09-20.

Frozen means: a second implementation may be written against this document and
the vectors beside it, and neither will change under it. Every cross-reference
resolves and §13 is empty. What
changed on the way to v1 is in `BUILD-LOG.md`; the decisions behind it are in
`DECISIONS.md`, numbered and dated.
§12.1 lists what is vectored and what is not. It does **not** claim every MUST is vectored — several are not, and they are named there.

Norn reuses these specifications verbatim; where they conflict with this document,
they win:

- `c2sp.org/tlog-tiles` — log storage and read API
- `c2sp.org/tlog-checkpoint` — signed tree heads
- `c2sp.org/signed-note` — signature line format
- `c2sp.org/tlog-cosignature` — witness cosignatures (v1)
- `c2sp.org/tlog-witness` — witness HTTP protocol
- `c2sp.org/tlog-policy` — witness quorum policy (§9.1)
- `c2sp.org/tlog-proof` (v1) — self-contained inclusion proof bundles. Referenced for comparison only: §8.1 is Norn's own format and is **not** claimed byte-compatible
- RFC 6962 §2.1 — Merkle tree hashing (SHA-256)
- RFC 6962 §2.1.1 — inclusion-proof verification, used by §8.1
- RFC 6962 §2.1.2 — consistency-proof verification, used by §11.1. Both proof
  algorithms, and the node ordering each expects, are that document's and are
  not restated here
- RFC 8949 §4.2.1 — deterministic CBOR ("core deterministic encoding")
- RFC 4648 §6 — base32, for `origin` (§2, §9.1). The alphabet is given in §2
  because this document also uses a *different* base32 in §9.3
- BIP-350 — bech32m, the text form of an enrollment request (§16.2). §16.2
  states Norn's choices within it and nothing else about it
- RFC 8032 — Ed25519 · RFC 7748 — X25519

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

## 4. Entries

### 4.0 Encoding profile (normative — the byte-level contract)

All Norn **CBOR** structures — entries, enrollment requests, trust files,
proof bundles (§8.1) and fork evidence (§11.1) —
use **RFC 8949 §4.2.1 Core Deterministic Encoding** with these restrictions.
The canonical *state* is JSON, not CBOR, and is governed by §14 instead; it is
keyed by `device_id` and by 32-byte WireGuard keys, neither of which would fit
the map-key cap below:

| Rule | Requirement |
|---|---|
| Integers | major type 0 only; shortest form; ≤ 2⁶³−1. **No negative integers.** |
| Floats, tags, `undefined`, indefinite-length items | **forbidden** (see the note on over-determination below) |
| `null` | **forbidden** — an OPTIONAL field is *absent*, never `null` |
| Booleans | allowed (`params.rotate_needs_signer` only) |
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
logical entry several legal encodings, and `entry_hash` is over the bytes as
received (§4.1) — so two encodings of one governance entry are two distinct
leaves that both replay, which walks around the `dup-entry` defence by exactly
the route the consume-the-whole-input rule in §4.1 exists to close.
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
| `entry_hash` | `SHA-256` of the entry **as received**, byte for byte — identity for de-duplication. Not of a re-encoded canonical form: §5.1 records it at step 1, *before* the entry is decoded at step 2, so an entry that never decodes must still have one |
| leaf hash | `SHA-256(0x00 ‖ entry bytes)` (RFC 6962 §2.1) |
| signature preimage | the 14-byte prefix `norn/entry/v1\n` (13 ASCII characters and one `0x0A`), then the envelope encoded **without** the `sigs` key |

`sigs` is an array of maps `{"kid","role","sig"}` sorted by `kid` bytewise, with no
repeated `kid`. Signing does not change the preimage, so signatures can be added by
different parties in any order and the result is still canonical.

`v`, `t`, `net`, `ts`, `body` and `sigs` are all **mandatory**; only `after` is
optional. Omitting any mandatory key is `decode`.

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
every signature valid while changing its `entry_hash`, which is what
`dup-entry` is keyed on. A decoder that stops at the end of the item lets the
same governance entry be applied twice.

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
| `device_id` | matches `^[a-z0-9][a-z0-9.-]{0,63}$` |
| `name`, `reason` | UTF-8, 1–64 / 0–256 bytes |
| `text` (`note`, `policy`) | UTF-8, ≤ 4096 bytes |
| `labels` | map text→text; ≤ 32 entries; keys 1–23 bytes (the map-key cap above — a longer key is unencodable); values ≤ 256 bytes |
| `roots`, `signers` at genesis | arrays of 32-byte `pk`, no duplicates, no key in both; `len(roots) ≥ root_thr ≥ 1`; `len(signers) ≥ signer_thr ≥ 1` |
| `kid` (in `sigs`, and in `signer_remove`/`root_remove` bodies) | exactly 16 characters matching `^[0-9a-f]{16}$`. A malformed `kid` is a schema violation (`decode`), **not** a `kid` that merely fails to resolve — that distinction matters because the two produce different reason codes. |
| `sigs` array | sorted by `kid` and free of repeats (§4.0); an unsorted or repeating array is `decode` |

Reserved label keys (advisory hints for owner mode, D-026): `ip` — comma-separated
CIDR list used as allowed-ips; `endpoint` — `host:port`. A control plane may
override endpoints; it can never override keys.

### 4.1 Envelope

An entry is the deterministic CBOR encoding of:

```
{
  "v":    1,                      # format version
  "t":    <type string>,          # §4.3
  "net":  <bytes16 net_id>,
  "ts":   <uint unix seconds>,    # signer's clock; advisory
  "after":<uint>,                 # OPTIONAL — log size the signer observed (§4.4)
  "body": { ... },                # per type
  "sigs": [ {"kid": <hex16>, "role": <"root"|"signer"|"device">, "sig": <bytes64>}, ... ]
}
```

Map keys MUST be sorted per RFC 8949 §4.2.1: **bytewise lexicographic order of
their encoded form**, i.e. of the CBOR text-string item including its header, not
of the key string itself. Since every Norn map key is 1–23 bytes (§4.0) its header
is a single byte `0x60 + length`, so this is equivalent to "shorter key first,
then bytewise" — but it is **not** equivalent to sorting the bare key strings,
which would order an entry `after, body, net, sigs, t, ts, v` instead of the
correct `t, v, ts, net, body, sigs, after`. Canonical JSON (§14) does sort bare
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
| `rotate` | `device_id`, `wg_pk` (new), `device_pk` (new, OPTIONAL) | the *current* device key; **and the incoming `device_pk` too when the body carries one** (proof of possession, D-032); plus ≥ `signer_thr` signers if `params.rotate_needs_signer` |
| `revoke` | `device_id`, `reason` (string, **OPTIONAL** — absent is equivalent to `""`) | ≥ `signer_thr` signers, **or** the device itself, **or** ≥ `root_thr` roots |
| `signer_add` | `pk` | ≥ `root_thr` roots |
| `signer_remove` | `kid` | ≥ `root_thr` roots |
| `signer_thr` | `thr` (uint) | ≥ `root_thr` roots |
| `root_add` | `pk` | ≥ `root_thr` roots |
| `root_remove` | `kid` | ≥ `root_thr` roots; MUST leave ≥ `root_thr` roots. "And ≥ 1 root" follows from that and `root_thr ≥ 1` (§5.1 entry-0 step 6), so it is **implied, not a second test** — an implementation checking only the threshold is conforming |
| `root_thr` | `thr` (uint) | ≥ `root_thr` roots (the *old* threshold) |
| `params` | partial §4.5 map | ≥ `root_thr` roots |

| `note` | `text` (string ≤ 4096) | any 1 signer or root; **no state effect** |
| `log_key` | `pk` (bytes32), `overlap` (uint s) | ≥ `root_thr` roots — log-key rotation; both keys valid for `overlap` (`ENROLLMENT.md` §6) |
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
(`ENROLLMENT.md` part 3). A device signature over that envelope would require a
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

### 4.4 `after` — ordering guard

If present, the entry is valid only at log index ≥ `after`. A signer sets it to the
log size it observed when signing. It stops a log operator from inserting a signed
entry *earlier* than the signer intended (e.g. moving a `revoke` before a later
`enroll` of the same id). Inserting it *later* is delay, which receipts (§7) and
staleness (part 6) catch. RECOMMENDED for every entry.

### 4.5 `params`

| key | type | default | meaning |
|---|---|---|---|
| `checkpoint_interval` | uint s | 60 | T_c — max time between checkpoints |
| `staleness` | uint s | 600 | S — checkpoint age before `degraded` |
| `mmd` | uint s | 60 | max merge delay promised by receipts |
| `rotate_needs_signer` | bool | false | whether `rotate` needs a signer countersignature |

The witness policy is deliberately **not** a parameter (D-034). It has exactly
two homes: `norn.trust.policy`, which a node is provisioned with, and the
`policy` entry type, which supersedes it inside the log. A third copy in `params`
would let two verifiers disagree about the quorum that guards the log.

## 5. Replay — the state machine

Replay is the pure function

```
replay(anchor, entries[]) → state
```

where `entries[]` are the raw entry byte strings in log order and **`anchor`** is
the pair taken from the verifier's trust file (§9):

| field | type | source |
|---|---|---|
| `net` | 16 bytes | `norn.trust.net` |
| `genesis_hash` | 32 bytes | `norn.trust.genesis_hash` |

Nothing else is trusted a priori. In particular `state.net` is copied from the
**anchor**, not from the genesis entry, so a log that fails to produce a genesis
still yields a state identified with the right network.

### 5.1 Procedure

Entry 0 is handled once, then every later entry runs the same numbered list.
The order is **normative**: several vectors are simultaneously wrong in more
than one way, so the first matching step decides the reason code. The four
that carry the weight are `log/99-bad-precedence-decode-before-unknown-type`
(step 3 before step 4), `log/100-bad-precedence-decode-before-after` (step 3
before step 6 — a reader that decodes leniently, reads `after` and applies the
envelope schema afterwards answers `after` where this document says `decode`),
`log/101-bad-precedence-after-before-threshold` (step 6 before step 7) and the
two `threshold-before-dup-*` entries for step 7 against step 8. An ordering
with no such vector is an ordering a second implementation may reverse.

Replay of an **empty** list of entries yields the zero state of §5.3 with
`size` 0 and `rejected` empty: there is nothing to reject.

**Entry 0 (genesis).** In order — though unlike §5.2's ordering, **every failure here is `bad-genesis`**, so no artifact distinguishes one arrangement of these steps from another. The order below is the one that reads most naturally; it is not a guarantee, and §12.1 records it as unvectored.

1. `entry_hash` is recorded as seen.
2. Decode per §4.0 and check the envelope per §4.1. Any failure → **abort** (`bad-genesis`).
3. `t` MUST be `genesis`, and `net` MUST equal `anchor.net` → else **abort** (`bad-genesis`).
4. `leaf_hash` MUST equal `anchor.genesis_hash` → else **abort** (`bad-genesis`).
5. `after`, if present, MUST be 0 → else **abort** (`bad-genesis`).
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

1. `entry_hash` already seen → reject (`dup-entry`). Every entry that reaches
   this step is added to the seen set, **whether or not it is later rejected**.
2. Decode per §4.0 → on failure reject (`decode`).
3. Envelope check per §4.1: exactly the permitted keys, `v` = 1, `net` =
   `anchor.net`, well-formed `sigs` → on failure reject (`decode`).
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
| `enroll` | body closed and `request` present · the request decodes under §16.1 and its `net` equals the entry's (`decode`) · the request's signature verifies under its **own** `device_pk` (`no-device-sig`) · valid `signer` count ≥ `signer_thr` (`threshold`) · `device_id` not currently `active` (`dup-id`) · `wg_pk` not in `active_wg` (`dup-wg`) | add the device `active`, with the `device_id`, `device_pk`, `wg_pk`, `labels` and `expires` **from the request** |
| `rotate` | body well-formed (`decode`) · `device_id` known (`unknown-device`) · currently `active` (`not-active`) · valid `device` signature by the device's **current** `device_pk` (`no-device-sig`) · if `params.rotate_needs_signer`, signer count ≥ `signer_thr` (`threshold`) · new `wg_pk` not active **for another device** (`dup-wg`) · if the body carries `device_pk`, a valid `device` signature by **that** key as well (`no-device-sig`) | replace `wg_pk`, and `device_pk` if the body carries one |
| `revoke` | body well-formed (`decode`) · `device_id` known (`unknown-device`) · currently `active` (`not-active`) · authorised by signers, roots **or** the device itself (`threshold`) | `status` = `revoked`, drop from `active_wg` |
| `signer_add`, `root_add` | body well-formed and closed (`decode`) · `kid(pk)` not already a root or signer (`dup-key`) | add to that role |
| `signer_remove` | body well-formed and closed (`decode`) · `kid` is a signer (`unknown-key`) | remove. **No quorum invariant** — removing a compromised signer key MUST always be possible, including the last one (D-028). A network left with fewer signers than `signer_thr` cannot enrol until roots add one; that is recoverable, an unremovable stolen key is not. |
| `root_remove` | body well-formed and closed (`decode`) · `kid` is a root (`unknown-key`) · removing it leaves ≥ `root_thr` roots and ≥ 1 root (`root-invariant`) | remove |
| `signer_thr`, `root_thr` | body well-formed and closed (`decode`) · `1 ≤ thr ≤ len(set)` (`bad-thr`) | set the threshold |
| `log_key` | body well-formed and closed (`decode`) · `pk` 32 bytes, `overlap` a uint (`decode`) | **append** `{pk, overlap, since_index}` to `log_keys` |
| `policy` | body well-formed and closed (`decode`) · `text` ≤ 4096 bytes (`decode`) · `text` MUST parse as `c2sp.org/tlog-policy` (`decode`) | replace `policy` |
| `params` | body well-formed and closed (`decode`) · non-empty, only §4.5 keys, each of the right type (`decode`) | **merge** into `params` |
| `note` | body well-formed and closed (`decode`) · `text` ≤ 4096 bytes (`decode`) | none |

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
| `dup-entry` | `entry_hash` already seen |
| `after` | `after` > index |
| `threshold` | fewer valid signatures of the required role than the threshold |
| `no-device-sig` | `enroll`/`rotate` lacks a required valid signature by a device key — for `enroll` that is the **embedded request's own** signature (§4.3), for `rotate` a signature on the envelope. **Not `revoke`** — a `revoke` may be authorised by signers, roots *or* the device, so a `revoke` carrying none of the three is `threshold` (§5.1). |
| `dup-id` | `enroll` with a `device_id` that is currently `active` |
| `dup-wg` | a `wg_pk` that is already active. For `enroll` that means active for **any** device — a `device_id` may be reused after revocation, but a live key may not. For `rotate` it means active for **another** device: re-presenting the device's own key is how an identity key rotates alone (D-032). |
| `unknown-device` | `rotate`/`revoke` names a `device_id` never enrolled |
| `not-active` | `rotate`/`revoke` on a device that is already `revoked` |
| `dup-key` | `signer_add`/`root_add` of a `pk` whose `kid` already exists in either role |
| `unknown-key` | `signer_remove`/`root_remove` of a `kid` not in that role |
| `root-invariant` | `root_remove` would leave `< root_thr` roots or `< 1` root. **Removals only** — a `root_thr`/`signer_thr` value outside `1 … len(set)` is `bad-thr`, because the *value* is wrong rather than the resulting set (D11). |
| `bad-thr` | a `signer_thr`/`root_thr` value of 0, or one exceeding the size of the set it applies to. This is a **replay** decision, not a schema one: the value is a well-formed uint, so it is never `decode`. |

Signature counting, precisely: a signature `{kid, role, sig}` is *valid* iff
`kid` names a key this entry may be signed by **in that role**, and Ed25519
verification of `sig` over the preimage succeeds. For `signer` and `root` that
key is whatever the state **before this entry** holds in that role. For
`device` it is the `device_pk` of the device this entry names:

- on `enroll`, the `device_pk` inside the **embedded request** (§4.3) — an
  `enroll` body carries no other key;
- on `rotate`, the device's **current** `device_pk` from the state, **and** the
  incoming `device_pk` the body carries, when it carries one. The incoming key
  is by construction not in the state before the entry, which is the whole
  point of §5.1's proof of possession: a signature by it is valid, and D-032
  requires it;
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
| `rejected` | array of `{index, reason}` | in index order |

A device record:

| field | type | meaning |
|---|---|---|
| `device_pk` | 32 bytes | current identity key |
| `wg_pk` | 32 bytes | current WireGuard key |
| `status` | `"active"` \| `"revoked"` | |
| `since_index` | uint | index of the entry that last changed `status` (§5.1) |
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
equal to `T` **has** passed. When the policy is satisfied at no instant — which
includes `quorum none`, where nobody vouches for the time either — there is **no
clock**, and expiry is not judged at all: the device keeps the status replay gave
it. Norn fails towards the last state a quorum vouched for, rather than dropping
devices on a number nobody signed.

## 6. The log

- Layout, tiles, entry bundles, and `checkpoint` exactly per `tlog-tiles`. Tile height 8 (width 256), as torchwood requires.
- A checkpoint body is exactly three lines (`c2sp.org/tlog-checkpoint`): the origin, the tree size in decimal with **no leading zeroes**, and the root as **standard base64 with padding, 32 bytes once decoded** — any other decoded length is an error, and so is base64 the line's own length does not account for. `0124` and `124` are the same number and two spellings of one head. The length bound is not decoration: a reader that skips it and also skips the rebuild below accepts a head that is not a SHA-256 root at all, and the two rules are the only ones that look at that line (cold gate run 10, D11).
- Leaf hash = `H(0x00 ‖ entry_bytes)` (RFC 6962 §2.1). An entry bundle is each entry's length as a **big-endian** uint16 followed by that many bytes, repeated — the framing `c2sp.org/tlog-tiles` defines, and the reason §4.0's `MAX_ENTRY_BYTES` is 65535 rather than 65536. A partial bundle holds **exactly** the number of entries its path declares.
- **The paths, restated.** `c2sp.org/tlog-tiles` defines them and this document does not vary them — but it restates them here for the same reason §7 restates the note framing and §9.1 the policy grammar: a verifier cannot be written without them, and a reader holding this document and the vectors has no other copy. A hash tile at level `L` covering index group `N` is `tile/<L>/<N>`, and an entry bundle is `tile/entries/<N>`, where `<N>` is the tile's index written in **three-digit groups, most significant first, joined by `/`** — `0`, `1000` and `1234567` are `000`, `x001/000` and `x001/x234/567`, with every group but the last prefixed `x`. A tile that is not yet full is **partial**: its path gains `.p/<W>`, where `<W>` is how many of the 256 entries it holds. So a log of 126 entries serves its only hash tile at `tile/0/000.p/126` and its only bundle at `tile/entries/000.p/126` — both of which this suite ships, and every concrete path written here is one a reader can open. When a tile fills, the `.p/<W>` suffix goes away and the path is the bare group; the next tile starts again at width 1. Tile height is 8, so width is 256 and level `L` covers 256^(L+1) leaves.
- A verifier rebuilds the tree from the **entry bundles** and compares its head with the signed checkpoint; that comparison is what binds the entries to the head. The served `tile/<L>/…` hashes MUST also agree with the tree it rebuilt. They are not needed to reach the head, and checking them is not optional: a node serves the tiles it fetched onward to its peers (`GOSSIP.md`), so a node that accepted tiles it never checked would pass on a lie it had the means to catch.
- The checkpoint is a `tlog-checkpoint` note: `origin` line = §2 `origin`, size, root; **no extension lines**. Signed by the log key; cosigned by witnesses per `tlog-cosignature` v1.
- The log MUST issue a new checkpoint after every append and at least every `checkpoint_interval`.
- **Log operator validation is optional and non-binding.** A log SHOULD refuse entries that fail §5 against its own replay, to keep the log tidy — but verifiers MUST NOT rely on it (`THREAT-MODEL.md` G3).
- Additional paths (Norn-specific, ignored by generic tooling):
  - `<prefix>/add` — submission (§7)
  - `<prefix>/anchors/<size>.ots` — OpenTimestamps proof for the checkpoint at `size` (D-009; advisory). The stamped value is `SHA-256` of the note's leading bytes **through the newline that terminates the blank separator line** — the three body lines **plus the blank line**, four `0x0A` in all, and no signature line. Not the three-line body of the bullet above and not §7's *signed text*, which stops one `0x0A` earlier: those are three different byte ranges and the word "body" is not enough to pick one. `anchors/cases.json` gives the digest and names the bytes that produce it, so this is checkable without parsing OpenTimestamps. Not the signed note: cosignatures are appended as witnesses answer, so a note-level digest would stop matching the moment one replied — and the log's signature adds nothing to a claim about *when* the tree existed, since the log is the party the anchor exists to constrain.
  - `<prefix>/norn.trust` — a *copy* of the trust file, for convenience only; never authoritative (G6)

## 7. Submission and receipts

`POST <prefix>/add` with body = entry bytes (`Content-Type: application/cbor`).

Response `200` body is a signed note (`c2sp.org/signed-note`) by the log key:

```
norn/receipt/v1
<origin>
<b64 leaf hash>
<uint deadline unix seconds>       # = now + params.mmd
```

The note framing is `c2sp.org/signed-note`, restated here so an implementer needs
nothing else (D22). These rules are **verified against `golang.org/x/mod/sumdb/note`**,
the canonical implementation the transparency ecosystem uses: it accepts the
verifier keys and the receipt this suite ships, unchanged, and opens notes this
spec's rules produce.

- The **signed text** is everything up to **and including** the newline that ends
  the last text line. It does **not** include the blank separator line. A note's
  text lines are non-empty, so **the **first** blank line ends the text** — there
  is no second one to choose between. A reader that ends the text at the *last*
  blank line signs a different string, and the two readings are told apart by no
  Norn artifact only because every note text here has a fixed line count (§12.1).
- The text is followed by one blank line, then one signature line per signer. **Every signature line, including the last, ends in one `0x0A`**: a block that simply stops is unterminated, not merely short of a newline, and a reader that trims trailing newlines before parsing cannot tell the two apart.
- A signature line is `\u2014 ` (em dash U+2014, then one space), the key name, one
  space, then base64 of a payload that begins with a 4-byte `key_id`. A key name
  **contains no space**, so the line splits at its **first** space and everything
  after it is the payload — split at the *last* one instead and a line carrying
  two spaces parses as a signature from a name nobody lists, which §10 ignores
  rather than refuses. The payload is **standard base64 **with padding****
  (RFC 4648 §4, the `+/` alphabet, `=` to a multiple of four); unpadded base64
  decodes to the same bytes and is not this encoding. **What
  follows the key id depends on the algorithm the key was published under**,
  and this document uses two:
  - **algorithm `0x01`**, a plain Ed25519 note signature (the log's, and a
    receipt's): `key_id ‖ signature` — 4 + 64 = 68 bytes, signed over the note
    text.
  - **algorithm `0x04`**, a `c2sp.org/tlog-cosignature` v1 line (every
    witness's): `key_id ‖ timestamp ‖ signature` — 4 + 8 + 64 = 76 bytes. The
    timestamp is an unsigned 64-bit **big-endian** count of seconds since the
    Unix epoch, and it is the only timestamp in the artifact: §5.3's `T` is
    derived from these eight bytes and from nothing else. The signature is
    **not** over the note text. It is over
    `"cosignature/v1\n" ‖ "time " ‖ <timestamp as decimal, no leading zeroes> ‖ "\n" ‖ <note text>`
    — two newline-terminated header lines, then the whole note text through
    its final newline, with no signature lines.
- The decoded payload is **exactly** that length — **exactly** 68 bytes for
  algorithm `0x01` and **exactly** 76 for `0x04`. Not "at least": a verifier
  that reads the first 68 bytes and ignores what follows accepts unboundedly
  many byte-distinct forms of one checkpoint, every one of which verifies. Two
  nodes gossiping that head then disagree about its bytes, and everything keyed
  on them — a cache, a de-duplication set, §6's OpenTimestamps digest over the
  body — is keyed on something an attacker chooses. A line whose payload is the
  wrong length is a malformed note, not a line to skip.
- A note carries **at least one signature line**. A block with none is a
  malformed note rather than an unsigned one; in practice §10's "at least one
  such line MUST be present" refuses such a checkpoint first, which is why
  §12.1 lists this rule as one no file can isolate.
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
- A verifier key string is `<name>+<key_id as 8 hex digits>+<base64(alg ‖ pk)>`.
  Split it on `+` **at most twice**: standard base64 contains `+`.

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

### 8.1 Bundle format (normative)

Deterministic CBOR per §4.0, a closed map of exactly these six keys. A bundle
is **not signed**: its authority is the signed checkpoint inside it, which is
why there is no domain prefix here — there is nothing for one to separate.

| key | type | meaning |
|---|---|---|
| `v` | uint | `1` |
| `device` | text | the `device_id` this bundle proves |
| `index` | uint | the entry's index in the log |
| `entry` | bytes | the entry itself, so the bundle stands alone |
| `proof` | array of 32-byte strings | RFC 6962 inclusion proof, leaf to root |
| `checkpoint` | text | the signed checkpoint note, verbatim |

Checking a bundle: **verify its checkpoint per §10** — this network's origin,
this network's log key, and a satisfied witness quorum — then confirm
`SHA-256(0x00 ‖ entry)` and `proof` reach that checkpoint's root at `index` for
that size, then confirm that **`device` is the `device_id` the `entry` names**
— for an `enroll`, the id inside the embedded request; for the other device
types, the `device_id` in the body — and apply the rules below.

That last step is not bookkeeping. The inclusion proof binds the *entry* to the
log and says nothing about the label beside it, so without it a bundle reading
`device: "nas"` around another device's entry proves exactly as much as an
honest one, and a consumer keying on `device` believes something no proof
established.

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

A node MUST treat a peer as proven only if:

1. the bundle's checkpoint verifies under the node's trust policy (§9), and
2. the bundle's checkpoint is consistent with the node's stored checkpoint, and
3. replay of the log up to that checkpoint yields the device as `active`, and
   the key the node installs for it is **the `wg_pk` replay gives**: the
   device's current key in the §5.3 state, never the key written in the
   bundle's entry, and
4. the checkpoint is not stale: **`elapsed > params.staleness`** makes it so,
   where `elapsed` is the node's **monotonic** reading now minus its monotonic
   reading when it learned this checkpoint's quorum time (§5.3).

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
| `fresh` | `elapsed ≤ S` — the boundary is fresh, because condition 4 makes `elapsed > S` the violation |
| `hard_stale` | `S_hard` is configured **and** `elapsed > S_hard` |
| `degraded` | otherwise |

`S` is the log's, so the whole network agrees when a view is too old to trust.
**`S_hard` is the node's own and is opt-in**: zero means not configured, and a
node that was never configured for it stays `degraded` for ever rather than
going `hard_stale`. That asymmetry is deliberate — crossing `S_hard` drops every
peer, so a log unreachable over a weekend must not take a network down by
itself. It is a local decision for the same reason the witness policy is not a
`params` key (D-034).

**The order is part of the rule.** `fresh` and `hard_stale` are separate
conditions, and both hold whenever `S_hard < elapsed ≤ S`. Read in the order
written, that region is `fresh`: **a node never drops its peers while the
network calls its view fresh**. So an `S_hard` below `S` does nothing until
`elapsed` passes `S`, and from there the view goes straight to `hard_stale`
without being `degraded`. Nobody has to misconfigure a node to get there. `S`
is a `params` key that a root quorum can raise, and `S_hard` stays where the
node put it. A node that chose `S_hard = 700` while `S` was 600 is in that
region as soon as `S` becomes 900, and this suite's own log does exactly that
(`00-genesis`, then `29-params`). The two `hard-below-staleness` cases in
`detect/staleness.json` are that node. Letting `S` win costs nothing a root
quorum did not already have: the same signatures that raise `staleness` could
enroll a device outright.

Because the node replays the whole log, condition 3 is what actually decides;
the bundle is the portable, offline-checkable evidence that goes in alerts and
audit output.

**A bundle proves that its device was enrolled, not which key it uses now.**
The bundle's entry is the one that made the device `active`. For an `enroll`,
that entry holds the request and the key the request carried. A `rotate`
changes the key and leaves `since_index` where it was (§5.1), so any device
that has ever rotated carries a bundle whose entry names a key it no longer
uses. That is the normal case and not a stale bundle. `proofs/nas.bundle`
proves `nas`'s enrolment at index 1, and its entry carries the key
`116f00fa…`. Replay gives `2a955fd2…`, the key `nas` rotated to at
`35-rotate-nas`. A node that required the two to match would drop every peer
that had ever rotated, and nothing would tell it so. `proofs/cases.json` lists
under `installs` the key a node installs for each device whose bundle ships.

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
| `log_urls` | array of text, ≥ 1 | where to fetch checkpoint and tiles. **Each URL is non-empty**: an array holding `""` satisfies "≥ 1" and names nowhere |
| `witnesses` | array of `{name, key, url?}`, **≥ 1** | `key` is a **cosignature** verifier key — `c2sp.org/tlog-cosignature` algorithm `0x04`, not a note key's `0x01` — and MUST parse as one; **a witness `name` is 1–64 bytes** and unique within the file — bounded like the network `name` above, and for the same reason: it is a label an operator reads. The algorithm is part of the key id, so the same public key published under the two algorithms is **two different verifiers**: a file naming a witness with a note key names a key no witness will ever sign with. A file with no witnesses MUST be rejected: with nothing to cosign, the policy's quorum can never be met, so the anchor could never accept a checkpoint. |
| `policy` | text | verbatim `c2sp.org/tlog-policy`; MUST parse, and MUST name **exactly** the witnesses `witnesses` lists, with the same keys. The two are not redundant: `witnesses` is where a node learns a witness's name and address, `policy` is where it learns whether that witness counts — so a file where they differ configures a quorum over parties the node cannot reach, or lists parties nothing requires, and either way the operator believes they set something they did not. A `log` line, if the policy carries one, is subject to the same argument: **it MUST be `norn.trust.log_key`**. A file whose two halves name different logs is the same operator error, and the only one of the two a verifier ever uses is `log_key`. The correspondence is on the **set** of names: a witness listed twice is refused by the uniqueness rule above, not by this one, and an implementation that strikes each name off as it matches conflates the two — it then refuses a duplicate here and passes the suite without the uniqueness rule at all |
| `anchor` | `{type, max_lag, mode}`, OPTIONAL | All three members are required **when `anchor` is present**. `max_lag` is **uint seconds**. The two text members are not symmetric: **an unknown `type` is ignored**, not refused — anchoring is advisory (D-009), so a reader that cannot check `"roughtime"` simply does not check it and the rest of the file stands — while **`mode` MUST be `"advisory"`**, because guessing what an unrecognised enforcement mode means is how a node enforces something nobody asked for. A reader that refuses an unknown `type`, or accepts an unknown `mode`, is wrong in opposite directions |

Unknown keys MUST cause rejection. The fingerprint (§9.3) is taken over these
bytes, so a wrong field name or type changes it.

**`MAX_TRUST_BYTES` is 65536**. A trust file is keys, URLs, a witness list and
a policy — it does not wrap an entry, and nothing in it scales with the log. A
file larger than this MUST be refused on length, before anything it declares is
allocated.

**The policy grammar.** `policy` is `c2sp.org/tlog-policy` verbatim and is not
redefined here, but a verifier cannot be written without it, so its four
directives are restated. Lines end in ASCII newline; fields are separated by
ASCII spaces and tabs **only**:

```
log     <vkey> [<url>]
witness <name> <vkey> [<url>]
group   <name> all|any|<k> <name>...
quorum  <name>
```

Both URLs are **optional in the grammar and present in every Norn policy** —
omitting them parses, and a second implementation that stops reading a line
after the key will silently accept a policy it has misread. A `group` names
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
| the final newline | **optional**: the last directive need not end in one |
| field separators | ASCII space (`0x20`) and tab (`0x09`) **only**, in runs. Three other characters are an **error** anywhere in a line — `0x0B` (`\v`), `0x0C` (`\f`) and `0x0D` (`\r`) — not a separator and not content. **That set is closed**: every other character, every other Unicode whitespace character included (U+00A0, U+2028, …), is **content**. It is closed because a `policy` entry's text is replayed (§5.1), so a character one reader refuses and another keeps is a `decode` on one node and a new quorum on the other. Until this was written, this repository's two parsers disagreed on 23 characters, and no vector could tell |
| field count | each directive takes **exactly the fields its production above allows** — `quorum` one, `witness` two or three, `log` one or two, `group` a name, a threshold and one or more members — and a line with more is an **error**. Stated because it was doing the work of the rule above it: with the stray whitespace in an optional URL, a reader that treats `\v` as a separator sees a four-field `witness` and refuses it *here*, so the separator rule could be deleted and every vector stayed green (cold gate run 10, D9) |
| leading whitespace | spaces and tabs before the keyword are not part of it |
| names | each `witness` and `group` name is defined **once**; a repeat is an error |
| keys | a verifier key appears **once** in a policy, on whatever line: the same key under two `witness` names, on a `log` and a `witness` line, or on two `log` lines is an **error**. Keys are compared as the `vkey` text. Under two names, one cosignature line (§7: name and key id) matches both, so one witness answering once meets `group home 2 a b`. Two *different* keys held by one operator cannot be detected here or anywhere else, and are two witnesses as far as any policy can tell |
| `group` members | each **previously defined**, and **no member twice** — `group home 2 pi pi` would otherwise be met by one witness. "At least one" is the field count's rule, not a separate one: a `group` line with no members has three fields, and the field count refuses it before this row is reached (`bad-empty-group`) |
| `group` thresholds | `all` is `n`, `any` is 1, and a count is **canonical decimal** with `1 ≤ k ≤ n`. `0` is met by nobody, so a policy carrying it accepts an **uncosigned** head; `02` and `2` are the same number and two spellings of one quorum |
| keywords | the four directives, `all` and `any` are **lowercase**. Nothing here is case-folded |
| nested groups | a `group` may name a `group`. It counts as **one** member of the outer group, met or not met as its own threshold decides |
| `log` lines | **not required**, and **more than one is allowed**: a policy naming a log's old and new key is what a rotation looks like from outside (`two-log-lines`). A Norn **trust file**'s policy carries at most one, because a `log` line that is present must name `norn.trust.log_key` (§9.1's `policy` row) and the `keys` row forbids naming it twice. That limit is the trust file's, not the grammar's: a `policy` entry (§5.1) has no such correspondence. Norn takes the log key it verifies with from `log_key`, never from here |
| `quorum` | exactly one line, naming a witness, a group, or `none` |

### 9.2 TOML rendering

```toml
# Norn trust file for norn-testnet
# fingerprint = Y2KM-WGEJ-5GCD-X3HA
# Compare the fingerprint out of band before trusting this file.

version      = 1
net          = "6e6f726e2d746573746e65742d303031"   # hex
origin       = "norn/nzxxe3rnorsxg5domv2c2mbqge"
name         = "norn-testnet"
genesis_hash = "4e18d55c…"                          # hex
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
  simply **omitted** from the CBOR map (§4.0: OPTIONAL means absent, never `null`).

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
accepted nothing has only the trust file's key.

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

**The witness policy rotates the same way and differs in one respect: it
replaces.** A `policy` entry supersedes `norn.trust.policy` for every checkpoint
a node accepts after replaying it, and for §5.3's `T`. Keys accumulate because
an overlap is the point; policies do not, because a policy is one document and
two in force at once is exactly the disagreement about the quorum that §4.5
refuses to allow. Publishing one takes the root quorum (§4.3).

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

```
loop every T_g or on demand:
  cp := fetch checkpoint (log_urls, then peers)         # part 6
  # The SIGNATURE decides first. A checkpoint signed by a key this anchor does
  # not trust is refused for that, whatever origin it names: `wrong-origin` is
  # about a checkpoint this network's own key signed, and until the signature
  # has been checked there is no reason to believe any field in the note.
  # Signed by norn.trust.log_key, or by a key a state this node already
  # accepted names (§9.4). Never by a key learned from this checkpoint.
  # Every signature line whose name and key id match a trusted log key MUST
  # verify, and at least one such line MUST be present. Not "at least one
  # verifies": a checkpoint carrying a valid signature AND a forgery under the
  # same key is refused, exactly as a witness's two lines are below. The
  # canonical signed-note implementation does not impose this; Norn does.
  verify log signature (torchwood VerifyCheckpoint)     # norn.trust.log_key
                                                        # and norn.trust.policy:
                                                        # a checkpoint must be
                                                        # accepted before the log
                                                        # can be replayed, so
                                                        # acceptance cannot depend
                                                        # on anything the log says
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
      # A line naming anyone the policy does NOT list is IGNORED, not refused
      # and not counted -- a witness cosigning a log this node's policy does
      # not name is normal in a shared log, and a reader that refuses over one
      # stops accepting checkpoints everybody else accepts. The log's own
      # signature line may appear anywhere in the block; order carries nothing.
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
  fetch new tiles / entry bundles (TileFetcher / TileFS + PermanentCache)
  state := replay(trust, entries[0:cp.size])
  T := the evaluation time of cp (§5.3)                  # witness time, never ours
  proven := { d ∈ state.devices : status == active && not expired(d, T) }
  store cp; hand proven to the enforcer                  # part 5
```

## 11. Fork handling

A node that observes two valid, policy-satisfying checkpoints for the same origin
that are not consistent MUST:

1. write both checkpoints and the failed proof to `fork/<unix>.evidence`,
2. keep its stored checkpoint and proven set unchanged,
3. raise a `FORK` alarm, and
4. refuse every later checkpoint not consistent with the stored one — forever,
   until an operator explicitly resets with a new trust file (KEYTRANS rule).

### 11.1 Evidence format (normative)

Evidence is the one artifact this protocol produces for **somebody else** — a
witness operator, a mailing list, a stranger — so it has to be checkable by a
reader who has the network's trust file and nothing else: no running log, no
connection, and **no reason to trust whoever handed them the file**. That is
why the format is here rather than in `GOSSIP.md`.

Deterministic CBOR per §4.0, a closed map of exactly these seven keys:

| key | type | meaning |
|---|---|---|
| `version` | uint | `1` |
| `held` | text | the signed checkpoint the accuser was holding — the branch it can speak for, because it has the entries |
| `conflicting` | text | the signed checkpoint that could not be reconciled with it |
| `size` | uint | where the two disagree: the **conflicting** head's size |
| `held_root` | bytes (32) | what the held branch had at `size` |
| `proof` | array of bytes (32 each) | **RFC 6962 §2.1.2** consistency proof chaining (`size`, `held_root`) to `held`'s own head, in that document's node order — the algorithm is not restated here and a reader implementing their own ordering will reject sound evidence. **Empty when `size` equals `held`'s size**, where the two signatures say it alone |
| `policy` | text | the `tlog-policy` the **accuser** was verifying under, so a reader can see which witnesses were meant to prevent this. **Informational.** It MUST parse as `c2sp.org/tlog-policy` — a closed schema with a stated grammar is part of the format — and a reader MUST NOT verify anything under it. The reader uses **its own** policy: the trust file's, or one it has replayed (§9.4). Verifying under the carried field hands the accuser the quorum rule, and an accuser writing `quorum none` then gets two uncosigned checkpoints accepted as proof of equivocation — which, by §11 rule 4, takes the network down until an operator installs a new trust file. This implementation did exactly that until cold-model gate run 7 |

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
   over. Without this the reader is taking the accuser's word for the number
   that matters most, and
4. conclude a fork **only if `held_root` differs from `conflicting`'s root**. If
   they agree, the file proves nothing: a log and its own earlier self is not a
   fork, and a node MUST NOT publish that as an accusation.

A reader that refuses at any step MUST NOT conclude a fork. This is worth
stating separately because §11 rule 4 makes the conclusion **permanent** until
an operator installs a new trust file: a reader that skips a step accepts an
accusation any stranger can write, and takes the network down until a human
intervenes. Each step has a vector in `fork/` for that reason.

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
`served/`, `proofs/`, `fork/` and `checkpoints-bad/` vectors come from the **Go**
implementation instead, because producing a tiled log requires one. `anchors/`
comes from `python-opentimestamps`, the reference implementation of a format
neither of Norn's owns — and they are validated against
libraries neither implementation wrote: `transparency-dev/formats` parses the
checkpoint, and `x/mod/sumdb/tlog` checks every inclusion proof. Nothing in the
suite is checked only against its own author.

| file | contents |
|---|---|
| `keys.json` | every test key: Ed25519 `{seed, public, kid}` by name, X25519 public keys by name, and `net` |
| `entries/NN-<type>.cbor` | one valid entry per type, canonical bytes |
| `entries/NN-<type>.json` | mirror: `{entry, entry_hash, leaf_hash, preimage_sha256, size}` where `size` is the byte length of the `.cbor`. The `entry` object mirrors the **CBOR**, so an optional field absent from the entry is absent here too — unlike `state.json`, where §5.3's schema fields are always emitted |
| `log/NN-<name>.cbor` | the replay fixture, **126 entries** in order. The file names are labels, not the order: **read the sequence from `manifest.json`**, never by globbing and sorting |
| `log/NN-<name>.reason` | beside each entry that must be rejected: its §5.2 reason code |
| `log/manifest.json` | `{"anchor": {"net", "genesis_hash"}, "entries": [{"index", "name", "reason"}]}` — the replay input and expected outcome; `reason` is `""` for an accepted entry |
| `state.json` | canonical replay output for `log/` (§5.3) |
| `genesis/<NN-case>/` | one single-entry log per way entry 0 can abort, each with its own `manifest.json` and `state.json`; an abort stops replay, so the cases cannot share a log. `cases.json` lists them |
| `trust-bad/<NN-case>.cbor` | trust files that decode cleanly but MUST be rejected as anchors; the file name says why, `cases.json` lists them |
| `served/` | the fixture's entries as a real **tlog-tiles directory**: `tile/entries/…` bundles, `tile/<L>/…` hashes, and `checkpoint` — which **is** the signed note (§6), not an unsigned file with a signed sibling |
| `proofs/<device>.bundle` | one §8.1 proof bundle per active device, each proving the entry that made that device active; `cases.json` gives the origin, the log-key seed, the device list and, under `installs`, the key a node installs for each device (§8.1 condition 3) |
| `trust.cbor` · `trust.toml` · `trust.fingerprint` | the trust anchor (§9), authoritative bytes, human rendering, and its fingerprint |
| `receipt.note` | a submission receipt: the signed note itself (§7) |
| `policies/<name>.txt` | §9.1's restated grammar, one whole policy per rule. `cases.json` marks each `accept` true or false and says which rule it is about |
| `log-empty/` | a log with **no entries**: `manifest.json` and the zero state §5.1 says it replays to. Not a `bad-genesis` abort — there is nothing to reject |
| `trust-good/<name>.cbor` | trust files §9.1 **permits**, for the members it marks optional or leaves open. `cases.json` lists them |
| `requests/<name>.cbor` · `.txt` · `.json` | enrollment requests (§16): the request bytes, its bech32m text form, and a mirror `{request, preimage_sha256, text, size}`. `cases.json` lists them, each with a `form` — `canonical` for §16.2's lowercase form, or `uppercase` for the same request in the form §16.2 says a reader MUST also accept, which names the canonical case it duplicates |
| `requests-bad/<name>.txt` | requests that MUST be refused — by the text layer, the CBOR profile, a field rule or signature verification. `cases.json` gives each case's reason |
| `receipt.json` | `{comment, origin, leaf_hash, deadline, text_sha256}`, where `text_sha256` is `SHA-256` of the **signed text** — through the newline ending the last text line, excluding the blank separator and the signature lines |
| `checkpoints-bad/<NN-case>.checkpoint` | checkpoints that MUST be refused, each served in place of `served/checkpoint` over the honest tiles. `cases.json` lists them, and its `signature_blind_accepts` names the ones a verifier that never calls Ed25519 accepts — five of the sixteen. That set is **computed** from the shipped files, not asserted |
| `entries-hostile/<name>.cbor` | input that is not an entry and never could be, for §4.0's three resource limits — the entry size, the nesting depth and the map-key cap. `cases.json` says what each refusal must be about, and marks the cases that sit exactly **at** a limit and MUST be accepted |
| `proven/cases.json` | the devices admitted at four evaluation times (§5.3), including the boundary where `expires` equals `T` |
| `fork/` | `evidence.cbor` and the `conflicting.checkpoint` it is about (§11.1), plus `bad-consistent` and `bad-other-origin`, which MUST be refused. `cases.json` lists them |
| `anchors/` | OpenTimestamps proofs written by `python-opentimestamps`: `checkpoint-<size>.ots`, `sample.ots` over an arbitrary digest, and a calendar's reply. **`cases.json` states each proof's digest in hex and names the bytes that produce it** — for the checkpoint proof, `served/checkpoint` through the newline that terminates the blank separator line, which is the §6 range and *not* the three-line body. Without it a reader has to parse the OpenTimestamps container, a format this document does not describe, before it can tell which of three byte ranges was stamped |
| `proofs-bad/<name>.bundle` | bundles that MUST be refused (§8.1); `cases.json` gives the log key to check them under and what each refusal must be about |
| `detect/` | the stored-checkpoint sequences §10 needs, each branch with its own tiles, plus `staleness.json` for §8.1's condition 4 |
| `served-rotated/` | the served head signed by a published `log_key` (§9.4), with `cases.json` giving the key, its `since_index` and its `overlap`. Serve it over `served/`'s tiles |
| `served-superseded/` | the served head cosigned by two of three witnesses, for §9.4's policy half. Serve it over `served/`'s tiles |
| `served-bad/` | §6's refusals for a served log, which is a directory rather than a file: each case names the path to replace or delete over an honest copy of `served/` |
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
| §4.0 encoding profile | every entry; controls `profile-base`, `labelcap-base`, `two-sig-base` | `bad-cbor-nonshortest` and `bad-cbor-nonshortest-length` (an integer and a length header: the two halves of the shortest-form rule), `bad-cbor-null`, `bad-cbor-unsorted-keys`, `bad-tag-wrapped-value`, `bad-indefinite-text`, `bad-indefinite-map`, `bad-duplicate-map-key`, `bad-invalid-utf8`, `bad-integer-too-large`. The 23-byte map-key cap has no *entry* case, because §4.3 put the device's claims in the request and a closed-schema check fires first on any other key — it is vectored at the decoder instead, in `entries-hostile/` |
| §4.3 `enroll` embeds the request | every `enroll` in the log; `enroll-unicode-labels`, `enroll-contractor` | **`bad-no-device-sig`** and **`bad-order-enroll`** (a request signed by a *signer*, not the device it names), **`bad-forged-device-sig`** (a request signature of the right shape and wrong), and `bad-device_id-uppercase`, `bad-device_id-leading-dot`, `bad-pk-length` — faults **inside** the request, inside an entry that is otherwise well formed and properly signed, so an implementation treating `request` as opaque bytes accepts all three |
| §4.0/§4.3 schemas | `enroll-laptop`, `enroll-unicode-labels` | `bad-kid-format`, `bad-missing-sigs`, `bad-empty-sigs`, `bad-unknown-role`, `bad-unknown-envelope-key`, `bad-unknown-body-key`, `bad-device_id-uppercase`, `bad-device_id-leading-dot`, `bad-pk-length`, `bad-sig-length`, `bad-text-too-long`, `bad-unsorted-sigs` |
| §4.2 signatures, hashes, preimage | 16 entry mirrors | **`bad-forged-signer-sig`, `bad-forged-device-sig`** — syntactically perfect signatures that do not verify. Without these an implementation that never calls Ed25519 reproduces the whole manifest |
| §4.0 the whole input is consumed | — | `bad-trailing-byte`: an accepted `log_key` entry with one byte after it. Its signatures still verify and its `entry_hash` differs, so a decoder that stops at the end of the item applies the same governance entry twice |
| §9.4 the policy supersedes | `served-superseded/`: two of three cosignatures — enough for the trust file, short of what the roots published | the informed reader is the stricter one here |
| §10 the stored checkpoint, §11's duties | `detect/`: accepting a head that grows, refusing one that shrinks **without** accusing, and proving a fork at the same size and on a shorter branch | the shorter-branch case is what a forking log looks like when it hides behind "a log does not shrink". It also pins §10's **order**: under a size-rule-first reading it comes out `refuse` rather than `fork`, so no evidence is written and no alarm is raised |
| §8.1 condition 4 | `detect/staleness.json`, including `elapsed` exactly on `staleness` | a node with no corroborated instant reports `unknown` rather than guessing |
| §9.4 rotation | `served-rotated/`: the same head under a key the roots published — refused by a reader holding only `trust.cbor`, accepted by one that has replayed the rotation | a key that vouched for itself is what the ordering forbids |
| §10 the checkpoint's origin | `served/checkpoint` | `checkpoints-bad/10-wrong-body-origin`: signed by this network's key under this network's name, naming another log |
| §4.0 both limits, at the boundary | `entries-hostile/at-the-depth-limit` and `at-the-size-limit`, which MUST be accepted | `past-the-depth-limit` and `past-the-size-limit`, one step beyond each. Without the accepted half a decoder enforcing 4, 16 or 64 passes |
| §16.2 padding | every request's text form | `requests-bad/excess-padding` and `non-zero-padding`: the payload is the valid request with its encoding corrupted, so only §16.2 refuses them |
| §9.4 the anchor key is kept **alongside** | `served/checkpoint`, signed by `norn.trust.log_key`, which the log publishes **nowhere**: the two `log_key` entries name other keys entirely | a reader that *replaces* `log_keys` with the published ones cannot read the head the log is serving. Replacing is the weakening — it trusts only what the log said about itself |
| §4.1 `sigs` elements are a closed map | every entry | `bad-sigs-fourth-key`: a fourth key beside `kid`, `role` and `sig` |
| §4.1 `v` MUST be 1 | every entry | `bad-version-two`. No entry carried any other value, so a reader that never looked at `v` reproduced the manifest |
| §5.1 `rotate` on a revoked device | `rotate-nas` | `bad-rotate-revoked`: `laptop` is known and revoked, so it is `not-active` and not `unknown-device`. The only other `not-active` vector is a `revoke` |
| §5.1 `dup-key` is across **both** roles | `signer_add-recover` | `bad-root_add-existing-signer`: adding a current signer as a root. Every other dup-key vector re-added a key into the role it was already in |
| §4.0 the profile's banned items, at the decoder | the three `at-the-…-limit` cases | `bare-null`, `bare-undefined`, `bare-float`, `bare-negative-integer`, `bare-tag`, `bare-indefinite-text`, `bare-nontext-map-key` and `bare-invalid-utf8` — each a whole input with no schema above it, so the profile is the only thing that can refuse, and each refused for **its own** rule. The in-entry negatives cannot pin these: a lenient decoder hands the envelope check a malformed field and the reason is `decode` either way |
| §4.0 free text has no lower bound | `note-empty-text`, `revoke-empty-reason` and `revoke-no-reason` — all **accepted**. `text` is bounded above only, `reason` is 0–256, and §4.3 marks it OPTIONAL | a reader that requires one byte rejects entries this document accepts, which only a positive can show |
| §4.0 resource limits | — | `entries-hostile/oversize-entry` (a header promising 65536 bytes, refused on length before anything is allocated) and `entries-hostile/deep-nesting` (200 nested arrays, deterministic throughout, so only the depth rule can refuse it) |
| §4.0 the map-key cap, at the decoder | `entries-hostile/at-the-key-limit` (23 bytes, MUST be accepted) | `past-the-key-limit`: a one-pair map with a 24-byte key and a uint value, so nothing but the cap can refuse it. `requests-bad/oversize-label-key` reaches the `labels` *field* rule first, which is a different check in a different layer |
| §4.4 `after` at the boundary | `after-at-its-own-index`: a floor met exactly | `bad-after-by-one`: one past the index, the smallest violation there is |
| §5.1 the request's `net` | every `enroll` | `bad-request-net`: a properly signed request for another network, so only that check refuses it |
| §5.1 `dup-id` before `dup-wg` | — | `bad-dup-id-and-wg`: an active `device_id` *and* a WireGuard key active for another device |
| §5.1 the order **inside** `enroll` and `rotate` | — | `bad-enroll-request-net-and-sig` (the request's `net` decides before its signature), `bad-enroll-unsigned-request-no-signers` (the request's signature decides before the signer count — the case `bad-enroll-empty-sigs` cannot make, since its request *is* signed) and `bad-rotate-dupwg-and-no-new-key-sig` (`dup-wg` decides before the proof of possession on the incoming `device_pk`). Each is wrong in both of its two ways at once |
| §5.2 a `device` signature's `kid` resolves | — | `bad-device-sig-wrong-kid`: the signature verifies and its `kid` names another key. The preimage excludes `sigs`, so rewriting a `kid` leaves the signature intact |
| §5.2 a signature counts only **in its declared role** | — | `bad-role-mismatch` for the root/signer direction, and `bad-device-sig-wrong-role` for the device one: the device's key really did sign, under `role: "signer"`, where it resolves to nothing. An implementation that ignores the declared role accepts it |
| §4.0 the `kid` **body** rule | `signer_remove-below-threshold` | `bad-kid-format-in-body`: a `signer_remove` whose body `kid` is not `^[0-9a-f]{16}$` → `decode`, not `unknown-key`. `bad-kid-format` puts the malformed kid in `sigs`, which is the other half of the distinction this document draws |
| §4.0 `revoke`'s `reason` cap | `revoke-by-roots` | `bad-revoke-reason-too-long`: 257 bytes. `bad-text-too-long` covers `note` and `policy`, whose cap is 4096 and a different rule |
| §4.0 the genesis `name` bound | the log's entry 0 | `genesis/14-name-too-long` and `15-name-empty` — both ends, because a reader enforcing only the cap and one enforcing only the floor are different implementations |
| §5.3 genesis `params` is **overlaid** | `state.json`'s `checkpoint_interval`, which the genesis body does not set and the §4.5 default supplies | a reader that *replaces* the defaults instead loses the key entirely |
| §4.3 the request's `ts` is unconstrained | `enroll-request-from-the-future`: an accepted `enroll` whose embedded request is dated ten days after the entry carrying it | the check a reader is most likely to add unasked |
| §4.4 `after` is a floor | `after-below-index` | `bad-after` |
| §5 replay, 15 of the 16 reason codes | the log | **84 rejecting entries** |
| §5 `bad-genesis` | — | `genesis/`; it cannot appear in the log, since it aborts replay |
| §5.1 genesis | the log's entry 0 | **19 abort paths** in `genesis/`, one single-entry log each. Two of them are step 7's two halves: `18-bootstrap-sigs-wrong-role` varies the **role string** a signature declares, `19-bootstrap-sigs-from-signers` varies the **key set** it resolves against — signed only by keys the body lists under `signers`, each line declaring `root`. Step 6 requires the two sets disjoint, so a reader that bootstrap-resolves against `signers` too admits a network this one aborts on (cold gate run 10, D15) |
| §5.1 seen set, §4.3 roles | — | `bad-repeat-of-rejected`, `bad-one-of-two-signers`, `bad-role-mismatch`. Step 1's two stated properties are `bad-repeat-of-undecodable` (the hash is recorded **before** the entry is decoded, so a copy of one that never decoded is `dup-entry` and not a second `decode`) and `bad-repeat-of-genesis` (entry 0's hash is recorded too, so a byte copy of it is `dup-entry` and not `dup-genesis`) |
| §5.2 `bad-thr` | — | both halves: `bad-thr-zero` and `bad-thr` (value above the set size) |
| §5.1 a `policy` entry is a policy | `policy-rotated`, which raises the quorum from 2 of 3 to 3 of 3 | `bad-policy-unparseable`: text that is well-formed, under the size cap, and not a `tlog-policy` |
| §4.3 `revoke`'s three authorisations | `revoke-by-roots`, `revoke-self-laptop` (the device authorising its own revocation, and the only signature on it) | `bad-revoke-neither-quorum`: one signer of two and two roots of three — short on every rule independently, and a quorum only if the counts are pooled |
| §5.1 `params`: non-empty, §4.5 keys, right types | `params` entries in the log | `bad-params-empty`, `bad-params-unknown-key`, and `bad-params-wrong-type` — a CBOR `true` where a uint belongs, which a loose decoder reads as 1. The same key rule at entry 0 is `genesis/13-params-unknown-key`, where the two readings differ by the whole log: one aborts to the zero state, the other replays every entry |
| §14.1 key order above the BMP | `enroll-astral-labels`, whose labels carry one astral key and one private-use key: the only pair in the suite where UTF-8 bytewise order and UTF-16 code-unit order disagree | — |
| §5.3 state, incl. D-028 and `expires` | `state.json`, `enroll-contractor` | `signer_remove-below-threshold` accepted, then `signer_add-recover` |
| §5.3 a witness counts at its **newest** verifying line | `served-twice-cosigned/`: one witness answers twice and both lines verify, so the head is valid and only the tie-break decides. `cases.json` records the instant it must come out at, and the one an oldest-line reader would get instead | `checkpoints-bad/12-second-line-from-one-witness` cannot pin this — its second line does not verify, so §10's per-line rule refuses the checkpoint first |
| §5.3 the derivation of `T` | `served/checkpoint`, whose three witnesses cosign seven seconds apart, so the **newest** and the **oldest** are both separated from the answer; `proofs/cases.json` records the value `T` must come out as | — |
| §5.3 evaluation time | `proven/cases.json`: the admitted set at four values of `T` — no clock, before, **exactly at**, and after the one deadline the fixture carries. `state.json` is clock-independent by design, so this is the only vector that exercises expiry | the `at-the-deadline` case, where `expires == T` and the device is **out** |
| §7 receipt | `receipt.note` | — |
| §7 the note framing | `served/checkpoint` | `checkpoints-bad/13-ascii-dash-signature` (an ASCII hyphen for §7's em dash), `14-unterminated-signature-block` (the final line does not end in a newline), `15-size-leading-zero` (a size line that is not canonical decimal) and `16-two-log-signatures` — two lines under the log's key, one forged. **This implementation accepted the last two** until run 8 asked for them |
| §9.1 a verifier key's id binds its name, key and algorithm | `trust.cbor` | `37-log-key-id-mismatch`: the right name, the right key, the right algorithm and one hex digit of the id changed |
| §5.1 an empty log | `log-empty/`: the zero state, `rejected` empty | a reader that treats *no* genesis as a *missing* one reports `bad-genesis` and differs by a whole field |
| §9.1 and §11.1's byte caps | — | `trust-bad/38-oversize`, padded with **valid** `log_urls` whose count nothing bounds, and `fork/bad-oversize`, padded through a `witness` URL the policy grammar does not bound. Each is correct in every other respect, so only its size can refuse it, and each is refused **on length** before anything it declares is allocated |
| §9.1 `anchor` is OPTIONAL | `trust-good/no-anchor` — **accepted**. Every other trust file in the suite carries one, so a reader that required it rejected nothing | — |
| §9.1 the members the table shows and never constrained | `trust-good/witness-without-url` and `trust-good/anchor-unknown-type`, both **accepted**: a reader that requires an optional member refuses files this document allows | `31-witness-open-schema`, `32-witness-name-too-long` (renamed in the policy too, so correspondence holds), `33-log-url-empty-string`, `34-anchor-missing-member`, `35-anchor-unknown-mode` and `36-policy-log-key-mismatch`. An unknown anchor **type** is ignorable — anchoring is advisory (D-009) — where an unknown **mode** is not |
| §9 trust file, fingerprint | `trust.cbor` | **38 rejected anchors** in `trust-bad/`. **`15`** and **`16`** parse cleanly as verifier keys and are refused only by the algorithm rule; **`17`** and **`18`** are a witness the policy never names and a policy naming a witness the file does not list, each otherwise perfectly valid |
| §9.1 four rules that another rule used to decide | `trust.cbor` | `26-name-too-long` and `27-name-empty` (both ends of the 1–64 byte bound; `14` covers absent), `28-empty-log-urls` (present and empty, which is a different path from absent), `29-no-witnesses-only` — whose policy is `quorum none` and names no witnesses either, so the correspondence rule agrees and only the "a file with no witnesses MUST be rejected" minimum can refuse it — and `30-duplicate-witness-name-only`, which lists all three witnesses *and* a byte-identical second `pi`, so the names and keys correspond exactly and only uniqueness is broken |
| §9.1's three MUSTs about the **log key** | `trust.cbor` | `11-log-key-name-mismatch` (the note name is not `origin`), `13-origin-only` (`origin` is not `norn/` + base32(`net`)) and `16-log-key-is-a-cosignature-key`. Each carries its damaged key in its **policy** as well, so the `log`-line correspondence rule agrees and only the rule the case is named after can refuse it. Without that, all three rules were deletable one at a time with the whole suite still green, and `04-origin-mismatch` — which breaks two of them at once — hid the fact (cold gate run 10, D12) |
| §14 canonical JSON | every `.json`; `enroll-astral-labels`, whose `escapes` label carries every row of §14.2's tables into `state.json`, and `enroll-unicode-labels` | — |
| §10 a bad cosignature is refused, not merely uncounted | `served/checkpoint` | `checkpoints-bad/11-forged-cosignature-with-quorum`: three named witnesses, two verifying, so the quorum is met without the third and §10 refuses it anyway. `08` cannot tell the two readings apart, because one valid line falls short either way |
| §10 the rule is per **line**, not per witness | `served/checkpoint`, one line per witness | `checkpoints-bad/12-second-line-from-one-witness`: all three verify and `friend` carries a second, newer line that does not. A reader taking each witness's newest *verifying* line sees a full quorum. `11` cannot stand in — there the bad line's witness has no good line, so declining to count it still leaves a quorum of two |
| §11.1 the proof is empty at the held size | `fork/evidence.cbor` uses the non-degenerate branch | `fork/bad-proof-at-same-size`: a consistency proof where the two signatures say it alone |
| §8.1 and §11.1 are closed maps, versioned, and bounded | `proofs/`, `fork/evidence.cbor` | `proofs-bad/open-schema` and `wrong-version`; `proofs-bad/device-not-in-entry`, where the proof, the entry and the checkpoint are all honest and only the **label** beside them is another device's — an inclusion proof binds the entry to the log and says nothing about a label. For evidence: `fork/bad-open-schema`, `bad-wrong-version` and `bad-size-above-held`, because an accuser can only speak for sizes its own branch reaches. **This implementation left the evidence map open and the device unbound** until run 8 asked |
| §11.1 the carried `policy` decides nothing | `fork/policy-not-the-readers.cbor`: sound evidence whose `policy` requires a witness that cosigned nothing — it MUST still prove the fork, because the reader verifies under its own | `fork/bad-policy-says-quorum-none`: two checkpoints no quorum cosigned, and a carried policy saying none is needed. A reader that trusts the field concludes a fork any stranger can write, and §11 rule 4 makes it permanent. `fork/bad-policy-unparseable` is the format half |
| §6 tiles and bundles | `served/`, read back to reproduce `state.json`; a forged head is `checkpoints-bad/04-forged-log-signature` and a fourth body line is `checkpoints-bad/09-extension-line` | `served-bad/`: an entry bundle with one byte changed, one the log will not serve at all, `tampered-hash-tile` — one byte inside one leaf hash, which leaves the entries and the signed head honest, so only the hash-tile rule can refuse it — and `consistent-tampered-log`, where the bundle and the level-0 tile are changed **together**. That last one is the only file that reaches the rebuild-and-compare rule: the other two tamper cases change a leaf hash as a side effect, so the tile rule refuses them first and a reader that never compares the rebuilt head with the checkpoint passed everything (cold gate run 10, D11). `checkpoints-bad/17-root-wrong-length` is the root line's own negative |
| §6 the anchor digest | `anchors/cases.json` names the bytes and gives the digest, and `checkpoint-<size>.ots` chains from it. Anchoring is **advisory** (D-009), so a reader computing one of the two neighbouring byte ranges — the three-line body, or §7's signed text — never matches a stamp and never reports one, which is why the range is stated in hex rather than in a word both bullets use | no negative: a proof over the wrong digest simply fails to chain, and the failure is indistinguishable from an anchor for another tree. Run 11's `OTSDigestSignedText` variant is caught by the digest comparison alone |
| §7 note framing, the three splits a file can separate | `served/checkpoint` and `receipt.note`, both read with these rules | `checkpoints-bad/18-signature-name-with-space` (split at the first space or the last), `19-signature-unpadded-base64` (standard base64, padded) and `20-signature-payload-too-long` (the payload is **exactly** 68 or 76 bytes, never a prefix of something longer). Each is the honest checkpoint with one signature line rewritten, so the line is well-formed under the lax reading and malformed under this document's. The other two splits — a blank line inside the text, and a note with no signature lines — are in **What is not vectored** below |
| §8.1 a bundle's checkpoint is checked per §10 | `proofs/`, whose checkpoints carry the quorum | `proofs-bad/no-quorum` (the log's signature and nobody else's) and `proofs-bad/wrong-origin` (this network's key over another network's origin line) |
| §8.1 condition 3, the key a node installs | `proofs/cases.json`'s `installs`: for every device, the `wg_pk` replay gives. `nas` rotated after it enrolled, so `proofs/nas.bundle` proves an entry naming a key `nas` no longer uses and `installs` names the other one. A reader that requires the bundle's key to match installs nothing for `nas` (cold gate run 11, D14) | — |
| §8 proof bundles | `proofs/`, one per active device | `proofs-bad/`, **9 proof refusals**: a wrong entry, a foreign checkpoint, a tampered proof, a checkpoint signed by a key the anchor does not name, one with no witness quorum and one whose checkpoint names another origin — each differing from a valid bundle in exactly one thing |
| §10 the signature decides before the origin | — | `proofs-bad/foreign-checkpoint` MUST be refused about "no valid signature from a trusted key" and `proofs-bad/wrong-origin` about "is for origin". A reader that checks the origin first reports the wrong one for the first of them |
| §10 verifier loop, steps 1–4 | `served/` verified end to end, **signature first** | `checkpoints-bad/01-unsigned`, `02-wrong-log-key`, `03-wrong-origin` and **`04-forged-log-signature`** — the last one being a signature of the right shape under the right key id that does not verify. Without it a verifier that never checks the log signature reproduces the whole suite |
| §10 step 3, the witness quorum | `served/checkpoint`, cosigned by all three witnesses | `checkpoints-bad/05-one-cosignature-short`, `06-no-cosignatures`, `07-unnamed-witness-only` and **`08-forged-cosignature`**, which carries two lines naming witnesses the policy lists, one of which does not verify: the quorum is met by counting and refused by checking. `quorum none` accepting an uncosigned head needs a second anchor and is **not vectored** |
| §10 step 3, **which** lines count as a listed witness's | `served-extra-witness/` (an unlisted **name**) and `served-name-collision/` (a listed name under an unlisted **key id**) — both MUST be accepted, and the second is the only file that separates matching on the name alone from matching on name and key id. Run 10's `V236_CosigNoKeyIDMatch` passed 236/236 without it | the negatives are `checkpoints-bad/08-forged-cosignature`, `11-forged-cosignature-with-quorum` and `12-second-line-from-one-witness`, where the line's name *and* id are the policy's and the signature is not |
| §16 enrollment requests | `requests/`, **5 request cases** including a 64-byte `device_id`, non-ASCII labels and an uppercase text form | `requests-bad/`, **25 request refusals** across all four layers, including **`forged-signature`** (structurally perfect, signed by another key) and `oversize-label-key` (§4.0's map-key cap) |
| §11.1 fork evidence | `fork/evidence.cbor` and `fork/conflicting.checkpoint`: a second branch of this same network, diverging at entry 40, signed by the same log key and cosigned by the same witnesses. Checking it needs only `trust.cbor` | one per reader step: `fork/bad-other-origin` and `fork/bad-unverifiable-conflicting` (step 1, each half), `fork/bad-size-mismatch` (step 2), `fork/bad-forged-proof` (step 3 — both checkpoints verify and the sizes agree, so nothing but the proof can refuse it), and `fork/bad-consistent` (step 4: a log and its own earlier self) |
| §16.1's `expires > ts`, at the entry layer | every `enroll` | `bad-enroll-request-expires-at-ts`: an entry whose embedded request breaks §16.1. The only other vector for the rule is a *request*, and an `enroll` decodes its request under §16.1 too |
| §4.0's map-key cap in **bytes** | `entries-hostile/at-the-key-limit`: 23 bytes and 12 characters | `past-the-key-limit` is 24 bytes and 13 characters. Both were ASCII until run 9, so "23 bytes" and "23 characters" gave the same answer everywhere |
| §10 a reader that does not hold `at` | — | `detect/shorter-with-no-held-branch`: the same served branch as the fork case, read by a node holding the stored head and **not** the entries. It refuses and MUST NOT accuse. Inside §10's own loop the node always holds `at`; this clause is for a monitor handed a checkpoint, or a node restarted from its stored one |
| §10 a line the reader does not know | `served-extra-witness/`: the honest head plus one more line, from a witness the policy never names and the trust file does not list. It verifies under its own key, counts for nothing, and the head MUST be **accepted** | `07-unnamed-witness-only` cannot pin this: it is refused for want of a quorum either way, so it separates nothing |
| §8.1 `S_hard` unconfigured | `detect/staleness.json`'s `unconfigured-hard-stays-degraded` and `-still-fresh`, which carry `hard: 0` | every other case carries 3600, so a reader that read 0 as a limit of zero passed while dropping every peer — the outcome the asymmetry exists to prevent |
| §8.1 the freshness table is read in order | `detect/staleness.json`'s `hard-below-staleness-still-fresh`: `hard` 700, `staleness` 900, `elapsed` 800, where `fresh` and `hard_stale` both hold and only the order decides. `-past-staleness` is the same node at 901, which goes straight to `hard_stale` | every earlier case had `hard` above `staleness`, where the two rows cannot overlap, so a reader testing `hard_stale` first passed the whole suite (cold gate run 11, D1) |
| §9.1 what a quorum **means** | the `evaluate` tables in `policies/cases.json`: a set of cosigner names and whether they satisfy the policy. `nested-group` is the one that separates a nested group from a flattened one — `outer` is `all` of **one** member, and that member is `any` of two, so `pi` alone satisfies it and a flattening reader needs both | `bad-duplicate-member` (met by one witness), `bad-k-zero` (met by **nobody**, so an uncosigned head passes) and `bad-k-leading-zero`. Parsing alone could not reach any of the three |
| §9.1 the restated `tlog-policy` grammar | `policies/minimal`, `no-trailing-newline`, `blank-and-whitespace-lines`, `comment-and-indent`, `comment-tab-indented`, `witness-url-fragment`, `nested-group`, `no-log-line`, `two-log-lines` (the grammar allows more than one) and `nbsp-is-content` (U+00A0 is outside the closed set, so it is content) | `bad-vertical-tab`, `bad-form-feed`, `bad-carriage-return`, the same three `-in-url`, `bad-extra-field`, `bad-trailing-comment`, `bad-duplicate-name`, `bad-duplicate-key`, `bad-log-key-as-witness`, `bad-forward-reference`, `bad-two-quorums`, `bad-no-quorum`, `bad-empty-group` (refused by the **field count**, which is the only rule that requires a member), `bad-unknown-keyword` and `bad-quorum-undefined`. Run 8 flipped nine readings of this grammar and all nine passed without these. Each of the three error characters ships **twice**, because one placement rules out only one lax reading: between `quorum` and `pi` a reader that splits on it parses, and inside a URL a reader that keeps it as content parses. The first placement alone let the content reading through (cold gate run 10, D9; run 11, D12). The key rule has two negatives because it spans directives: a reader that checks it between `witness` lines only refuses `bad-duplicate-key` and accepts `bad-log-key-as-witness` (run 11, D2) |
| §16.2 bech32m | the text form of every request, and `requests/req-minimal-upper` — the same request in the all-uppercase form §16.2 says a reader MUST accept, which is the one *positive* obligation the section carries and the form a QR code produces | `wrong-hrp`, `plain-bech32` (the same bytes under bech32's constant), `mixed-case`, `corrupt-character`. BIP-350's own vectors are in both implementations' unit tests |

**What is not vectored.** A suite that looks complete is worse than one that
admits its holes, so:

- **`quorum none` accepting an uncosigned head.** It needs a second trust
  anchor, and one is not shipped.
- **§4.3's "a key contributes at most once".** `sigs` is sorted by `kid` with
  no repeats (§4.1), and `kid` is `SHA-256(pk)[0:8]` — a function of the key —
  so one key cannot appear twice in one entry and the de-duplication in
  signature counting never fires. Confirmed by deleting it: every check stays
  green. It is written down because a reader who counts signatures without it
  is relying on a rule two sections away, and that is worth saying once.
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
- **A **blank line inside a note's text**, as distinct from the one that ends
  it.** §7 says the first blank line ends the text because text lines are
  non-empty; a reader that took the *last* one would sign a different string.
  Every note text in Norn is a checkpoint body (three lines, §6) or a receipt
  (four, §7), so a text carrying a blank line has the wrong line count under
  **both** readings and is refused either way. Separating them needs a note
  whose text is valid with a blank line in it, which this protocol has none of.
- **A note with no signature lines.** §7 requires at least one, and so does
  §10 — "at least one such line MUST be present" — and §10's check is reached
  first, so a checkpoint with an empty signature block is refused before the
  framing rule applies. No artifact tells a reader that enforces both from one
  that enforces only the second.
- **§10's "the root the SERVED branch has at `at` … recomputed from the
  entries, **never from a supplied proof**".** No shipped file supplies one: a
  `detect/` pair serves both branches with their own tiles, so a reader takes
  the root from the entries because there is nothing else to take it from. The
  clause is a real rule about a real attack — a peer that offers a proof of a
  root its entries do not produce — and nothing here distinguishes a reader
  that honours such a proof from one that ignores it. Reaching it needs a
  served log that carries a proof, which `tlog-tiles` does not serve.
- **The median, as distinct from the k-th newest.** With three witnesses and a
  threshold of two they are the same timestamp, so no reading of the fixture
  tells them apart. Separating them needs a fourth witness, which this network
  does not have.
- **§16.1's 32-byte `device_pk`, independently.** `requests-bad/short-device-pk`
  is refused by that rule, and a verifier that skipped it would fail anyway: a
  31-byte key verifies nothing. No construction separates the two, so the rule
  is refused-but-not-pinned, which is different from covered.
- **§5's `state.net` coming from the anchor rather than from the genesis
  entry.** Unobservable: entry 0 aborts whenever the two differ, so no file can
  tell the two readings apart. Recorded here because a reader will look.
- **`entry_hash` being over the bytes *as received* rather than a
  re-canonicalised form.** §5.1 step 1's *ordering* is vectored — a copy of an
  entry that never decoded is `dup-entry` — but the received-versus-recanonical
  half cannot be: the only entry whose raw bytes differ from its canonical form
  violates §4.0, and is `decode` at step 2 before any hash of a canonical form
  could be taken. `60-bad-trailing-byte` is caught by the whole-input rule, not
  by the hash.
- **`MAX_ENTRY_BYTES` applied to an embedded request, as distinct from the
  entry.** §4.0 requires both, and a request travels *inside* an entry — so a
  request over the cap implies an entry over the cap, and the entry rule
  refuses it first. The two can never disagree, and no file can show the
  request rule doing the work.
- **`MAX_BUNDLE_BYTES`, as distinct from the other two byte caps.** A valid
  bundle has no slack: `device` is bound to the entry, `entry` fixes the leaf
  hash, `checkpoint` and `proof` are what they are, and `v` is 1 — so an
  oversize bundle is necessarily wrong in a second way, and a reader without
  the cap refuses it for the inclusion proof instead. The trust file and
  evidence caps *are* vectored, because each has one field that grows while
  staying correct. The cap still belongs in §8.1: it is there to stop an
  unbounded parse of hostile input, which is exactly the input no valid vector
  can be.
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
- **§9.1's witness-name uniqueness, for a reader whose correspondence check
  strikes each name off as it matches.** Such a reader refuses
  `30-duplicate-witness-name-only` at the correspondence step and so passes the
  whole suite with no uniqueness rule at all. §9.1 says the correspondence is
  on the **set** of names precisely so that reader is non-conforming — but the
  vectors cannot tell it apart from a conforming one, and no construction
  separates them, because a policy cannot name the same witness twice.

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

## 13. Open items

None. The one item this section carried — that `enroll` required a device
signature the device could not produce — was closed by giving `enroll` a
`request` body: the device signs its **own** request (§16.1), the signer
embeds it verbatim, and the entry carries the device's consent without the
device ever seeing the envelope. §4.3 and §5.1 are written that way, and
`requests-bad/` vectors the refusals.

Sections that describe something deliberately **not** in v1 say so where they
are, rather than here: paper roots (`ENROLLMENT.md` tier 3), multi-log
validity (D-009's O2), and policy transparency are named in `PLAN.md`'s
stretch list.

The verifier hands the enforcer an in-memory proven set and mirrors it to
`/run/norn/proven.json` (schema in `ENFORCEMENT.md` §9). Modes, backends, the
reconciler and failure semantics are normative in `ENFORCEMENT.md`.

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

Checkpoint acquisition order, the witness-time clock and the peer gossip
endpoints are normative in `GOSSIP.md`. The **freshness states themselves are
§8.1 of this document**, with `detect/staleness.json` as their table: they
decide what a node reports about a checkpoint it has, so a reader holding the
specification and the vectors must not need a second file to reproduce them. The **fork evidence format is §11.1 of this document**: it is the
one artifact a stranger is asked to check, so it may not live in a file that
does not ship beside the vectors. The policy text in `norn.trust` is verbatim
`c2sp.org/tlog-policy`.

## 16. Enrollment requests and key handling

An **enrollment request** is what a device hands a signer: *this is the name I
claim, this is the WireGuard key I want in the peer table, and here is a
signature by my device key.* It is not a log entry, but it does reach the log:
an `enroll` entry carries it **verbatim** as its whole body, and that is where
the device's consent lives (§4.3). It exists so that the `enroll` entry a signer
builds can carry a `device_pk` the device has demonstrably used, and so that the
whole exchange fits through a phone camera (`ENROLLMENT.md` part 3).

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
| `labels` | map text→text | | as `enroll` (§4.3), under the same §4.0 caps |
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
to a human. `ENROLLMENT.md` part 7 rule 1 is *what you sign is what you see*, and a
request displayed before its signature is checked is a request an attacker
chooses the text of.

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

### 16.3 Key handling

Signing keys are reached through the **ssh-agent protocol** (Ed25519 only in v0),
so hardware tokens, password-manager agents and software keys all look identical
to `norn sign`. Tiers, the root ceremony, rotation and the recovery runbooks are
normative in `ENROLLMENT.md`, as are trust-file bootstrap and the `log_key` /
`policy` overlap rules.
