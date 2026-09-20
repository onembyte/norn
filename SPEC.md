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
- RFC 8949 §4.2.1 — deterministic CBOR ("core deterministic encoding")
- RFC 8032 — Ed25519 · RFC 7748 — X25519

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
| `origin` | `norn/` + **RFC 4648** base32 of `net_id`, lowercased, padding stripped | checkpoint origin line; the log key's signed-note name MUST equal it. Note this document also uses *Crockford* base32, in §9.3 only — they are different alphabets. |
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

All Norn **CBOR** structures — entries, enrollment requests and trust files —
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
| Maps | definite length; keys sorted as §4.1; no duplicate keys; unknown keys → reject |
| Arrays | definite length |

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

A decoder MUST bound its own resource use. Two limits, both normative:

- **Nesting depth is at most 8.** The top-level map is depth **1**, so a value
  inside it is depth 2. An `enroll`'s embedded request (§16.1) is a byte string
  whose contents are parsed separately, and its own nesting **restarts at 1**:
  the two documents are decoded by two calls, and a limit that leaked across
  them would make an entry's validity depend on the shape of something it
  merely carries. The deepest structure the entry schema itself allows is a
  request's `labels` value, at depth 3 of that inner document.
- **`MAX_ENTRY_BYTES` is 65535**, and an entry is at most that many bytes. Not
  65536: §6 frames entries in `tlog-tiles` entry bundles behind a **uint16**
  length prefix, so 65535 is the largest entry that can be served at all. A
  limit above it would admit an entry that is valid and unpublishable, and an
  encoder that truncated the length to fit would produce a bundle that decodes
  as a different log.

Neither limit is reachable by a valid entry; they exist so that a hostile input
cannot exhaust a verifier, and both are vectored in `entries-hostile/`.

The `sigs` key is **mandatory**; an entry with no signatures carries `sigs: []`,
which is well-formed and is rejected later by an authorisation rule rather than
by `decode`. Which rule depends on the type: `threshold` for `note` and the
governance types, but **`no-device-sig`** for `enroll` and `rotate`, whose first
step-8 check is the device signature (§5.1). `role` is a
**closed enum** — a value outside `root` / `signer` / `device` is a schema
violation and rejects the entry with `decode` (D18). This is distinct from §5.1
step 7, where a *well-formed* signature whose `kid` does not resolve in that role
is silently not counted.

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
| `enroll` | `request` (bytes — a §16 enrollment request, verbatim) | ≥ `signer_thr` signers. The device's consent is the **embedded request**, not a signature on this envelope (§4.3) |
| `rotate` | `device_id`, `wg_pk` (new), `device_pk` (new, OPTIONAL) | the *current* device key; **and the incoming `device_pk` too when the body carries one** (proof of possession, D-032); plus ≥ `signer_thr` signers if `params.rotate_needs_signer` |
| `revoke` | `device_id`, `reason` (string, **OPTIONAL** — absent is equivalent to `""`) | ≥ `signer_thr` signers, **or** the device itself, **or** ≥ `root_thr` roots |
| `signer_add` | `pk` | ≥ `root_thr` roots |
| `signer_remove` | `kid` | ≥ `root_thr` roots |
| `signer_thr` | `thr` (uint) | ≥ `root_thr` roots |
| `root_add` | `pk` | ≥ `root_thr` roots |
| `root_remove` | `kid` | ≥ `root_thr` roots; MUST leave ≥ `root_thr` roots and ≥ 1 root |
| `root_thr` | `thr` (uint) | ≥ `root_thr` roots (the *old* threshold) |
| `params` | partial §4.5 map | ≥ `root_thr` roots |

`thr` is a plain uint **here**, deliberately. Its range — `1 … len(set)` — is a
**replay** decision, not a schema one (§5.2's `bad-thr`): the value is a
well-formed uint either way, so an implementation that enforced `≥ 1` as a
field constraint would return `decode` where `bad-thr` is required. `log/61-bad-thr-zero`
and the value-above-the-set case vector both halves.
| `note` | `text` (string ≤ 4096) | any 1 signer or root; **no state effect** |
| `log_key` | `pk` (bytes32), `overlap` (uint s) | ≥ `root_thr` roots — log-key rotation; both keys valid for `overlap` (`ENROLLMENT.md` §6) |
| `policy` | `text` (verbatim tlog-policy) | ≥ `root_thr` roots — replaces witness policy in state |

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
than one way, so the first matching step decides the reason code.

Replay of an **empty** list of entries yields the zero state of §5.3 with
`size` 0 and `rejected` empty: there is nothing to reject.

**Entry 0 (genesis).** In order:

1. `entry_hash` is recorded as seen.
2. Decode per §4.0 and check the envelope per §4.1. Any failure → **abort** (`bad-genesis`).
3. `t` MUST be `genesis`, and `net` MUST equal `anchor.net` → else **abort** (`bad-genesis`).
4. `leaf_hash` MUST equal `anchor.genesis_hash` → else **abort** (`bad-genesis`).
5. `after`, if present, MUST be 0 → else **abort** (`bad-genesis`).
6. Body checks: `roots` and `signers` are non-empty arrays of distinct 32-byte
   keys, disjoint from each other; `1 ≤ root_thr ≤ len(roots)`;
   `1 ≤ signer_thr ≤ len(signers)`; `params`, if present, has only §4.5 keys.
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
| `policy` | body well-formed and closed (`decode`) · `text` ≤ 4096 bytes (`decode`) | replace `policy` |
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

Signature counting, precisely: a signature `{kid, role, sig}` is *valid* iff the
state before this entry maps `kid` to a key **in that role** (for `device`: `kid`
equals `kid(device_pk)` of the device this entry names — for `enroll`, the
`device_pk` in the body) and Ed25519 verification of `sig` over the preimage
succeeds. Invalid signatures are ignored, not fatal; only the count of valid ones
per role matters.

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
| `log_keys` | array of `{overlap, pk, since_index}` | one per `log_key` entry, in log order. `since_index` is the **index of that `log_key` entry** — not a log size, not the index from which the key becomes valid. The trust file's initial log key is **not** listed: it is not in the log. |
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
after it satisfy the policy (§9). A `tlog-checkpoint` body carries no timestamp
of its own — the `tlog-cosignature` lines are the only timestamps in the
artifact, and `T` is the only value derived from them.

A device is expired exactly when `expires != 0 && expires <= T`; an `expires`
equal to `T` **has** passed. When the policy is satisfied at no instant — which
includes `quorum none`, where nobody vouches for the time either — there is **no
clock**, and expiry is not judged at all: the device keeps the status replay gave
it. Norn fails towards the last state a quorum vouched for, rather than dropping
devices on a number nobody signed.

## 6. The log

- Layout, tiles, entry bundles, and `checkpoint` exactly per `tlog-tiles`. Tile height 8 (width 256), as torchwood requires.
- Leaf hash = `H(0x00 ‖ entry_bytes)` (RFC 6962 §2.1). Entry bundles are uint16-length-prefixed entry bytes.
- The checkpoint is a `tlog-checkpoint` note: `origin` line = §2 `origin`, size, root; **no extension lines**. Signed by the log key; cosigned by witnesses per `tlog-cosignature` v1.
- The log MUST issue a new checkpoint after every append and at least every `checkpoint_interval`.
- **Log operator validation is optional and non-binding.** A log SHOULD refuse entries that fail §5 against its own replay, to keep the log tidy — but verifiers MUST NOT rely on it (`THREAT-MODEL.md` G3).
- Additional paths (Norn-specific, ignored by generic tooling):
  - `<prefix>/add` — submission (§7)
  - `<prefix>/anchors/<size>.ots` — OpenTimestamps proof for the checkpoint at `size` (D-009; advisory). The stamped value is `SHA-256` of the checkpoint **body** — the note text up to and including the blank line, without any signature lines. Not the signed note: cosignatures are appended as witnesses answer, so a note-level digest would stop matching the moment one replied — and the log's signature adds nothing to a claim about *when* the tree existed, since the log is the party the anchor exists to constrain.
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
  the last text line. It does **not** include the blank separator line.
- The text is followed by one blank line, then one signature line per signer.
- A signature line is `\u2014 ` (em dash U+2014, then one space), the key name, one
  space, then base64 of `key_id ‖ signature` — 4 + 64 = 68 bytes.
- `key_id` = `SHA-256(name ‖ 0x0A ‖ alg ‖ pk)[0:4]`, with `alg` = `0x01` for Ed25519.
  Note that the key id binds the **name**, so the same key under two names has two ids.
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

Checking a bundle: verify the checkpoint note under `norn.trust.log_key`;
confirm `SHA-256(0x00 ‖ entry)` and `proof` reach the checkpoint's root at
`index` for that size; then apply the rules below.

> **This is Norn's own format, and v1 says so rather than deferring it again.**
> The shape is the same as `c2sp.org/tlog-proof` — checkpoint, index, inclusion
> proof — and byte compatibility with it was never established, so v1 does not
> claim it. A later version may adopt that format outright; what it may not do
> is what earlier drafts did, which is name a specification the bytes had never
> been checked against.

A node MUST treat a peer as proven only if:

1. the bundle's checkpoint verifies under the node's trust policy (§9), and
2. the bundle's checkpoint is consistent with the node's stored checkpoint, and
3. replay of the log up to that checkpoint yields the device as `active` with that `wg_pk`, and
4. the checkpoint is not stale (part 6).

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
| `log_urls` | array of text, ≥ 1 | where to fetch checkpoint and tiles |
| `witnesses` | array of `{name, key, url?}`, **≥ 1** | `key` is a **cosignature** verifier key — `c2sp.org/tlog-cosignature` algorithm `0x04`, not a note key's `0x01` — and MUST parse as one; `name` unique within the file. The algorithm is part of the key id, so the same public key published under the two algorithms is **two different verifiers**: a file naming a witness with a note key names a key no witness will ever sign with. A file with no witnesses MUST be rejected: with nothing to cosign, the policy's quorum can never be met, so the anchor could never accept a checkpoint. |
| `policy` | text | verbatim `c2sp.org/tlog-policy`; MUST parse, and MUST name **exactly** the witnesses `witnesses` lists, with the same keys. The two are not redundant: `witnesses` is where a node learns a witness's name and address, `policy` is where it learns whether that witness counts — so a file where they differ configures a quorum over parties the node cannot reach, or lists parties nothing requires, and either way the operator believes they set something they did not |
| `anchor` | `{type, max_lag, mode}`, OPTIONAL | `type` text (`"opentimestamps"`), `max_lag` **uint seconds**, `mode` text (`"advisory"`) |

Unknown keys MUST cause rejection. The fingerprint (§9.3) is taken over these
bytes, so a wrong field name or type changes it.

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

### 9.2 TOML rendering

```toml
# Norn trust file for norn-testnet
# fingerprint = YV05-H4J9-MA1G-P8V2
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
four joined by `-` (U+002D): `YV05-H4J9-MA1G-P8V2` (D-029). The
`trust.fingerprint` file holds exactly that string followed by one `0x0A`.

80 bits is chosen so that an attacker who controls the delivery channel (threat
A10) cannot grind a substitute trust file with a matching fingerprint.

`nornd` MUST refuse to start without a trust file and MUST refuse one whose
`genesis_hash` does not match entry 0.

## 10. Verifier procedure (normative outline)

```
loop every T_g or on demand:
  cp := fetch checkpoint (log_urls, then peers)         # part 6
  verify log signature (torchwood VerifyCheckpoint)
  verify witness policy: every cosignature by a witness the policy names
      must verify, and the quorum must be satisfied  # refuse otherwise
  if stored_cp exists:
      require cp.size >= stored_cp.size    # an earlier view undoes every
                                           # revocation made since, and is
                                           # signed and cosigned correctly
      require the head this log had at stored_cp.size == stored_cp.root
                                           # a node holds every entry, so it
                                           # recomputes this rather than
                                           # trusting a supplied proof
      on mismatch → FORK (§11)
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
| `proof` | array of bytes (32 each) | consistency proof chaining (`size`, `held_root`) to `held`'s own head. **Empty when `size` equals `held`'s size**, where the two signatures say it alone |
| `policy` | text | the network's `tlog-policy` at the time, so a reader can see which witnesses were meant to prevent this |

A reader MUST, in this order:

1. verify **both** checkpoints per §10 — this network's origin, this network's
   log key, and a satisfied witness quorum. A log signing two heads by itself
   is a log misbehaving in private; what makes a fork provable to a third party
   is that independent witnesses vouched for **both**.
2. check `conflicting`'s size equals `size`,
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
| `log/NN-<name>.cbor` | the replay fixture, **97 entries** in order. The file names are labels, not the order: **read the sequence from `manifest.json`**, never by globbing and sorting |
| `log/NN-<name>.reason` | beside each entry that must be rejected: its §5.2 reason code |
| `log/manifest.json` | `{"anchor": {"net", "genesis_hash"}, "entries": [{"index", "name", "reason"}]}` — the replay input and expected outcome; `reason` is `""` for an accepted entry |
| `state.json` | canonical replay output for `log/` (§5.3) |
| `genesis/<NN-case>/` | one single-entry log per way entry 0 can abort, each with its own `manifest.json` and `state.json`; an abort stops replay, so the cases cannot share a log. `cases.json` lists them |
| `trust-bad/<NN-case>.cbor` | trust files that decode cleanly but MUST be rejected as anchors; the file name says why, `cases.json` lists them |
| `served/` | the fixture's entries as a real **tlog-tiles directory**: `tile/entries/…` bundles, `tile/<L>/…` hashes, and `checkpoint` — which **is** the signed note (§6), not an unsigned file with a signed sibling |
| `proofs/<device>.bundle` | one §8.1 proof bundle per active device, each proving the entry that made that device active; `cases.json` gives the origin, the log-key seed and the device list |
| `trust.cbor` · `trust.toml` · `trust.fingerprint` | the trust anchor (§9), authoritative bytes, human rendering, and its fingerprint |
| `receipt.note` | a submission receipt: the signed note itself (§7) |
| `requests/<name>.cbor` · `.txt` · `.json` | enrollment requests (§16): the request bytes, its bech32m text form, and a mirror `{request, preimage_sha256, text, size}`. `cases.json` lists them |
| `requests-bad/<name>.txt` | requests that MUST be refused — by the text layer, the CBOR profile, a field rule or signature verification. `cases.json` gives each case's reason |
| `receipt.json` | `{comment, origin, leaf_hash, deadline, text_sha256}`, where `text_sha256` is `SHA-256` of the **signed text** — through the newline ending the last text line, excluding the blank separator and the signature lines |
| `checkpoints-bad/<NN-case>.checkpoint` | checkpoints that MUST be refused, each served in place of `served/checkpoint` over the honest tiles. `cases.json` lists them and says which two a signature-blind verifier accepts |
| `entries-hostile/<name>.cbor` | input that is not an entry and never could be, for §4.0's two resource limits. `cases.json` says what each refusal must be about |
| `proven/cases.json` | the devices admitted at four evaluation times (§5.3), including the boundary where `expires` equals `T` |
| `fork/` | `evidence.cbor` and the `conflicting.checkpoint` it is about (§11.1), plus `bad-consistent` and `bad-other-origin`, which MUST be refused. `cases.json` lists them |
| `anchors/` | OpenTimestamps proofs written by `python-opentimestamps`: `checkpoint-<size>.ots` over the fixture's checkpoint body, `sample.ots` over an arbitrary digest, and a calendar's reply |
| `proofs-bad/<name>.bundle` | bundles that MUST be refused (§8.1); `cases.json` gives the log key to check them under and what each refusal must be about |
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
| §4.0 encoding profile | every entry; controls `profile-base`, `labelcap-base`, `two-sig-base` | `bad-cbor-nonshortest`, `bad-cbor-null`, `bad-cbor-unsorted-keys`, `bad-tag-wrapped-value`, `bad-indefinite-text`, `bad-indefinite-map`, `bad-duplicate-map-key`, `bad-invalid-utf8`, `bad-integer-too-large`. The 23-byte map-key cap moved to `requests-bad/oversize-label-key`: since §4.3 put the device's claims in the request, no *entry* body has a free-form map left, and a closed-schema check would fire first on any other key |
| §4.3 `enroll` embeds the request | every `enroll` in the log; `enroll-unicode-labels`, `enroll-contractor` | **`bad-no-device-sig`** and **`bad-order-enroll`** (a request signed by a *signer*, not the device it names), **`bad-forged-device-sig`** (a request signature of the right shape and wrong), and `bad-device_id-uppercase`, `bad-device_id-leading-dot`, `bad-pk-length` — faults **inside** the request, inside an entry that is otherwise well formed and properly signed, so an implementation treating `request` as opaque bytes accepts all three |
| §4.0/§4.3 schemas | `enroll-laptop`, `enroll-unicode-labels` | `bad-kid-format`, `bad-missing-sigs`, `bad-empty-sigs`, `bad-unknown-role`, `bad-unknown-envelope-key`, `bad-unknown-body-key`, `bad-device_id-uppercase`, `bad-device_id-leading-dot`, `bad-pk-length`, `bad-sig-length`, `bad-text-too-long`, `bad-unsorted-sigs` |
| §4.2 signatures, hashes, preimage | 16 entry mirrors | **`bad-forged-signer-sig`, `bad-forged-device-sig`** — syntactically perfect signatures that do not verify. Without these an implementation that never calls Ed25519 reproduces the whole manifest |
| §4.0 resource limits | — | `entries-hostile/oversize-entry` (a header promising 65536 bytes, refused on length before anything is allocated) and `entries-hostile/deep-nesting` (200 nested arrays, deterministic throughout, so only the depth rule can refuse it) |
| §4.4 `after` is a floor | `after-below-index` | `bad-after` |
| §5 replay, 15 of the 16 reason codes | the log | 51 rejecting entries |
| §5 `bad-genesis` | — | `genesis/`; it cannot appear in the log, since it aborts replay |
| §5.1 genesis | the log's entry 0 | twelve abort paths in `genesis/`, one single-entry log each |
| §5.1 seen set, §4.3 roles | — | `bad-repeat-of-rejected`, `bad-one-of-two-signers`, `bad-role-mismatch` |
| §5.2 `bad-thr` | — | both halves: `bad-thr-zero` and `bad-thr` (value above the set size) |
| §4.3 `revoke`'s three authorisations | `revoke-by-roots`, `revoke-by-device` | `bad-revoke-neither-quorum`: one signer of two and two roots of three — short on every rule independently, and a quorum only if the counts are pooled |
| §5.1 `params` is non-empty | `params` entries in the log | `bad-params-empty` |
| §14.1 key order above the BMP | `enroll-astral-labels`, whose labels carry one astral key and one private-use key: the only pair in the suite where UTF-8 bytewise order and UTF-16 code-unit order disagree | — |
| §5.3 state, incl. D-028 and `expires` | `state.json`, `enroll-contractor` | `signer_remove-below-threshold` accepted, then `signer_add-recover` |
| §5.3 evaluation time | `proven/cases.json`: the admitted set at four values of `T` — no clock, before, **exactly at**, and after the one deadline the fixture carries. `state.json` is clock-independent by design, so this is the only vector that exercises expiry | the `at-the-deadline` case, where `expires == T` and the device is **out** |
| §7 receipt | `receipt.note` | — |
| §9 trust file, fingerprint | `trust.cbor` | 18 rejected anchors in `trust-bad/`. **`15`** and **`16`** parse cleanly as verifier keys and are refused only by the algorithm rule; **`17`** and **`18`** are a witness the policy never names and a policy naming a witness the file does not list, each otherwise perfectly valid |
| §14 canonical JSON | every `.json`; `policy-escaping`, `enroll-unicode-labels` | — |
| §6 tiles and bundles | `served/`, read back to reproduce `state.json`; a forged head is `checkpoints-bad/04-forged-log-signature` and a fourth body line is `checkpoints-bad/09-extension-line` | `served-bad/`: an entry bundle with one byte changed, and one the log will not serve at all |
| §8 proof bundles | `proofs/`, one per active device | `proofs-bad/`: a wrong entry, a foreign checkpoint, a tampered proof and a checkpoint signed by a key the anchor does not name — each differing from a valid bundle in exactly one thing |
| §10 verifier loop, steps 1–4 | `served/` verified end to end, **signature first** | `checkpoints-bad/01-unsigned`, `02-wrong-log-key`, `03-wrong-origin` and **`04-forged-log-signature`** — the last one being a signature of the right shape under the right key id that does not verify. Without it a verifier that never checks the log signature reproduces the whole suite |
| §10 step 3, the witness quorum | `served/checkpoint`, cosigned by all three witnesses | `checkpoints-bad/05-one-cosignature-short`, `06-no-cosignatures`, `07-unnamed-witness-only` and **`08-forged-cosignature`**, which carries two lines naming witnesses the policy lists, one of which does not verify: the quorum is met by counting and refused by checking. `quorum none` accepting an uncosigned head needs a second anchor and is **not vectored** |
| §16 enrollment requests | `requests/`, four cases including a 64-byte `device_id` and non-ASCII labels | `requests-bad/`, 23 cases across all four layers, including **`forged-signature`** (structurally perfect, signed by another key) and `oversize-label-key` (§4.0's map-key cap) |
| §11.1 fork evidence | `fork/evidence.cbor` and `fork/conflicting.checkpoint`: a second branch of this same network, diverging at entry 40, signed by the same log key and cosigned by the same witnesses. Checking it needs only `trust.cbor` | one per reader step: `fork/bad-other-origin` and `fork/bad-unverifiable-conflicting` (step 1, each half), `fork/bad-size-mismatch` (step 2), `fork/bad-forged-proof` (step 3 — both checkpoints verify and the sizes agree, so nothing but the proof can refuse it), and `fork/bad-consistent` (step 4: a log and its own earlier self) |
| §16.2 bech32m | the text form of every request | `wrong-hrp`, `plain-bech32` (the same bytes under bech32's constant), `mixed-case`, `corrupt-character`. BIP-350's own vectors are in both implementations' unit tests |

**What is not vectored.** A suite that looks complete is worse than one that
admits its holes, so:

- **`quorum none` accepting an uncosigned head.** It needs a second trust
  anchor, and one is not shipped.
- **§5's `state.net` coming from the anchor rather than from the genesis
  entry.** Unobservable: entry 0 aborts whenever the two differ, so no file can
  tell the two readings apart. Recorded here because a reader will look.

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
the first realistic policy. Vector `log/49-policy-escaping` exercises every row
of both tables above.

## 15. Distribution, freshness and gossip

Checkpoint acquisition order, the witness-time clock, the `fresh → degraded →
hard-stale` state machine and the peer gossip endpoints are normative in
`GOSSIP.md`. The **fork evidence format is §11.1 of this document**: it is the
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
