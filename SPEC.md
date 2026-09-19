# Norn — Specification v0 (draft)

Written **2026-09-18** (plan part 4). Status: **draft** — frozen at Phase 6.
Every MUST here has, or will have, a test vector under `testdata/vectors/`.

Norn reuses these specifications verbatim; where they conflict with this document,
they win:

- `c2sp.org/tlog-tiles` — log storage and read API
- `c2sp.org/tlog-checkpoint` — signed tree heads
- `c2sp.org/signed-note` — signature line format
- `c2sp.org/tlog-cosignature` — witness cosignatures (v1)
- `c2sp.org/tlog-witness` — witness HTTP protocol
- `c2sp.org/tlog-proof` (v1) — self-contained inclusion proof bundles
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
| `origin` | `norn/<base32-lowercase(net_id) without padding>` | checkpoint origin line; the log key's signed-note name MUST equal it |
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

All Norn structures (entries, enrollment requests, trust files, canonical state)
use **RFC 8949 §4.2.1 Core Deterministic Encoding** with these restrictions:

| Rule | Requirement |
|---|---|
| Integers | major type 0 only; shortest form; ≤ 2⁶³−1. **No negative integers.** |
| Floats, tags, `undefined`, indefinite-length items | **forbidden** |
| `null` | **forbidden** — an OPTIONAL field is *absent*, never `null` |
| Booleans | allowed (`params.rotate_needs_signer` only) |
| Byte strings | definite length; fixed sizes where stated (`net` 16, `pk` 32, `sig` 64) |
| Text strings | definite length; valid UTF-8; every **map key** is a text string of 1–23 bytes |
| Maps | definite length; keys sorted as §4.1; no duplicate keys; unknown keys → reject |
| Arrays | definite length |

Derived values:

| Name | Definition |
|---|---|
| `kid(pk)` | lowercase hex of `SHA-256(pk)[0:8]` — 16 ASCII chars, as a text string |
| entry bytes | the full envelope **with** `sigs`, deterministically encoded |
| `entry_hash` | `SHA-256(entry bytes)` — identity for de-duplication |
| leaf hash | `SHA-256(0x00 ‖ entry bytes)` (RFC 6962 §2.1) |
| signature preimage | the 14 ASCII bytes `norn/entry/v1` + `0x0A`, then the envelope encoded **without** the `sigs` key |

`sigs` is an array of maps `{"kid","role","sig"}` sorted by `kid` bytewise, with no
repeated `kid`. Signing does not change the preimage, so signatures can be added by
different parties in any order and the result is still canonical.

Field constraints (violations → reason `decode`):

| Field | Constraint |
|---|---|
| `device_id` | matches `^[a-z0-9][a-z0-9.-]{0,63}$` |
| `name`, `reason` | UTF-8, 1–64 / 0–256 bytes |
| `text` (`note`, `policy`) | UTF-8, ≤ 4096 bytes |
| `labels` | map text→text; ≤ 32 entries; keys 1–23 bytes (the map-key cap above — a longer key is unencodable); values ≤ 256 bytes |
| `roots`, `signers` at genesis | arrays of 32-byte `pk`, no duplicates, no key in both; `len(roots) ≥ root_thr ≥ 1`; `len(signers) ≥ signer_thr ≥ 1` |
| `thr` | uint ≥ 1 and ≤ the size of the set it applies to (checked at replay) |

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
correct `t, v, ts, net, body, sigs, after`. Canonical JSON (§12) does sort bare
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
| `genesis` | `name` (string), `roots` ([pk]), `root_thr` (uint), `signers` ([pk]), `signer_thr` (uint), `params` (§4.5) | ≥ `root_thr` of `roots` |
| `enroll` | `device_id`, `device_pk` (bytes32 Ed25519), `wg_pk` (bytes32 X25519), `labels` (map string→string, OPTIONAL), `expires` (uint, OPTIONAL) | the device (`device_pk`) **and** ≥ `signer_thr` signers |
| `rotate` | `device_id`, `wg_pk` (new), `device_pk` (new, OPTIONAL) | the *current* device key; plus ≥ `signer_thr` signers if `params.rotate_needs_signer` |
| `revoke` | `device_id`, `reason` (string) | ≥ `signer_thr` signers, **or** the device itself, **or** ≥ `root_thr` roots |
| `signer_add` | `pk` | ≥ `root_thr` roots |
| `signer_remove` | `kid` | ≥ `root_thr` roots |
| `signer_thr` | `thr` (uint ≥ 1) | ≥ `root_thr` roots |
| `root_add` | `pk` | ≥ `root_thr` roots |
| `root_remove` | `kid` | ≥ `root_thr` roots; MUST leave ≥ `root_thr` roots and ≥ 1 root |
| `root_thr` | `thr` (uint ≥ 1, ≤ number of roots) | ≥ `root_thr` roots (the *old* threshold) |
| `params` | partial §4.5 map | ≥ `root_thr` roots |
| `note` | `text` (string ≤ 4096) | any 1 signer or root; **no state effect** |
| `log_key` | `pk` (bytes32), `overlap` (uint s) | ≥ `root_thr` roots — log-key rotation; both keys valid for `overlap` (`ENROLLMENT.md` §6) |
| `policy` | `text` (verbatim tlog-policy) | ≥ `root_thr` roots — replaces witness policy in state |

Signature counting: a key contributes at most once; a key counts only for the role
it currently holds; a device key counts only for its own `device_id`.

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
| `witness_policy` | string | — | tlog-policy text, informational (the *binding* copy is in `norn.trust`) |

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

"Abort" means replay stops: `rejected` holds exactly `{index: 0, reason: "bad-genesis"}`,
`size` is 0, and no other field is populated beyond `net`. A log whose entry 0 is
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

| `t` | checks, in order | effect |
|---|---|---|
| `enroll` | body fields well-formed (`decode`) · valid `device` signature by `body.device_pk` (`no-device-sig`) · valid `signer` count ≥ `signer_thr` (`threshold`) · `device_id` not currently `active` (`dup-id`) · `wg_pk` not in `active_wg` (`dup-wg`) | add the device `active` |
| `rotate` | body well-formed (`decode`) · `device_id` known (`unknown-device`) · currently `active` (`not-active`) · valid `device` signature by the device's **current** `device_pk` (`no-device-sig`) · if `params.rotate_needs_signer`, signer count ≥ `signer_thr` (`threshold`) · new `wg_pk` not active **for another device** (`dup-wg`) | replace `wg_pk`, and `device_pk` if the body carries one |
| `revoke` | body well-formed (`decode`) · `device_id` known (`unknown-device`) · currently `active` (`not-active`) · authorised by signers, roots **or** the device itself (`threshold`) | `status` = `revoked`, drop from `active_wg` |
| `signer_add`, `root_add` | `kid(pk)` not already a root or signer (`dup-key`) | add to that role |
| `signer_remove` | `kid` is a signer (`unknown-key`) | remove. **No quorum invariant** — removing a compromised signer key MUST always be possible, including the last one (D-028). A network left with fewer signers than `signer_thr` cannot enrol until roots add one; that is recoverable, an unremovable stolen key is not. |
| `root_remove` | `kid` is a root (`unknown-key`) · removing it leaves ≥ `root_thr` roots and ≥ 1 root (`root-invariant`) | remove |
| `signer_thr`, `root_thr` | `1 ≤ thr ≤ len(set)` (`bad-thr`) | set the threshold |
| `log_key` | `pk` 32 bytes, `overlap` a uint (`decode`) | **append** `{pk, overlap, since_index}` to `log_keys` |
| `policy` | `text` ≤ 4096 bytes (`decode`) | replace `policy` |
| `params` | non-empty, only §4.5 keys, each of the right type (`decode`) | **merge** into `params` |
| `note` | `text` ≤ 4096 bytes (`decode`) | none |

A rejected entry is appended to `state.rejected` as `{index, reason}` and
changes nothing else. `size` becomes `index + 1` whether the entry was accepted
or rejected. Replay never aborts after entry 0.

`since_index` records the index of the entry that last **changed the device's
status**: `enroll` sets it, `revoke` sets it, `rotate` leaves it alone.

Entries whose `expires` is earlier than the checkpoint time are treated as
`revoked` *at evaluation time*, not at replay, so state stays clock-independent.

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
| `no-device-sig` | `enroll`/`rotate`/self-`revoke` lacks a valid signature by the device key |
| `dup-id` | `enroll` with a `device_id` that is currently `active` |
| `dup-wg` | `enroll`/`rotate` with a `wg_pk` that is currently active for another device |
| `unknown-device` | `rotate`/`revoke` names a `device_id` never enrolled |
| `not-active` | `rotate`/`revoke` on a device that is already `revoked` |
| `dup-key` | `signer_add`/`root_add` of a `pk` whose `kid` already exists in either role |
| `unknown-key` | `signer_remove`/`root_remove` of a `kid` not in that role |
| `root-invariant` | `root_remove`/`root_thr` would leave `< root_thr` roots or `< 1` root |
| `bad-thr` | `signer_thr`/`root_thr` value is 0 or exceeds the set size |

Signature counting, precisely: a signature `{kid, role, sig}` is *valid* iff the
state before this entry maps `kid` to a key **in that role** (for `device`: `kid`
equals `kid(device_pk)` of the device this entry names — for `enroll`, the
`device_pk` in the body) and Ed25519 verification of `sig` over the preimage
succeeds. Invalid signatures are ignored, not fatal; only the count of valid ones
per role matters.

### 5.3 Canonical state schema (normative)

Two implementations MUST produce byte-identical canonical JSON (§12) of this
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
| `log_keys` | array of `{overlap, pk, since_index}` | one per `log_key` entry, in log order. The trust file's initial log key is **not** listed — it is not in the log. |
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

## 6. The log

- Layout, tiles, entry bundles, and `checkpoint` exactly per `tlog-tiles`. Tile height 8 (width 256), as torchwood requires.
- Leaf hash = `H(0x00 ‖ entry_bytes)` (RFC 6962 §2.1). Entry bundles are uint16-length-prefixed entry bytes.
- The checkpoint is a `tlog-checkpoint` note: `origin` line = §2 `origin`, size, root; **no extension lines**. Signed by the log key; cosigned by witnesses per `tlog-cosignature` v1.
- The log MUST issue a new checkpoint after every append and at least every `checkpoint_interval`.
- **Log operator validation is optional and non-binding.** A log SHOULD refuse entries that fail §5 against its own replay, to keep the log tidy — but verifiers MUST NOT rely on it (`THREAT-MODEL.md` G3).
- Additional paths (Norn-specific, ignored by generic tooling):
  - `<prefix>/add` — submission (§7)
  - `<prefix>/anchors/<size>.ots` — OpenTimestamps proof for the checkpoint at `size` (D-009; advisory)
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

Semantics: *the log promises the entry will be included in a checkpoint of some size
issued no later than `deadline`.* A receipt whose leaf is absent from every
checkpoint cosigned after `deadline` is non-repudiable proof of log misbehaviour
(A2). Submitters MUST keep receipts until inclusion is verified.

Errors: `400` malformed, `409` rejected by the log's own replay (with the §5 reason
code; advisory), `429` rate-limited.

## 8. Proof bundles — what a node holds per peer

For each `active` device the node stores a `c2sp.org/tlog-proof@v1` bundle
("spicy signature"): the cosigned checkpoint, the entry index, the inclusion
proof. A node MUST treat a peer as proven only if:

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
| `log_key` | text | signed-note verifier key for the log; its note name MUST equal `origin` |
| `log_urls` | array of text, ≥ 1 | where to fetch checkpoint and tiles |
| `witnesses` | array of `{name, key, url?}` | `key` is a signed-note verifier key; `name` unique within the file |
| `policy` | text | verbatim `c2sp.org/tlog-policy`; MUST contain a `quorum` line |
| `anchor` | `{type, max_lag, mode}`, OPTIONAL | `type` text (`"opentimestamps"`), `max_lag` **uint seconds**, `mode` text (`"advisory"`) |

Unknown keys MUST cause rejection. The fingerprint (§9.3) is taken over these
bytes, so a wrong field name or type changes it.

### 9.2 TOML rendering

```toml
# Norn trust file for norn-testnet
# fingerprint = ZVGR-QRTN-JY0V-H1Z0
# Compare the fingerprint out of band before trusting this file.

version      = 1
net          = "6e6f726e2d746573746e65742d303031"   # hex
origin       = "norn/nzxxe3rnorsxg5domv2c2mbqge"
name         = "norn-testnet"
genesis_hash = "4e18d55c…"                          # hex
log_key      = "norn/nzxxe3rnorsxg5domv2c2mbqge+bea4a666+…"
log_urls     = ["https://log.norn.example/testnet", "http://10.0.0.155:8099/norn"]
policy       = "log …\nwitness pi …\ngroup home 2 pi vps friend\nquorum home\n"
anchor       = { max_lag = 86400, mode = "advisory", type = "opentimestamps" }

[[witness]]
name = "pi"
key  = "norn-witness/pi+…"
url  = "http://10.0.0.153:8100"
```

Byte strings render as **lowercase hex** in TOML and stay raw bytes in CBOR; no
field is ever base64 in the trust file.

### 9.3 Fingerprint

The first **10 bytes** of `SHA-256(CBOR(trust))` — 80 bits — encoded in
**Crockford base32** (alphabet `0123456789ABCDEFGHJKMNPQRSTVWXYZ`, which omits
I, L, O and U), most-significant bit first, as 16 characters in four groups of
four: `ZVGR-QRTN-JY0V-H1Z0` (D-029).

80 bits is chosen so that an attacker who controls the delivery channel (threat
A10) cannot grind a substitute trust file with a matching fingerprint.

`nornd` MUST refuse to start without a trust file and MUST refuse one whose
`genesis_hash` does not match entry 0.

## 10. Verifier procedure (normative outline)

```
loop every T_g or on demand:
  cp := fetch checkpoint (log_urls, then peers)         # part 6
  verify log signature (torchwood VerifyCheckpoint)
  verify witness policy (ThresholdPolicy / ParsePolicy)
  if stored_cp exists:
      require cp.size >= stored_cp.size
      verify consistency proof stored_cp → cp; on failure → FORK (§11)
  fetch new tiles / entry bundles (TileFetcher / TileFS + PermanentCache)
  state := replay(trust, entries[0:cp.size])
  proven := { d ∈ state.devices : status == active && not expired(now) }
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

## 12. Test vectors (deliverable of Phase 0/1)

| file | contents |
|---|---|
| `keys.json` | fixed seeds for log, 3 witnesses, 2 roots, 2 signers, 3 devices |
| `entries/NN-<type>.cbor` + `.json` | one valid entry per type, byte-exact |
| `entries/bad-*.cbor` + `.reason` | one rejected entry per §5 reason code |
| `log/` | the replay fixture: 42 entry `.cbor` files, a `.reason` file beside each entry that must be rejected, and `manifest.json` |
| `log/manifest.json` | `{"anchor": {"net", "genesis_hash"}, "entries": [{"index", "name", "reason"}]}` — the replay input and its expected outcome; `reason` is `""` for an entry that must be accepted |
| `bad-genesis/` | a one-entry log plus `manifest.json` whose anchor pins a different genesis, so replay aborts |
| `state.json` | canonical replay output for `log/` |
| `receipt.note` | one receipt |
| `proof-<device>.bundle` | one tlog-proof@v1 bundle |
| `trust.cbor` + `trust.toml` + `trust.fingerprint` | the trust file for `log/` |
| `fork/` | two conflicting cosigned checkpoints + expected evidence output |

**Canonical JSON** (for `state.json` and the `.json` mirrors of `.cbor` entries):

- object keys sorted by **UTF-8 code point** — plain bytewise on the key string.
  This is **not** the CBOR map order of §4.1, which sorts by encoded form
  (length first). The two orders differ, and the difference is visible in every
  vector: an entry encodes as `t, v, ts, net, body, sigs, after` in CBOR and
  serialises as `after, body, net, sigs, t, ts, v` in JSON. Implementations MUST
  keep the two orderings separate.
- no whitespace: `,` and `:` as separators, nothing else;
- UTF-8, non-ASCII **not** escaped;
- byte strings as lowercase hex strings;
- integers as JSON numbers; booleans as `true`/`false`;
- a field that the schema defines is always emitted (§5.3); "absent fields
  absent" governs **entry encoding** (§4.0), not state serialisation.

Two implementations MUST produce identical bytes.

Cosignature and checkpoint vectors are taken from the C2SP repositories, not reinvented.

## 13. Open items

- (none as of 0.2; new items are appended here with the checkpoint that raised them)

The verifier hands the enforcer an in-memory proven set and mirrors it to
`/run/norn/proven.json` (schema in `ENFORCEMENT.md` §9). Modes, backends, the
reconciler and failure semantics are normative in `ENFORCEMENT.md`.

## 15. Distribution, freshness and gossip

Checkpoint acquisition order, the witness-time clock, the `fresh → degraded →
hard-stale` state machine, the peer gossip endpoints and fork evidence format are
normative in `GOSSIP.md`. The policy text in `norn.trust` is verbatim
`c2sp.org/tlog-policy`.

## 16. Enrollment requests and key handling

Enrollment request = deterministic CBOR `{net, device_id, device_pk, wg_pk, labels,
expires, ts}` signed by `device_pk` with domain prefix `"norn/enroll-request/v1\n"`;
text form is bech32m with HRP `norn`. Signing keys are reached through the ssh-agent
protocol (Ed25519 only in v0). Trust-file bootstrap and the `log_key`/`policy`
overlap rules are normative in `ENROLLMENT.md`.
