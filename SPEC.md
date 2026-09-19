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

Map keys MUST be encoded in the order required by RFC 8949 §4.2.1 (length-first,
then bytewise). Unknown keys MUST cause rejection (this is a *closed* schema).

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

```
state := { roots: {kid→pk}, root_thr, signers: {kid→pk}, signer_thr, log_keys: [{pk, valid_until}], policy_text,
           devices: {device_id → {device_pk, wg_pk, status: active|revoked, since_index, labels, expires}},
           active_wg: {wg_pk → device_id}, params, rejected: [ {index, reason} ] }
```

Replay processes entries by index. For each entry:

1. Decode. Any decode error, unknown key, wrong `v`, or `net` ≠ trust-file `net_id` → **reject** (`decode`).
2. Index 0 MUST be `genesis` and `H(0x00 ‖ bytes)` MUST equal `norn.trust.genesis_hash`; otherwise **abort replay** (`bad-genesis`). Any later `genesis` → reject.
3. If `after` present and `after` > index → reject (`after`).
4. Verify every signature (§4.2) against current state; drop signatures from unknown or wrong-role keys; count distinct valid keys per role.
5. Apply type rules:
   - `enroll`: `device_id` not currently `active` else reject (`dup-id`); `wg_pk` not in `active_wg` else reject (`dup-wg`); device signature present; signer count ≥ `signer_thr`. → add device `active`, `since_index = index`.
   - `rotate`: device `active`; signed by current `device_pk`; new `wg_pk` not in `active_wg`. → update keys.
   - `revoke`: device `active`; authorised per §4.3. → `status = revoked`, remove from `active_wg`.
   - governance types: root count ≥ `root_thr`; apply; `root_remove`/`root_thr` invariants as in §4.3.
   - `note`: 1 valid signer/root signature; no change.
   - Entries whose `expires` < checkpoint time are treated as `revoked` *at evaluation time*, not at replay (so state is clock-independent).
6. Rejected entries are appended to `state.rejected` with a **fixed reason code**; reason codes are part of the test vectors. Replay never aborts on a rejected entry (only on `bad-genesis`).

Replay is a pure function `(trust, entries[]) → state`. Two implementations MUST produce byte-identical canonical JSON of `state` for every vector.

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

Delivered out of band (G6). Deterministic CBOR, also rendered as TOML for humans:

```
version      = 1
net_id       = "<hex32>"
origin       = "norn/<base32>"
name         = "casa-onembyte"
genesis_hash = "<b64 leaf hash of entry 0>"
log_key      = "<signed-note verifier key string>"
log_urls     = ["https://log.lan.example/norn", "http://10.0.0.155:8099/norn"]
[[witness]]
name = "pi.lan"         key = "<verifier key string>"
[[witness]]
name = "vps.example"    key = "<verifier key string>"
policy       = "2 of [pi.lan, vps.example, ...]"   # tlog-policy text; binding
anchor       = { type = "opentimestamps", max_lag = "24h", mode = "advisory" }  # OPTIONAL
```

Fingerprint for verbal/QR check: first 8 bytes of `H(CBOR(trust))`, rendered as
4 words from a 256-word list. `nornd` MUST refuse to start without a trust file
and MUST refuse a trust file whose `genesis_hash` does not match entry 0.

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
| `log/` | a full tlog-tiles directory: 40 entries, ≥ 2 partial tiles, checkpoint with 3 cosignatures |
| `state.json` | canonical replay output for `log/` |
| `receipt.note` | one receipt |
| `proof-<device>.bundle` | one tlog-proof@v1 bundle |
| `trust.cbor` + `trust.toml` + `trust.fingerprint` | the trust file for `log/` |
| `fork/` | two conflicting cosigned checkpoints + expected evidence output |

Cosignature and checkpoint vectors are taken from the C2SP repositories, not reinvented.

## 13. Open items

- Whether `labels` should be able to carry `allowed_ips` as an *advisory* hint for owner mode (leaning yes; the control plane can override endpoints but never keys).

## 14. Proven-set interface

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
