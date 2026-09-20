# COLD GATE 6.5 — independent implementation audit of Norn SPEC v1

VERDICT: SPEC SUFFICIENT WITH GAPS

Method: `SPEC.md` was read end to end before any code was written. A Go
implementation (stdlib only, own CBOR codec) was built from the prose in
`impl/` — deterministic CBOR codec, entry schema and signature verification,
the §5 replay state machine, §5.3/§14 canonical JSON, §9 trust file and
fingerprint, §7 signed notes, §16 enrollment requests and bech32m, RFC 6962
hashing and inclusion proofs, `tlog-tiles` reading, §8.1 proof bundles.
The vectors were then run against it, and finally 58 *variant* builds were
run — each flipping one decision the prose left open, or blinding one check —
to find out which decisions the suite actually pins.

---

## Stage 2 — check counts

`shasum -a 256 -c SHA256SUMS`: 293/293 files intact.

| area | checks |
|---|---|
| `entries/` (16 entries × hashes, preimage, size, canonical round-trip, JSON mirror) | 112 |
| `log/` replay (90 entries, reason per manifest **and** per `.reason`) + `state.json` byte compare | 182 |
| `genesis/` (12 abort cases, reason + size + `state.json` byte compare) | 36 |
| `trust.cbor` / `.toml` / `.fingerprint` | 9 |
| `trust-bad/` (18 anchors that must be refused) | 18 |
| `requests/` (4 cases: parse, sig, preimage, size, bech32m decode + re-encode + uppercase, JSON mirror) | 36 |
| `requests-bad/` (23 refusals) | 23 |
| `receipt.note` / `receipt.json` | 10 |
| `served/` (checkpoint, log signature, 3 cosignatures, entry bundle, level-0 tile, root, replay) | 99 |
| `proofs/` (6 bundles + constructed tamper negatives) | 72 |
| constructed profile/limit probes (mine, not shipped vectors) | 6 |
| **TOTAL** | **603 checks, 603 passed, 0 failed** |

Shipped-vector checks alone: **597 / 597**.

Every one of the **107 shipped negatives** (54 in `log/`, 12 in `genesis/`,
18 in `trust-bad/`, 23 in `requests-bad/`) is refused, and for the reason it
names: `log/` and `genesis/` are compared against both `manifest.json` and the
`.reason` file by exact reason code; `trust-bad/` and `requests-bad/` were run
through a diagnostic pass that prints *which layer* refused each file, and
every one was refused at the layer its case name implies — with two exceptions,
which are defects G3 and G4 below.

**One disagreement, investigated.** My first run scored 415/416 with a single
failure: my `c2sp.org/tlog-policy` parser, written strictly from the only
example the spec gives (§9.2), **rejected the suite's own valid `trust.cbor`**.
Conclusion: the **spec is wrong**, not the vector — see G1. Widening the
parser to accept the trailing URL field the real policy lines carry brought
the suite to 597/597 and unlocked the `served/`, `proofs/` and `receipt`
sections (which depend on a parsed trust file), giving the totals above.

## Stage 3 — variant results

58 variants built, one decision each. **40 were caught** by the suite;
**18 still passed all 597 shipped checks.** All 18 were then enabled
*simultaneously* — an implementation diverging from the intended protocol in
eighteen separate ways — and it still scored 597/597.

Caught (the suite does pin these — a partial list of the load-bearing ones):
entry-signature blindness (14 failures), inclusion/leaf-hash blindness (15),
lenient CBOR (16), unsorted `sigs`, bare-string map-key sort (132), the
signature domain prefix (134), role-field matching, the embedded-request
signature, `after` as a floor rather than an equality, `dup-wg`/`dup-id`
scoping, closed envelope and body schemas, `net` checking, UTF-8 validation,
the `device_id` pattern, integers above 2⁶³−1, `bad-thr` vs `decode`,
`thr = 0`, D-028 (`signer_remove` has no quorum invariant), the `root-invariant`
threshold, `since_index` semantics for `enroll`/`rotate`/`revoke`,
`log_keys.since_index`, re-enrolment replacing the record wholesale, genesis
`after = 0` and role disjointness, every §14.2 escaping rule, the trailing
`0x0A`, bech32 vs bech32m, mixed case, and the governance step-7-before-step-8
order.

---

## Defects

Ordered worst first. "Prose" = a competent implementer reading only this
document could reasonably diverge. "Vectors" = the prose is clear but nothing
in the suite forces it, so a wrong implementation ships green.

### G1 — §9.1 requires a normative parse against a grammar the document neither defines nor references (Prose)

**Where:** §9.1 `policy` row; §9.2 TOML rendering; the normative-reference list
at the head of the document; §15.

**What it says:** `policy` is "verbatim `c2sp.org/tlog-policy`; **MUST parse**,
and MUST name **exactly** the witnesses `witnesses` lists, with the same keys."
Four of the eighteen `trust-bad/` cases (`09-policy-without-quorum`,
`10-missing-policy`, `17-witness-not-in-policy`,
`18-policy-names-an-unlisted-witness`) can only be decided by parsing it.

**The problem:** `c2sp.org/tlog-policy` is **not in the list of specifications
Norn reuses** at the head of the document (which names tlog-tiles,
tlog-checkpoint, signed-note, tlog-cosignature, tlog-witness, tlog-proof,
RFC 6962, RFC 8949, RFC 8032, RFC 7748 — and not tlog-policy). The grammar is
never restated. The only concrete example, in §9.2, elides the two lines that
matter:

```
policy = "log …\nwitness pi …\ngroup home 2 pi vps friend\nquorum home\n"
```

**How I know it is real:** I implemented `log <key>` and `witness <name> <key>`
from that example — the only reading it supports — and my implementation
**rejected `vectors/trust.cbor`**, the suite's own anchor. The real lines are
`log <key> <url>` and `witness <name> <key> <url>`. That is a first-attempt
interoperability failure caused directly by the prose. A second implementer
who guesses differently (e.g. treats the URL as part of the key string) gets a
different answer on cases 17 and 18.

**What it should say:** add `c2sp.org/tlog-policy` to the normative-reference
list at the head, and either restate the grammar in §9.1 or replace §9.2's
elided example with the complete policy string that `trust.toml` actually
carries. Also state which name — the trust file's short `name` ("pi") or the
verifier key's internal note name ("norn-witness/pi") — the policy's `witness`
directive is matched on.

### G2 — nothing in the suite forces a verifier to check a single signed-note or cosignature signature (Vectors)

**Where:** §7, §6, §8.1, §10; §12.1 rows for §7, §10 (verifier loop) and
§10 (witness quorum).

**How I know it is real:** three variants — `NORN_NOTE_SIGBLIND`
(signed-note verification always returns true), `NORN_COSIG_BLIND` (witness
cosignature verification always returns true) and `NORN_KEYID_BLIND` (never
check the 4-byte note key id) — **each pass 597/597**, and so does all three
together. The suite ships exactly one `receipt.note`, one `served/checkpoint`,
six proof bundles and one `fork/conflicting.checkpoint`, all of them valid.
There is **no note-layer negative anywhere in the 294 files.**

This is the same class of defect an earlier run of this audit found at the
entry layer. The entry layer is now genuinely well covered —
`bad-forged-signer-sig` and `bad-forged-device-sig` catch a signature-blind
entry verifier with 14 failures. The note layer has nothing. §10 makes
"verify log signature" the *first* step of the verifier loop and says the
witness quorum must be satisfied or the checkpoint refused; an implementation
that does neither reproduces the whole suite.

**Compounding this,** §12.1 *claims* these negatives exist:

> §10 verifier loop, steps 1–4 … an unsigned checkpoint, one signed by another
> key, and one signed under another origin's name are each refused
>
> §10 step 3, the witness quorum … one cosignature short, none at all,
> cosignatures only from witnesses the policy does not name, and a forged one
> carrying a named witness's key id are each refused; `quorum none` accepts an
> uncosigned head

None of those files ship. `find vectors -type f` returns 294 files; `served/`
contains exactly `checkpoint`, `tile/0/000.p/90` and `tile/entries/000.p/90`.

**What it should say / ship:** `served/checkpoint-unsigned`,
`served/checkpoint-wrong-key`, `served/checkpoint-wrong-origin`,
`served/checkpoint-one-cosig`, `served/checkpoint-no-cosigs`,
`served/checkpoint-forged-cosig`, and a `quorum none` policy case — or §12.1
must stop claiming them.

### G3 — the §4.0 23-byte map-key cap is not exercised by the vector cited for it, and the vector breaks §4.0's own construction rule (Vectors + Prose)

**Where:** §4.0 encoding-profile table ("every **map key** is a text string of
1–23 bytes"); §12.1 cites `requests-bad/oversize-label-key` for it **twice**.

**How I know it is real:** `NORN_NOMAPKEYCAP=1` — a decoder with no map-key
length cap at all, and with the §4.3 `labels` key-length constraint also
disabled — **passes 597/597**. I decoded `requests-bad/oversize-label-key.txt`
independently: it is canonical CBOR, 251 bytes, one label
`kkkkkkkkkkkkkkkkkkkkkkkk` (24 bytes) → `"at the cap"`, and it is refused by
**Ed25519 verification**, not by any length rule. The `sig` field was not
recomputed over the patched preimage.

This violates a rule §4.0 states about itself, in the same section:

> 2. **The patch cannot canonicalise** — invalid UTF-8, an integer above 2⁶³−1,
>    an **oversized map key** — so the entry is **re-signed over the patched
>    preimage**. Without this the vector is rejected for its broken signature
>    and the rule it names is never reached.

That is exactly what happened. Fix: regenerate the vector re-signed over its
own patched preimage.

### G4 — §16.1's `expires > ts` rule is not pinned, for the same reason (Vectors)

**Where:** §16.1 (`expires` … "MUST be > `ts`"); `requests-bad/expires-at-ts`.

**How I know it is real:** `NORN_NO_EXPIRES_GT=1` passes 597/597. I decoded
`requests-bad/expires-at-ts.txt`: canonical CBOR, `ts = 1760000010`,
`expires = 1760000010`, refused by signature verification. Unlike G3 this
patch *would* canonicalise, so re-signing it is trivial and the case then
tests what it names.

### G5 — the evaluation-time expiry clock is contradictory, names a value the checkpoint format does not carry, and is unvectored (Prose)

**Where:** §5.1 last paragraph, §10, §6, §5.3 `expires`.

**What it says:**

- §5.1: "Entries whose `expires` is earlier than **the checkpoint time** are
  treated as `revoked` *at evaluation time*, not at replay."
- §10: `proven := { d ∈ state.devices : status == active && not expired(now) }`

**The problems, all three:**
1. Two different clocks are specified for the same decision — "the checkpoint
   time" in §5.1 and `now` in §10. They differ by up to `staleness` (600 s by
   default), which is enough to admit or refuse a peer.
2. **A `tlog-checkpoint` has no timestamp.** §6 fixes the checkpoint at
   "`origin` line, size, root; **no extension lines**". The only timestamps
   anywhere near it are the 8-byte fields inside `tlog-cosignature`
   cosignatures — of which there may be one per witness, all different. So
   "the checkpoint time" names a value that does not exist in the artifact, and
   the spec never says to derive it from the cosignatures (nor which one, nor
   min/max/median).
3. Neither the comparison ("earlier than", i.e. strict `<`, vs §10's
   `expired`, undefined) nor the boundary case `expires == t` is resolved.

**Unvectored:** there is no `proven.json` and no proven-set fixture in the
suite; `state.json` is deliberately clock-independent, so nothing tests this.
`contractor` carries `expires = 1767776000` and is simply `active` in
`state.json`.

This is the one gap with a direct production consequence: it governs when a
device stops being admitted to the VPN, which is what Norn is for.

**What it should say:** pick one clock, define it as a concrete byte-level
derivation (e.g. "the median cosignature timestamp on the checkpoint that
produced this state", or plainly "the verifier's wall clock at evaluation"),
state the comparison as `expires != 0 && expires <= T`, and ship one fixture
with a `T` and an expected proven set.

### G6 — §11 fork-evidence format is defined nowhere in this document, yet §12.1 claims it is vectored and that "everything normative is vectored" (Prose)

**Where:** §11, §12.1's §11 row, §12.1's closing claim, §15.

**What it says:** §11 requires a node to "write both checkpoints and the failed
proof to `fork/<unix>.evidence`". §15 defers "fork evidence format" to
`GOSSIP.md`, which is not shipped and is **not in the normative-reference list**.
§12.1 then says:

> §11 fork evidence | `fork/evidence.cbor` and `fork/conflicting.checkpoint`
> … Checking it needs only `trust.cbor`
>
> **Everything normative is vectored.** The list that stood here — §6's
> cosignatures and §11's fork evidence — is empty as of v1.

**How I know it is real:** I could not check this vector. `fork/evidence.cbor`
is a 7-key deterministic CBOR map whose keys are `held`, `held_root`,
`conflicting`, `size`, `proof`, `policy`, `version`. Not one of those names
appears in `SPEC.md`. The shipped filename (`evidence.cbor`) also does not
match §11's (`<unix>.evidence`). Checking it needs `trust.cbor` **and a format
definition that this document does not contain**. §12.1's claimed negatives
for this row ("evidence for another origin is refused; so is a 'fork' between a
log and its own earlier self") also ship as no files.

### G7 — §12.1's coverage table, the thing the spec asks to be judged on, is wrong in at least six places (Prose)

**Where:** §12.1, and the header's claim on line 10.

§12.1 opens by saying a suite that looks complete is worse than one that admits
its holes, "and an inaccurate coverage claim is the same failure wearing a
different hat". Measured against the shipped files:

1. `genesis/` — §12.1 says "**nine** abort paths in `genesis/`" (twice: also
   "nine ways a genesis entry is refused" in `README.md`). `genesis/cases.json`
   lists **twelve**, and twelve directories ship.
2. §6 row's negatives — "forged head, tampered bundle, missing bundle" — ship
   as no files.
3. §8 row's negatives — "wrong entry, foreign checkpoint, tampered proof,
   wrong log key" — ship as no files. (I constructed two of these myself.)
4. §10 rows' negatives — see G2 — ship as no files.
5. §11 row's negatives — see G6 — ship as no files.
6. `requests-bad/oversize-label-key` is cited for §4.0's map-key cap and does
   not exercise it — see G3.

The header also contradicts §12.1 directly. Line 10: "§12.1 lists what is
vectored and what is not. It does **not** claim every MUST is vectored —
several are not, and they are named there." §12.1's own closing line:
"**Everything normative is vectored.**" Both cannot be true, and the second
is false (see G5, G8, G9).

§12's file table additionally omits `fork/`, `anchors/` and `SHA256SUMS`,
against `README.md`'s rule that "a file being absent from this list is a bug in
the list".

### G8 — `rotate`'s proof-of-possession on the incoming `device_pk` (D-032) is untested; the vector named for it does not reach the rule (Vectors)

**Where:** §4.3 `rotate` row ("**and the incoming `device_pk` too when the body
carries one** (proof of possession, D-032)"); §5.1 `rotate` rule, last check;
`log/46-bad-rotate-no-new-key-sig`.

**How I know it is real:** `NORN_ROTATE_NEWPK_NOSIG=1` — an implementation that
never verifies the incoming key's signature — **passes 597/597**. I decoded
entry 46: body `{device_id: printer, wg_pk: …, device_pk: printer-id2}`, sigs
`[signer1/signer, signer3/signer]`. It carries **no device signature at all**,
so it is refused at the *current*-key check (`no-device-sig`), three checks
earlier in the same rule. The positive `40-rotate-device-key-only` carries both
device signatures, so the two readings never diverge on it.

**Why it matters:** the fixture turns `rotate_needs_signer` on at index 29.
Under that setting, an implementation missing this check lets two signers
install an attacker-chosen identity key on a device with no proof the attacker
holds it — precisely the property D-032 exists to guarantee. Fix: a vector
carrying a valid current-key signature and no signature by the new `device_pk`.

### G9 — §4.0's resource limits are stated as MUSTs, are unreachable by design, and are neither vectored nor admitted as unvectored; and one of them contradicts §6 (Prose + Vectors)

**Where:** §4.0 ("A decoder MUST bound its own resource use: nesting depth is at
most **8** … and an entry is at most **65536** bytes"); §6; §16.2.

Four separate problems:

1. **Unvectored.** `NORN_NOLIMITS=1` and `NORN_NODEPTH=1` each pass 597/597.
   §4.0 itself says "Neither limit is reachable by a valid entry", so no
   *valid* entry can test them — but the limits exist for hostile input, and a
   hostile-input vector (a 1 MB entry, a 200-deep nest) costs nothing. My own
   constructed probes cover this; the suite does not, and §12.1 does not name
   it as a hole.
2. **The depth convention is undefined.** "Nesting depth is at most 8" — the
   document never says whether the top-level map is depth 0 or 1, nor whether
   an `enroll`'s embedded request (a byte string containing CBOR) continues the
   count or restarts it. Two implementations counting differently differ by one
   or by four.
3. **The justification is stale.** "(the deepest structure the schema allows is
   an entry's `body.labels` value)" — §4.3 moved the device's claims into the
   request, and §12.1 says so explicitly: "no *entry* body has a free-form map
   left". No entry has `body.labels` any more.
4. **Off by one against §6.** §4.0 allows an entry of exactly 65536 bytes. §6
   says "Entry bundles are uint16-length-prefixed entry bytes", so the largest
   entry representable in a tlog-tiles bundle is 65535. A spec-valid entry
   cannot be served. §16.2 further refers to "§4.0's `MAX_ENTRY_BYTES`" — a
   symbol §4.0 never introduces by that name.

### G10 — §5.1 calls its ordering normative and asserts it is vectored; four orderings are not (Vectors)

**Where:** §5.1 ("The order is **normative**: several vectors are simultaneously
wrong in more than one way, so the first matching step decides the reason
code."), and each type rule's "checks, in order".

Passing 597/597:

| variant | the other defensible reading |
|---|---|
| `NORN_TYPE_FIRST` | step 4 (`unknown-type`) decided before step 3 (envelope closedness) |
| `NORN_THRESHOLD_FIRST` | step 7 (quorum) decided before step 6 (`after`) |
| `NORN_ENROLL_ORDER_SWAP` | `enroll`: `dup-id`/`dup-wg` decided before `threshold` |
| `NORN_ROTATE_ORDER_SWAP` | `rotate`: `dup-wg` decided before the `rotate_needs_signer` quorum |

Only the governance step-7-before-step-8 order is genuinely pinned, by
`85-bad-undersigned-malformed` (`NORN_STEP8_FIRST` fails 4 checks). The prose
is clear in all four cases, so this is a suite gap rather than a reading
hazard — but §5.1 explicitly rests its claim on vectors that are
"simultaneously wrong in more than one way", and for `enroll` and `rotate`
none are.

### G11 — §4.3 and §5.2 contradict each other on `thr`'s type (Prose)

**Where:** §4.3 (`signer_thr` / `root_thr` rows: "`thr` (uint ≥ 1 …)") vs §5.2
(`bad-thr`: "a `signer_thr`/`root_thr` value of 0 … This is a **replay**
decision, not a schema one: the value is a well-formed uint, so it is never
`decode`.").

An implementer who takes §4.3's table at face value enforces `≥ 1` as a field
constraint and, per §4.0 ("Field constraints … violations → reason `decode`"),
returns `decode` where §5.2 demands `bad-thr`. The suite does catch this
(`log/61-bad-thr-zero`, and `NORN_BADTHR_AS_DECODE` fails 8 checks) — but only
after the fact. Fix: drop "≥ 1" from §4.3's table, or annotate it "(enforced at
replay as `bad-thr`, not as a schema constraint)".

### G12 — §8.1's "domain `norn/proof/v1`" names nothing, and the section's own unresolved TODO survived the freeze (Prose)

**Where:** §8.1.

**What it says:** "Deterministic CBOR per §4.0, **domain `norn/proof/v1`**",
followed by a six-key table: `v`, `device`, `index`, `entry`, `proof`,
`checkpoint`. There is no domain field in that table, no signature over the
bundle for a domain prefix to separate, and the string `norn/proof/v1` appears
nowhere else in the document. I parsed all six bundles as a closed six-key map
and they are byte-canonical — so the domain is emitted nowhere. An implementer
cannot tell whether they are required to produce or check it.

**And:** §8.1 carries a block-quoted note ending "**Reconcile before freezing
v1.**" in a document whose header reads "Status: **v1**, frozen 2026-09-20" and
whose §13 reads "Open items: None." Either the reconciliation happened and the
note should go, or it did not and §13 is wrong.

### G13 — smaller unpinned decisions (Vectors)

Each of these passes 597/597; the prose is clear enough that I do not expect
divergence, but the suite does not enforce it.

- **`NORN_REVOKE_COMBINE`** — pooling signer and root signatures into one
  quorum on `revoke` instead of §4.3's three independent alternatives. The
  fixture's `84-revoke-by-roots` meets the root quorum outright, so the
  readings never differ. Worth a vector: a revoke with `root_thr - 1` roots and
  `signer_thr - 1` signers must be `threshold`.
- **`NORN_JSON_UTF16SORT`** — §14.1 says object keys sort "bytewise over the
  UTF-8 encoding"; no object key anywhere in the suite is an astral character,
  so UTF-16 code-unit order (what a JavaScript implementation gets for free) is
  indistinguishable. One emoji label key would pin it. The *value* escaping
  rules are well pinned by `49-policy-escaping`.
- **`NORN_CHECKPOINT_EXT`** — §6's "no extension lines" is unenforced; the only
  checkpoints shipped have exactly three text lines.
- **`NORN_PARAMS_ALLOW_EMPTY`** — §5.1's `params` rule requires "non-empty";
  no vector.
- **`NORN_TRUST_ALL_OPTIONAL`** — only `name` and `policy` are pinned as
  mandatory trust-file keys (`trust-bad/14`, `trust-bad/10`). The other seven
  are mandatory only by inference from `anchor` being the one marked OPTIONAL,
  and none is vectored missing.
- **`NORN_HASH_AFTER_DECODE`** — §5.1 step 1 (`entry_hash` already seen) runs
  *before* step 2 (decode), but §4.0 defines `entry_hash` over "entry bytes …
  **deterministically encoded**", which an undecodable entry does not have. I
  resolved the circularity by hashing the raw bytes; hashing the re-encoded
  canonical form and skipping the check for undecodable entries also passes.
  Fix: §4.0 should say `entry_hash` is SHA-256 of the bytes as received.
- **`NORN_NET_FROM_GENESIS`** — §5's "`state.net` is copied from the **anchor**,
  not from the genesis entry" is unobservable, because entry-0 step 3 aborts
  whenever the two differ. Harmless redundancy, listed for completeness.

---

## Every decision the prose did not make for me

Including the ones the vectors happened to pin. Each was a coin-flip at the
moment I wrote it; where a variant exists it is named.

1. **`entry_hash` of an undecodable entry** — raw bytes vs re-encoded canonical
   form (`NORN_HASH_AFTER_DECODE`). §5.1's step order makes the latter
   impossible; §4.0's definition makes the former non-literal.
2. **Nesting-depth base** — top-level item at depth 1 (my choice) or 0; whether
   an embedded request continues the count.
3. **Whether the 65536-byte cap is checked before or after decoding** — I check
   before, on the raw input.
4. **Whether "shortest form" applies to length headers as well as integers** —
   I applied it to every major type's argument, per RFC 8949 §4.2.1; §4.0's
   table says it only under "Integers".
5. **Whether the 1–23-byte map-key cap applies to the trust file, requests and
   proof bundles, not only entries** — I applied it everywhere §4.0 governs.
6. **Whether a `params` map inside `genesis.body` is validated for key names**
   — §5.1 entry-0 step 6 says yes; the reason code on failure is `bad-genesis`.
7. **Whether `thr ≥ 1` is a schema or a replay rule** (G11) —
   `NORN_THR_ALLOW_ZERO`, `NORN_BADTHR_AS_DECODE`.
8. **Whether a `sigs` entry's `role` must match the key's actual role, or
   whether a kid may be resolved in any role** — §5.2 is explicit, §4.3's
   "a key counts only for the role it currently holds" reads the other way
   (`NORN_ROLE_IGNORED`, caught).
9. **Whether `note` accepts a valid `device` signature** — I read §5.1 step 7's
   "no valid `signer` or `root` signature" as excluding it
   (`NORN_NOTE_ANY_SIG`, caught by `82-bad-device-signed-note`).
10. **Whether `revoke`'s three authorisations pool or stand alone** (G13,
    `NORN_REVOKE_COMBINE`).
11. **Whether `enroll`'s `dup-id` is "currently active" or "ever used"**, and
    whether its `dup-wg` covers revoked devices (`NORN_ENROLL_DUPID_EVER`,
    `NORN_ENROLL_DUPWG_ALL`, both caught).
12. **Intra-rule check order for `enroll` and `rotate`** (G10).
13. **Whether step 3's envelope check precedes step 4's `unknown-type`** (G10).
14. **Whether `after` is a floor or an equality** (`NORN_AFTER_STRICT`, caught).
15. **`signer_remove` quorum invariant** — D-028 says there is none; I obeyed
    it (`NORN_SIGNER_REMOVE_INV`, caught by `54-signer_remove-below-threshold`).
16. **`root_remove`'s invariant: `≥ root_thr` and `≥ 1`, or only `≥ 1`**
    (`NORN_ROOT_INV_ONLY_ONE`, caught).
17. **Whether `rotate` updates `since_index`** — §5.1 says it does not
    (`NORN_ROTATE_TOUCH_SINCE`, caught).
18. **Whether re-enrolment merges or replaces labels/expiry** — §5.3 says
    replace (`NORN_REENROLL_MERGE`, caught).
19. **`log_keys.since_index` = the entry's index or the resulting log size**
    (`NORN_LOGKEY_SINCE_SIZE`, caught; §5.3 goes out of its way here).
20. **Canonical-JSON key sort for non-BMP keys** (G13).
21. **Whether U+007F and `/` are escaped** — §14.2 says no (caught).
22. **Whether the entry `.json` mirror is canonical JSON** — §12.1's §14 row
    says "every `.json`", so yes; I compared byte-for-byte against the file's
    own `entry` member.
23. **Byte order of the entry bundle's uint16 length prefix** — §6 says
    "uint16-length-prefixed" and does not say. I assumed big-endian; it worked.
24. **The `tlog-cosignature` v1 signed message** —
    `"cosignature/v1\ntime <unix>\n" ‖ checkpoint text`, with a 4+8+64 blob.
    Not restated in SPEC.md; it is a listed normative reference, so this is
    legitimate, but it is the one construction I had to guess outright. It
    verified against all three witnesses.
25. **Whether a signed note may carry zero signature lines** — I reject.
26. **Whether a signed note must end with a newline after the last signature
    line** — I require it.
27. **Whether the trust-file keys other than `anchor` are mandatory** (G13).
28. **The `tlog-policy` grammar** (G1) — the one guess that broke.
29. **Whether the proof bundle's `index` must equal the device's
    `since_index`** — §8 does not require it, §12 implies it; I check it and it
    holds for all six.
30. **Whether the trust file's `policy` matches witnesses on the short `name`
    or the verifier key's internal note name** — I used the short name.

## What is genuinely well done — do not break this

- **§4.1's warning about map-key ordering.** Spelling out that bytewise order
  of the *encoded* form gives `t, v, ts, net, body, sigs, after` and **not**
  `after, body, net, sigs, t, ts, v`, and that §14's canonical JSON sorts the
  other way and the two "MUST NOT be conflated", is the single most useful
  paragraph in the document. I got it right first time because of it, and my
  variant that sorts bare strings fails 132 checks.
- **§4.0's note on how to construct negative vectors** — the distinction
  between patches that canonicalise away (keep the original signature) and
  patches that cannot (re-sign over the patched preimage), with the
  `profile-base` / `labelcap-base` / `two-sig-base` controls shipped beside
  them. It is rare for a spec to teach its own test methodology. That it names
  the exact failure mode G3 fell into is what let me diagnose G3 in one step.
- **§14 in its entirety.** Every escaping row, the explicit "no HTML-safe
  escaping", "U+007F is not escaped", "no surrogate pairs", and the mandatory
  trailing `0x0A`. `log/49-policy-escaping` exercises every row and catches
  four separate variants. Byte-identical state on the first run.
- **§5.2's "Signature counting, precisely" paragraph** and the `no-device-sig`
  vs `threshold` split for `revoke`. Both are exactly the places two
  implementations would otherwise diverge, and both are nailed down.
- **The §4.3 rationale for why `enroll` embeds a request.** It explains the
  asymmetry, the threat, and what the embedded request proves that an envelope
  signature would not. `bad-order-enroll` and `bad-forged-device-sig` turn it
  into a test an "opaque bytes" implementation cannot pass
  (`NORN_ENROLL_SIG_ON_ENV` fails 42 checks).
- **§5.3's insistence that every field is always present**, plus the explicit
  contrast with §4.0's absent-means-absent rule for entries. No guessing.
- **§6's OpenTimestamps digest definition.** "SHA-256 of the checkpoint
  **body** — the note text up to and including the blank line, without any
  signature lines", with the reason given. This is one byte different from
  §7's signed-text rule ("does **not** include the blank separator line"), and
  both are stated precisely enough that I verified from prose alone that
  `anchors/checkpoint-90.ots` stamps `SHA-256(text ‖ blank line)` and not
  `SHA-256(text)`. That is the standard the rest of the cross-document
  references should be held to.
- **§9.1's witness-key algorithm note** — that `0x01` and `0x04` under the same
  public key are two different verifiers, and why. `trust-bad/15` and `/16`
  land exactly on it.
- **D-028** (`signer_remove` has no quorum invariant, with the reasoning) and
  **D-032** (`dup-wg` means "another device" for `rotate`, so an identity key
  can rotate alone). Both are counter-intuitive and both are argued, not just
  asserted.

## What I did not cover, and why

- **`anchors/`** — the three OpenTimestamps files. I verified §6's stamped
  digest appears in `checkpoint-90.ots` (it does), but wrote no `.ots` parser
  and did not validate the attestation chain or `calendar-response.bin`. The
  `.ots` format is not restated and is advisory per D-009.
- **`fork/`** — not checkable from SPEC.md; see G6. I decoded `evidence.cbor`
  only far enough to establish that its seven keys appear nowhere in the prose.
- **§10 beyond what `served/` reaches** — the consistency requirement
  (`cp.size >= stored_cp.size`, recomputing the head at `stored_cp.size`), the
  `fresh → degraded → hard-stale` machine and the peer-gossip endpoints are
  normative in `GOSSIP.md`, which is not shipped. No artifacts exist for them.
- **§11's four-step fork response** — no artifacts.
- **The proven set / expiry evaluation** — no vector exists (G5).
- **§7's submission endpoint, §16.3 ssh-agent key handling, `ENROLLMENT.md`,
  `ENFORCEMENT.md`, `tlog-witness` HTTP** — out of scope by reference.
- **Consistency proofs** — the suite ships inclusion proofs only.

## Reproducing

```
cd impl && go build -o /tmp/nornrun .
NORN_BREAKDOWN=1 /tmp/nornrun ../vectors          # 603/603
/tmp/nornrun ../vectors -diag                     # which layer refused each negative
NORN_SKIP_CONSTRUCTED=1 NORN_NOTE_SIGBLIND=1 NORN_COSIG_BLIND=1 \
  NORN_ROTATE_NEWPK_NOSIG=1 NORN_NOMAPKEYCAP=1 NORN_NO_EXPIRES_GT=1 \
  NORN_NOLIMITS=1 /tmp/nornrun ../vectors         # 597/597 — six divergences, green
```

`impl/variant.go` lists all 58 switches.
