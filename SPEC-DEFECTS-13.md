# SPEC-DEFECTS-13 — cold reading of Norn SPEC v1 (run 13)

Reader: an independent implementer with `SPEC.md`, `testdata/vectors/` and
nothing else. Implementation: Go standard library only, in `work/impl/`
(`cbor.go`, `entry.go`, `replay.go`, `json.go`, `note.go`, `policy.go`,
`trust.go`, `merkle.go`, `verify.go`, `bech32.go`; harness `suite.go`,
`main.go`; divergence inputs `demo.go`). Decisions were logged in
`work/decisions.md` (C01–C95) from the specification alone, before the
vector README, any manifest, or any vector was opened; that file has not been
edited since.

## 1. Tally

| item | result |
|---|---|
| `SHA256SUMS` digests | **645 / 645 verified** |
| behaviour checks the suite defines (manifests + README), final | **708 / 708 passed** |
| first full run, before any correction | **707 / 708** suite-defined checks (the binary printed 784/800 because it also counted 92 checks of my own, see below) |
| what the one first-run failure was | a harness misreading, not a spec reading: I assumed `requests/req-minimal-upper.json`'s `text` member held the canonical lowercase form; it holds the uppercase `.txt`. Fixed in `suite.go`; no protocol code changed |
| my own extra check (not suite-defined, reported, not tallied) | §12.1's row "§14 canonical JSON — every `.json`": **77 / 92**. All 15 failures are the `cases.json` files of `anchors/`, `checkpoints-bad/`, `detect/`, `fork/`, `proofs/`, `proofs-bad/`, `served-bad/`, `served-large/` and the five `served-*` heads, plus `detect/staleness.json` and `proofs/right-edge.json`: pretty-printed, not §14 canonical (D19) |

Check inventory (708): keys 43 · entries mirrors 16 · log per-entry reason
138 + `.reason` files 138 + `state.json` 1 + anchor 1 · genesis 38 ·
log-empty 1 · entries-hostile 16 (refusal *kind* mapped by hand from each
`rules[].says`, as §12 instructs) · trust.cbor/fingerprint/TOML 5 ·
trust-bad 42 · trust-good 5 · policies 57 accept/refuse + 7 `evaluate` rows ·
requests 32 · requests-bad 25 (refused, and a `signature: valid` case must
not be refused by the signature layer) · receipt 2 + receipt-bad 9 (exact
§7 code) · served 5 · served-large 2 · served-bad 5 (exact §10.1 code) ·
checkpoints-bad 27 (exact §10.1 code) + `signature_blind_accepts` recomputed
1 · served-rotated 3 · served-superseded 2 · served-twice-cosigned 2 ·
served-extra-witness 1 · served-name-collision 1 · proofs 15 · proofs-bad 13
(exact code) · proven 10 · detect 7 (outcome and exact code) · staleness 9 ·
fork 26 (4 `sound` + 21 exact §11.1 code + `conflicting.checkpoint`) ·
anchors 3. Every closed vocabulary a manifest names (§5.2 reasons, §7
receipt codes, §10.1 codes, §11.1 codes, freshness states) is compared by
exact string.

One base-implementation change was made after the first run, and it was
found by the sweep, not by a vector: my trust-file correspondence compared
witness *counts* plus inclusion, which silently refused a duplicated witness
name and made the separate uniqueness rule dead (the variant deleting it
survived). C72 says "set equality on names", which is what §9.1 says; the
code was brought into line with C72. Score unchanged (708/708).

## 2. The sweep

Every variant changes exactly one decision of the base implementation, and is
a switch named at the decision point (`V("…")` in the source). The single
variant space was enumerated from the decision log *and* from every rule the
suite could in principle distinguish: each profile ban and cap (both sides of
each boundary), each envelope/body/request field rule, every adjacent pair of
every ordered check list (§5.1, enroll/rotate/revoke internals, §7 receipt,
§10.1 loop and bundle, §11.1), every comparison (origin, key ids, names,
public keys), every encoding choice in §14, every grammar rule in §9.1, the
key-rotation and policy-rotation rules, freshness, expiry, the bech32m text
layer, and the tile/merkle algorithms.

| | count |
|---|---|
| single variants built and run against the whole suite | **313** |
| caught | 259 |
| **survivors** | **54** |
| composite pairs, survivor × survivor | 1431 — all 1431 still pass (no pair of survivors is caught together) |
| composite pairs, survivor × caught variant | 13986 — 13975 caught, **11 pass: 4 genuine rescues, 7 switch-overlap artifacts** (§2.2) |
| concrete divergence inputs built from suite keys (`go run . -demo`) | **47**, all 47 diverge base vs variant; plus one input with no variant (D12) |

Artifacts: `sweep-single.tsv`, `sweep-pairs-ss.tsv`, `sweep-pairs-sc.tsv`,
`demos.txt`, `demo-artifacts/`.

### 2.1 Survivors, classified

Classes, in the specification's own terms: **DECL** — declared in §12.1's
"What is not vectored"; **GAP** — coverage gap behind unambiguous prose;
**UNDEC** — prose the document does not decide; **DEF** — prose that answers
the question two ways, changing what a conforming node does. "Demo" gives the
divergence observed on a concrete input signed with `keys.json` keys
(base → variant).

| # | survivor | decision changed | class | demo (base → variant) | defect |
|---|---|---|---|---|---|
| 1 | `rotate-revoke-open` | rotate/revoke bodies open (table says "well-formed", not "closed") | DEF | device-signed rotate with an extra body key: `decode` → **accepted, new wg key installed** | D1 |
| 2 | `bundle-learned-keys` | bundle checkpoint verified under learned log keys + replayed policy | UNDEC | nas bundle over `served-rotated/checkpoint`: `log-signature` → accepted | D2 |
| 3 | `receipt-learned-keys` | receipt verified under learned log keys | UNDEC | genesis receipt re-signed by `logkey2`: `log-signature` → accepted | D2 |
| 4 | `thr-upper-exclusive` | `thr < len(set)` instead of `≤` | GAP | `signer_thr` 2 with two signers: accepted → `bad-thr` | D3 |
| 5 | `order-after-before-type` | §5.1 step 6 before step 4 | DEF | unknown `t`, `after` 99: `unknown-type` → `after` | D4 |
| 6 | `order-after-before-dup-genesis` | step 6 before step 5 | DEF | second genesis, `after` 99: `dup-genesis` → `after` | D4 |
| 7 | `note-body-before-threshold` | `note` body before step 7 | DEF | unsigned 4097-byte note: `threshold` → `decode` | D4 |
| 8 | `revoke-auth-before-status` | revoke authorisation before `not-active` | DEF | unsigned revoke of a revoked device: `not-active` → `threshold` | D4 |
| 9 | `env-net-late` | envelope `net` judged after step 7 | DEF | unsigned `signer_add` for another net: `decode` → `threshold` | D4 |
| 10–15 | `receipt-swap-{log-signature-receipt, receipt-origin, origin-leaf-hash, leaf-hash-deadline, deadline-entry, entry-expired}` | each adjacent pair of §7's eight steps swapped | GAP | six two-fault receipts, each re-signed by `logkey`: every one changes code | D4 |
| 16 | `cp-body-before-sig` | §10.1 step 4 before step 3 | GAP | size `0138` signed by `stranger`: `log-signature` → `checkpoint` | D4 |
| 17 | `evidence-held-before-policy` | §11.1 step 5 before step 4 | GAP | foreign held head + unparseable policy: `policy` → `held` | D4 |
| 18 | `note-length-only-known` | 68/76 length enforced only on lines matching a trusted key | DEF | served head + a stranger's 70-byte line: `note` → accepted | D6 |
| 19 | `note-utf8-required` | notes must be UTF-8 | UNDEC | served head + a valid stranger cosignature named `norn-witness/\xff`: accepted → `note` | D6 |
| 20 | `vkey-compare-pk-only` | correspondence compares public keys only | UNDEC | policy names pi `norn-witness/pi-alt` (same pk): refused → accepted | D7 |
| 21 | `policy-quorum-last` | no directive may follow `quorum` | UNDEC | witness defined after `quorum`: accepted → refused | D8 |
| 22 | `policy-entry-one-log-line` | trust-file "at most one log line" applied to `policy` entries | GAP | root-signed policy entry = `two-log-lines.txt`: accepted → `decode` | D9 |
| 23 | `vkey-id-upper-ok` | uppercase hex key id accepted | UNDEC | trust with `+BEA4A666+`: refused → accepted | D10 |
| 24 | `vkey-name-ascii-space-only` | "Unicode space" = ASCII whitespace | UNDEC | witness key name with U+2003: refused → accepted | D10 |
| 25 | `vkey-name-space-ok` | no space rule on key names | GAP | witness key name with U+00A0: refused → accepted | D10 |
| 26 | `learned-key-match-pk-only` | a learned log key matches any line it verifies | UNDEC | head signed by `logkey2` under name `log-2`: `log-signature` → accepted | D11 |
| 27 | `cbor-allow-simple` | simple values other than true/false are profile-valid | UNDEC | evidence with `size` = simple(16): `cbor` → `schema` | D13 |
| 28 | `evidence-same-size-refused` | never prove a same-size fork | GAP | genuine same-size fork (logkey + 3 witnesses): proven → `proof` | D14 |
| 29–31 | `cap-bundle-strict`, `cap-bundle-lax`, `cap-bundle-none` | MAX_BUNDLE_BYTES off by one / absent | DECL (declaration false) | 81919-byte valid bundle: accepted → `bundle`; 81920-byte bundle sound in every other respect: `bundle` → accepted | D15 |
| 32 | `rotation-replace-trust-key` | learned keys replace the trust key | GAP | informed reader re-reads `served/checkpoint`: accepted → `log-signature` | D16 |
| 33 | `name-cap-plus1` | genesis name ≤ 65 bytes | GAP | genesis with a 65-byte name: `bad-genesis` → accepted | D17 |
| 34 | `name-cap-minus1` | genesis name ≤ 63 bytes | GAP | 64-byte name: accepted → `bad-genesis` | D17 |
| 35 | `trustname-cap-plus1` | network name ≤ 65 bytes | GAP | refused → accepted | D17 |
| 36 | `trustname-cap-minus1` | network name ≤ 63 bytes | GAP | accepted → refused | D17 |
| 37 | `witnessname-cap-minus1` | witness name ≤ 63 bytes | GAP | accepted → refused | D17 |
| 38 | `witnessname-cap-chars` | witness name counted in characters | GAP | 65 bytes / 33 chars: refused → accepted | D17 |
| 39 | `labels-max-31` | ≤ 31 labels | GAP | request with 32 labels: accepted → `decode` | D17 |
| 40 | `labels-empty-reject` | present-empty `labels` refused | GAP | `labels: {}`: accepted → `decode` | D17 |
| 41 | `cbor-empty-key` | empty map key allowed | GAP | label key `""`: `decode` → accepted | D17 |
| 42 | `tiles-missing-ok` | an unfetchable hash tile is skipped | GAP | `served/` minus `tile/0/000.p/138`: `unserved` → accepted | D18 |
| 43 | `loop-missing-checkpoint-note` | missing checkpoint reported as `note` | GAP | `unserved` → `note` | D18 |
| 44 | `tilepath-no-x` | no `x` prefix on non-final groups | GAP | index 1000: `tile/0/x001/000` → `tile/0/001/000` | D18 |
| 45 | `root-b64-unpadded-ok` | unpadded root line | GAP | re-signed + re-cosigned: `checkpoint` → accepted | D18 |
| 46 | `cosig-wrong-length-ignored` | 68-byte line under a listed witness's name+id ignored | GAP | `cosignature` → accepted | D18 |
| 47 | `leaf-b64-unpadded-ok` | unpadded receipt leaf hash | GAP | `leaf-hash` → accepted | D18 |
| 48 | `trust-origin-casefold` | trust `origin` compared case-insensitively | GAP | uppercase origin + matching key name: refused → accepted | D18 |
| 49 | `enroll-dupwg-other-only` | `dup-wg` for enroll = another device only | DECL | unreachable (dup-id fires first) | — |
| 50 | `entry-hash-canonical` | `entry_hash` over re-encoded form | DECL | unreachable | — |
| 51 | `note-split-last-blank` | text ends at the last blank line | DECL | unreachable with fixed line counts | — |
| 52 | `sig-no-dedup` | a key may count twice | DECL | unreachable (repeated kid is `decode`) | — |
| 53 | `state-net-from-genesis` | `state.net` from entry 0 | DECL | unreachable | — |
| 54 | `t-quorum-none-zero-clock` | `quorum none` yields T = 0 with a clock | DECL | needs a second anchor | — |

Totals: DEF 7 · UNDEC 9 · GAP 29 · DECL 9.

Eleven hooks are never reached by any vector at all — the suite contains no
input on which the rule is even evaluated: `cbor-allow-simple`,
`cbor-empty-key`, `labels-empty-reject`, `loop-missing-checkpoint-note`,
`rotate-revoke-open`, `sig-no-dedup`, `t-quorum-none-zero-clock`,
`tilepath-no-x`, `tiles-missing-ok`, `vkey-id-upper-ok`,
`vkey-name-space-ok`.

### 2.2 Composites

**Survivor × survivor (1431 pairs).** All 1431 pass: no two survivors
interact, so the 54 are independent holes, not one hole seen 54 times.

**Survivor × caught variant (54 × 259 = 13986 pairs).** 13975 are still
caught. 11 pass — a composite "rescuing" a variant the suite caught alone:

| composite | genuine? | why |
|---|---|---|
| `evidence-same-size-refused` + `evidence-held-root-unbound` | **genuine** | refusing every same-size file hides the missing `held_root` binding: `bad-held-root-at-same-size` is refused anyway (D14) |
| `evidence-same-size-refused` + `evidence-proof-at-same-size-ok` | **genuine** | same mechanism for `bad-proof-at-same-size` (D14) |
| `rotation-replace-trust-key` + `policy-rotation-ignored` | **genuine** | the informed reader now refuses `served-superseded` for `log-signature` instead of `quorum`, and that case names no code (D16) |
| `note-split-last-blank` + `note-trim-trailing-newlines` | **genuine** | ending the text at the *last* blank line turns `23-extra-final-newline` into an empty signature block, which is refused as `note` anyway, hiding the trimming reader. Both are framing decisions §12.1 calls unvectorable / vectored respectively |
| `env-net-late` + `env-no-net-check` | artifact | the first switch re-imposes the net check at a later step, so the composite is `env-net-late` alone |
| `note-length-only-known` + `note-length-unchecked` | artifact | the first re-imposes the length check on matched lines |
| `note-length-only-known` + `note-payload-at-least` | artifact | same |
| `order-after-before-type` + `after-ignored` | artifact | the early `after` test does not consult the step-6 switch |
| `order-after-before-type` + `order-threshold-before-after` | artifact | `after` already runs before step 4, so moving step 7 ahead of step 6 changes nothing; `101` still sees `after` first |
| `revoke-auth-before-status` + `revoke-pooled` | artifact | the early authorisation test is the unpooled rule, so pooling never runs on `bad-revoke-neither-quorum` |
| `witnessname-cap-minus1` + `witnessname-cap-plus1` | artifact | the two cancel: the cap is 64 again |

Four genuine rescues; seven are two switches implementing one decision at two
code points, whose composite equals one survivor alone.

## 3. Defects

Most severe first. Each: the section and the exact words at fault; what a
second implementer cannot know or could reasonably get wrong; the vector or
surviving variant that proves it; the smallest change that closes it.

### D1 — `rotate`/`revoke` bodies: "well-formed", not "closed" (§5.1 table vs §4.0)

- **Words.** §5.1's table, rows `rotate` and `revoke`: "body well-formed
  (`decode`)". Every other row: "body well-formed **and closed** (`decode`)".
  §4.0: "**Bodies are closed schemas too** … a body with an unknown key … is
  `decode`", and §4.0 also says "a reader implements from the row".
- **What a second implementer can get wrong.** Implementing §5.1 row by row —
  as the document says readers do — gives open `rotate`/`revoke` bodies. That
  is a reading of the text, not a slip, and it changes the state: the rotate
  is applied and a new WireGuard key installed.
- **Proof.** Survivor `rotate-revoke-open` — its hook is never even reached:
  no vector carries an unknown key in a `rotate` or `revoke` body. Demo:
  `[log/0-genesis, log/1-enroll-nas, rotate{device_id:"nas",
  wg_pk:SHA-256("demo-wg-nas2"), comment:"x"}]`, signed by `nas`'s device key
  → base `decode`, variant **accepted, `nas` re-keyed**. The two nodes then
  install different keys for `nas`, and every later `rotate`/`revoke` of `nas`
  is judged against different states.
- **Smallest change.** Write "well-formed and closed" in both rows; ship
  `bad-rotate-unknown-body-key` and `bad-revoke-unknown-body-key`.

### D2 — after a log-key rotation, bundles and receipts have no defined verification key (§7, §8, §8.1 vs §9.4)

- **Words.** §8: "The bundle is self-contained, so it can be checked by
  someone holding only `norn.trust`". §8.1: "verify its checkpoint per §10 —
  this network's origin, **this network's log key**, and a satisfied witness
  quorum"; condition 1: "the bundle's checkpoint verifies under **the node's
  trust policy (§9)**". §7: "The note MUST verify under **the anchored log
  key**". Against §9.4: "A checkpoint MUST be signed by `norn.trust.log_key`,
  or by a `pk` in `log_keys` of a state this node has already accepted", and
  `overlap` obliges the log to keep the old key only "for at least `overlap`
  seconds".
- **What cannot be known.** Once `overlap` has passed, the log signs heads and
  receipts with the new key only. A holder of only `norn.trust` — the
  audience §8 sells bundles to — cannot verify any bundle or receipt made
  afterwards; a node that has replayed may use its learned keys or may not
  ("this network's log key" and "the anchored log key" do not say), and
  whether a replayed `policy` replaces "the node's trust policy" for bundles is
  unstated (§11.1 states it for evidence; §8.1 does not). The fixture itself
  rotates twice (`27-log_key`, index 90).
- **Proof.** Survivors `bundle-learned-keys`, `receipt-learned-keys`. Demos:
  `proofs/nas.bundle` with its checkpoint replaced by
  `served-rotated/checkpoint` (same tree, signed by `logkey2`) →
  `log-signature` vs accepted; the genesis receipt re-signed by `logkey2` →
  `log-signature` vs accepted. Both readers pass all 708 checks.
- **Smallest change.** One sentence in §7 and §8.1: the note/bundle checkpoint
  is verified "under the verifier's trusted log keys (§9.4) and its current
  policy"; and either drop "only `norn.trust`" from §8 or say a bundle made
  after a rotation is checkable only by a reader that has replayed it. Vector:
  the two demo files, served-rotated style (refused fresh, accepted informed).

### D3 — the inclusive threshold bound is unpinned (§5.1, §5.2 `bad-thr`)

- **Words.** "`signer_thr`, `root_thr` | … `1 ≤ thr ≤ len(set)` (`bad-thr`)".
- **What can go wrong.** The prose is clear; the suite does not hold anyone to
  it. Every accepted threshold entry sets `thr` below the set size
  (`18-signer_thr-2` with three signers, `23-root_thr-3` with four roots), and
  `bad-thr` is above it, so `<` for `≤` — the commonest off-by-one — passes,
  and it bites on the commonest governance act there is, n-of-n.
- **Proof.** Survivor `thr-upper-exclusive`. Demo: `signer_thr` 2 with two
  signers, signed by root1+root2 → accepted vs `bad-thr`; the two nodes then
  count every later `enroll`'s signers against different thresholds.
- **Smallest change.** Add an accepted `signer_thr` (or `root_thr`) equal to
  its set's size to `log/`.

### D4 — "normative" orderings that the text licenses reversing, and orderings no vector reaches (§5.1, §7, §10.1, §11.1)

- **Words.** §5.1: "The order is **normative** … An ordering with no such
  vector is an ordering a second implementation **may reverse**." §5.3: "Two
  implementations MUST produce byte-identical canonical JSON", and the reason
  code is part of that JSON (`rejected`). §7: "a reader MUST check in this
  order"; §12.1: "§7 receipt, codes and check order | … 9 `receipt-bad/`
  cases".
- **What cannot be known.** Read as written, the §5.1 sentence permits
  reversing any pair of steps that lacks a two-fault vector, while the same
  paragraph calls the order normative — the question is answered both ways,
  and the answer lands in the canonical state. Outside replay there is no such
  licence, but the orders are simply untested: no `receipt-bad/` file has
  faults in two adjacent steps, so §12.1's claim that the receipt *order* is
  vectored is not true.
- **Proof.** Replay (all demos change the `rejected` reason):
  `order-after-before-type` (`unknown-type` → `after`),
  `order-after-before-dup-genesis` (`dup-genesis` → `after`),
  `note-body-before-threshold` (`threshold` → `decode`),
  `revoke-auth-before-status` (`not-active` → `threshold`), `env-net-late`
  (`decode` → `threshold`). Receipts: all six adjacent swaps of §7's steps
  survive, each with a two-fault receipt re-signed by `logkey`. §10.1:
  `cp-body-before-sig` (size `0138` under an untrusted signer:
  `log-signature` → `checkpoint`). §11.1: `evidence-held-before-policy`
  (`policy` → `held`).
- **Smallest change.** Replace the §5.1 sentence with "An ordering with no such
  vector is still normative; it is merely untested." Ship one two-fault vector
  per untested adjacent pair (the demo inputs are ready-made), and correct
  §12.1's receipt row until they exist.

### D5 — two definitions of a checkpoint's age (§8.1 vs §15)

- **Words.** §8.1 condition 4: "`elapsed` is the node's monotonic reading now
  minus its monotonic reading when it learned this checkpoint's quorum time".
  §15: "Its estimate of now is the newest quorum time it has seen plus
  monotonic elapsed time since seeing it; an older time MUST NOT move that
  estimate backwards. The age of a held checkpoint is this estimate minus that
  checkpoint's quorum time." §15 then says "The freshness states and their
  ordered thresholds are §8.1".
- **What cannot be known.** The two agree only while the held checkpoint's
  quorum time is the newest one seen. A newly adopted, larger head can carry
  an *older* quorum time (a different witness subset, or skewed witness
  clocks). Example, under `trust.cbor`'s 2-of-3 policy: held A =
  `served/checkpoint`, T = 1760003607, learned at monotonic 0; adopted B, a
  grown head cosigned only by pi at …605 and friend at …620 (each witness's
  clock moving forward), so T = 1760003605, learned at monotonic 50;
  S = 600, `S_hard` = 650. At monotonic 650: §8.1 gives
  elapsed(B) = 600 → `fresh`; §15 gives age(B) = 1760003607 + 650 − 1760003605
  = 652 → `hard_stale`, and §13.2 then empties the desired peer set. §8.1 also
  says a node with no quorum time "has no estimate, and under §5.3 judges no
  expiry at all", tying expiry to the running estimate, where §5.3 and §13
  judge it at "the checkpoint's witness time" — a smaller version of the same
  split (my C89/C90).
- **Proof.** No vector can see it: `detect/staleness.json` supplies `elapsed`
  as a number. Prose answering one question two ways.
- **Smallest change.** Define `elapsed` once (e.g. §8.1: "`elapsed` is §15's
  age") and give `staleness.json` a case built from two (T, learned-at) pairs.

### D6 — whose note rules win, and lines nobody trusts (preamble, §7, §10)

- **Words.** Preamble: "Norn reuses these specifications verbatim; **where
  they conflict with this document, they win**". §10: "The canonical
  signed-note implementation does not impose this; Norn does." §7: "What
  follows the key id **depends on the algorithm the key was published
  under**" and "Any other decoded length is malformed note framing". §10: "A
  line naming anyone the policy does NOT list is IGNORED, not refused … a
  reader that refuses over one stops accepting checkpoints everybody else
  accepts."
- **What cannot be known.** The document says its own stricter note rules
  exceed the reused specification and also that the reused specification wins
  on conflict, so which governs is answered both ways. The exact-length rule
  is applied to every line, including lines from keys the reader does not
  hold — whose algorithm, and therefore length, §7 itself says it cannot know.
  A shared log carrying one cosignature from a witness on a third algorithm is
  then refused by every reader of §7 as written, exactly the outcome §10 says a
  reader must not cause. Separately, nothing says whether note text or key
  names must be UTF-8.
- **Proof.** Survivors `note-length-only-known` (served head plus a stranger's
  70-byte line: `note` vs accepted) and `note-utf8-required` (a valid stranger
  cosignature named `norn-witness/\xff`: accepted vs `note`).
- **Smallest change.** "§7 and §10 are Norn's profile of `c2sp.org/signed-note`
  and govern where they are stricter." Apply the 68/76 length only to lines
  whose name and key id match a trusted key (framing alone for the rest). One
  sentence on UTF-8 in notes. Vectors: the two demo heads.

### D7 — "the same keys": which comparison? (§9.1)

- **Words.** `policy` row: "MUST name **exactly** the witnesses `witnesses`
  lists, **with the same keys**"; "it MUST be `norn.trust.log_key`". Grammar
  table: "Keys are compared by their parsed underlying public key, not by vkey
  text, name or key ID".
- **What cannot be known.** Whether "same key" is the same verifier key (name,
  algorithm, public key) or the same public key, the only comparison the
  section defines. Under the second, a trust file whose `witnesses` publishes
  pi as `norn-witness/pi` and whose policy publishes the same public key as
  `norn-witness/pi-alt` is valid, and §10 (which matches lines on name **and**
  key id) then depends on which of the two vkeys a node matches with: under the
  policy's, pi's real cosignatures name nobody. `42-witness-key-mismatch`
  changes the public key, so both comparators refuse it.
- **Proof.** Survivor `vkey-compare-pk-only`; demo above: refused vs accepted.
- **Smallest change.** "the same verifier key — name, algorithm and public key"
  (and likewise for the `log` line); vector renaming only a note name.

### D8 — may a directive follow the `quorum` line? (§9.1)

- **Words.** "there is **exactly one** `quorum` line, and it names a witness, a
  group, or the reserved name `none`"; table: "exactly one line, naming a
  previously-defined witness, a previously-defined group…".
- **What cannot be known.** Whether `witness`/`group`/`log` lines after
  `quorum` are allowed. The answer decides whether a root-signed `policy`
  entry is applied (and so the quorum every later checkpoint must meet) and
  whether a trust file loads.
- **Proof.** Survivor `policy-quorum-last` (my C64); demo `witness pi …\nquorum
  pi\nwitness vps …\n`: accepted vs refused.
- **Smallest change.** One row in the grammar table, and a policy vector.

### D9 — a `policy` entry with two `log` lines is never replayed (§9.1, §5.1)

- **Words.** §9.1: "A Norn **trust file**'s policy carries at most one … That
  limit is the trust file's, not the grammar's: a `policy` entry (§5.1) has no
  such correspondence", and two `log` lines are "what a rotation looks like
  from outside".
- **What can go wrong.** Clear prose, no entry-layer vector (only
  `policies/two-log-lines` at the grammar layer). A verifier that reuses its
  trust-file loader for `policy` entries refuses exactly the policy a log-key
  rotation produces, keeps the old quorum, and disagrees with every other node
  about which heads to accept.
- **Proof.** Survivor `policy-entry-one-log-line`; demo: root-signed `policy`
  entry carrying `two-log-lines.txt` → accepted vs `decode`.
- **Smallest change.** Put such an entry in `log/`.

### D10 — verifier-key syntax left open, and a vector that cannot isolate its rule (§7, §9.1)

- **Words.** §7: "`<name>+<key_id as 8 hex digits>+<base64(alg ‖ pk)>`" (case
  unstated). §9.1: "Key names MUST be non-empty and contain neither `+` nor **a
  Unicode space**" (undefined; the same section calls U+00A0 and U+0085
  "content").
- **What cannot be known.** Whether `+BEA4A666+` is a valid key id; which
  characters "a Unicode space" covers (White_Space property? category Zs?).
  And `policies/bad-vkey-name-space` puts an ASCII space in the name, which the
  field-separator rule refuses before any key parser runs, so the name rule is
  untested — §12.1 records the analogous carriage-return case as
  non-isolating but not this one.
- **Proof.** Survivors `vkey-id-upper-ok`, `vkey-name-ascii-space-only`,
  `vkey-name-space-ok`; demos on `trust.cbor` (refused vs accepted each).
- **Smallest change.** "8 lowercase hex digits"; "a character with the Unicode
  White_Space property"; a vector with U+00A0 inside a vkey name.

### D11 — what name does a learned log key sign under? (§9.4, §4.3, §7)

- **Words.** §9.4: "signed by `norn.trust.log_key`, or by **a `pk`** in
  `log_keys`"; §4.3 `log_key` body: "`pk` (bytes32)". §7 matches signature
  lines by name and key id, and a bare `pk` has neither.
- **What can be got wrong.** The name is inferable from §2 (the log key's
  note name equals `origin`; my C58), and `served-rotated/` is consistent with
  it, but a reader that matches learned keys by public key alone passes too.
- **Proof.** Survivor `learned-key-match-pk-only`; demo: served head signed by
  `logkey2` under the name `log-2`, read by a node that replayed the rotation
  → `log-signature` vs accepted.
- **Smallest change.** "A learned key is the verifier key
  `<origin>+<id>+base64(0x01 ‖ pk)`."

### D12 — a served log whose entry 0 is not `genesis_hash` has no refusal code (§10.1, §9.3, §5.1)

- **Words.** §10.1: "a **closed list**: an implementation reports one of these
  codes and no other". §9.3: "`nornd` … MUST refuse one whose `genesis_hash`
  does not match entry 0". §5.1: an entry-0 failure aborts to the zero state.
- **What cannot be known.** Whether the loop refuses such a log (with no code
  to report) or adopts the aborted state and hands the enforcer an empty set.
- **Proof.** No variant can express the refusal. Constructed input: the
  138-entry log with a different, root-signed genesis, a fresh checkpoint
  signed by `logkey` and cosigned by pi, vps and friend over it → my loop
  (which follows the closed list) accepts it, replay records
  `{0, bad-genesis}`, proven set **empty**.
- **Smallest change.** Add a `genesis` code to §10.1 between `head` and `fork`.

### D13 — CBOR simple values other than the four named (§4.0)

- **Words.** "Floats, tags, `undefined`, indefinite-length items |
  forbidden"; "`null` | forbidden"; "Booleans | valid CBOR items". Simple
  values 0–19 and 32–255 are not mentioned, and RFC 8949 core deterministic
  encoding allows them.
- **What cannot be known.** Whether they are profile violations; §11.1's
  closed codes then split between `cbor` and `schema`.
- **Proof.** Survivor `cbor-allow-simple` (hook never reached); demo:
  `fork/evidence.cbor` with `size` = simple(16) → `cbor` vs `schema`.
- **Smallest change.** "Simple values other than `false` and `true` are
  forbidden"; one `entries-hostile/bare-simple` file.

### D14 — a same-size fork is never proven by any vector (§11.1)

- **Words.** `proof` row: "**Empty when `size` equals `held`'s size**, where
  the two signatures say it alone"; step 3 "or, when `size` is `held`'s own
  size, that `held_root` is the root `held` is signed over".
- **What can go wrong.** Every same-size file in `fork/` is a negative, so a
  reader that never proves a same-size fork — the plainest equivocation there
  is — passes; in composite it also rescues `evidence-held-root-unbound` and
  `evidence-proof-at-same-size-ok`, both caught alone.
- **Proof.** Survivor `evidence-same-size-refused`; demo: held =
  `served/checkpoint`, conflicting = a 138-entry head with another root signed
  by `logkey` and cosigned by all three witnesses, empty proof → fork proven
  vs `proof`.
- **Smallest change.** Ship that file in `fork/cases.json`'s `sound`.

### D15 — §12.1's reason for not vectoring MAX_BUNDLE_BYTES is false (§8.1, §12.1)

- **Words.** §12.1: "A valid bundle has no slack: `device` is bound to the
  entry, `entry` fixes the leaf hash, `checkpoint` and `proof` are what they
  are … so an oversize bundle is necessarily wrong in a second way".
- **What is wrong.** `checkpoint` is "the signed checkpoint note, verbatim",
  and §10 makes extra cosignature lines from unlisted witnesses normal and
  ignored, so a bundle can grow without bound while staying valid — the same
  kind of slack (a field that grows while staying correct) §12.1 relies on to
  vector the trust and evidence caps.
- **Proof.** Survivors `cap-bundle-strict`, `cap-bundle-lax`,
  `cap-bundle-none`. Demo (`demo-artifacts/`): `proofs/nas.bundle` padded with
  real `stranger` cosignatures to exactly 81919 bytes (valid: accepted vs
  `bundle` under the strict variant) and to 81920 bytes (sound in every other
  respect: `bundle` vs accepted under the lax one).
- **Smallest change.** Ship the two files as `proofs/at-the-cap` and
  `proofs-bad/one-past-the-cap`; delete the bullet.

### D16 — §9.4's "alongside" and the superseding policy are not pinned the way §12.1 says (§9.4, §12.1)

- **Words.** §12.1: "§9.4 the anchor key is kept **alongside** |
  `served/checkpoint` … a reader that *replaces* `log_keys` with the published
  ones cannot read the head the log is serving."
- **What is missing.** No manifest asks a reader that has replayed the
  rotation to read `served/checkpoint`; `served-rotated/` asks only "refuse
  fresh, accept informed". And `served-superseded/`'s informed refusal has no
  code, so in composite `rotation-replace-trust-key` rescues
  `policy-rotation-ignored`: the informed reader refuses for `log-signature`
  instead of `quorum` and passes.
- **Proof.** Survivor `rotation-replace-trust-key`; demo: informed reader
  re-reads `served/checkpoint` → accepted vs `log-signature` (the node stops
  accepting the head its log is actually serving).
- **Smallest change.** Add "informed reader accepts `served/checkpoint`" to
  `served-rotated/cases.json`, and `codes: {informed: "quorum"}` to
  `served-superseded/cases.json`.

### D17 — boundary values still pinned far from the boundary (§4.0, §9.1, §16.1)

- **Words.** Genesis `name` "1–64"; trust `name` "text, 1–64 bytes"; witness
  "`name` is 1–64 bytes"; `labels` "≤ 32 entries"; map keys "1–23 bytes".
  §12.1 on the genesis name: "both ends, because a reader enforcing only the
  cap and one enforcing only the floor are different implementations" — the
  ends shipped are *empty* and *far over*, not 64/65.
- **Proof.** Survivors `name-cap-plus1`, `name-cap-minus1` (a 65- or 64-byte
  genesis name aborts one reader's whole network and not the other's),
  `trustname-cap-plus1`, `trustname-cap-minus1`, `witnessname-cap-minus1`,
  `witnessname-cap-chars`, `labels-max-31` (32 labels), `labels-empty-reject`
  (`labels: {}`), `cbor-empty-key` (label key `""`); every one with a demo.
- **Smallest change.** At-the-cap positives and one-past negatives, in
  multi-byte characters, exactly as run 12 did for `reason`, `text` and label
  values.

### D18 — refusals on the served path and in receipts that no vector reaches (§6, §7, §10.1, §9.1)

- **Words.** §10.1 step 1: "The same code for any file a later step needs and
  cannot fetch — an entry bundle (step 8), a hash tile (step 11)"; §6 paths
  "`x001/x234/567`"; §6 root "standard base64 with padding"; §7 "Once a line's
  name and key id match a trusted key, verification also checks the length
  for that key's algorithm"; §7 step 5 leaf hash "standard base64"; §9.1
  `origin` "MUST equal".
- **Proof.** Survivors `tiles-missing-ok` (a missing hash tile is never served
  in the suite: `unserved` vs accepted), `loop-missing-checkpoint-note`,
  `tilepath-no-x` (no tile index ≥ 1000 exists: `tile/0/x001/000` vs
  `tile/0/001/000`), `root-b64-unpadded-ok` (`checkpoint` vs accepted),
  `cosig-wrong-length-ignored` (vectored for the log key only: `cosignature`
  vs accepted), `leaf-b64-unpadded-ok` (`leaf-hash` vs accepted),
  `trust-origin-casefold` (vectored for the checkpoint origin, not the trust
  file's). Each has a demo.
- **Smallest change.** One vector each.

### D19 — §12.1 coverage rows that are inaccurate in either direction (low)

- "§14 canonical JSON | every `.json`": 15 of the suite's 92 `.json` files
  (the `cases.json` of the served-log, checkpoint, detect, fork, proof and
  anchor directories, `detect/staleness.json`, `proofs/right-edge.json`) are
  pretty-printed, not §14 canonical; §14 itself scopes the rules to
  `state.json` and the entry mirrors.
- "The median, as distinct from the k-th newest … no reading of the fixture
  tells them apart": `proofs/cases.json`'s `replayed_policy_quorum_time` is a
  3-of-3 computation, where the k-th newest is the oldest and the median is
  not; a median reader gets 1760003607 and fails. (Over-modest, harmless.)
- The receipt-order, bundle-cap and anchor-key rows are corrected under D4,
  D15 and D16.
- **Smallest change.** Correct the rows.

## 4. Declared survivors, confirmed

`enroll-dupwg-other-only`, `entry-hash-canonical`, `note-split-last-blank`,
`sig-no-dedup`, `state-net-from-genesis`, `t-quorum-none-zero-clock` survive
exactly as §12.1's "What is not vectored" says, and for the stated reasons
(each is unreachable by construction or needs a second anchor). The
`MAX_BUNDLE_BYTES` declaration is the exception — its reasoning is wrong
(D15).

## 5. Decisions the vectors pinned, and decisions they did not

Of my 95 logged decisions, the vectors confirmed every one they reach; none
had to be reversed. The ones whose alternative survives are C02 (D13), C05
empty key (D17), C16 (D1), C19 (D17), C49/C50 (D6), C58 (D11), C64 (D8), C66
and C67 (D10), C72/C73 (D7), C78 and C82 (D2), C89/C90 (D5). C12, C29, C31,
C81 and C95 were not given hooks: C12's alternative is caught
(`gov-body-before-threshold`), and C29/C31/C81/C95 change nothing a closed
vocabulary or a state field records.

## 6. Verdict

Passing every vector was never the criterion. The document is unusually
careful, and its suite is strong where it has been attacked before. But a
second implementer reading it cold can still, by following its own words,
re-key a device that another node refuses to re-key (D1), lose the ability to
check any bundle or receipt after the log rotates its key (D2), write a
different canonical state from the same log because the text both mandates
and licenses an ordering (D4), and compute a different freshness state — and
so a different peer table — from the same history (D5). Those are prose that
answers a protocol question two ways, and surviving variants that change what
a conforming node does on input a network can really see.

SPEC INSUFFICIENT
