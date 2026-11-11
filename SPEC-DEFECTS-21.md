# Cold gate run 21 — specification defects

Reader: an independent implementer working from `SPEC.md` alone, with the vector
suite in `testdata/vectors/`. Implementation: Go, standard library only,
`work/impl/` (package `norn`, harness `cmd/harness`, counterexample builder
`cmd/counter`). Reading decisions were fixed in `work/decisions.md` (C01–C73)
before any vector, manifest or the vectors README was opened.

## 1 Tally

**Digests.** `shasum -a 256 -c SHA256SUMS`: 1229/1229 OK. The harness re-checks
all 1229 in Go and also checks that every file in the tree is listed (1230
checks, all pass).

**First full run:** 5004 checks, 4974 pass, **30 fail**. All 30 were harness
mistakes, none an implementation or specification fault:

- 2: `log/`'s replayed state is shipped at the vector root (`state.json`), not
  `log/state.json`; the harness looked in the wrong place.
- 27: the harness required a `.reason` file beside each `genesis/<case>/00-genesis`;
  §12 promises `.reason` files only for the multi-entry replay fixtures, and
  none ship under `genesis/`.
- 1: an expectation I added myself (that `checkpoints-good/cosignature-time-at-the-cap`
  keeps T at 1760003607 or 2⁶³−1). §5.3 gives 1760003614 (pi's newest line at
  2⁶³−1 plus friend's at …614 is the newest instant that satisfies 2 of 3); the
  implementation was right and the expectation was dropped.

**Final run:** **4975 checks, 4975 pass, 0 fail** (1.3 s). By area:

| area | checks | area | checks |
|---|---|---|---|
| sums | 1230 | cctv (outcome) / cctv-flag | 914 / 914 |
| citations (every `rules` phrase found in the named SPEC section) | 541 | log (162 entries, reasons, `.reason`, state) | 277 |
| log-order / log-rules / log-cas / log-republish / log-edges / log-admission / log-empty | 123 / 86 / 68 / 39 / 28 / 15 / 1 | genesis / genesis-good | 54 / 4 |
| entries / entries-hostile / entries-utf8 | 16 / 17 / 3 | keys | 30 |
| trust / trust-good / trust-bad | 4 / 13 / 59 | policies (parse + evaluate rows) | 85 |
| requests / requests-bad / heads-run16 | 17 / 30 / 8 | receipt / receipt-good / receipt-bad / receipt-rotated | 2 / 4 / 25 / 3 |
| served / checkpoints-good / checkpoints-bad (49 codes + `signature_blind_accepts`) | 5 / 2 / 50 | served-large (accept, tiles, 40 path rows) / served-large-bad / served-bad / grown-log | 44 / 3 / 8 / 9 |
| served-extra-witness / -name-collision / -unknown-algorithm / -stranger-name / -twice-cosigned / -superseded / -empty-entry / -genesis | 1/1/1/1/1/4/3/4 | served-rotated / -rotated-earlier / -rotated-wrong-name | 5 / 2 / 2 |
| detect (9 pairs + 12 staleness rows) | 21 | dropped-witness / unreached-witness / quorum-none / genesis-unapplied / replayed-policy | 2 / 2 / 3 / 3 / 8 |
| proofs / proofs-bad / proofs-rotated | 20 / 27 / 2 | proven (4 T cases, 8 bundles, 8 grants, 49 grant labels) | 69 |
| fork (11 sound, 43 codes, rotated key, caps, conflicting) | 59 | anchors | 3 |

Every closed code a manifest names is compared exactly (`codes` maps, replay
reasons, §7, §10.1 loop and bundle codes, §11.1 codes). Reader models the
manifests leave implicit, and how I read them: a *fresh* reader holds only the
named trust file; an *informed* reader verified and replayed `served/` and uses
the learned keys and replayed policy; it **holds** `served/`'s head where that
matters (`served-superseded`) and where it makes no difference (bundles,
evidence), and holds no head in `served-rotated-earlier`, `dropped-witness` and
`heads-run16`, whose answers require that (L7); `detect/` stored heads hold `served/`'s first
`size` entries unless `held: none`; `receipt-bad` binds the submitted leaf to
`receipt.json`'s `leaf_hash`, with `now_unix` as the checking time.

## 2 The sweep

**Method.** Every variant is a named switch at one decision point of the base
implementation (`norn.V(name)`); the harness runs the whole suite (all checks
except the digest and citation areas, which no implementation choice can move)
once per variant and reports the checks that newly fail. A variant that fails
no check is a survivor. Three rounds: 500 variants, then 508 (8 added for
§12.1's declared rules, 2 variants found buggy and fixed), then 15 more
(boolean coercion of each remaining uint member, the split-root comparisons and
binding structure). The list (`work/sweep/variants3-all.txt`; one-line descriptions from
`harness -list`) by family, with survivors:

| family | variants | survive | family | variants | survive |
|---|---|---|---|---|---|
| replay rules (signature resolution, roles, thresholds, `prev`, params, genesis, `log_key`/`policy` invariants, caps, lifecycle) | 90 | 4 | replay check order (every adjacent pair of every §5.1 list) | 35 | 0 |
| trust file, origin, fingerprint | 44 | 4 | policy grammar and evaluation | 35 | 1 |
| verifier loop, tiles, paths, Merkle, inclusion and consistency | 33 | 0 | requests and bech32m | 32 | 5 |
| CBOR profile (every ban; both sides of every cap) | 27 | 0 | note framing, verifier keys, cosignature message | 26 | 1 |
| fork evidence | 26 | 3 | checkpoint steps and their order | 25 | 1 |
| bundles and binding | 24 | 3 | grants | 20 | 0 |
| envelope, `sigs`, preimage, kid, leaf hash | 19 | 0 | receipts | 15 | 1 |
| canonical state and JSON | 15 | 1 | boolean coercion of a uint member | 12 | 11 |
| freshness, expiry, anchor digest | 11 | 0 | evaluation time and the held head | 11 | 2 |
| byte and content keys | 9 | 2 | NORN-ED25519-v1 | 8 | 2 |
| rotation (learned keys and policies) | 6 | 0 | **total** | **523** | **41** |

**Counts.** 523 distinct single variants; **482 caught, 41 survive.**
`work/sweep/single-final.tsv` gives each variant's catch count and its first
catching checks.

**Survivors, classified.**

*Equivalent — no input distinguishes base and variant (12):*

| variant | why |
|---|---|
| `b32-first-1` (separator = first `1`) | HRP `norn` holds no `1` and the data charset has none, so first and last `1` coincide on every string that can decode |
| `note-split-last-space` | a name holding a space fails the name rule, so both splits refuse the same lines as `note` (§7 says so) |
| `ed-no-order-R` | with `A` of order L, the cofactorless equation forces `R = [S]B − [k]A` into the prime-order subgroup, and the stdlib compares canonical bytes; the R clause only matters under the cofactored equation, where it **is** pinned (`ed-cofactored-strict-A` is caught by 8 checks, and `cmd/counter` shows it accepting `requests-bad/torsion-R-signature`) |
| `req-sig-stdlib` | the same argument for Go's library once `device_pk` passed point admission at decode (another library may differ) |
| `ed-noncanonical-A` (declared, §12.1) | verified by computation: none of the 38 lenient encodings with y ≥ p, nor the two negative-zero x = 0 encodings, decodes to a point of order L (`cmd/counter` scenario `ed-canonical-clauses-implied`) |
| `ev-split-above-size-ok` | implied: §11.1 step 7 makes `conflicting.size = size`, and a split above it cannot chain to `conflicting` |
| `trust-witness-alg-unchecked`, `trust-witness-name-loose`, `trust-witness-name-no-cap` | correspondence puts the witness's verifier key and name into the policy, whose grammar refuses the same thing (§12.1's table says this for 15/16, 32 and 54) |
| `req-pk-any-length`, `req-no-size-cap`, `pol-none-member-rule-absent` | declared in §12.1; equivalent (the point rule refuses a non-32-byte key; the text layer and the entry cap bound every request; `none` is never defined) |

*Declared unobservable or unreachable in §12.1, confirmed (8):*
`dd-genesis-no-bytes`, `dd-reencoded-bytes`, `dupkey-by-bytes`,
`genesis-no-kid-check`, `enroll-dupwg-other`, `state-net-from-genesis`,
`t-count-unverified`, `cp-witness-alg-unchecked-verify` (section 4).

*Genuine — a concrete input separates them (21), each with a counterexample in
`work/counter/` built and signed with `keys.json`'s seeds:*

| variant | base → variant on the counterexample | defect |
|---|---|---|
| `held-current-policy` | re-read of the held head carrying a forged line of a dropped witness: `cosignature` → accept | M1 |
| `ev-split-held-root-unchecked`, `ev-split-conf-root-unchecked` | v2 evidence with `split` at a head's own size and `split_root` the other head's root, empty split proofs: `proof` → fork proved | M2 |
| `env-prev-bool-ok`, `env-ts-bool-ok`, `env-v-bool-ok`, `req-v-bool-ok`, `req-ts-bool-ok`, `bdl-v-bool-ok`, `bdl-index-bool-ok`, `ev-version-bool-ok`, `ev-split-bool-ok`, `trust-version-bool-ok`, `trust-maxlag-bool-ok` | a boolean where §4.0 requires a uint: refused (`decode` / `bundle` / `version` / `schema` / invalid trust) → accepted, with different replayed states for the entry cases (a signer added; a device enrolled) | L1 |
| `note-text-optional` | a signer-signed `note` with body `{}`: `decode` → accepted | L2 |
| `req-ts-optional` | an `enroll` whose signed request has no `ts`: `decode` → device `sundial` enrolled | L3 |
| `rcpt-leaf-prefix` | a receipt whose leaf line is 33 bytes, the genesis leaf plus `00`, signed by the log key: `leaf-hash` → accept | L4 |
| `bdl-binding-ignore-after-prev`, `bdl-binding-sigs-loose`, `bdl-binding-net-any-length` | a bundle (real 2-leaf tree, log-signed, quorum-cosigned) around a `rotate` naming nas with `prev: true` / malformed `sigs` / a 15-byte `net`: `binding` → accept | L5 |
| `trust-witness-match-key-name` | `trust.cbor` with the policy's short names `pi` and `vps` swapped between their keys: invalid → valid | L6 |

**Composites.** 2211 composites run (`work/sweep/composites.tsv`):

- **All 41 survivors at once:** survives — a reader holding every surviving
  reading together still passes the whole suite.
- **Survivor × survivor:** 811 pairs, all survive; no two survivors interact.
  Ten composites containing `ed-noncanonical-A` (9 here, 1 below) were not
  run, after the first 31 such composites had all behaved like their other
  half: that variant is equivalent by exhaustive computation, so every
  composite with it reduces to its other half, and each costs minutes without
  the point cache.
- **Survivor × caught:** each survivor paired with every caught variant of its
  own family that at most three checks catch (the fragile ones, which a
  survivor could mask): 1399 pairs, **1396 caught, 3 survive.**
  `dupkey-by-bytes × dupkey-same-role` reduces to the declared survivor (the
  byte comparison overrides the role scope at the same decision point).
  `trust-witness-match-key-name × trust-correspond-by-pk` and
  `× trust-correspond-names-only` are real masking: matching array witnesses to
  policy lines by the verifier key's note name hides a correspondence check that
  compares only public keys (alone caught by `trust-bad/48`) or only names
  (alone caught by `trust-bad/42` and `48`), because those files are then refused for the
  other reason. L6's counterexample separates both composites from base (invalid
  → valid), so they add no defect, and they make L6 worth a vector.

## 3 Defects

Most severe first. No H. Two M. Seven L.

### M1 — The held head's re-read: two sections name two different policies for the same check

**Where, exactly.** §10.1 step 6: "a cosignature line whose name **and** key id
match a listed witness does not verify — listed meaning named by **the policy
in force (§9.4)**, not a witness a `policy` entry has dropped that the trust
file still lists". Against §5.3: "a reader that holds that tree head keeps the
policy and the `T` it accepted it under … The copy's own lines are still
checked as §10 checks every checkpoint: a cosignature line that names a witness
**that policy** lists", and §10's outline: "every line is checked as above,
**under the policy that accepted it**". §10 adds that "where a reader needs an order, §10.1's table decides", so the
table is where an implementer reads each step's rule.

**What a second implementer cannot know.** For a re-read of the held head after
the reader replayed a `policy` entry inside that head's range, which policy
lists the witnesses whose lines must verify. Following §10.1 (the closed table,
and the sentence that explicitly says a dropped witness no longer counts as
listed) gives the current policy; following §5.3 and the outline gives the held
one. They differ exactly when the replayed policy dropped or added a witness.

**Proof.** Surviving variant `held-current-policy`. Counterexample
`work/counter/held-current-policy/`: a two-entry log (`dropped-witness/00-genesis.cbor`
and `01-policy-drops-friend.cbor`) with tiles and a head at size 2 signed by
`logkey` and cosigned by pi, vps and friend, under `dropped-witness/trust.cbor`.
A reader verifies and holds it (accepted under the trust policy, which lists
friend), replays it (the policy in force now names only pi and vps), and is
then served `copy.checkpoint`: the same tree head plus one line under friend's
name and key id whose last signature byte is flipped. Base (held policy):
`cosignature`. Variant (policy in force): friend is unlisted, the line is
ignored, the re-read is accepted. The reverse holds for a witness the new
policy adds. Anyone on the path can append such a line. Neither reader changes
its stored head or its peer table; they differ in whether the log (or a peer
serving the copy) is reported as invalid, which §13.2 turns into an alarm and
§15 into a bad peer response. `served-superseded/forged-pi.checkpoint` cannot
separate the readings: pi is listed by both policies.

**Smallest change.** In §10.1 step 6, after "the policy in force (§9.4)", add:
"— for a re-read of the tree head the reader already holds, the policy that
accepted it (§5.3)". Vector: this counterexample, `cosignature` for the
informed reader holding the head and `accept` for an informed reader that
does not.

### M2 — §11.1's split proof at a head's own size: the root comparison is in one sentence, missing from the code table, and unvectored

**Where, exactly.** §11.1 reader step 4: "that `split_proof_held` chains
(`split`, `split_root`) to `held`'s signed head and `split_proof_conflicting`
chains it to `conflicting`'s — each as step 3 does, **with the same empty-proof
rule at a head's own size**." The `proof` row of the closed code table lists,
for the main proof, "where `size` equals the held size, `held_root` is not the
root the held checkpoint is signed over — there is no proof to check, and this
comparison is the only thing binding `held_root` to anything", but for the
split lists only "a split proof does not chain `split_root` at `split` to its
head, or a split proof is carried where none is required". The `split_root`
row says the proof is "Empty when `split` equals `held`'s size, where the
signature says it alone".

**What a second implementer cannot know.** Whether "the same empty-proof rule"
means only "the proof is empty there" or also "and `split_root` equals that
head's root". The closed code table, which a reader implements step by step
and which the section makes the contract ("the first step whose check fails
decides which"), names only the first. A reader taking it literally accepts an empty split proof at a head's
own size with any `split_root`. §11.1's own guarantee ("An accuser can
understate the split and never overstate it") then fails: the split can be
claimed at the full size of either head.

**Proof.** Surviving variants `ev-split-held-root-unchecked` and
`ev-split-conf-root-unchecked`. Counterexamples
`work/counter/ev-split-held-root-unchecked/evidence.cbor` and
`…-conf-root-unchecked/evidence.cbor`, both made from
`fork/evidence-at-same-size.cbor` (both heads genuinely signed and cosigned,
same size 162, different roots) by setting `split` = 162, `split_root` = the
conflicting (resp. held) root, and both split proofs empty — no signature is
needed, evidence is unsigned. Base: `proof`. Variant: fork proved. Consequence
under §11 rule 3: a node holding the branch whose root the accuser wrote into
`split_root` finds its own branch "has `split_root` at `split`", takes the
common prefix to be its whole held head, and keeps every device it enforces —
including those enrolled on its branch after the real split, which is exactly
what rule 3 exists to remove (SEC-021). Same-size heads are only the simplest
case: with heads of sizes 100 and 80, an accuser can write `size` = `split` = 80,
`split_root` = the 100-head branch's root at 80 with a real consistency proof to
that head, and an empty proof to the 80-head, and the variant reader accepts a
common prefix at 80 that is not one. It needs a genuinely signed equivocation
(the log and a witness quorum misbehaving) and a file written to overstate the
split, which is why this is M and not H.

**Smallest change.** Add to the `proof` row: "…or, where `split` equals a
head's own size, `split_root` is not the root that head is signed over"; and
replace "with the same empty-proof rule" by "with the same rule at a head's own
size: no proof, and `split_root` equal to that head's root". Vector: the two
files above, each `proof`.

### L1 — §4.0's boolean ban is vectored for six members and not for eleven others

**Where.** §4.0: "Booleans | valid CBOR items; schemas MUST reject them outside
`params.rotate_needs_signer`"; §5.1 step 3: "every member of the type §4.1
gives it (`t` text, `ts`, `after` and `prev` uint, `body` a map)". Vectors hold
the ban for `after` (`log-rules/42`), `thr` (`bad-signer_thr-bool`,
`bad-root_thr-bool`, `genesis/21`, `22`), `overlap`, `params` uints,
`expires` (`requests-bad/bool-expires`) and evidence `size`
(`fork/bad-bool-size`). The run 20 row says so for the envelope ("this case
holds after, not every separately checked envelope member"), but §12.1's "What
is not vectored" list names none of the following.

**Unvectored members (each a surviving variant with a counterexample):**
envelope `prev`, `ts`, `v` (`work/counter/env-*-bool-ok/`: a root-quorum
`signer_add` with `prev: false` adds `signer3`; a signer's `note` with
`ts: false` or `v: true` applies); request `v`, `ts` (`req-*-bool-ok/`: device
`sundial` is enrolled); bundle `v`, `index` (`bdl-*-bool-ok/nas.bundle`:
`index: true` reads as 1 and the inclusion proof holds); evidence `version`
(`evidence-v1.cbor` with `version: true` proves the fork) and `split`
(`evidence.cbor` with `split: false`, a zero root and empty proofs proves a
fork claiming no prefix, which §11 rule 3 turns into fail-closed); trust
`version` and `anchor.max_lag`. The text is unambiguous, so a careful reader
gets every one right; but nothing in the suite would tell a reader that coerces
booleans (a lenient CBOR decoder's habit) that it diverges, here on the signer
set and on admission.

**Smallest change.** Name these members in §12.1's "What is not vectored", or
ship one boolean negative per member beside its repaired twin.

### L2 — A `note` body without `text` is refused by inference only

**Where.** §4.3 lists `note | text (string ≤ 4096)` without OPTIONAL; §4.0:
"a body with an unknown key — or missing a required one — is `decode`".
Requiredness is inferred from the absence of an OPTIONAL marker, while the
neighbouring free-text field `reason` is OPTIONAL with "absent is equivalent to
`""`", and §12.1 groups `text` and `reason` together as free text with no lower
bound. **Proof:** `note-text-optional`; `work/counter/note-text-optional/01.cbor`
(signer1's `note` with body `{}`): base `decode`, variant accepted; the
canonical states differ in `rejected`. No effect on enforcement. **Change:**
"`text` is required; a `note` without it is `decode`", and a vector beside
`note-empty-text`.

### L3 — A request without `ts` is refused by the ✓ column alone

§16.1's table marks `ts` required. **Proof:** `req-ts-optional`;
`work/counter/req-ts-optional/01.cbor` (a signer's `enroll` whose signed request
for `sundial` has no `ts`): base `decode`, variant enrolls the device.
`requests-bad/ts-is-text` holds the type, not the presence. **Change:** a
`requests-bad/missing-ts` vector, or name it as unvectored.

### L4 — A receipt leaf hash longer than 32 bytes is unvectored

§7 step 5: "decode to exactly 32 bytes". `receipt-bad` has a 31-byte leaf and
non-canonical spellings, none longer than 32. **Proof:** `rcpt-leaf-prefix`;
`work/counter/rcpt-leaf-prefix/receipt.note` (33-byte leaf = genesis leaf ‖ `00`,
signed by `logkey`): base `leaf-hash`, a first-32-bytes reader accepts it as the
genesis receipt. The checkpoint analogue is vectored (`checkpoints-bad/17`).
**Change:** add the 33-byte twin of `leaf-31-bytes.note`.

### L5 — §8.1's binding enumeration omits `after` and `prev`, and its `sigs` and `net` clauses are unvectored

**Where.** §8.1: "its closed set of members, each of its type: `v` 1, a text
`t`, a 16-byte `net`, a uint `ts`, a map `body`, well-formed `sigs`". The list
after the colon reads as exhaustive and does not mention `after` or `prev`.
**Proof:** `bdl-binding-ignore-after-prev`, `bdl-binding-sigs-loose`,
`bdl-binding-net-any-length`; `work/counter/bdl-*/bundle.bundle` (a two-leaf
tree of the fixture genesis and a `rotate` naming nas, with a real inclusion
proof under a `logkey`-signed head cosigned by all three witnesses): base
`binding`, variants accept. A bundle installs nothing (condition 3 replays), so
only the bundle verdict differs. **Change:** add "a uint `after` and `prev` when
present" to the list, and vectors for the three.

### L6 — Witness correspondence by short name is only half-pinned

§9.1: "The `witness` directive is matched on **its own `<name>`** … never the
note name inside the verifier key". `trust-bad/60` is also refused by the
other direction of correspondence (the policy names `pi`, which the array no
longer lists), so a reader that matches array entries to policy lines by the
verifier key's note name still refuses it. **Proof:**
`trust-witness-match-key-name`; `work/counter/trust-witness-match-key-name/trust.cbor`
(only the policy's short names `pi` and `vps` swapped between their keys):
base invalid, variant valid, with `pi`'s array URL now attached to the policy
witness named `vps`. Operator configuration only. The same matching also
masks two caught correspondence errors in composite (section 2), and this file
separates both. **Change:** this file as `trust-bad/61-witness-names-swapped`.

### L7 — Under-claims and reader models in §12

- `served-rotated-earlier/`'s `informed: accept` is right only for a reader that
  learned `logkey2` **and holds no head**. A §10 reader that verified `served/`
  stores its head (§10 "store cp"; §13.2 persists it), and answers `rollback`
  for this 20-entry log (`cmd/counter` scenario `rotated-earlier-reader-model`).
  `dropped-witness/` and `heads-run16/` likewise give readers a replayed policy
  or key without a held head. §12 should say the informed reader there holds no
  checkpoint.
- §11.1's code table lists "`split` is above `size`" as its own refusal; it is
  implied by steps 7 and 4 together (the split proof to `conflicting` cannot
  chain above `size`), so `fork/bad-split-above-size` cannot isolate it — worth
  a line in "What is not vectored", as the trust file's witness algorithm and
  name rules get in the table but not in that list.
- §3.1 item 3's R clause is implied by the cofactorless equation once A is
  admitted; it is the cofactored reading that needs it. The text says both
  equations agree "with A and R both of order exactly L" but not that, under
  the definition it chooses, the R clause is the one that can never fire.

## 4 Declared survivors — §12.1's "What is not vectored", checked

| §12.1 item | checked how | result |
|---|---|---|
| §3.1 at every admission point | variants `add-`, `logkey-`, `policy-entry-`, `rotate-`, `genesis-`, `req-`, `trust-logkey-`, `pol-`, `ev-policy-` `no-point-check` | all caught (1–7 checks each); the policy `log`-line point check is held by `log-order/15` as stated |
| source-neutral acquisition | — | not representable in static vectors; my harness has no source dimension. Agreed |
| §13 reconciliation, `proven.json`, §13.1 grant bound and overlaps | not implemented | agreed for the interface; but the grant bound and the overlap rule are pure functions of (grant, provider prefixes) and could be tabled like `grant-labels.json` — "cannot be demonstrated" over-claims |
| §16.3 key handling | not implemented | agreed |
| `none` as a group member vs undefined name | `pol-none-member-rule-absent` | survives, as declared |
| CR inside a policy verifier key | `vkey-b64-lenient` | caught only by `trust-bad/44`, as declared |
| OpenTimestamps attestations | digest recomputed from `served/checkpoint`; digest bytes found inside each `.ots` | as declared; `anchor-signed-text` and `anchor-whole-note` caught |
| a key contributes at most once | `sigs-dup-kid-ok` | caught (`log/134`), and the counting de-duplication is unreachable, as declared |
| "must not count it even in the moment before" | `t-count-unverified` | survives, as declared |
| entry 0's step order | — | every failure is `bad-genesis`; nothing to sweep, as declared |
| §3.1's canonical clauses | `ed-noncanonical-A` + exhaustive computation over y ∈ [p, 2²⁵⁵) and negative zero | survives; claim confirmed |
| blank line inside note text | `note-last-blank-line` | caught by `checkpoints-bad/45`, as declared |
| served root never from a supplied proof | — | no artifact carries a proof; agreed |
| §16.1 32-byte `device_pk` | `req-pk-any-length` | survives, as declared |
| `state.net` from the anchor | `state-net-from-genesis` | survives, as declared |
| `entry_hash` over received bytes | `dd-reencoded-bytes` | survives; the lenient reading is caught as declared (`dd-*` variants 3–13 checks) |
| `MAX_ENTRY_BYTES` on the embedded request | `req-no-size-cap` | survives, as declared |
| witness key must be a cosignature key at verification | `cp-witness-alg-unchecked-verify` | survives, as declared |
| `dup-wg` for `enroll`: any vs another | `enroll-dupwg-other` | survives, as declared |
| entry 0's byte key | `dd-genesis-no-bytes` | survives; `dd-genesis-no-content` is caught (`log-republish/15`), as declared |
| two keys with one `kid` | `dupkey-by-bytes`, `genesis-no-kid-check` | survive, as declared |
| run 16 L8 / run 17 D11 lists "now vectored" | the corresponding variants (`sig-revoke-any-device`, `prev-gov-absent-at-zero`, `env-ts-optional`, `ord-remove-unknown-before-prev`/`ord-rootrm-invariant-before-unknown`, `sigs-kid-uppercase-ok`, `sig-enroll-roots-count`, `req-expires-zero-means-none`, `rot-policy-log-lines-trusted`, `loop-genesis-leaf-only`, `ev-use-carried-policy`, …) | all caught |

Not in the list but surviving: L1–L6's members, and the equivalences in L7.

## 5 Decisions the vectors pinned, and decisions they did not

Pinned (the opposite reading is a caught variant): C01–C02 (every
`ed-*` variant but the two equivalences in section 2), C03, C04–C07 (27/27
`cbor-*` caught, both sides of the depth, key, integer and size caps), C08 for
`after`, `thr`, `overlap`, params, `expires` and evidence `size` only, C09–C10
(19/19 envelope variants caught), C11–C13
(7/9 key variants caught; the two survivors are declared), C14–C30 (all 35
order variants and 86/90 replay-rule variants caught; the survivors are three
declared and L2), C31–C32 (14/15, the survivor declared), C33 (20/20 grant
variants), C34–C39 (25/26, the survivor equivalent), C40–C44 (24/25 checkpoint
steps, survivor declared), C45 except M1's policy question (`held-requorum`,
`held-skip-lines`, `held-new-T` caught), C46–C52 (33/33 loop, tile, path and
Merkle variants and 6/6 rotation variants caught), C53 except L4 (14/15), C54–C56
except L5 (21/24), C57 except M2 (23/26, the third survivor equivalent),
C59–C60 except L6 (40/44, the rest equivalent), C61–C67 (34/35, survivor
declared), C68–C69 except L3 (27/32, the rest equivalent or declared), C70–C73
(11/11 freshness, expiry and digest variants).

Not pinned: C45's choice of policy for a held head's lines (M1); C58's
root comparison at a head's own size (M2); C08's boolean ban on the eleven
members of L1; the requiredness of `note`'s `text` (L2), which my log did not
record as a decision because the §4.3 table read as settling it; C68's request
`ts` presence (L3); C53's upper leaf length (L4);
C56's `after`/`prev`, `sigs` and `net` in binding (L5); C59's short-name
matching (L6). Harness readings the manifests leave implicit are listed at the
end of section 1.

## 6 Verdict

Every vector passes, and 482 of 523 single-decision variants are caught. Of
the 41 survivors, 20 are equivalent or declared; 21 are real and come with
inputs. Two of them are readings the text supports on its own: which policy
checks a held head's re-read lines (M1), and whether an empty split proof at a
head's own size still binds `split_root` (M2), the second able to keep a
fork's rogue devices in a frozen set. The rest are stated rules the suite does
not hold (L1–L6) and suite wording (L7).

SPEC INSUFFICIENT
