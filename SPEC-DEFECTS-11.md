# Norn `SPEC.md` — adversarial specification review (gate 11)

## Verdict

**SPEC SUFFICIENT WITH GAPS.**

I built a complete second implementation in Go (standard library only) from
`SPEC.md` alone, without reading any other copy of the project, and it
reproduced every shipped artifact: 622/622 named checks, `SHA256SUMS` clean,
every negative refused for the reason its `cases.json` names. That happened on
essentially the first serious run — 588/589 checks on the first execution, and
the single failure was a check I had not written, not a rule I had misread.
That is a very unusual result and it is the main finding: the document is
good enough that an independent reader lands on the intended bytes.

It is not *sufficient* without qualification, because a 148-variant sweep found
**23 readings that the document permits, the suite cannot separate, and that
disagree with each other**. Eighteen of those are either declared in §12.1's
"What is not vectored" list, or are coverage gaps behind unambiguous prose.
Five are places where the prose itself does not decide, and two of those change
what a conforming node *does*:

* §8.1's freshness ladder is a table, not an ordered list, and `fresh` and
  `hard_stale` can both be true at once (defect 1);
* §9.1's restatement of `tlog-policy` — which announces itself as complete —
  omits a rule the same section leans on (defect 2).

Neither is fatal; both are a sentence each to fix. Hence "with gaps" rather
than "insufficient".

---

## 1. Method

* Implementation: `work/norn/`, ~5,400 lines of Go, no third-party imports.
  Own CBOR codec (encoder + deterministic-profile decoder), canonical JSON,
  RFC 6962 inclusion and consistency proofs, `tlog-tiles` reader, signed-note
  and `tlog-cosignature` parser, `tlog-policy` parser *and evaluator*,
  RFC 4648 base32, Crockford base32, bech32m, an OpenTimestamps header reader,
  a purpose-built TOML reader for §9.2, the §5 replay machine, the §9 trust
  loader, the §8.1 bundle checker, the §11.1 evidence checker and the §10
  verifier loop including the stored-checkpoint/fork block.
* Every rule that could be read two ways was wired to a boolean in
  `work/norn/variants.go`. Default = my best-faith reading of the prose.
* Harness: `./harness -vectors <dir> [-variant A,B] [-skip-sums]`. Sweep
  artefacts in `work/sweep/`: `singles2.txt` (every single variant),
  `pairresults*.txt` (composites), `varnames.txt`, `narrow2.txt`, `pairlist*.txt`.
* I recorded each guess *before* looking at the vector that would settle it;
  the running log is `work/DECISIONS-I-HAD-TO-MAKE.md` and §4 below is its
  finished form.

## 2. Check tally

| | |
|---|---|
| Named checks | **622** |
| Passed | **622** |
| Failed | **0** |
| `SHA256SUMS` | **clean** — all 526 listed files present, 0 mismatches |

Breakdown of what those 622 cover:

| area | checks |
|---|---|
| `SHA256SUMS` | 1 |
| trust anchor: load, fingerprint, TOML→CBOR **byte-for-byte** rebuild, 3 `trust-good`, 38 `trust-bad` | 45 |
| `policies/`: 23 files + 10 `evaluate` rows | 33 |
| `entries/`: 16 entries × (decode, entry_hash, leaf_hash, preimage, size, **full JSON mirror rebuilt and compared byte for byte**) | 96 |
| `log/`: 126 per-entry outcomes + 84 `.reason` cross-checks + `state.json` + anchor agreement | 212 |
| `genesis/`: 19 cases × (state.json, single `bad-genesis` abort) | 38 |
| `log-empty/` | 1 |
| `entries-hostile/`: 16, each refused **for its own `says`** or accepted at the limit | 16 |
| `requests/` 5 × 7 (decode, sig, preimage, size, encode, text-decode, hrp, roundtrip, mirror) + `requests-bad/` 25 | 68 |
| `receipt.note` / `receipt.json` | 9 |
| `served/` end to end (verify, size, quorum time, replay→`state.json`) | 4 |
| `checkpoints-bad/` 20 + the computed `signature_blind_accepts` set | 21 |
| `served-bad/` 4, `served-extra-witness`, `served-name-collision`, `served-twice-cosigned` (+T), `served-rotated` (3 answers), `served-superseded` (3) | 15 |
| `proofs/` 6 × 2 + `proofs-bad/` 9 (each matched against its `says`) | 21 |
| `fork/`: 2 positives + 12 negatives matched against `says` + `conflicting.checkpoint` | 15 |
| `detect/` 5 pairs | 6 |
| `proven/` 4 + `detect/staleness.json` 7 | 11 |
| `anchors/` (OTS digest of the checkpoint, sample parse) | 4 |
| §5.3's `active_wg` derivation identity | 1 |
| §8.1 condition 3's `active` half, per bundle | 6 |

Four groups in that list are mine rather than the suite's, because no
`cases.json` asks for them: the §9.2 TOML→CBOR rebuild, the `anchors/` digest,
§5.3's `active_wg` derivation identity and §8.1 condition 3's `active` half.
All passed; the first two and the last are discussed below.

## 3. Variant sweep

| | count |
|---|---|
| Single variants built | **148** |
| Single variants the suite **catches** | **125** |
| Single variants that **still pass all 622 checks** | **23** |
| Composite (pair) variants enumerated | **5,151** |
| Composite variants executed | **5,151** (all of them) |
| Composites that still pass | **253**, and every one is a pair of variants that already passed alone |

### 3.1 The 23 single variants that survive

Grouped by what they mean.

**(a) Declared unvectored by §12.1 — the document is right about itself (6)**

| variant | the reading it takes |
|---|---|
| `EnrollDupWgOther` | `enroll`'s `dup-wg` means "active for **another** device" |
| `NoteLastBlankLine` | a note's text ends at the **last** blank line |
| `TUnboundedNone` | `quorum none` yields an unbounded `T` (drops every `expires`) |
| `TrustStrikeOffNames` | the witness/policy correspondence strikes each name off as it matches |
| `TrustNoNameUnique` | no witness-name uniqueness rule at all |
| `BundleNoSizeCap` | no `MAX_BUNDLE_BYTES` |

`TrustStrikeOffNames` + `TrustNoNameUnique` together also pass — which is
exactly the composite §12.1 predicts ("Such a reader … passes the whole suite
with no uniqueness rule at all"). Confirmed.

**(b) Genuine prose gaps — the document does not decide (5)**

| variant | defect |
|---|---|
| `HardBeforeFresh` | 1 — §8.1's table is not stated to be ordered |
| `PolDupKeyCheck` | 2 — the key-uniqueness rule is missing from the restatement |
| `PolAtMostOneLog` | 2 — so is "at most one `log` line" |
| `ReceiptDeadlineLax` | 4 — §7 gives the deadline line no canonical-decimal rule |
| `PolEmptyGroupOK` | 5 — "at least one member" is subsumed by the field-count rule |

**(c) Coverage gaps — the prose is unambiguous, no shipped file separates the readings (7)**

| variant | defect |
|---|---|
| `TrustNoKeyIDCheck` | 3 — `trust-bad/37` is refused by a different rule |
| `TextCapChars` | 6 — byte caps vs character caps |
| `LabelValueChars` | 6 |
| `OriginPrefixMatch` | 7 — `==` vs prefix |
| `OriginCaseFold` | 7 |
| `LogKeyNamePrefix` | 7 |
| `ResolveKeysAfterEntry` | 8 — §4.2's "the state *before* this entry" |

**(d) Harmless — the two readings cannot disagree on any legal input (5)**

| variant | why it cannot bite |
|---|---|
| `DeviceIDChars` | §2's charset is ASCII-only, so bytes and characters always agree |
| `LogSigIDOnlyMatch` | §7 makes the key id bind the name, so an id match implies a name match |
| `CosigIDOnlyMatch` | same |
| `EntryTNonStringUnknown` | no artifact carries a non-text `t` and both readings refuse |
| `TileCheckLevel0Only` | `served/` ships only level 0, so there is nothing above to check |

`LogSigIDOnlyMatch` and `CosigIDOnlyMatch` stop being harmless the moment
`TrustNoKeyIDCheck` is also taken — see defect 9.

### 3.2 What the suite caught, and how narrowly

125 of 148 were caught. The distribution is informative: **52 were caught by
exactly one check**. That is the suite working as designed — §12.1's whole
argument is that each negative should isolate one rule — but it also means the
margin is one file wide in 52 places. Notable single-file catches:

| the only check that caught it | variant |
|---|---|
| `served-name-collision` | `CosigNameOnlyMatch` |
| `served-rotated/anchor-key-kept-alongside` | `LogKeysReplace` |
| `served-twice-cosigned/T` | `TOldestLine` |
| `detect/fork-on-a-shorter-branch` | `SizeRuleBeforeFork` |
| `served-bad/consistent-tampered-log` | `NoRebuildCompare` |
| `served-bad/tampered-hash-tile` | `NoTileCheck` |
| `proofs-bad/foreign-checkpoint` (its `says`, not its refusal) | `OriginBeforeSignature` |
| `fork/bad-size-above-held` (its `says`) | `EvidenceSizeEqFirst` |
| `proven/at-the-deadline` | `ExpiresStrict` |
| `staleness/at-the-staleness-boundary` | `StaleGE` |
| `entries-hostile/past-the-key-limit` | `KeyCapChars`, `KeyCapNone` |
| `checkpoints-bad/16-two-log-signatures` | `LogSigAnyValid` |

Every one of those files is named in §12.1 as the case that exists to pin that
reading. The coverage table is, on this evidence, unusually honest.

Three catches are worth calling out as *only* visible through a `says` string
rather than through accept/refuse: `OriginBeforeSignature`,
`EvidenceSizeEqFirst` and `EvidenceConflictingFirst`. See defect 10.

### 3.3 Composites

A single variant measures one rule. A **pair** measures whether one rule's only
guard is a *different* rule — the case where each half is caught alone and the
two together are not. That is the composite this phase exists to find.

I enumerated and ran **all 5,151** pairs among the 102 variants that either
survived or were caught by at most two checks. (Runs were ordered by how likely
a pair was to interact — every same-subsystem pair first, then every pair of
individually-surviving variants, then the rest — because the machine sat at
load 50+ from unrelated processes throughout; the ordering affected only the
wall clock, and the sweep finished.)

| | |
|---|---|
| pairs enumerated | 5,151 |
| pairs executed | **5,151** |
| within one subsystem (trust×trust, policy×policy, evidence×evidence, bundle×bundle, note/checkpoint×same, verifier×same, freshness×same, profile×same, JSON×same, bech32×same) | 647 |
| pairs of individually-surviving variants | 253 |
| **pairs that still pass all 622 checks** | **253** |
| pairs that pass where **either half was caught alone** | **0** |

**Result: the 253 surviving composites are exactly the 253 pairs of
individually-surviving variants. Not one composite rescued a half the suite
caught alone.** The composite sweep therefore adds nothing beyond the 23 single
survivors — which is itself the finding: the suite's catches are independent,
and no rule in this document is load-bearing only because a second rule happens
to fire first.

Five composites worth naming, each run directly:

| composite | outcome |
|---|---|
| `TrustStrikeOffNames` + `TrustNoNameUnique` | **passes** — precisely the reader §12.1 predicts ("passes the whole suite with no uniqueness rule at all"). Confirmed. |
| `TrustNoKeyIDCheck` + `CosigIDOnlyMatch` | **passes** — a verifier that never recomputes a key id and then matches lines on the declared id alone. Defect 9. |
| `TrustNoKeyIDCheck` + `TrustNoPolicyLogLine` | **caught**, 2 failures (`trust-bad/36` and `37`) — this is how defect 3 was isolated |
| `NoTileCheck` + `NoRebuildCompare` | **caught**, 3 failures — §6's two independent bindings do not cover for each other |
| `CosigPerWitness` + `CosigIgnoreBad` | **caught**, 2 failures (`checkpoints-bad/11`, `12`) — §10's per-line rule is pinned twice over |

---

## 4. Defects

### Defect 1 — §8.1's four freshness states are a table, not a ladder, and two rows can be true at once *(severity: high)*

**Prose as written.** §8.1:

> | state | when |
> |---|---|
> | `unknown` | no witness has vouched for any instant … |
> | `fresh` | `elapsed ≤ S` — the boundary is fresh … |
> | `hard_stale` | `S_hard` is configured **and** `elapsed > S_hard` |
> | `degraded` | otherwise |

Nothing says the rows are evaluated in order. `degraded`'s "otherwise" implies
*some* ordering exists, but `fresh` and `hard_stale` are independent
predicates and both hold whenever `S_hard < elapsed ≤ S`.

**Evidence.** Variant `HardBeforeFresh` — identical except that `hard_stale` is
tested before `fresh` — passes all 622 checks. It survives because every case
in `detect/staleness.json` uses `staleness: 900` with `hard: 3600` or `hard: 0`,
so `S_hard > S` throughout and the overlap region is empty. No shipped file has
`S_hard < S`.

**Why it matters in practice.** `S` is the network's (`params.staleness`) and
`S_hard` is the node's own local opt-in — §8.1 makes that asymmetry deliberate
("It is a local decision for the same reason the witness policy is not a
`params` key"). `params` is mutable by root quorum, so `S` moves and `S_hard`
does not. **The shipped fixture does exactly this**: genesis sets
`staleness: 600` (`entries/00-genesis.json`) and a later `params` entry raises
it to `900` (`state.json`). Any node that had chosen `S_hard = 700` before that
entry — a perfectly sensible choice when `S` was 600 — now lives permanently in
the overlap region, and reports `fresh` under one reading of §8.1's table and
`hard_stale` under the other. §8.1 says crossing `S_hard` "drops every peer".
Two conforming nodes, opposite enforcement, from the same inputs.

**Suggested fix.** One clause: "The states are tested in the order given; the
first whose condition holds is the answer." (Or the other order, if
`hard_stale` is meant to win — but say which.) Add one case to
`detect/staleness.json` with `hard` below `staleness`, e.g.
`{"name":"hard-below-staleness","elapsed":500,"hard":300,"expect":"..."}`.

---

### Defect 2 — §9.1's restated policy grammar omits the key-uniqueness rule the same section relies on *(severity: medium-high)*

**Prose as written.** In the `log lines` row of the grammar table:

> `log` lines | **not required**. A Norn trust file's policy carries **at most
> one**: the grammar permits more, and since a `log` line that is present must
> name `norn.trust.log_key` (§9.1's `policy` row) and **no key may appear twice
> in one policy**, a second one cannot be written.

That argument uses two rules that appear nowhere else in the document: "no key
may appear twice in one policy", and "a Norn policy carries at most one `log`
line". The table they appear in is introduced as:

> **The rest of the grammar, stated because a restatement that leaves it out is
> not enough to write an agreeing verifier.**

The table has rows for blank lines, comments, final newline, separators, field
count, leading whitespace, **names**, group members, group thresholds,
keywords, nested groups, log lines and quorum. The `names` row says "each
`witness` and `group` **name** is defined once" — about names, not keys.

**Evidence.** Variants `PolDupKeyCheck` (enforce key uniqueness) and
`PolAtMostOneLog` (enforce at-most-one-`log`) each pass all 622 checks, as does
the default that enforces neither. No file in `policies/` carries a repeated
key or a second `log` line, and `policies/cases.json` has no case for either.
So the suite permits both parsers.

**Why it matters in practice.** This is not cosmetic, because a `policy` **log
entry** (§4.3, §5.1) must "parse as `c2sp.org/tlog-policy`" or the entry is
`decode`. A policy that lists one witness key under two names —
`witness a K` / `witness b K` — parses for one implementation and is `decode`
for the other. The two then disagree about `state.policy`, hence about
`state.json` (which §5.3 makes a byte-identical MUST), hence about `rejected`,
hence about every subsequent checkpoint's quorum. One node's `group home 2 a b`
is met by a single witness answering once; the other node never got the policy
at all. That is the exact failure mode §9.1's `group` members row exists to
prevent ("`group home 2 pi pi` would otherwise be met by one witness") — the
rule is there for members and missing for keys.

**Suggested fix.** Add two rows to the table:

> | keys | a `vkey` is used **once** in a policy; the same key under two names, or on both a `log` and a `witness` line, is an error |
> | `log` count | at most one |

and ship `policies/bad-duplicate-key.txt` and `policies/bad-two-log-lines.txt`.

---

### Defect 3 — `trust-bad/37-log-key-id-mismatch` does not isolate the rule §12.1 says it covers *(severity: medium)*

**Prose as written.** §12.1:

> | §9.1 a verifier key's id binds its name, key and algorithm | `trust.cbor` |
> `37-log-key-id-mismatch`: the right name, the right key, the right algorithm
> and one hex digit of the id changed |

and, two rows earlier, about the other three log-key MUSTs:

> Each carries its damaged key in its **policy** as well, so the `log`-line
> correspondence rule agrees and only the rule the case is named after can
> refuse it. Without that, all three rules were deletable one at a time with
> the whole suite still green …

**Evidence.** Variant `TrustNoKeyIDCheck` — parse a verifier key string without
recomputing `SHA-256(name ‖ 0x0A ‖ alg ‖ pk)[0:4]` and comparing — passes all
622 checks. The reason is visible in the file:

```
trust-bad/37-log-key-id-mismatch
  log_key            = norn/nzxxe3rnorsxg5domv2c2mbqge+1ea4a666+AV6v97lm…
  policy `log` line  = norn/nzxxe3rnorsxg5domv2c2mbqge+bea4a666+AV6v97lm…
                                                       ^ still the honest id
```

The damaged id was **not** propagated into the policy, so §9.1's "a `log` line …
MUST be `norn.trust.log_key`" refuses the file first. With
`-variant TrustNoKeyIDCheck,TrustNoPolicyLogLine` both `36-policy-log-key-mismatch`
and `37-log-key-id-mismatch` are accepted. By contrast I verified that `11` and
`13` *do* carry their damaged key in the policy, exactly as §12.1 claims — `37`
is the one that was given a different treatment while the table claims the
same.

**Why it matters in practice.** §12.1 opens by saying an inaccurate coverage
claim "is the same failure wearing a different hat". This is one. Concretely, a
second implementer who treats the key id as an opaque label — which is the
natural thing to do, since the id is also the thing you *match* on — ships a
trust loader that accepts anchors this document says MUST be refused, and
passes the suite while doing it.

**Suggested fix.** Regenerate `37` with the damaged id in the policy's `log`
line too, as `11`, `13` and `16` already do. A witness-key variant
(`39-witness-key-id-mismatch`, damaged in both `witnesses` and the policy's
`witness` line) would cover the other half.

---

### Defect 4 — the receipt's `deadline` line is not required to be canonical decimal, while §6's size line is *(severity: low)*

**Prose as written.** §6, about the checkpoint: "the tree size in decimal with
**no leading zeroes** … `0124` and `124` are the same number and two spellings
of one head." §7, about the receipt, shows only:

```
<uint deadline unix seconds>       # = now + params.mmd
```

with no canonicality rule and no vector (`checkpoints-bad/15-size-leading-zero`
covers the checkpoint line only).

**Evidence.** Variant `ReceiptDeadlineLax` (accept `00123`) passes all 622.

**Why it matters.** Less than for a checkpoint — a receipt is not gossiped and
nothing is keyed on its bytes — but §7 sells the receipt as "non-repudiable
proof of log misbehaviour", which means somebody will compare two copies of
one. The asymmetry is unexplained: the document is emphatic about canonical
decimal three sections earlier.

**Suggested fix.** One clause in §7's list: "the deadline line is canonical
decimal, as §6's size line is"; and a `receipt-bad/leading-zero.note`.

---

### Defect 5 — §9.1's "a `group` has at least one member" is unreachable behind the field-count rule *(severity: low, no interop risk)*

**Prose as written.** Two rows of the same table:

> | field count | … `group` a name, a threshold and one or more members — and a line with more is an **error** |
> | `group` members | at least one, each **previously defined**, and **no member twice** |

**Evidence.** Variant `PolEmptyGroupOK` (drop the "at least one member" rule,
keep the field-count rule) passes all 622. `policies/bad-empty-group.txt` is
`group g all` — three fields — so the field-count rule refuses it first.

**Why it matters.** Both readings refuse, so there is no disagreement; this is
a note, not a hazard. It is worth recording only because §12.1 lists
`bad-empty-group` under "the restated `tlog-policy` grammar" as if it exercised
the members rule, and it does not — the same shape of claim as defect 3, one
size smaller.

**Suggested fix.** Either delete the redundant half of the members row, or make
`bad-empty-group.txt` a four-field line whose fourth field is empty-ish in a
way only the members rule can catch (there is no such line, which is the point:
the rule is genuinely subsumed). Simplest: say so in §12.1.

---

### Defect 6 — the byte-counted caps on `name`, `reason`, `text` and label values are not separated from character counting *(severity: medium)*

**Prose as written.** §4.0's field table:

> | `name`, `reason` | UTF-8, 1–64 / 0–256 **bytes** |
> | `text` (`note`, `policy`) | UTF-8, ≤ 4096 **bytes** |
> | `labels` | … values ≤ 256 **bytes** |

The prose is unambiguous. The vectors are not.

**Evidence.** Variants `TextCapChars` (count `name`/`reason`/`text` in runes)
and `LabelValueChars` (count label values in runes) each pass all 622 checks.
The over-long negatives — `genesis/14-name-too-long`,
`log/116-bad-revoke-reason-too-long` (257 bytes),
`log/83-bad-text-too-long`, `requests-bad/oversize-label` — are ASCII, so bytes
and characters give the same answer.

§12.1 records having found and fixed precisely this for the map-key cap:

> | §4.0's map-key cap in **bytes** | `entries-hostile/at-the-key-limit`: 23 bytes and 12 characters | `past-the-key-limit` is 24 bytes and 13 characters. **Both were ASCII until run 9**, so "23 bytes" and "23 characters" gave the same answer everywhere |

The same fix was not applied to the four field caps.

**Why it matters in practice.** `reason` is the clearest case: it is free-form
human text on a `revoke`, and 256 bytes is about 85 CJK characters or 128
Cyrillic ones. A revocation whose reason is written in any non-Latin script and
runs past 256 bytes is accepted by a character-counting reader and `decode` for
a byte-counting one — so the two disagree about `state.rejected`, about whether
the device is revoked at all, and therefore about the proven set. §5.3's "Two
implementations MUST produce byte-identical canonical JSON" is violated by two
readers who both pass the suite. `text` (a `note` or, worse, a **`policy`
entry**, which lands verbatim in `state.policy` and decides the quorum) has the
same shape at 4096, and label values at 256.

**Suggested fix.** Make one of the four multi-byte, the way run 9 did for the
map-key cap: e.g. `bad-revoke-reason-too-long` at 257 bytes / 200 characters,
plus an accepted twin at 256 bytes / 150 characters.

---

### Defect 7 — `cp.origin == norn.trust.origin` and the log key's note name are not separated from a prefix or case-folded match *(severity: low)*

**Prose as written.** §10: `require cp.origin == norn.trust.origin`.
§9.1: the log key's "note name MUST equal `origin`".

**Evidence.** Three variants pass all 622: `OriginPrefixMatch`
(`strings.HasPrefix`), `OriginCaseFold` (case-insensitive), `LogKeyNamePrefix`
(prefix match on the log key's name). `checkpoints-bad/03-wrong-origin` and
`10-wrong-body-origin` use unrelated origins; `trust-bad/11-log-key-name-mismatch`
uses `someone/else`; `13-origin-only` uses `norn/aaaa…`. None is a prefix or a
case variant of `norn/nzxxe3rnorsxg5domv2c2mbqge`.

**Why it matters.** Low, because §2's origin is a fixed-width base32 of a
16-byte `net_id` with padding stripped, so for well-formed origins no one is a
proper prefix of another. But §10 spends a paragraph arguing that the
*cosignature* match must be on name **and** id, because a name-only match hands
anyone a veto — and ships `served-name-collision/` to pin it. The same argument
applies to the origin comparison from the other direction (a prefix match hands
an attacker an *acceptance*), and it is not pinned.

**Suggested fix.** `checkpoints-bad/21-origin-with-a-suffix.checkpoint`, whose
origin line is this network's origin plus one base32 character, signed by this
network's key under this network's name. One file, and the rule stops being
deletable.

---

### Defect 8 — §4.2's "the state *before* this entry" is unvectored for the one entry type where it can matter *(severity: low)*

**Prose as written.** §4.2: "Signatures MUST be verified against the key the
`kid` resolves to in the state *before* this entry."

**Evidence.** Variant `ResolveKeysAfterEntry` — for `root_add`, resolve the root
quorum against the roots *including* the key being added — passes all 622. No
entry in `log/` is signed by a key it is itself adding.

**Why it matters.** A `root_add` signed by `root_thr − 1` existing roots plus
the incoming key is a root quorum that bootstraps itself. §9.4's whole security
argument for `log_key` rotation is an ordering argument of the same shape ("a
stolen log key therefore cannot name its own successor"); the root-key version
of it is stated once in §4.2 and never exercised.

**Suggested fix.** A `log/` negative: a `root_add` carrying `root_thr − 1` valid
root signatures and one by the key in the body, expected `threshold`.

---

### Defect 9 — the key-id rule and the name half of the `(name, key id)` match are individually deletable, and together they open a real hole *(severity: medium, composite)*

**Evidence.** Three variants pass individually: `TrustNoKeyIDCheck` (defect 3),
`LogSigIDOnlyMatch` and `CosigIDOnlyMatch` (match a signature line on key id
alone). Individually all three are safe — §7's id binds the name, so either
half of the test implies the other *provided the id is recomputed*. Take
`TrustNoKeyIDCheck` away and that implication is gone: a verifier that trusts a
declared id and then matches lines on the id alone has verified nothing about
the name at all.

The composite `TrustNoKeyIDCheck,CosigIDOnlyMatch` still passes all 622 checks.
No shipped artifact contains a trust file with a mis-declared witness key id, so
nothing exercises the pair.

**Why it matters in practice.** This is the attack §10 describes in reverse.
§10 refuses the name-only match because "cosign a head under a name you do not
hold and every node that matches on the name alone refuses it". The id-only
match with an unchecked id has the dual property: an operator who is handed a
trust file with a witness entry whose *declared* id matches some other party's
key accepts that party's cosignatures as the named witness's. §9.1 already
says the file must be compared out of band by fingerprint (§9.3), which is the
real defence — but "the id binds the name" is stated as a property, and it is
only a property if somebody recomputes it.

**Suggested fix.** Fixing defect 3 fixes this: once `37` isolates the key-id
rule, `TrustNoKeyIDCheck` is caught and the composite cannot be reached.

---

### Defect 10 — the vectors score refusals against error phrases the specification never defines *(severity: medium, contract-level)*

**Prose as written.** §5.2 is a closed, normative list of 16 reason codes — but
only for replay. Every other refusing layer has none: the trust file, the
policy parser, the note/checkpoint parser, the bundle checker, the evidence
checker, the request decoder and the CBOR profile itself.

The vectors nevertheless score against strings:

| file | field | examples |
|---|---|---|
| `entries-hostile/cases.json` | `says` | `simple value`, `deeper than`, `map key must be 1-23 bytes`, `major type`, `exceeds` |
| `proofs-bad/cases.json` | `says` | `carries an entry about`, `no valid signature from a trusted key`, `is for origin`, `no quorum cosigned` |
| `fork/cases.json` | `says` | `can only speak for what it holds`, `claims a disagreement`, `does not chain`, `nothing here is a fork`, `requires none` |
| `served-bad/cases.json` | `says` | prose sentences |

**Evidence.** These strings appear nowhere in `SPEC.md`. I reverse-engineered my
error vocabulary from `cases.json` to make the suite pass — which means the
suite tested my ability to read `cases.json`, not my ability to read the
specification. Three of my 125 catches depend *only* on a `says` match rather
than on accept/refuse: `OriginBeforeSignature` (§10's signature-before-origin
ordering, caught only because `proofs-bad/foreign-checkpoint` says
`no valid signature from a trusted key`), `EvidenceSizeEqFirst` and
`EvidenceConflictingFirst` (§11.1's step ordering, caught only by `says`). Those
three orderings are therefore *normatively pinned by a JSON file and not by the
document*.

**Why it matters in practice.** §11 rule 4 makes one class of refusal permanent
until a human installs a new trust file. Two implementations that cannot agree
on *why* they refused cannot triage that together, and an operator reading one
node's alarm cannot match it against another's. The document already
demonstrates the fix at replay level: §5.2 is exactly the right artefact.

**Suggested fix.** Either (a) give §7/§9.1/§8.1/§11.1/§16 closed reason-code
lists in §5.2's style and have `cases.json` name codes rather than substrings,
or (b) at minimum, state in §12 that `says` is a semantic hint and that a
second implementation is expected to map it by hand — so a reader knows the
suite is not asking for those exact bytes.

---

### Defect 11 — §6 uses "the checkpoint body" for two different byte ranges one bullet apart, and the file that separates them ships with no instructions *(severity: medium)*

**Prose as written.** §6, bullet 2:

> A checkpoint body is **exactly three lines** (`c2sp.org/tlog-checkpoint`): the
> origin, the tree size …, and the root …

§6, last bullet:

> `<prefix>/anchors/<size>.ots` — … The stamped value is `SHA-256` of the
> checkpoint **body** — the note text up to and including the blank line,
> without any signature lines.

The two are one byte apart. Using the shipped `served/checkpoint`:

```
SHA-256(three body lines)              = 7318fbb7d8c017c4469f36eb92e4fcc913a451b7fec9e0a89075289ed97184ee
SHA-256(three body lines + blank line) = 4e2492c7c08d8e84f6dc5785e248e836abe015f5e20c6ea54fcc1342ee5e096b
```

`anchors/checkpoint-126.ots` stamps the **second**. The qualifier after the em
dash settles it — but only for a reader who notices that `body` has just been
redefined against the definition three bullets above, and against §7, where the
*signed* text explicitly "does **not** include the blank separator line". The
document makes that distinction deliberately (it is why a receipt's
`text_sha256` and an anchor's digest differ), and then reuses one word for
both.

**Evidence.** Variant `OTSDigestSignedText` fails exactly one check — and that
check is one I wrote, not one the suite asks for. `anchors/` has **no
`cases.json`**; §12's table describes the directory in one line —
"`checkpoint-<size>.ots` over the fixture's **checkpoint body**", which repeats
the ambiguous word *without* §6's disambiguating clause, so the §12 table read
on its own gives the wrong (three-line) answer — and §12.1 does not mention
anchors at all, in either the vectored or the not-vectored list (`grep -i
'anchors\|ots' SPEC.md` returns six hits, none of them in §12.1).
Neither does `vectors/README.md` beyond "Norn reads `.ots` files and never
writes them". On top of that, the `.ots` container format is described nowhere
in `SPEC.md` — I had to recognise the `\x00OpenTimestamps\x00\x00Proof\x00`
magic, the version varint and the `0x08` SHA-256 op from outside knowledge to
extract the digest at all.

**Why it matters in practice.** Anchoring is advisory (D-009), so a reader who
computes the other digest simply never matches any stamp and never says so.
That is the worst kind of divergence: silent, and in the one mechanism whose
job is to constrain the log operator about *time*.

**Suggested fix.** (a) In §6, do not call it "the body": say "`SHA-256` of the
note's leading bytes through the newline that terminates the blank separator
line — the three body lines plus the blank line, four `0x0A` in all". (b) Ship
`anchors/cases.json` giving, for each `.ots`, the hex digest it must be checked
against and which bytes of which file produce it — so the rule is vectored
without the reader having to parse OpenTimestamps.

---

### Defect 12 — §9.1's "any other whitespace character" is not an enumerated set *(severity: low)*

**Prose as written.**

> | field separators | ASCII space and tab **only**, in runs. Any other
> whitespace character anywhere in a line — `\r`, `\v`, `\f` — is an **error**,
> not a separator and not content |

The three named characters are introduced with an em-dash gloss, which reads as
examples rather than as the definition. A reader must decide whether U+000B,
U+000C, U+000D is the whole list, or whether NUL, U+001C–U+001F, U+0085 or
U+00A0 are also "whitespace characters".

**Evidence.** Not separable by any shipped file — `policies/bad-vertical-tab`
and `bad-carriage-return` cover two of the three named characters and nothing
else. Both readings pass.

**Why it matters.** Policy text is carried verbatim in a `policy` log entry, so
a byte one reader calls an error and the other calls part of a witness name
splits `state.json` and the quorum, exactly as in defect 2. The risk is small
because such a policy is unlikely to be written by accident — but a hostile
`policy` entry is not an accident.

**Suggested fix.** Close the set: "the bytes `0x0B`, `0x0C` and `0x0D`; every
other byte other than `0x20` and `0x09` is content". Add
`policies/bad-form-feed.txt` for the third named character.

---

### Defect 13 — §4.0's opening enumeration omits two of the artifacts it governs *(severity: editorial)*

§4.0 opens: "All Norn **CBOR** structures — entries, enrollment requests and
trust files — use RFC 8949 §4.2.1 …". Proof bundles (§8.1) and fork evidence
(§11.1) are also §4.0 CBOR — each says so at its own site — but a reader
building a decoder from §4.0 alone will scope it to three artifacts and then
have to come back. The same paragraph later says `MAX_ENTRY_BYTES` "does not
bound the other CBOR artifacts that cite this section: a proof bundle (§8.1), a
trust file (§9.1) and fork evidence (§11.1)" — so the full list exists two
paragraphs down. Fix: put it in the first sentence.

---

### Defect 14 — §8.1 condition 3's "with that `wg_pk`" has no antecedent, and the fixture distinguishes the two readings *(severity: medium)*

**Prose as written.** §8.1:

> A node MUST treat a peer as proven only if:
> 1. the bundle's checkpoint verifies under the node's trust policy (§9), and
> 2. the bundle's checkpoint is consistent with the node's stored checkpoint, and
> 3. **replay of the log up to that checkpoint yields the device as `active`
>    with that `wg_pk`**, and
> 4. the checkpoint is not stale …

"That `wg_pk`" is not defined in condition 3's own sentence. The nearest
candidate is the bundle's — the whole list is about a bundle — but there is a
second reading in which the node simply installs whatever `wg_pk` replay gives
it and condition 3 only asserts `active`.

**Evidence.** The two readings disagree on the shipped fixture. `proofs/` is
"one §8.1 proof bundle per active device, each proving **the entry that made
that device active**" (§12), i.e. the `enroll`. For `nas` that is index 1:

```
proofs/nas.bundle      index 1, t=enroll, device "nas",  request.wg_pk = 116f00fa…
state.json devices.nas  status active, since_index 1,            wg_pk = 2a955fd2…   (log/35-rotate-nas)
```

The other five bundles agree with the state because those devices were never
rotated. So:

* under "that `wg_pk`" = the replayed one, `nas` is proven — which is what
  `proven/cases.json` requires (it lists `nas` in all four cases);
* under "that `wg_pk`" = the bundle's, `nas` fails condition 3 and is dropped.

**Nothing in the suite catches the second reading**, because no vector joins a
bundle to a proven set. `proofs/cases.json` exercises only §8.1's "Checking a
bundle" procedure (checkpoint, inclusion proof, device-to-entry binding), which
does not include conditions 1–4; `proven/cases.json` is computed from
`state.json` alone. A node that reads condition 3 the strict way silently drops
every rotated peer and passes every check in the suite.

**Why it matters in practice.** `rotate` is a routine operation — it is how a
device changes its WireGuard key — and §5.3 deliberately leaves `since_index`
alone on a rotate so the "entry that made the device active" stays the enrol.
That design makes stale bundles the *normal* case for any device that has ever
rotated, so the strict reading is not an edge case: it drops peers in the
ordinary course of operation, and does it quietly.

**Suggested fix.** Two words: "…yields the device as `active` with **the**
`wg_pk` **the node will install**", plus a sentence saying what the bundle's own
entry proves (that the device was enrolled at that index) and what it does not
(its current key). A `proven/` case keyed off `proofs/nas.bundle` would pin it.


---

## 5. Every decision the prose did not make for me

These are guesses. Most turned out right; a guess that happened to match is
still a guess, and a second implementer will face all of them.

### 5.1 The CBOR profile

1. **Simple values other than the three named.** §4.0 bans `null` and
   `undefined` by name and allows booleans. It says nothing about CBOR simple
   values 0–19 or 24 (e.g. `0xF0`). I refuse every major-type-7 argument except
   20 and 21. Unobservable — no vector carries one.
2. **What `≤ 2⁶³−1` binds.** I applied it to every major-type-0 *value*, and
   separately refused any declared length exceeding the remaining input or the
   artifact's byte cap. §4.0 states the cap in the Integers row only; whether a
   length header above 2⁶³−1 is "an integer" is not said.
3. **The depth of a bare scalar.** §4.0 says the top-level map is depth 1 and a
   scalar adds none, so a bare scalar is depth 0. Fine, but `entries-hostile/`
   is full of bare scalars and the rule is stated only for containers.
4. **Where `MAX_ENTRY_BYTES` is enforced.** Buffer length *and* declared
   lengths during decoding. `entries-hostile/oversize-entry` is a small file
   whose header promises 65536, and §4.0's "refused on length before anything
   it declares is allocated" only works if the check is also inside the decoder.
   §4.0 does not say that in so many words.
5. **The comparison domain for the `sigs` sort.** §4.0 says "sorted by `kid`
   bytewise". `kid` is a 16-character hex *text string*; bytewise over the text
   and bytewise over the decoded 8 bytes agree, so the ambiguity is harmless —
   but the document never says which.
6. **Error strings.** See defect 10. Everything my decoder says was written to
   match `cases.json`.
7. **Scope of the depth limit.** I apply depth ≤ 8 to bundles and evidence as
   well as to entries, requests and trust files. §4.0's enumeration (defect 13)
   suggests otherwise on a first reading.

### 5.2 Entries and replay

8. **Type errors in the envelope are `decode`.** §5.1 step 3 lists "exactly the
   permitted keys, `v` = 1, `net` = `anchor.net`, well-formed `sigs`". It never
   says what a `t` that is a uint, a `ts` that is text, or a `body` that is an
   array should produce. I made every type violation `decode`, which puts it
   before step 4's `unknown-type`. Unobservable: no vector carries one.
9. **Where genesis's body schema check lives.** Step 2 or step 6. §5.1 admits
   entry 0's ordering is unvectored; I put it in step 6.
10. **Field constraints are keyed by field name.** §4.0's constraint table names
    fields (`device_id`, `name`, `reason`, `text`, `labels`, `kid`); §4.3 names
    the keys each type carries. I apply each constraint wherever the name
    appears in any body.
11. **No upper bound on `overlap`, `ts`, `after`, `expires`, `thr`** beyond
    §4.0's 2⁶³−1.
12. **`revoke`'s absent `reason`** is equivalent to `""` (stated) and is not
    recorded in the device record (not stated — §5.3 simply has no field).
13. **`enroll` over a revoked id** also clears the old `wg_pk` from `active_wg`.
    §5.3's derivation rule makes this necessary but §5.1's effect column does
    not mention it.

### 5.3 State and canonical JSON

14. **`active_wg`'s JSON keys are the lowercase hex of the 32-byte WireGuard
    key.** §5.3 says the map is `wg_pk → device_id`; §14.1 says "byte strings"
    render as lowercase hex, which naturally reads as a rule about *values*.
    §4.0's aside ("keyed by `device_id` and by 32-byte WireGuard keys") confirms
    the key is the raw key, not its hex, so the hex rendering is an inference.
    It is pinned by `state.json`, but only after you have guessed right.
15. **`roots` / `signers` values render as hex.** Same inference, same pinning.
16. **`params` keys are emitted even when never set.** §5.3 says "§4.5 defaults,
    overlaid by …", and §14.1 says absent members are always emitted; together
    that gives all four. Pinned by `state.json`.
17. **`T = 0` means "no clock".** That is `proven/cases.json`'s convention.
    §5.3 defines "no clock" as a state, not as a value of `T`; I modelled it as
    a separate boolean.

### 5.4 Notes, checkpoints and the verifier

18. **A payload that is neither 68 nor 76 bytes makes the whole note
    malformed.** §7 gives the length per algorithm, and the algorithm is a
    property of a key you have not yet matched. I decided the note is malformed
    before matching. `checkpoints-bad/20` is 69 bytes and fails either way.
19. **A stranger's line still has to be well-formed.** §10 says an unlisted
    line is "IGNORED, not refused"; §7's framing rules apply to every line. I
    parse all lines strictly and then ignore unmatched ones — which is what
    `checkpoints-bad/18-signature-name-with-space` requires, but "ignored"
    could be read as "not even parsed".
20. **Which policy verifies the head you are about to replay from.** The trust
    file's, or one from a state already accepted — never one from this
    checkpoint. §9.4's bootstrap argument implies it; `served-superseded/`
    confirms both answers are correct for different readers.
21. **A standalone bundle is checked under the trust file's policy** (§8.1 says
    "per §10", and a bundle checker has no replayed state).
22. **Fork evidence is verified under the reader's trust-file log key**, not
    under a replayed `log_keys` (§11.1 says "the network's trust file and
    nothing else").
23. **The receipt's shape.** §7 shows four lines in a code block; I treated the
    literal first line `norn/receipt/v1` and the four-line structure as
    normative. §7 never says "exactly four lines" the way §6 says "exactly three".

### 5.5 The log and the tiles

24. **`tlog-tiles` paths.** §6 defers them and does not restate them, and the
    C2SP document is not in the sealed directory. I derived
    `tile/entries/000.p/126` and `tile/0/000.p/126` from outside knowledge of
    `tile/<L>/<3-digit groups>[.p/<width>]`. **A reader with only `SPEC.md` and
    `vectors/` cannot use `served/`, `served-bad/`, `served-*/` or `detect/` at
    all.** The document is honest about this ("this one neither restates them
    nor varies them"), and §7 and §9.1 both chose the opposite policy for the
    same reason ("a verifier cannot be written without it"). This is the single
    largest obstacle to a second implementer and I would restate the two path
    forms in §6 in one line each.
25. **Which hash-tile levels must be checked.** §6 says the served `tile/<L>/…`
    hashes MUST agree; it does not say a verifier must fetch every level, or
    what an absent level means. I check every level present and skip absent
    ones. `served/` ships only level 0.
26. **Entry-bundle entry count.** I require a partial bundle to hold exactly the
    declared width. §6 defers the framing to `tlog-tiles`.

### 5.6 Trust file, policy, encodings

27. **Trust-file check ordering.** Unobservable — `trust-bad/cases.json` asks
    only for refusal.
28. **Byte caps are on the encoded file**, not on anything decoded (§9.1/§11.1
    say "refused on length").
29. **An empty witness `url`** is allowed. §9.1 constrains `log_urls` elements
    to be non-empty and says nothing about witness `url`; §12.1 treats the
    witness `url` as a member "never constrained".
30. **Duplicate `log_urls`** are allowed (unconstrained).
31. **Policy `witness`/`group` names have no length or charset bound.**
32. **The "any other whitespace" set** — see defect 12.
33. **Verifier-key id hex is parsed case-insensitively** and compared
    lowercase. §7 says "8 hex digits" without a case rule.
34. **Crockford base32 is MSB-first over exactly 80 bits**, giving 16 symbols
    with no padding (stated, but the grouping into four-by-four is given only by
    example).
35. **bech32m comes entirely from BIP-350** (§16.2 says so explicitly).
36. **§9.2's TOML→CBOR mapping**: which members are byte strings comes from
    §9.1's type column; `[[witness]]` order is the CBOR array order (stated).
    I implemented the rebuild and it reproduces `trust.cbor` byte for byte —
    but §9.2 ships no `cases.json` asking anyone to check it, so this is a
    normative MUST ("Building the CBOR from this rendering must reproduce
    `trust.cbor` byte for byte") that the suite does not test.

### 5.7 §10 and §11

37. **The node keeps its stored branch's *entries*, not just its checkpoint.**
    §10's `mine` is "the root THIS NODE's branch had at `at`", and the only way
    to have that root for `at < stored_cp.size` is to hold the entries.
    `detect/cases.json` supplies them implicitly (`stored` is a head over
    `../served`'s entries and `held: "none"` marks the case where they are
    absent). §10 never says a node persists entries; §8 says it stores proof
    bundles and §10 says "store cp".
38. **`accept` / `refuse` / `fork`** is `detect/cases.json`'s vocabulary. §10
    produces `FORK` and "refuse"; "accept" is implied by falling through.
39. **§11 rule 4's permanence** is not implemented or tested — nothing in the
    suite can observe it.

---

## 6. What I could not cover, and why

* **§9.2's TOML rendering** — I *did* implement and verify the byte-for-byte
  rebuild, but on my own initiative; the suite does not ask for it and ships no
  negative (a TOML file whose CBOR differs). So the rule is verified for one
  file and unpinned in general.
* **`anchors/`** — I verify the digest of `checkpoint-126.ots` and that
  `sample.ots` parses. I do **not** verify the OpenTimestamps attestation chain,
  the calendar reply in `anchors/calendar-response.bin`, or `anchor.max_lag`,
  because `SPEC.md` describes none of the format and anchoring is advisory
  (D-009). `calendar-response.bin` is exercised by nothing I could write.
* **`keys.json`** — never read. Nothing in `SPEC.md` requires a verifier to.
* **§8.1 conditions 1–4 as a joined-up rule.** I check condition 1 (a bundle's
  checkpoint verifies), condition 3's `active` half, and condition 4's ladder
  from `staleness.json`. Condition 2 — "the bundle's checkpoint is consistent
  with the node's stored checkpoint" — is exercised by no vector: every bundle
  in `proofs/` carries the same head as `served/checkpoint`, so consistency is
  trivial. Condition 3's `wg_pk` half is defect 14.
* **§11 rules 1–4 as behaviour** (writing `fork/<unix>.evidence`, keeping the
  stored set, raising an alarm, refusing forever). I implemented the *decision*
  (`detect/` comes out `accept`/`refuse`/`fork` correctly) and the evidence
  *format*, but the persistence and the permanence are outside anything the
  vectors can observe.
* **§7's submission side** — `POST /add`, the 400/409/429 statuses and the
  `mmd` deadline semantics. No vector, no server.
* **`quorum none` accepting an uncosigned head** — §12.1 says a second trust
  anchor would be needed and none ships. I therefore could not test
  `TUnboundedNone` against a real artifact; it passes vacuously.
* **`MAX_BUNDLE_BYTES`** — §12.1 argues no valid oversize bundle can exist, and
  my variant confirms the cap is unreachable.
* **The median-vs-k-th-newest reading of `T`** — needs a fourth witness, as
  §12.1 says. With three witnesses and a threshold of two the two rules coincide.
* **A note with a blank line inside its text, and a note with no signature
  lines** — §12.1 explains why no Norn artifact can carry either.
* **Level-1 and higher hash tiles** — `served/` is 126 entries, one tile deep.
* **The `.ots` container beyond its header** — see above.
* **Anything requiring a network**: `log_urls`, witness HTTP
  (`c2sp.org/tlog-witness`), gossip, `T_g`.
* **Monotonic-clock behaviour in §8.1 condition 4** — I model `elapsed` as the
  number `staleness.json` supplies. Whether an implementation actually uses a
  monotonic source is not observable from files.

---

## 7. Closing assessment

Three things are worth saying plainly, because a report that only lists faults
misrepresents this document.

**No rule here is propped up by another.** All 5,151 composites were run and
not one of them rescued a variant the suite caught alone. In a document this
dense with cross-references — §5.1's ordering leaning on §4.0's closedness,
§10's cosignature match leaning on §7's key id, §9.1's correspondence leaning
on the uniqueness rule — that is a real property, and it is the one thing a
single-variant sweep cannot show.

**The precedence work is real and it is pinned.** §5.1's numbered list is the
part most specifications get wrong, and every ordering it claims to fix has a
vector that fixes it: I built six ordering variants (`AfterBeforeDecode`,
`ThresholdBeforeAfter`, `DupBeforeThreshold`, `UnknownTypeFirst`,
`EnrollSigAfterCount`, `RotateSigBeforeDupWg`) and all six were caught, each by
the `log/99…111` entry named for it.

**§12.1's self-assessment is accurate.** I tested all six of its "not vectored"
claims that a variant can express, and all six behaved exactly as it says —
including the subtle composite it predicts, where a strike-off correspondence
check hides a missing uniqueness rule. I found no case where §12.1 claims
coverage it has, except defect 3 (`37-log-key-id-mismatch`) and, in a smaller
way, defect 5.

**The hard parts are right.** The `(name, key id)` cosignature match, the
per-line rather than per-witness refusal, the newest-verifying-line tie-break,
the fork-before-size ordering in §10, the "recomputed from the entries" clause,
the anchor key kept *alongside* the published ones, the policy that *replaces*
where keys *accumulate*, `expires == T` having passed, `elapsed > S` making the
boundary fresh, `S_hard = 0` meaning unconfigured, the request-`ts`
non-constraint, `entry_hash` recorded before decoding — I implemented every one
of those from the prose and every one matched. Those are the decisions that
usually separate two implementations, and this document settles them.

The gaps that remain are, with one exception, in the seams: a table whose rows
are not stated to be ordered, a restatement that is one rule short of complete,
four byte-caps whose vectors are all ASCII, an anchor digest nothing instructs
you to check, and an error vocabulary that exists for §5 and nowhere else.
