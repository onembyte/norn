# Cold-model gate run 13 — SPEC.md v1 against `vectors/`

Second implementation written from the prose alone (Go, standard library only), run against the
whole suite, then swept under 185 single-reading variants and every pair of the 160 the suite
catches. Everything referred to below lives in `work/` beside this file.

## Verdict

**SPEC SUFFICIENT WITH GAPS**

Reasoning. I built every layer the document specifies — the §4.0 codec, the entry schema and
preimages, replay and its sixteen reason codes, canonical state and JSON, the trust file and
fingerprint, the policy grammar and its evaluation, notes, checkpoints, cosignatures and `T`,
receipts, the tiled log, bundles, the proven set, the §10 loop with its stored-checkpoint block,
fork evidence as a reader and as a writer on both sides of a fork, freshness, enrollment requests
and the anchor digest — without seeing a line of either reference implementation, and the first
complete execution reproduced the suite except for two harness-loader mistakes of mine and one
probe that no file binds. Not one of the roughly one hundred reading decisions I wrote down
before opening a vector was overturned by one. The evidence my simulated node writes on the
longer branch is `fork/evidence.cbor` byte for byte. On the question the brief singles out — a
checkpoint's evaluation time, which policy computes it, and what a node admits with no clock —
the document and the suite agree with each other for a node reading a head for the first time.

Why not SUFFICIENT. Two kinds of gap remain, and I judge that neither crosses the line the brief
draws ("a defect that changes what a conforming node does … if the prose itself does not decide
it"), though the first comes close:

1. **The same checkpoint has two evaluation times on two conforming nodes**, and the document
   never says so. §9.4 does decide it — a `policy` entry supersedes the trust policy "for every
   checkpoint a node accepts after replaying it, and for §5.3's `T`" — so a node that has
   replayed the fixture's `policy-rotated` (3 of 3) computes `T` = 1760003600 for the served head
   where a fresh node computes 1760003607, and for `served-twice-cosigned/` the informed node's
   correct answer is 1760003607, exactly the value that vector labels `oldest_would`, "the reading
   this case exists to rule out" (Defect 1, verified by construction). A device whose `expires`
   falls in that seven-second window is on one node's network and off the other's. The prose
   decides it, but only by a subordinate clause two sections away from where `T` is defined, and
   the vector's own gloss points an informed implementer at the wrong fix.
2. **Three suite holes behind unambiguous prose on rules that decide admission or a fork.** A
   reader that tolerates a repeated `sigs` element applies a revocation the document refuses; a
   reader that pools root signatures into the signer count admits a device the document refuses;
   a reader without §11.1's `conflicting.size == size` check concludes a fork — permanently, by
   §11 rule 4 — from two honest heads of one log. Each passes all 886 checks (Defects 2–4, each
   verified by building the input the suite lacks). These are holes in the vectors, not in the
   prose, and §12.1 does not admit them.

The remaining findings are small: two §6 encoding rules stated more weakly than their §7 twins and
unvectored, a handful of prose gaps with no admission consequence, and coverage gaps the prose
decides unambiguously.

## 1. Method

**What I built.** `work/` is a Go module (`module gate13`, go 1.24, standard library only:
`crypto/ed25519` and `crypto/sha256` for the primitives, `encoding/base64` for §7's standard
alphabet with its strict decoder, `encoding/json` only to read `cases.json`, and the usual
`bytes`/`strings`/`strconv`/`unicode/utf8`; the two base32 alphabets, bech32m, CBOR and everything
above them are hand-written). Every protocol layer is my own code:

| file | lines | contents |
|---|---|---|
| `cbor.go` | 353 | §4.0 deterministic CBOR decoder (profile, depth 8, key cap, strict ordering, whole input, allocation bound) and encoder |
| `entry.go` | 289 | §4.1 envelope schema, `sigs` well-formedness, §4.2 preimage, §16.1 request decoding and preimage |
| `replay.go` | 744 | §5 state machine: entry 0, steps 1–8, every type rule, signature counting per role, §5.3 state |
| `json.go` | 209 | §14 canonical JSON for the state and the entry/request mirrors |
| `trust.go` | 305 | §9.1 trust file, §2 origin, §9.3 Crockford fingerprint, correspondence rules |
| `policy.go` | 398 | §9.1 tlog-policy grammar (all twelve rules of the table) and quorum evaluation with nested groups |
| `note.go` | 560 | §7 signed notes, verifier keys with recomputed ids, cosignature lines and preimage, §6 checkpoint body, §7 receipt, §10 log-line and witness-line rules, §5.3 `T` |
| `merkle.go` | 339 | RFC 6962 tree hash, inclusion and consistency proofs (verify and generate), tlog-tiles paths, entry bundles, hash-tile check, rebuild-and-compare |
| `bech32m.go` | 145 | BIP-350 from memory: charset, polymod, HRP expansion, padding rules, the two constants, case rules |
| `verifier.go` | 545 | §8.1 bundles, §11.1 evidence reader and writer (both role assignments), §10 loop with the stored-checkpoint block, proven set, §8.1 freshness ladder, §6 anchor digest |
| `variants.go` | 382 | the 185 boolean readings and one line of description each |
| `main.go` | 1165 | the harness: 886 checks, a §9.2 TOML reader that rebuilds `trust.cbor`, the sweep and pair drivers |
| `probes.go` | 333 | constructions the suite lacks, signed with `keys.json` (entries, requests, checkpoints with cosignatures, evidence) |

5,767 lines in all, of which 3,887 are the implementation (the first ten files) and 1,880 the
variant table, harness and probes. Nothing was copied from anywhere; the C2SP documents were not fetched.

**How the harness works.** `./harness` runs every directory of the suite and prints
`checks: N run, P passed, F failed`; `-v` lists each check by id (`<dir>/<case>[/<aspect>]`).
Every positive is compared byte for byte where the suite ships bytes: the entry mirrors are
rebuilt from my decoder and canonical-JSON writer and compared as whole files, `state.json` and
every `genesis*/`/`log-empty/` state likewise, `trust.cbor` is rebuilt from `trust.toml` through
my encoder, request text forms are re-encoded and compared, and the evidence my node writes on
`detect/fork-on-a-longer-branch` is compared with `fork/evidence.cbor`. Every negative must be
refused, and where a `cases.json` gives an `about` I map it to my own vocabulary by hand and check
that my refusal is about that rule (`hostileAbout`, `bundleAbout`, `evidenceAbout` in `main.go`);
those `/about` checks are marked as such so the sweep can tell a hint-only catch from an
accept/refuse one. The `signature_blind_accepts` set is recomputed by running the checkpoint cases
with both signature checks switched off, and every `says` phrase of every `rules` map is checked
to occur verbatim in `SPEC.md` (187 checks). Served logs are read through an overlay
(`ServedLog.Overrides`) so `checkpoints-bad/`, `served-*/` and `served-bad/` are served "in place of"
the honest files exactly as their `cases.json` say. `detect/` builds a node holding the stored head
and, unless `held: none`, the held branch's entries and replayed state, then offers it the served
directory and checks outcome, that no evidence is written on a refusal, and that written evidence
convinces my own §11.1 reader at the right size.

**How the sweep works.** Every reading is a field of one global struct `V` (`variants.go`), zero
meaning my best-faith reading. `-sweep` flips each field in turn (by reflection), reruns all 886
checks in-process, and records the checks that pass at baseline and fail under the variant; a
variant with an empty set "survives". `-pairs` reruns every pair of caught variants and reports a
**RESCUE** when the pair's failing set is empty and a **PARTIAL** when every check that caught one
member alone passes under the pair. The pair run was sharded over three processes
(`-shard i/3`). `-probes` builds the inputs the suite lacks and runs each under the default reading
and under the relevant surviving variant. Every harness section recovers independently, so a
variant that breaks the trust file cannot truncate a run.

**Artefacts.** `first-run.log` (first complete execution), `final-run.log` (`-v`),
`sweep-full.log` and `sweep-analysis.json` (single variants, with every catching check id),
`pairs-0.log`…`pairs-2.log` (composites), `probes.log` and `probes/` (the constructed inputs),
`DECISIONS-I-HAD-TO-MAKE.md` (the log written before the vectors were opened, with outcomes appended).

## 2. Check tally

`sha256sum -c SHA256SUMS`: **602 of 602 OK**; the directory holds 603 files (the sums file itself).

| directory | checks | passed | failed | what is checked |
|---|---|---|---|---|
| `trust.*` | 5 | 5 | 0 | parse, fingerprint text and file newline, `net`, TOML→CBOR byte identity |
| `trust-bad/` | 45 | 45 | 0 | refused |
| `trust-good/` | 6 | 6 | 0 | accepted |
| `entries/` | 32 | 32 | 0 | mirror file byte identity (entry, hashes, preimage, size) and re-encoding |
| `log/` | 261 | 261 | 0 | 130 reason codes, `state.json` byte identity, 130 `.reason` files agree with the manifest |
| `genesis/` | 38 | 38 | 0 | 19 aborts and their states |
| `genesis-good/` | 4 | 4 | 0 | 2 accepts and their states |
| `log-empty/` | 1 | 1 | 0 | zero state |
| `entries-hostile/` | 33 | 33 | 0 | 15 refusals with their `about`, 3 accepts |
| `policies/` | 45 | 45 | 0 | 15 accepts, 23 refusals, 7 `evaluate` rows |
| `requests/` | 25 | 25 | 0 | decode, signature, mirror, text decodes, text re-encodes, uppercase twin |
| `requests-bad/` | 25 | 25 | 0 | refused |
| `receipt.*` | 2 | 2 | 0 | accepted; fields and `text_sha256` |
| `receipts-bad/` | 14 | 14 | 0 | refused |
| `served/` | 4 | 4 | 0 | accepted end to end; state byte identity; `T` = 1760003607; size |
| `checkpoints-bad/` | 27 | 27 | 0 | 26 refused; `signature_blind_accepts` recomputed and equal |
| `served-extra-witness/`, `-name-collision/`, `-witness-id-collision/`, `-log-id-collision/` | 4 | 4 | 0 | accepted |
| `served-twice-cosigned/` | 4 | 4 | 0 | accepted, `T` = 1760003614; informed reader accepts; probe (informational) |
| `served-rotated/` | 3 | 3 | 0 | fresh refuses; the key is in `log_keys` with the stated `since_index`/`overlap`; informed accepts |
| `served-superseded/` | 2 | 2 | 0 | fresh accepts; informed refuses |
| `served-unused-witness/` | 2 | 2 | 0 | refused under `trust-good/unused-witness.cbor`; honest head accepted under it |
| `served-bad/` | 5 | 5 | 0 | refused |
| `proofs/` | 33 | 33 | 0 | 6 bundles accepted, device bound, `T`, `installs`, `since_index`; replay device list |
| `proofs-bad/` | 18 | 18 | 0 | 9 refused, each about its rule |
| `fork/` | 31 | 31 | 0 | 3 proofs at the stated sizes, 12 refusals each about its rule, both conflicting heads verify |
| `detect/` | 25 | 25 | 0 | 6 outcomes, evidence written/not written, evidence re-read, `evidence.cbor` byte identity, 9 staleness rows |
| `proven/` | 4 | 4 | 0 | four evaluation times |
| `anchors/` | 1 | 1 | 0 | digest of the §6 byte range |
| `says/` | 187 | 187 | 0 | every `says` phrase verbatim in `SPEC.md` |
| **total** | **886** | **886** | **0** | |

**First execution versus after fixes.** The first run aborted at 219 checks on a harness path
mistake (`log/state.json` instead of `state.json`). The first *complete* execution
(`first-run.log`) was **883 run, 880 passed, 3 failed**: `detect/accept-grown` and
`detect/fork-at-the-same-size`, because my harness loaded the 40-entry held branch by asking
`served/` for `tile/entries/000.p/40`, which a log that has grown to 130 no longer serves (fixed
with a prefix loader used only for held branches); and `served-twice-cosigned/informed-quorum-time`,
my own check that an informed reader returns the file's `quorum_time` — which it does not, and
which no file binds (turned into the informational probe discussed under Defect 1). **Nothing about the
default reading's behaviour changed after the first execution**; the later edits added variants
(each behind its own flag), the probes, a guard for a crash under one *variant* reading
(`PolicyErrorCharsAreSeparators` produced a zero-field line), and a hand-written base32 in place
of the standard library's, with identical output on every check.

## 3. Variant sweep

185 variants swept; **160 caught, 25 survive**. Of the 160, **101 are caught by exactly one
vector file** (counting the derived comparisons `state.json` and `signature_blind_accepts` as
part of the file that produces them), 26 by two, 28 by three or more; **3 are caught by a hint
string alone**. Full lists: `sweep-full.log`, `sweep-analysis.json`.

### 3.1 Single variants that survive (25)

Classification: **D** = declared in §12.1's "What is not vectored"; **C** = coverage gap behind
unambiguous prose; **P** = genuine prose gap; **N** = cannot disagree on any legal input.

| variant | reading | class | note |
|---|---|---|---|
| `SigsRepeatOK` | `sigs` sorted non-decreasing, a repeated element tolerated | **C** | Defect 3; probe P2: a valid `revoke` with one element repeated is `decode` under the rule and a revocation without it |
| `EnrollRootsCountAsSigners` | root signatures count towards `signer_thr` on `enroll` | **C** | Defect 4; probe P3: an `enroll` signed by the three roots is `threshold` under the rule and admitted without it |
| `RootLineLenient` | §6 root line decoded leniently (unpadded, non-zero pad bits, CR), receipts strict | **P/C** | Defect 5; probe P12: an unpadded root line, re-signed and cosigned, is accepted |
| `SizeLineSignedOK` | §6 size line accepts `+130`, receipt deadline strict | **P/C** | Defect 5; probe P12 |
| `ReenrollKeepsOldLabels` | a re-enrolment without `labels` keeps the earlier record's | **C** | Defect 6; probe P5 |
| `WitnessURLNonEmpty` | a present witness `url` must be non-empty | **P** | Defect 7a; probe P7. §9.1 bounds `log_urls` elements only |
| `MissingHashTileOK` | a hash tile the log does not serve is tolerated | **P** | Defect 7b. §6 says served tiles MUST agree; it does not say an absent one is a refusal |
| `NonMapBodyAtStep8` | a `body` that is not a map reaches step 8 | **P (reason code only)** | Defect 7c. §5.1 step 3 says "each of the type §4.1 gives it", and §4.1 gives `body` `{ ... }`; the difference is `decode` vs `threshold` on an under-signed governance entry |
| `KidCaseInsensitive` | `kid` regex accepts `A–F` | **C** | probe P8: `decode` vs `threshold` in `state.rejected` |
| `LabelCountExclusive` | 32 labels refused | **C** | probe P6; `too-many-labels` has 33, no request has 32 |
| `PolicyEntryLogLineChecked` | a `policy` entry's `log` line must name a trusted log key | **C** | §5.1 checks witness keys only; a reader adding this refuses entries the document accepts, and no entry has a foreign `log` line |
| `TrustPolicyRequiresLogLine` | a trust file's policy must carry a `log` line | **C** | "A `log` line, if the policy carries one"; every trust file carries one |
| `PolicyTrimAllWhitespace` | Unicode whitespace trimmed at line edges | **C** | `nbsp-is-content` puts U+00A0 inside a field; at a line edge the two readings differ (an NBSP-indented `quorum` line parses under one and is an unknown directive under the other) |
| `TrustCapExclusive`, `EvidenceCapExclusive`, `BundleCapExclusive` | a file of exactly the cap refused | **C** (bundle: **D**) | only the over side is vectored (`38-oversize`, `bad-oversize`) |
| `BundleOriginLenient` | §8.1/§11.1 compare the origin by prefix, separately from §10 | **D** | "Two other origin comparisons" |
| `CorrespondenceStrikeOff` | correspondence strikes names off as matched | **D** | |
| `CountKeyTwice` | a key may contribute twice | **D / N** | `kid` is a function of the key and `sigs` has no repeats |
| `EnrollDupWgOtherDeviceOnly` | `enroll` `dup-wg` only for another device | **D / N** | `dup-id` fires first |
| `QuorumNoneHasClock` | `T` computed under `quorum none` | **D** | needs a second anchor |
| `NoteLastBlankLineEndsText` | the last blank line ends a note's text | **D / N** | |
| `NoteNoSigLinesOK` | a note with no signature lines parses | **D / N** | §10's "at least one such line" refuses first |
| `VKeyB64Lenient` | verifier-key base64 decoded leniently | **D** | |
| `VKeyNameMaySpace` | a verifier-key name may contain a space | **D** | |

### 3.2 What the suite caught, and how narrowly

**Hint-string-only catches (3).** These variants leave every accept/refuse check green and fail
only an `/about` check:

- `OriginBeforeSignature` — only `proofs-bad/foreign-checkpoint/about`. §12.1 declares the order
  of §10's checks unvectored and says `about` is not normative, so this is as documented: the
  signature-before-origin order is held by nothing a conforming reader must produce.
- `EvidenceSizeAboveHeldOK` — only `fork/bad-size-above-held/about`; the file is refused anyway
  because `conflicting`'s size then differs from `size`. Declared multi-rule in §12.1.
- `EvidenceSizeMismatchOK` — only `fork/bad-size-mismatch/about`; the file is refused anyway
  because its proof no longer chains. **Not declared**: §12.1 presents `bad-size-mismatch` as the
  step-2 vector. Defect 2.

**One-file-wide catches (101 of 160).** The suite is built one file per rule, so this is
expected; the ones worth knowing about because the single file is doing unusual work:

- `JSONKeyOrderUTF16` and `JSONUppercaseEscapes` are caught by `state.json` alone (through
  `enroll-astral-labels`); no entry mirror separates them.
- `WitnessOldestLine` is caught only by `served-twice-cosigned/quorum-time`, and the wrong value it
  produces (1760003607) is the value a *correct* informed reader produces (Defect 1).
- `TUnderReplayedPolicy` (compute `T` under the policy the state just replayed) is caught only by
  the two `quorum_time` values, both of which assume a reader holding the trust policy.
- `MatchLogByNameOnly` (match the log's line on its name alone) is caught by no file built for it:
  the only checks that fail are the informed-reader ones (`served-rotated/informed-accepts`, four
  `detect/` cases, `served-twice-cosigned/informed-accept`), and they fail only because an informed
  node holds two log keys under one name, so the served line "matches" the learned key and fails
  under it. A fresh reader with the same bug accepts every shipped head; probe P4 shows it refusing
  an honest head that carries a stranger's line under the log's name. `served-log-id-collision/`
  has no name-collision twin for the log the way `served-name-collision/` has for a witness.
- `ReplayedPolicyIgnored` is caught only by `served-superseded/informed-refuses`;
  `LogKeysReplaceTrust` only by the informed-reader checks against `served/`.
- `SizeRuleFirst` only by `detect/fork-on-a-shorter-branch`; `AccuseWithoutHeld` only by
  `detect/shorter-with-no-held-branch`; `NoRoleSwap` only by `detect/fork-on-a-longer-branch`
  (through my requirement that evidence be written and be checkable).
- `ExpiresStrict` only by `proven/at-the-deadline`; `HardStaleFirst`, `HardZeroIsLimit`,
  `FreshExclusive`, `NoClockIsDegraded` each by one row of `detect/staleness.json`.
- `ConsistencyProofAlwaysCarriesFirst` only by `fork/evidence-at-64`.
- `OTSDigestBody` and `OTSDigestSignedText` only by `anchors/checkpoint-130.ots`'s stated digest.
- Every §9.1 grammar variant by exactly the `policies/` file named for it; every §9.1 trust rule
  by exactly the `trust-bad/` file named for it; every §7 line-framing variant by exactly one
  `checkpoints-bad/` file (plus the derived `signature_blind_accepts`); every §16.2 variant by
  exactly one `requests-bad/` file.

**Catches that depend on the harness reading the suite the way I did.** Three catches would not
exist for an implementer who tests only "a reader holding `trust.cbor`": `MatchLogByNameOnly`,
`ReplayedPolicyIgnored` and `LogKeysReplaceTrust` fail only in the informed-reader path, which
the `served-rotated/` and `served-superseded/` cases describe in prose but no file scripts.

### 3.3 Composites

**12,720 pairs executed** (every pair of the 160 caught variants, three shards, `pairs-*.log`):
**0 full rescues** — no pair of readings the suite catches separately passes the suite together —
and **51 partial rescues**, where every check that caught one member alone passes under the pair
while the pair as a whole still fails somewhere. The 51 fall into three shapes:

- **33 are masking by a second fault that refuses earlier or breaks the fixture.** A reading
  that accepts `50-bad-policy-unparseable` or `129-bad-policy-witness-key-not-a-cosigner`
  (`PolicyEntryUnparsed`, `PolicyEntryKeysUnchecked`) leaves the served log's state with a policy
  the node cannot adopt, so the whole end-to-end path refuses and the tile, cosignature,
  `T`-policy and witness-line variants lose their signal (13 pairs); `AfterEqualIndexRefused`,
  `BootstrapAgainstSignersToo` and `LogKeysReplaceTrust` break replay or the informed reader the
  same way (6); `Bech32LengthLimit90` refuses every ~250-character request before the bech32m rule
  under test is reached (5); `PolicyURLRequired` refuses the `policies/` negatives for the wrong
  reason (3); `EvidenceSkipProof`, `SkipQuorumInReaders`, `EvidencePolicyUnparsed`,
  `TIsNewestLine` and the two `ParseUint`-based decimal variants subsume their partners (6). In every
  one of these the pair fails between 1 and 109 checks, so nothing is hidden from a reader who
  looks at the whole run.
- **13 are offsetting or subsuming faults on one axis**: depth counted from zero *and* scalars
  adding depth (`at-the-depth-limit` still fails); prefix *and* case-fold name matching; id-only
  *and* name-only line matching (the branch order decides); mixed case accepted *and* uppercase
  refused; size rule first *and* accusing without held entries (the first never reaches the
  second; `fork-on-a-shorter-branch` still fails); `PolicyExtraFieldsOK` with either wrong splitter
  (`bad-extra-field` still fails); `NoRoleSwap`/`ReplayedPolicyIgnored` with a name-only matcher (the
  informed `detect/` cases refuse for the matcher's reason).
- **5 are genuine composites — a second fault inside the same function hides the first — and
  they are the ones worth knowing about:**
  - `MatchLogByIDOnly` or `MatchLogByNameOnly` **+** `NoteFirstValidLogLine` or
    `SkipLogSignatureCheck` (4 pairs). A reader that matches the log's line loosely *and* stops at
    the first line that verifies (or does not verify) accepts `served-log-id-collision/` again,
    because the stranger's line it wrongly claimed as the log's is now forgiven. The pair is caught
    only by `checkpoints-bad/16-two-log-signatures` and `receipts-bad/two-log-signatures` — the
    files §12.1 says the canonical `x/mod` implementation opens. Two `two-log-signatures` files are
    therefore holding up four readings at once.
  - `EvidenceSizeMismatchOK` **+** `EvidenceSkipProof`. Alone, the missing size-equality check is
    caught by a hint string only (§3.2); with the consistency proof also unchecked,
    `fork/bad-size-mismatch` is **accepted as a fork**. This is Defect 2's consequence shown on a
    shipped file rather than a constructed one: the file is refused first by the equality, then by
    the proof, and by nothing else.

No pair rescued a survivor either: the 25 survivors were not in the pair space (they are caught by
nothing), and no caught variant becomes uncaught in any pair.

## 4. Defects

Severity: **High** would change who is admitted, whether a fork is concluded or whether a head is
fresh on a reading the prose leaves open; **Medium** changes one of those on a reading the prose
decides but the suite does not pin, or the prose decides only obliquely; **Low** is a reason-code,
encoding-spelling or documentation difference. VERIFIED means I ran the construction.

### Defect 1 — A checkpoint's `T` is node-relative, and the twice-cosigned vector labels the informed reader's correct answer as the wrong reading *(severity: Medium)*

**Prose as written.** §5.3: "`T` is the **quorum time** of the checkpoint the state was replayed
from: the newest instant such that the witnesses whose cosignature timestamp is at or after it
satisfy the policy (§9)." §9.4: "A `policy` entry supersedes `norn.trust.policy` for every
checkpoint a node accepts after replaying it, and for §5.3's `T`." §10's loop: "`state :=
replay(trust, entries[0:cp.size])` / `T := the evaluation time of cp (§5.3)`". §12.1: "`served/checkpoint`,
whose three witnesses cosign seven seconds apart, so the **newest** and the **oldest** are both
separated from the answer". `served-twice-cosigned/cases.json`: "its evaluation time is
`quorum_time`. A reader that takes each witness's oldest line instead gets `oldest_would`, which
is the reading this case exists to rule out".

**Evidence (VERIFIED).** The fixture's witnesses sign `served/checkpoint` at 1760003600 (pi),
1760003607 (vps) and 1760003614 (friend); `served-twice-cosigned/` adds a second `pi` line at
1760003621. The trust policy is `group home 2 pi vps friend`; the log's `49-policy-rotated`
raises it to 3 of 3. Probe P9 (`probes.log`):

```
T of served/checkpoint        trust policy (2 of 3): T=1760003607   replayed policy (3 of 3): T=1760003600
T of served-twice-cosigned    trust policy:          T=1760003614   replayed policy:          T=1760003607  (= the file's oldest_would)
```

My node, following §9.4 literally (the replayed policy supersedes for every head accepted after
replaying it), reports for `served-twice-cosigned/` read *after* replaying `served/`:
`informed reader T=1760003607 (file: quorum_time=1760003614, oldest_would=1760003607)`
(`served-twice-cosigned/PROBE-informed-quorum-time` in `final-run.log`). Under the variant
`TUnderReplayedPolicy` even a fresh node gives those values, and the suite catches that — so the
suite pins the fresh reader and says nothing about the informed one.

**Why it matters.** Two conforming nodes holding the same checkpoint disagree about `T` by seven
seconds, and a device whose `expires` lies in (1760003600, 1760003607] is admitted by the node
that replayed the rotation and dropped by the one that has not. More practically: an implementer
who tests the informed path against `served-twice-cosigned/` sees exactly `oldest_would`, reads the
gloss, and "fixes" a tie-break that was right. The document argues at length that `T` must not
depend on the local machine; it does not say that `T` depends on which policy the machine holds,
which is a different thing but the same surprise.

**Suggested fix.** State in §5.3, where `T` is defined, which policy computes it: "the policy in
force when the node accepted the checkpoint — `norn.trust.policy` until the node has replayed a
`policy` entry, and that entry's text from the next checkpoint on". Say in the same paragraph that
the transition checkpoint therefore has one `T` for a node that bootstraps on it and another for a
node that had already replayed the rotation. In `served-twice-cosigned/cases.json` and
`proofs/cases.json`, say "for a reader holding `trust.cbor`'s policy" beside each `quorum_time`,
and give the informed reader's value too (1760003607 and 1760003600) so that value stops reading
as the wrong tie-break. If the intent is instead that `T` is always computed under the newest
policy the node holds *after* replay (the literal order of §10's pseudo-code), then the two shipped
`quorum_time` values are wrong and should become 1760003600 and 1760003607.

### Defect 2 — `fork/bad-size-mismatch` does not pin §11.1 step 2's "`conflicting`'s size equals `size`" *(severity: Medium, suite)*

**Prose as written.** §11.1 step 2: "check `size` is not above `held`'s own size … then that
`conflicting`'s size equals `size`". §12.1: "one per reader step: … `fork/bad-size-mismatch`
(step 2)", and, listing the files that break more than one rule, "`proofs-bad/foreign-checkpoint`,
`fork/bad-size-above-held` and `fork/bad-unverifiable-conflicting`" — not `bad-size-mismatch`.

**Evidence (VERIFIED).** Under `EvidenceSizeMismatchOK` the file is still refused, by "proof does
not chain held_root to held" (`sweep-full.log`); only its `/about` check fails. Probe P1 builds
the evidence the suite lacks — `held` = `served/checkpoint` (130), `size` = 41, `held_root` =
the served branch's root at 41 with a correct consistency proof, `conflicting` =
`detect/honest-earlier/checkpoint` (an honest, cosigned head of size 40) — and runs both readers:

```
P1 size-mismatch (honest 40)   default: refused: evidence: claims a disagreement at a size the conflicting head does not have
                               variant: fork concluded = true (from two HONEST heads)
```

(`probes/evidence-size-mismatch-honest.cbor`.)

**Why it matters.** A reader without the check concludes a fork from a log and its own honest
earlier head; §11 rule 4 then refuses every later checkpoint until an operator installs a new
trust file. This is precisely the "accusation any stranger can write" §11.1 warns about, and the
suite passes a reader that is open to it.

**Suggested fix.** Rebuild `bad-size-mismatch` as probe P1 does (correct proof and `held_root` at
`size`, a cosigned conflicting head of another size), so that only the equality can refuse it; or
add such a file beside it and list the current one under §12.1's multi-rule files.

### Defect 3 — The "free of repeats" half of the `sigs` rule has no vector *(severity: Medium, suite)*

**Prose as written.** §4.0: "`sigs` is an array of maps `{"kid","role","sig"}` sorted by `kid`
bytewise, with no repeated `kid`"; field table: "`sigs` array | sorted by `kid` and free of repeats
(§4.0); an unsorted or repeating array is `decode`". §12.1 vectors "`bad-unsorted-sigs`" only.

**Evidence (VERIFIED).** `SigsRepeatOK` (non-decreasing order, a repeated element tolerated)
survives the suite. Probe P2 builds a `revoke` of `printer` at index 130 signed by the two current
signers, with the first `sigs` element repeated:

```
P2 repeated sig element   default: reason="decode" printer=active   variant: reason="" printer=revoked
```

(`probes/revoke-repeated-sig.cbor`.)

**Why it matters.** The same log revokes `printer` on one node and not on the other; `state.rejected`
and the proven set diverge. §4.0's own argument for the rule ("CBOR does not canonicalise array
order, so the sorted-and-unique requirement on `sigs` is a schema rule … a decoder will not catch
it") is exactly why a decoder-level test cannot stand in for it.

**Suggested fix.** Add `bad-repeated-sig`: an otherwise accepted entry with one `sigs` element
duplicated, so every signature verifies and only the repeat rule refuses it.

### Defect 4 — An `enroll` signed by roots alone has no vector *(severity: Medium, suite)*

**Prose as written.** §4.3: `enroll` requires "≥ `signer_thr` signers"; "a key counts only for the
role it currently holds"; §5.1's `enroll` row: "valid `signer` count ≥ `signer_thr` (`threshold`)".

**Evidence (VERIFIED).** `EnrollRootsCountAsSigners` survives: `7-bad-threshold`,
`86-bad-one-of-two-signers`, `95-bad-removed-signer`, `96-bad-stranger-signer` and
`54-bad-enroll-empty-sigs` carry no root lines. Probe P3 builds an `enroll` of a new device
signed by `root1`, `root2` and `root3` as `root`:

```
P3 enroll signed by roots   default: reason="threshold" admitted=false   variant: reason="" admitted=true
```

(`probes/enroll-by-roots.cbor`.)

**Why it matters.** A reader that generalises "roots are the network's authority" — encouraged by
`revoke-by-roots`, where they are — admits a device the document refuses. Who is on the VPN differs
between two nodes.

**Suggested fix.** Add `bad-enroll-by-roots` (a properly signed request, a root quorum, no
signers), and its `rotate` twin under `rotate_needs_signer`.

### Defect 5 — §6's root and size lines are held to weaker words than §7's leaf and deadline lines, and the difference is unvectored *(severity: Low, prose and suite)*

**Prose as written.** §6: "the tree size in decimal with **no leading zeroes**, and the root as
**standard base64 with padding, 32 bytes once decoded** — any other decoded length is an error,
and so is base64 the line's own length does not account for." §7, for the receipt: "the third is
`b64` (§1) of a §6 leaf hash, **exactly 32 bytes once decoded** and **exactly its `b64`
encoding**: 44 characters, padded, with zero padding bits, and nothing else in the line … the
fourth is the deadline in **canonical decimal, as §6's size line is**: ASCII digits with **no
leading zeroes**, no sign".

**Evidence (VERIFIED).** `RootLineLenient` (lenient decoding of the checkpoint's root line only)
and `SizeLineSignedOK` (a `+` accepted on the size line only) both survive; the receipt has
`leaf-hash-unpadded`, `leaf-hash-non-canonical-pad-bits`, `leaf-hash-carriage-return` and
`deadline-plus-sign`, the checkpoint has `17-root-wrong-length` and `15-size-leading-zero` only.
Probe P12 re-signs the served body with my own log-key and witness signer (`probes/checkpoint-size-plus.checkpoint`,
`probes/checkpoint-root-unpadded.checkpoint`):

```
P12 size line +130        default: refuse   variant: accept
P12 root line unpadded    default: refuse   variant: accept
```

**Why it matters.** §7 spends a paragraph on why one head must have one byte form (caches,
de-duplication, the §6 anchor digest). A reader that reads §6 for the checkpoint and §7 for the
receipt — the natural split — holds the receipt to the exact encoding and the checkpoint only to
its decoded length; "base64 the line's own length does not account for" does not say "zero
padding bits", and "no leading zeroes" does not say "no sign". Not an admission question.

**Suggested fix.** Give §6's two lines §7's wording ("exactly its `b64` encoding", "ASCII digits,
no sign, fits in 64 bits") or a cross-reference to it, and ship `checkpoints-bad/` twins of the
four receipt spellings.

### Defect 6 — "Replaces the record wholesale" on re-enrolment has no vector *(severity: Low, suite)*

**Prose as written.** §5.3: "A device record holds only what its **most recent** `enroll`
established: re-enrolling a `device_id` after revocation replaces the record wholesale, so labels
and expiry from the earlier enrolment do not survive."

**Evidence (VERIFIED).** `ReenrollKeepsOldLabels` survives because `3-enroll-pi-cam` carries no
labels, so `33-enroll-pi-cam-again` has nothing to inherit. Probe P5 enrols a device with two
labels, revokes it and re-enrols it without labels: `default: labels=0   variant: labels=2`.

**Why it matters.** `labels` carry `ip` and `endpoint`, the advisory hints owner mode installs, so
two nodes would install different allowed-ips for one device. Low because the hints are advisory
and the prose is unambiguous.

**Suggested fix.** Give `3-enroll-pi-cam` labels or an `expires`, and keep `33` bare.

### Defect 7 — Four small prose gaps *(severity: Low, prose)*

(a) **A present witness `url` that is empty.** §9.1 says "Each URL is non-empty" of `log_urls`
only; the `witnesses` row says `url?` and nothing about its content. VERIFIED by probe P7: my
reading accepts `url: ""`, the other refuses. Fix: say whether the `log_urls` rule applies.

(b) **A hash tile the log does not serve.** §6: "The served `tile/<L>/…` hashes MUST also agree
with the tree it rebuilt … checking them is not optional." It does not say that a tile the reader
cannot fetch is a refusal, and `served-bad/` deletes an entry bundle but never a hash tile
(`MissingHashTileOK` survives). Inferred: a reader that checks "every tile it can fetch" passes and
serves nothing onward, which is the outcome the rule exists to prevent. Fix: one sentence and a
`served-bad/missing-hash-tile` case.

(c) **A `body` that is not a map.** §4.1's schema gives `body` the shape `{ ... }` and §5.1 step 3
says "each of the type §4.1 gives it", which I read as `decode` at step 3; a reader that treats
`body` as opaque until step 8 answers `threshold` for an under-signed governance entry
(`NonMapBodyAtStep8` survives). Reason code only. Fix: name `body` (a map) in step 3's list beside
`t`.

(d) **The name and key id of a learned log key.** A `log_key` entry carries a raw `pk`; to match a
signature line a reader needs a name and an id. §2 ("the log key's signed-note name MUST equal
[origin]") and §7's id formula decide it, but §9.4 and §10, where learned keys are introduced, do
not say so. VERIFIED only in the sense that `served-rotated/` accepts under that derivation. Fix:
one sentence in §9.4.

### Defect 8 — Small coverage gaps behind unambiguous prose *(severity: Low, suite)*

Each of these survives the suite; none changes admission; the prose decides each:

- the exact-cap boundary of `MAX_TRUST_BYTES` and `MAX_EVIDENCE_BYTES` (`TrustCapExclusive`,
  `EvidenceCapExclusive`; only the over side ships);
- a request with exactly 32 labels (`LabelCountExclusive`; VERIFIED by probe P6);
- an uppercase `kid` in `sigs` (`KidCaseInsensitive`; VERIFIED by probe P8: `decode` vs `threshold`);
- a `policy` entry whose `log` line names a key the node does not trust (`PolicyEntryLogLineChecked`
  — a stricter reader refuses an entry the document accepts);
- a trust file whose policy has no `log` line (`TrustPolicyRequiresLogLine`);
- Unicode whitespace at a policy line's edge (`PolicyTrimAllWhitespace`);
- a stranger's line under the log's **name** with another id, read by a fresh node
  (`MatchLogByNameOnly` — caught only through the rotation path; VERIFIED by probe P4).

## 5. Every decision the prose did not make for me

The full log, written before any vector was opened, is `DECISIONS-I-HAD-TO-MAKE.md`; this is its
finished form. **None was overturned by a vector.** `V` = a shipped file agrees; `U` = no shipped
file can tell (the probes above cover several); `D` = declared unvectored in §12.1.

**CBOR profile (§4.0).** Booleans are allowed at the decoder anywhere and refused by the schema
(both give `decode`; U). Simple values other than `true`/`false` are refused (U). `MAX_ENTRY_BYTES`
is inclusive and checked on the raw length before decoding, and any length header promising more
than the remaining input is refused before allocation (V: `at-the-size-limit`, `oversize-entry`).
Depth counts containers only, top level = 1, ≤ 8 (V). The 1–23-byte key cap is a decoder rule for
every map (V). Keys compare by encoded form, strictly increasing (V). The profile, whole-input rule
included, applies to every CBOR artifact with its own byte cap (V for entries, trust, bundles,
evidence). Caps are inclusive (U for trust/evidence/bundle boundaries).

**Entry schema (§4.1–4.3).** A non-map `body` or non-uint `after` is `decode` at step 3 (U/V).
Governance bodies are validated after the threshold (V: `94`, `48`). A `note` with only a device
signature is `threshold` (V: `91`). `reason` absent equals `""` (V). A `rotate` whose incoming
`device_pk` equals the current one is accepted (U). A `rotate` re-presenting its own `wg_pk` is
not `dup-wg` (V: `40`). `log_key` needs both `pk` and `overlap` (V). The embedded request is decoded
under every §16.1 rule, its `net` compared to the entry's, and its `ts` never compared (V: `57`,
`117`, `125`). `params` types: bool for `rotate_needs_signer`, uints otherwise (V: `108`). A `thr` of
the wrong type is `decode`, out of range is `bad-thr` (V: `19`, `69`). A `device`-role line on a
governance entry counts for nothing (V). Role must match the role the key holds (V: `87`, `115`). A
device signature must carry `kid(device_pk)` (V: `59`). `dup-genesis` fires before the body is
looked at (V: `14`). `sig` must be 64 bytes at step 3 (V: `82`). `revoke`'s three authorisations
are never pooled (V: `104`); roots never stand in for signers on `enroll` or `rotate` (U — Defect 4).

**Replay and state (§5).** Entry 0's hash is recorded even on abort (U). Genesis `after: 0` is
accepted (V). Empty genesis `params` aborts (V). Bootstrap resolves `root` lines against the body's
`roots` only, role respected (V: `18`, `19`). Abort gives size 0 and one rejection (V). Re-enrolment
sets `since_index` and replaces the record (V for `since_index`; U for the wholesale replacement —
Defect 6). Labels are emitted in bytewise JSON order (V). `root_remove` invariant as written (V).
Last signer removable (V: `62`). `root_thr` counted against the old set and threshold (V: `23`,
`42`). A `policy` entry's witness keys must be cosignature keys; its `log` lines are not checked
(V: `129`; U for `log` lines). `quorum none` in a `policy` entry is accepted (U). The request's
depth restarts at 1 (U by construction).

**Canonical JSON (§14).** `log_keys` elements `{overlap, pk, since_index}`, `rejected` elements
`{index, reason}`, booleans as literals, DEL verbatim, one trailing newline (all V through
`state.json`).

**Trust file (§9).** A witness `url` may be empty (U — Defect 7a). Verifier-key names must be
non-empty and space-free (D). Key data is strict canonical base64 of 33 bytes (D). Key ids are
recomputed and compared as lowercase text (V: `37`, `39`, `40`). `MAX_TRUST_BYTES` inclusive (U).
Anchor: any `max_lag`, any `type`, `mode == "advisory"` (V). Correspondence on the set of names
with text-equal keys, and every `log` line equal to `log_key` (V: `17`, `18`, `36`). Two `log` lines
both equal to `log_key` are refused by the grammar's `keys` rule (U). `quorum none` with witnesses
listed is accepted (U/D). The fingerprint is over the file bytes as received (V). Witness names
unique bytewise (V: `30`). `log_key`'s name equals `origin` byte for byte (V: `41`–`43`).

**Policy grammar (§9.1).** Keys on `log`/`witness` lines are opaque text (V: `bad-duplicate-key`
compares text). Names may be anything but `none`, including `all`, `any` or a number (U). A witness
may be defined after the `quorum` line if unused there (U). An empty policy is an error (V:
`bad-no-quorum`). `k` is `^[1-9][0-9]*$` with 1 ≤ k ≤ n (V). A group naming itself is a forward
reference (U). URLs are outside the `keys` rule (U). Lines split on `\n` only, final newline
optional (V). Error characters tested on every line before it is ignored (V). Evaluation on short
names (V). A `quorum` naming a group of groups is fine (U).

**Notes, checkpoints, receipts (§6, §7, §10).** The log's line is matched on name **and** id
(V: `served-log-id-collision`; name-only only through the rotation path — §3.2). With several
trusted log keys, "at least one such line" is across all of them and every matching line must
verify (V: `served-rotated`, `16`). A learned key's name is the origin and its id is recomputed
under algorithm `0x01` (V: `served-rotated`; Defect 7d). A stranger's line must still be 68 or 76
bytes (V: `26`). A log-key line of 76 bytes is refused (U, both readings refuse). Base64 in lines
is strict and canonical (V: `19`, `24`). Size `0` is legal; size and deadline fit in 64 bits (U /
V: `deadline-above-uint64`). The root line is 44 canonical characters (V for length only —
Defect 5). The separator line is exactly empty (U). Names split at the first space (V: `18`).
Witness lines are matched on name and id against the current policy's `witness` keys, whether or
not a quorum uses them; each matching line must verify; a witness counts at its newest verifying
line; the quorum is evaluated over witnesses with a verifying line (V: `served-*`, `11`, `12`,
`served-unused-witness`, `served-twice-cosigned`). Under `quorum none`, listed witnesses' lines are
still verified (U/D). `T` is the newest of the witnesses' timestamps at which the set with
timestamp ≥ it satisfies the policy (V). **`T` is computed under the policy the checkpoint was
accepted under** (V for a fresh reader; the informed reader is Defect 1). A receipt deadline of `0`
is accepted (U). A receipt has exactly four lines (V).

**Verifier loop and fork (§10, §11).** Compare-then-size-rule with `at = min`; served root
recomputed from the served entries after the served tree has passed its own tile and head checks;
`mine` is the stored root at the stored size, else the held branch's root, else refuse without
accusing (V: all six `detect/` cases). Equal size and root is an accept (V through the informed
reader). Evidence roles: served longer → `held` = served, `conflicting` = stored, `size` = stored
size, proof from the served entries (V: byte identity with `fork/evidence.cbor`); otherwise `held` =
stored, `size` = served size, proof from the held entries, empty at equal size (V through my own
reader only). The carried `policy` is parsed under the grammar only (U). Both checkpoints verify
under the reader's trust policy and trust log key (V). `held_root` and proof elements are 32 bytes
(U). RFC 6962 §2.1.2 with a power-of-two `first` (V: `evidence-at-64`). A bundle's checkpoint is
verified under the trust file only (V; a rotated-key bundle is D). A bundle over an entry naming no
device is refused; over a `rotate` it is accepted (U; probe P10). The bundle's entry is decoded and
envelope-checked but its signatures are not verified (U). `index < size` (U).

**Tiled log (§6).** Every bundle for the size is fetched, the partial one holding exactly its
declared count with no trailing byte (V: `served-bad/`). Every hash tile that exists for the size is
fetched and compared; a missing one is a refusal (V for tampered, U for missing — Defect 7b). Level
`L` tiles exist only where a complete `256^L` subtree does (V). Entries are not validated while
reading; replay decides (V).

**Proven set and freshness (§5.3, §8.1).** Expired iff `expires != 0 && expires <= T`; no `T`
means nothing expires (V: `proven/`). The ladder in the written order with `S_hard = 0` meaning
unconfigured (V: `staleness.json`).

**Requests (§16).** Entirely lowercase or entirely uppercase, lowercased before decoding, HRP
`norn` after lowercasing, last `1` separates, all characters 33–126, checksum `0x2bc830a3`, no
length cap, padding under five bits and zero (V: `requests/`, `requests-bad/`). One trailing `\n`
stripped from `.txt` (V). Labels ≤ 32 with values ≤ 256 bytes (V for values; U for the count —
Defect 8). `expires > ts` (V). Decoded payload ≤ 65535 (U). An empty `labels` map is accepted (D).

**Anchors.** SHA-256 through the fourth `0x0A` (V).

## 6. What I could not cover, and why

- **The informed reader's `T`.** No file binds it (Defect 1); my node's answer is recorded as a
  probe, not a check.
- **`quorum none` end to end** — an uncosigned head accepted, a node with no clock keeping its
  peers, `unknown` freshness from a real head. `proven/no-clock` and `staleness/no-clock` exercise
  the consequences from a stated `t = 0`; nothing ships a second trust anchor (declared in §12.1).
- **§11 rule 4 over time.** `detect/` offers one head per case; that a forked node keeps refusing
  inconsistent heads "forever" and keeps accepting consistent ones is not scripted, and I built no
  multi-round case.
- **A served tree that fails its tile checks and would also be a fork.** I refuse before comparing
  (§10 lists tile fetching after the stored-checkpoint block, but the served root at `at` needs the
  entries). No file has both faults.
- **A bundle whose checkpoint is signed by a rotated key**, and §8.1 condition 2 as a node's own
  check — declared unshipped.
- **A verifier key with an algorithm byte other than `0x01` or `0x04`.** I refuse it as unparseable;
  the document says only that it "uses two".
- **OpenTimestamps itself.** I check the stated digest of the stated byte range and do not parse
  `.ots`, as `anchors/cases.json` intends.
- **Interop with `x/mod/sumdb/note`, `transparency-dev/formats` and `x/mod/sumdb/tlog`.** No
  network and no third-party code; my own signer side (probe P11: a checkpoint I sign and cosign
  with the test keys is accepted by my reader) is the only cross-check of the cosignature preimage
  beyond the shipped heads.
- **The witness HTTP protocol, gossip, enforcement** — referenced documents, not shipped.
- **A rotation vector for the median-versus-k-th-newest question** — declared unvectorable with
  three witnesses.

## 7. Closing assessment

This document can be implemented cold. Everything that decides who is admitted, whether a fork is
concluded and whether a head is fresh is written down, and the vectors pin nearly all of it hard
enough that 160 of 185 deliberately wrong readings fail at least one check. The places it is
weakest are, characteristically, the places where a rule lives in one section and its consequence
in another: `T` is defined in §5.3, the policy that computes it is fixed by a clause in §9.4, and
the vector that would tell an informed reader it is right says the opposite. The suite's three
material holes (a repeated signature element, an `enroll` by roots, a size mismatch in evidence)
are each a one-file addition, and each guards a rule the prose already states without ambiguity.

Five things I would ask the authors not to break:

1. **`T` from the cosignature timestamps under the policy in force at acceptance, never the local
   clock, and no `T` at all under `quorum none`.** Every reading that touched this failed a check;
   the one that did not (the informed reader) needs the sentence Defect 1 asks for.
2. **The §5.1 ordering with its precedence vectors** (`99`–`103`, `109`–`111`, the two
   `threshold-before-dup-*`). They are the reason two implementations agree on `state.rejected`.
3. **Compare before the size rule, and swap the evidence roles on the longer branch.** Without
   `fork-on-a-shorter-branch` and `fork-on-a-longer-branch` the two most natural simplifications of
   §10 and §11.1 pass the suite; with them my writer reproduced `fork/evidence.cbor` byte for byte
   without ever seeing how the reference builds one.
4. **Name-and-id matching for every signature line, per line, with strangers ignored** — the four
   `served-*-collision`/`extra-witness` heads and `11`/`12`/`unused-witness` between them close every
   veto and every over-count I could think of.
5. **The trust file's key kept alongside the learned ones, and the replayed policy replacing.**
   `served-rotated/` and `served-superseded/` are the only two files with two right answers, and
   they are what make rotation non-circular in practice, not only in the argument.
