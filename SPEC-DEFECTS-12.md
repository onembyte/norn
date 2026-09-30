# Cold-model gate run 12 — Norn Specification v0 (frozen v1, 2026-09-20)

Independent, adversarial second implementation from `sealed/SPEC.md` and
`sealed/vectors/` alone. Nothing outside `gate12/` was read; no network; no
C2SP or BIP documents fetched. Go 1.24.7 (the brief said 1.26; nothing here
depends on the difference), standard library only.

## Verdict

**SPEC INSUFFICIENT** — narrowly, and for a short list of specific reasons.

The bar set for this run is not "the checks pass". They do: 553 of 553 checks,
every positive reproduced byte for byte, every negative refused, and every
refusal about the rule the suite names — on the second execution, after one
ordering slip in my own code. The bar is whether a second implementer *could
not reasonably have got it wrong*, and whether anything the prose leaves open
changes what a conforming node does. Four things do, and the suite cannot see
any of them:

1. **§9.1's comment rule and its error-character rule contradict each other**
   for a comment line that contains `0x0D` (Defect 1). Two conforming readers
   disagree on whether a `policy` entry is `decode` or a new quorum — the exact
   disagreement §9.1 says the closed character set exists to prevent. Verified
   by construction: both readers pass the suite and replay to different
   `state.json`.
2. **§10 does not say what "a witness the policy names" means** for a
   `witness` line that no `group` or `quorum` reaches (Defect 2). One reader
   refuses a head over a bad line from that witness, the other ignores it.
   Verified.
3. **§5.3's `T` for one checkpoint depends on the node's history** (Defect 3):
   `served/checkpoint` has `T = 1760003607` under the trust file's 2-of-3
   policy and `T = 1760003600` under the 3-of-3 policy the log's own roots
   published at `49-policy-rotated`. The suite pins the first; §9.4 says the
   informed node uses the second. Two conforming nodes admit different sets
   of peers for the same head at the expiry boundary. Verified.
4. **§11.1's `held` cannot be "the checkpoint the accuser was holding" when
   the conflicting branch is the longer one** (Defect 5); the evidence can
   only be written with the roles swapped, and the prose does not say so.
   Verified: the literal reading is unwritable, the swapped file verifies.

Everything else is either strong (the encoding profile, replay, canonical
JSON, the trust file, receipts, the loop, the freshness ladder — the sweep
shows the suite catching 95 of 128 alternative readings, most of them by
accept/refuse on more than one file) or is a coverage gap behind prose that
does decide the question (§4). The four above are each a sentence to fix and
one file to ship. Had they been fixed, the verdict would be SPEC SUFFICIENT
WITH GAPS.

## 1. Method

### What I built

`work/` holds a complete second implementation, 5,300 lines of Go (plus a
1,000-line harness and a 350-line demonstration test file), all written for
this run from the prose:

| file | lines | what it implements |
|---|---|---|
| `cbor.go` | 442 | §4.0 strict CBOR decoder (shortest form for every head argument, key order by encoded form, 1–23-byte text keys, depth ≤ 8 in containers, byte caps, whole-input consumption, UTF-8) and a deterministic encoder |
| `entry.go` | 299 | §4.1–4.3 envelope, `sigs` schema, genesis body, hashes and the §4.2 preimage |
| `request.go` | 342 | §16.1 request schema and preimage; §16.2 bech32m (polymod, HRP expansion, padding rule, case rules) |
| `replay.go` | 626 | §5 replay: entry 0, the numbered steps, every type rule in its written order, signature counting per §5.2, canonical state (§5.3) |
| `canonjson.go` | 123 | §14 canonical JSON |
| `note.go` | 243 | §7 signed-note framing, verifier-key strings with recomputed ids, note and cosignature verification |
| `policy.go` | 358 | §9.1 tlog-policy grammar and quorum evaluation |
| `trust.go` | 488 | §9.1 trust file, correspondence rules, §9.3 fingerprint, and a §9.2 TOML reader that rebuilds the CBOR |
| `checkpoint.go` | 389 | §6 body, §10 log-signature/origin/witness rules, §5.3 quorum time, §7 receipts, trust-only and informed contexts (§9.4) |
| `merkle.go` | 150 | RFC 6962 tree, inclusion and consistency proof generation and verification |
| `tiles.go` | 172 | tlog-tiles paths, entry bundles, hash-tile rebuild and comparison |
| `bundle.go` | 189 | §8.1 proof bundles, the install-key rule (condition 3) |
| `evidence.go` | 170 | §11.1 fork evidence, reader and writer |
| `verifier.go` | 148 | §10 stored-checkpoint/fork block, proven set at `T`, §8.1 freshness ladder |
| `variants.go` | 177 | 128 boolean readings |
| `main.go` | 1018 | the harness: every directory, the `about`/`rules` mapping, the sweep and the pair sweep |
| `extra_test.go` | ~350 | forged artifacts (from `keys.json` seeds) that demonstrate each surviving reading disagreeing |

Nothing was imported beyond `crypto/ed25519`, `crypto/sha256`, `encoding/*`,
`regexp` and the usual plumbing.

### The harness

`./gate12` runs every directory and prints a per-directory tally. Each
negative is checked two ways: it must be refused, and my refusal's rule
(my own vocabulary) must be in a hand-written set mapped from the case's
`about`/`rules` phrase — the mapping is in `main.go` beside each directory.
A refusal for the wrong rule is recorded as `HINT-ONLY`, so the sweep can
tell an accept/refuse catch from a catch that rests on a string.

Positives are reproduced byte for byte wherever bytes ship: the 16 entry
mirrors, `state.json` (from `log/`, from `served/` and from the
`detect/accept-grown` path), the 19 `genesis/` states, `log-empty`, the six
request mirrors and their text forms in both directions, the six proof
bundles (rebuilt from the served entries and compared to the shipped files),
`fork/evidence.cbor` (likewise rebuilt), `trust.cbor` from `trust.toml`, and
the fingerprint. The `signature_blind_accepts` list is recomputed by running
my verifier with Ed25519 disabled and compared to the shipped list.

`./gate12 -sweep` runs the whole suite once per variant and lists the checks
that fail only under it. `./gate12 -pairs` runs every pair in which at least
one member was caught alone and reports any check caught alone that passes
under the pair ("rescued"). `go test -run TestDemo -v` runs the forged
demonstrations.

### Artefacts

All under `/tmp/claude-0/-home-user-norn/795f1315-f861-5665-9b1d-af3ad14b1642/scratchpad/gate12/work/`:
`DECISIONS-I-HAD-TO-MAKE.md` (the pre-vector log plus outcomes),
`first-run.log`, `sweep-single.log`, `pairs.log`, `extra_test.go`,
`demo-fork-at-64.evidence.cbor`, and this report.

## 2. Check tally

SHA256SUMS: **579 of 579 files OK** (`sha256sum -c`, before anything else was
opened).

| directory | checks | passed | failed (final) | failed on FIRST execution |
|---|---|---|---|---|
| `entries/` (16 mirrors) | 16 | 16 | 0 | 0 |
| `log/` (129 reasons + 87 `.reason` files + `state.json`) | 217 | 217 | 0 | 2 (`110-bad-enroll-request-net-and-sig`, `state.json`) |
| `genesis/` | 19 | 19 | 0 | 0 |
| `genesis-good/` | 1 | 1 | 0 | 0 |
| `log-empty/` | 1 | 1 | 0 | 0 |
| `entries-hostile/` | 16 | 16 | 0 | 0 |
| `trust.cbor` / `.toml` / `.fingerprint` / `keys.json` | 7 | 7 | 0 | 0 |
| `trust-bad/` | 45 | 45 | 0 | 0 |
| `trust-good/` | 5 | 5 | 0 | 0 |
| `policies/` (32 parse + 6 evaluate rows) | 38 | 38 | 0 | 0 |
| `requests/` (6 × cbor/text/mirror) | 19 | 19 | 0 | 0 |
| `requests-bad/` | 25 | 25 | 0 | 1 (`excess-padding`, hint only — see Defect 6) |
| `anchors/` | 4 | 4 | 0 | 0 |
| `receipt.note` / `receipt.json` | 2 | 2 | 0 | 0 |
| `receipts-bad/` | 14 | 14 | 0 | 0 |
| `served/` (checkpoint, tiles, replay, T, informed policy) | 6 | 6 | 0 | 1 (replay == state.json, same cause as `log/`) |
| `checkpoints-bad/` (23 + the blind set) | 24 | 24 | 0 | 0 |
| `served-extra-witness/`, `-name-collision/`, `-witness-id-collision/`, `-log-id-collision/` | 4 | 4 | 0 | 0 |
| `served-twice-cosigned/` | 2 | 2 | 0 | 0 |
| `served-rotated/` (both readers + key in state) | 3 | 3 | 0 | 0 |
| `served-superseded/` (both readers) | 2 | 2 | 0 | 0 |
| `served-bad/` | 4 | 4 | 0 | 0 |
| `proofs/` (6 bundles × verify/installs/index/T/rebuild) | 31 | 31 | 0 | 0 |
| `proofs-bad/` | 10 | 10 | 0 | 0 |
| `proven/` | 4 | 4 | 0 | 0 |
| `fork/` (positive, twin, rebuild, 12 negatives) | 17 | 17 | 0 | 0 |
| `detect/` (5 cases, evidence self-check, replay) | 8 | 8 | 0 | 1 (replay == state.json, same cause) |
| `detect/staleness.json` | 9 | 9 | 0 | 0 |
| **total** | **553** | **553** | **0** | **5** |

**First execution: 548/553.** Four of the five failures had one cause in my
code: inside an `enroll` I verified the request's signature before comparing
its `net` with the entry's, where §5.1's table puts `net` first
(`110-bad-enroll-request-net-and-sig` → `no-device-sig` instead of `decode`,
and therefore three `state.json` comparisons). My pre-vector decision B12
had the order right; the parser did not. Fixed by splitting structure from
signature. The fifth, `requests-bad/excess-padding`, was refused on the
first run and every run — but by §4.0's whole-input rule, not §16.2's
padding rule; that is Defect 6, not a bug in my code, and the harness now
accepts either rule for that one file with a comment saying why.

## 3. Variant sweep

128 readings wired; 95 caught by at least one check; **33 survive**.
Full per-variant catch lists are in `sweep-single.log`.

### 3.1 Surviving variants

**Declared in §12.1's "What is not vectored" (12):**
`BundleNoSizeCap`, `BundleOriginLax`, `EvidenceOriginLax` (the two other
origin comparisons), `CorrespondenceStrikesNames`, `DupWgEnrollOtherDeviceOnly`,
`EnrollSkipsLabelCap`, `EntryHashOverCanonical`, `NoteTextLastBlankLine`,
`QuorumNoneGivesClock`, `QuorumTimeMedian`, `RequestNoSizeCap`,
`StateNetFromGenesis`. Every declaration checked out: each of these passes
553/553.

**Coverage gap behind prose that does decide it (11):**
- `GenesisAfterMustBeAbsent` — §5.1 entry-0 step 5 says "`after`, if present,
  MUST be 0"; the fixture's genesis carries no `after`, so a reader that
  refuses any `after` at index 0 passes. A whole log replays on one node and
  aborts on the other (demonstrated).
- `BundleLeftoverBytesOK` — §6 "a partial bundle holds exactly the number of
  entries its path declares"; no bundle with trailing bytes ships.
- `MapKeyAllowEmpty` — §4.0 "1–23 bytes"; only the upper bound is vectored.
- `Utf8AllowSurrogates` — "valid UTF-8"; `bare-invalid-utf8` is not a surrogate.
- `VkeyNameUnconstrained` — §7 "a key name contains no space"; no key string
  with a space ships (a witness key with one would be accepted by that reader).
- `TrustWitnessURLNonEmpty` — the prose constrains `log_urls` elements to
  non-empty and says nothing about a witness `url`; no empty one ships.
- `NoteEmptyNameOK` — a line `—  <payload>` (empty name); not shipped.
- `CheckpointSizeZeroRefused` — a size line of `0` is canonical decimal; no
  empty-log checkpoint ships.
- `LabelsEmptyMapRefused` — `labels: {}` is a present, empty map; the prose
  forbids an empty `params` explicitly and says nothing here.
- `BundleEntryMustBeEnroll` — §8.1 allows `rotate`/`revoke` entries in a bundle;
  every shipped bundle is an `enroll`.
- `ConsistencyNoPow2Prepend` — RFC 6962 §2.1.2 step 1 (prepend `first_hash`
  when `first` is a power of two) is never exercised: the only shipped
  evidence is at size 40 and the `detect/` forks are at 40 and 41. See Defect 4.

**Genuine prose gap (10):** `PolicyErrCharsIgnoredInComments` (Defect 1),
`NamedMeansReachableFromQuorum` (Defect 2), `NoteB64LaxPadBits` (Defect 8),
`EnvelopeTypeChecksDeferred` (Defect 9), `PolicyNamesSeparateNamespaces`,
`QuorumMustBePreviouslyDefined`, `PolicyNoneNotReserved`,
`PolicyTrailingSpaceIsError`, `PolicyVkeysMustParse` / `PolicyEntryParsesVkeys`
(Defect 10 covers the five grammar ones). Each was demonstrated to make two
readers disagree on a legal input (`go test -run TestDemo -v`).

**Cannot disagree on any legal input (0 that survive as such)** — the readings
I expected to be unobservable (`EntryHashOverCanonical`, `StateNetFromGenesis`,
the strike-off correspondence) are in the declared list above, and §12.1
already explains why.

One more deserves a note although it is nominally caught:
`UnknownLinePayloadUnbounded` (a stranger's line may carry a payload of any
length ≥ 4) fails only my *derived* check that recomputes
`signature_blind_accepts`. On accept/refuse alone it survives, and §7's
"exactly that length" has no length to name for a line under a key the
reader does not hold. A stranger using some third algorithm is refused by
one reader and ignored by the other.

### 3.2 What the suite caught, and how narrowly

**One-file-wide catches (53 of the 95: 47 caught by exactly one check, and 6
more whose only other catch is my derived blind-set check).** Most rules are
pinned by exactly one file, which is the suite's stated design ("one whole
policy per rule", "each differing from a valid bundle in exactly one thing").
The list, by file:

- `entries-hostile/`: `at-the-depth-limit` (DepthCountsScalars),
  `past-the-depth-limit` (DepthLimitNine), `past-the-size-limit` (SizeLimitOffByOne).
- `genesis/19` (GenesisBootstrapAnyRole); `log-empty/state.json` (NoGenesisIsBadGenesis).
- `trust-bad/`: 29 (TrustAllowNoWitnesses), 35 (TrustAcceptAnyMode), 38
  (TrustNoSizeCap), 40 (VkeyIdCaseInsensitive), 42 (TrustLogKeyNameCaseFold);
  `trust-good/`: anchor-unknown-type, no-anchor, witness-without-url.
- `policies/`: bad-forward-reference, bad-trailing-comment, bad-k-leading-zero,
  bad-k-zero, bad-log-key-as-witness, bad-uppercase-keyword (one variant each).
- `requests/req-minimal-upper` (Bech32RefuseUppercase); `requests-bad/`:
  plain-bech32, mixed-case, non-zero-padding.
- `receipts-bad/`: extension-line, leaf-hash-too-long.
- `checkpoints-bad/`: 09, 15, 17, 14, 18, 20 — each is the *only*
  accept/refuse catch for its variant; the second listed catch in
  `sweep-single.log` is my derived blind-set check, not a shipped file.
- `served-log-id-collision`, `served-name-collision`,
  `served-witness-id-collision` (the three matching rules), `served-twice-cosigned`
  (WitnessOldestLine), `served/checkpoint under the replayed policy`
  (PublishedKeysReplaceTrustKey), `served-superseded` (InformedKeepsTrustPolicyToo).
- `served-bad/tampered-hash-tile` (SkipHashTileCheck), `consistent-tampered-log`
  (SkipRootCompare).
- `proofs/nas installs` (BundleInstallEntryKey); `proofs-bad/`: open-schema,
  device-not-in-entry.
- `proven/at-the-deadline` (ExpiryStrict); `staleness/`: at-the-staleness-boundary
  (FreshStrict), hard-below-staleness-still-fresh (HardStaleBeforeFresh),
  unconfigured-hard-stays-degraded (HardZeroIsALimit).
- `detect/fork-on-a-shorter-branch` (SizeRuleBeforeForkCheck).
- `fork/`: bad-oversize, bad-policy-unparseable, bad-proof-at-same-size.

None of these is a complaint: one file per rule is enough when it binds
accept/refuse. It does mean the suite has no redundancy — a single corrupted
or mislabelled file silently uncovers a rule.

**Catches that rest on a hint string only** (the file is refused under the
lax reading too, by another rule; only my `about` mapping notices):
- `fork/bad-open-schema` under `EvidenceOpenSchema` — refused for
  `held_root == conflicting.root`. The file is a consistent 129/119 pair plus a
  `surprise` key, so the closed-schema rule for evidence is **not** pinned by
  accept/refuse (Defect 7).
- `fork/bad-size-above-held` under `EvidenceSizeAboveHeldOK` — refused for
  `conflicting`'s size ≠ `size`. §12.1 declares this one ("breaks more than one
  rule").
- `checkpoints-bad/08` under `WitnessPerWitnessNotPerLine` — refused for the
  quorum; §12.1 says so ("`08` cannot tell the two readings apart"). `11` and
  `12` do pin it by accept/refuse.
- `requests-bad/excess-padding` under any reading — refused by §4.0's
  trailing-byte rule; the padding rule never fires (Defect 6).

Per §12's definition, `says` binds a phrase to a section and `about` is a
hint; none of the above is a failure of the suite's contract, but the first
and last are places where the contract's own coverage claim is wrong.

### 3.3 Composites

**7,600 pairs executed** (every pair of the 128 variants in which at least
one member was caught alone; the 528 survivor–survivor pairs were skipped
because two readings the suite cannot see cannot rescue each other). 41
minutes; full output in `pairs.log`. A pair "rescues" a variant when every
check that caught it alone passes under the pair; 18 pairs did that, 11 more
rescued some of a member's catches. Each of the 18 was then run in full:

**Pairs that pass the whole suite (5):**

| pair | what it is |
|---|---|
| `PolicyHashIsTrailingComment` + `PolicyTrailingSpaceIsError` | **A real composite.** Strip from `#` anywhere, and refuse a line that then ends in a separator. `bad-trailing-comment` (`quorum pi # note`) is refused for the trailing space, so the pair passes 553/553 — and accepts `quorum pi#note`, which §9.1 refuses (`pi#note` is one undefined name). `TestDemoCompositeTrailingComment`. See Defect 14. |
| `DepthCountsScalars` + `DepthLimitNine` | Equivalent reading: "count the scalar, allow 9" is "count containers, allow 8" on every input. Not a finding. |
| `PolicyErrCharsAreContent` + `PolicyErrCharsIgnoredInComments` | Wiring artifact: in my parser the comment-aware flag re-checks the three characters in every non-comment line, so the pair collapses to the default rule plus Defect 1's reading. Confirms that reading survives; nothing new. |
| `PolicyErrCharsAreSeparators` + `PolicyErrCharsIgnoredInComments` | Same artifact. |
| `QuorumTimeIsOldest` + `QuorumTimeMedian` | Precedence artifact: the median branch runs first, so the pair *is* `QuorumTimeMedian`, a declared survivor. |

**Full rescues where the pair still fails elsewhere (13)** — the rescued
member's catches vanish only because the partner breaks something bigger:
`PublishedKeysReplaceTrustKey` is rescued by `AfterStrict`, `NoLogSigCheck`,
`RootRemoveNoInvariant` and `InformedKeepsTrustPolicyToo` (each of which
either destroys the replayed state that holds the published keys or removes
the check the head fails); `MatchLogLineByIdOnly` by `LogSigAnyOneVerifies`
and `NoLogSigCheck`; `MatchWitnessLineByIdOnly` / `-ByNameOnly` by
`NoCosigCheck` and `WitnessPerWitnessNotPerLine` (if a bad line is merely
uncounted, matching the wrong line no longer refuses); the two matching
readings by each other (each rescues the other's file and keeps its own
failure); `WitnessOldestLine` by `QuorumTimeIsNewest` (which still fails
seven `T` checks). None of these is a reading a second implementer could
hold and pass the suite.

**Partial rescues (11):** the four wide variants (`AfterStrict`,
`ReasonCountsChars`, `TextCapStrict`, `RootRemoveNoInvariant`) each rescue
one or two checks of a partner while failing 15–108 of their own; and
`UnknownWitnessLineRefused` rescues one catch each of `NoLogSigCheck`,
`SigLineSplitLastSpace` and `UnknownSigLineB64Lax` — refusing every
stranger's line hides a reader that mis-parses stranger's lines — while
still failing the four `served-*` positives. Not exploitable.

**Conclusion.** One composite passes the suite and disagrees with the
prose (Defect 14); no pair rescues any of the security-relevant catches
(signature, cosignature, matching, quorum, fork order, tiles) without failing
a positive.

## 4. Defects

Severity: **High** — changes admission, fork conclusion or freshness and the
prose does not decide it; **Medium** — changes what a node does in a case
the prose does not decide, or a coverage claim in §12.1 that is false;
**Low** — reason-code, framing or robustness readings that differ without
changing admission, or coverage gaps behind clear prose.

### Defect 1 — A carriage return inside a comment line: comment rule vs error-character rule *(severity: High)*

**Prose.** §9.1, the grammar table: "comments — a line whose **first
character other than ASCII space or tab** is `#` is ignored **in its
entirety**"; two rows later: "field separators — … Three other characters are
an **error** anywhere in a line — `0x0B` (`\v`), `0x0C` (`\f`) and `0x0D`
(`\r`) — not a separator and not content. … It is closed because a `policy`
entry's text is replayed (§5.1), so a character one reader refuses and
another keeps is a `decode` on one node and a new quorum on the other."

**Evidence (VERIFIED).** Both readings pass 553/553 (`PolicyErrCharsIgnoredInComments`
survives the sweep; the six error-character vectors put the character between
fields or inside a URL, never in a comment). `TestDemoPolicyCommentCR` forges
a `policy` entry, signed by `root1`–`root3`, whose text is the trust policy
with the quorum raised to 3 and a first line `# raised quorum\r`. Appended to
the 129-entry log: the error-anywhere reader records `{129, decode}` and keeps
the old policy; the comment-ignored reader accepts it and replaces the policy.
The two `state.json` differ, and from the next checkpoint one node requires
three cosignatures and the other two.

**Why it matters.** It is precisely the disagreement the paragraph says the
closed set exists to prevent, and CRLF line endings in a hand-edited policy
are the most likely way for a `\r` to reach a comment line.

**Fix.** One sentence: "The three characters are an error in every line,
**including** comment and blank lines, which are tested for them before
being ignored." Ship `policies/bad-carriage-return-in-comment.txt` (and
`-in-blank-line`).

### Defect 2 — "A witness the policy names" is not defined for a witness no quorum reaches *(severity: Medium)*

**Prose.** §10: "verify witness policy: every cosignature LINE naming a
witness the policy names must verify … A line naming anyone the policy does
NOT list is IGNORED". §9.1: "The `witness` directive is matched on its own
`<name>`".

**Evidence (VERIFIED).** `NamedMeansReachableFromQuorum` survives the sweep
(every shipped witness is in `group home`). `TestDemoUnreachableWitness`
adds `witness stranger <stranger's real key>` to the trust policy without
adding it to any group, then serves `served/checkpoint` plus a line under
`norn-witness/stranger` with the stranger's key id and a zero signature. The
"every witness line" reader refuses the head (`cosignature-invalid`); the
"reachable from quorum" reader accepts it.

**Why it matters.** Accept/refuse of a legal head differs between conforming
nodes. §10's own argument ("the other reading hands anyone a veto") applies
to a witness listed but unused — it holds a listed key, so it is not "anyone",
but nothing in the policy requires its cosignature either.

**Fix.** Define it: "the policy names a witness when it carries a `witness`
directive for it, whether or not any `group` or the `quorum` line uses it."
Ship a policy with an unused witness and a head carrying its bad line.

### Defect 3 — `T` for one checkpoint depends on which policy the node holds *(severity: Medium)*

**Prose.** §5.3: "`T` is the quorum time of the checkpoint the state was
replayed from: the newest instant such that the witnesses whose cosignature
timestamp is at or after it satisfy the policy (§9)". §9.4: "A `policy`
entry supersedes `norn.trust.policy` for every checkpoint a node accepts
after replaying it, and for §5.3's `T`."

**Evidence (VERIFIED).** `served/checkpoint`'s three cosignatures are at
1760003600 (pi), 1760003607 (vps), 1760003614 (friend). Under the trust
file's `group home 2 …` the newest instant two witnesses vouch for is
1760003607 — the value `proofs/cases.json` pins. Under the policy replayed
from `49-policy-rotated` (`3` of the same three) it is 1760003600.
`TestDemoQuorumTimeDependsOnHistory` computes both with my verifier. A node
that bootstrapped from `trust.cbor` accepts this head under 2-of-3 and gets
607; a node that already held `detect/current.checkpoint` (which contains
entry 49) verifies the same head under 3-of-3 and gets 600. A device with
`expires` in (1760003600, 1760003607] is admitted by the second node and
refused by the first.

**Why it matters.** §5.3 goes to lengths to make the state identical on every
node; `T` is the one input to admission that is not, and the difference is
not a clock error but a design consequence nobody wrote down. The suite pins
only the trust-only value.

**Fix.** State which policy computes `T` for a head: the one the head was
*accepted under* (matches the suite) or the one in force after replay
(matches §9.4's sentence). Then add the informed reader's `T` for
`served/checkpoint` to `proofs/cases.json` so both are pinned.

### Defect 4 — RFC 6962 consistency verification is never exercised at a power-of-two size *(severity: Medium)*

**Prose.** §11.1 `proof`: "RFC 6962 §2.1.2 consistency proof … the
algorithm is not restated here and a reader implementing their own ordering
will reject sound evidence."

**Evidence (VERIFIED).** The only shipped evidence is at size 40; the
`detect/` forks compare at 40 and 41; nothing has `first` a power of two,
where §2.1.2's step 1 prepends `first_hash` to the path. A reader that omits
that step (`ConsistencyNoPow2Prepend`) passes 553/553.
`TestDemoConsistencyPowerOfTwo` forges a conflicting head at size 64 (entry
63 altered; signed by `logkey`, cosigned by pi and vps from `keys.json`)
and builds evidence from the honest 129 branch: the correct reader concludes
a fork; the step-1-less reader reports "consistency proof does not chain"
and — under §11 — never raises the alarm. File: `demo-fork-at-64.evidence.cbor`.

**Why it matters.** A reader with this bug accepts every shipped vector and
silently fails to conclude forks at sizes 1, 2, 4 … 128, 256 …; the spec's
own warning names exactly this failure and the suite cannot see it.

**Fix.** Ship one more evidence file at a power-of-two `size` (64 or 128 fit
the 129-entry fixture), and say in §11.1 that the shipped sizes exercise
step 1.

### Defect 5 — Evidence for a fork on the longer branch cannot be written as §11.1 describes `held` *(severity: Medium)*

**Prose.** §11.1: "`held` — the signed checkpoint the accuser was holding —
the branch it can speak for, because it has the entries"; "`size` — the
**conflicting** head's size"; step 2: "check `size` is not above `held`'s own
size". §11 rule 1: "write both checkpoints and the failed proof".

**Evidence (VERIFIED).** `TestDemoForkOnALongerBranch`: a node holding
`detect/fork-shorter/checkpoint` (41 entries, its own tiles) is offered
`served/checkpoint` (129). §10 correctly says FORK at size 41. The literal
evidence — `held` = the 41-entry head, `conflicting` = the served 129 head,
`size` = 129 — violates step 2 and needs a `held_root` at 129 the accuser's
branch does not have. The only writable file has `held` = the *served* head
(whose entries the node just fetched) and `conflicting` = the head it was
holding; that file verifies under my §11.1 reader.

**Why it matters.** §10's loop always fetches the served entries, so the
swap is always possible — but a node written to the letter writes nothing,
or writes a file every reader refuses, in the case that "looks like a
growing log". The reader side of §11.1 is unaffected.

**Fix.** Reword `held`: "the head of the branch whose entries the accuser
holds — its stored head, or the served head it fetched — whichever reaches
`size`"; add a `detect/` case where the fork is on the longer branch and the
node writes evidence.

### Defect 6 — `requests-bad/excess-padding` is refused by §4.0, not by §16.2's padding rule *(severity: Low)*

**Prose.** §16.2: "A decoder MUST reject a payload whose padding is 5 bits
or more"; §12.1: "`requests-bad/excess-padding` and `non-zero-padding`: the
payload is the valid request with its encoding corrupted, so only §16.2
refuses them."

**Evidence (VERIFIED).** `req-minimal.cbor` is 204 bytes = 1632 bits = 327
five-bit groups with 3 padding bits. `excess-padding.txt` is one group longer
(339 vs 338 characters): 328 groups = 1640 bits = 205 bytes with **zero**
leftover bits. Any 5→8 regrouping yields the valid request plus one `0x00`
byte and sees no padding at all; the file is refused because the CBOR item
is followed by a byte (`profile/trailing`). My first run reported exactly
that. Only when the original padding is ≤ 2 bits does adding a group leave
5–7 visible padding bits.

**Why it matters.** The claim that the padding rule is what refuses this file
is false, and the rule as written ("5 bits or more") is unobservable on the
boundary. A reader with no padding check at all passes the suite for this
file. The whole-input rule is what protects it — worth saying.

**Fix.** Build the vector from a request whose natural padding is ≤ 2 bits
(any length ≡ 1, 3 or 4 mod 5 … i.e. 8n mod 5 ∈ {1,2}), or state the rule as
BIP-173 does ("the incomplete group MUST be four bits or fewer, and zero")
and note that an excess on a byte boundary is caught by §4.0.

### Defect 7 — `fork/bad-open-schema` does not isolate the closed-schema rule *(severity: Low)*

**Prose.** §12.1: "For evidence: `fork/bad-open-schema`, `bad-wrong-version`
and `bad-size-above-held` … **This implementation left the evidence map
open** … until run 8 asked."

**Evidence (VERIFIED).** Decoded without the schema rule, the file is
`held` = the honest 129 head, `conflicting` = the honest 119 head, `size` =
119, `held_root` = the honest root at 119, plus a key `surprise`. An
open-schema reader refuses it at step 4 ("a log and its own earlier self").
`TestDemoBadOpenSchemaIsNotAFork` prints the fields. The sweep flags the
catch as hint-only.

**Fix.** Rebuild it from `evidence.cbor` (a real fork) plus the extra key, so
that only the schema can refuse it — as `proofs-bad/open-schema` already
does for bundles (that one is pinned by accept/refuse).

### Defect 8 — Signature-line base64 with non-zero padding bits is not addressed *(severity: Low)*

**Prose.** §7: "The payload is **standard base64 with padding** (RFC 4648 §4
…); unpadded base64 decodes to the same bytes and is not this encoding." For
the receipt's leaf line, by contrast: "with zero padding bits".

**Evidence (VERIFIED).** `TestDemoNoteB64PadBits` flips one padding bit in
the last data character of a cosignature line of `served/checkpoint`. A
strict decoder refuses the note; a lax one (`NoteB64LaxPadBits`) decodes the
same 76 bytes and accepts the head. Both readers pass the suite.

**Why it matters.** §7 spends a paragraph on why one head must have one byte
form ("everything keyed on them … is keyed on something an attacker
chooses"); this is a second spelling it left open.

**Fix.** Add "with zero padding bits" to the signature-line sentence and ship
`checkpoints-bad/24-signature-non-canonical-pad-bits`.

### Defect 9 — §5.1 step 3 does not list the envelope field types *(severity: Low)*

**Prose.** Step 3: "Envelope check per §4.1: exactly the permitted keys, `v`
= 1, `net` = `anchor.net`, well-formed `sigs` → on failure reject (`decode`)."
Step 4: "`t` not in §4.3 → reject (`unknown-type`)."

**Evidence (VERIFIED).** An entry with `t: 5` (a uint) is `decode` to a reader
that checks every field's §4.1 type at step 3 and `unknown-type` to one that
checks only what step 3 lists (`EnvelopeTypeChecksDeferred` survives). Both
reject; `state.json` differs. `TestDemoEnvelopeTypeReason`.

**Fix.** "…exactly the permitted keys, each of the type §4.1 gives it, …".

### Defect 10 — Five smaller holes in the restated policy grammar *(severity: Low)*

All VERIFIED as reader disagreements by `TestDemoPolicyGrammarGaps`; each
turns a `policy` entry into `decode` on one node and a replaced policy on
the other.
- **Namespaces.** "each `witness` and `group` name is defined once" — one
  namespace or two? `witness pi …` then `group pi 1 pi` parses under two, and
  `quorum pi` is then ambiguous.
- **Forward reference from `quorum`.** "previously defined" is said of group
  members only; `quorum pi` before `witness pi` is accepted by a
  resolve-at-end reader and refused by a sequential one.
- **`none` as a definable name.** "the reserved name `none`" — reserved from
  definition, or only special in `quorum`?
- **Trailing separators.** "fields are separated by … in runs" — a reader
  that makes a trailing run produce an empty field refuses `witness pi k `.
- **Parseability of vkeys.** The grammar row "keys — compared as the `vkey`
  text" implies no parse; a reader that parses each vkey refuses a policy
  entry with a malformed key that the other keeps — after which the
  malformed witness can never match a line, and the quorum may be unmeetable.

**Fix.** One sentence each; the first and fifth are the ones that change a
quorum.

### Defect 11 — Under `quorum none` (or any head with no clock) §8.1 condition 4 is undecidable and admission is unstated *(severity: Low; inferred from prose)*

**Prose.** §5.3: under `quorum none` "there is no clock". §8.1 condition 4:
"the checkpoint is not stale: `elapsed > params.staleness` makes it so",
with `elapsed` measured from "when it learned this checkpoint's quorum
time". Freshness table: `unknown` — "no witness has vouched for any instant,
so there is no `elapsed` to measure … MUST NOT report `fresh`".

**Evidence.** Not runnable — the prose says what to *report* (`unknown`)
and never says whether a peer behind an `unknown` head is proven. §9.4
explicitly allows the roots to lower the quorum to `none`, so this is a
reachable state. My implementation admits the peers (condition 4 has no
value to fail on); a reader that treats "not fresh" as "stale" drops every
peer the moment the roots publish `quorum none`.

**Fix.** One sentence under condition 4: "With no quorum time there is no
`elapsed`; condition 4 is then vacuously met / then fails" — either, stated.

### Defect 12 — §8.1 condition 2 has no procedure when the bundle's head is newer than the stored one *(severity: Low; inferred)*

**Prose.** "the bundle's checkpoint is consistent with the node's stored
checkpoint". A bundle carries an inclusion proof and no consistency proof.

**Evidence.** For a bundle head at or below the stored size the node can
compare its own root; above it, it has nothing to compare unless it fetches
that branch's entries — which the prose does not ask for here. Not vectored
(every bundle carries `served/checkpoint`, the stored head itself).

**Fix.** Say "consistent, by §10's stored-checkpoint block, which may require
fetching the served entries" or restrict bundles to the stored head.

### Defect 13 — Coverage gaps behind clear prose *(severity: Low, listed once)*

The eleven readings in §3.1's second group. The two worth a file each:
`genesis` with `after: 0` (accepted by the prose; a reader that refuses it
aborts a whole log), and a bundle with a trailing byte (the "exactly"
rule). The rest are one hostile input each.

### Defect 14 — `bad-trailing-comment` is refused by a reader that strips trailing comments, if it also refuses trailing whitespace *(severity: Low)*

**Prose.** §9.1: "a `#` anywhere else in a line is **an ordinary character**,
not the start of a trailing comment. So … `quorum pi # note` is a `quorum`
line with two names — refused by the field count below, not read as
`quorum pi`."

**Evidence (VERIFIED).** The composite `PolicyHashIsTrailingComment` +
`PolicyTrailingSpaceIsError` passes 553/553: the vector's `# note` is
preceded by a space, so a reader that strips from `#` is left with
`quorum pi ` and, treating the trailing run as an empty field, refuses it
for the field count — the rule the case is named for. That reader accepts
`quorum pi#note` (`TestDemoCompositeTrailingComment`), which the spec
refuses because `pi#note` is one undefined name.

**Why it matters.** Low: a policy accepted by one node and `decode` on
another, but only a policy nobody would write on purpose. It is the one
composite of two readings the suite caught separately that passes it
together.

**Fix.** Ship `bad-trailing-comment-no-space.txt` (`quorum pi#note`), which
no comment-stripping reader survives.

## 5. Every decision the prose did not make for me

The pre-vector log is `DECISIONS-I-HAD-TO-MAKE.md` (with an outcomes
section). Grouped, in finished form:

**Encoding profile.** Integers above 2^63−1 refused even in shortest form
(confirmed). Booleans decoded anywhere, refused by the schema where a uint
belongs. UTF-8 = RFC 3629 (surrogates refused; unseparated). Map keys 1–23
bytes in every map, including labels and params (upper bound confirmed,
lower unseparated). Depth counts containers, top level = 1, ≤ 8; a request's
depth restarts (confirmed). Size cap checked on the raw length first, then
any declared length beyond the remaining input is `truncated` (confirmed).
Shortest form for every head argument (confirmed). Strict increase of encoded
keys is one comparison (confirmed).

**Entries.** Step 3 checks each envelope field's type (unseparated — Defect
9). A `genesis` at index > 0 is `dup-genesis` without looking at its body.
Governance: threshold before any body check (confirmed). Signatures of a role
the entry does not need are ignored. A `rotate` whose incoming key equals the
current one needs one signature (edge, untested). `log_key` may repeat a key
(untested). A `policy` entry is grammar-checked only (unseparated — Defect
10). `revoke.reason`, `note.text` may be empty (confirmed). `enroll` order:
closed body · request structure · request `net` · request signature ·
signers · `dup-id` · `dup-wg` (confirmed; my first build had the middle two
swapped). A device-role line on an `enroll` envelope is neither required nor
counted. `dup-wg` on `rotate` excludes the device's own key (confirmed).
Removed root may sign its own removal (untested).

**Genesis.** Body closed; `roots`/`signers` distinct and disjoint; thresholds
in range; `params` non-empty with §4.5 types; bootstrap counts `root` lines
resolving in `body.roots` only (confirmed by 18/19). `after: 0` accepted
(unseparated). Zero state and empty log as §5.1 says (confirmed).

**State/JSON.** Exactly §5.3's names; §14's order and escaping; mirrors
built from the generic CBOR value (all byte-identical).

**Trust.** Closed maps at every level; `anchor` all-or-nothing; `mode` must be
`advisory`, `type` free; origin by encoding `net`; key ids recomputed and
compared as lowercase text; log key alg 0x01 and name == origin byte for
byte; witness keys alg 0x04; names 1–64 bytes and unique; correspondence on
the set of (name, key) pairs; every `log` line == `log_key`; cap 65536
inclusive (all confirmed). Key names may not contain a space or newline
(unseparated). Witness `url` unconstrained (unseparated).

**Policy grammar.** Error characters checked before comment/blank
classification (unseparated — Defect 1). One namespace for witness and
group names; `none` reserved; `quorum` resolved at end of file; trailing
separator runs ignored; vkeys not parsed (all unseparated — Defect 10).
Everything else confirmed by `policies/`.

**Notes.** First blank line ends the text; each line `— name payload\n`;
split at the first space; padded standard base64 with zero padding bits
(unseparated — Defect 8); every payload 68 or 76 bytes (matched lines
exact; unknown lines unseparated); a line is a key's iff name **and** id
match (confirmed three ways); all matched lines verify and at least one
log line exists (confirmed).

**Checkpoints / loop.** Three lines, canonical size, 44-char root; origin
byte for byte; published log keys are `(origin, 0x01, pk)` and are kept
alongside the trust key (confirmed by `served-rotated`); every `witness`
line's witness is "named" (unseparated — Defect 2); `T` = newest instant
whose ≥-set satisfies the policy, each witness at its newest verifying line
(confirmed); no clock under `quorum none` or when unsatisfiable. Stored
block: fork check before the size rule, roots recomputed from entries, no
accusation without the held branch (confirmed). All tiles implied by the size
are compared (confirmed). Freshness ladder in the written order (confirmed).
Under `unknown` the proven set is not gated (Defect 11).

**Receipts.** Four exact lines, deadline canonical uint64, leaf 44 chars
strict (all confirmed).

**Bundles.** Six closed keys, `v` 1, `index < size`, proof elements 32 bytes,
cap 81919; checkpoint per §10 under the reader's own policy; the entry is
decoded, not signature-checked, to find its device; `rotate`/`revoke` entries
allowed (unseparated); the installed key is replay's (confirmed by `nas`).

**Evidence.** Seven closed keys, cap 65536, reader's policy only, `size ≤
held.size`, proof empty at `held.size`, RFC 6962 §2.1.2 otherwise, fork iff
roots differ (all confirmed except the power-of-two path — Defect 4). The
writer swaps roles when the served branch is longer (Defect 5).

**Requests.** All field rules; `expires > ts` strict; empty `labels` map
allowed (unseparated); standalone `net` uncompared; bech32m with HRP folding
for an all-uppercase string, mixed case refused, constant 0x2bc830a3, padding
< 5 bits and zero (confirmed except excess-padding — Defect 6).

**Evaluation.** Expired iff `expires != 0 && expires <= T` (confirmed at the
boundary); no clock → nothing expires (confirmed).

## 6. What I could not cover, and why

- **OpenTimestamps.** I checked the stated digest against the stated byte
  range and that the digest bytes occur inside each `.ots` file; I did not
  parse the container (the document does not describe it and forbids fetching
  the format).
- **The witness HTTP protocol, gossip, enforcement, `ENROLLMENT.md`,
  `GOSSIP.md`, `ENFORCEMENT.md`.** Referenced, not shipped, not vectored.
- **`quorum none` accepting an uncosigned head.** Needs a second trust anchor
  the suite does not ship (declared); I did not forge one because the
  interesting question there is Defect 11, which no anchor would settle.
- **Log-operator behaviour** (`/add`, 409 codes, checkpoint cadence,
  `overlap` as an obligation on the log): not verifiable from a static suite.
- **Monotonic-clock behaviour** in condition 4: I implemented the ladder as a
  pure function of `elapsed`; whether a real node's `elapsed` is measured
  correctly is outside a vector's reach.
- **Interop with `golang.org/x/mod/sumdb/note` and `transparency-dev`
  libraries**: forbidden here (standard library only); the spec claims the
  shipped notes open under them, and I have no reason to doubt it since my
  independently written parser opens the same bytes.
- **Pair sweep coverage**: pairs among the 33 survivors were not run (two
  readings the suite cannot see separately cannot be rescued together).

## 7. Closing assessment

This is a very good specification with a very good suite. A cold reader
reproduced every byte and every refusal, and 95 of 128 alternative readings
were caught — most by accept/refuse, several by more than one file, and the
declared holes in §12.1 are exactly the holes. What is left is small and
precise: two grammar/verification sentences that can be read two ways with
consequences for the quorum (Defects 1, 2), one design consequence about `T`
that is true and unwritten (3), one RFC path the suite never walks (4), one
evidence-writer case the format cannot express as described (5), and a
handful of Low items that are a sentence each. Fix the first five and add
the five files they call for, and this document meets its own bar.

**Five things I would ask the authors not to break:**

1. **The reason-code precedence table in §5.1 and the fact that the suite
   pins it** (`99`–`103`, the two `threshold-before-dup-*`, `109`–`111`).
   It is what makes `state.json` a byte contract rather than a description.
2. **"Name AND key id" for every signature line, with the three
   `served-*-collision` heads.** The veto argument in §10 is the best
   paragraph in the document; the vectors make it unforgettable.
3. **`served-rotated` and `served-superseded` having two correct answers,
   stated as such.** It is the only honest way to vector §9.4, and it caught
   my "either policy will do" reading immediately.
4. **The at-the-cap positives in non-ASCII** (`name-at-the-cap`,
   `req-label-at-the-cap`, the 4096-byte policy). Every "count bytes"
   sentence would be prose without them.
5. **The `detect/` pairs, with `fork-on-a-shorter-branch` before the size
   rule.** It is the one place where the order of two checks decides whether
   an alarm is raised, and the suite sees it.
