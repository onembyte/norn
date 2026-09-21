# Norn v1 — adversarial specification review

Independent Go implementation (standard library only: own CBOR codec, canonical
JSON, signed-note parser, Merkle/RFC-6962 proofs, tlog-policy parser, bech32m,
RFC 4648 and Crockford base32, tlog-tiles reader, replay engine). Built from
`SPEC.md` and `vectors/` inside the sealed directory and nothing else. Sources
in `work/norn/` and `work/cmd/suite/`; sweep logs in `work/sweepF.txt` and
`work/compF.txt`.

## 1. Verdict

**SPEC INSUFFICIENT.**

Not because I failed the suite — I pass all of it — but because there are five
places where a competent second implementer, reading only this document, would
build something the shipped vectors **reject**, and one place where the document
**contradicts its own vectors**. Those are not coverage gaps; they are
behaviours the conformance suite requires and the normative text never states.
On top of that, 52 single-switch variant implementations and 9 two-switch
combinations pass the entire suite while disagreeing with mine, and the
specification admits to only about a dozen of those.

## 2. Check tally

| | |
|---|---|
| Named checks run | **236** |
| Passed | **236** |
| Failed | **0** |
| SHA256SUMS | verifies — 507 files, none missing, none extra, none mismatched |
| Single-switch variants | **208** (52 still pass) |
| Multi-switch composites | **50** (9 still pass) |

Breakdown: trust-bad 38, requests-bad 25, policies 19 (incl. `evaluate` quorum
tables), entries-hostile 19, genesis 18, checkpoints-bad 17 (16 files + the
`signature_blind_accepts` arithmetic), entries 16, fork 14, requests 10,
proofs-bad 9, staleness 7, proofs 6, detect 5, served 4 + served-{rotated 3,
bad 3, superseded 2, extra-witness 1, twice-cosigned 1}, proven 4, trust-good 3,
log 2 (124 reason codes + 82 `.reason` files), plus `state.json`, `log-empty`,
`trust.cbor`, `trust.toml`, the TOML->CBOR byte-for-byte round trip,
`trust.fingerprint`, `receipt.note`, the §2 origin derivation, the §6
OpenTimestamps body digest, SHA256SUMS, and three limit-boundary assertions.

For every negative I confirmed the refusal is the one it is named for by turning
off exactly that check in a variant and watching that vector — and only that
vector — start passing.

## 3. Defects

### D1 — §5.1 entry 0 step 6 and `genesis/17-params-empty` disagree

Prose: "Body checks: `roots` and `signers` are non-empty arrays ...; `params`,
if present, has only §4.5 keys."  An empty map trivially has only §4.5 keys, so
the literal reading **accepts** `genesis/17-params-empty` and replays the log;
the vector requires `bad-genesis` and the zero state.

Evidence: I implemented the literal reading first and this was the one vector in
the suite I failed. Variant `V67b_GenesisParamsMayBeEmpty` restores it and fails
exactly that vector. §12.1 steers a reader wrong here too: "The same **key** rule
at entry 0 is `genesis/13-params-unknown-key`" — but non-emptiness transfers as
well and nothing says so.

Fix: step 6 should end "...`params`, if present, is **non-empty**, has only §4.5
keys, and each value has the §4.5 type" — the same three conditions §5.1's
`params` type rule imposes.

### D2 — §7 never requires the signature block to be newline-terminated

Prose: "The text is followed by one blank line, then one signature line per
signer."  Nothing says a signature line ends in 0x0A, and §7 claims the framing
is "restated here so an implementer needs nothing else (D22)".

Vector: `checkpoints-bad/14-unterminated-signature-block` is byte-identical to
`served/checkpoint` minus the final 0x0A (591 vs 590 bytes) and MUST be refused.

Evidence: `V81_NoFinalNewline` fails that one vector and nothing else, so it is
the only rule that can refuse the file — and the document does not contain it.
(A reader who ignores D22 and reads `x/mod/sumdb/note`, which §7 names, gets it
right; the restatement is what is incomplete.)

Fix: "Every signature line, including the last, ends in one 0x0A."

### D3 — no normative section states that the checkpoint size line is canonical decimal

Prose: §6 defers the checkpoint to `c2sp.org/tlog-checkpoint`; §7 restates the
note framing and says nothing about the body's three lines. "canonical decimal"
appears in SPEC.md only in §9.1 (policy group thresholds) and in §12.1's
**coverage table**, which attributes the rule to "§7 the note framing".

Vector: `checkpoints-bad/15-size-leading-zero` has body line 2 = `0124`,
correctly re-signed by the log and all three witnesses over honest tiles. A
reader that parses it as 124 rebuilds the same root and accepts.

Evidence: `V82_SizeLeadingZero` fails that one vector and nothing else.

Fix: §6 should spell out the three body lines — origin, size as canonical
decimal, root as standard base64 of 32 bytes — or §12.1 should attribute the
rule to `c2sp.org/tlog-checkpoint` rather than to §7.

### D4 — nothing requires *every* line naming the log key to verify

Prose: §10 says only "verify log signature (torchwood VerifyCheckpoint)"; §7
describes what *a* signature line is, never what a *block* must satisfy. The
nearest thing is a pseudocode comment: "The log's own signature line may appear
anywhere in the block; order carries nothing."

Vector: `checkpoints-bad/16-two-log-signatures` is `served/checkpoint` plus a
fifth line under the log's own name and key id that does not verify.

Evidence: `V83_FirstValidLogSig` fails that one vector and nothing else. The
canonical implementation §7 names, `x/mod/sumdb/note`, does not impose this rule
either — it fails a note only when *no* known verifier's signature opens it. And
§12.1 records the provenance: "**This implementation accepted the last two**
until run 8 asked for them". The rule entered through a vector, not the prose.

Fix: §10 step 1 — "Every signature line whose name and key id match a trusted log
key MUST verify; at least one such line MUST be present."

### D5 — §8.1's checking procedure never binds `device` to `entry`

Prose: "Checking a bundle: verify its checkpoint per §10 ... then confirm
SHA-256(0x00 || entry) and proof reach that checkpoint's root at index for that
size, and apply the rules below."  "The rules below" are §8's conditions 1-4,
and condition 3 needs the whole log — which the self-contained bundle does not
carry. The only textual hook is the table gloss "`device` | text | the
`device_id` this bundle proves".

Vector: `proofs-bad/device-not-in-entry` — checkpoint, entry and proof all
honest, only the `device` label is another device's — MUST be refused.

Evidence: `V132_NoDeviceBinding` fails that one vector and nothing else. **I
inferred this rule from the vector's filename and its `says` string, not from the
document** — stating that explicitly because it is reverse-engineering, not
conformance. §12.1 confirms: "This implementation left the evidence map open and
the device unbound until run 8 asked".

Fix: add to §8.1's checking sentence "...and confirm that `device` is the
`device_id` the `entry` names (for an `enroll`, the id inside the embedded
request)."

### D6 — §12 makes a false arithmetic claim about its own vectors

Prose (§12 file table): "`cases.json` lists them and says **which two** a
signature-blind verifier accepts".

Vectors: `checkpoints-bad/cases.json`'s `signature_blind_accepts` lists **five**
(04, 08, 11, 12, 16); `vectors/README.md` also says five and names them.

Evidence: I ran my verifier with every Ed25519 check forced to succeed over all
sixteen files. It accepts exactly those five and refuses the other eleven. The
JSON and the README are right; §12 is wrong. Fix: "which five".

### D7 — §4.0 requires shortest form only of *integers*, not of length headers

Prose: "Integers | major type 0 only; shortest form; <= 2^63-1."  Byte strings,
text strings, arrays and maps get only "definite length". RFC 8949 §4.2.1, which
§4.0 names, requires preferred serialization of every argument — but the table is
what a reader implements from, and it enumerates rules field by field.

Evidence: `V01_LenNotShortest` — integers shortest, length headers not — passes
all 236 checks. The only vector, `log/64-bad-cbor-nonshortest`, patches an
*integer* (`av 18 01`), so it cannot separate the readings.

Why it is worse than incompatibility: under the lax reading one logical entry has
several legal encodings. `entry_hash` and the leaf hash are over the bytes as
received, so two encodings of one governance entry are two distinct leaves that
both replay — bypassing the `dup-entry` defence that §4.0's whole-input rule
exists to protect, by a different route.

Fix: "Integers, and every other argument — byte-string, text-string, array and
map lengths — use the shortest form", plus a vector patching a length header.

### D8 — "keys sorted" and "no duplicate keys" each mask the other

Prose (§4.0): "Maps | definite length; keys sorted as §4.1; no duplicate keys".
§4.1 says "bytewise lexicographic order of their encoded form" — it does not say
*strictly* increasing.

Evidence: the only duplicate-key vector, `log/74-bad-duplicate-map-key`, carries
`"v":1` twice, adjacently (necessarily, since the map is otherwise sorted). So
`V16_NoDupKeyCheck` passes 236/236 (strict sorting refuses it), and
`V200_SortNonDecreasing` passes 236/236 (the duplicate rule refuses it), and the
two **together** are caught. A reader who reads "sorted" as non-decreasing *and*
implements duplicates as last-key-wins — common CBOR decoder behaviour — accepts
a duplicated key.

Fix: "keys **strictly increasing** in §4.1's order"; the no-duplicates rule then
follows rather than being a second test.

### D9 — §9.1's policy grammar never bounds a directive's field count, and that unstated rule is what actually refuses the whitespace vectors

Prose: "field separators | ASCII space and tab **only**, in runs. Any other
whitespace character anywhere in a line — \r, \v, \f — is an **error**."

Evidence: `V112_AnyWhitespaceSep` — the reading §9.1 explicitly forbids — passes
all 236 checks. Both vectors put the stray character inside an optional URL
(`https://example/\vw`), so a reader that treats \v as a separator sees a
five-field `witness` line and refuses it for *arity*. Arity is stated nowhere.
`V208_PolicyExtraFields` also passes 236/236 alone; `V112 + V208` is caught.

So the grammar's most emphatic rule is pinned only by a rule the grammar does
not contain.

Fix: add "field count | a directive with more fields than its production allows
is an error", and move the stray whitespace somewhere a reader cannot absorb it
(e.g. `quorum\vpi`).

### D10 — §9.1's comment rule is ambiguous about tabs and about `#` after fields

Prose: "a line whose first non-space character is `#` is ignored."  Every other
rule in that table says "ASCII space and tab"; this one says "non-space".

Evidence, three ways, each passing 236/236:
`V210_PolicyCommentSpaceOnly` (only U+0020 counts, so a tab-indented `#` line is
a directive); `V209_PolicyTrailingHash` (strip from the first `#` anywhere);
`V209 + V110_CommentsNotAllowed` (no leading-`#` rule at all, only
strip-from-`#`, which turns a comment line into a blank one).

The three readings differ on the first policy whose witness URL carries a
fragment: `witness pi <key> https://w.example/#tag`.

Fix: "a line whose first character other than ASCII space or tab is `#` is
ignored in its entirety; a `#` anywhere else in a line is an ordinary
character", plus a vector with a `#` inside a URL.

### D11 — two of the three §6/§10 checks on a served log are individually unpinned

Prose (§6): "A verifier rebuilds the tree from the entry bundles and compares its
head with the signed checkpoint ... The served tile/<L>/... hashes MUST also
agree ... checking them is not optional."  (§10): "served := the root the SERVED
branch has at `at` # recomputed from the entries, never from a supplied proof".

Evidence:
- `V154_NoRebuild` passes 236/236: `served-bad/tampered-entry-bundle` changes one
  byte of one entry, which also changes its leaf hash, so the hash-tile rule
  refuses it first. `V153 + V154` is caught. Only one of the two §6 rules is
  load-bearing for any shipped file.
- `V152_ServedFromProof` passes 236/236: no vector supplies a proof.
- `V207_CPRootAnyLen + V154_NoRebuild` passes 236/236 — a reader with neither
  rule accepts a checkpoint whose root line decodes to something other than 32
  bytes. No section bounds the root line.

Fix: ship a `served-bad` case where entry bundle and level-0 tile are tampered
*consistently*; state the root line's length; mark §10's "never from a supplied
proof" clause unvectored.

### D12 — normative rules no artifact can reach (dead normative text)

Each verified by a variant that deletes the rule and still passes 236/236.

| rule | where | why unreachable | variant |
|---|---|---|---|
| "a key contributes at most once" | §4.3 | `sigs` is sorted and unique by `kid`, and `kid` is injective in `pk` | V44 |
| "only a cosignature that verifies contributes a timestamp ... even in the moment before that refusal" | §5.3 | §10 refuses the checkpoint over that line, so no `T` is produced | V73 |
| "Entry 0 (genesis). **In order:**" | §5.1 | every entry-0 failure is `bad-genesis`; §5.1's own justification ("the first matching step decides the reason code") does not apply | V212 |
| `origin` == norn/ + base32(net) | §9.1 | masked by the log-key note-name rule | V90 |
| log key's note name == `origin` | §9.1 | masked by the origin rule and the policy log-line rule | V93 |
| `log_key` MUST NOT be a cosignature key | §9.1 | `trust-bad/16` is refused by the policy log-line rule | V92 |
| witness key algorithm checked at verification | §10 | spec admits | V222 |
| `root_remove` leaves ">= 1 root" | §4.3 | spec admits ("implied, not a second test") | V60 |

`V90`/`V93` is the sharpest pair: two separate §9.1 MUSTs, each deletable with no
observable effect; only deleting **both** lets `trust-bad/04-origin-mismatch`
through. §12.1 counts 04 among its 38 refusals without noting it is
over-determined.

### D13 — §7's note framing leaves three splits undecided

All pass 236/236: `V203_NoteTextLastBlank` (the text ends at the *last* blank
line); `V202_NoteSplitLastSpace` (split the line on its last space);
`V204_NoteRawBase64` (unpadded base64); `V206_NoteSigLenLoose` (accept a payload
longer than 68/76 and verify the prefix); `V205_NoteNoLinesOK` (require >= 1
signature line).

`V206` has teeth: it accepts trailing bytes inside a signature line's base64, so
a checkpoint has unboundedly many byte-distinct forms that all verify. §7 gives
the two payload lengths and never says another length is invalid.

Fix: "a note's text lines are non-empty, so the first blank line ends the text; a
key name contains no space; the base64 is standard with padding; the decoded
payload is **exactly** 68 bytes for algorithm 0x01 and **exactly** 76 for 0x04."

### D14 — §5.1's "normative" ordering is not fully observable

The relative order of step 3 (envelope), step 6 (`after`) and step 7 (signature
counting) is unpinned: `V213_StepAfterBeforeEnvelope` passes 236/236,
`V214_StepThrBeforeAfter` passes 236/236, and the two together still pass. No
vector is both `after`-violating and threshold-violating, or both
`after`-violating and envelope-violating. §12.1's five deliberate "wrong in both
of its two ways at once" vectors cover other pairs.

Fix: ship the two missing pairs, or record the orderings as unvectored.

### D15 — §5.1 entry 0 step 7's "the roots in its own body" is not pinned

`V216_GenesisCountSigners` (bootstrap-resolve a `role: "root"` signature against
the body's `signers` as well as its `roots`) passes 236/236.
`genesis/18-bootstrap-sigs-wrong-role` varies the `role` **string**, not the key
**set**. Since genesis requires the two disjoint, this is a real difference: a
genesis signed only by `signers` declaring `role: "root"` is a valid network
under one reading and `bad-genesis` under the other.

### D16 — "a line naming a witness the policy names": name alone, or name + key id?

§10 does not say. Given §7's "the algorithm is part of the id" and "the id binds
the name", a line with the right note name and a wrong key id is either not a
line naming a listed witness (ignore it) or it is (refuse the checkpoint).
`V236_CosigNoKeyIDMatch` implements the second and passes 236/236;
`served-extra-witness/` uses a stranger with a different *name*, so it cannot
separate them.

Fix: "a line names a witness the policy lists when **both** its name and its key
id match that witness's verifier key".

## 4. Variant table

208 single-switch variants and 50 composites. A variant that still passes is the
finding. Full logs: `work/sweepF.txt`, `work/compF.txt`.

### 4.1 The 52 singles that still pass all 236 checks

| variant | reading | spec admits? |
|---|---|---|
| V01_LenNotShortest | only integers need shortest form | no — D7 |
| V16_NoDupKeyCheck | no duplicate-map-key rule | no — D8 |
| V18_DepthNoRestart | an embedded request's nesting continues the entry's | half |
| V44_KeyCountsTwice | a repeated kid counts once per line | no — D12 |
| V57_DupWgEnrollNarrow | enroll dup-wg means "active for another device" | yes |
| V60_RootRemoveNoOne | root_remove tests only >= root_thr | yes |
| V73_TFromAllLines | an unverified line contributes a timestamp to T | half — D12 |
| V90_NoOriginCheck | no origin <-> net check | no — D12 |
| V92_LogKeyMayBeCosig | log_key may be a cosignature key | no — D12 |
| V93_NoLogKeyNameCheck | log key's note name need not equal origin | no — D12 |
| V95_StrikeOffNames | correspondence as a multiset strike-off | yes |
| V112_AnyWhitespaceSep | \r \v \f also separate policy fields | no — D9 |
| V118_FlattenGroups | flatten nested groups keeping the outer k | no (proper flattening V229 IS caught) |
| V121_QuorumNoneNoClock | quorum none yields a clock | yes |
| V134_NoBundleSizeCap | no MAX_BUNDLE_BYTES | yes |
| V152_ServedFromProof | take the served root from the checkpoint | no — D11 |
| V154_NoRebuild | never compare the rebuilt head with the signed root | no — D11 |
| V162_SinceIndexIsSize | a learned key is usable only once size > since_index | no |
| V200_SortNonDecreasing | "sorted" means non-decreasing | no — D8 |
| V202_NoteSplitLastSpace | split a signature line on its last space | no — D13 |
| V203_NoteTextLastBlank | the note text ends at the last blank line | no — D13 |
| V204_NoteRawBase64 | unpadded base64 accepted | no — D13 |
| V205_NoteNoLinesOK | a note must carry >= 1 signature line | no — D13 |
| V206_NoteSigLenLoose | over-long signature payloads accepted | no — D13 |
| V207_CPRootAnyLen | the root line need not be 32 bytes | no — D11 |
| V208_PolicyExtraFields | ignore fields beyond a production | no — D9 |
| V209_PolicyTrailingHash | # anywhere starts a comment | no — D10 |
| V210_PolicyCommentSpaceOnly | only U+0020 may precede a comment # | no — D10 |
| V211_PolicyNoneShadow | a witness named "none" shadows the reserved name | no |
| V212_GenesisOrderSwap | entry-0 checks in a different order | no — D12 |
| V213_StepAfterBeforeEnvelope | check after before the envelope | no — D14 |
| V214_StepThrBeforeAfter | count signatures before the after guard | no — D14 |
| V216_GenesisCountSigners | bootstrap roots include the body's signers | no — D15 |
| V219_EntryHashCanonical | entry_hash over a re-encoded canonical form | yes |
| V220_NetFromGenesis | state.net from the genesis entry | yes |
| V222_WitnessAlgAtVerify | witness key algorithm re-checked at verification | yes |
| V224_EvidenceSizeFirst | §11.1 step 2 before step 1 | no |
| V225_Bech32FirstSep | the bech32m separator is the first '1' | stated, unvectored |
| V236_CosigNoKeyIDMatch | a cosignature line matched on its name alone | no — D16 |
| V238_ProofNodesAnyLen | a proof element need not be 32 bytes | stated, unvectored |
| V241_EmptyTreeZero | the empty tree's root is 32 zero bytes | not stated at all |
| V244_SizeLineNoDigitsOnly | the size line may carry non-digits | no |
| V245_OriginTrailingSlash | compare origins ignoring a trailing / | no |
| V246_AnchorMaxLagAny | anchor.max_lag may be any type | stated, unvectored |
| V247_TrustPolicyNoParse | the trust file's policy need not parse | no (masked) |
| V248_RotateSameKeyNoPoP | rotate to the same device_pk needs no second signature | no (equivalent) |
| V254_DupKeyByPK | dup-key compares public keys, not kids | no |
| V256_EvidenceHeldNeConflicting | *require* the two evidence checkpoints to differ | stricter reader the suite cannot refute |
| V257_RequestOwnCapOnly | MAX_ENTRY_BYTES applies to the entry, not the request | yes |
| V258_ReceiptOriginUnchecked | do not check the receipt's origin line | no |
| V259_LogURLScheme | *require* log_urls to be http(s) | stricter reader the suite cannot refute |
| V260_PolicyWitnessKeyAlg | *require* the policy's witness keys to be cosig keys | implied by correspondence |

### 4.2 The 9 composites that still pass

V95+V103 (strike-off correspondence AND no uniqueness rule — confirms §12.1's own
admission); V202+V204; V152+V154; V207+V154 (neither rebuild nor root-length, so
a non-32-byte root is accepted); V209+V110; V224+V139; V222+V236; V213+V214
(D14); V210+V208.

### 4.3 Composites that ARE caught — the masking proofs

V90+V93 (-> trust-bad/04), V16+V200 (-> log/74), V112+V208 (->
policies/bad-vertical-tab), V153+V154 (-> served-bad/tampered-entry-bundle),
V92+V102 (-> trust-bad/16), V94+V103 (-> trust-bad/08), V118+V229 (->
policies/nested-group), V247+V94 (-> trust-bad/09), V162+V160 (-> the served
head under the anchor key). Each pair is two rules that each mask the other.

## 5. Every decision the prose did not make for me

Marked **pinned** where a vector happened to decide it for me rather than the
text.

§4.0: (1) shortest form for length headers — not pinned (D7). (2) strict vs
non-strict sorting — not pinned (D8). (3) key cap at the decoder vs per schema —
pinned. (4) key cap in bytes vs characters — pinned. (5) scalars and depth —
pinned (and stated). (6) MAX_ENTRY_BYTES inclusive — pinned. (7) request depth
restart — not pinned. (8) whether the 2^63-1 cap is a decoder or field rule —
unobservable. (9) which of several profile violations a decoder reports —
unobservable (all `decode`).

§4.1/§4.3: (10) a non-string `t` -> `decode` or `unknown-type` — not pinned.
(11) envelope `net` length vs anchor comparison — unobservable. (12) order of
`sigs` element validation vs the sort/unique rule — unobservable. (13) whether a
`rotate` body's `device_id` must match §2's regex — only pinned via requests.

§5.1: (14) order of steps 3/6/7 — not pinned (D14). (15) entry-0 internal order
— unobservable (D12). (16) genesis bootstrap key set — not pinned (D15).
(17) empty genesis params — pinned, and the prose is wrong (D1). (18) params
merge vs replace — pinned. (19) genesis params overlay vs replace — pinned.
(20) log_keys append vs replace — pinned. (21) policy replace vs accumulate —
pinned. (22) rotate and since_index — pinned. (23) re-enrolment replaces the
record wholesale — pinned. (24) size counts consumed vs accepted — pinned.
(25) revoke may not pool counts — pinned. (26) enroll dup-wg scope — not pinned
(admitted). (27) rejected entries join the seen set — pinned. (28) entry 0 joins
the seen set — pinned.

§5.3/§10: (29) expires == T has passed — pinned. (30) no clock keeps replay's
status — pinned. (31) newest verifying line per witness — pinned. (32) T is the
quorum time, not the newest — pinned. (33) unverified lines and T — unobservable.
(34) elapsed == S is fresh, S_hard == 0 is unconfigured — both pinned.

§7: (35-39) the five splits of D13 — not pinned. (40) every log-key line must
verify — pinned, stated nowhere (D4). (41) newline-terminated block — pinned,
stated nowhere (D2). (42) canonical decimal size — pinned, stated nowhere
normative (D3). (43) key_id binds name, algorithm and key — pinned
(trust-bad/37). (44) split a verifier key on at most two '+' — pinned.

§9: (45) origin/name/algorithm rules — not pinned individually (D12).
(46) correspondence as set vs multiset — not pinned (admitted). (47) whether
log_urls must look like URLs — not pinned. (48) whether the policy's witness keys
are re-checked — not pinned. (49) anchor type ignored / mode must be advisory —
both pinned. (50) anchor optional — pinned. (51) witness array order is
significant — verified by rebuilding the CBOR from trust.toml and matching
trust.cbor byte for byte.

§9.1 grammar: (52) directive arity — not pinned (D9). (53) comment scope — not
pinned (D10). (54) a witness named "none" — not pinned. (55) nested-group
semantics — pinned only against a *proper* flattening; a naive one still passes.
(56) forward references, duplicate members, k=0, k=02 — all four pinned.

§8.1/§11.1: (57) the bundle's device<->entry binding — pinned, stated nowhere
(D5). (58) MAX_BUNDLE_BYTES — not pinned (admitted). (59) held != conflicting —
not pinned. (60) evidence step order — not pinned. (61) the carried policy
decides nothing — pinned both ways.

§6/§10: (62) rebuild-vs-head and recompute-not-supplied — not pinned (D11).
(63) fork comparison before the size rule — pinned. (64) no accusation without
holding `at` — pinned. (65) tile path syntax, tile height, uint16 framing —
pinned, but the path syntax comes from tlog-tiles, not SPEC.md.

§16: (66) expires > ts, and the request ts unconstrained against the entry's —
both pinned. (67) HRP, padding and case — pinned; separator position stated but
not pinned.

§14: (68) every escaping and ordering rule — pinned by `enroll-astral-labels`,
the best-designed vector in the suite.

## 6. What I could not cover

- **OpenTimestamps.** No `.ots` verifier — it needs the chain and a calendar, and
  anchoring is advisory. I did verify the one checkable claim: §6 says the
  stamped value is SHA-256 of the checkpoint **body** "up to and including the
  blank line", and `anchors/checkpoint-124.ots` contains exactly
  `81ad55390d8753d262d13aa41392407e3bdf123f28aeef33f389bc46a42872dd`, which is
  that digest and **not** the signed text's nor the whole note's. `sample.ots`
  and `calendar-response.bin` are unexercised.
- **§11 rules 1-4.** Nothing exercises writing `fork/<unix>.evidence`, keeping
  the proven set unchanged, raising the alarm, or "refuse every later checkpoint
  not consistent with the stored one, **forever**". That is the rule whose misuse
  takes a network down, it is behaviour over time, and no static file can pin it.
- **§8 conditions 2 and 4 as a running node applies them.** Condition 4 only
  against `detect/staleness.json`'s table; condition 2 only through `detect/`'s
  pairs. The monotonic clock is untestable from files.
- **§7's submission protocol** (POST /add, 400/409/429, the mmd promise), **§6's**
  checkpoint cadence, **§9.4's** `overlap` obligation on the log, **§16.3's**
  ssh-agent requirement — obligations on a running log or signer, none vectorable.
- **Tile paths above index 999.** Implemented but unexercised (largest log is 124).
- **The `says` wording.** For proofs-bad/, fork/ and entries-hostile/ the
  expectation is a substring of an error message; I made my messages contain
  them, which is cosmetic. The substantive check is that each vector is refused by
  a *distinct* rule, verified by disabling exactly that rule.

## 7. Rules I got right from outside knowledge, not from the document

I did **not** search the web for this project. I did use prior knowledge of the
public standards the preamble names. Where that knowledge supplied a rule the
document did not, it is listed here.

1. **RFC 6962 §2.1.1 / §2.1.2** — the inclusion- and consistency-proof algorithms
   and node ordering. SPEC.md explicitly defers them; a fair deferral, but no
   vector would help a reader find the ordering by trial and error.
2. **RFC 6962's empty-tree root = SHA-256("")** — needed by MerkleRoot([]), never
   reached by any vector (`V241` passes), stated nowhere in SPEC.md.
3. **RFC 8949 §4.2.1's preferred serialization applies to every argument**, not
   just integers. This is D7: I implemented the RFC's rule; the table names only
   integers; no vector separates them.
4. **RFC 4648 §6 / Crockford bit packing** — MSB-first, 5 bits at a time. SPEC.md
   gives both alphabets but not the bit order.
5. **BIP-350** — charset, HRP expansion, generator polynomial and polymod, the
   six-character checksum, the 33-126 printable range, 8<->5-bit regrouping.
   §16.2 says outright that a reader must fetch BIP-350, which is honest.
6. **c2sp.org/signed-note conventions** — that a note's text lines are non-empty
   (so the *first* blank line ends the text) and that a key name has no space.
   These resolved D13's ambiguities; §7 states neither while claiming to be
   self-sufficient.
7. **c2sp.org/tlog-checkpoint** — the size line is decimal without leading
   zeroes. This is D3.
8. **c2sp.org/tlog-tiles path syntax** — `tile/<L>/<N>`, `tile/entries/<N>`, the
   `.p/<W>` suffix. §6 defers this explicitly and fairly; without it `served/`
   cannot be read at all.
9. **x/mod/sumdb/note's behaviour** — which is how I know D4's rule is *not*
   inherited from the canonical implementation §7 points at, and is genuinely
   absent from the document.
10. **Ed25519 (RFC 8032)** via crypto/ed25519, and standard base64 with padding
    (§1 does define b64).

One place where the document saved me and outside knowledge would not have:
§4.1's warning that CBOR map-key order is over the *encoded* form, not the bare
string, with the worked `after, body, net, sigs, t, ts, v` counter-example. That
is the single most useful paragraph in the specification — the variant that
implements the other reading (`V07_SortBareStrings`) collapses 32 checks
instantly. The document is at its best where it does this, and at its worst where
it lets §12.1's coverage table carry rules the normative sections do not.
