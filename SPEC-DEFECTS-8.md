# Norn v1 — adversarial specification review

Independent Go implementation (standard library only: own CBOR codec, canonical
JSON, signed-note/cosignature parser, RFC 6962 Merkle tree and proof verifiers,
tlog-tiles reader, tlog-policy parser, bech32m, Crockford base32, trust-file and
evidence readers). Source under `work/norn/`; variant sweep in
`work/sweep-final.txt`.

## 1. Verdict

**SPEC INSUFFICIENT.**

* §10's normative procedure, implemented exactly as written, gives the WRONG
  answer on a shipped vector (`detect/fork-on-a-shorter-branch`), in the unsafe
  direction: it declines to raise FORK where the suite requires one (D1).
* §10's step order contradicts §12.1's own description of it and the refusal
  reason the suite demands (D2).
* `detect/staleness.json` requires labels and a parameter (`S_hard`,
  fresh/degraded/hard_stale/unknown) that appear nowhere in this document (D4).
* §4.0 asserts the bundle, trust file and evidence formats "each state their own
  bound"; none states any bound (D3).
* Three coverage claims are demonstrably false (D5, D6, D8) and four vector
  cross-references do not resolve (D7).
* 58 of 180 single-switch variants, each a defensible alternative reading, pass
  the entire suite unchanged.

## 2. Check tally

Vector files: 431 (430 in SHA256SUMS + SHA256SUMS). SHA256SUMS verifies 430/430.
Baseline harness: **582 assertions, 582 pass, 0 fail**.
Variants built and run: **180**. Variants that still pass everything: **58**.

Coverage of the 582: the 116-entry replay fixture entry by entry against
manifest.json AND the .reason files; state.json byte-for-byte; 16 entry mirrors
(entry_hash, leaf_hash, preimage_sha256, size, canonical-JSON mirror, CBOR
re-encode round-trip); 15 genesis/ aborts each with its own state.json;
trust.cbor + fingerprint + TOML rendering; 30 trust-bad/; 5 requests/ (CBOR,
signature, preimage, mirror, bech32m text, uppercase form) and 25 requests-bad/;
8 entries-hostile/ (refused for the named reason, or accepted at a boundary);
receipt.note vs receipt.json and the log key; served/ (bundles -> tree -> signed
head -> state.json, plus level-0 hash tiles); quorum time 1760003607; 12
checkpoints-bad/; 8 proofs/ and 6 proofs-bad/ with their `says` strings; 4
proven/ evaluation times; 2 positive and 8 negative fork/ cases with `says`; 4
detect/ pairs; served-rotated/ and served-superseded/ in BOTH correct readings;
3 served-bad/; the 5-rung staleness ladder; anchors/checkpoint-116.ots against
the checkpoint-body digest.

## 3. Defects

### D1 - §10's stored-checkpoint block cannot reach FORK on a shorter branch

Prose (§10):

    if stored_cp exists:
        require cp.size >= stored_cp.size
        require the head this log had at stored_cp.size == stored_cp.root
        on mismatch -> FORK (§11)

Vector (`detect/cases.json`): stored `current.checkpoint` (116) + served
`honest-earlier` (40) -> `refuse`; stored `current.checkpoint` (116) + served
`fork-shorter` (41) -> **`fork`**.

Read literally the first `require` fails for both, so FORK is unreachable for
any offered head shorter than the stored one; the second `require` is not even
computable then, because the offered log has fewer than `stored_cp.size`
entries.

Proof: variant `detect-spec10-literal` fails exactly one check -
`detect/fork-on-a-shorter-branch: got "refuse" want "fork"`. §12.1 knows the
intent ("the shorter-branch case is what a forking log looks like when it hides
behind 'a log does not shrink'"); §10 does not encode it.

Should say: on a shorter head, recompute the root the STORED branch had at
`cp.size` (the node holds every entry) and compare with `cp.root`; differ ->
FORK, agree -> refuse without accusing.

### D2 - §10 checks origin before the log signature; §12.1 and the vectors require the reverse

§10 lists `require cp.origin == norn.trust.origin` before `verify log
signature`. §12.1: "`served/` verified end to end, **signature first**".
`proofs-bad/cases.json` makes it observable: `foreign-checkpoint` must be
refused with a reason about "no valid signature from a trusted key",
`wrong-origin` with "is for origin".

Proof: variant `cp-origin-before-signature` fails exactly
`proofs-bad/foreign-checkpoint reason`.

### D3 - §4.0 claims three artifacts state their own size bound; none does

§4.0: "a proof bundle (§8.1), a trust file (§9.1) and fork evidence (§11.1) ...
each states its own bound. Every one of them is bounded; none shares this
number." §8.1 says only "the bound is this artifact's, not the entry's" - no
number. §9 and §11.1 give nothing. The assertion is false and the MUST is
unimplementable.

Proof: `bundle-entry-size-limit` (bound = 65535) and `trust-entry-size-limit`
both pass, as does my unbounded baseline.

### D4 - the freshness ladder the suite requires is not in this document

`detect/staleness.json` demands `fresh`/`degraded`/`hard_stale`/`unknown` and
supplies `"hard": 3600` ("this node's local S_hard"). §8.1 condition 4 defines
only `elapsed > params.staleness`. §5.3 never names `unknown`. §15 defers the
ladder to `GOSSIP.md`, which is not shipped and is not in the preamble's list of
reused specifications. §12.1 still files staleness.json under "§8.1 condition
4", and `vectors/README.md` claims "SPEC.md beside them is the only document
required to interpret any of it". I produced the right answers only because the
vector file itself carries `hard` and the label names.

### D5 - §12.1's claim about trust-bad/15 is false; §9.1's witness-key-algorithm MUST is entirely unvectored

§12.1: "`15` and `16` parse cleanly as verifier keys and are refused only by the
algorithm rule." `15-witness-key-is-a-note-key` lists exactly ONE witness (`pi`,
algorithm 0x01) while its policy names `pi`, `vps` and `friend`; §9.1's
correspondence rule refuses it on its own.

Proof: `trust-no-witness-key-alg` - dropping §9.1's "MUST be a cosignature key"
outright - passes all 582 checks. `trust-no-witness-key-alg,trust-no-corres-
pondence` accepts 15. (16 IS pinned: `trust-no-log-key-alg` fails.)

Should say: rebuild 15 with all three witnesses present and only `pi`'s
algorithm byte differing, in both the array and the policy.

### D6 - "04 and 08 are the only files a signature-blind verifier accepts" is false

`checkpoints-bad/cases.json` and `vectors/README.md` both say so. Variant
`cp-signature-blind` (verify nothing; count lines by shape) accepts **04, 08, 11
and 12**. Related: §12.1's "Without [04] a verifier that never checks the log
signature reproduces the whole suite" is also wrong - `cp-skip-log-signature`
fails four checks (04, proofs-bad/wrong-log-key, proofs-bad/foreign-checkpoint's
reason, and served-rotated's trust-only refusal).

### D7 - four vector cross-references do not resolve

The preamble says "Every cross-reference resolves."

* §14: "Vector `log/49-policy-escaping` exercises every row of both tables
  above." No such vector; index 49 is `49-policy-rotated`. The escaping content
  is in `log/104-enroll-astral-labels`.
* §12.1 cites `policy-escaping` - same non-existent name.
* §12.1 cites `revoke-by-device` - no such vector; the case is
  `36-revoke-self-laptop`.
* §4.3 cites `log/61-bad-thr-zero`; the vector is `69-bad-thr-zero` and index 61
  is `61-bad-kid-format` - exactly the index drift §12.1 warns against two
  sections later.

### D8 - proofs-bad/ holds six bundles; §12 and the README say four

`vectors/README.md` and §12's table both describe four (wrong entry, foreign
checkpoint, tampered proof, wrong log key). `proofs-bad/cases.json` has six -
plus `no-quorum` and `wrong-origin`, which §12.1 names in a different row.

### D9 - §4.3's type table is split by prose, orphaning three rows

The `thr`-is-a-plain-uint paragraph sits between the `params` row and the
`note`, `log_key` and `policy` rows, so in rendered Markdown those three fall
outside the table as literal pipe text. They carry the signature requirements
for two governance types and the "no state effect" rule for `note`.

### D10 - §5.2's "for enroll ... active for ANY device" is unobservable

The "any" vs "another" readings differ only when the wg key is active for the
enrolling device_id itself - in which case that id is `active` and §5.1's
preceding `dup-id` check fires. If the id was revoked, its key is not in
`active_wg`. No separating case is constructible.

Proof: variant `enroll-dupwg-other-only` passes all 582 checks.

### D11 - §9.4's "keeps the trust file's key alongside rather than replacing it" is unvectored

Proof: `log-keys-replace-trust-key` passes. The fixture's second `log_key` entry
(index 89) republishes the anchor's own key, so a reader that discards the
anchor key after learning any key is never caught.

### D12 - the restated tlog-policy grammar is not sufficient to write a verifier that agrees

§9.1 restates the grammar "because a verifier cannot be written without it". At
least nine questions remain open and every one is unvectored:

| question | variant that still passes |
|---|---|
| blank lines permitted? | policy-allow-blank-lines |
| must the last line be newline-terminated? | policy-allow-no-final-newline |
| may a name be defined twice? | policy-allow-dup-names |
| may a group name something defined later? | policy-allow-forward-refs |
| is more than one quorum line an error? | policy-quorum-count-lax |
| is a log directive required? | policy-require-log-line |
| does `any` mean k=1? | policy-any-is-all |
| may a group member be another group? | policy-groups-witnesses-only |
| do \r, \v, \f separate fields? | policy-unicode-fields |

The last four pass because no policy in the suite uses `any`, nests a group, or
contains those bytes.

### D13 - §5.3's "a witness counts once ... its newest" tie-break is unvectored

§12.1 points at `checkpoints-bad/12-second-line-from-one-witness`, but 12's
second `friend` line does NOT verify, so §10's per-line rule refuses the whole
checkpoint before the tie-break is reached. No artifact carries two VERIFYING
lines from one witness.

Proof: `quorum-time-oldest-line` passes all 582 checks, while
`quorum-time-newest-line-overall` and `quorum-time-oldest-overall` both fail -
so the aggregate k-th-newest rule is pinned but the per-witness tie-break is
not. §12.1's "What is not vectored" names the median/k-th distinction but not
this one.

### D14 - §5.2's dup-key "in either role" is unobservable

`17-bad-dup-key` is a same-role duplicate; nothing adds a key already held in
the other role. Variant `dup-key-same-role-only` passes.

### D15 - three §4.0 bans and the UTF-8 rule are each individually unpinned

* `cbor-allow-null` passes: the only null vector puts it in `after`, where a
  type check refuses it anyway. Only `cbor-null-is-absent` (the genuinely
  lenient reading) is caught.
* `cbor-allow-negative` and `cbor-allow-nontext-mapkey` pass; §12.1's "What is
  not vectored" does not name them.
* `cbor-allow-bad-utf8` passes AND `text-no-utf8-check` passes; only both
  together fail. Neither layer is independently pinned.

### D16-D22 - further rules stated but never exercised

| # | rule | variant that passes |
|---|---|---|
| D16 | §4.0 "each element of sigs is a closed map of exactly {kid, role, sig}; a fourth key is decode" | sigs-allow-fourth-key |
| D17 | §5.2 decode covers "wrong v" - no entry vector has v != 1 | entry-no-v-check |
| D18 | §5.1 rotate -> not-active: 12-bad-not-active is a revoke; no rotate names a revoked device | rotate-revoked-is-unknown |
| D19 | §5.1's empty-log rule | empty-log-is-bad-genesis |
| D20 | §5.1's entry-0 order is "normative" but unobservable (all failures are bad-genesis); genesis params type rule and the role:"root" requirement on bootstrap signatures likewise unpinned | genesis-checks-reordered, genesis-params-no-typecheck, genesis-params-nonempty, genesis-sigs-any-role |
| D21 | §7 note framing: verifier-key id not checked; em-dash prefix; trailing newline on the signature block; witness algorithm byte at verification; canonical decimal size; how many log signatures a checkpoint may carry | vkey-no-id-check, note-accept-ascii-dash, note-allow-unterminated-siglines, cosig-any-alg, cp-size-noncanonical-ok, cp-exactly-one-log-signature |
| D22 | §9.1 members shown but never constrained: witness element closedness, url requiredness, witness name bounds, empty log-url strings, anchor member requiredness and literals, policy log key vs trust log_key | trust-witness-open-schema, trust-witness-url-required, trust-witness-name-bounds, trust-log-urls-nonempty-strings, trust-anchor-all-required, trust-anchor-literals, trust-policy-log-key-must-match |

### D23 - the resource-limit count disagrees with itself

§4.0 "Two limits, both normative"; §12's table "for §4.0's two resource limits";
README and entries-hostile/cases.json "three resource limits - the entry size,
the nesting depth and the map-key cap". §12.1 carries a separate row for the
map-key cap.

### D24 - §9.1 predicts a hole §12.1 does not admit, and 30 does not close it

§9.1 warns that a strike-out correspondence reader "passes the suite without the
uniqueness rule at all", and `30-duplicate-witness-name-only` exists to close
it. It does not: a strike-out reader refuses 30 through the correspondence rule.

Proof: the combination `trust-correspondence-strikeout,trust-allow-dup-witness-
name` - a reader with NO witness-name uniqueness rule at all - passes all 582
checks. §12.1's four-item "What is not vectored" list does not name this.

### D25 - §8.1 and §11.1 schemas are loosely pinned

bundle-open-schema, bundle-no-v-check, bundle-entry-must-name-device,
evidence-open-schema, evidence-no-version-check and
evidence-size-must-be-le-held all pass.

### D26 - free-text lower bounds

§4.0 gives `reason` 0-256 and note/policy `text` "<= 4096" with no floor. No
vector carries an empty or absent one, so text-min-one-byte, reason-min-one-byte
and revoke-reason-required all pass - three readings that contradict the table
and conform to the suite.

### D27 - normative dependencies missing from the preamble, and one algorithm never cited

The preamble enumerates what Norn "reuses verbatim": the C2SP documents, RFC
6962 §2.1, RFC 8949 §4.2.1, RFC 8032, RFC 7748. It omits:

* **BIP-350.** §16.2 is unimplementable from this document: it gives the HRP,
  the constant, the padding rule and the case rule, but not the charset, the
  generator polynomial, the separator rule, HRP expansion, or the checksum
  length. §9.1 restates the policy grammar precisely because "a verifier cannot
  be written without it"; the same reasoning was not applied here.
* **RFC 4648.** Named inline in §2/§9.1 but not listed; the alphabet is never
  given.
* **RFC 6962 §2.1.1/§2.1.2.** §6 cites only §2.1 (hashing). §8.1 says "RFC 6962
  inclusion proof, leaf to root". §11.1's `proof` field says only "consistency
  proof chaining (size, held_root) to held's own head" - no citation, no
  algorithm, no node ordering. Only fork/evidence.cbor pins it.

## 4. Variant table

180 variants, one switch each. Full raw output in `work/sweep-final.txt`.

### 4.1 Still passing - 58 (the finding)

after-before-dup-genesis (after decided before dup-genesis) | bundle-entry-must-
name-device | bundle-entry-size-limit | bundle-no-v-check | bundle-open-schema |
cbor-allow-bad-utf8 | cbor-allow-negative | cbor-allow-nontext-mapkey |
cbor-allow-null | cbor-depth-scalar-counts | cosig-any-alg | cp-exactly-one-log-
signature | cp-size-noncanonical-ok | cp-witness-match-keyid |
dup-key-same-role-only | empty-log-is-bad-genesis | enroll-dupwg-other-only |
entry-no-v-check | evidence-no-version-check | evidence-open-schema |
evidence-size-must-be-le-held | genesis-checks-reordered |
genesis-params-no-typecheck | genesis-params-nonempty | genesis-sigs-any-role |
log-keys-replace-trust-key | note-accept-ascii-dash |
note-allow-unterminated-siglines | policy-allow-blank-lines |
policy-allow-dup-names | policy-allow-forward-refs |
policy-allow-no-final-newline | policy-any-is-all | policy-groups-witnesses-only
| policy-quorum-count-lax | policy-require-log-line | policy-unicode-fields |
quorum-none-has-a-clock | quorum-time-median | quorum-time-oldest-line |
reason-min-one-byte | request-no-size-limit | revoke-reason-required |
rotate-revoked-is-unknown | sigs-allow-fourth-key | text-min-one-byte |
text-no-utf8-check | trust-anchor-all-required | trust-anchor-literals |
trust-correspondence-strikeout | trust-entry-size-limit |
trust-log-urls-nonempty-strings | trust-no-witness-key-alg |
trust-policy-log-key-must-match | trust-witness-name-bounds |
trust-witness-open-schema | trust-witness-url-required | vkey-no-id-check

### 4.2 Combinations

| combination | passes | shows |
|---|---|---|
| trust-correspondence-strikeout + trust-allow-dup-witness-name | YES | a reader with no witness-name uniqueness rule passes the suite (D24) |
| cbor-allow-bad-utf8 + text-no-utf8-check | no (3) | UTF-8 pinned only by both layers (D15) |
| trust-no-witness-key-alg + trust-no-correspondence | no (3, incl. trust-bad/15) | correspondence, not the algorithm rule, refuses 15 (D5) |
| cp-witness-match-keyid + cp-uncounted-not-refused | no (11, 12) | the per-line refusal rule IS pinned |
| cp-signature-blind | no (04, 08, 11, 12 + 4 more) | four files, not two, catch a signature-blind reader (D6) |

### 4.3 Correctly rejected - 122 (failing-check count in parens)

CBOR: cbor-allow-trailing (5), cbor-allow-nonshortest (3), cbor-allow-huge-uint
(3), cbor-allow-tags (3), cbor-allow-dup-mapkey (3), cbor-allow-unsorted-maps
(4), cbor-sort-bare-strings (4), cbor-null-is-absent (3), cbor-no-mapkey-cap
(1), cbor-depth-16 (1), cbor-depth-4 (1), entry-no-size-limit (2),
entry-size-limit-65536 (1).

Entry schema/signatures: kid-format-not-schema (3), body-kid-format-not-schema
(3), role-enum-not-schema (3), sigs-unsorted-ok (3), device-id-no-charset (10),
entry-no-net-check (3), preimage-no-prefix (112), preimage-keeps-empty-sigs
(112), ignore-declared-role (4), device-sig-any-known-device (13),
thr-range-is-schema (3), params-empty-ok (3), rotate-device-pk-required (11),
entry-ts-monotonic (4), entry-after-monotonic (3).

Replay: dup-entry-after-decode (3), seen-set-accepted-only (4),
governance-threshold-after-body (5), note-needs-signer-threshold (9),
after-must-equal-index (16), after-is-a-ceiling (19), enroll-sig-before-net (3),
enroll-signers-before-request-sig (3), enroll-dupwg-before-dupid (3),
enroll-merges-old-record (5), enroll-request-ts-must-not-exceed (8),
rotate-new-key-sig-before-dupwg (3), rotate-dupwg-any-device (4),
rotate-sets-since-index (2), rotate-always-needs-signer (3),
revoke-keeps-since-index (2), revoke-pool-counts (9), root-remove-no-invariant
(28), signer-remove-quorum-invariant (4), thr-allows-zero (12),
thr-no-upper-bound (48), log-key-replaces (4), log-key-since-index-is-size (3),
params-replace (2), policy-no-parse (4), size-counts-accepted-only (2),
replay-aborts-on-rejection (92), genesis-abort-keeps-size (30),
genesis-after-unconstrained (2), genesis-hash-is-entry-hash (96),
state-omit-empty-labels (2), state-active-wg-includes-revoked (2),
proven-no-clock-drops-expiring (1), expiry-strict-less (1).

Canonical JSON: json-sort-utf16 (2), json-escape-slash (2), json-html-safe (2),
json-escape-del (2), json-escape-nonascii (2), json-uppercase-hex (2),
json-no-trailing-newline (17).

Notes/checkpoints/quorum: note-text-includes-blank-line (31),
cosig-signs-note-text-only (23), cosig-time-leading-zeros (23),
cosig-timestamp-little-endian (23), keyid-omits-alg, cp-allow-extension-lines
(1), cp-skip-log-signature (4), cp-signature-blind (8), cp-uncounted-not-refused
(2), cp-origin-before-signature (1), policy-witness-matched-on-short-name (23),
quorum-time-newest-line-overall (1), quorum-time-oldest-overall (1),
policy-urls-required (1), policy-never-superseded (1), log-keys-never-learned
(1), log-key-only-latest (1).

Merkle/tiles/detect: leaf-hash-no-prefix (12), node-hash-no-prefix (15),
tiles-skip-hash-tiles (1), detect-spec10-literal (1), staleness-ge (1).

Trust: trust-version-any (1), trust-no-origin-check (1), origin-base32hex (9),
origin-base32-padded (9), trust-no-name-bounds (2), trust-name-upper-only (1),
trust-name-lower-only (1), trust-no-log-key-alg (1), trust-no-log-key-name (1),
trust-allow-empty-log-urls (1), trust-allow-no-witnesses (1),
trust-allow-dup-witness-name (1), trust-no-correspondence (2),
fingerprint-rfc4648-alphabet (2).

Requests/bech32m: request-no-device-pk-length (3), request-expires-unbounded
(1), request-expires-ge-ts (1), request-labels-cap-64 (1),
request-preimage-entry-prefix (60), bech32-accept-bech32 (1),
bech32-allow-mixed-case (1), bech32-reject-uppercase (1), bech32-lax-padding
(1), bech32-90-char-limit (5).

Bundles/evidence/anchors: evidence-policy-need-not-parse (1),
evidence-use-carried-policy (2), evidence-skip-proof (2),
evidence-equal-roots-are-a-fork (1),
evidence-proof-may-be-present-at-same-size (1),
anchor-digest-excludes-blank-line (1).

## 5. Every decision the prose did not make for me

[pinned] = a vector happened to decide it anyway.

CBOR / encoding
1. What the 1-23 byte map-key cap means for a non-text key (banned only by
   implication). I rejected them.
2. Whether a map KEY occupies its own depth level. I chose "containers only";
   at-the-depth-limit pins the container reading only because its innermost item
   is a scalar. [pinned]
3. Whether the 65535 cap is on the whole document or on the outer item's
   declared length. Both work on oversize-entry.
4. Whether entry_hash semantics ("as received") extend to bundles/trust files.
5. Whether the preimage is built by re-encoding or by splicing bytes out of the
   received document. Never stated; equivalent only because the input is already
   deterministic.

Entries / replay
6. Whether step 3's "envelope check per §4.1" includes type-checking ts, after
   and body (I said yes) or defers them to step 8. [pinned by 32, 45]
7. Whether §4.0's field-constraint table applies at step 3 or inside step 8.
8. Whether `t` must be checked as text before the unknown-type step.
9. For revoke, whether the device's authorisation is "one valid device
   signature" or a threshold. I chose >= 1. [pinned by 102]
10. Whether a threshold applies to the pre- or post-entry key set. §4.3 says "the
    old threshold" only for root_thr. [pinned by 26, 62]
11. Whether bad-thr's len(set) is measured before or after the entry.
12. Whether a note's "any 1 signer or root" is one total or one of each.
    [pinned by 90]
13. since_index for a re-enrolled device. [pinned]
14. Whether active_wg is recomputed or maintained incrementally.
15. Whether `rejected` may hold more than one entry per index.
16. Whether the size cap is applied before or after recording entry_hash. §4.0
    says the hash comes first. [pinned by 110]

Canonical state / JSON
17. Whether params emits all four keys or only those set. [pinned]
18. Whether log_keys is [] or absent when empty. [pinned]
19. net as hex of 16 bytes. [pinned]
20. Whether labels keys sort by the same rule as object keys. [pinned by astral]
21. Whether the trailing 0x0A applies to the entry .json mirrors. [pinned]

Notes / checkpoints / quorum
22. Whether a signature-line name may contain '+'. I split left-to-right.
23. Whether a line naming a policy witness with a MISMATCHED key id counts as
    naming that witness (refuse) or nobody (skip). Not decided;
    cp-witness-match-keyid passes.
24. What to do with lines naming neither the log nor a policy witness. I ignored
    them; §10 does not say.
25. How ties break when two witnesses share a timestamp.
26. Whether a replayed policy entry must itself satisfy §9.1's correspondence
    with trust.witnesses. I said no. [pinned by served-superseded]
27. Whether the trust file's policy survives a policy entry. §9.4 says no.
    [pinned]
28. Whether the anchor's log key survives learning one from the log (D11).

Trust file
29. Everything in D22.
30. Whether origin comparison is case-sensitive.
31. Whether the fingerprint covers the received bytes or a re-encoding.

Fork evidence / bundles
32. Whether size may exceed held's size, and what a reader does then.
33. Whether the consistency proof's elements are ordered as RFC 6962 produces
    them - never stated (D27).
34. Whether a bundle must prove the entry that made the device active (D25).
35. Whether §11's "refuse forever" is observable behaviour. No vector.

Requests / text form
36. Whether expires is compared against the request's ts or the entry's.
    [pinned by expires-at-ts and enroll-request-from-the-future]
37. Whether the HRP comparison is case-insensitive after lowering.
38. Whether the uppercase form must round-trip to the same bytes. [pinned]

## 6. What I could not cover

* **anchors/**. SPEC.md does not define the OpenTimestamps format. I verified
  only that checkpoint-116.ots contains SHA-256 of the checkpoint body INCLUDING
  the blank separator line - which does pin §6's wording (variant
  anchor-digest-excludes-blank-line fails). sample.ots and calendar-response.bin
  are opaque from this document.
* **tlog-tiles beyond one partial tile.** 116 entries means only
  tile/entries/000.p/116 and tile/0/000.p/116 exist. Full tiles, level >= 1 hash
  tiles and the xNNN/ thousands grouping are exercised by nothing; I implemented
  them from the upstream layout, not from the document.
* **§7 submission.** POST /add, deadline = now + mmd, and 400/409/429 have no
  vector. I checked only that receipt.note parses, verifies under the anchor key
  and matches receipt.json.
* **§9.4's overlap** - a timing obligation on the log, not a file property.
* **§11 rules 1-4** other than the evidence format: writing
  fork/<unix>.evidence, keeping the stored checkpoint, the alarm, the permanent
  refusal.
* **§16.3** ssh-agent key handling.
* **Everything deferred to documents that do not ship**: GOSSIP.md,
  ENFORCEMENT.md, ENROLLMENT.md, THREAT-MODEL.md, DECISIONS.md, BUILD-LOG.md,
  PLAN.md - including every D-numbered rationale.
* **state.net from the anchor vs the genesis entry** - the document says it is
  unobservable and it is.

## 7. Rules I got right from outside knowledge, not from the document

Public standards only; recorded because a rule I got right from outside is a
rule this specification may have failed to state.

1. **BIP-350 / bech32m (§16.2).** The document gives the HRP, the constant
   0x2bc830a3, the padding rule and the case rule. From BIP-173/350 I supplied:
   the charset qpzry9x8gf2tvdw0s3jn54khce6mua7l, the generator constants
   {0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}, the polymod
   loop, HRP expansion ([c>>5...] || 0 || [c&31...]), that the separator is the
   LAST '1', the 6-character checksum, and the 33-126 character range. §16.2
   cannot be implemented from this document alone.
2. **RFC 6962 §2.1.1 and §2.1.2.** The inclusion-proof verification algorithm
   (§8.1 names it but does not give it) and the CONSISTENCY-proof algorithm and
   node ordering (§11.1 names neither), plus the largest-power-of-two split used
   to build any root. Load-bearing: fork/evidence.cbor is the only thing pinning
   the consistency proof.
3. **RFC 4648 base32.** The alphabet A-Z2-7; §2 and §9.1 name the RFC but never
   give it, warning only that Crockford's alphabet differs.
4. **c2sp.org/tlog-tiles.** Tile paths (tile/<L>/<NNN>, .p/<width> for partial,
   xNNN/ grouping) and that entry bundles concatenate uint16-length-prefixed
   entries with no header. §6 restates the framing; the paths I reconstructed
   from the shipped directory.
5. **c2sp.org/signed-note.** That a verifier key's name may not contain '+'
   (what makes "split on + at most twice" work), that the signature base64 is
   standard WITH padding, and that a note with no signature lines is still
   well-formed. §7 restates most of the framing well, but not these three.
6. **RFC 8949 §4.2.1.** The shortest-form argument thresholds (24 / 2^8 / 2^16 /
   2^32). The reduction of "bytewise on the encoded form" to length-then-bytes
   for 1-23-byte keys IS stated, correctly, in §4.1.
7. **RFC 8032 / Ed25519** via crypto/ed25519, as cited.

Everything else - the domain prefixes, the cosignature message layout, the key
id construction, the canonical-JSON escaping table, the reason-code ordering,
the T definition, the trust-file schema, the evidence schema - came from this
document.
