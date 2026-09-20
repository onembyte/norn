# COLD GATE 6.7 — independent implementation audit of Norn SPEC v1

VERDICT: SPEC INSUFFICIENT

Independent Go implementation (stdlib only; own CBOR codec, own bech32m, own
signed-note/cosignature parser, own Merkle/RFC 6962, own canonical JSON, own
tlog-policy parser, own TOML→CBOR reconstructor), written from `SPEC.md` alone.
Implementation in `impl/`, runner `./norncheck <vectors> <variant>`.

---

## Stage 2 — results

```
VARIANT base: checks=241 pass=241 fail=0
```

Breakdown of the 241 checks:

| area | checks | note |
|---|---|---|
| `entries/` | 16 | entry_hash, leaf_hash, preimage_sha256, byte length, canonical re-encode, `.json` mirror |
| `log/` | 105 + 1 | every manifest reason code, plus `state.json` byte-for-byte |
| `genesis/` | 12 | abort + serialised state byte-for-byte |
| `trust.cbor` / `trust.fingerprint` / `trust-bad/` | 2 + 25 | |
| `trust.toml` | 1 | §9.2 rebuild reproduces `trust.cbor` byte for byte |
| `requests/` + `requests-bad/` | 4 + 25 | |
| `entries-hostile/` | 6 | refusal reason matched against `says` |
| `served/` | 3 | checkpoint, replayed state, quorum time `T` |
| `checkpoints-bad/` | 11 | |
| `served-bad/` | 2 | applied over a copy of `served/` |
| `served-rotated/` / `served-superseded/` | 2 + 2 | both answers, trust-only and informed |
| `proofs/` + `proofs-bad/` | 7 + 4 | refusal reason matched against `says` |
| `proven/` | 4 | |
| `fork/` | 1 + 6 | refusal reason matched against `says` |
| `receipt.note` | 1 | incl. `text_sha256` boundary |
| `anchors/checkpoint-105.ots` | 1 | stamped digest = SHA-256 of the body **including** the blank line |

`shasum -a 256 -c SHA256SUMS` passes on all 369 files.

**Disagreements with vectors: one, and I concluded the specification is at
fault, not the vector** — `entries-hostile/at-the-depth-limit` (J1 below).
Everything else I initially got "wrong" was my bug, found and fixed
(RFC 6962 audit-path direction; bundle check order).

## Stage 3 — variants

99 variant implementations, each making the other defensible choice at one
decision point, each re-run against the whole suite.
**27 of them still pass all 241 checks.** One (`cp-count-cosig`) turned out to
be a no-op in my code and is discarded. The other 26 are the evidence below.

---

## Defects

### J1 — §4.0 nesting-depth rule contradicts its own vector

**Section:** §4.0, "A decoder MUST bound its own resource use".

**What the prose says:** "Nesting depth is at most 8. The top-level map is
depth **1**, so a value inside it is depth 2. … The deepest structure the entry
schema itself allows is a request's `labels` value, at depth 3 of that inner
document."

Both sentences count **scalars**: a request is `map(1) → labels map(2) → a
label's text value(3)`. There is no counting under which a label's value lands
at depth 3 unless scalar values occupy a depth level.

**How I know it is real:** `entries-hostile/at-the-depth-limit.cbor` is
`81 81 81 81 81 81 81 81 00` — eight nested arrays with a `uint 0` inside the
eighth. Under the prose's own counting that `0` is at depth 9 and the input
must be refused; `entries-hostile/cases.json` marks the case `"accepted": true`
and the README says an accepted case "sits exactly at a limit and MUST be
accepted, which is what bounds it from below". My variant `depth-scalars`
implements the prose literally and is the only variant in the suite that fails
**for following the document**:

```
VARIANT depth-scalars: checks=241 pass=240 fail=1
  FAIL hostile/at-the-depth-limit: must be accepted, got nesting deeper than the limit
```

**What it should say:** the limit counts **container** nesting only — "a map or
array nested inside the top-level item is depth 2; scalars do not add a level;
the deepest *container* the entry schema allows is a request's `labels` map, at
depth 2 of that inner document". Or keep scalar counting and change the bound
to 9. Either way the worked example and the vector must be made to agree.

This is the worst defect in the set because it is the one place where a careful
reader who implements exactly what is written produces an implementation that a
shipped vector rejects.

### J2 — the cosignature line format is never given, and §7's restatement is wrong for it

**Section:** §7 (note framing), §6 (checkpoint), §5.3 (`T`).

**What the prose says:** §7 restates the `signed-note` framing "so an
implementer needs nothing else (D22)", and states: "A signature line is `— `
…, the key name, one space, then base64 of `key_id ‖ signature` — **4 + 64 =
68 bytes**."

A `tlog-cosignature` v1 line is **76 bytes** (`key_id ‖ 8-byte big-endian
timestamp ‖ 64-byte signature`), and its signed message is not the note text
but `"cosignature/v1\ntime <decimal seconds>\n" ‖ <note signed text>`. Neither
fact appears anywhere in this document. §5.3 leans on the timestamps
("the `tlog-cosignature` lines are the only timestamps in the artifact, and `T`
is the only value derived from them") without ever saying where in the line a
timestamp lives.

**Why it is real:** I could only produce a passing verifier because I already
knew `c2sp.org/tlog-cosignature`. A reader who takes §7 at its word — it is the
document's only description of a note signature line, it is presented as
sufficient, and §6 and §11.1 point at no other — parses every cosignature line
as malformed and refuses `served/checkpoint`, every `proofs/*.bundle`, and
`fork/evidence.cbor`. The suite would then be unimplementable rather than
merely failed.

The inconsistency is self-evident in the document's own logic: §9.1 restates the
whole `tlog-policy` grammar because "a verifier cannot be written without it",
and §7 restates signed-note for the same reason — but the one external format
that is strictly harder to guess and is load-bearing for §5.3's evaluation time
is left entirely to a link.

**What it should say:** scope §7's restatement ("this describes an algorithm-1
Ed25519 note signature; a `tlog-cosignature` algorithm-4 line carries
`key_id ‖ uint64be timestamp ‖ signature`, 76 bytes"), and restate the
cosignature signed message in §5.3 beside the definition of `T`.

### J3 — §8.1's bundle check is under-specified: quorum and origin are both optional in practice

**Section:** §8.1, "Checking a bundle".

**What the prose says:** "verify the checkpoint note under
`norn.trust.log_key`; confirm `SHA-256(0x00 ‖ entry)` and `proof` reach the
checkpoint's root at `index` for that size; then apply the rules below." The
"rules below" are the four conditions for treating a *peer* as proven, of which
condition 1 ("verifies under the node's trust policy (§9)") is the only place a
witness quorum is mentioned — and it is part of the peer rule, not the bundle
rule. The origin line is never mentioned at all. Contrast §11.1, which for the
same kind of embedded checkpoint says explicitly "verify **both** checkpoints
per §10 — this network's origin, this network's log key, and a satisfied
witness quorum."

**How I know it is real:** two variants pass the entire suite.

```
*** STILL PASSES: VARIANT bundle-no-quorum   (bundle checkpoints need only the log signature)
*** STILL PASSES: VARIANT bundle-origin-after (bundle checkpoint origin line checked, or not)
```

`bundle-check-origin` (origin checked *before* the signature) fails, because
`proofs-bad/foreign-checkpoint` must be refused for "no valid signature from a
trusted key" — so the vectors pin the *order* of a check they never require you
to perform at all. Nothing in `proofs-bad/` is an uncosigned bundle or a
`10-wrong-body-origin`-shaped bundle.

The consequence is not cosmetic: §8 sells the bundle as "self-contained, so it
can be checked by someone holding only `norn.trust` — which is what makes it
useful in an alarm, an audit trail, or a bug report". Under one conforming
reading that artifact carries independent witness corroboration; under the
other a log acting alone can mint one, and the reader has no way to tell which
kind they were handed.

**What it should say:** §8.1 should read "verify the checkpoint per §10" like
§11.1 does, and `proofs-bad/` should gain an uncosigned bundle and a
wrong-body-origin bundle.

### J4 — §6's hash-tile MUST has no vector, and §12.1 implies it does

**Section:** §6, third bullet; §12.1 row "§6 tiles and bundles".

**What the prose says:** "The served `tile/<L>/…` hashes MUST also agree with
the tree it rebuilt. They are not needed to reach the head, and **checking them
is not optional**: a node serves the tiles it fetched onward to its peers …"

**How I know it is real:**

```
*** STILL PASSES: VARIANT blind-tiles (never reads tile/0/… at all)
```

`served-bad/` holds exactly two cases and both are *entry bundle* cases
(tampered, missing). There is no tampered hash tile anywhere in the suite, so
the MUST is unenforced. §12.1's coverage table nevertheless presents §6 as
vectored and its "**What is not vectored**" list — which the section insists is
the honest accounting, "an inaccurate coverage claim is the same failure
wearing a different hat" — does not name it.

**What it should say:** add `served-bad/tampered-hash-tile` (one byte changed
in `tile/0/000.p/105`, which leaves the entry bundles and the head untouched so
only the tile rule can refuse it), or move the rule to the not-vectored list.

### J5 — an unknown or wrongly-typed `params` key is unvectored, and at genesis the divergence is total

**Section:** §5.1 entry-0 step 6 ("`params`, if present, has only §4.5 keys" →
abort `bad-genesis`); §5.1's `params` row ("non-empty, only §4.5 keys, each of
the right type (`decode`)").

**How I know it is real:** two variants pass the whole suite.

```
*** STILL PASSES: VARIANT allow-unknown-param  (unknown §4.5 key silently ignored)
*** STILL PASSES: VARIANT params-loose-type    (a bool where a uint is required, ignored)
```

`log/68-bad-unknown-body-key` — the only unknown-body-key vector — is a **note**
(`body: {text, extra}`), not a `params` entry; `log/103-bad-params-empty` covers
only the non-empty rule. Nothing in `genesis/`'s twelve cases has a `params`
map at all with a bad key.

This is the highest-consequence unpinned rule in the replay machine. Two
implementations that disagree about it produce a different `params` map (so a
different `staleness`, so a different freshness decision) and, at genesis,
one aborts the whole replay to the zero state while the other replays 105
entries — the maximum possible divergence in `state.json`.

**What it should say:** nothing; the prose is clear. The vectors need
`log/NN-bad-params-unknown-key`, `log/NN-bad-params-wrong-type`, and
`genesis/13-params-unknown-key`.

### J6 — §16.2's uppercase MUST has no positive vector

**Section:** §16.2.

**What the prose says:** "The canonical form is **lowercase**. An all-uppercase
form MUST also be accepted, because QR alphanumeric mode has no lowercase
letters and a request is meant to cross a room on a phone screen."

**How I know it is real:**

```
*** STILL PASSES: VARIANT bech32-reject-upper
```

Every `requests/*.txt` is lowercase; `requests-bad/` covers `mixed-case`, and
§12.1's §16.2 row lists only negatives (`wrong-hrp`, `plain-bech32`,
`mixed-case`, `corrupt-character`). The one *positive* obligation in §16.2 is
untested, and it is the one that decides whether the enrolment flow the design
exists for — a device printing a QR code, a signer scanning it — works between
two implementations at all.

**What it should say:** ship `requests/req-minimal-upper.txt` (the same bytes in
uppercase, marked as an accept).

### J7 — §12.1's claim about the derivation of `T` is false

**Section:** §12.1, row "§5.3 the derivation of `T`".

**What the prose says:** "`served/checkpoint`, whose three witnesses cosign
seven seconds apart, so **the newest, the median and the k-th newest disagree**;
`proofs/cases.json` records the value `T` must come out as."

The policy is `group home 2 pi vps friend` / `quorum home`, i.e. n = 3, k = 2.
The cosignature timestamps are pi = 1760003600, vps = 1760003607,
friend = 1760003614. The k-th newest of three **is** the median of three; they
are the same value, 1760003607, which is what `proofs/cases.json` records. Only
"newest" differs.

**How I know it is real:**

```
VARIANT t-newest: checks=241 pass=240 fail=1     (correctly caught)
VARIANT t-oldest: checks=241 pass=240 fail=1     (correctly caught)
*** STILL PASSES: VARIANT t-median               (not caught)
```

A second implementer who reads §5.3's definition as "the median of the verified
cosignature timestamps" passes every vector and diverges on any policy that is
not k-of-(2k−1) — `group 2 of 5`, or any nested group, where median and k-th
newest are different numbers. The coverage table asserts the opposite and is the
reason nobody has noticed.

**What it should say:** either correct the claim, or — better — make it true by
shipping a second checkpoint with four or five witnesses, or a nested group, so
that median and k-th newest genuinely differ.

### J8 — the scope of `MAX_ENTRY_BYTES` is ambiguous, and a legal proof bundle can exceed it

**Section:** §4.0 ("**`MAX_ENTRY_BYTES` is 65535**, and an entry is at most that
many bytes") vs §8.1, §11.1 and §9 (each "Deterministic CBOR per §4.0").

**What the prose says:** the limit is stated inside the section that every other
CBOR artifact incorporates wholesale. A bundle (§8.1) contains an `entry` field
that may itself be 65535 bytes, plus an index, a proof and a whole signed
checkpoint — so a **valid** bundle for a maximal entry necessarily exceeds
`MAX_ENTRY_BYTES`. An implementer who reads "per §4.0" as including the size
limit rejects a bundle the protocol requires them to accept; one who does not
has no bound at all on a hostile bundle, which is the thing §4.0's limits exist
to prevent.

**How I know it is real:**

```
*** STILL PASSES: VARIANT size-limit-everything (MAX_ENTRY_BYTES applied to bundles too)
```

Every bundle in the suite is ~1.4 KB, so the suite cannot see the difference.
The same question applies to trust files and fork evidence, and the depth
limit's scope is equally unstated for them (it happens not to bite).

**What it should say:** §4.0 should say explicitly which of its rules travel
with "per §4.0" and which are entry-only, and §8.1/§11.1/§9.1 should each state
their own byte bound.

### J9 — three orderings inside §5.1's `enroll` and `rotate` rules are unvectored, including the one §4.0 explains twice

**Section:** §5.1's per-type check tables ("Each rule's checks run in the order
written") and §4.0's discussion of `sigs: []`.

**How I know it is real:** three variants that swap adjacent checks pass.

```
*** STILL PASSES: VARIANT enroll-threshold-first        (threshold before the request signature)
*** STILL PASSES: VARIANT enroll-sig-before-net         (request signature before the net check)
*** STILL PASSES: VARIANT rotate-newkey-before-dupwg    (incoming-device_pk signature before dup-wg)
```

Each is a real divergence on an entry that is wrong in both ways at once:
`no-device-sig` vs `threshold`, `no-device-sig` vs `decode`, `no-device-sig` vs
`dup-wg`. The suite has a dedicated family for exactly this
(`98`…`101`, `bad-dup-id-and-wg`) and it stops short of the three cases inside
`enroll` and `rotate`.

The first of them is the one the document goes out of its way to explain a
second time: §4.0 — "An unsigned `enroll`, for instance, is `threshold` and not
`no-device-sig`: the embedded request is still signed by the device, so the
device-signature check passes and the signer count is what fails." That
paragraph exists precisely because the ordering is not obvious, it names
`log/bad-enroll-empty-sigs` as its vector — and `54-bad-enroll-empty-sigs` has
a *valid* request signature, so it cannot distinguish the two orders. The rule
is explained twice and pinned zero times.

**What it should say:** nothing; add `log/NN-bad-enroll-unsigned-request-no-signers`
(→ `no-device-sig`), `…-bad-request-net-and-sig` (→ `decode`) and
`…-bad-rotate-dupwg-and-no-new-key-sig` (→ `dup-wg`).

### J10 — §5.1 step 1's seen-set timing is unvectored in both of its stated forms

**Section:** §5.1 step 1; §4.0's definition of `entry_hash` ("§5.1 records it at
step 1, *before* the entry is decoded at step 2, so an entry that never decodes
must still have one"); §5.1 entry-0 step 1.

**How I know it is real:**

```
*** STILL PASSES: VARIANT seen-after-decode  (hash recorded only for entries that decode)
*** STILL PASSES: VARIANT no-genesis-seen    (entry 0's hash never recorded)
```

`log/84-bad-repeat-of-rejected` is a byte copy of `log/4-bad-dup-id`, which
**decodes** cleanly and is rejected later for `dup-id`; and
`log/13-bad-dup-entry` is a byte copy of `log/1-enroll-nas`, not of entry 0.
So neither of the two properties the document states is exercised. A log
carrying two identical undecodable entries yields `decode, decode` under one
reading and `decode, dup-entry` under the other — different `rejected` arrays,
i.e. a direct violation of §5.3's byte-identical MUST. Same for a log whose
entry 1 is a byte copy of its genesis (`dup-entry` vs `dup-genesis`).

**What it should say:** nothing; add `log/NN-bad-repeat-of-undecodable` (a byte
copy of an entry that failed at step 2) and `log/NN-bad-repeat-of-genesis`.

### J11 — §10's stored-checkpoint block, §11's fork *detection*, and §8's staleness condition are entirely unvectored

**Section:** §10 (`require cp.size >= stored_cp.size`; `require the head this
log had at stored_cp.size == stored_cp.root`; `on mismatch → FORK`), §11 rules
1–4, §8.1 condition 4.

**How I know it is real:** my implementation contains **none of them** and
passes 241/241. `served/` ships one checkpoint; nothing in the suite is a
sequence of checkpoints presented to the same reader.

This is not a case of the material being unavailable: the honest log's head at
size 41 is `26cc1e41…` and `fork/conflicting.checkpoint` is signed over
`75bbf38f…` at size 41, both cosigned by the policy's witnesses. The suite
contains a ready-made fork **for the detector** and only ever asks the reader to
check the finished accusation. §11 rule 4 makes the conclusion permanent until
an operator installs a new trust file, so getting the *detector* right matters
at least as much as getting the reader right — and §12.1's "What is not
vectored" list names neither it nor condition 4's monotonic-staleness rule
(`elapsed > params.staleness`, boundary included), whose `params.staleness`
value is carried all the way into `state.json` and then never used by anything.

**What it should say:** add a `detect/` directory — stored checkpoint, incoming
checkpoint, expected outcome (accept / refuse-shrinking / FORK) — and a
staleness case naming `elapsed` and the expected fresh/stale verdict; or list
all three under "What is not vectored".

### J12 — a tail of field rules that no vector reaches

Each of these is a stated rule that my variant violates while still passing all
241 checks. None is individually alarming; together they are the long tail of
"refused-but-not-pinned".

| variant that still passes | rule it ignores |
|---|---|
| `kid-body-loose` | §4.0: `kid` in a `signer_remove`/`root_remove` **body** must match `^[0-9a-f]{16}$` → `decode`. The only `bad-kid-format` vector (`log/61`) puts the bad kid in `sigs`. The document explicitly flags this exact distinction ("that distinction matters because the two produce different reason codes") and then vectors only one half. |
| `device-sig-any-role` | §5.2: a `device` signature must be declared with `role: "device"`. `86-bad-role-mismatch` pins the root/signer direction only (`role-ignore` correctly fails). |
| `no-reason-cap` | §4.0: `revoke`'s `reason` ≤ 256 bytes. `82-bad-text-too-long` covers `note`/`policy` only. |
| `no-name-len` | §4.0: genesis `name` 1–64 bytes. |
| `trust-no-name-len` | §9.1: trust `name` 1–64 bytes (`trust-bad/14` covers missing, not over-length). |
| `trust-allow-empty-log-urls` | §9.1: `log_urls` ≥ 1 (`trust-bad/24` covers missing, not empty). |
| `trust-no-witness-min` | §9.1: "A file with no witnesses MUST be rejected". `trust-bad/07-no-witnesses` is caught first by the policy/witness correspondence rule, so the MUST itself is never reached. |
| `trust-no-dup-witness` | §9.1: witness `name` unique within the file. `trust-bad/08` is likewise caught by another rule. |
| `no-key-cap` | §4.0: every map key is 1–23 bytes. `requests-bad/oversize-label-key` is caught by the `labels` field rule instead, so the *decoder-level* cap is unobservable — which §12.1 half-admits and then still lists as covered. |
| `genesis-params-replace` | §5.3: genesis `params` is **overlaid** on the §4.5 defaults. The fixture's genesis sets all four keys, so replace and overlay agree. |
| `request-ts-le-entry` | §4.3: the request's `ts` is *not* constrained against the entry's. A reader who adds the "obvious" check diverges and nothing catches it. |
| `cosig-all-lines` | §10 ("every cosignature by a witness the policy names must verify") vs §5.3 ("Two verifying lines from the same witness … are its newest") do not settle what to do with a witness that contributes one good line and one bad one. Both readings pass. |
| `evidence-policy-must-match` | §11.1: the evidence's `policy` field has **no** stated validation rule, so an accuser may write anything there. Worth noting: `fork/evidence.cbor` carries the *trust file's* 2-of-3 policy, while `held` is at size 105 where the log's own policy (published at index 49) is 3-of-3 — "the network's `tlog-policy` at the time" is not what the vector contains, and nothing can say so. |

---

## Every decision the prose did not make for me

Listed whether or not a vector happened to pin it.

**Encoding profile**
1. Nesting depth counts **containers only** (forced by the vector, against the prose — J1).
2. `MAX_ENTRY_BYTES` enforced on the whole input length **and** on any declared string/array/map length before allocation; **not** applied to trust files, bundles or fork evidence (J8).
3. The `≤ 2⁶³−1` cap applies to major-type-0 integers only, not to lengths/counts.
4. Map-key sortedness compared on the encoded key item (equivalent here to "shorter first, then bytewise"); duplicate detection by decoded key string as well as by encoded bytes.
5. The signature preimage is produced by re-encoding the decoded envelope minus `sigs`, relying on the profile being canonical; equivalently one may splice the original bytes. Unstated which is normative.
6. `sigs` sortedness compared on the `kid` string (all kids are 16 ASCII chars, so this equals bytewise on the encoded item).
7. `entry_hash` is SHA-256 of the received bytes, computed before decoding, and recorded for entry 0 too (J10).

**Replay**
8. Threshold comparisons are `count >= thr` (pinned: `thr-strict-gt` fails hard).
9. A `revoke` is authorised if **any one** of signers / roots / device suffices independently; counts are never pooled (pinned by `102`).
10. `dup-id` is checked against `status == "active"` only; `dup-wg` for `enroll` against `active_wg` only, so a revoked device's WireGuard key is re-usable (`dupwg-all-devices` fails, so this is pinned).
11. For `rotate`, "active for another device" excludes the device's own current key (pinned by `40`).
12. `since_index` is untouched by `rotate` and by any rejected entry.
13. Genesis `params` **overlays** the §4.5 defaults; a `params` entry **merges** (merge pinned by `mmd: 45` surviving; overlay unpinned — J12).
14. An unknown `params` key, and a wrongly typed one, are `decode` / `bad-genesis` (unpinned — J5).
15. `genesis` body `roots`/`signers` disjointness tested by `kid`, not by raw key bytes (indistinguishable in practice).
16. `log_key` may re-publish a key already in `log_keys` or the anchor's own key (pinned by entry 89).
17. `signer_remove` may empty the signer set (pinned by 62/63); `root_remove`'s invariant is evaluated against the post-removal count.
18. A `note` body's `text` has no minimum length.

**tlog-policy**
19. Exactly one `quorum` line; a `group` member must be previously defined; `k` is decimal without leading zeros and `1 ≤ k ≤ n`; fields split on runs of spaces and tabs; no blank lines, no comments; the text must end in `\n`. Only the "must parse / must not parse" boundary is vectored (`50-bad-policy-unparseable`), so most of this grammar detail is my choice.
20. `witness` directives are matched on the short name; a duplicate short name is a parse error.

**Notes, checkpoints and time**
21. Cosignature line = `key_id ‖ uint64be timestamp ‖ 64-byte sig`, signed message `"cosignature/v1\ntime <n>\n" ‖ <signed text>`, key id over algorithm `0x04`. **Taken from prior knowledge of `c2sp.org/tlog-cosignature`, not from this document** (J2).
22. A checkpoint body is exactly three lines; the size line has no leading zeros.
23. A signature line belongs to a policy witness iff both its name and its key id match that witness's verifier key; anything else is an unnamed line that counts for nothing and need not verify.
24. A witness contributing one verifying and one non-verifying line: I accept (both readings pass — J12).
25. `T` = the largest observed verified timestamp `t` such that `{w : ts_w ≥ t}` satisfies the policy; candidates are drawn from the observed timestamps only. Unpinned against "median" (J7).
26. "No clock" and `T = 0` are operationally identical, because expiry requires `expires != 0`.
27. A rotated log key's signed-note **name** is the origin (`log_keys` records only a `pk`; §2/§9.1 supply the name).
28. An informed reader keeps the anchor's key **and** all published keys, but uses only the **latest** published policy (both pinned, by `served-rotated`/`served-superseded`).

**Bundles, evidence, trust**
29. A bundle's checkpoint must satisfy the witness quorum, and its origin line is not checked (both unpinned — J3).
30. Fork evidence's `policy` only has to parse (unpinned — J12).
31. A trust file's witness verifier-key **note** name (`norn-witness/pi`) is unrelated to the witness short name (`pi`) and is not constrained.
32. `anchor`'s three members are all required when `anchor` is present.

**Canonical JSON**
33. Key order is bytewise over UTF-8 of the bare key (pinned by `enroll-astral-labels`; `json-utf16-order` fails).
34. `/`, `<`, `>`, `&`, U+007F and everything above U+007F are emitted verbatim (pinned by `49-policy-escaping`).

**Wire / layout**
35. tlog-tiles partial-tile paths `tile/entries/000.p/105` and `tile/0/000.p/105`; the tree is rebuilt from entry bundles and the head compared. Only one tile of one level exists in the fixture, so nothing about multi-group paths or full tiles is exercised.

---

## What the specification does genuinely well — do not break these

- **§5.1's numbered, normative ordering.** It is the single reason 105 reason
  codes come out identically in a from-scratch implementation. The explicit
  "several vectors are simultaneously wrong in more than one way, so the first
  matching step decides the reason code" is exactly the right sentence, and the
  `98`–`101` precedence family is exactly the right vector shape. The gaps in
  J9 are gaps in an otherwise excellent mechanism.
- **§4.0's two-construction rule for encoding negatives** ("the patch
  canonicalises away" / "the patch cannot canonicalise, so re-sign") with the
  `profile-base`, `labelcap-base`, `two-sig-base` controls. Every one of my
  lenient-decoder variants was caught, and caught for the *stated* reason. This
  is the best-designed part of the suite.
- **The four forged-signature vectors** (`bad-forged-signer-sig`,
  `bad-forged-device-sig`, `04-forged-log-signature`, `08`/`11`
  forged cosignatures) plus `bad-device-sig-wrong-kid`, `genesis/01-hash-mismatch`
  and the tampered inclusion/consistency proofs. Nine of my ten blindness probes
  died — only `blind-tiles` survived (J4) — and a verifier that never calls
  Ed25519 gets nowhere at all.
- **§14 canonical JSON.** Fully normative, no library defaults, and
  `49-policy-escaping` + `enroll-astral-labels` between them kill every plausible
  JSON shortcut including the UTF-16 key-order trap. `state.json` matched
  byte-for-byte on the first attempt.
- **The two-correct-answers directories** (`served-rotated/`,
  `served-superseded/`). Making acceptance depend on what the reader has
  replayed, in both directions — the informed reader is more permissive in one
  and stricter in the other — is a genuinely clever test and it forced me to
  implement §9.4's ordering properly rather than pattern-match.
- **§9.2's mapping back to CBOR.** Precise enough that a hand-written TOML
  reader reproduced `trust.cbor` byte for byte and matched the fingerprint,
  including the `witness`/`witnesses` singular-plural trap and the
  "byte strings are hex in TOML, never base64" rule.
- **§5.3's `T` discussion** — the three things "that decision needs and the rest
  of this document does not supply", and the `quorum none` argument. The
  reasoning is correct and the `proven/at-the-deadline` boundary vector is right;
  only the coverage claim about it (J7) is wrong.
- **§4.0's `dup-entry` / trailing-byte argument** and `60-bad-trailing-byte`.
  A whole class of "same governance entry applied twice" is closed by one vector
  and one paragraph.
- **§12.1's "What is not vectored" section existing at all.** It is the right
  instinct; J4, J5, J7 and J11 are failures of that list's completeness, not of
  the idea.
- **The `anchors/` OTS digest.** `checkpoint-105.ots` stamps SHA-256 of the
  checkpoint body **including** the blank separator line, exactly as §6 says —
  and the receipt's `text_sha256` uses the *other* boundary, exactly as §7 says.
  Two adjacent, easily conflated definitions, both stated precisely and both
  independently vectored. That is how the rest of the document should read.

---

## What I could not cover, and why

- **`quorum none`** accepting an uncosigned head — needs a second anchor, which
  the suite does not ship (the specification says so).
- **§10's stored-checkpoint block, §11's fork detector, §8.1 conditions 2 and 4**
  — no fixture presents a reader with a sequence of checkpoints or an elapsed
  duration, so I implemented none of them (J11). What I did verify is that the
  material for the fork detector is present and unused.
- **Multi-tile logs.** 105 entries means one partial level-0 tile and no level-1
  tile, so tile-path construction beyond `000.p/<w>`, full tiles, and any
  level ≥ 1 hash tile are untested by anything I wrote.
- **OpenTimestamps beyond the digest binding.** I confirmed the stamped digest;
  I did not parse the attestation graph, follow the calendar reply, or apply
  `anchor.max_lag`. The specification calls the anchor advisory and defers the
  format, and `anchors/` ships no `cases.json`.
- **`POST /add`, receipts as a protocol** (the `409` reason code, `mmd`
  deadlines, rate limiting) — one static `receipt.note` is the whole surface.
- **`log_key`'s `overlap`** — an obligation on the log, not checkable from a
  verifier's side, and the suite contains a single checkpoint.
- **`GOSSIP.md` / `ENFORCEMENT.md` / `ENROLLMENT.md`** — normatively deferred,
  and not supplied. The `fresh → degraded → hard-stale` machine, `/run/norn/proven.json`,
  and the witness HTTP protocol are therefore entirely outside what I could test,
  even though §8.1 condition 4 and §4.5's `staleness` reach into them.
- **Interoperability with the real libraries.** §7 and §12 lean on
  `x/mod/sumdb/note`, `transparency-dev/formats` and `x/mod/sumdb/tlog` having
  accepted these bytes. Standard-library-only, I could not re-run that check;
  I verified the bytes against my own reading of the formats instead.
- **Ed25519 edge cases** (non-canonical `S`, small-order `A`) — `crypto/ed25519`
  decides these for me and the specification says nothing, so two
  implementations on different libraries could still disagree on a hostile
  signature. Untested here and unvectored.

---

## Why the verdict is INSUFFICIENT and not SUFFICIENT WITH GAPS

The bar is the prose, not the vectors. Two findings clear it on their own:

- **J1**: a reader who implements §4.0's depth rule exactly as written fails a
  shipped vector. The document contradicts itself and its own test data.
- **J2**: a reader holding only this document cannot parse a cosignature line —
  and §7, the only place the document describes a note signature line, states a
  length that is wrong for one, under a sentence promising the reader needs
  nothing else.

J3 and J5 then add two places where two readings are both defensible, both pass
every vector, and produce materially different security properties (a proof
bundle that does or does not require witness corroboration; a genesis that does
or does not abort). J7 is a false statement in the section whose entire purpose
is to be an honest accounting.

This is a strong document — much stronger than the verdict suggests, and
stronger in the places that usually rot first. But "could not reasonably get it
wrong" is not yet true.
