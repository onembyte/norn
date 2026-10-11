# Cold gate run 14 — specification defects

Implementer: an independent cold reader. Inputs: `SPEC.md` and `testdata/vectors/` only. Everything written is under `work/`.
Implementation: Go, standard library only, `work/impl/` (package `norn`, harness `cmd/harness`, divergence builder `cmd/diverge`, probe `cmd/probe`).
Interpretation decisions: `work/decisions.md` (C01–C107), written before any vector, README or manifest was opened and not edited since.

## 1 Tally

**Host pause.** The run was paused when its host Claude Code session exited at about **16:43 -03 on 2026-10-11**, during the first single-variant sweep, and resumed at **17:03 -03** the same day. Nothing written was lost. When the host exited, seven of the eight sweep shards had finished. The eighth (`work/sweep/single-7`) had died with exit 137 on variant `dec.allowAbove63.size`. That variant admits a checkpoint size of 2⁶³, and my reader was building the whole list of implied entry bundles before fetching any, about 3.6×10¹⁶ of them. After resuming I made bundle iteration lazy, finished the shard, and then re-ran **the whole single sweep on the final code** (`work/sweep3/`), so every number below comes from the final build.

**Digests.** `testdata/vectors/SHA256SUMS` has 794 lines and all 794 verify (`shasum -a 256 -c`, and again inside the harness). Every file in the suite except `SHA256SUMS` itself is listed, and nothing is listed that is not shipped.

**First full run: 3620 checks, 3105 pass, 515 fail.** All 515 failures were in my harness's expectations, not in the implementation. The implementation was not changed to fix any of them.
- 490 `cctv/N deciding flag`: I derived each case's deciding flag from §3.1's literal listing order (`low_order_A, low_order_R, non_canonical_A, non_canonical_R, …`). The manifest uses non-canonical first. The `outcome` column agreed on all 914. The mismatch is defect L6 below. The check now asserts only that the manifest flag is one of the vector's flags, and the harness prints the 490-case mismatch as an observation.
- 24 `genesis/*/00-genesis .reason file`: I expected `.reason` files beside the `genesis/` cases, but only `log/` and `log-admission/` ship them.
- 1 `requests/req-minimal-upper mirror`: I put the canonical lowercase text in the mirror, and the mirror carries the uppercase text.

**Final run: 3607 checks, 3607 pass, 0 fail** (`work/run-final.txt`). Breakdown:

| area | checks | | area | checks |
|---|---|---|---|---|
| SHA256SUMS digests | 794 | | `entries/` decode + mirrors | 32 |
| CCTV outcomes, flag membership, point classification | 1829 | | `proofs/`, `proofs-bad/`, `proofs-rotated/` | 41 |
| `log/` (162 reasons, `.reason` files, state) | 327 | | `proven/` (T cases, grants, bundles) | 21 |
| `genesis/` + `genesis-good/` | 50 | | `log-admission/` + `log-empty/` | 20 |
| `policies/` (accept/refuse + evaluate rows) | 71 | | `receipt*` | 21 |
| `requests/` + `requests-bad/` | 98 | | `entries-hostile/` | 17 |
| `trust*` (anchor, fingerprint, TOML, good, bad) | 57 | | `staleness.json` (incl. derived ages) | 15 |
| `served*` (all served variants, large, bad, genesis) | 67 | | `detect/` | 9 |
| `fork/` | 44 | | `checkpoints-bad/` + `signature_blind_accepts` | 34 |
| `keys.json` | 48 | | caps, anchors, misc cross-checks | 11 |

`signature_blind_accepts` is computed, not asserted: a reader that never calls Ed25519 accepts exactly 04, 08, 11, 12, 16 and 31. The harness also checks that the served log's entries are `log/`'s entries in manifest order, and that each anchor `.ots` file carries its stated digest.

## 2 The sweep

**Method.** Each variant is a named switch at one decision point of the base (`V("…")` in `work/impl/norn/*.go`). The list is in `work/variant-names.txt`. Each run executes the whole suite except the 794 digest checks, which no variant can affect: 2812–2813 checks per run. A variant that fails no check is a survivor. Sweeps ran 8-way parallel. Composites ran fail-fast, stopping at the first failing check.

**Space: 374 variants.** By family: `order` 43 (every adjacent pair of every ordered list: §5.1 steps 1–8, enroll, rotate and revoke internals, the §10.1 loop, bundle, receipt and evidence steps), `field` 33, `cbor` 24 (each ban allowed, each cap moved by ±1), `policy` 25, `trust` 25, `cap` 18 (per-artifact caps ±1, none, entry-cap reuse), `evidence` 14, `tiles` 12, `grant` 10, `ed` 9, `env` 9, `note` 10, plus `b32`, `b64` per site, `dec` per site, `receipt`, `rotation`, `fresh`, `time`, `json`, `merkle`, `genesis`, `gov`, `params`, `dup`, `fork`, `cosig`, `logsig`, `revoke`, `rotate`, `sig`, `install`, `origin`, `fp`, `req`, `bundle`, `vkey` and others.

**Singles: 314 caught, 60 survive.** Each caught variant is caught by a vector that exercises its rule (first failure per variant in `work/sweep3/all-single.jsonl`).

**Survivors classified (60).**

| class | n | variants |
|---|---|---|
| equivalent (no input separates them) | 15 | `b32.firstSeparator` (HRP `norn` and the data charset contain no `1`) · `cap.requestMinus1/Plus1/None` (the largest valid request is ≈9.3 KB, so the cap changes only the layer of a refusal) · `ed.allowNegZero` (x = 0 only at the identity and the order-2 point) · `ed.allowNonCanonicalY` (probe: all 19 values y ∈ [p, 2²⁵⁵) decode to points with a torsion component) · `ed.cofactored` (§3.1 says so) · `enroll.dupWGOtherOnly` · `evidence.allowSplitAboveSize` (the conflicting split proof always fails then) · `field.witnessNameMin0` (an empty name cannot appear in a policy) · `merkle.inclusionNoSnCheck`, `merkle.consistencyNoSnCheck` (short proofs end on an interior hash, so they agree barring a SHA-256 collision) · `sig.countRepeats` · `trust.correspondenceByNoteName` · `trust.noWitnessAlgCheck` (correspondence forces the same text through the policy's 0x04 rule) |
| declared in §12.1, not equivalent | 2 | `note.lastBlankLine`, `time.noneIsSatisfiedAlways` |
| genuine, the spec is ambiguous or silent (or a wording slip) | 15 | the five grant variants (`grant.allowBareAddress`, `allowLeadingZeroBits`, `allowNetmask`, `allowZone`, `trimUnicode`) → H1 · `field.deviceIDDollarNewline` → H2 · `rotate.newKeyMustDiffer` → M1 · `tiles.rejectEmptyEntry` → M2 · `tiles.fullBundleTrailingOK`, `tiles.hashTileTrailingOK` → M3 · `cosig.tsBound63` → M4 · `note.allowEmptyName`, `note.splitOnWhitespace` → M5 · `trust.witnessKeyNotLogKey` → M6. That is 14 variants under 8 defects (the two note variants share M5). `tiles.fetchBeforeGenesis` is wording → L1 |
| genuine, the spec is clear and only the suite is silent | 28 | listed in L2 with their inputs |

(15 equivalent + 2 declared + 15 ambiguity or wording + 28 suite gaps = 60. The L2 table also carries the one genuine composite.)

**A concrete input for every genuine survivor.** `work/impl/cmd/diverge` builds 44 inputs: one per genuine single (43) plus the genuine composite. Inputs that need signatures are signed with the suite's own seeds from `keys.json` (the roots, `signer1`, device keys, `logkey`, `logkey2` and the three witnesses). The builder writes them to `work/divergence/` and runs base and variant on each. **All 44 differ** (`work/divergence/RESULTS.txt`). Where a log is needed, the replay inputs are the fixture genesis `log/0-genesis.cbor` followed by the crafted entries, under the trust anchor (`*.entries` are uint16-framed).

**Composites.**
- survivor × survivor: 1,596 pairs over the first 57 survivors, plus 230 pairs involving the three late survivors and the corrected `order.sizeBeforeConflicting`. **Two are caught**: `policy.noAlgRoleCheck + trust.noLogAlgCheck` (by `trust-bad/16`) and `policy.noAlgRoleCheck + trust.noWitnessAlgCheck` (by `trust-bad/15`). These are the trust-level and policy-level statements of the algorithm rule covering for each other (see L4). Every other pair survives, as it must when each half has its own separating input.
- survivor × caught: 17,898 pairs, plus 1,256 for the late variants. **Nine escapes** (seven distinct pairs, one of which appears in both runs, plus one genuine). Eight collapse onto a single decision point or onto an existing survivor: `grant.trimUnicode+grant.noTrim`, `field.genesisNameMin2+…Min0` and `field.trustNameMin2+…Min0` are two switches on one decision. `note.lastBlankLine+note.trimTrailingNewlines`, `order.policyBeforeSchema+evidence.policyUnparsed` and `order.policyBeforeSchema+order.heldBeforePolicy` reduce to their first member. `order.sizeBeforeConflicting+order.proofBeforeSize` appears twice, once before and once after the fix; it reduces to its first member. **One is genuine: `order.revokeKnownBeforeBody + field.reasonCapMinus1`.** The only vector that pins the 256-byte `reason` cap from below (`log/143-bad-revoke-reason-at-the-cap`) names an unknown device, so moving the device lookup ahead of the body check hides a 255-byte cap. Input: `work/divergence/composite.revokeKnown+reasonCap.entries`, an authorised revoke of an active device with a 256-byte reason. Base: accepted. Composite: `decode`.

One variant was mis-implemented and corrected during the run. `order.sizeBeforeConflicting` first evaluated the size rule only on a *verified* conflicting checkpoint, so it could never fire before the `conflicting` refusal. It now reads the unverified size, and it still survives, with a real input.

## 3 Defects

### H1 — §4.0 never says what "an IPv4 or IPv6 prefix" is, and the grant decides allowed-ips

**Words.** §4.0: "A node derives the grant from the label alone — the label split on commas, each part **trimmed and parsed as an IPv4 or IPv6 prefix**, masked to its prefix, duplicates removed, sorted as text — and a label that is absent or does not parse **as a whole** is **no grant**". §13.1: under `routes = "granted"` the grant bounds a peer's allowed-ips.

**What a second implementer cannot know.** Neither the prefix syntax nor the trim set is given. The suite's provenance says the entry and state vectors come from a **Python** reference. The other implementation is **Go**. The two standard libraries disagree on realistic labels. I compared them locally (no network) in `work/impl/cmd/probe` and with `python3 -I`:

| `ip` label | Go `net/netip` (base) | Python `ipaddress.ip_network(strict=False)` after `str.strip()` |
|---|---|---|
| `10.9.1.5` (a bare host — what an operator writes for one address) | no grant | `10.9.1.5/32` |
| `10.9.1.0/024` | no grant | `10.9.1.0/24` |
| `10.9.1.0/255.255.255.0` (netmask) | no grant | `10.9.1.0/24` |
| `10.9.1.0/0.0.0.255` (hostmask) | no grant | `10.9.1.0/24` |
| `fe80::1%eth0/64` (zone) | no grant | `fe80::/64` |
| `10.9.1.0/24, fd00::/64` (NBSP after the comma) | no grant (ASCII trim) | both prefixes (Unicode trim) |
| `1.2.3.4/32　` | no grant | `1.2.3.4/32` |

Both readers conform to the sentence above. The label is chosen by the device in its own request, which §16.1 makes the device's consent, and signed by a signer who sees an ordinary-looking value. So two conforming nodes install different allowed-ips for the same peer, and publish different `grant` arrays in `proven.json`, from one entry in the log. Rendering is not the problem: both libraries print RFC 5952 forms identically on every case I tried.

**Proof.** Survivors `grant.allowBareAddress`, `grant.allowLeadingZeroBits`, `grant.allowNetmask`, `grant.allowZone` and `grant.trimUnicode`. Inputs `work/divergence/grant.*.cbor`: signed `enroll` entries whose embedded requests are signed by suite device keys. Base gives no grant; each variant gives the grant shown. `proven/cases.json`'s `grants` cover only `router` (CIDR with host bits), `badgrant` (`, nope`) and absent labels.

**Smallest change.** Give the grammar: "each part, after removing ASCII space and tab at both ends, MUST be `<address>/<length>`, where `<address>` is a dotted-quad IPv4 address with no leading zeroes or an RFC 4291 §2.2 IPv6 text address with no zone, and `<length>` is canonical decimal within the family's range. Anything else, including a bare address, a netmask and an empty part, is no grant." Then add one vector per row above to `proven/`.

### H2 — the `device_id` regex has dialect-dependent end anchoring

**Words.** §4.0 field constraints: "`device_id` | matches `^[a-z0-9][a-z0-9.-]{0,63}$`". §2: "UTF-8 string, 1–64 bytes".

**What a second implementer can get wrong.** In Python's `re`, the reference's language, `$` also matches *before a final newline*. In Go's RE2 and in JavaScript it matches only at the end. Ruby's `$` is an end-of-line anchor. Checked locally: `re.match(r"^[a-z0-9][a-z0-9.-]{0,63}$", "nas\n")` matches, and `re.fullmatch` does not. The 1–64-byte bound does not help: `"nas2\n"` is 5 bytes. `kid` is protected by its explicit "exactly 16 characters" and `device_id` has no such guard. The device chooses its `device_id` in its own request.

**Proof.** Survivor `field.deviceIDDollarNewline`. Input `work/divergence/field.deviceIDDollarNewline.cbor`: an `enroll` signed by `signer1` whose request (signed by the `printer` device key) names `nas2\n`. Base: `decode`. Variant: accepted, so the two readers' canonical states differ (different `rejected`, a new device, a new `active_wg` entry) and so do their peer tables.

**Smallest change.** "matches `[a-z0-9][a-z0-9.-]{0,63}` as a whole: every byte of the string, and no other byte" (or write the anchors as `\A…\z`). Add a vector with a trailing LF.

### M1 — `rotate` to the key the device already holds is unspecified, and §5.2 calls it impossible

**Words.** §4.3 `rotate`: "the *current* device key; **and the incoming `device_pk` too when the body carries one**". §5.1: "if the body carries `device_pk`, a valid `device` signature by **that** key as well". §5.2: "The incoming key is **by construction not in the state before the entry**".

**Ambiguity.** If the body's `device_pk` equals the current one, `sigs` can hold only one element for that `kid`, because the array is sorted and unique. Reading "as well" as needing a second signature refuses the entry. So does inferring from §5.2 that an incoming key must be new. My base (C26) accepts it, with one signature satisfying both checks. The device itself authors this entry. Nodes then disagree on its `wg_pk`, and their canonical states differ.

**Proof.** Survivor `rotate.newKeyMustDiffer`. Input `work/divergence/rotate.newKeyMustDiffer.entries`: enrol `x2` with the `astral` key, then a `rotate` with `device_pk = astral`, signed by `astral`. Base: accepted. Variant: `decode`.

**Smallest change.** One sentence in §5.1: "A `device_pk` equal to the current one is permitted, and one signature by it satisfies both device checks." Correct §5.2's "by construction" to "need not be". Add a vector.

### M2 — a zero-length entry in a bundle: framed, or not?

**Words.** §6: "An entry bundle is each entry's length as a **big-endian** uint16 followed by that many bytes, repeated". §10.1 step 8: "the entry bundles … do not frame … or do not add up to that size".

**Ambiguity.** Nothing says whether length 0 frames. Under my base (C69) it frames, and replay later refuses it as `decode`. A reader that treats it as a framing error refuses the whole checkpoint as `entries`, and goes on refusing every later head of that log. The log alone can produce this, since operator validation is "optional and non-binding". The result is that some nodes advance and others degrade toward `hard_stale`.

**Proof.** Survivor `tiles.rejectEmptyEntry`. Input `work/divergence/tiles.rejectEmptyEntry.*`: the 162 fixture entries plus one empty entry, with a correct bundle and level-0 tile, signed by `logkey` and cosigned by all three witnesses. Base: accepted (index 162 is `decode` in replay). Variant: `entries`.

**Smallest change.** "A frame of length 0 is well-framed; the empty entry is refused by replay (`decode`)." Or forbid it. Either way, add a vector.

### M3 — exactness is stated for partial bundles only, and for no hash tile

**Words.** §6: "A **partial** bundle holds **exactly** the number of entries its path declares." §10.1 step 12: "a served hash tile disagrees with the rebuilt tree".

**Ambiguity.** For a full bundle (256 entries) followed by trailing bytes, and for a hash tile longer than `32 × width`, the text does not say whether the extra bytes refuse. A reader that consumes 256 frames, or `width` hashes, and stops is reading the words as written. The log can serve either shape, and nodes then split between accepting and refusing (`entries` or `tiles`).

**Proof.** Survivors `tiles.fullBundleTrailingOK` (input: `served-large`'s full bundle `tile/entries/000` plus `00 00`; base `entries`, variant accepts) and `tiles.hashTileTrailingOK` (input: `served/tile/0/000.p/162` plus 32 zero bytes; base `tiles`, variant accepts). `overfull-entry-bundle` exercises only the partial bundle.

**Smallest change.** "Every bundle, full or partial, frames exactly its width with no trailing bytes; every hash tile is exactly 32 × width bytes." Add the two vectors.

### M4 — does D-076's 2⁶³−1 bound cover a cosignature's timestamp?

**Words.** §6: "at most 2⁶³−1 — §4.0's bound on every integer, and **one bound for every decimal line a note carries** (D-076)". §7: the timestamp is "an unsigned 64-bit big-endian count", and it is signed as `"time " ‖ <timestamp as decimal>`.

**Ambiguity.** The timestamp is a binary field of a signature line and is rendered as a decimal line in the signed message. "Every integer" and "every decimal line" can both be read to cover it. My base (C60) accepts any uint64. A reader that applies the bound refuses the line, and §10 then refuses the whole checkpoint as `cosignature`. A listed witness that emits such a timestamp splits nodes between accepting and refusing. Under acceptance, that timestamp also takes part in computing T.

**Proof.** Survivor `cosig.tsBound63`. Input `work/divergence/cosig.tsBound63.checkpoint`: the served head with `pi` re-cosigning at 2⁶³. Base: accepted, T = 1760003607. Variant: `cosignature`.

**Smallest change.** "A cosignature timestamp above 2⁶³−1 fails that witness's check (`cosignature`)", or state that the bound does not apply to it. Add the vector.

### M5 — a signature line's name has no grammar beyond "contains no space"

**Words.** §7: "The note framing asks of every signature line only what needs no key: the prefix, **a name**, and canonical padded base64…". Also: "A key name **contains no space**, so the line splits at its first space".

**Ambiguity.** Two cases. (a) Is the empty string "a name"? `—  <b64>` frames under one reading and is `note` under the other (my C57: refuse). (b) "Space" can mean U+0020 or any whitespace. `— a\tb <b64>` is an ignorable stranger's line under the first reading and a framing error under the second, because the payload becomes `b <b64>`. Anyone relaying a checkpoint (a proven peer, §15) can append such a line to an honest head, and nodes then split between accepting it and refusing it as `note`.

**Proof.** Survivors `note.allowEmptyName` (input `work/divergence/note.allowEmptyName.checkpoint`: base `note`, variant accepts) and `note.splitOnWhitespace` (input `…splitOnWhitespace.checkpoint`: base accepts, variant `note`).

**Smallest change.** "A signature line's name is one or more bytes other than U+0020 and LF; the line splits at its first U+0020." Add the two vectors.

### M6 — a trust file may give a witness the log's own public key when its policy has no `log` line

**Words.** §9.1 `keys`: "a verifier key appears **once** in a policy … This applies across `log` and `witness` lines". §7: "the same public key published under `0x01` and `0x04` is two different verifiers". §9.1 `log` lines: "**not required**".

**Ambiguity.** The duplicate rule runs over the *policy text*. A trust file whose policy omits the optional `log` line can list a witness whose key is the log key under 0x04. Read one way, that is permitted ("two different verifiers"). Read the other way, it is refused (the duplicate rule's own rationale: one key must not count twice, here the log cosigning itself). My base permits it. This is reachable only through an operator's trust file, and nodes provisioned from that file split between starting and refusing to start.

**Proof.** Survivor `trust.witnessKeyNotLogKey`. Input `work/divergence/trust.witnessKeyNotLogKey.trust.cbor`: base valid, variant invalid.

**Smallest change.** "A trust file's `log_key` takes part in the policy's duplicate-key rule whether or not a `log` line names it." Add `trust-bad/51`.

### L1 — §10.1 numbers the hash-tile fetch as step 11, which is `genesis`

**Words.** §10.1 step 1: "an entry bundle (step 8), **a hash tile (step 11)** — reported at that step". The same table puts `genesis` at 11 and `tiles` at 12. `served-bad/cases.json` repeats "step 11 needs the hash tile".

**Consequence.** A reader that fetches the tiles at step 11, before the genesis check, answers `unserved` where the base answers `genesis`, on a log that is refused either way. Survivor `tiles.fetchBeforeGenesis`: `detect/other-genesis` with its hash tile removed gives base `genesis`, variant `unserved`. The neighbouring order is equally unpinned: `order.tilesBeforeGenesis`, with a tampered tile over the same log, gives base `genesis`, variant `tiles`.

**Change.** "(step 12)". Add the two-fault vector.

### L2 — §12.1 says the unvectored MUSTs "are named there", and 29 genuine gaps are not

**Words.** Preamble: "It does **not** claim every MUST is vectored — several are not, **and they are named there**." §12.1: "Everything else named in the table above ships".

In each row below the spec text is unambiguous. A careful reader gets it right, and the suite would not notice one who did not. Each row was found by a surviving variant and has an input in `work/divergence/`, on which base and variant disagree.

| rule (section) | surviving variant | input → base / variant |
|---|---|---|
| integers ≤ 2⁶³−1, upper value accepted (§4.0) | `cbor.intBoundStrict` | `note` with `ts = 2⁶³−1` → accepted / `decode` |
| re-enrolment replaces the record (§5.3) | `enroll.keepOldLabels` | enrol with `ip`, revoke, re-enrol without labels → `{}` / old `ip` and its grant kept |
| `size` 0 never passes (§11.1 step 3) | `evidence.allowSizeZero` | two cosigned size-0 heads with different roots → `proof` / fork proven (permanent, §11 rule 4) |
| genesis name ≥ 1 byte, lower side (§4.0) | `field.genesisNameMin2` | 1-byte name → accepted / `bad-genesis` |
| genesis body closed (§4.0) | `genesis.openBody` | genesis with an extra body key → `bad-genesis` / accepted |
| trust `name` 1–64 (§9.1), both sides | `field.trustNameCap63`, `Cap65`, `Min2` | 64-, 65- and 1-byte names |
| witness `name` 1–64 (§9.1) | `field.witnessNameCap63`, `Min2` | `pi` renamed to 64 bytes / to 1 byte |
| IPv4-mapped is no grant (§4.0) | `grant.allowMapped` | `::ffff:10.0.0.1/128` → none / granted |
| note lines end in LF only (§7) | `note.trimCR` | the served head with CRLF → `note` / accepted |
| receipt has exactly four lines (§7 step 3) | `receipt.atLeastFourLines` | five-line receipt, re-signed → `receipt` / accepted |
| receipt origin equality (§7 step 4) | `receipt.originCaseFold` | origin with one letter upper-cased → `origin` / accepted |
| request `device_pk` is a valid point (§3.1 item 2) | `req.noPointCheck` | `enroll` whose request key is the identity → `decode` / `no-device-sig` (canonical state differs) |
| witness vkey is 0x04 in a `policy` entry (§9.1) | `policy.noAlgRoleCheck` | root-signed policy entry with an 0x01 witness key → `decode` / accepted |
| trust `log_key` is 0x01 without a `log` line (§9.1) | `trust.noLogAlgCheck` | → invalid / valid |
| learned key named the origin (§9.4) | `rotation.learnedByPKAnyName` | served head signed by `logkey2` under `elsewhere/log` → `log-signature` / accepted (informed reader) |
| learned key valid for any head (§9.4) | `rotation.learnedOnlyAboveSince` | 20-entry head signed by `logkey2` (published at index 27) → accepted / `log-signature`; in fork evidence this decides whether an accusation is made |
| §5.1 rotate: body before `unknown-device` | `order.rotateKnownBeforeBody` | malformed rotate for an unknown id → `decode` / `unknown-device` |
| §5.1 revoke: body before `unknown-device` | `order.revokeKnownBeforeBody` | same, for revoke |
| §10.1 steps 4/5 | `order.originBeforeBody` | four-line body and wrong origin, log-signed → `checkpoint` / `origin` |
| §10.1 steps 5/6 | `order.cosigBeforeOrigin` | wrong origin and a forged `pi` line → `origin` / `cosignature` |
| §10.1 steps 7/8 | `order.entriesBeforeQuorum` | log-only head at size 163 → `quorum` / `unserved` |
| §10.1 steps 11/12 | `order.tilesBeforeGenesis` | see L1 |
| bundle steps 1/2 | `order.bundleVersionAfterCheckpoint` | `v: 2` plus an untrusted checkpoint → `bundle` / `log-signature` |
| §11.1 steps 3/4 | `order.policyBeforeSchema` | unparseable policy and an unknown key → `schema` / `policy` |
| §11.1 steps 6/7 | `order.sizeBeforeConflicting` | unverifiable conflicting and size ≠ its size → `conflicting` / `size` |
| `reason` ≤ 256, accepted side (§4.0) | composite `order.revokeKnownBeforeBody + field.reasonCapMinus1` | authorised revoke with a 256-byte reason → accepted / `decode` |

**Change.** Add each row's input as a vector, or list the row under "What is not vectored". The `log`, `trust-bad`, `checkpoints-bad`, `receipt-bad` and `fork` directories already have the right shape for every one.

### L3 — §3.1's canonical-encoding clauses are redundant with the order check, and two vectors claim to isolate one

**Words.** §3.1 item 1: "the encoded `y` is below `p`, **the sign bit is 0 when `x` is 0**, … `[L]P = O` and `P ≠ O`". README for `genesis/`: "`24-root-noncanonical` … so only §3.1 aborts them", with the rule "the sign bit is 0 when `x` is 0". README for `trust-bad/47`: "uses the negative-zero x encoding … so only §3.1 invalidates the anchor".

**Fact.** Every encoding that fails either canonical clause decodes, under a lenient decoder, to a point that the order clause refuses. x = 0 occurs only at the identity and the order-2 point. I computed all 19 values y ∈ [p, 2²⁵⁵) (`work/impl/cmd/probe noncanon`): each is off the curve or carries a torsion component. So `ed.allowNegZero` and `ed.allowNonCanonicalY` are *equivalent* mutants, and no vector can isolate those clauses, `24` and `47` included. Nothing a node does changes. The vectors pin §3.1, not the clause they name.

**Change.** Say so in §3.1, along the lines of "the canonical clauses are implied by `[L]P = O ∧ P ≠ O`; they are stated because libraries decode differently", and list it under §12.1's unvectored items.

### L4 — three coverage claims are wider than their vectors

- §12.1, policy grammar row: "Negatives: … **role-mismatched algorithms**". `policies/bad-witness-vkey-algorithm` gives its witness the *same* public key as its `log` line, so the duplicate-key rule refuses it too, and `policy.noAlgRoleCheck` survives. That matters in a `policy` *entry* (L2 row).
- §12.1, trust row: "**`15`** and **`16`** … are refused **only by the algorithm rule**". Each carries its key into the policy, where the policy grammar's algorithm rule refuses it again. The trust-level rule alone is unpinned (`trust.noLogAlgCheck` survives), and only the composite with `policy.noAlgRoleCheck` is caught.
- §11.1: "**Each step has a vector** in `fork/`". `bad-size-zero`'s held head is non-empty, so RFC 9162's own `m > 0` refuses it without the stated size-0 rule (`evidence.allowSizeZero` survives; L2 row).

### L5 — §12's table counts 45 trust-bad files, and 48 ship

**Words.** §12: "`trust-bad/<NN-case>.cbor` | **45 trust files**". `trust-bad/cases.json` lists 48, the directory holds 48, and §12.1 says "**48 rejected anchors**". **Change:** "48".

### L6 — `ed25519-cctv/cases.json` claims §3.1's listing order and uses another

The manifest comment says "Derived from ed25519vectors.json's flags in SPEC.md **§3.1's listing order**". §3.1 lists `low_order_A, low_order_R, non_canonical_A, non_canonical_R, low_order_component_A, low_order_component_R`. The generator (`gen_cases.py`) orders `non_canonical_*` first, and 490 of the 913 rejects name a different deciding flag than the literal listing gives. Every `outcome` is unaffected. **Change:** reorder the list in §3.1 or in the generator.

### L7 — the suite README contradicts SPEC on closed codes

`testdata/vectors/README.md`: "§5.2 gives replay a closed list of reason codes and **no other layer has one**, so outside replay there is nothing to compare". SPEC §7, §10.1 and §11.1 each define a closed list, and §12 tells readers to compare the `codes` maps. SPEC governs, but the README sits beside the vectors and a reader may take it as authoritative. **Change:** delete or correct the paragraph.

## 4 Declared survivors — §12.1's "What is not vectored", each checked

| §12.1 item | checked by | result |
|---|---|---|
| §3.1 on a policy's optional `log` line | reasoning: `vkey.noPointCheck` is caught only through witness keys (`trust-bad/47`, `log-admission/07`) | confirmed unvectored as declared |
| source-neutral checkpoint acquisition | no static check involves a source | confirmed |
| §13 reconciliation, `proven.json` | `AllowedIPs` (§13.1) is exercised by no check, so any change to it survives | confirmed. §13.1's routes intersection belongs here too |
| §16.3 key handling | no artifact | confirmed |
| `none` as a group member vs undefined | `policy.allowNoneMember` is caught by `bad-none-group-member`, but a reader reporting "undefined" gives the same result | confirmed indistinguishable |
| CR inside a policy verifier key | the control-byte rule refuses it before the key parser; `vkey.lenientBase64` is caught only by `trust-bad/44` (`log_key`) | confirmed |
| OpenTimestamps attestations | the harness checks only digests and byte ranges | confirmed |
| `quorum none` accepting an uncosigned head | `time.noneIsSatisfiedAlways` survives | confirmed |
| "a key contributes at most once" | `sig.countRepeats` survives (equivalent); `env.sigsRepeatOK` is caught by `log/134` | confirmed |
| "must not count it even in the moment before that refusal" | not expressible in a static file | confirmed |
| order of entry 0's steps | one code (`bad-genesis`) | confirmed |
| a blank line inside note text | `note.lastBlankLine` survives (codes differ, both refuse) | confirmed |
| §10 root "never from a supplied proof" | no shipped file supplies a proof | confirmed |
| §16.1's 32-byte `device_pk` independently | a 31-byte key never verifies | confirmed |
| `state.net` from the anchor | entry 0 aborts whenever they differ | confirmed |
| `entry_hash` as received vs re-canonical | non-canonical bytes are `decode` first | confirmed |
| `MAX_ENTRY_BYTES` on an embedded request | `cap.requestMinus1/Plus1/None` survive. Stronger than declared: no valid request comes within 56 KB of the cap, so the bound never changes an outcome even for a standalone request | confirmed, equivalent |
| witness key = cosignature key at verification | unreachable behind §9.1 | confirmed |
| `dup-wg` for `enroll`: any vs another device | `enroll.dupWGOtherOnly` survives (equivalent) | confirmed |

Every declared item holds. The list is incomplete: H1–M6 and the L2 rows are not on it.

## 5 Decisions the vectors pinned, and decisions they did not

**Pinned.** A variant at the decision point is caught by a named vector:
C02 (S < L, R checks) · C03 · C05 · C06 upper side · C07 · C08 · C09 · C10 · C11 · C12 (entry, bundle, trust and evidence caps on both sides) · C13 · C14 · C15 · C16 · C18 · C19 · C20 (uppercase, leading dot, 63/65) · C21 · C22 · C23 (masking, whole-label failure, ASCII-space trim) · C24 · C25 (request `net`, `expires > ts`) · C27 · C28 (role) · C29 · C30 (overlap and threshold booleans) · C31 · C32 · C33 · C34 · C35 · C37 · C38 · C39 · C40 · C41 (all pairs but one) · C42 · C43 · C44 · C45 · C46 (parse) · C47 · C48 · C49 · C50 · C51 · C52 · C53 · C54 · C56 · C58 · C59 · C61 · C62 (pairs 2/3, 3/5, 6/7) · C64 · C65 (order pairs) · C66 · C67 · C68 · C70 · C71 · C73 · C74 · C75 · C76 · C77 · C78 · C79 · C80 · C81 · C82 · C83 · C84 · C85 · C86 (name) · C87 (65-byte witness name) · C88 · C89 · C90 · C92 · C93 (inclusion/binding, checkpoint/inclusion) · C94 · C95 · C96 · C98 (most pairs) · C100 · C102 · C103 · C104 (constant, case, HRP) · C106.

**Not pinned.**
- C01's canonical sub-clauses and C02's equation choice: equivalent, so unpinnable (L3).
- C06 at the 2⁶³−1 value itself.
- C17 and C36: unobservable.
- C20 trailing newline (H2).
- C23 prefix syntax and trim set (H1).
- C25 request `device_pk` point.
- C26 (M1).
- C30 genesis body closedness.
- C46 algorithm role in `policy` entries.
- C55 (declared).
- C57 (M5).
- C60 (M4).
- C62 pairs 4/5, 5/6, 7/8.
- C63 learned-key naming and activation.
- C65 exactly four lines, origin case.
- C69 (M2).
- C72: no observable difference.
- C84/C87 name bounds on one side.
- C91 (M6).
- C93 pair 1/2.
- C97 (L1).
- C98 pairs 3/4 and 6/7.
- C99 size 0 with an empty held head.
- C101: not a decision a file can test.
- C105: harness file framing only.
- C107 (§13, declared).
- Also unpinned by any manifest: §6 full-bundle and hash-tile exactness (M3).

## 6 Verdict

The implementation reproduces every check in the suite: 3607 of 3607, 794 of 794 digests. Of 374 single-decision variants, 60 survive. 43 of them are genuine and have concrete, signed, divergent inputs, and composites add one more. Most are suite gaps under clear text. Two are network-visible ambiguities that two conforming implementations in the suite's own two languages resolve differently on device-authored entries: the grant's prefix syntax (H1) and the `device_id` regex's end anchor (H2). Six more are M ambiguities reachable through a log, a relaying peer, a witness or an operator's trust file.

SPEC INSUFFICIENT
