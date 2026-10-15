# Cold gate run 16 — specification defects

Reader: an independent implementer working from `SPEC.md` and `testdata/vectors/` only,
in `/Users/francomichetti/dev/security/norn-lanes/sealed-run16b`. No other copy of the
project, no web, no network. Implementation: Go 1.26.4, standard library only, under
`work/impl/` (package `norn`, harness `cmd/harness`, sweep and input builder
`cmd/survivors`). Ed25519 verification is my own (RFC 8032 with `math/big`, profiled by
§3.1). The proof verifiers follow RFC 9162 §2.1.3.2 / §2.1.4.2, and bech32m follows
BIP-350, all from memory of the standards. `crypto/ed25519` is used only to sign
constructed inputs and in one cross-check test. The decisions log (`work/decisions.md`,
C01–C73) was written before any vector file was opened and has not been edited since.

## 1 Tally

| run | checks | pass | fail |
|---|---|---|---|
| first full run (`work/run1-first.txt`) | 3042 | 3042 | 0 |
| final run (`work/run-final.txt`, final binary, every variant switch off) | 3042 | 3042 | 0 |

The first full run had no failures, so there is no first-run failure to report.
Before the first run I wrote the whole implementation and the harness from
`SPEC.md` and the manifests' shapes, and I checked nothing against expected values
before it.

Because a clean first run proves little on its own, I confirmed that the harness
discriminates. Spot variants fail as expected: `dup-bytes-only` fails
`log/114…117`, `tile-no-check` fails `served-bad/tampered-hash-tile`, and
`cp-cosig-skip-failing` fails `checkpoints-bad/08,11,12`. A unit test also checks my
Ed25519 verifier against `crypto/ed25519` on 200 honest and mutated signatures, and
bech32m round-trips.

What the 3042 checks are. One check per line, the exact closed code compared wherever
a manifest gives one:

- `sums` 984: every digest in `SHA256SUMS`, recomputed in Go. I also checked them with
  `shasum -c` before implementing: 984/984 OK, covering every file but `SHA256SUMS`.
- `cctv` 914; `keys` 30; `hostile` 17 (refusal category mapped from `says`).
- `trust` 4 (`trust.cbor`, fingerprint, TOML→CBOR rebuild byte for byte, the
  unreached-witness anchor); `trust-bad` 52; `trust-good` 9.
- `policies` 76 (65 parse verdicts + 11 `evaluate` rows).
- `entries` 32 (canonical re-encoding + §14 mirror, byte for byte).
- Replay, every entry's reason, every `.reason` file, every `codes` map and every
  `state.json` byte for byte: `log` 277, `log-edges` 24, `log-republish` 28,
  `log-order` 43, `log-cas` 68, `log-admission` 15, `log-empty` 1, `genesis` 78,
  `genesis-good` 6.
- `served` 4 (accept, replayed state = `state.json`, `T` = 1760003607, replayed-policy
  `T` = 1760003600); `checkpoints-bad` 47 (46 codes + the computed
  `signature_blind_accepts` set, which equals the shipped six); `served-extra-witness`,
  `served-name-collision`, `served-stranger-name`, `served-unknown-algorithm` 1 each;
  `served-twice-cosigned` 2 (accept, `T` = 1760003614); `served-superseded` 2;
  `served-rotated` 3; `served-rotated-wrong-name` 2; `served-rotated-earlier` 2;
  `unreached-witness` 2; `served-large` 42 (accept, implied tiles, the 40-row path
  table); `served-bad` 7; `served-large-bad` 2; `served-empty-entry` 3;
  `served-genesis` 4.
- `receipt` 2 (accept; `receipt.json` matches the note), `receipt-bad` 19,
  `receipt-rotated` 2.
- `requests` 36 (text→bytes, canonical text, uppercase twin, accept, mirror);
  `requests-bad` 30.
- `proofs` 19 (8 bundles + 8 `installs` + cap + origin + right edge); `proofs-bad` 15;
  `proofs-rotated` 2.
- `proven` 21 (4 evaluation times, grants, the bundle join); `grant-labels` 39.
- `fork` 46 (11 sound, 34 coded, `conflicting.checkpoint` = the evidence's).
- `detect` 9; `staleness` 15 (12 states + 3 derived ages); `anchors` 3.

## 2 The sweep

**Mechanism.** Each variant is a named switch at one decision point of the base, so the
base runs with every switch off. A variant changes exactly one decision. The harness
runs the whole suite (all 3042 checks) under each variant. A variant that fails no
check is a **survivor**. Variants are registered with the decision or rule they flip
(`work/bin/harness -list`, 456 lines).

**Counts (final sweep, `work/sweep-final.txt`).** 456 single variants: **404 caught,
52 survive.**

| area | variants | survive | | area | variants | survive |
|---|---|---|---|---|---|---|
| cbor (profile) | 25 | 1 | | replay rules | 68 | 7 |
| envelope | 14 | 2 | | order (§5.1 internals) | 32 | 1 |
| fields | 37 | 2 | | prev | 8 | 1 |
| dup (seen sets) | 9 | 4 | | ed25519 | 9 | 3 |
| note framing | 16 | 3 | | checkpoint (§10.1 2–7) | 26 | 4 |
| receipt | 13 | 1 | | verifier loop | 16 | 0 |
| tiles | 8 | 2 | | merkle | 4 | 1 |
| bundle | 12 | 2 | | evidence | 25 | 4 |
| trust | 36 | 4 | | vkey | 6 | 0 |
| policy grammar | 32 | 3 | | rotation (§9.4) | 8 | 2 |
| grant | 17 | 2 | | json (§14) | 10 | 0 |
| time (§5.3 T) | 6 | 1 | | freshness | 7 | 0 |
| bech32 | 9 | 1 | | request | 2 | 1 |
| replay (empty log) | 1 | 0 | | | | |

The enumeration covers:

- every profile ban, in both directions; each cap one byte or one unit either side
  (entry 65534/65536, bundle 65535/81918/81920, trust 65535/65537, evidence
  65535/65537, depth 7/9/scalars, key cap 22/24/chars/empty, labels 31/33, values
  255/257/chars/min-1, reason, text and name caps both sides);
- every field rule;
- every adjacent pair of every ordered list: §5.1 steps 1–8, each type rule's
  internal order, §10.1 loop and bundle, §11.1 0–9, §7 receipt 1–8;
- every comparison: origins (equality, prefix, case fold) in checkpoint, receipt and
  trust; key ids (name-only, id-only, by public key); vkey id case and recomputation;
  correspondence (names-only, by-pk, subset, superset); public-key disjointness rules;
- every encoding choice: canonical base64 at each site, decimal canonicality and
  bounds, JSON escapes and key order, CBOR key order, bech32 constant and case;
- the grammar rules: the policy grammar, device_id, the grant grammar, signature-line
  names;
- key and policy rotation: name binding, replace vs keep, latest-only, activation
  index, retirement, policy accumulate, policy log lines;
- freshness and age; expiry boundary and no-clock behaviour; the text layers;
- the tile paths, the full-tile fallback, prefix compare, level-0-only, MTH split,
  consistency prepend, parity inclusion and exact proof length.

**Survivors classified (52).**

*A. Equivalent mutants: no input separates them from the base (10).*

| variant | why no input can separate |
|---|---|
| `b32-separator-first-1` | HRP `norn` has no `1` and the data charset has none |
| `ed-cofactored` | with `A` and `R` both of order exactly `L`, the two equations agree (§3.1 item 3 says so) |
| `env-net-type-lax` | `net` is compared with the 16-byte anchor anyway |
| `evidence-split-above-size-ok` | a split above `size` = conflicting's size cannot have a consistency proof to conflicting, so step 8 refuses it regardless |
| `note-split-last-space` | names hold no space and base64 holds none |
| `trust-witness-alg-any`, `trust-witness-name-any-utf8`, `trust-witness-name-cap-65` | correspondence puts the witness key and name into the policy, whose grammar refuses them (§12.1 admits this for `15`/`16`) |
| `dup-genesis-not-recorded` | masked by my C24 reading (the genesis content key also catches every byte copy); caught in composite with `dup-genesis-content-not-recorded` |
| `pol-utf8-check` | differs only on a policy given as raw bytes; every policy a node sees arrives as CBOR text, already UTF-8 |

*B. Declared survivors (§12.1 "What is not vectored"), confirmed (12).*
`enr-dupwg-other-device`, `entry-hash-recanonical`, `state-net-from-genesis`,
`req-no-size-cap`, `sig-count-repeats`, `genesis-sigs-before-body`,
`pol-none-member-as-name`, `pol-vkey-lax-base64`, `ed-lenient-y`,
`ed-lenient-sign-zero` (computed: none of the 38 encodings with `y ∈ [p, 2²⁵⁵)`,
either sign, decodes leniently to a point of order `L`), `quorum-none-needs-a-cosignature`,
`t-quorum-none-unbounded`. Section 4 goes through each.

*C. Genuine survivors: a concrete input separates base and variant (30).* All 30
inputs are built by `work/bin/survivors` under `work/survivor-inputs/`, signed where
needed with the suite's own keys (`keys.json` seeds: roots, signers, `logkey`,
`logkey3`, witnesses, devices), and both answers are printed in
`work/survivors-report.txt`.

| variant | input (under `work/survivor-inputs/`) | base | variant | class |
|---|---|---|---|---|
| `cbor-simple-twobyte-bool` | `log-order-03-params-twobyte-true.cbor` in place of `log-order/03` | idx 3 `decode`; idx 4 `stale-state`; `rotate_needs_signer` false | idx 3 applied; idx 4 `threshold`; true | defect M1 |
| `evidence-policy-no-point-check` | `evidence-carried-policy-small-order.cbor` | `policy` | fork proven | defect M2 |
| `merkle-proof-extra-ok` | `nas-proof-padded.bundle` | `inclusion` | accept | defect M3 |
| `dup-genesis-content-not-recorded` | `genesis-copy-extra-sig.cbor` after `log/0` | `1:dup-entry` | `1:dup-genesis` | defect L1 |
| `listed-trust-file-witnesses` | `policy-drops-friend.cbor` replayed, then `checkpoint-forged-friend-after-drop` | accept | `cosignature` | defect L2 |
| `tile-full-for-partial` | `tile-full-log/` (600 entries, head at 300, `tile/0/001.p/44` absent, `tile/0/001` served) | `unserved` | accept | defect L3 |
| `trust-logkey-no-point-check` | `trust-small-order-log-key.cbor` | invalid | valid | defect L4 |
| `policy-text-no-cap` | `policy-over-4096.cbor` after `log/0` | `1:decode` | applied | defect L5 |
| `cp-log-match-keyid-only` | `checkpoint-stranger-with-log-keyid` | accept | `log-signature` | gap (L8) |
| `cp-cosig-match-keyid-only` | `checkpoint-stranger-with-pi-keyid` | accept | `cosignature` | gap (L8) |
| `rev-device-sig-from-any-device` | `revoke-nas-by-laptop-key.cbor` after `log/0..3` | `4:threshold`, nas active | applied, nas revoked | gap (L8) |
| `prev-gov-absent-at-zero` | `signer_add-no-prev-at-version-0.cbor` | `1:stale-state` | applied | gap (L8) |
| `env-ts-optional` | `note-without-ts.cbor` | `1:decode` | applied | gap (L8) |
| `label-value-min-1` | `enroll-empty-label-value.cbor` | applied | `1:decode` | gap (L8) |
| `logkey-vs-policy-log-lines` | `policy-names-logkey3.cbor`, `log_key-logkey3.cbor` | applied | `2:dup-key` | gap (L8) |
| `policy-log-lines-trusted` | `checkpoint-signed-by-logkey3` after that policy | `log-signature` | accept | gap (L8) |
| `tile-verify-level0-only` | `served-large-level1-tile-tampered.bin` at `tile/1/000.p/1` | `tiles` | accept | gap (L8) |
| `note-no-keyid-minimum` | `checkpoint-stranger-3-byte-payload` | `note` | accept | gap (L8) |
| `note-del-forbidden` | `checkpoint-stranger-name-with-DEL` | accept | `note` | gap (L8) |
| `rc-origin-prefix` | `receipt-origin-suffix.note` (re-signed) | `origin` | accept | gap (L8) |
| `evidence-v1-extra-keys-ok` | `evidence-v1-with-split-keys.cbor` | `schema` | fork proven | gap (L8) |
| `evidence-v2-split-optional` | `evidence-v2-without-split-keys.cbor` | `schema` | fork proven | gap (L8) |
| `grant-compress-last-run` | label `1:0:0:2:3:0:0:4/128` | `1::2:3:0:0:4/128` | `1:0:0:2:3::4/128` | gap (L8) |
| `grant-no-dedupe` | label `10.0.0.1/8, 10.0.0.2/8` | `[10.0.0.0/8]` | the prefix twice | gap (L8) |
| `bundle-bind-enroll-only` | `bundle-rotate-nas.bundle` (nas's real rotate, index 35) | accept | `binding` | gap (L8) |
| `bundle-device-grammar` | `bundle-uppercase-label.bundle` | accept | `bundle` | gap (L8) |
| `req-standalone-net-unchecked` | `request-other-network.txt` | refuse | accept | gap (L8) |
| `cp-quorum-before-cosig` | `checkpoint-one-forged-pi-only` | `cosignature` | `quorum` | order gap (L8) |
| `dup-content-any-decodable` | `copy-enroll-nas-unsorted-sigs.cbor` after `log/0,1` | `2:decode` | `2:dup-entry` | order gap (L8) |
| `rootrem-invariant-before-unknown` | `root_thr-3.cbor`, `root_remove-unknown-at-full-threshold.cbor` | `2:unknown-key` | `2:root-invariant` | order gap (L8) |

**Composites.**

- Survivor × survivor, all 1176 pairs of the 49 survivors of sweep 3
  (`work/composites-ss.txt`): 1175 survive and **one is caught**:
  `dup-genesis-content-not-recorded` × `dup-genesis-not-recorded`, by
  `log/113-bad-repeat-of-genesis`. Under my C24 reading the genesis content key and the
  genesis byte key each hide the other, so `bad-repeat-of-genesis` pins only their
  conjunction. The other pairs survive because each survivor's distinguishing input lies
  outside the suite, and no vector lies in two survivors' blind spots.
  - The three survivors added after sweep 3 (`pol-vkey-lax-base64`,
    `tile-verify-level0-only`, `trust-logkey-no-point-check`) were paired with all
    other survivors too (`work/composites-new.txt`): 150 pairs, all survive.
  - In all: **1326 survivor × survivor pairs, 1 caught.**
- Survivor × caught, 49 × 404 = 19,796 pairs (`work/composites-sc.txt`), plus
  3 × 404 = 1212 for the newer survivors (`work/composites-new.txt`). In all
  **21,008 pairs: 20,996 caught, 12 survive.**
  - The newer-survivor run first showed one more surviving pair,
    `trust-logkey-no-point-check` × `vkey-no-point-check`. That was a harness bug: a
    temporary variant toggle switched off a variant that was already active. I fixed
    the toggle, re-checked every surviving pair with the fixed binary, and re-ran the
    single sweep (unchanged: 404/52). The pair is now caught by
    `trust-bad/47-witness-noncanonical-point`.
  - The 12 surviving pairs fall into two groups:
    - *Six are artifacts of how I wrote the switches, not masking:*
      - `cp-quorum-before-cosig` × `cp-cosig-before-origin` and ×
        `learned-needs-since-index`: one ordered step list, edited by both
        switches, so the first one wins.
      - `genesis-sigs-before-body` × `genesis-role-ignored` and ×
        `genesis-resolve-signers-too`: the pre-check uses the base rule.
      - `quorum-none-needs-a-cosignature` × `bundle-no-quorum` and ×
        `evidence-no-quorum`: "no quorum" is implemented as a `quorum none`
        policy.
    - *Six are genuine masking:*
      - `dup-content-any-decodable` × `dup-content-at-apply`: an early content check
        supersedes the late one.
      - `pol-none-member-as-name` × `pol-none-member`: the two `none` rules hide
        each other, as §12.1 declares.
      - `logkey-vs-policy-log-lines` × `logkey-not-vs-anchor`: the trust policy's
        own `log` line names the anchor key. A reader that compares a `log_key`
        with policy `log` lines therefore still refuses
        `log-republish/08-log-key-anchor`, without the D-078 anchor comparison.
      - `policy-log-lines-trusted` × `learned-latest-only`, ×
        `learned-replaces-anchor`, × `learned-superseded-retired`: the policy the
        served log ends with names both the anchor key and the first published key
        on `log` lines. A reader that trusts policy `log` lines gets back exactly
        the keys those variants drop, so `served-rotated`'s informed answers stop
        separating "learned from `log_key` entries" from "named on a policy line".

## 3 Defects

Rated per the brief: **H** a conforming reader can be turned against its network, or
two conforming readers decide differently on input a network can really see; **M**
two readings change what a node does, in a corner reachable only through operator
configuration or a malformed input; **L** wording, an over- or under-claim, nothing a
node does differently. Most severe first.

### M1 — §4.0: the restated profile does not exclude the two-byte encodings of `false` and `true`

- **Words at fault.**
  - §4.0, allow-list: "one of the two simple values `false` (20) and `true` (21) of
    major type 7 — and **nothing else**".
  - The table: "Simple values | only `false` (20) and `true` (21); **every other simple
    value is forbidden**, whichever form encodes it".
  - "Shortest form means every argument … which is the integer's value *and* the
    **length header** of a byte string, text string, array or map".
- **What a second implementer can get wrong.** `0xf8 0x14` / `0xf8 0x15` is
  "simple value 20/21 in the two-byte form":
  - the "whichever form" clause applies only to the *other* values;
  - the shortest-form sentence enumerates integer values and length headers and never
    mentions major type 7.
  
  RFC 8949 §3.3 makes these sequences not well-formed. But the spec says a reader
  "implements from the row", and the row admits the reading. A decoder built on a
  lenient CBOR library maps them to booleans. The spec's own preimage definition
  ("the envelope encoded **without** the `sigs` key") then re-encodes `0xf5`, so the
  original signatures verify.
- **Proof.** Variant `cbor-simple-twobyte-bool` survives the whole suite. Input
  `work/survivor-inputs/log-order-03-params-twobyte-true.cbor` is the root-signed
  `log-order/03-params-require-rotate-signer` with its `0xf5` written `0xf8 0x15`.
  Served in its place, the base answers `decode` and keeps `rotate_needs_signer` false;
  the variant applies it.
  
  The next entry (`log-order/04`) then diverges: `stale-state` against `threshold`.
  A log operator can serve this byte variant of any boolean-carrying entry it holds, so
  two readers hold different states.
- **Smallest change.** Add to the Simple values row: "encoded as the single bytes
  `0xf4` and `0xf5`; a head `0xf8 xx` is not well-formed for any `xx` (RFC 8949 §3.3)".
  Ship `entries-hostile/two-byte-false` (`0xf8 0x14`, "simple value") and an in-entry
  negative like the one above.

### M2 — §11.1 / §3.1: whether the carried evidence `policy` gets the valid-point check is unstated

- **Words at fault.**
  - §11.1 `policy` row: "It MUST parse as `c2sp.org/tlog-policy` — a closed schema with
    a stated grammar is part of the format — and a reader MUST NOT verify anything
    under it".
  - §3.1 item 2 lists every place a key is admitted (genesis, `root_add`, `signer_add`,
    `log_key`, `enroll`, a rotate's `device_pk`, "every verifier key a `policy`
    **entry**'s text carries", a request, a trust file). It then sums up: "every key
    that enters a verifier's state is a valid point where it enters".
  - §9.1's grammar: "Every `<vkey>` MUST be parsed as a C2SP verifier key … 32-byte
    Ed25519 public key".
- **What a second implementer cannot know.** The carried policy never enters state and
  is not on item 2's list. A reader whose policy parser includes the point check (one
  parser for all policies, as mine does) refuses such a file as `policy`. A reader that
  applies the check only at item 2's admission points proves the fork.
- **Proof.** Variant `evidence-policy-no-point-check` survives. Input
  `work/survivor-inputs/evidence-carried-policy-small-order.cbor` is
  `fork/evidence.cbor` with the policy `witness t <order-4 key, correct id>` /
  `quorum t`. Base answers `policy`; variant proves the fork.
- **Impact.** A proven fork is permanent until an operator installs a new trust file
  (§11 rule 4). Two readers handed this file from a peer diverge: one freezes, one
  files a bad peer response. It needs a real fork plus a malformed carried field,
  hence M.
- **Smallest change.** In §11.1's `policy` row, after "MUST parse", say either
  "every verifier key a valid point (§3.1), refused as `policy`" or "its keys are not
  point-checked". Add the file above to `fork/` with its code.

### M3 — Preamble, §8.1, §11.1: proof verification is deferred to RFC 6962 sections that hold no verifier; exact proof length is unpinned

- **Words at fault.**
  - Preamble: "RFC 6962 §2.1.1 — inclusion-proof verification, used by §8.1" and
    "RFC 6962 §2.1.2 — consistency-proof verification, used by §11.1. Both proof
    algorithms, and the node ordering each expects, are that document's and are not
    restated here".
  - §11.1 `proof` row: "the algorithm is not restated here and a reader implementing
    their own ordering will reject sound evidence".
- **What a second implementer cannot know.** To my knowledge (this run could not re-read
  the RFC), RFC 6962 §2.1.1 and §2.1.2 *define* audit paths and consistency proofs (how
  to build them). They give no verification procedure; that is RFC 9162 §2.1.3.2 /
  §2.1.4.2, which `SPEC.md` never names. A reader must derive a verifier, and a derived
  verifier has to decide on its own what to do with a proof longer than it needs.
  RFC 9162's procedure refuses it; a recompute-and-compare derivation that stops at the
  root accepts it.
- **Proof.** Variant `merkle-proof-extra-ok` survives. Input
  `work/survivor-inputs/nas-proof-padded.bundle` is `proofs/nas.bundle` with one extra
  32-byte hash. Base `inclusion`, variant accept. The same applies to consistency
  proofs in evidence (a padded proof still chains), where it decides whether a node
  freezes. The suite pins the other derivation error, parity-only inclusion, through
  `proofs/right-edge.json`.
- **Smallest change.** Cite RFC 9162 §2.1.3.2 and §2.1.4.2 for verification (keep RFC
  6962 for the structures). Add one sentence: "a proof with more or fewer elements than
  the procedure consumes is refused". Ship `proofs-bad/padded-proof`
  (`inclusion`) and `fork/bad-padded-proof` (`proof`).

### L1 — §5.1 entry 0 step 1: "The duplicate key" (singular) survives D-078's split into two keys

- **Words.** "1. The duplicate key of §5.1 step 1 is recorded as seen." Since D-078, step
  1 has two seen sets ("an `entry_hash` and a `content_hash` are never compared with
  each other"). Entry 0 never "reaches this step", so whether the genesis's content key
  is recorded when it is applied is unstated (my C24).
- **Proof.** `dup-genesis-content-not-recorded` survives. Input
  `genesis-copy-extra-sig.cbor` (the genesis plus one unresolvable signature element,
  needing no key at all) after `log/0`: base `dup-entry`, variant `dup-genesis`. The
  state's `rejected` list, which §5.3 says must be byte-identical, differs. Nothing is
  enforced differently.
  
  `log/113-bad-repeat-of-genesis` pins only the conjunction of the two genesis keys
  (composite caught).
- **Change.** "Its `entry_hash` is recorded in the first set; once applied (step 8) its
  `content_hash` is recorded in the second." Ship the input above.

### L2 — §10.1 step 6: "listed witness" is undefined once a `policy` entry has dropped a witness

- **Words.** §10.1 step 6: "a cosignature line whose name **and** key id match a
  **listed** witness does not verify".
  - §10's outline and §9.1 say "a witness the policy names / lists".
  - §12.1 also uses "list" for the trust file's `witnesses` array ("a witness the
    policy never names and a policy naming a witness the file does not list").
  - After a `policy` entry that drops a witness, the trust file still lists it and the
    policy in force does not.
- **Proof.** `listed-trust-file-witnesses` survives. The reader replays `log/0` +
  `policy-drops-friend.cbor` (root-signed, `prev` 0, applied). It is then given
  `checkpoint-forged-friend-after-drop` (the served head with one byte of friend's
  signature changed). Base accepts (friend is no longer named), variant refuses
  `cosignature`. Impact is limited: under either reading anyone can already veto a head
  with a forged line under a *currently* named witness (§9.1, "Counting is not
  checking"). The second reading only adds the removed witnesses' names.
- **Change.** Write "a witness the policy in force names (§9.4)" in §10.1 step 6, and
  ship a post-rotation case.

### L3 — §6 / §10.1 step 12: silent on serving a full tile in place of a partial one

- **Words.** §6: "When a tile fills, the `.p/<W>` suffix goes away and the path is the
  bare group". §10.1 step 12 and step 1 (`unserved`) say nothing about a reader that,
  failing to fetch `tile/0/N.p/W`, uses the first `W` hashes of a full `tile/0/N` the
  log now serves. Whether `c2sp.org/tlog-tiles` permits that is outside what this run
  could check (no network).
- **Proof.** `tile-full-for-partial` survives. The directory
  `work/survivor-inputs/tile-full-log/` is a 600-entry log with a head at size 300
  signed by `logkey` and cosigned by all three witnesses; `tile/0/001.p/44` is absent
  and `tile/0/001` is served. Base `unserved`, variant accept. This matters for §15,
  where a peer "may legitimately serve an older head".
- **Change.** One sentence in §6: either "a verifier fetches exactly these paths" or
  "a verifier MAY use the first `W` hashes of the full tile", plus a vector.

### L4 — §12.1 over-claim: "NORN-ED25519-v1 is vectored at every admission point item 2 names"

- **Words.** §12.1, "What is not vectored", first bullet: "§3.1's NORN-ED25519-v1 is
  vectored at every admission point item 2 names". Item 2 names "a trust file's
  `log_key`".
- **Proof.** `trust-logkey-no-point-check` survives. Input
  `trust-small-order-log-key.cbor` is `trust.cbor` with `log_key` replaced by the
  order-4 point under the origin's name with its id recomputed, and the policy's
  optional `log` line removed. Base: invalid; variant: valid. Every other admission
  point is pinned: my variants for genesis, `signer_add`/`root_add`, `log_key`,
  `enroll`, rotate, policy witness and log line, and trust witnesses are all caught.
- **Change.** Ship that file as `trust-bad/55-log-key-small-order`, or narrow the claim.

### L5 — §12.1 over-claim: the `policy` text cap

- **Words.** §12.1: "`bad-text-too-long` is the same shape for `note` and `policy`'s
  4096-byte cap: 4097 bytes, 2049 characters." `log/83-bad-text-too-long` is a `note`.
  No entry tests a `policy` text over 4096 bytes.
- **Proof.** `policy-text-no-cap` survives. Input `policy-over-4096.cbor` (a
  root-signed, parseable policy padded with a comment) after `log/0`: base `decode`,
  variant applied.
- **Change.** Ship a `bad-policy-text-too-long` entry, or reword the sentence.

### L6 — §12.1 inaccurate declared hole: §16.1's 32-byte `device_pk` *is* pinned

- **Words.** §12.1, "What is not vectored": "**§16.1's 32-byte `device_pk`,
  independently.** … No construction separates the two, so the rule is
  refused-but-not-pinned".
- **Proof.** `req-device-pk-length-lax` is **caught**, by `log/81-bad-pk-length`. That
  is an `enroll` whose request carries a 31-byte `device_pk` (confirmed with
  `work/bin/inspect`). A reader without the length rule decodes the request and fails
  its signature: `no-device-sig`, where the manifest says `decode`.
- **Change.** Remove the bullet, or say the entry layer pins it through the code.

### L7 — §3.1 item 3 omits the validity of `A`

- **Words.** "A signature `R ‖ S` (64 bytes) verifies under a key `A` over a message
  `M` only if `R` is a valid point; …". Validity of `A` is implied only by item 2
  (admitted keys) and item 4 ("rejects every vector … `low_order_A`,
  `non_canonical_A`, `low_order_component_A`").
- **Proof.** `ed-no-A-check` is caught, but only by `ed25519-cctv/` (15 vectors), so it
  is the CCTV statement that pins it, not the predicate. My C01.
- **Change.** "… only if `A` and `R` are valid points".

### L8 — §12.1 under-claim: explicit, network-visible rules the suite does not exercise, missing from "What is not vectored"

§12.1 says "a suite that looks complete is worse than one that admits its holes". Each
rule below is stated plainly in `SPEC.md`, so a careful reader gets it right. Each
survives the whole suite, though, and its distinguishing input (in section 2, class C)
is something a network can see. Highest impact first:

| rule (section, words) | variant that survives | consequence of the misreading |
|---|---|---|
| §7/§10: a line is matched by "key name **and** key id" | `cp-log-match-keyid-only`, `cp-cosig-match-keyid-only` | anyone who can append a line (any relay) vetoes heads at id-only readers; `served-name-collision` pins only the name-only half |
| §4.3: "a device key counts only for its own `device_id`" (for `revoke`) | `rev-device-sig-from-any-device` | any enrolled device can revoke any other |
| §4.4: "absent where it does not [exist] — which is only an `enroll` of a `device_id` that no accepted entry has ever named" | `prev-gov-absent-at-zero` | a governance entry without `prev` at version 0 applies at one reader and is `stale-state` at another |
| §4.0: "`v`, `t`, `net`, `ts`, `body` and `sigs` are all **mandatory**" (`ts` only: `sigs` has `bad-missing-sigs`) | `env-ts-optional` | state split on a signed entry without `ts` |
| §4.0: label "values ≤ 256 bytes, the empty value included" | `label-value-min-1` | state split on an `enroll` with an empty label value |
| §5.1 `log_key`: "not the public key of any **witness** the policy in force names" | `logkey-vs-policy-log-lines` | a rotation pre-announced on a policy `log` line is refused at readers that extend disjointness to `log` lines |
| §9.1 `log` lines: "Norn takes the log key it verifies with from `log_key`, never from here" | `policy-log-lines-trusted` | a head signed by a key named only on a policy `log` line is accepted |
| §10.1 step 12: "**every** served hash tile" | `tile-verify-level0-only` | a corrupt level-1 tile is accepted and served onward. No vector tampers a level-1 tile; only the tile-path table in `served-large/cases.json` lists one |
| §7: "canonical padded base64 that decodes to at least the 4-byte `key_id`" | `note-no-keyid-minimum` | a 3-byte stranger line refuses heads at conforming readers and not at lax ones |
| §7: control characters "below U+0020" (DEL allowed) | `note-del-forbidden` | a stranger line with DEL in its name vetoes heads at readers that treat DEL as a control |
| §7 receipts: "The origin line MUST equal" | `rc-origin-prefix` | prefix-matching readers accept receipts for an extended origin |
| §11.1: exactly seven keys at version 1, eleven at version 2 | `evidence-v1-extra-keys-ok`, `evidence-v2-split-optional` | malformed evidence proves a fork at one reader only |
| §4.0 grant: RFC 5952 form; "duplicates removed" | `grant-compress-last-run`, `grant-no-dedupe` | different grant text in `proven.json` |
| §8.1: rotate/revoke bound "through the `device_id` in the body" (positive side) | `bundle-bind-enroll-only` | a reader that refuses every non-`enroll` bundle passes |
| §8.1 `device` is text (no grammar) | `bundle-device-grammar` | a bundle around a rejected entry is accepted at one reader only |
| §16.1 (D-078): a consumer refuses a request for another network | `req-standalone-net-unchecked` | a human is shown a request that cannot take effect |
| §10.1 order 6 before 7; §5.1 step 1's content key after steps 2–3; `root_remove` unknown-key before root-invariant | `cp-quorum-before-cosig`, `dup-content-any-decodable`, `rootrem-invariant-before-unknown` | different closed codes (§5.1 itself admits untested orders) |

The not-vectored list also omits node behaviours the static suite cannot reach:

- §11 rule 3's frozen-set computation. `split` is vectored; the set the node keeps
  enforcing is not.
- §15's `CLOCK_SKEW` alarm.
- §13.2's restart and corroboration rules.

**Change.** Add the rows above to "What is not vectored", or ship one vector each. All
the inputs already exist in `work/survivor-inputs/`.

### L9 — §6 anchors bullet: two of the "three different byte ranges" are one range

- **Words.** "Not the three-line body of the bullet above and not §7's *signed text*,
  which stops one `0x0A` earlier: those are three different byte ranges".
- **Problem.** A checkpoint body is three LF-terminated lines (§6), and §7's signed text
  is "everything up to **and including** the newline that ends the last text line". For
  a checkpoint those are the same bytes. I computed the SHA-256 of `served/checkpoint`
  through the blank line (`81497d83…`, matching `anchors/cases.json`), through the
  signed text (`5b39e219…`) and without the final LF (`ab76f532…`): there are two
  neighbours, not three. No behaviour depends on it; the digest is pinned in hex.
- **Change.** "Not the three-line body, which is §7's signed text and stops one `0x0A`
  earlier".

## 4 Declared survivors — §12.1 "What is not vectored", each checked

| declared item | check | result |
|---|---|---|
| §3.1 vectored at every admission point | one variant per admission point | **not accurate**: all caught except the trust file's `log_key` (`trust-logkey-no-point-check` survives), see L4 |
| source-neutral acquisition | — | not reachable by static files; confirmed (nothing in the suite carries a source) |
| §13 reconciliation, `proven.json` | — | confirmed not vectored |
| §16.3 key handling | — | confirmed not vectored |
| `none` as a group member vs the earlier-definition rule | `pol-none-member-as-name` | survives: confirmed (my stronger `pol-none-member`, which drops both, is caught) |
| CR inside a policy verifier key | `pol-vkey-lax-base64` (lax base64 for policy keys only) | survives: confirmed (control-byte rule first; 33-byte data has no pad bits) |
| OpenTimestamps attestations | digest presence only | confirmed; the digest range itself is pinned (`anchors/` range check passes, the three-line-body and signed-text ranges do not match) |
| `quorum none` accepting an uncosigned head | `quorum-none-needs-a-cosignature`; input `checkpoint-uncosigned` under my `trust-quorum-none.cbor` | survives: confirmed; base accept, variant `quorum`. Also `t-quorum-none-unbounded`: base no clock and 8 proven, variant `T`=1767776001 and 7 proven (contractor dropped) |
| "a key contributes at most once" | `sig-count-repeats` | survives: confirmed (sorted unique kids make it unreachable; `env-sigs-repeat-ok` is caught by `log/134-bad-repeated-kid`) |
| "must not count it even in the moment before that refusal" | — | confirmed unobservable at file level |
| order of entry 0's steps | `genesis-sigs-before-body` | survives: confirmed |
| §3.1 canonical clauses | `ed-lenient-y`, `ed-lenient-sign-zero` + computation | survives: confirmed; 0 of 38 non-canonical `y` encodings is a valid point; x = 0 points have order 1 or 2 |
| blank line inside the text vs between signatures | `note-last-blank-line` | between signatures: caught by `checkpoints-bad/45` (`note` vs `log-signature`); inside the text: equivalent (line count) — confirmed |
| "never from a supplied proof" | — | confirmed: no file supplies a proof |
| §16.1's 32-byte `device_pk` | `req-device-pk-length-lax` | **caught** by `log/81-bad-pk-length` (`decode` vs `no-device-sig`): the declaration is wrong, see L6 |
| `state.net` from the anchor | `state-net-from-genesis` | survives: confirmed |
| `entry_hash` as received | `entry-hash-recanonical` | survives: confirmed |
| `MAX_ENTRY_BYTES` on the embedded request | `req-no-size-cap` | survives: confirmed |
| witness key must be a cosignature key at verification | — | confirmed unreachable (the trust file and the grammar refuse first) |
| `dup-wg` for `enroll` "any device" | `enr-dupwg-other-device` | survives: confirmed |

## 5 Decisions the vectors pinned, and decisions they did not

Pinned means a variant flipping that decision is caught. Decisions from
`work/decisions.md`:

- **Pinned:**
  - Ed25519: C01, C02 as a whole, C03.
  - Profile: C05 (for entries and requests), C06, C07, C08 (the caps), C09.
  - Envelope and replay: C12, C14, C16 (except `ts` presence), C17, C19, C20 (across
    roles), C22, C23, C26, C27, C29–C36.
  - Log, notes, receipts, bundles: C38, C39, C42, C43, C45, C48, C50, C51.
  - Policy, trust, verifier, evidence: C53–C61 (except C54), C63–C69.
  - Text and JSON: C71, C72, C73.
  - Partly pinned:
    - C15, all but the RFC 5952 tie-break and duplicate removal.
    - C37 (level-0 comparison and the path table) and C40 (MTH split, right-edge
      inclusion, power-of-two prepend).
    - C44, the name-only half. C46, all but origin prefix. C47, the negatives. C49, all
      but exact length.
    - C52, trust witnesses and `policy` entries.
- **Not pinned (a flipped decision survives):**
  - C04: two-byte `false`/`true` (M1).
  - C10: decoder-internal check order. By design, every hostile vector carries one
    fault.
  - C11: content hash by re-encoding vs slicing. Equivalent under a strict decoder.
  - C18, the "named device" half: revoke by another device's key.
  - C21: `prev` at version 0.
  - C24: genesis content key (L1).
  - C25: content key only after the envelope.
  - C28: `log_key` vs policy `log` lines.
  - C37: exact paths with no full-tile fallback (L3), and level-1 comparison.
  - C40/C49: exact proof length (M3).
  - C41: DEL in notes.
  - C44: id-only matching.
  - C47: refusing non-enroll bundles; device grammar.
  - C52: trust `log_key` point (L4); the carried evidence policy (M2).
  - C54: UTF-8 inside the grammar (no network input).
  - C62: "listed" after a policy rotation (L2).
  - C70: standalone request `net`.

## 6 Verdict

The implementation passes all 3042 checks, first run and final run. 404 of 456
single-decision variants are caught. Of the 52 survivors:

- 22 are equivalent or declared;
- 30 have concrete separating inputs. Of those, 3 expose places where `SPEC.md`
  admits two readings that change what a node does on malformed but servable input:
  two-byte booleans, the carried evidence policy's key validity, and proof-length
  exactness behind a verifier the spec attributes to a document that contains none;
- the rest are wording and coverage-claim defects (L1–L9).

There is no H defect. There are three M defects.

SPEC INSUFFICIENT

## 7 Closing self-check

Every file I wrote is under `work/`:

- `work/decisions.md`, `work/SPEC-DEFECTS-16.md`;
- the implementation `work/impl/` (`go.mod`; `norn/` with 15 source files and one
  test; `suite/suite.go`; `cmd/harness`, `cmd/inspect`, `cmd/survivors`);
- binaries `work/bin/{harness,harness2,inspect,survivors}`;
- run and sweep records: `work/run1-first.txt`, `work/run-final.txt`,
  `work/sweep{1,2,3}.txt`, `work/sweep1.time`, `work/sweep-final.txt`,
  `work/survivors*.txt`, `work/caught.txt`, `work/pairs-*.txt`,
  `work/composites-*.txt`, `work/sc-survivors.txt`, `work/survivors-report.txt`;
- the separating inputs `work/survivor-inputs/` (36 files, including the
  `tile-full-log/` directory);
- tool state in `work/home`, `work/gocache`, `work/gopath`, `work/tmp`, which `HOME`,
  `GOCACHE`, `GOPATH` and `TMPDIR` pointed to for every tool run.

Outside `work/`, the sealed directory still holds exactly `SPEC.md` and
`testdata/vectors/`: `find` lists no other file, nothing in `testdata/` is newer than
`SPEC.md`, and all 984 digests still verify.

For full disclosure, these are things the agent tooling did itself, not commands of
mine, outside the sealed directory. All are tooling, not project files, and no copy
of the project was ever touched:

- The Bash tool saved one oversized output (my `sed` of `testdata/vectors/README.md`)
  to its own `tool-results/` file under `~/.claude/projects/…`. I read the README text
  back from that file.
- It keeps background-task capture files under the session scratch `tasks/`
  directory. Mine were redirected into `work/`, and the monitor's holds one line.
- It writes a working-directory marker in `/tmp` after each command.
- Running `go` and the shell reads the installed toolchain and shell profile.

No web or network access was used.
