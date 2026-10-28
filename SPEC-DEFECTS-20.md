# Cold gate run 20 — SPEC.md defects

Reader: one cold implementer, working from `SPEC.md` and `testdata/vectors/` only.
Implementation: Go, standard library only, `work/impl/` (`norn/` library, `cmd/harness`,
`cmd/sweep`, `cmd/probe`). Decisions logged before any vector was opened:
`work/decisions.md` (C01–C78, not edited since).

## 1 Tally

| run | checks | pass | fail |
|---|---|---|---|
| digests (`shasum -c SHA256SUMS`, before implementing) | 1204 | 1204 | 0 |
| first full harness run | 3674 | 3674 | 0 |
| final harness run | 3782 | 3782 | 0 |

The first full run had no failures. The 108 checks added afterwards are the
`keys.json` suite (each Ed25519 seed derives its public key and kid; each X25519
public key derives from SHA-256(prefix ‖ `wg/` ‖ name); `net`), which I had skipped
in the first run and which also passed at once.

The harness runs every manifest and `cases.json` in the suite and re-checks every
digest in `SHA256SUMS`. That covers all eight replay fixtures (each entry's reason,
every `.reason` file, every `codes` map, byte-identical `state.json`); the 27 + 2
genesis logs; the hostile and UTF-8 decoder inputs; 914 CCTV vectors; 71 policies
with their `evaluate` rows; the trust files, the fingerprint, and rebuilding
`trust.cbor` byte for byte from `trust.toml`; requests (text ⇄ CBOR, canonical
re-encoding, mirrors, consumer network); every receipt; every served, checkpoint,
detect, tile, bundle, evidence and reader case with its closed code; staleness and
its age derivation; the proven sets, grants and grant table; anchors; and the
`signature_blind_accepts` set, which the harness recomputes with a verifier that
never calls Ed25519 (the six listed files are exactly the ones it accepts).

## 2 The sweep

**Mechanism.** Every decision point in `norn/` is a switch `V("name")`, enabled
through `NORN_VARIANT`. Every ordered check list (replay steps 1–8, all eleven type
rules, the checkpoint steps 2–7, the loop steps 8–12, bundle, evidence, receipt) is a
named step list. So `swap-<list>-<i>` exchanges two adjacent checks and
`skip-<list>-<step>` drops one, both generated mechanically. Every cap and floor goes
through `capOf`, so `cap-<name>-minus` and `cap-<name>-plus` move each boundary one
step either way. Each variant runs against the whole suite (`cmd/sweep`, 7 jobs). It
survives if no check fails.

**Counts.**

| sweep | variants | caught | survivors |
|---|---|---|---|
| sweep 1 (first enumeration) | 556 | 500 | 56 |
| sweep 2 (after fixing my own modelling artefacts, and adding readings) | 566 + 4 | 516 | 54 |
| composites survivor × survivor (all pairs) | 1431 | 0 | 1431 |
| composites survivor × weakly-caught (each of the 54 × each of the 304 caught variants that fail ≤ 3 checks) | 16416 | 16399 | 17 |
| extra: `entryhash-recanonical` (§12.1 declared item) | 1 | 1 | 0 |

The variant space covers these families:

- 52 boundary variants (26 caps and floors × ±1).
- 87 skips and 71 swaps.
- About 360 named readings: profile bans and leniencies, every field rule, kid,
  role, label, name and text rules, grant grammar and rendering, policy grammar,
  vkey grammar, note framing, base64 and decimal canonicality per site, origin,
  name, key-id and public-key comparisons, log-key and policy rotation, held-head
  rules, quorum-time rules, freshness and expiry boundaries, bech32m, canonical
  JSON, tile paths, fallback, framing, and the Merkle and consistency verifiers.

The four variants with capital letters in their names, which my generator first
missed, were run by hand: `ed-reduce-S`, `ed-skip-A-check`, `ed-skip-R-check` and
`held-head-recomputes-T`. All four are caught.

In sweep 1, six survivors (`swap-ev-3`, `swap-remove-2`, `swap-replay-2`,
`cbor-depth-scalars`, `cap-entry-±`) were artefacts of my own lazy step closures.
In each case a later step re-ran the earlier check and returned the same code. Once
the closures were fixed, each is caught. I did not count them as survivors.

**The 54 survivors of sweep 2, classified.**

*A. Declared in SPEC §3.1/§7/§12.1 as equivalent or unvectorable — confirmed (15):*
`count-no-dedupe`, `ed-cofactored`, `ed-lenient-decode`, `enroll-dupwg-other-only`,
`policy-allow-none-member`, `req-pk-any-length`, `cap-request-minus`,
`cap-request-plus`, `state-net-from-genesis`, `note-split-last-space`,
`trust-witness-any-alg`, `trust-witness-name-any`, `trust-witness-name-no-cap`,
`cap-witname-plus`, `cap-witname-floor-minus`. The last five are hidden by the
trust file's correspondence with a policy, whose grammar refuses the same keys and
names again. §12.1's rows for trust-bad 15/16 and 32/54 say so.

I checked `ed-lenient-decode` by computation (`norn/claim_test.go`). All 24
encodings with y in [p, 2²⁵⁵), or with x = 0 and the sign bit set, that decode
leniently are the identity or of non-prime order.

*B. Equivalent by construction: no input of any kind separates base and variant (22):*

- `bech-first-separator`: neither the HRP `norn` nor the data charset contains `1`.
- `cons-allow-short` and `incl-allow-short`: they need a SHA-256 collision.
- `ev-allow-split-above-size`: a split above `size` cannot chain to the conflicting
  head, so the code is still `proof`.
- `note-name-go-unicode`: Go's `unicode.IsSpace` is exactly §7's list, and controls
  are refused earlier.
- `genesis-bytes-not-seen`: the content set catches every byte copy of entry 0 (see
  L2).
- Swaps whose two sides share a code or cannot both fail: `swap-enroll-0`,
  `swap-logkey-0`, `swap-logkey-4`, `swap-note-0`, `swap-note-1`, `swap-policy-0`,
  `swap-policy-1`, `swap-replay-1`, `swap-replay-3`. For `swap-replay-3`, `genesis`
  is a known type.
- `swap-revoke-1`, `swap-rotate-1`, `skip-revoke-known` and `skip-rotate-known`: an
  unknown device cannot be judged active.
- `skip-loop-entries` and `swap-loop-0`: the head needs the entries.
- `skip-replay-decode`: the envelope step also refuses undecodable bytes as
  `decode`.

*C. Genuine survivors: a network-visible difference that no vector holds (17).*
For 15 of them I built a concrete input, signed with the suite's own keys where it
needs a signature, and ran base and variant on it. They are in `work/probes/`, made
by `cmd/probe`, and every one disagrees:

| probe | variant | input | base | variant |
|---|---|---|---|---|
| P1 | `cap-uint-plus` | signer-signed `note` with `ts` = 2⁶³ | `decode` | applied |
| P2 | `env-bool-as-uint` | signer-signed `note` with `after: true` | `decode` | applied |
| P3, P3b | `skip-params-prev` | root-signed `params` with no `prev` / `prev` 7 | `stale-state` | applied |
| P4 | `swap-logkey-2` | root-signed `log_key` with order-8 `pk` and `prev` 7 | `decode` | `stale-state` |
| P5 | `swap-ev-1` | `fork/evidence.cbor` at version 3 with `version` written `18 03` | `cbor` | `version` |
| P6 | `trust-correspondence-ignore-names` | `trust.cbor` with array witness `pi` renamed `pj`, policy unchanged | invalid | valid |
| P7 | `trust-name-ascii` | `trust.cbor` with `name` `réseau-de-test` | valid | invalid |
| P8 | `trust-require-policy-log-line` | `trust.cbor` with the optional policy `log` line removed | valid | invalid |
| P9 | `binding-structure-only` | bundle of served entry 132 (`expires` = `ts`) at the served head, real path | `binding` | accept |
| P10 | `enroll-expires-after-entry-ts` | signer-quorum `enroll`, request `ts` 100 / `expires` 200, entry `ts` 1760000000 | applied | `decode` |
| P11, P11b | `grant-mapped-dotted-only` | label `::ffff:a00:1/128`, `0:0:0:0:0:ffff:a00:1/128` | no grant | `::ffff:a00:1/128` |
| P12 | `held-same-head-skip-verify` | `served/checkpoint` re-cosigned with pi's line forged, read by a reader holding that head | `cosignature` | accept |
| P13 | `note-allow-blank-first` | `\n— <origin> <log sig over the empty text>\n` | `note` | `checkpoint` (as a receipt: `receipt`) |
| P14 | `receipt-leaf-any-length` | log-signed receipt with a 31-byte leaf hash | `leaf-hash` | accept |
| P15 | `cap-bundle-entry-minus` | bundle around a 65535-byte `rotate` naming nas, 2-leaf head signed and cosigned by all three | accept | `bundle` |

The other two genuine survivors need a 64-bit `kid` collision, which I did not grind
in this run. Two valid points with equal SHA-256[0:8] take about 2³² Ed25519 key
generations with a distinguished-point search, a few CPU-hours.

- `genesis-kid-distinct` is defect M3.
- `dupkey-by-pk` compares `signer_add`/`root_add` by public key instead of by kid.
  The spec is explicit there (kid), so it is a gap only.

**Composites.** All 1431 survivor × survivor pairs survive. So no two survivors
interact: each is independent, and no vector holds two of them at once.

Survivor × weakly-caught: 17 of 16416 survive.

- **Artefacts (12).** Neither the spec nor the suite is at stake in these:
  - The same switch set both ways: `cap-bundle-entry-±`, `cap-witname-floor-±`,
    and `trust-witness-name-no-cap` with `cap-witname-minus`.
  - Two adjacent swaps applied in sequence that move the caught check back into
    place: `swap-logkey-0/1`, `swap-logkey-2/3` (this one reduces to the known
    survivor `swap-logkey-2`), `swap-loop-0/1`, `swap-replay-1/2`,
    `swap-revoke-1/2`, `swap-rotate-1/2`.
  - My own "no envelope → `decode`" fallbacks masking a skip: `skip-replay-decode`
    with `swap-replay-0`, and `swap-replay-3` with `skip-replay-envelope`.
  - `skip-params-prev` with `swap-params-0`: once `prev` is skipped, its order
    cannot matter.
- **Meaningful (5).** These show a vector that holds its rule only because a gap
  exists:
  - `held-same-head-skip-verify` with `held-head-current-policy`. A reader that
    re-verifies a held head under the *current* policy, but accepts it anyway
    because it is the held head, passes. `served-superseded/` is the only vector
    for "the held head keeps its policy", and it cannot tell that rule from "the
    held head is never re-verified". Probe P12 can (L1 item 10).
  - `trust-require-policy-log-line` with each of `b64-lenient-vkey`,
    `trust-allow-witness-is-log`, `trust-logkey-any-alg` and
    `trust-no-point-check`. trust-bad/44, 51, 53 and 55 isolate their rules by
    *omitting* the optional policy `log` line. A reader that refuses every policy
    without a log line refuses all four for that reason instead, and passes without
    the four rules. On files that do carry a log line, the policy grammar and the
    text correspondence re-check the same key, so the composite reader differs
    from base only on log-line-free files, which is P8. Shipping P8 as a positive
    makes those four negatives isolating again (L1 item 6).

## 3 Defects

Rated per the brief: **H** a conforming reader can be turned against its network,
or two conforming readers decide differently on input a network can see; **M** two
readings change what a node does, in a corner reachable only through operator
configuration or malformed input; **L** wording, over- or under-claim.

### M1 — A provider prefix wider than the grant: clip it or withhold it?

- **Where.** §13.1 Routes: "the desired allowed-ips of a peer are the endpoint
  provider's, each masked, kept only where it lies within a prefix of the peer's
  grant (§4.0); a provider's prefix outside the grant is withheld and reported as a
  provider claim, so a provider MAY narrow a grant and MUST NOT widen it". §12.1
  calls the same rule "§13.1's **intersection** of a peer's allowed-ips with its
  grant".
- **What a second implementer cannot know.** Grant `10.9.1.0/24` (from label
  `10.9.1.5/24`); the provider supplies `10.9.0.0/16`. Two readings, and both
  narrow rather than widen:
  - "kept only where it lies within" as a *filter*: the /16 is not inside a grant
    prefix, so it is withheld, the peer is installed with no allowed-ips, and the
    claim is reported.
  - "kept only where it lies within" as an *intersection*, which is §12.1's word:
    the part inside the grant is kept, and the node installs `10.9.1.0/24`.

  One node cannot reach the peer at all, the other routes the /24 to it. The prefix
  that is "outside the grant" is only partly outside, so that sentence does not
  decide either.
- **Proof.** No vector: §12.1 declares §13.1 outside the static suite. The input
  above is concrete: label `10.9.1.5/24`, provider prefix `10.9.0.0/16`. It is
  reachable through the endpoint provider's configuration, an operator's input.
- **Smallest change.** "kept only if it lies **wholly** within a prefix of the grant;
  a provider prefix that is wider than, or not contained in, every grant prefix is
  withheld whole, never clipped". Or the opposite decision, stated as plainly.
  Change §12.1's "intersection" to match.

### M2 — Two peers with overlapping allowed-ips: no normative rule

- **Where.** §4.3, D-081: "What a node installs for two peers whose allowed-ips
  overlap is not a replay rule; `ENFORCEMENT.md` narrates how `nornd` gives neither
  peer the overlapping prefix and reports the pair". Preamble: the companions are
  "**informative** … no rule lives in them".
- **What a second implementer cannot know.** Replay accepts overlapping grants on
  purpose (D-081). Under `routes = "advisory"`, or a provider that supplies
  overlapping prefixes within grants, two proven peers can be due the same prefix.
  WireGuard gives an allowed-ip to one peer only, the last one written. §13.1 says
  nothing, and the one description of the answer (neither peer, reported) sits in a
  document the spec says holds no rule. A conforming node that installs peers in
  replay order sends the overlapping prefix to whichever device came last. Another
  sends it to neither. The two route the same destination differently. That is a
  network-visible split, reachable through provider configuration or two approved
  grants.
- **Proof.** No vector (§13 is outside the static suite).
- **Smallest change.** Move the rule into §13.1: "when the desired allowed-ips of two
  proven peers overlap, the overlapping prefix is installed for neither, and the
  pair is reported".

### M3 — Two genesis keys may share one `kid`; the state and signature resolution are keyed by `kid`

- **Where.** §4.0 field table, `roots`, `signers` at genesis: "arrays of 32-byte
  `pk`, no duplicates, no key in both". §5.1 entry 0 step 6: "`roots` and `signers`
  are non-empty arrays of distinct 32-byte keys, disjoint from each other". §5.3:
  "`roots` | map `kid` → 32 bytes", and the same for `signers`. §5.2: "a signature
  `{kid, role, sig}` is *valid* iff `kid` names a key this entry may be signed by
  **in that role**".
- **What a second implementer cannot know.** Duplicates are judged on key bytes, and
  `kid` is only 64 bits. Two distinct valid points with one `kid` pass step 6.
  After that, the state schema cannot hold both keys, and "the key `kid` names" is
  ambiguous. One implementation keeps the first key, another the last, and a third
  tries both. They then disagree on:
  - the canonical state (§5.3's byte-identical MUST);
  - whether the genesis applies at all. With `roots` = [K1, K2] colliding,
    `root_thr` = 1, signed by K1: a last-wins reader aborts the whole log as
    `bad-genesis`, a first-wins reader replays it;
  - which of two colliding signers can authorise an `enroll`. A different proven
    set means different peers in WireGuard.

  After genesis the gap is closed: `signer_add`/`root_add` refuse a `kid` already
  present in either role (§5.1, `dup-key`). Only entry 0 is open, and entry 0 is
  the operator's configuration. Whoever generates two keys of one set can grind the
  collision in about 2³² work.
- **Proof.** Variant `genesis-kid-distinct` (distinctness by `kid`) survives the
  whole suite, as do `dupkey-by-pk` and both together. No input was built (64-bit
  collision; see §2).
- **Smallest change.** In §4.0's row and §5.1 step 6: "…distinct 32-byte keys
  **with pairwise distinct `kid`s, within and across the two arrays**". A genesis
  that repeats a kid is `bad-genesis`. This is the same comparison `signer_add`
  already uses.

### L1 — §12.1 omits rules that no vector holds (under-claim)

Every rule below is stated clearly in SPEC.md, and my base gets it right. But each
has a surviving variant, a concrete input above, and no line in "What is not
vectored". §12.1 promises to list what is not vectored, and these rows are missing.
Smallest change for each: ship the probe as a vector beside its repair, or add the
rule to the list.

1. **§4.4/§5.1 `params` `prev`** ("`params` | `params` | `versions.params`";
   "`prev` is `versions.params` (`stale-state`)"). Probe P3/P3b. The §12.1 row
   "`prev` binds the source of every state change" has five stale stories, and none
   is for `params`.
2. **§4.0 integers "≤ 2⁶³−1"** at the CBOR layer. `bad-integer-too-large` uses
   2⁶⁴−1, so a cap of 2⁶⁴−1 passes. Probe P1 (2⁶³). The decimal note lines are
   pinned at 2⁶³ (`checkpoints-bad/33`), but the CBOR integer is not.
3. **§5.1 step 3 "(`t` text, `ts`, `after` and `prev` uint …)"** plus §4.0
   "schemas MUST reject [booleans]". There is no envelope-level boolean vector;
   every boolean vector sits in a body or in `params`. Probe P2.
4. **§3.1 item 2 "refused as `decode` at its entry type's body step"** for a
   `log_key`, before `prev`. `log-order/22` pins the length and type fields, not
   point admission. Probe P4.
5. **§11.1 order `cbor` (1) before `version` (2).** No file fails both. Probe P5.
6. **§9.1 three trust-file readings** (P8's gap also hides trust-bad/44, 51, 53
   and 55; see the composites in §2):
   - correspondence is "on the **set** of names": an array name differing from the
     policy's short name under the same key. Probe P6.
   - `name` is "text, 1–64 bytes", and no positive is non-ASCII. Probe P7.
   - "A `log` line, if the policy carries one": every positive trust file carries
     one. Probe P8.
7. **§8.1 "Decoding here is the request's structure and field rules".** The field
   rule `expires` > `ts` is not held at the binding layer; only the device_id
   grammar, length and point rules are. Probe P9 is a real served entry, with a real
   path and the served head.
8. **§5.1 / §5.3 "`expires` is never applied during replay".** No `enroll`
   carries a request already expired at the entry's `ts`. That is the check a reader
   adds unasked, as with the request `ts` (`enroll-request-from-the-future`). Probe
   P10.
9. **§4.0 "An IPv4-mapped IPv6 prefix is no grant either".** Every mapped case in
   `grant-labels.json` uses the dotted form. A reader that detects only
   `::ffff:a.b.c.d` text gives `::ffff:a00:1/128` a grant. Probe P11. Also change
   the wording to "(whatever its spelling: the value lies in `::ffff:0:0/96`)".
10. **§5.3 "a reader that holds that tree head keeps the policy and the T it
    accepted it under".** No vector re-serves the held head with a bad line, so a
    reader that takes "whatever cosignature lines arrive with it" to mean "already
    accepted, nothing to verify" passes. That reader then stores and serves a copy
    carrying a forged witness line. Probe P12. The composite with
    `held-head-current-policy` also survives, so `served-superseded/` does not
    hold "keeps its policy" on its own. Also add: "the copy is still verified in
    full, under that policy".
11. **§7 "The text is at least one line …"** See L3 for the over-claim. Probe P13.
12. **§7 receipt step 5 "decode to exactly 32 bytes".** `bad-leaf-hash` is invalid
    base64, so canonical base64 of 31 bytes is not held. Probe P14.
13. **§8.1 `entry` "at most `MAX_ENTRY_BYTES`" from below.** `oversize-entry` is
    65536; nothing carries 65535, so a cap of 65534 passes. Probe P15.

Also unvectored, and not listed:
- **§11.1 order `cbor` before `version`** (item 5).
- **`signer_add` dup-key "whose `kid` already exists"** against a pk comparison. This
  cannot be vectored without a 64-bit collision, so it belongs in the "not vectored"
  list.

### L2 — §12.1 over-claims what `bad-repeat-of-genesis` pins

- **Where.** §12.1, row "§5.1 seen set, §4.3 roles": "`bad-repeat-of-genesis`
  (entry 0's key is recorded too, so a byte copy of it is `dup-entry` and not
  `dup-genesis`)". §5.1 entry-0 step 1 is the rule.
- **Problem.** Since D-078, entry 0's `content_hash` joins the second set when it
  applies. A byte copy of entry 0 decodes, and its content hash is that set's, so it
  is `dup-entry` whether or not its `entry_hash` was recorded. Variant
  `genesis-bytes-not-seen` survives. Entry 0's byte-set membership is unobservable,
  because a genesis that does not apply aborts replay.
- **Smallest change.** Move "entry 0's `entry_hash` joins the first set" to "What is
  not vectored", with that reason. `log-republish/15` pins the content half.

### L3 — Two §12.1 rows give rationales that are stale or over-claim

- **"§4.0 the whole input is consumed".** It says "a decoder that stops at the end
  of the item applies the same governance entry twice". Since D-070 that reader
  answers `dup-entry`, as §4.0's own paragraph says ("must be `decode`, not
  `dup-entry`"). The vector still discriminates (`cbor-allow-trailing` is caught),
  but for that reason, not the stated one.
- **"§7 the text is at least one line (D-078)".** It cites
  `checkpoints-bad/46-blank-first-line` as the negative. A reader that lets the
  text be empty ends the text at line 0 and then refuses 46 for framing, because the
  body lines do not frame as signature lines. So 46 does not isolate the rule
  (`note-allow-blank-first` survives). Probe P13 (empty text, log-signed) does:
  `note` against `checkpoint`.
- **Change.** Correct the two rationales; ship P13.

### L4 — §12.1 under-claims: "entry_hash … as received" *is* vectored

- **Where.** §12.1: "**`entry_hash` being over the bytes *as received* rather than a
  re-canonicalised form** … the received-versus-recanonical half cannot be".
- **Problem.** I made a reader that canonicalises leniently before step 1, as a lax
  CBOR library that decodes and re-encodes would (`entryhash-recanonical`). It is
  caught by 11 checks:
  - `log/60-bad-trailing-byte` becomes `dup-entry`;
  - log/73, 74 and 75 become `dup-entry`;
  - `log-republish/14-params-canonical-true` is cancelled by its own non-canonical
    predecessor 13. That is run 15's H2 in another form, and the suite holds it.
- **Change.** Drop the claim, or narrow it to "cannot be separated from a reader
  that hashes a *strictly* re-encoded form".

### L5 — §10's veto argument over-claims what name-and-key-id matching buys

- **Where.** §10, in the outline's comment: "a line carrying a listed witness's name
  under some other key names nobody … The other reading hands anyone a veto". Also
  the §12.1 row "§10 the origin comparison is **equality**": "a name-only match
  hands anyone a veto".
- **Problem.** The key id is four public bytes, copied from any checkpoint. A line
  `— norn-witness/pi base64(id_pi ‖ ts ‖ junk)` matches pi by name and id, fails,
  and refuses the head as `cosignature`, with no grinding. So name-and-id matching
  does not take the veto away from a malicious line-appender. It takes it away only
  from an honest stranger who reuses a name. Conforming readers still agree, so
  nothing a node does differs. Whoever can add lines (the log, a relay) could
  already withhold.
- **Change.** Say that the rule protects against accidental name reuse, and that a
  forged line naming a listed witness is refused by design (as `checkpoints-bad/08`
  shows).

### L6 — §8.1 condition 1 says "trust policy"

- **Where.** §8.1, "1. the bundle's checkpoint verifies under the node's trust
  policy (§9)".
- **Problem.** §8.1's own checking paragraph says "the policy of that state", and
  §5.3 says "the trust file's, or the most recently replayed". The vectors pin the
  replayed policy (`replayed-policy/bundle-informed` is `quorum`;
  `reader-always-trust-policy` is caught).
- **Change.** "verifies under the policy in force (§9.4)".

### L7 — §14.1's "base64 appears only inside notes" is contradicted by §13.3

- **Where.** §14.1 byte strings: "never base64 (base64 appears only inside notes,
  §7)". §13.3: "`wg_pk` (base64 WireGuard public key)".
- **Problem.** `proven.json` is not §14-canonical, but the parenthesis is an
  absolute claim.
- **Change.** "(base64 appears in this document's canonical JSON nowhere; notes
  (§7) and `proven.json` (§13.3) use it)".

## 4 Declared survivors — §12.1's "What is not vectored", each checked

| # | item | checked how | result |
|---|---|---|---|
| 1 | §3.1 vectored at every admission point; policy `log` line by `log-order/15` | variants `*-no-point-check` at all 11 sites | all caught. `policy-no-log-point-check` is caught by log-order/15. Confirmed |
| 2 | source-neutral acquisition | harness serves directories only | not testable statically. Confirmed |
| 3 | §13 reconciliation, `proven.json` | not implemented (node behaviour); text read for ambiguities | outside the static suite. Confirmed. Two normative gaps there: M1 (clip vs withhold) and M2 (overlap) |
| 4 | §16.3 key handling | not implemented | outside the static suite. Confirmed |
| 5 | `none` as a group member | `policy-allow-none-member` | survives (refused as undefined). Confirmed |
| 6 | CR inside a policy verifier key | `b64-lenient-vkey` | caught only through the trust `log_key` (trust-bad/44). Inside a policy the control-byte rule refuses first. Confirmed |
| 7 | OpenTimestamps attestations | digest range only (`anchor-range-text`, `-whole` caught) | proof trees not validated. Confirmed |
| 8 | "a key contributes at most once" | `count-no-dedupe` | survives; `sigs-repeat-ok` is caught by log/134. Confirmed |
| 9 | "must not count it even in the moment before that refusal" | my `checkCosigs` returns nothing on refusal | unobservable. Confirmed |
| 10 | order of entry 0's steps | single code `bad-genesis` | unobservable by construction. Confirmed |
| 11 | §3.1 canonical clauses | `ed-lenient-decode` plus exhaustive check of the 24 lenient encodings | survives; none has order L. Confirmed |
| 12 | blank line inside a note's text | `note-last-blank` | caught by 45 (between signatures). Inside text both readings refuse on line count. Confirmed |
| 13 | "never from a supplied proof" | no shipped file carries one | unobservable. Confirmed |
| 14 | §16.1's 32-byte `device_pk` | `req-pk-any-length` | survives (point admission refuses). Confirmed |
| 15 | `state.net` from the anchor | `state-net-from-genesis` | survives. Confirmed |
| 16 | `entry_hash` as received vs re-canonicalised | `entryhash-recanonical` | **caught by 11 checks: the claim is wrong (L4)** |
| 17 | `MAX_ENTRY_BYTES` on an embedded request | `cap-request-±` | survive. Confirmed |
| 18 | witness key must be a cosignature key at verification | policy grammar fixes 0x04 before any line is checked | unreachable. Confirmed |
| 19 | `dup-wg` for `enroll`: any vs another device | `enroll-dupwg-other-only` | survives. Confirmed |
| 20 | run 16 L8 rules "now vectored"; frozen set, CLOCK_SKEW, restart are node behaviour | the run 16 rows' variants (`proofs/nas-rotate`, `laptop-revoke`, etc.) | caught; node behaviour outside the suite. Confirmed |
| 21 | run 17 D11 rules "now vectored" | `kid-case-insensitive`, `enroll-roots-may-authorise`, `req-expires-zero-ok`, `note-allow-unsigned`, grant forms, `reader-always-trust-policy`, `binding-no-point-check`, `cbor-allow-empty-key`, `qt-none-is-max`, `expiry-no-clock-drops`, `loop-genesis-pin-only` | all caught. Confirmed |

The list is accurate except item 16. It is also incomplete: L1 and L2 name rules
that belong on it.

## 5 Decisions the vectors pinned, and decisions they did not

For each logged decision I ran the opposite reading as a sweep variant.

**Pinned**, meaning the opposite reading is caught:

- C01, C03: point validity and every admission site.
- C04, C05, C07–C11: profile allow-list, both halves of shortest form, map-key text
  and length, key order, UTF-8, trailing bytes, depth.
- C12: every artifact cap, both sides, except the entry cap at the bundle layer and
  the request cap.
- C13–C15, C17–C19: device_id, names and text caps, labels, kid, sigs order,
  booleans in bodies.
- C20–C25: grant split and trim, mapped-before-masking for the dotted form, the
  IPv6 grammar, RFC 5952 rendering, sort.
- C26–C33, C35–C46: envelope, both seen sets, content hash, signature resolution,
  revoke, note threshold, request decoding, `expires` > `ts`, the rotate order,
  enroll `prev`, governance `prev` except `params`, kid dup-key, log-key and policy
  disjointness (witness lines only), params types and zero values, thresholds, the
  root invariant, bootstrap, state and JSON.
- C47–C56: note framing (except the empty-text case), names, exact lengths,
  cosignature bounds, checkpoint body including size `0`, learned keys named the
  origin, listed witnesses, group semantics, quorum time, the receipt order.
- C57–C61: paths, fallback only when the file is absent, the loop order, zero
  frames, fork vs rollback.
- C62–C64: bundle schema, inclusion, structural binding.
- C65–C67: trust file (except P6–P8), policy grammar, vkeys.
- C68: fingerprint.
- C69–C71: evidence order (except cbor/version) and proofs.
- C72–C74: freshness ladder and the age estimate.
- C75: bech32m.
- C77: anchors.
- C34: `wg_pk` is not validated. `heads-run16/request-this-network` carries an
  all-zero `wg_pk` and must be accepted, which pins it at the consumer.

**Not pinned**, meaning the opposite reading survives:

- **C16**: genesis keys distinct by bytes rather than by kid. This is M3.
- **C06**: the CBOR integer at exactly 2⁶³.
- **C19**: booleans in envelope uint members.
- **C37**: `params` `prev`.
- **C47**: the empty-text note.
- **C64**: binding field rules beyond the id grammar and the point.
- **C65**: trust-name UTF-8, the optional policy log line, short-name
  correspondence.
- **C69**: evidence `cbor` before `version`.
- **C76**: request layer order. It has no closed codes, so it is unobservable by
  design.

I also tested three readings that are not in the decisions log:

- The re-read held head must still be verified (P12). Not pinned.
- Replay does not judge `expires` against the entry's `ts` (P10). Not pinned.
- Mapped prefixes are judged by value, whatever the spelling (P11). Not pinned.

## 6 Verdict

No H defect was found. Three M defects:

- M1: whether a provider prefix wider than the grant is clipped or withheld.
- M2: what is installed for overlapping allowed-ips. The only answer is in an
  informative companion.
- M3: genesis `kid` collisions.

Each is a point where SPEC.md's text supports two readings that change what a node
does, reachable through operator configuration. M1 and M2 are in §13, which no
vector reaches. M3 is a survivor of the sweep.

There are also seven L defects. L1 alone lists 13 rules that are stated plainly and
held by no vector, each with a concrete input in `work/probes/` on which the two
readings disagree. Every one of 3782 checks passes, the first full run included.
Passing every vector is not the criterion, and a second implementer reading SPEC.md
alone could still get M1–M3 wrong.

SPEC INSUFFICIENT
