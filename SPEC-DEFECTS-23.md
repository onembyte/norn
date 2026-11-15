# Cold gate run 23 — specification defects

Reader: a cold implementer holding only `SPEC.md` and `testdata/vectors/`.
Implementation: Go, standard library only, `work/impl/` (`norn/` library,
`cmd/harness` runner, `cmd/construct` counterexample builder). Decisions taken
before any vector was opened: `work/decisions.md` (C01–C73), not edited since.

## 1 Tally

- **Digests.** All 1313 lines of `testdata/vectors/SHA256SUMS` verify (`shasum -a 256 -c`, and again
  inside the Go harness), and the list names exactly the 1313 shipped files besides itself.
- **Before the first full run.** The harness was built section by section. The first run of the
  replay section alone gave 731 pass / 80 fail:
  - 45 were every `state.json`, from a bug in my own JSON string escaper (no closing quote);
  - 32 were the harness expecting `.reason` files that `genesis/` does not ship;
  - 3 were the harness comparing an applied entry with the `codes` maps' `accept`.

  The second run had only those 3, and they were then fixed. None of the 80 was a protocol reading.
- **First full run** (every manifest, `cases.json`, mirror and state file): **4625 checks, 4625
  pass, 0 fail.**
- I then added two variant-independent sections: the digest list in Go (1314 checks) and a check
  that every manifest `rules` phrase occurs in the SPEC section it names (596 checks; all occur).
- **Final run:** **6535 checks, 6535 pass, 0 fail** (`work/run-final.txt`, every check listed).
  Every closed code a manifest names is compared exactly: replay reasons (§5.2), receipt codes (§7),
  loop and bundle codes (§10.1), evidence codes (§11.1). Where a manifest gives only `says`, I mapped
  the hint by hand onto my own refusal reason: trust-bad reasons, request layers, entries-hostile
  rules and CCTV deciding flags.

## 2 The sweep

Every variant flips one decision of the base at its decision point (`V("name")` switches in
`work/impl/norn/`). Each was run against the whole suite (`work/sweep.sh`; results under
`work/sweep/`).

**Single variants: 466 distinct.** They come in four rounds: 419, then 25, then 10, then 14
(`work/variants*.txt`). That is 468 runs, because two variants were re-run after I corrected how
they model their reading: `ev-v2-split-optional` and `trust-correspond-casefold`. They cover:

- every profile ban and cap on both sides of each boundary: depth 7/9, key cap 22/24, entry
  65534/65536, bundle 81918/81920, trust and evidence 65535/65537, text 4095/4097, reason 255/257,
  labels 31/33, names 63/65;
- every field rule, every adjacent pair of every ordered list (replay steps, each type rule, the
  §10.1 loop, bundles, evidence, receipts), every comparison, every encoding choice, the grammars,
  key and policy rotation, freshness and expiry, the text layers, and the tile and Merkle
  algorithms.

**Results at outcome level** (closed codes and accept/refuse): **419 caught, 47 survive.** At the
level of my hand mappings, 4 more are caught: `req-pk-any-length`, `trust-correspond-strike-off`,
`trust-witness-name-skip-grammar` and `trust-correspond-casefold`. Each still refuses the same
file, only with another reason.

The 47 survivors, classified (`work/final-survivors.txt`):

| class | count | variants |
|---|---|---|
| equivalent, declared in §12.1 "What is not vectored" | 15 | `ed-skip-canonical-y`, `ed-skip-reencode`, `ed-skip-r-order-only`, `policy-none-member-ok`, `ev-skip-split-le-size`, `sig-count-repeats`, `trust-witness-any-alg`, `trust-witness-name-skip-grammar`, `req-pk-any-length`, `state-net-from-genesis`, `entry-hash-reencoded`, `req-cap-uncapped`, `enroll-dupwg-another-only`, `genesis-no-byte-key`, `dupkey-by-pk` |
| equivalent, stated in the body | 4 | `ed-cofactored` (§3.1 item 3), `note-split-last-space` (§7), `policy-sep-vt-ff-cr` (§9.1 field-count row), `trust-correspond-strike-off` (§9.1 policy row: it still refuses duplicates) |
| equivalent, undeclared, by construction | 6 | `bech32-first-separator` (the HRP `norn` has no `1`, and the data charset has none either), `incl-ignore-short` and `cons-ignore-short` (a short path ends at a subtree hash, never the root, barring a SHA-256 collision), `entry-cap-65536` (a 65536-byte entry cannot be framed behind a uint16, and the bundle and decoder caps are vectored separately), `unknown-type-before-content-dup` (applied content always has a known `t`), `trust-witness-refuse-only-01` alone (correspondence puts the key into the policy grammar; it is genuine only with `policy-witness-refuse-only-01`) |
| **genuine: a distinguishing input was built** | 22 | listed below; inputs in `work/counterexamples/` |

The 22 genuine survivors, plus the one composite that unmasks `trust-witness-refuse-only-01`, and their concrete inputs (`work/impl/cmd/construct`, output in
`work/counterexamples.txt`, `work/counterexamples-round4.txt` and `work/collide.txt`). Each input is
signed with the suite's own keys where it needs a signature. Each constructed refusal was checked to
be for its intended rule only (`work/construct why`). Repeated runs give byte-identical results.

| variant | input | base | variant |
|---|---|---|---|
| `grant-mapped-drop-part` | signed `enroll` with request label `ip = "10.9.0.0/24, ::ffff:10.9.0.1/128"` (applies) | grant `[]` | `["10.9.0.0/24"]` |
| `grant-allow-two-dcolon` | same, `fd00::1::5/128` | `[]` | `["fd00:0:1::5/128"]` |
| `grant-octet-allow-256` | same, `10.9.0.256/32` | `[]` | a grant |
| `logsig-try-all-matching` | log keys K1, K2 published by the roots with equal key id `068aa69c` under the origin (birthday search, 67,966 keys); a grown head signed by K2 | `log-signature` | accept |
| `trust-logkey-refuse-only-04` | `trust.cbor` with `log_key` under algorithm 0x02 (id recomputed), policy log line removed | invalid | valid |
| `trust-witness-refuse-only-01` + `policy-witness-refuse-only-01` | `trust.cbor` with pi's key under algorithm 0x02 in both halves | invalid | valid |
| `policy-log-refuse-only-04` | root-signed `policy` entry, prev 0, with a `log` line under algorithm 0x02 | `decode` | applied |
| `policy-witness-refuse-only-01` | same, a `witness` line under algorithm 0x02 | `decode` | applied |
| `held-relax-by-size` | reader holds `served/`'s head; offered a 162-entry branch with another last entry, log-signed, cosigned by pi alone | `quorum` | `fork` |
| `bundle-held-relax` | `proofs/nas.bundle` with its checkpoint replaced by `served-superseded/checkpoint`; informed reader holding `served/` | `quorum` | accept |
| `ev-held-relax` | `fork/evidence.cbor` with `held` replaced by `served-superseded/checkpoint`; the same reader | `held` | fork proved |
| `tiles-skip-missing-upper` | `served-large/` with `tile/1/000.p/1` removed | `unserved` | accept |
| `params-routes-granted-only` | root-signed `params {routes: "advisory"}`, prev 0 | applied | `decode` |
| `rotate-roots-ok` | `rotate_needs_signer` true; a rotate signed by the device and two roots | `threshold` | applied |
| `rotate-dup-device-pk` | laptop rotates to nas's `device_pk` (both signatures present) | applied | refused |
| `devid-no-trailing-dot-dash` | signed enrol of `edge.` | applied | `decode` |
| `genesis-after-forbidden` | fixture genesis with `after: 0`, re-signed, its own leaf pin | applied | `bad-genesis` |
| `logkey-overlap-positive` | root-signed `log_key` with `overlap: 0` | applied | `decode` |
| `cbor-allow-simple-ge32` | `fork/bad-simple-size.cbor` with `f0` → `f8 20` | `cbor` | `schema` |
| `decimal-allow-plus` | served head with size line `+162`, log-signed, cosigned by all three; receipt with deadline `+1760000060` | `checkpoint`, `deadline` | accept, accept |
| `policy-k-allow-plus` | trust policy with `group home +2 pi vps friend` | refused | parses |
| `note-name-zwsp-space` | `served/checkpoint` plus a stranger line named `witness.example/a<U+200B>b` | accept | `note` |
| `trust-correspond-casefold` | `trust.cbor` with the array's `pi` renamed `PI` (policy still `pi`) | invalid | valid |

**Composites.**

- **After round 3: 538 composites.** 496 pair every two of the 32 survivors then known. 31 of those
  are caught, each because it contains `ev-v2-split-optional`, which stopped being a survivor once
  that variant modelled its reading in full. The other 465 all survive: no two survivors catch each
  other through interaction.
- The other 42 pair a survivor with a related caught variant. 39 are caught. 3 survive, and each
  reduces to its surviving half: `params-routes-granted-only`×`params-routes-open`,
  `policy-witness-refuse-only-01`×`trust-witness-any-alg` and
  `trust-correspond-casefold`×`trust-correspond-names-only`.
- Pairs the spec itself discusses behave as it says:
  - `sig-count-repeats`×`sigs-repeat-ok` is caught by `log/134`.
  - `ed-skip-canonical-y`×`ed-skip-reencode` survives, as §12.1 predicts; each of them paired with
    `ed-skip-order-check` is caught.
  - `trust-witness-any-alg`×`policy-witness-any-alg` is caught.
- **After round 4: 497 composites** (`work/variants-composite4.txt`).
  - 403 pair a round-4 survivor with each earlier survivor. Exactly one is caught:
    `ed-skip-r-order-only`×`ed-cofactored`. Both are equivalent alone, but together they accept a
    mixed-order `R` under the cofactored equation, and `requests-bad/torsion-R-signature` and its
    peers catch them. This is the interaction §3.1 item 3 describes.
  - 78 pair round-4 survivors with each other; none is caught.
  - 16 pair a round-4 survivor with a related caught variant. 13 are caught; the 3 survivors reduce
    to their surviving halves.
- **Total: 1035 composites.**

## 3 Defects

Most severe first. "Unvectored" means no shipped file separates the readings. "Undeclared" means
§12.1 does not name it, although the preamble says "§12.1 lists what is vectored and what is not.
It does not claim every MUST is vectored — several are not, and they are named there."

### D1 — H — §4.0: an IPv4-mapped prefix inside a multi-prefix `ip` label

- **Words.** "a label that is absent or does not parse **as a whole** is **no grant**: a bound with
  a hole in it is not the bound the signers signed, so the parts that did parse count for nothing.
  An IPv4-mapped IPv6 prefix is no grant either, whatever its spelling: its address before masking
  lies in `::ffff:0:0/96`."
- **What a second implementer cannot know.** The mapped prefix is syntactically a valid RFC 4291
  prefix, so the label does "parse as a whole". The sentence then says the *prefix* is no grant.
  - Reading A (mine, C41, decided before the vectors): such a part voids the whole label.
  - Reading B: the mapped prefix contributes nothing and the other parts stand.
  - Both satisfy the stated rationale, that implementations render mapped addresses differently.
- **Proof.** Every mapped case in `proven/grant-labels.json` (`::ffff:10.0.0.1/128`,
  `::ffff:10.0.0.1/0`, `::ffff:a00:1/128`, `0:0:0:0:0:ffff:a00:1/128`) is a one-part label, where
  both readings give `[]`. Survivor `grant-mapped-drop-part`.
  - Input: `work/counterexamples/grant-mapped-drop-part/enroll.cbor`, a signer-signed `enroll`
    whose device-signed request carries `ip = "10.9.0.0/24, ::ffff:10.9.0.1/128"`. Replay applies it
    under both readings; the grant is `[]` or `["10.9.0.0/24"]`.
  - Under `routes = "granted"` (the default) one node installs `10.9.0.0/24` for the peer and the
    other installs nothing. `proven.json` publishes different `grant` arrays.
  - The input is an ordinary signed enrolment the network carries, which is why this is H. It is M
    if one counts such a label as malformed input.
- **Smallest change.** Replace the sentence with: "A part whose address, before masking, lies in
  `::ffff:0:0/96` does not parse, so a label holding one is no grant." Add the grant-labels case
  `10.9.0.0/24, ::ffff:10.9.0.1/128` → `[]`.

### D2 — M — §7, §9.4: two trusted keys with the same name and key id

- **Words.**
  - §7: "the signature line's key name and key id select the key — no key is tried against a line
    that does not name it" (receipt step 2).
  - §7: "What follows the key id is judged by the trusted key whose name and key id the line
    matches".
  - §9.4: "A learned key is the verifier key `<origin>+<id>+base64(0x01 ‖ pk)`: named the origin".
  - §5.1 `log_key` compares only "as public-key bytes".
- **What a second implementer cannot know.** Every log key, the anchor's and every learned one,
  has the same name, so only a 4-byte id separates them. Nothing refuses a published key whose id
  equals an active one's, and nothing says which key "the key" is when two match. Readers split:
  - First match, or "must verify under every matching key": refuse.
  - Any match: accept.
  - `golang.org/x/mod/sumdb/note`, which §7 cites as the reference: as I recall it, it reports an
    ambiguous key. I consulted no source, per the no-network rule.
- **Proof.** Survivor `logsig-try-all-matching`.
  - A birthday search over deterministic seeds found two keys with key id `068aa69c` under
    `norn/nzxxe3rnorsxg5domv2c2mbqge` after 67,966 keys, about two seconds.
  - The roots publish both (`log_key` prev 0, then prev 1). The log signs its next head with the
    second key: base `log-signature`, variant accept. With only the second key published, both
    accept.
  - Files: `work/counterexamples/logsig-try-all-matching/` (seeds, tiles, checkpoint).
  - Two first-match readers also disagree with each other if they hold their keys in different
    orders: one accepts K2's heads and refuses K1's, the other the reverse.
  - The same holds for two witness lines that share a note name.
  - The log operator chooses the keys the roots publish, so it can split the readers at will.
    Rated M only because it takes a deliberately ground key.
- **Smallest change.** In §5.1's `log_key` row add "· `pk`'s key id under the origin is not an
  active log key's (`dup-key`)". In §9.1 add "two verifier keys with the same name and key id are an
  error". Or state in §7: "a line that matches two trusted keys refuses the note".

### D3 — M (trust `log_key`) / L (grammar) — §9.1: the algorithm rules are worded as exclusions

- **Words.**
  - `log_key`: "signed-note verifier key for the log (algorithm `0x01`); MUST parse as one, MUST NOT
    be a cosignature key".
  - `witnesses`: "`key` is a **cosignature** verifier key — `c2sp.org/tlog-cosignature` algorithm
    `0x04`, not a note key's `0x01`".
  - Grammar: "A `log` vkey MUST use algorithm `0x01`; a `witness` vkey MUST use algorithm `0x04`."
- **What a second implementer can get wrong.** The only normative clause in the trust row is the
  exclusion. A reader that refuses exactly the other role's algorithm accepts a third algorithm
  byte. Every negative the suite has uses the other role's algorithm. Across all trust files and
  policies, the only algorithm bytes present are `0x01` and `0x04` (checked with
  `work/construct inspect`). The negatives:
  - `trust-bad/15`, `16` and `53`;
  - `policies/bad-witness-vkey-algorithm-distinct` and `bad-log-vkey-algorithm-distinct`;
  - `log-edges/11` and `13`.
- **Proof.** Survivors `trust-logkey-refuse-only-04`, `policy-log-refuse-only-04` and
  `policy-witness-refuse-only-01`; also `trust-witness-refuse-only-01` together with
  `policy-witness-refuse-only-01`.
  - `work/counterexamples/trust-logkey-refuse-only-04/trust.cbor` is a log key under algorithm
    0x02, with its id recomputed and no policy log line: invalid vs valid. The two readers disagree
    on whether a node starts.
  - `policy-*-refuse-only-*/policy.cbor` are root-signed `policy` entries carrying a 0x02 key:
    `decode` vs applied. The replayed states diverge, as does every later `prev`.
- **Smallest change.** Trust rows: "MUST parse as a verifier key with algorithm `0x01`" (and
  `0x04`). Add one trust and one policy vector with algorithm `0x02`.

### D4 — L — unvectored, undeclared rules a careful reader gets right

Each is plain in the text. Each survives the suite, and §12.1 does not name it. Inputs for all are
in §2's table.

- **(a) A held head is origin, size *and root*.** §5.3: "**This checkpoint** is its tree head —
  origin, size and root". A reader that relaxes the quorum on size alone accuses a fork from a head
  no quorum signed: `held-relax-by-size`, `quorum` vs `fork`. This is the most consequential reader
  error in this class, and no file tests it.
- **(b) Bundles and evidence are checked under the current policy even at the held head.** §5.3: "a
  checkpoint carried inside a bundle (§8.1) or fork evidence (§11.1) is checked under the policy the
  reader holds now ... even when it names the tree head the reader already holds".
  `replayed-policy/`'s informed reader holds no head, so neither half is tested: `bundle-held-relax`
  (`quorum` vs accept) and `ev-held-relax` (`held` vs fork proved).
- **(c) Which hash tiles step 12 needs.** §10.1 step 1: "a hash tile (step 12)". Missing level-0
  tiles and a tampered level-1 tile are vectored. A missing level-1 tile is not:
  `tiles-skip-missing-upper`, `unserved` vs accept. The text never lists the tiles a size implies.
  It should say "every tile at every level `L` with `size ≥ 256^L`".
- **(d) Positive values no file carries:**
  - `routes = "advisory"` (`params-routes-granted-only`);
  - a genesis `after: 0` (§5.1 step 5, "MUST be 0"; `genesis-after-forbidden`);
  - `overlap: 0` (`logkey-overlap-positive`);
  - a `device_id` ending in `.` or `-` (`devid-no-trailing-dot-dash`);
  - a rotate onto another device's `device_pk`, which no rule forbids (`rotate-dup-device-pk`);
  - a stranger's signature-line name holding a character outside §7's white-space list, e.g.
    U+200B, which must be ignored rather than refused (`note-name-zwsp-space`).
- **(e) Negatives no file carries:**
  - roots standing in for signers under `rotate_needs_signer` (`rotate-roots-ok`);
  - `f8 20`–`f8 ff` (§4.0 "32–255 in the two-byte form", `cbor-allow-simple-ge32`);
  - a `+` sign on a canonical decimal: checkpoint size, receipt deadline, policy `k`
    (`decimal-allow-plus`, `policy-k-allow-plus`);
  - two `::` and an octet above 255 in a grant (`grant-allow-two-dcolon`, `grant-octet-allow-256`);
  - case-folded witness-name correspondence in a trust file (`trust-correspond-casefold`).
- **Smallest change.** Ship one file per item. Failing that, extend §12.1's "What is not vectored"
  so that the preamble's claim holds.

### D5 — L — §8.1 condition 2 has no procedure and no code

- **Words.** "the bundle's checkpoint is consistent with the node's stored checkpoint". A bundle
  carries no consistency proof, and §10.1's closed bundle list has no code for this failure.
- `proofs-older-head/` ships only consistent bundles.
- A reader cannot tell what to do with an inconsistent head, which is evidence of a fork, or with a
  newer head beyond saying it "installs nothing". Installs come from replay to the stored head, so
  nothing a node installs differs.
- **Smallest change.** "consistent: the node's own branch has the bundle's root at the bundle's
  size; a bundle whose head is newer is not judged until a checkpoint at least that large is
  accepted; an inconsistent one is refused and handled as §11."

### D6 — L — §7's comparison with `golang.org/x/mod/sumdb/note`

- **Words.** "They differ in two places." D2 is plausibly a third: how a key name and id that
  match two keys are treated.
- **Smallest change.** Settle D2 and say how it relates to that library.

## 4 Declared survivors — §12.1 "What is not vectored", each checked

| item | checked by | result |
|---|---|---|
| §3.1 vectored at every admission point, including the policy `log` line | `genesis-skip-point`, `genesis-skip-signer-point`, `keyadd-skip-point`, `logkey-skip-point`, `rotate-skip-point`, `policy-skip-point`, `req-skip-point`, `trust-skip-point`, `ev-policy-skip-point` | every one caught: the positive claim holds |
| source-neutral acquisition; §13 reconciliation and `proven.json`; §16.3 | — | not static; §13.1's grant bound and overlap rule not implemented here (declared) |
| `none` as a group member | `policy-none-member-ok` | survives, equivalent (undefined anyway); confirmed |
| CR inside a policy verifier key | `vkey-lax-base64` (caught by `trust-bad/44`) and `policy-allow-cr` (caught) | confirmed: the control rule decides first |
| OpenTimestamps attestations | digest range checked (`anchors/`) | confirmed; containers not parsed |
| "a key contributes at most once" | `sig-count-repeats` survives; with `sigs-repeat-ok`, caught by `log/134` | confirmed, including the mutual masking |
| §5.3 "the moment before that refusal" | my verifier returns no cosignatures on refusal | unobservable; confirmed |
| order of entry 0's steps | single code `bad-genesis` | unobservable; confirmed |
| §3.1's canonical clauses | `ed-skip-canonical-y`, `ed-skip-reencode` (and both together) survive; with `ed-skip-order-check`, caught | confirmed |
| a blank line inside a note's text | `note-text-ends-at-last-blank` caught by `checkpoints-bad/45` | confirmed |
| §10 "never from a supplied proof" | my reader never takes one | unobservable statically; confirmed |
| §16.1's 32-byte `device_pk` | `req-pk-any-length` refuses the same files (at point admission) | confirmed: refused, never isolated |
| `state.net` from the anchor | `state-net-from-genesis` survives | confirmed |
| `entry_hash` over bytes as received | `entry-hash-reencoded` survives; lenient re-encoders (`cbor-allow-trailing` etc.) caught | confirmed |
| `MAX_ENTRY_BYTES` on an embedded request | `req-cap-uncapped` survives | confirmed |
| witness key a cosignature key at verification | my verifier never checks it there | unreachable; confirmed |
| `dup-wg` at enrol "any" vs "another" | `enroll-dupwg-another-only` survives | confirmed |
| entry 0's byte key | `genesis-no-byte-key` survives (`genesis-no-content-key` is caught by `log-republish/15`) | confirmed |
| two keys with the same `kid` | `dupkey-by-pk` survives | confirmed. The same birthday argument at 2^16 makes D2 practical, so the 32-bit signed-note id deserves the attention this item gives the 64-bit `kid` |
| separate `split` ≤ `size` | `ev-skip-split-le-size` survives | confirmed |
| trust witness algorithm and name rules | `trust-witness-any-alg`, `trust-witness-name-skip-grammar` survive (outcome) | confirmed, but see D3: a *third* algorithm is masked only while the policy grammar is exact |
| subgroup check on R | `ed-skip-r-order-only` survives; `ed-skip-r-check` caught by CCTV 304; `ed-skip-r-order-only`×`ed-cofactored` caught by the torsion-R vectors | confirmed: the check is redundant only under the cofactorless equation |
| run 16 and 17 lists "now vectored" | their variants are all caught | confirmed |

## 5 Decisions the vectors pinned, and decisions they did not

**Pinned.** Each was caught by its variant.

- C01–C03, C05, C06, C08, C09: the profile.
- C04, except two-byte simple ≥ 32.
- C07: entry, bundle, trust and evidence caps.
- C10–C24 and C26–C31: envelope, `sigs`, both seen sets, every type rule and its order, `prev`,
  `after`, genesis.
- C25, except an `advisory` positive.
- C33–C36: state, canonical JSON, `T`, expiry.
- C37: same-head copies from the log.
- C38–C40, C42: grant trimming, octets, lengths, RFC 5952, masking, sorting.
- C43, C44, C46: note framing.
- C47: name and id matching, learned key names.
- C48–C51, C53–C56, C58, C59: checkpoint, cosignature, quorum, anchors, paths, fallback, branch
  comparison, genesis.
- C52: receipts and their order.
- C60–C63: bundles and binding.
- C64–C66: trust fields, correspondence by text, fingerprint.
- C67: the policy grammar.
- C68, C69: evidence.
- C70: bech32m and requests.
- C71: NORN-ED25519-v1.
- C72: freshness.

**Not pinned:**

- C41: a mapped part in a multi-part label (D1).
- C47: uniqueness of a (name, key id) match (D2).
- C64/C67: a third algorithm byte (D3).
- C37: size-only relaxation, bundle and evidence relaxation (D4 a, b).
- C57: upper-level tiles (D4 c).
- C25, C27, C23 positives; C32 (no `device_pk` uniqueness); C18 (roots under
  `rotate_needs_signer`); C04 two-byte simple ≥ 32; C49/C52 and C67 signs; C39 two `::` and octet
  bounds; C45 non-listed characters; C64 name case (D4 d, e).
- C07 request cap and C31: declared unobservable.
- C73 (§13 reconciliation): declared, not implemented.

## 6 Verdict

- **D1 (H).** A device's own `ip` label can make two conforming nodes install different allowed-ips.
- **D2 and D3 (M).** Two readings of key selection and of the algorithm rules change what a node
  accepts, through a deliberately ground key or an operator's trust file.
- **D4–D6 (L).** The rest are unvectored rules that a careful reader of the text gets right, and two
  wording gaps.

SPEC INSUFFICIENT
