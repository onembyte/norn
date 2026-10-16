# Cold gate run 17 — SPEC defects

Reader: an independent implementer working from `SPEC.md` and `testdata/vectors/` only.
Implementation: Go, standard library only, `work/impl/` (library `norn/`, harness
`cmd/harness/`, survivor constructor `cmd/survivors/`). Ed25519 verification (NORN-ED25519-v1),
the RFC 9162 proof verifiers and bech32m are written from the standards; `crypto/ed25519` is
used only to *sign* the inputs built for survivors. The reading decisions were logged in
`work/decisions.md` (C01–C90) before any vector, manifest or the vector README was opened.

## 1 Tally

`SHA256SUMS`: all 1059 digests verify, and the list names exactly the 1059 shipped files
other than itself (checked twice: once with `shasum -c` before any implementation, once
per file inside the harness).

| run | checks | pass | fail |
|---|---|---|---|
| first full run (`work/run-first.txt`) | 3326 | 3254 | 72 |
| final run (`work/run-final.txt`) | 3274 | 3274 | 0 |

The 72 first-run failures, by cause:

- **19 — my implementation.** §5.1 step 7 (the root quorum for governance entries and the
  signer-or-root rule for `note`) was written but never called on the base path; it was
  only reachable through a variant switch. 15 entries of `log/` (from `26-bad-threshold-root`
  to `151-bad-precedence-note-threshold-before-body`, plus three accepted entries whose
  predecessors had wrongly applied), `log-cas/25-threshold-before-stale`, and the three states
  `log/state`, `log-cas/state` and `served/state` failed. Calling step 7 between step 6 and
  step 8 fixed all of them.
- **52 — my harness, not the implementation.** I expected a `.reason` file beside every
  refused entry in `genesis/<case>/` as `log/` has; those directories ship only
  `manifest.json` and `state.json` (26 missing-file errors, 26 empty reason comparisons).
  The final harness checks a `.reason` file wherever one ships, and requires one in every
  directory except `genesis/` (§12 promises them for `log/`, not for `genesis/`). These 52
  checks are gone from the final count.
- **1 — my harness.** The mirror of `requests/req-minimal-upper` carries its own uppercase
  text, not the canonical lowercase one.

Final per-area counts (all pass): sums 1059, cctv 915 (914 outcomes + count), keys 60,
entries 48, log 277, log-cas 68, log-order 43, log-republish 39, log-rules 34, log-edges 24,
log-admission 15, log-empty 1, genesis 52, genesis-good 4, hostile 17, trust 4, trust-bad 54,
trust-good 10, policies 76, requests 37, requests-bad 30, receipt 6, receipt-bad 20,
receipt-rotated 2, served 3, checkpoints-bad 47 (46 codes + the recomputed
`signature_blind_accepts` set), served-extra-witness 1, served-name-collision 1,
served-unknown-algorithm 1, served-stranger-name 1, served-twice-cosigned 2 (with its quorum
time), served-superseded 2, served-rotated 3, served-rotated-wrong-name 2,
served-rotated-earlier 2, served-empty-entry 4, served-large 43
(including the 40-row path table), served-bad 7, served-large-bad 3, grown-log 5,
served-genesis 4, detect 18, staleness 15, unreached-witness 2, dropped-witness 3,
heads-run16 11, proofs 38, proofs-bad 18, proofs-rotated 2, proven 44, grant-labels 41,
fork 53, anchors 3. Every check that has a closed code compares the code, not `says`.

## 2 The sweep

**Method.** Every variant is a switch at one decision point of the base implementation
(`norn/variants.go`; each `reg(...)` names the decision and the section). The harness runs
the whole suite once per variant in process; a variant is *caught* if any check that passes
for the base fails, otherwise it *survives*. Variants were enumerated from the decisions log
and from every rule the suite could see: each profile ban and cap on both sides of the
boundary, every field rule, every adjacent pair of every ordered check list (§5.1 steps,
each §5.1 type rule, entry 0, §10.1's loop, the bundle steps, the evidence steps, the
receipt steps, the freshness ladder), every comparison (origins, names, key ids, public
keys, kids), every encoding (CBOR heads, base64, decimal, bech32m, canonical JSON), the
policy grammar row by row, key and policy rotation, freshness, expiry, note framing, tiles
and the Merkle algorithms.

**Counts.** 446 single-decision variants: **400 caught, 46 survive.** (Five rounds:
`work/sweep-1.txt` 417, then 13, 5, 7 and 4 more after reading the first results; two weak
round-1 variants were redefined more strongly in round 2 and are counted once, at their
final definition.)

**Survivors, classified** (concrete inputs in `work/survivors/`, results in
`work/survivors-table.txt`; "base → variant" is what the two decide on that input):

*A. Equivalent by construction — no input separates them (19).*
`ed-cofactored` (§3.1 item 3 proves the two equations agree once item 1 holds),
`ed-lenient-y`, `ed-lenient-x0-sign` (§12.1 declares both), `note-split-last-space` (§7
argues it: a name holding a space never frames), `gv-dup-key-by-pk` (a kid is a function of
the key), `bech32-first-separator` (neither `norn` nor the data charset contains `1`),
`req-pk-any-length` (§3.1's point admission needs 32 bytes), `trust-witness-alg-unchecked`,
`trust-witness-name-unicode`, `trust-witness-name-cap-65` (correspondence puts every
witness key and name in the policy, whose grammar enforces the same rules),
`trust-correspondence-strike-off` (with the uniqueness rule kept), `en-dup-wg-other-device-only`,
`ge-net-from-entry`, `rp-count-without-dedupe`, `ge-hash-before-type`,
`rp-entry-hash-recanonicalised`, `req-no-size-cap` (all declared in §12.1),
`cbor-length-vs-input-before-cap` (only the decoder's error kind changes; every artifact maps
both kinds to the same code), `req-consumer-net-before-sig` (a request consumer has no
closed code; both refuse).

*B. Observable, and the specification leaves the answer open (13)* — the defects of §3:
`pol-trailing-whitespace-is-a-field` (D1), `ev-trust-log-key-only` (D2),
`tile-fallback-full-length`, `bundle-fallback-exact` (D3), `ev-split-zero-root-unchecked` (D4),
`trust-policy-capped-4096` (D5), `bundle-binding-request-signature`,
`bundle-binding-request-net`, `bundle-binding-full-envelope` (D6), `bundle-entry-cap`,
`bundle-entry-decoded-under-bundle-cap` (D7), `bundle-short-hash-is-inclusion` (D8),
`ev-declared-length-is-oversize` (D9).

*C. Observable, the specification states the answer, no vector holds it (14)* — D11:

| variant | input | base → variant |
|---|---|---|
| `env-kid-case-insensitive` | `note-uppercase-kid.cbor` at index 162 of `log/` (signer1 signs; a surplus element with kid `ABCDEF0123456789`) | `decode` → accepted |
| `en-roots-count-for-enroll` | `enroll-by-roots.cbor` at 162 (device `probe`, request by `sundial`, the 3 current roots sign, no signer) | `threshold` → accepted |
| `vf-genesis-leaf-hash-only` | `trust-invalid-genesis.cbor` (genesis_hash of `log/0-genesis` with one of its two root signatures) + a one-entry log signed and cosigned | `genesis` → accept (an empty proven set) |
| `grant-sort-numeric` | label `9.0.0.0/8, 1::/16` | `[1::/16, 9.0.0.0/8]` → `[9.0.0.0/8, 1::/16]` |
| `grant-double-colon-may-be-empty` | label `1:2:3:4:5:6:7::8/128` | no grant → `[1:2:3:4:5:6:7:8/128]` |
| `req-expires-zero-is-none` | `request-expires-zero.cbor` (ts 1760020000, `expires: 0`, signed by `sundial`) | refused → accepted |
| `rc-no-signature-line-is-log-signature` | `receipt-unsigned.note` | `note` → `log-signature` |
| `ev-trust-policy-only` | `evidence-two-of-three.cbor` (both heads cosigned by pi and vps), read by a reader holding the replayed 3-of-3 policy | `held` → fork proved |
| `bundle-trust-policy-only` | `nas-two-of-three.bundle`, same reader | `quorum` → accept |
| `bundle-binding-request-raw` | `bundle-probe-81-bad-pk-length.bundle` (real entry 81, its request's own id `probe`) | `binding` → accept |
| `bundle-binding-request-no-point-check` | `bundle-probe-order8-request.bundle` (request `device_pk` of order 8) | `binding` → accept |
| `cbor-empty-key-ok` | `evidence-empty-key.cbor` (`fork/evidence.cbor` plus key `""`) | `cbor` → `schema` |
| `ck-quorum-none-needs-a-cosignature` | `served-uncosigned.checkpoint` under `trust-quorum-none.cbor` | accept → `quorum` |
| `t-quorum-none-unbounded` | `served/checkpoint` under `trust-quorum-none.cbor`, proven set | contractor kept → contractor dropped |

**Composites.** 1713 runs (`work/comp-out-*.txt`): every pair of the 46 survivors (1035)
and every survivor paired with each caught variant of its own family (678).

- *Survivor × survivor:* 0 of 1035 caught. No two survivors interact; each pair is as
  invisible to the suite as its members, and the inputs above separate the members one by one.
- *Survivor × caught:* 675 of 678 caught. Three survive:
  `trust-correspondence-strike-off` + `trust-duplicate-witness-name-ok` is the masking §9.1
  itself describes — a correspondence check that strikes names off refuses the duplicate
  `trust-bad/08` holds, so the uniqueness rule can be dropped unseen. It is equivalent, not a
  gap: both forms refuse every file with a repeated name. The other two
  (`bundle-no-quorum-check` + `bundle-trust-policy-only`,
  `trust-correspondence-strike-off` + `trust-correspondence-subset`) are artefacts of my
  switches sharing one branch — the survivor's branch returns before the caught switch is
  consulted — so each composite is its survivor alone.

## 3 Defects

Most severe first. Ratings as the brief defines them.

### D1 — H — §9.1 policy grammar: trailing whitespace on a line is undefined

**Words.** "ASCII space (`0x20`) and tab (`0x09`) separate fields, in runs." and the row
"leading whitespace | spaces and tabs before the keyword are not part of it". Nothing is said
of spaces or tabs after the last field.

**What a second implementer cannot know.** Whether `quorum home␠` is a one-argument
`quorum` line. A reader that removes leading blanks (as the row tells it to) and then splits
on separator runs — `re.split('[ \t]+', …)`, Go's `regexp.Split` — gets an empty last field
and refuses the line under the field-count row; a reader using `strings.Fields` semantics
accepts it. The spec singles out leading whitespace, which invites exactly the first reading.

**Proof.** `pol-trailing-whitespace-is-a-field` survives the whole suite. `work/survivors/policy-trailing-space.cbor` is a `policy` entry signed by the
log's three current roots with `prev` = `versions.policy`, whose text lowers the quorum to 1
of 3 and ends `quorum home␠\n`. Appended at index 162 of `log/`: the base applies it, the
variant refuses it as `decode`. Then `served-superseded/checkpoint` (cosigned by pi and vps):
a reader that applied the entry accepts it, the other refuses it as `quorum`. Two readers of
one root-signed log now hold two quorums — the failure the names row itself cites as the
reason that row exists ("a refused `policy` entry leaves two readers with different
quorums"). The same text in a trust file makes one reader start and the other refuse the
anchor.

**Smallest change.** Add a row: "trailing whitespace | spaces and tabs after the last field
are not part of it and add no field" (or forbid them, with a code), and ship
`policies/trailing-space` and `policies/trailing-tab` plus one root-signed `policy` entry in
a replay fixture.

### D2 — H — §11.1 step 1: which log keys verify evidence

**Words.** "verify **both** checkpoints per §10 — this network's origin, this network's log
key, and a satisfied witness quorum under the reader's own policy, never the one in the
file", with the opening claim that evidence is checkable "by a reader who has the network's
trust file and nothing else". §7 and §8.1, by contrast, spell out "the log keys the verifier
trusts … (§9.4: the trust file's, plus every `log_key` of a state it has accepted)". §11.1
alone says "this network's log key", singular, and spells out the replayed *policy* but not
the learned keys.

**What a second implementer cannot know.** After a log-key rotation, whether a node verifies
peer-supplied evidence under its learned keys (as §10 and §9.4 do for checkpoints) or under
`norn.trust.log_key` only (as the singular wording and the trust-file-only story suggest).
A fork signed under the published key is exactly what a log that rotated and then equivocated
produces.

**Proof.** `ev-trust-log-key-only` survives. `work/survivors/evidence-rotated-key.cbor`
(version 1): `held` is `served-rotated/checkpoint` (signed by `logkey2`, cosigned by all three
witnesses), `conflicting` is a size-162 head with another root signed by `logkey2` and
cosigned by pi, vps and friend, `held_root` is held's root, `proof` empty. A reader that has
replayed `served/` (and so learned `logkey2` at index 27) proves the fork under the base and
answers `held` under the variant; a reader holding only `trust.cbor` answers `held` either
way. By §11 rule 4 the first freezes for good and the second does not, on the same file.

**Smallest change.** Replace "this network's log key" with "the log keys the reader trusts
(§9.4: the trust file's, plus every `log_key` of a state it has accepted)", say that a reader
holding only the trust file refuses post-rotation evidence as `held` (as §8 says of bundles),
and ship this file with `fresh`/`informed` answers beside `proofs-rotated/`.

### D3 — M — §6 / §10.1: how a full tile or bundle used in place of a deleted partial is judged

**Words.** §6: "a verifier that cannot fetch `tile/<L>/<N>.p/<W>` MAY fetch `tile/<L>/<N>`
and use its first `W` hashes, and likewise the full entry bundle …; what it uses is compared
with the tree it rebuilt exactly as the partial path would have been". §10.1 step 12: "a tile
of width `W` is exactly 32 × `W` bytes, and a longer or shorter one disagrees whatever its
first 32 × `W` bytes say"; step 8: "Bytes after the last frame a full bundle needs are … this
code either way".

**What a second implementer cannot know.** Whether the fallback file is itself judged as a
full tile (exactly 8192 bytes; a full bundle of exactly 256 frames and nothing after) or only
by the first `W` hashes / frames it "uses". Both are faithful to one of the two sentences.

**Proof.** `tile-fallback-full-length` and `bundle-fallback-exact` survive. Over `grown-log/`
verifying its head at 162 with both partial paths absent: `tile/0/000` plus two trailing bytes
(`grown-full-tile-trailing.bin`) — base accept, variant `tiles`; `tile/0/000` cut to 162
hashes (`grown-full-tile-truncated.bin`) — accept vs `tiles`; `tile/entries/000` plus two
trailing bytes (`grown-full-bundle-trailing.bin`) — accept vs `entries`. A node verifying an
older head (a lagging peer's, or its own after restart) adopts it or not depending on the
reading. Reachable only through a malformed full file, hence M.

**Smallest change.** One sentence: "the full tile or bundle used in place of a partial must
itself be well formed (8192 bytes; exactly 256 frames), and only its first `W` are compared"
— or the opposite — plus `grown-log/full-tile-trailing-bytes`. (Related wording: §6 says the
verifier *MAY* fall back, while §10.1 step 1 makes `unserved` wrong whenever the full path is
served and `grown-log/older-head-over-full-tiles` requires acceptance; see D10.)

### D4 — M — §11.1: a non-zero `split_root` at `split` 0 has no rule and no code

**Words.** The `split_root` row: "All zero when `split` is 0"; step 4: "A `split` that is 0
carries an all-zero `split_root` and two empty proofs"; the `proof` code lists "a split proof
is carried where none is required" but nothing about the root.

**What a second implementer cannot know.** Whether evidence with `split` 0 and a non-zero
`split_root` is refused (and as `proof` or `schema`) or accepted. Accepted, it proves a fork
and — `split` 0 — makes the reader fail closed (§11 rule 3) for good.

**Proof.** `ev-split-zero-root-unchecked` survives. `work/survivors/evidence-split-zero-root.cbor`
(`fork/evidence.cbor` with `split` 0, `split_root` 0x01×32, both split proofs empty): base
`proof`, variant proves the fork.

**Smallest change.** Add to the `proof` code: "or, at `split` 0, a `split_root` that is not
all zero", and ship `fork/bad-split-zero-with-a-root` beside `bad-split-zero-with-a-proof`.

### D5 — M — §9.1: whether the 4096-byte policy cap binds a trust file's policy

**Words.** §4.0's field constraint "`text` (`note`, `policy`) | UTF-8, ≤ 4096 bytes" (an entry
field); §9.1's `policy` "verbatim `c2sp.org/tlog-policy`; MUST parse"; §3.1 / D-079 "a policy
parses one way everywhere".

**What a second implementer cannot know.** Whether the cap is part of what a policy *is* (and
so binds the trust file) or only a bound on the entry field. `fork/evidence-at-the-cap` pins
"no cap" for the policy evidence carries; nothing pins the trust file.

**Proof.** `trust-policy-capped-4096` survives. `work/survivors/trust-policy-over-4096.cbor`
(the shipped anchor with one witness URL lengthened; policy 4695 bytes, file 5432 bytes):
base valid, variant invalid — one node starts, the other refuses to (§13.2). Operator
configuration only, hence M. Note the consequence either way: a trust policy above 4096 bytes
can never be re-published as a `policy` entry.

**Smallest change.** "A trust file's `policy` is bounded only by `MAX_TRUST_BYTES`" (or the
opposite), and a `trust-good/policy-over-4096` vector.

### D6 — M — §8.1 binding: what "decodes under §16.1" covers, and whether the entry must be an entry

**Words.** "The id an `enroll` names is the one its request decodes to under §16.1: an entry
whose request does not decode, or whose body names no `device_id`, names no device"; "for the
other device types, the `device_id` in the body".

**What a second implementer cannot know.** §16.1 is the request format *and* the consumer's
duties (verify `sig`, refuse another network's request). Does a request with a forged
signature, or for another network, "decode"? And does an entry that fails §4.1 (for example
`v: 2`) still "name" the device in its body?

**Proof.** `bundle-binding-request-signature`, `bundle-binding-request-net` and
`bundle-binding-full-envelope` survive. Bundles over the real served head, each with a correct
inclusion proof and labelled with the request's own id: `log/98-bad-forged-device-sig`
(label `forged`) and `log/57-bad-request-net` (label `halfsigned`) — base accept, variant
`binding`; `bundle-nas-v2-rotate.bundle` (a rotate naming nas with `v: 2`, in a two-leaf tree
signed by `logkey` and cosigned) — base accept, variant `binding`. Enforcement is unaffected
(condition 3 replays), so M, not H. The shipped `proofs-bad/request-undecodable` does not pin
the rule either: its label `probe` differs from the undecodable request's own id, so a reader
that reads the raw request map also answers `binding`; `bundle-probe-81-bad-pk-length.bundle`
(entry 81 under its own id) separates them (`binding` vs accept) — see D11.

**Smallest change.** "Decodes under §16.1 means its structure and field rules, §3.1's point
admission included; the request's signature and network are not part of it. The entry need
only decode under §4.0 with a text `t` and a map `body`."

### D7 — L — §8.1: an entry above `MAX_ENTRY_BYTES` inside a bundle

**Words.** "`MAX_ENTRY_BYTES` does not apply to a bundle … a bundle *wraps* an entry that may
itself be 65535 bytes".

**What a second implementer cannot know.** Whether the wrapped entry is still held to 65535.
Three readings: `bundle` at step 1, `binding` (it does not decode as an entry, so it names
nothing — my base), or accepted (decoded under the bundle's cap). Proof:
`bundle-entry-cap` and `bundle-entry-decoded-under-bundle-cap` survive;
`work/survivors/nas-oversize-entry.bundle` (66,756 bytes, a 66,079-byte rotate naming nas, in a
two-leaf tree signed by `logkey` and cosigned): `binding` / `bundle` / accept. Needs a log and
quorum to sign a leaf that can never be served; bundles prove nothing about acceptance. Fix:
"an entry inside a bundle larger than `MAX_ENTRY_BYTES` is `bundle`".

### D8 — L — §10.1 bundle step 1: a proof hash of the wrong length

§8.1 types `proof` as "array of 32-byte strings"; §11.1 says outright that a wrong hash length
is `schema`, checked before anything else; §8.1 and §10.1 say nothing, and step 3's
"inclusion proof does not chain" also fits. Proof: `bundle-short-hash-is-inclusion` survives;
`nas-short-proof-hash.bundle` (first hash cut to 31 bytes): `bundle` vs `inclusion`. Fix: "a
proof hash that is not 32 bytes is `bundle`", and a `proofs-bad/short-proof-hash` vector.

### D9 — L — §11.1 step 0: a declared length above the cap in a short file

"`oversize` | the file is larger than `MAX_EVIDENCE_BYTES`" against "refused on length, before
anything it declares is allocated". Proof: `ev-declared-length-is-oversize` survives;
`evidence-declared-oversize.cbor` (11 bytes, a text header declaring 70,000): `cbor` vs
`oversize`. Fix: "`oversize` is the file's own length; a declared length the file does not
hold is `cbor`."

### D10 — L — §6 "MAY" against §10.1 step 1

§6: a verifier "MAY fetch `tile/<L>/<N>` and use its first `W` hashes"; §10.1 step 1: "for a
partial path, `unserved` only when neither the partial path nor the full one is served". A
reader exercising the MAY's permission not to fall back reports `unserved` where
`grown-log/older-head-over-full-tiles` requires accept (my `tile-no-full-fallback` is caught by
it). The vector decides; the normative word disagrees with it. Fix: "MUST".

### D11 — L — §12.1's coverage claims

§12.1 says it "lists what is vectored and what is not … several are not, and they are named
there". Not so:

1. **Unvectored observable rules missing from "What is not vectored"** — every row of class C
   in §2 above: kid case in `sigs` (§4.0), signers-only for `enroll` (§4.3), step 11 by replay
   rather than leaf hash (§10.1), cross-family grant order and `::` standing for at least one
   group (§4.0, RFC 4291), `expires` 0 in a request (§16.1), a receipt with no signature line
   (§7 step 1), evidence and bundles under a *replayed* policy (§11.1, §8.1), the
   point-admission and decode parts of §8.1's binding, the profile floor of a map key in
   evidence (§4.0/§11.1). Each has a concrete input above on which the two readings differ.
   The bullet "Rules stated plainly that no vector holds yet (cold gate run 16, L8)" names
   none of them — in fact it names no rule at all.
2. "**§16.1's 32-byte `device_pk`** … So the rule is pinned, through the entry's code" — it is
   not: §3.1's point admission refuses a 31-byte key at the same step, so a reader without the
   length rule still answers `decode` (`req-pk-any-length` survives).
3. The trust-level witness **name** rule (1–64 bytes of the policy name grammar) is cited as
   vectored by `trust-bad/32-witness-name-too-long` and `54-witness-name-not-ascii`, but
   correspondence puts every witness name into the policy, whose grammar refuses both files
   without it (`trust-witness-name-unicode`, `trust-witness-name-cap-65` survive) — the same
   redundancy §12.1 already concedes for the algorithm rule (run 14, L4).
4. `proofs-bad/request-undecodable` does not pin "an undecodable request names no device"
   (D6).
5. "**19 `receipt-bad/` cases**" — twenty ship, and §12's own table says twenty.

Fix: move each of these into "What is not vectored" or ship the inputs listed in §2.

### D12 — L — Preamble: the precedence sentence points the wrong way

"Norn reuses these specifications verbatim; where they conflict with this document, they
win, with one exception. §7 and §10 are Norn's profile … and govern where they are stricter".
Read literally, `c2sp.org/tlog-checkpoint`'s optional extension lines win over §6's "no
extension lines" (a §6 rule, outside the exception); §10.1 step 4 restates "exactly three
lines" and `checkpoints-bad/09-extension-line` pins it, so the outcome is held, but the
sentence contradicts every SPEC rule outside §7 and §10 that narrows a reused standard (§4.0's
profile of RFC 8949, §16.2's of BIP-350). Fix: "where they conflict, this document wins".

## 4 Declared survivors — §12.1's "What is not vectored", each checked

| item | check | result |
|---|---|---|
| §3.1 vectored at every admission point | skipping the point check at each point: `ge-point-unchecked` (genesis/23, 24), `gv-add-point-unchecked` (log-admission/01, 02), `lk-point-unchecked` (log-admission/03), `ro-incoming-point-unchecked` (log-admission/06), `req-no-point-check` (log-edges/10), `vkey-no-point-check` (trust-bad/55, 47, log-order/15) | all caught — claim holds |
| source-neutral acquisition; §13 reconciliation; §16.3 key handling | node behaviour, outside static vectors | not checkable here; agreed |
| `none` as a group member indistinguishable from "undefined" | my parser refuses it by the definedness rule first; `pol-none-member-ok` (admitting it) is caught by `bad-none-group-member` | holds |
| CR inside a policy vkey cannot isolate key-data canonicality | the control-byte rule runs first in my parser by construction | holds |
| OpenTimestamps attestations | digest checked (`anchors/`), container not parsed | holds |
| `quorum none` accepting an uncosigned head | `ck-quorum-none-needs-a-cosignature` survives; confirmed with `trust-quorum-none.cbor` (accept vs `quorum`). The same missing anchor leaves §5.3's "no clock under `quorum none`" unvectored too (`t-quorum-none-unbounded`: contractor kept vs dropped) — not named | holds, and wider than stated |
| "a key contributes at most once" | `rp-count-without-dedupe` survives; `env-sigs-repeat-ok-counted` caught by `log/134` | holds |
| "must not count it even in the moment before that refusal" | my verifier yields no time for a refused checkpoint; no input can show the difference | holds |
| order of entry 0's steps | `ge-hash-before-type` survives | holds |
| §3.1's canonical clauses | `ed-lenient-y`, `ed-lenient-x0-sign` survive | holds |
| blank line inside a note's text | `note-text-ends-at-last-blank` caught by `checkpoints-bad/45` | holds |
| §10's "never from a supplied proof" | no served proof path exists in tlog-tiles; my verifier has none | holds |
| §16.1's 32-byte `device_pk` "pinned through the entry's code" | `req-pk-any-length` survives | **does not hold** (D11.2) |
| `state.net` from the anchor | `ge-net-from-entry` survives | holds |
| `entry_hash` over bytes as received | `rp-entry-hash-recanonicalised` survives | holds |
| `MAX_ENTRY_BYTES` on the embedded request | `req-no-size-cap` survives | holds |
| witness key must be a cosignature key at verification | unreachable: the key id binds the algorithm and §9.1/§5.1 refuse a 0x01 witness key first | holds |
| `dup-wg` for `enroll` "any device" | `en-dup-wg-other-device-only` survives | holds |
| "Rules stated plainly that no vector holds yet (run 16, L8)" | lists no rule | **incomplete** (D11.1) |

## 5 Decisions the vectors pinned, and decisions they did not

Pinned (a variant at the decision is caught; the deciding vector in brackets):
C02 point decoding and order (CCTV set, genesis/23–24); C03 S < L and R admission (CCTV,
`requests-bad/S-plus-L-signature`, `torsion-R-signature`, `checkpoints-bad/31`); C04 every
admission point (§4 above); C05 point check after the quorum (`log-admission/01–03`); C06 the
allow-list (`entries-hostile/bare-*`, `fork/bad-simple-size`, `log-republish/13`); C07 integer
cap (`log/bad-integer-too-large`); C08 shortest form for lengths too
(`log/75-bad-cbor-nonshortest-length`); C09 the map-key cap at the decoder
(`hostile/past-the-key-limit`, `at-the-key-limit`) — but not its 1-byte floor in evidence
(D11); C10 strictly increasing encoded keys (`bad-duplicate-map-key`, `bad-cbor-unsorted-keys`,
`enroll-astral-labels`); C11 depth 8 both sides (`hostile/at-`, `past-the-depth-limit`);
C12 per-artifact caps both sides (`trust-good/at-the-cap`, `trust-bad/41`, `proofs/at-the-cap`,
`proofs-bad/one-past-the-cap`, `fork/evidence-at-the-cap`, `fork/bad-one-past-the-cap`,
`hostile/*-size-limit`); C13 whole input (`log/60-bad-trailing-byte`); C14 UTF-8;
C16 booleans (`bad-*-bool`); C17 the two hashes and keys (`log/112`, `log-republish/*`,
`log-rules/12–13`); C18 `sigs` well-formedness (`bad-sigs-fourth-key`, `bad-unsorted-sigs`,
`log/134`) — except kid case (D11); C19 whole-string device_id (`log-edges/01`); C20 label
caps both sides; C21 genesis key arrays; C22 opaque hints (`requests/req-reserved-hints`,
`log/51-enroll-unicode-labels`); C43 no expiry at replay (`state.json` keeps `contractor`
active past its `expires`); C23 the grant grammar (41 rows, `proven` grants) —
except cross-family order and `::` for zero groups (D11); C24–C25 envelope and bodies;
C26 rotate signatures (`log-cas/32`, `log-order/02`); C27 revoke authorisations
(`log-rules/03–04`, `bad-revoke-neither-quorum`); C28–C29 roles (`bad-role-mismatch`,
`bad-device-sig-wrong-role`) — except roots on an `enroll` (D11); C30–C31 prev semantics
(`log-cas/*`, `log-rules/05–06`); C32 params types (`bad-params-*`, `log/157–158`);
C34–C35 entry 0 and the empty log; C36–C38 the step order (`log/99–103`, `149–153`,
`log-republish/15`, `log-rules/12`); C39 every adjacent pair inside each type rule
(`log-order/*`, `log-cas/25–31`, `log/110–111`, `log/140`, `log-rules/15`);
C40–C41 log/witness disjointness and log-line pre-announcement (`log-cas/20–24`,
`log-rules/10–11`); C42 params merge and write-after-validate (`bad-params-mixed-validity`);
C44–C45 lookup codes and state JSON (`state.json`, every fixture state); C46 T by newest line
and k-th newest (`served-twice-cosigned`, `proofs/cases.json`'s two times); C47 the boundary
(`proven/at-the-deadline`); C48–C49 tile geometry and paths (`served-large` table,
`served-large-bad/level-one-byte-changed`); C51 checkpoint body including size 0
(`checkpoints-bad/15, 17, 27, 29, 33`, `served-genesis/empty`); C52 the anchor range;
C53–C57 note framing and matching (`checkpoints-bad/*`, `served-name-collision`,
`served-unknown-algorithm`, `served-stranger-name`, `heads-run16/*`); C58 verifier keys
(`trust-bad/37, 39, 44, 49, 50`); C59 receipt order — except a note with no signature line
(D11); C60 bundle schema and cap — except a short proof hash (D8); C61–C62 bundle checkpoint
and exact inclusion (`proofs-bad/*`, `proofs/right-edge.json`); C63 binding through the body
id for rotate and revoke (`proofs-bad/rotate-`, `revoke-entry-other-device`); C65 the ladder
and both boundaries (`staleness.json`); C66–C67, C69 the trust file (`trust-bad/*`,
`trust-good/*`); C70–C72 the policy grammar and evaluation (`policies/*`) — except trailing
whitespace (D1); C73 fingerprint and TOML round trip (checked directly by the harness, no variant); C74–C75 rotation of keys and policy
(`served-rotated*`, `served-superseded`, `dropped-witness`, `heads-run16/policy-log-only`);
C76–C78 the loop order, branch comparison and genesis step (`checkpoints-bad/30, 34–36`,
`served-bad/*`, `detect/*`, `served-genesis/*`) — except step 11 by replay vs leaf hash (D11);
C79 tile exactness on full paths (`served-large-bad/*`); C80–C81 evidence steps and proofs
(`fork/*`) — except a non-zero split root at split 0 (D4); C82 canonical JSON escapes and key
order (`enroll-astral-labels`); C83, C85 request schema and bech32m (`requests-bad/*`,
`req-minimal-upper`) — except `expires` 0 (D11); C87 installs (`proofs/cases.json`);
C88 the largest lower bound (`staleness.json` observed rows); C89 request decode inside an
entry (`log/79–81`, `log-edges/10`, `bad-enroll-request-expires-at-ts`).

Not pinned (a variant at the decision survives; listed with where the report treats it):
C01 precedence (D12); C15 decoder error precedence (no artifact maps two profile errors to
different codes); C33 an unparseable anchor key or policy (unreachable from a valid trust
file); C50 the fallback
full file's own length (D3); C63's decode boundary (D6) and C64 the wrapped entry's size (D7);
C68 the trust policy's size (D5); C84 the consumer's net/signature order (no code);
C86 `says` is never compared, by design; C90 `dup-wg` for enroll "any device" (declared);
and §11.1's key set for evidence, which my log did not list as a decision because §10 seemed
to settle it — the sweep showed the wording does not (D2).

## 6 Verdict

Two H defects. D1 lets one root-signed `policy` entry — a quorum line that ends in a space —
apply for one conforming reader and be `decode` for another, so the two hold different
quorums and accept different checkpoints from then on. D2 leaves open whether a node verifies
peer-supplied fork evidence under the log keys it learned, so after a key rotation one node
freezes on a fork file for good and another does not. Four M defects (D3–D6) are reachable
only through malformed logs, malformed evidence, refused entries or operator configuration;
the L items are wording, code-only differences and coverage over-claims. Every H and M has a concrete input under `work/survivors/`, signed with the suite's own keys where a
signature is needed, on which the base and the surviving reading disagree.

SPEC INSUFFICIENT
