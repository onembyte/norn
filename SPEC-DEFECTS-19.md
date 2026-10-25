# Cold gate run 19 — specification defects

Reader: an independent implementer working only from `SPEC.md` and
`testdata/vectors/`. Implementation: Go, standard library only,
`work/impl/` (package `norn19/norn`, harness `cmd/harness`, survivor-witness
generator `cmd/survivors`). Decisions were logged before any vector was opened:
`work/decisions.md` (C01–C77), unchanged since.

---

## 1 Tally

**Digests.** `testdata/vectors/SHA256SUMS` lists 1145 files. All 1145 digests
match, and the directory holds exactly those files plus `SHA256SUMS` itself
(no unlisted file, no listed file missing). The harness re-verifies every
digest on each run (group `sums`).

**First full run:** 3437 checks — **3437 pass, 0 fail.** There was no
first-run failure to explain; the implementation as first written from the
decisions log reproduced every manifest, `cases.json`, `state.json`, mirror
and digest.

**Final run:** 3455 checks — **3455 pass, 0 fail** (`work/final-run.txt`). The
18 checks added after the first run are not fixes: 17 check `keys.json`'s
X25519 keys against `SHA-256(prefix ‖ "wg/" ‖ name)`, and one checks the
uppercase request's `.json` mirror.

What the 3455 checks cover, by group: every SHA256SUMS digest (1145); all 914
CCTV Ed25519 vectors plus the count (915); every replay manifest — `log/`,
`log-edges/`, `log-republish/`, `log-rules/`, `log-order/`, `log-cas/`,
`log-admission/`, `log-empty/`, 26 `genesis/` and 2 `genesis-good/` — each
entry's reason, every `.reason` file, every `codes` entry and every
`state.json` byte for byte (632); `policies/` parse and `evaluate` rows,
including the trailing-whitespace "same fields" claims (86); `fork/` sound,
codes and `rotated_key` (61); `trust-bad/` (58), `trust-good/` (11), trust,
fingerprint and TOML-to-CBOR reproduction (6); entry mirrors, types and
canonical re-encoding (48); `checkpoints-bad/` codes plus the computed
`signature_blind_accepts` set (48); keys (47); `served-large/` tiles and the
40-row path table (45); requests (45) and `requests-bad/` refusal layers (30);
grants (44); proofs (33), `proofs-bad/` (26), `proofs-rotated/` (2);
`receipt-bad/` (21), receipt, receipt-good, receipt-rotated (6); proven
evaluation times, grants and bundle joins (21); `entries-hostile/` (17);
staleness ladder and age derivation (15); and every remaining directory —
`detect/`, `served-bad/`, `served-large-bad/`, `grown-log/`,
`served-empty-entry/`, `served-genesis/`, `served-rotated*/`,
`served-superseded/`, `served-twice-cosigned/`, the stranger/collision/
unknown-algorithm heads, `unreached-witness/`, `dropped-witness/`,
`heads-run16/` (heads and requests), `replayed-policy/`, `quorum-none/`,
`genesis-unapplied/`, `checkpoints-good/` and `anchors/`.

## 2 The sweep

Every variant is one switch at one decision point of the base implementation
(`norn.V(name)`), registered with the decision it flips. Each was run against
the whole suite (all 3455 checks); a variant with zero failing checks is a
survivor.

**Single variants: 872** — 466 decision variants (profile bans and caps on both
sides of each boundary, every field rule, comparisons of origins, key ids,
names and public keys, every encoding choice, the policy, note, verifier-key,
device-id and grant grammars, key and policy rotation, freshness and expiry,
text layers, tile and Merkle algorithms, and one or more alternative readings
for each of C01–C77) and 406 ordering variants over the 17 ordered check lists
(replay steps, the eleven per-type lists, checkpoint steps 2–7, served steps
8–12, bundle steps, evidence steps, receipt steps): 74 adjacent swaps and 332
"move one check to any other position".

**Caught: 783. Survived: 89** (`work/final-counts.txt`,
`work/final-survivors.txt`).

Survivors, classified:

| class | count | variants |
|---|---|---|
| equivalent by construction — no input can separate them | 14 + 33 orderings | `admit.trust-witness`, `trust.witness-alg-unchecked`, `trust.witness-name-cap-65`, `trust.witness-name-unbounded`, `trust.witness-name-unicode-ok` (§9.1 correspondence copies the witness key and name text into the policy, whose parser applies the same rule); `bech.separator-first-1` (neither HRP `norn` nor the data charset contains `1`); `dup.genesis-bytes-not-recorded` (genesis's content key catches every byte copy); `ed.cofactored` (§3.1: equations agree on order-L points); `ev.split-above-size-ok` (no consistency proof chains a split above the conflicting head's size); `genesis.empty-sets-ok` (`1 ≤ thr ≤ len` refuses an empty set); `note.split-last-space` (§7: both splits refuse as `note`); `pol.cr-is-space`, `pol.vt-ff-are-space` (the control-byte rule refuses those bytes first); `req.depth-continues` (a deeper request fails its closed schema, `decode` either way). Orderings whose two checks return the same code or where the moved check cannot run without the other's output: `order.enroll.0`, `order.log_key.0`, `order.log_key.3`, `order.note.0`, `order.note.1`, `order.params.0`, `order.policy.0`, `order.policy.1`, `order.replay.1`–`.4`, `order.revoke.1`, `order.rotate.1`, `move.ev.6.0`–`.3`, `move.note.0.2`, `move.note.2.0`, `move.params.0.2`, `move.policy.0.2`, `move.policy.2.0`, `move.replay.1.3`–`.8`, `move.replay.3.0`, `move.replay.3.1`, `move.served.0.4`, `move.served.4.0` (`order.replay.2`'s substantive reading, content duplicates before the envelope, is the separate variant `dup.content-before-envelope`, caught by `log-rules/12`) |
| declared in §12.1 and confirmed | 9 | `dup.hash-recanonical`, `ed.lenient-decode`, `enroll.dupwg-other-device`, `req.device-pk-length-unchecked`, `req.size-uncapped`, `sig.count-duplicates`, `state.net-from-genesis`, `T.count-unverified-lines`, `trust.correspondence-strike-off` (§9.1's own text names it) |
| **genuine** — an input separates base and variant; witness built | 18 + 15 orderings | `frozen.prose-reading`, `grant.trim-one-space`, `pol.stop-after-key`, `cosig.read-first-76`, `tiles.partial-prefix-only`, `rcpt.any-valid`, `rcpt.read-first-68`, `rcpt.zero-time-checked`, `enroll.body-open`, `env.kid-any-length`, `revoke.device-id-grammar-unchecked`, `rotate.device-id-grammar-unchecked`, `policy.dup-key-includes-log-lines`, `genesis.type-unchecked`, `params.zero-refused`, `cbor.utf8-surrogates-ok`, `grant.keep-embedded-dotted-quad`, `json.escape-c1`; orderings `move.enroll.0.2`–`.6`, `move.log_key.0.2`–`.4`, `move.policy.0.3`, `.0.4`, `.1.3`, `.1.4`, `move.revoke.2.0`, `move.rotate.2.0`, `move.replay.2.0` |

Every genuine survivor has a concrete input under `work/survivors/<variant>/`,
signed with the suite's own keys (`keys.json` seeds: the fixture genesis's
roots and signers, `nas`, `laptop`, `router`, `logkey`, `witness-*`) on the
fixture anchor or `trust.cbor`. `work/bin/survivors` rebuilds them and prints
base and variant outcomes. All 35 rows read `DISAGREE`: one or more per genuine
survivor (`pol.stop-after-key` has two inputs), plus the second frozen-set case (`work/survivors/REPORT.txt`). Examples: `enroll.body-open`
base `1:decode`, variant applies; `cosig.read-first-76` base `cosignature`,
variant accepts; `frozen.prose-reading` on a fork that `CheckEvidence`
proves (split 2): base keeps `nas`, variant removes it.

**Composites.** Two sets were run against the whole suite. Totals are in
`work/final-ss-counts.txt` and `work/final-sc-counts.txt`; per-pair results are under `work/final-ss/` and
`work/final-sc/`.

*Survivor × survivor: 967 pairs.* These are all 820 pairs of the 41
non-ordering survivors, plus pairs of ordering survivors in the same list.
944 survive and 23 are caught. Every caught pair is two orderings in the same
list whose combination is a third permutation that the suite holds (for
example `move.log_key.0.4` + `order.log_key.0`, with 14 failing checks). No two
non-ordering survivors combine into anything visible: each pair still
reproduces all 3455 checks.

*Survivor × caught: 3640 pairs.* Each survivor was paired with every caught
variant of its family, plus the families its rule interacts with (trust ×
policy grammar, admission × Ed25519, `dup` × replay order, receipts × note and
log signature, and so on). 2915 are caught. Of the 725 that survive, 685 are
move × move in one list, which my switch reduces to a single move (one move
per list), so they show nothing beyond the survivor. 32 are swap-and-move
mixes that compose to permutations already classified in §2. The last 4 are
`trust.correspondence-strike-off` with either `trust.correspondence-subset` or
`trust.witness-duplicate-ok` — §9.1 describes this pair itself, and the
strike-off still refuses duplicates, so it matches base — and two
contradictory name-cap pairs. The composites that matter are 28 non-ordering
**exposures**, where a survivor becomes visible beside a caught variant (a 29th,
`pol.stop-after-key` + `trust.policy-urls-must-match`, is an artifact: the first
drops the URL that the second then looks for; 57 more are among orderings). They
mark rules that hide each other, so the suite catches a reader lax in both but
not one lax in either alone:
`admit.trust-witness` + `admit.policy-keys` (`trust-bad/47`);
`trust.witness-alg-unchecked` + `pol.witness-alg-unchecked` (`trust-bad/15`);
`trust.witness-name-*` + `pol.name-*` (`trust-bad/32`, `54`);
`dup.genesis-bytes-not-recorded` + `dup.genesis-content-not-recorded` or
`dup.bytes-only` or a content-check move (`log/113`);
`ed.cofactored` + `ed.no-order-check`, `ed.small-order-only` or
`ed.no-R-check` (CCTV); `ed.lenient-decode` + `ed.no-order-check` or
`ed.identity-ok` (CCTV); `req.device-pk-length-unchecked` +
`admit.request-device-pk` (`log/81`, `proofs-bad/pk-length-under-own-id`);
`pol.cr-is-space`/`pol.vt-ff-are-space` + `pol.controls-ok`. Each pair is a
redundancy that §3.1, §9.1 or §12.1 already describes, and none needs a new
vector. Two maskings run the other way: with the control rule off, a CR,
VT or FF read as a separator splits a URL field, and the field count refuses
the `-in-url` policies again.

**Modelling repairs during the sweep.** Some first-sweep survivors were
variants that could not express their reading: the evidence decoder's size
cap under `cbor.size-counts-declared`, where content-duplicate checking sat
for `dup.content-before-envelope`, the origin step reading the first text
line for `order.cp.2`, a naive `root_remove` invariant for
`order.root_remove.2`, `all` over flattened members for `pol.flatten-nested`,
URL rules, and absent-device semantics and raw `t`/`after` reads for reordered
replay checks. All were repaired and caught afterwards. A harness bug — the
report was not flushed before a non-zero exit — made the first sweep's
per-check files incomplete. The counts above come from the repaired
binaries. The base implementation's answers never changed.

## 3 Defects

### D1 (M) — §11 rule 3: the frozen set's formula and its prose disagree

**Words.** "keep enforcing, in every cycle, the **frozen set**: the devices
proven at the common prefix **and** proven at the head the node itself holds,
each with its `wg_pk` and the routes its enrollment granted as of the common
prefix, and only while its `wg_pk` at the held head is that same key: a device
whose key changed after the split is removed, since the old key may be the
reason it rotated (D-082 (3)). … the frozen set may only stay the same or
shrink; it MUST never grow: whatever either branch added after the split is
removed, and whatever this node's branch revoked after it stays out." §13.2 restates only
the formula: "keeps enforcing only the devices proven both there and at its own
held head — the set shrinks, never grows".

**What a second implementer cannot know.** The formula is an intersection by
`device_id` with one key test: equality of `wg_pk` at the held head. The prose
removes any device revoked after the split, any device added after it, and
any device whose key *changed* after it. Two histories on the node's own
branch satisfy the formula and break the prose:

1. *Revoke and re-enroll with the same key.* `nas` is active with key K at the
   split. After the split the held branch revokes `nas` and enrolls it again
   with K, which §5.2 allows because K is no longer active. The formula keeps
   `nas` (proven at both, same `wg_pk`). The prose removes it: it was revoked
   after the split ("stays out") and added after it ("is removed").
2. *Rotate away and back.* After the split the held branch rotates `nas` from
   K to K2 and back to K. The formula keeps `nas`, because its `wg_pk` at the
   held head is K. The prose removes it: its key "changed after the split",
   and K is exactly "the old key [that] may be the reason it rotated".

A frozen node that implements the sentence it reads first keeps a peer that
another frozen node evicts. It does so after a fork that both nodes have
proven, which is when the frozen set is the only authorisation left.

**Proof.** `work/survivors/frozen.prose-reading/` (case 1) and
`work/survivors/frozen.rotate-away-and-back/` (case 2) each hold the held and
conflicting entries, both signed checkpoints (log key plus all three
witnesses) and a version-2 `evidence.cbor`. `CheckEvidence` under `trust.cbor`
proves both forks with split 2. `FrozenSet` gives `{nas}` under the formula and
`{}` under the prose. No vector reaches §11 rule 3: §12.1 leaves the frozen set
to the Go tests.

**Smallest change.** Make the formula carry the prose: "the devices whose
record at the held head is the record they had at the common prefix — not
revoked, enrolled again or rotated to another `wg_pk` at any index at or after
the split — …". Add one evidence-plus-branch fixture per case, with the
expected frozen set.

### L1 — §4.0 grant trimming: "U+0020 is removed" — one, or every one?

**Words.** "A part is `<address>/<length>` and nothing else, once U+0020 is
removed from both of its ends and nothing else is" (with "each part trimmed"
above it).

**Room for error.** "Trimmed" suggests every leading and trailing U+0020; "U+0020
is removed from both of its ends" also reads as one character per end. Every
whitespace vector in `proven/grant-labels.json` has a single space at an end
(`'10.9.1.0/24 '`, `' 10.9.1.0/24 ,fd00::5/64'`), so a one-space reader passes.
A label such as `10.0.0.0/8,  fd00::/64` is something a device can request and
a signer approve. Under `routes = "granted"` one reader installs
`[10.0.0.0/8, fd00::/64]` and the other installs no grant at all. I rate it L
because the natural reading trims all and the one-space reading strains the
text, but the consequence is a different allowed-ips set.

**Proof.** Survivor `grant.trim-one-space`; witness
`work/survivors/grant.trim-one-space/` (a signed `router` enrol).

**Change.** "every U+0020 (any number) at either end", plus a grant-labels
case with two spaces.

### L2 — §9.1 field count for `witness` and `log` lines is not vectored

**Words.** "each directive takes **exactly the fields its production above
allows** — `quorum` one, `witness` two or three, `log` one or two … and a line
with more is an **error**". §9.1 also says "a second implementation that stops
reading a line after the key will silently accept a policy it has misread",
and claims "`policies/` vectors each rule from both sides".

**Room for error.** `bad-extra-field` puts its extra field on the `quorum`
line, so a reader that stops reading a `witness` or `log` line after the key —
the reader §9.1 itself warns about — passes everything. If one node accepts a
root-signed `policy` entry that another refuses, they hold different quorums
from then on.

**Proof.** `pol.stop-after-key`; witness `work/survivors/pol.stop-after-key/`
(the text, and the same text as a root-signed `policy` entry: base `decode`,
variant applies).

**Change.** Add `bad-witness-extra-field` and `bad-log-extra-field`, and
narrow the "both sides" claim until they exist.

### L3 — a listed witness's over-long cosignature is not vectored

**Words.** §7: "The decoded payload is **exactly** that length for the matched
key, never a prefix … and never 'at least'".

**Room for error.** The text is explicit. The suite holds the log's side
(`20-signature-payload-too-long`) and a witness's *shorter* side (`28`, 68
bytes), but not a witness line of 77 bytes. A reader that verifies the first
76 bytes accepts unboundedly many byte-distinct heads.

**Proof.** `cosig.read-first-76`; witness
`work/survivors/cosig.read-first-76/checkpoint` (base `cosignature`, variant
accepts).

**Change.** A `checkpoints-bad` case: pi's valid line plus one byte.

### L4 — partial-tile exactness is vectored only for full tiles

**Words.** §10.1 step 12: "a tile of width `W` is exactly 32 × `W` bytes, and
a longer or shorter one disagrees whatever its first 32 × `W` bytes say (run 14,
M3)".

**Room for error.** Every trailing-byte vector uses a full tile
(`served-large-bad/full-hash-tile-trailing-bytes`, `grown-log/
full-tile-trailing-bytes`). A reader that compares a served *partial* tile on
its prefix passes. One node refuses the head and another accepts it and serves
the long tile on to its peers.

**Proof.** `tiles.partial-prefix-only`; witness
`work/survivors/tiles.partial-prefix-only/` (`tile/0/000.p/162` plus two bytes:
base `tiles`, variant accepts).

**Change.** A `served-bad` case with a partial tile carrying trailing bytes.

### L5 — §7 receipt step 2: "any line" or "every line", and the length rule, are not vectored for receipts

**Words.** "The note MUST verify under a log key the verifier trusts … No line
selecting a trusted key, a bad signature, or a signature payload of the wrong
length for the selected key is `log-signature`."

**Room for error.** For checkpoints, §10 says plainly "Not 'at least one
verifies'". For receipts the rule is implied only by "a bad signature", and
"The note MUST verify under a log key" reads naturally as "some line
verifies". No `receipt-bad` case carries a second, forged log line or a 69-byte
payload. Receipts are what two parties compare when they accuse a log, so a
receipt with two byte-forms is the problem §7 sets out to prevent.

**Proof.** `rcpt.any-valid` and `rcpt.read-first-68`; witnesses
`work/survivors/rcpt.any-valid/two-log-lines.note` and
`work/survivors/rcpt.read-first-68/payload-69.note` (base `log-signature`,
variant `accept`).

**Change.** Restate §10.1 step 3's sentence in step 2 ("every line whose name
and key id select a trusted key MUST be 68 bytes and verify"), and add the two
receipts.

### L6 — §4.0 closed `enroll` body is not vectored

**Words.** "**Bodies are closed schemas too** … a body with an unknown key —
or missing a required one — is `decode`."

**Room for error.** Closedness is vectored for `note`, `rotate` and `revoke`
(`68`, `145`, `146`, `log-edges/07–08`) but not for `enroll`. A reader that
reads only `request` from the body applies an `enroll {request, x}`. The five
genuine `move.enroll.0.*` orderings follow from the same gap: closedness
checked after the request signature, signers, `prev`, `dup-id` or `dup-wg`.

**Proof.** `enroll.body-open`, `move.enroll.0.2`–`.6`; witnesses under
`work/survivors/enroll.body-open/` and `move.enroll.0.{3,4,5,6}/` (base
`decode`; variants apply, or answer `no-device-sig`, `threshold`,
`stale-state`, `dup-id`, `dup-wg`).

**Change.** `log/bad-enroll-unknown-body-key`, otherwise valid.

### L7 — §4.0 `kid` length is vectored only through non-hex characters

**Words.** "`kid` … exactly 16 characters matching `^[0-9a-f]{16}$`".

**Room for error.** `61-bad-kid-format` (`NOTHEX`), `121`
(`NOT-A-KID-AT-ALL`) and `log-rules/20` (uppercase) all fail the character
class. A reader that checks the characters but not the length treats a
17-character lowercase-hex kid as merely unresolvable, and the entry applies.

**Proof.** `env.kid-any-length`; witness
`work/survivors/env.kid-any-length/` (base `decode`, variant applies).

**Change.** One entry whose only fault is a 17-character lowercase-hex kid.

### L8 — `device_id` grammar in `rotate`/`revoke` bodies is vectored only for `enroll`

**Words.** §4.0's field table (violation → `decode`); §5.1: "body well-formed
and closed (`decode`) · `device_id` known (`unknown-device`)".

**Room for error.** A reader that skips the grammar in the body still refuses,
but as `unknown-device` instead of `decode`. `state.json`'s `rejected` then
differs, which breaks §5.3's byte-identical MUST.

**Proof.** `revoke.device-id-grammar-unchecked`,
`rotate.device-id-grammar-unchecked`; witnesses with `device_id` `"NAS"`.

**Change.** One `rotate` and one `revoke` naming `NAS`.

### L9 — §5.1 `policy` dup-key compares witness lines only; unvectored

**Words.** "no witness the text names has the public key of an active log
key".

**Room for error.** The text is exact, but `log-rules/10` (a log line
pre-announcing a log key) is the only nearby vector. A reader that also checks
`log` lines against the witnesses in force refuses a policy that drops `pi`
and names `pi`'s public key on a log line. The two readers then hold different
policies.

**Proof.** `policy.dup-key-includes-log-lines`; witness under
`work/survivors/` (base applies, variant `dup-key`).

**Change.** A positive `log-rules` case.

### L10 — §5.1 entry-0 type check is masked by its vector's body

**Words.** Entry 0 step 3: "`t` MUST be `genesis`".

**Room for error.** `genesis/02-not-genesis` also has a non-genesis body, so a
reader without the type check still aborts at step 6. Separating them needs an
entry 0 with another `t` and a genesis body, pinned by a trust file. That is
reachable only through an operator's anchor, hence L.

**Proof.** `genesis.type-unchecked`; witness
`work/survivors/genesis.type-unchecked/` (base `bad-genesis`, variant applies).

**Change.** A `genesis/27` with `t` `genesis2` and the fixture body.

### L11 — §5.3 D-082 (1)'s scope relative to §8.1 and §11.1

**Words.** §5.3: "a reader that holds that tree head keeps the policy and the
`T` it accepted it under, and reading it again, from the log or from a peer,
changes neither". §8.1: "verify its checkpoint per §10 … under the log keys the
verifier trusts … and the policy of that state".

**Room for error.** A bundle or evidence file arrives from a peer, and "per
§10" invites carrying D-082 (1) over. `replayed-policy/` pins the other
reading: the informed reader verified and replayed `served/`, so it holds that
head, and it still refuses the same tree head inside a bundle (`quorum`) and an evidence file (`held`). The
vectors catch it (`held.reread-applies-to-artifacts` is caught), so only the
wording is at fault.

**Change.** "in §10's loop; a bundle's or evidence's checkpoint faces the
reader's current policy even when it is the held tree head".

### L12 — §4.5/§5.1 `params` value ranges are unstated

**Words.** "non-empty, only §4.5 keys, each of the right type (`decode`)".

**Room for error.** Nothing says whether `staleness: 0` or
`checkpoint_interval: 0` is valid. The closed list implies yes, but a careful
reader may add a floor, and the `params` entry then splits replay.

**Proof.** `params.zero-refused`; witness (root-signed `{staleness: 0}`: base
applies, variant `decode`).

**Change.** "any uint, 0 included" in §4.5.

### L13 — §4.0 "valid UTF-8" is not tied to RFC 3629

**Room for error.** Encoded surrogates (CESU-8, `ED A0 80`) are invalid under
RFC 3629, but some decoders accept them, and no vector holds them
(`bare-invalid-utf8` is a different fault).

**Proof.** `cbor.utf8-surrogates-ok`; witness note (base `decode`, variant
applies).

**Change.** Cite RFC 3629 §3, and add `entries-hostile/bare-surrogate`.

### L14 — §4.0 RFC 5952 rendering of an IPv4-compatible address is unvectored

**Words.** "every group in lowercase hexadecimal (an embedded dotted quad is
written as two groups)".

**Room for error.** Explicit, and `64:ff9b::10.0.0.1` pins the translated
form. `::1.2.3.4` is what glibc's `inet_ntop` prints, and no case holds it. The
grant's text, compared and published as text, then differs.

**Proof.** `grant.keep-embedded-dotted-quad` (`::102:304/128` against
`::1.2.3.4/128`).

**Change.** One grant-labels case.

### L15 — §14.2 "no others" is unvectored for C1 controls

**Words.** "Exactly these characters are escaped, and no others".

**Room for error.** `escapes` covers every listed row, but not U+0080–U+009F.
A library that escapes C1 controls changes `state.json` bytes.

**Proof.** `json.escape-c1`; witness (`router` label `next<U+0085>line`: raw
`c2 85` against `\u0085`).

**Change.** Add U+0085 to `enroll-astral-labels`' `escapes` label.

### L16 — §7 receipt: "A zero time skips this local expiry judgment" is unvectored at deadline 0

**Proof.** `rcpt.zero-time-checked`: a log-signed receipt with deadline `0`,
checked with `now` 0. Base accepts; a reader that compares `0 ≥ 0` says
`expired`. Only a receipt promising inclusion by the epoch reaches this.

**Change.** A `receipt-good` case.

### L17 — orderings §5.1 calls normative but no vector holds

**Words.** "An ordering with no such vector is still normative, merely
untested." In addition to L6's five `enroll` orderings, ten genuine ordering
survivors have witnesses:

- `move.log_key.0.2`–`.4`: `log_key` closedness after `prev` or `dup-key`.
- `move.policy.0.3`, `.0.4`: `policy` closedness after `prev` or `dup-key`.
- `move.policy.1.3`, `.1.4`: the 4096-byte cap after `prev` or `dup-key`.
- `move.revoke.2.0`, `move.rotate.2.0`: `not-active` before the body check.
- `move.replay.2.0`: the envelope check before step 1, which turns a byte copy
  of a decodable, envelope-invalid entry from `dup-entry` into `decode`.

Each changes only a reason code, and so `state.json`.

**Change.** One two-fault entry per pair, as `log-order/16`–`23` do for the
`signer_*`/`root_*` lists.

### L18 — §11 rule 3: "proven at the common prefix" names no evaluation time

The common prefix is a size and has no checkpoint, so it has no `T`. Every
reading that uses no clock or a `T` at or before the held head's gives the same
set, because the held-head clause already judges expiry. A reader that used
the conflicting head's (later) `T` would drop more. Wording: "expiry judged at
the held head's `T`".

### L19 — §8.1 ladder: "`S` be `params.staleness`" — of which state

This is the `params` of the state replayed through the held checkpoint, but the
text does not say so; `detect/staleness.json` passes `S` in directly. Wording
only.

## 4 Declared survivors — §12.1 "What is not vectored", each checked

| §12.1 item | check | result |
|---|---|---|
| §3.1 at every admission point; policy `log` line by `log-order/15` | `admit.*` variants per point; `admit.policy-log-lines` | all caught except `admit.trust-witness`, which is equivalent (correspondence puts the key in the policy, whose parser admits it); `admit.policy-log-lines` caught (3) |
| source-neutral acquisition | — | not a property of static bytes; the harness serves directories only |
| §13 reconciliation, `proven.json` | — | not reachable; grants and proven sets checked through `proven/cases.json` |
| §16.3 key handling | — | not reachable |
| `none` as a group member vs undefined | `pol.none-member-ok` | caught (the rule against no rule); a reader reporting "undefined" gives the base outcome, as stated |
| CR inside a policy verifier key | `pol.controls-ok`, `vkey.data-lax` | both caught, the latter only through `trust-bad/44` — as stated |
| OpenTimestamps attestations | `anchors.digest-signed-text`, `anchors.digest-whole-note` | caught by the stated digest; the `.ots` files contain their digests |
| "a key contributes at most once" | `sig.count-duplicates`; `env.sigs-repeat-ok` | the first survives (equivalent, as stated); the second is caught by `log/134` |
| "must not count it even in the moment before that refusal" | `T.count-unverified-lines` | survives, as stated |
| order of entry 0's steps | — | entry-0 checks are side-effect-free predicates with one code; any order yields the same boolean |
| §3.1 canonical clauses | `ed.lenient-decode` | survives; caught when combined with `ed.no-order-check` or `ed.identity-ok` (CCTV) — exactly the implication stated |
| blank line inside note text | `note.last-blank-line` | caught by `45`; inside the text, equivalent |
| "never from a supplied proof" | — | no proof-supplying path exists in a tlog-tiles read; not reachable |
| §16.1 32-byte `device_pk` | `req.device-pk-length-unchecked` | survives; caught when combined with `admit.request-device-pk` |
| `state.net` from the anchor | `state.net-from-genesis` | survives |
| `entry_hash` over received bytes | `dup.hash-recanonical` | survives |
| `MAX_ENTRY_BYTES` on the embedded request | `req.size-uncapped` | survives |
| witness key must be a cosignature key at verification | — / `trust.witness-alg-unchecked` | the verifier takes keys only from parsed policies; the trust-level rule survives alone and is caught when combined with `pol.witness-alg-unchecked` (`trust-bad/15`) |
| `enroll` `dup-wg` "any device" | `enroll.dupwg-other-device` | survives, as stated |
| run 16 and run 17 lists, "now vectored" | `sig.revoke-any-device`, `prev.governance-zero-optional`, `env.ts-optional`, `bind.enroll-only`, `env.kid-uppercase-ok`, `enroll.roots-authorise`, `req.expires-zero-ok`, `note.zero-signatures-frame`, `reader.informed-uses-trust-policy`, `bind.request-no-point-admission`, `cbor.key-empty-ok`, `pol.quorum-none-unsatisfiable`, `expiry.no-clock-uses-zero`, `served.genesis-leaf-hash-only`, `gov.signers-authorise`, `sig.enroll-envelope-device-sig`, `req.labels-empty-ok` | all caught: the claim holds |

## 5 Decisions the vectors pinned, and decisions they did not

Per decision in `work/decisions.md`: the variants that flip it, caught or
survived (`work/final-counts.txt`).

**Pinned — every alternative caught:** C01 (map-key cap profile-wide), C03,
C04, C05, C06 (`fork/bad-declared-length-past-the-file`), C08, C09, C10, C12,
C14, C15 (each admission point), C16, C17, C18, C21 (all but the orderings in
§2 and L17), C23, C24, C25, C26, C28, C29, C30, C31, C34, C35, C40, C41, C42,
C43, C45, C46, C47, C50, C51 (including size 0 and the empty root), C52, C54
(held re-read: `served-superseded`; scope: `replayed-policy`), C56, C57, C58,
C59, C60, C62, C63, C65, C68, C69, C70, C74, C75, C77.

**Pinned except for an equivalent or declared reading:** C19 (bytes key for
genesis; re-canonical hash), C20 (empty sets), C22 (duplicate counting), C27
(`dup-wg` for enroll), C36–C38 (lenient decode, cofactored, trust-witness
admission), C48 (last-space split), C53 (unverified timestamps), C64 (five
survivors), C66 (CR/VT/FF as separators), C71 (split
above size), C72 (three request rules), C73 (separator). C64's five are four
rules made redundant by correspondence, plus the declared strike-off.

**Not pinned — a genuine survivor exists:** C07 (surrogates, L13), C11 (`kid`
length, L7), C13 (`enroll` closed body, L6), C20 (entry-0 type, L10), C32
(policy dup-key scope, L9), C33 (params ranges, L12), C39 (trim count, L1),
C44 (IPv4-compatible rendering, L14), C49 (witness payload over 76, L3), C55
(partial-tile length, L4), C61 (receipt any/every, length, zero time; L5,
L16), C67 (witness/log arity, L2), C76 (C1 escapes, L15), and §11 rule 3 (D1;
no C-number, because §12.1 places it outside the vectors). C02 — which of
several profile faults a hostile input is refused for — is pinned only
through `entries-hostile/`'s classes; inside entries every fault is `decode`.

**Pinned by vectors where the text alone left room:** D-082 (1)'s scope
(`replayed-policy/`, L11); content duplicates checked after the envelope
(`log-rules/12`); learned keys named the origin (`served-rotated-wrong-name`);
no activation index (`served-rotated-earlier`); a malformed served partial
does not fall back (`grown-log/malformed-partial-with-good-full`); `hard_stale`
before `fresh` (`hard-below-staleness`); the oldest-line versus newest-line
tie-break (`served-twice-cosigned`).

## 6 Verdict

The implementation written from `SPEC.md` reproduced the whole suite on its
first run. Of 872 single variants, 783 are caught. Of the 89 survivors, 56 are
equivalent or declared; the 33 genuine ones all have signed witnesses.
Nineteen of the defects are L: missing vectors on rules the text states, and
wording. One defect is M: §11 rule 3 gives a formula and prose that disagree
about which peers a node keeps after a proven fork. On two concrete,
proven-fork histories, conforming readers of that rule keep different peers,
and no vector can tell them apart.

SPEC INSUFFICIENT
