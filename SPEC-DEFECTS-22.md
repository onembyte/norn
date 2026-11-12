# Cold gate run 22 — SPEC defects

Reader: an independent implementer working from `SPEC.md` alone, with the
vector suite in `testdata/vectors/`. Nothing outside the sealed directory was
read. Implementation: Go, standard library only, `work/impl/` (about 6,250
lines of protocol code with its variant switches, plus 2,300 of harness and
probes; `work/harness` runs it). Decisions taken before any vector was opened: `work/decisions.md`
(C01–C73). Every digest in `SHA256SUMS` verifies (1,267 files, no unlisted
file). Every concrete input cited below is in `work/probes/`, built by
`work/probe -probe` with the suite's own keys (`keys.json` seeds), and its
base-versus-variant results are in `work/probes/RESULTS.txt`.

## 1 Tally

**First full run: 4,028 checks, 4,027 pass, 1 fail.** The failure was in my
harness, not in the implementation: a file-count assertion I wrote for `fork/`
assumed `cases + sound + 2` files where the directory holds
`cases + sound + 1` (the one extra file is `rotated_key`'s
`evidence-rotated-key.cbor`). No implementation decision changed after the
first run; no decision in `work/decisions.md` was contradicted by a vector.

**Final full run: 5,528 checks, 5,528 pass, 0 fail** (`work/final-results.txt`). The checks grew from 4,028 to 5,528 because I
added checks the suite defines but my first harness did not run:

- the deciding CCTV flag for every one of the 914 vectors (my classification of
  each key/signature pair into §3.1 item 4's first class matches
  `ed25519-cctv/cases.json` for all 914, not only the accept/reject outcome);
- 570 `rules` entries across every manifest: each `says` phrase is found
  verbatim in the SPEC section its `section` names;
- `checkpoints-bad/cases.json`'s `signature_blind_accepts` recomputed: a reader
  whose Ed25519 always says yes accepts exactly those six files and no other;
- cross-file metadata: every replay manifest's anchor is `trust.cbor`'s, each
  `.ots` file carries the digest `anchors/cases.json` states, and
  `signed_by` / `since_index` / `overlap` in four manifests match the
  `log_keys` row replay produces.

What the harness runs, per directory: every `SHA256SUMS` digest; `keys.json`
seed → public → kid; all 914 CCTV vectors; the 16 entry mirrors byte for byte;
all eight replay fixtures and 29 genesis logs (per-entry reason, every `.reason`
file, every `codes` entry, `state.json` byte for byte); the 18 decoder-only
inputs with the rule each must be refused for; `trust.cbor`, its fingerprint and
its TOML rendering rebuilt to the same bytes, 12 good and 59 bad trust files;
71 policies and every `evaluate` row; 9 requests (text ↔ bytes, mirror,
signature, canonical re-encoding) and 30 bad ones; every receipt case; the
served log end to end with `T` under the accepting and the replayed policy; 49
bad and 2 good checkpoints; every reader-history directory (`served-rotated*`,
`served-superseded`, `unreached-witness`, `dropped-witness`, `held-policy`
including the restart, `heads-run16`, `quorum-none`, `genesis-unapplied`,
`replayed-policy`, `served-genesis`); all nine `detect/` pairs; `served-bad`,
`served-large-bad`, `grown-log`, the `served-large` path table and implied
tiles; every bundle in `proofs/`, `proofs-bad/` (and each `repairs` twin),
`proofs-rotated/`, `right-edge.json`, `installs` and condition 3; every evidence
file and both `rotated_key` readers; `proven/cases.json` at its four times, its
grants and its bundle keys; all 49 grant labels; all 12 freshness rows with the
derived ages.

## 2 The sweep

Every variant is one switch at one decision point of the base implementation
(`V("name")` in `work/impl/*.go`). The harness is run once per variant over the
whole suite (`work/scripts/sweep.sh`, results in `work/sweep1/` to `work/sweep5/`,
summaries in `work/sweep*-summary.tsv`); a variant
the suite does not catch is a survivor.

**Single variants: 554 run, 507 caught, 47 survive** (20 genuine, 18 declared, 9 equivalent).
No variant is caught only by a check of my own (setup or derived checks were
excluded and re-tested: `work/scripts/own.py`), and none is caught only by a
panic. The variant space covers: every profile ban (tags, indefinite items,
null, undefined, floats, negative integers, simple values in both forms) and
every cap on both sides of its boundary (entry, request, bundle, inner bundle
entry, trust, evidence, depth, map key, labels count and value, name, reason,
note text, policy text, device_id, witness name, trust name, integer, checkpoint
size, cosignature time, receipt deadline); every field rule; every adjacent pair
in every ordered list (§5.1 steps 1–8, inside each of the eleven type rules,
§10.1 steps 2–12, bundle steps 1–4, evidence steps 0–9, receipt steps 1–8) plus
`prev` moved ahead of the body for each governance type; every comparison
(origins prefix and case, key ids, names by case, learned keys by public key or
name, correspondence by text, by public key, by count, by striking off; dup-key
by kid or public key, same role or both); every encoding (base64 per layer,
decimal per layer, hex case, bech32m separator, case, padding and constant, JSON
escapes and key order); every policy grammar row; key and policy rotation
(learned keys replacing, retired, activation index, trust-name; replayed policy
ignored, applied retroactively, applied before quorum; held head re-read four
ways); freshness, age and expiry boundaries; tile paths, fallbacks, framing and
the Merkle and RFC 9162 verifiers; Ed25519 (cofactored, lenient decoding, no
order check, reduced S, no R check, R subgroup only, no point admission, never
verify).

Survivors, classified:

| class | variants |
|---|---|
| **genuine** — an input a network can see separates base and variant (a probe was built for each) | `cond3-bundle-checkpoint` (D1), `T-trust-policy-always` (D5), `genesis-root-thr-zero-ok`, `genesis-signer-thr-zero-ok` (and their union `genesis-thr-zero-ok`), `genesis-signers-no-point-check`, `genesis-params-flag-truthy`, `genesis-params-routes-open`, `held-reread-judges-quorum`, `tiles-missing-skipped`, `quorum-none-skips-lines`, `cosig-match-name-casefold`, `log-match-name-casefold`, `pol-names-casefold`, `bundle-entry-cap-minus-one`, `trust-log-url-syntax`, `trust-anchor-type-any-type`, `vkey-name-cap-64`, `devid-empty-ok`, `replay-env-bool-prev` |
| **declared** in §12.1's "What is not vectored", and confirmed | `ed-lenient-decode`, `ed-R-no-subgroup`, `sig-count-repeats`, `T-count-unverified`, `genesis-no-byte-key`, `genesis-steps-reordered`, `dup-reencoded-byte-key`, `dupkey-by-pk`, `genesis-dup-kid-ok`, `enroll-dupwg-other-only`, `evidence-split-bound-unchecked`, `trust-witness-alg-any`, `trust-witness-name-unchecked`, `root-invariant-no-floor`, `pol-none-member-as-undefined`, `req-device-pk-any-length`, `state-net-from-genesis`, `cap-request-uncapped` |
| **equivalent by construction** — no input separates them | `ed-cofactored` (§3.1 item 3 permits it once A and R have order L); `incl-short-ok` (a short path can only end on the root through a SHA-256 collision across the 0x00/0x01 domains); `bech-first-separator` (neither the HRP `norn` nor the data charset contains `1`); `note-split-last-space` (§7 shows both splits refuse the same lines); `vkey-name-plus-ok` (the split at the first `+` can never leave one in the name); `logkey-swap-wit-active` and `policy-swap-cap-parse` (both steps give the same code); `reader-learned-trust-name` (§9.1 makes the trust key's name the origin); `trust-correspond-strike` (equal to set correspondence once both uniqueness rules hold, as §9.1 itself notes) |

**Composites: 2,885 run.**

- **Survivor × survivor: every pair of the 47, 1,081 run.** 1,080 survive and
  one is caught: `ed-cofactored` + `ed-R-no-subgroup` is refused by 15 CCTV
  `low_order_component_R` vectors (`cctv/266`, `267`, `285`, `286`, …). Each half
  survives alone, because §3.1's order check on R makes the two equations agree.
  The suite does hold the dangerous combination, a cofactored verifier that lets
  R carry torsion. The 1,080 surviving pairs add nothing new: each pair
  containing a genuine survivor is separated by that survivor's own probe, and
  the pairs of declared or equivalent survivors stay equivalent (for example,
  the kid-collision pairs still need two keys with one `kid`).
- **Survivor × caught: 1,804 run.** Each survivor was paired with every caught
  variant in its own subsystem (`work/scripts/composites.py` names the
  families). A survivor can only mask a caught variant through an input its own
  decision point sees. 1,797 stay caught. Seven pass, and none shows a new
  behaviour:
  - **Same decision point (three).** One switch overrides the other:
    `bundle-entry-cap-minus-one`+`bundle-entry-uncapped`,
    `ed-R-no-subgroup`+`ed-skip-R-check`,
    `trust-correspond-strike`+`trust-correspond-by-pk`.
  - **Reduce to an existing genuine survivor (two).** That survivor's probe
    separates them: `trust-log-url-syntax`+`trust-empty-url-ok` (the empty URL
    fails the scheme check; D12), and `quorum-none-skips-lines`+`T-none-uses-witnesses`
    (no lines are read, so no clock is derived; D7).
  - **Equivalent by construction (two).** `trust-correspond-strike`+`trust-dup-witness-ok`
    is exactly the masking §9.1 predicts ("it then refuses a duplicate here and
    passes the suite without the uniqueness rule at all"); with policy names
    unique by grammar, it refuses every file base refuses.
    `incl-short-ok`+`incl-no-right-edge` keeps the right hash order (after a
    right-edge promotion every later step is on the right edge) and loses only
    the end-of-path counter, so it agrees with RFC 9162 §2.1.3.2 except through
    a SHA-256 collision.

Results: `work/comp1-analysis.txt`, `work/comp2-analysis.txt`,
`work/sweep-comp/`, `work/sweep-comp2/`.

## 3 Defects

Ratings: **H** a conforming reader can be turned against the network, or two
conforming readers decide differently on input a network can really see; **M**
two readings change what a node does, only through an operator's configuration
or a malformed input; **L** wording, an over- or under-claim, or a stated rule no
vector holds. Every probe below names its input in `work/probes/` and its two
answers in `work/probes/RESULTS.txt`.

### D1 (H) — §8.1 condition 3: "that checkpoint" has two antecedents

**Words.** §8.1: "2. the bundle's checkpoint is consistent with the node's
stored checkpoint, and 3. replay of the log up to that checkpoint yields the
device as `active`, and the key the node installs for it is **the `wg_pk` replay
gives**: the device's current key in the §5.3 state". And just above: "A node
MUST establish a peer's proven identity and current key from the first three
checks below."

**What a second implementer cannot know.** "That checkpoint" can be the bundle's
checkpoint (the subject of conditions 1 and 2) or the node's stored checkpoint
(the noun just before it). Condition 2 exists only because the two can differ,
so the protocol expects bundles whose head is older than the head the node
holds; nothing says a node rebuilds its bundles at every head. The readings
part whenever a `revoke`, a re-enrolment or a `rotate` lands between the two
heads. Under the bundle-checkpoint reading a node keeps a revoked device and
installs a superseded key, the key §11 rule 3 calls "the reason it rotated".
§10's outline (`proven := … state` of the accepted checkpoint) and §13 point to
the stored-checkpoint reading, and "the node replays the whole log" leans the
same way, but §8.1's own MUST ties identity and key to the three checks. Two
implementations that each follow one passage install different keys on the
same log. That is why this is H and not M.

**Proof.** No vector can see it: every bundle `installs` and condition 3 are
checked against (`proofs/<device>.bundle`, the `sound` list,
`laptop-since-revoked`) sits at the served head, which is also the stored head.
The variant `cond3-bundle-checkpoint` (replay up to the bundle's own head)
survives the whole suite. The probes are real bundles at a size-10 head of
`served/`, built with the suite's log key and cosigned by pi, vps and friend.
For a reader holding `served/`'s head at 162 each passes all four §10.1 bundle
steps, and the size-10 root is consistent with 162:

- `work/probes/condition-3-older-bundle/laptop.bundle` (laptop's enrolment, index 2): stored-checkpoint reading installs nothing (laptop was revoked at 36); bundle-checkpoint reading installs laptop's `bd463785…`.
- `work/probes/condition-3-older-bundle/nas.bundle` (nas's enrolment, index 1): stored-checkpoint reading installs `2a955fd2…`; bundle-checkpoint reading installs `116f00fa…`, the pre-rotation key §8.1 says a node must never install.

**Smallest change.** Condition 3: "replay of the log up to **the node's stored
checkpoint**, which condition 2 has shown extends the bundle's, yields the
device as `active` …". Ship `proofs/laptop-older-head.bundle` and
`proofs/nas-older-head.bundle` (the probes) with `installs` omitting laptop and
naming `2a955fd2…` for nas.

### D2 (L) — §12.1's §3.1 coverage claim is false for genesis signers

**Words.** §12.1, "What is not vectored": "§3.1's NORN-ED25519-v1 is vectored at
every admission point item 2 names". Item 2 names "a genesis", and §5.1 step 6
admits both `roots` and `signers` there.

**Gap.** `genesis/23-root-order-eight` and `24-root-noncanonical` put the bad key
in `roots`. No vector puts one in `signers`. The variant
`genesis-signers-no-point-check` survives, so a reader that point-checks genesis
roots but not genesis signers passes everything.

**Proof.** `work/probes/genesis-signer-order-eight/00-genesis.cbor`: the fixture
genesis with the order-8 point from `genesis/23` appended to `signers`,
re-signed by root1–3, with an anchor pinning its leaf. Base: `bad-genesis`,
size 0. Variant: applied, size 1.

**Change.** Add `genesis/28-signer-order-eight`, or narrow the sentence.

### D3 (L) — "one per way entry 0 can abort" is an over-claim

**Words.** §12's `genesis/` row: "27 single-entry logs … each refused
`bad-genesis`, one per way entry 0 can abort". §5.1 step 6: "`1 ≤ root_thr ≤
len(roots)`; `1 ≤ signer_thr ≤ len(signers)`; `params`, if present, … each value
has the §4.5 type". §4.5: "a `params` entry or a genesis that gives it any text
but `granted` or `advisory` … is refused (`decode`, or `bad-genesis` at entry
0)".

**Gap.** Four more ways have no vector, and each variant survives:
- `genesis-root-thr-zero-ok`: root_thr 0;
- `genesis-signer-thr-zero-ok`: signer_thr 0, which lets anybody enrol with no signer;
- `genesis-params-flag-truthy`: `rotate_needs_signer: 1`;
- `genesis-params-routes-open`: `routes: "open"`.

The entry-level twins are vectored (`log/69-bad-thr-zero`,
`bad-params-flag-as-uint`, `log/157-bad-params-routes-unknown-value`). At index 0
the two readings differ by the whole network: one aborts to the zero state, the
other replays every entry.

**Proof.** `work/probes/genesis-root-thr-zero/`, `genesis-signer-thr-zero/`
(the genesis plus an enrol carrying no signer signature: base `bad-genesis`,
variant applies both and admits the device), `genesis-params-flag-uint/` and
`genesis-params-routes-open/`. Each is re-signed by root1–3 with its leaf
pinned. Base `bad-genesis`, variant applies.

**Change.** Add the four genesis cases, or reword the row to "27 of the ways".

### D4 (L) — a held head's re-read quorum is not isolated

**Words.** §5.3: "The copy's quorum is not judged again and nothing from the copy
is stored, so a copy with fewer valid lines than the policy needs is still the
held head (D-084 (1))."

**Gap.** `served-superseded/`'s copy has two of three lines, which meets
trust.cbor's 2-of-3, the policy that accepted the held head. So a reader that
re-judges the quorum under the accepting policy passes; variant
`held-reread-judges-quorum` survives. The §12.1 row says as much ("two of three
cosignatures — enough for the trust file") but does not name the gap.

**Proof.** `work/probes/held-head-one-cosignature/checkpoint`:
`served/checkpoint` with only the log line and pi's line. For the informed
reader holding that head: base `accept`, variant `quorum`. Control: a fresh
reader says `quorum` either way.

**Change.** Ship the one-cosignature copy under `served-superseded/` with
`informed: accept`.

### D5 (L) — `T` of a later head under a replayed policy is not vectored

**Words.** §5.3: "The policy is the one under which this checkpoint was
accepted: the trust policy for a first read, or the most recently replayed
policy for a reader that already has one (§9.4)." §9.4: "that policy computes
§5.3's `T` for those checkpoints too".

**Gap.** Every `T` the suite asks for belongs to a fresh reader (`proofs/cases.json`
`checkpoint_quorum_time`, `served-twice-cosigned/`) or to a held-head re-read
(`served-superseded/` `informed_quorum_time`). `replayed_policy_quorum_time` is
given only as the retroactive reading to rule out. No case asks for the `T` of
a head read by a reader that has already replayed a policy, which is every head
after a `policy` entry. A reader that keeps computing `T` under the trust policy
passes; variant `T-trust-policy-always` survives. `T` decides expiry and age
(§5.3, §15).

**Proof.** A reader that has accepted and replayed `served/` (policy 3-of-3),
holding no head, reads `served/checkpoint`: base `T = 1760003600`, variant
`T = 1760003607`.

**Change.** Add an `informed_fresh_quorum_time: 1760003600` to
`served-superseded/` (the informed reader without the held head), or a grown
head after the policy entry with its `T`.

### D6 (L) — a missing *full* hash tile is not vectored

**Words.** §10.1 step 1: "The same code for any file a later step needs and
cannot fetch — … a hash tile (step 12) — reported at that step".

**Gap.** `served-bad/missing-hash-tile` deletes a partial path
(`tile/0/001.p/44`, which falls back to a full path that is also absent), and
`grown-log/full-tile-gone` removes the full tile standing in for a partial. No
case deletes a tile that is full at the head's own size. A reader that skips a
missing full tile passes; variant `tiles-missing-skipped` survives.

**Proof.** `served-large/` with `tile/0/000` deleted (size 300, so that tile is
full): base `unserved`, variant `accept`, after which that node serves onward a
tree it never checked (§6).

**Change.** Add `served-bad/missing-full-hash-tile` (remove `tile/0/000`).

### D7 (L) — listed-witness lines under `quorum none` are not vectored

**Words.** §9.1: "Counting is not checking: a cosignature line whose name **and**
key id match a witness the policy lists must verify whether or not its quorum
reaches that witness". §10.1 step 6.

**Gap.** `quorum-none/` serves only honest lines. A reader that skips the witness
step when the quorum needs nobody passes; variant `quorum-none-skips-lines`
survives.

**Proof.** `work/probes/quorum-none-forged-pi/checkpoint` under
`quorum-none/trust.cbor`: `served/checkpoint` with the last byte of pi's
signature flipped. Base `cosignature`, variant `accept`.

**Change.** Add `quorum-none/forged-pi.checkpoint` (`cosignature`). In §10.1
step 6, write "whatever the quorum requires, `none` included".

### D8 (L) — signature-line names are not said to compare byte for byte

**Words.** §10: "A line NAMES a witness the policy lists when its **name and key
id** both match that witness's verifier key". §7: "the signature line's key name
and key id select the key".

**Gap.** "Match" is never qualified, and no vector carries a stranger line whose
name differs from a listed key's only in case. A reader that folds case passes;
variants `cosig-match-name-casefold` and `log-match-name-casefold` survive.
That reader then refuses honest heads over a line anyone can append. §12.1
gives exactly this reason for `served-name-collision/`.

**Proof.** `work/probes/stranger-upper-witness-name/checkpoint` (a line named
`NORN-WITNESS/PI` carrying pi's key id): base `accept`, variant `cosignature`.
`work/probes/stranger-upper-log-name/checkpoint` (the upper-cased origin with
the log key id): base `accept`, variant `log-signature`.

**Change.** Write "compared byte for byte" in §7, and add both stranger heads.

### D9 (L) — "Nothing here is case-folded" does not clearly cover names

**Words.** §9.1, keywords row: "the four directives, `all` and `any` are
**lowercase**. Nothing here is case-folded". Names row: "each name is defined
**once**, and a repeat is an error".

**Gap.** The sentence sits in the keywords row, so it does not clearly govern
whether `pi` and `PI` are one name. No vector defines two names that differ only
in case; variant `pol-names-casefold` survives. In a `policy` entry the two
readings leave two quorums in force.

**Proof.** `work/probes/policy-names-differ-in-case/`: the fixture genesis plus a
root-signed policy entry (prev 0) with `witness pi`, `witness PI`. Base: applies.
Variant: `decode`. `work/probes/trust-witness-names-differ-in-case/trust.cbor`:
base valid, variant invalid.

**Change.** Put "names compare byte for byte; nothing is case-folded" in the
names row, and add `policies/names-differ-in-case.txt` (accept).

### D10 (L) — a bundle's entry cap is pinned only from above

**Words.** §8.1, `entry` row: "at most `MAX_ENTRY_BYTES` (§4.0), like any entry,
and a longer one is `bundle`".

**Gap.** Only `proofs-bad/oversize-entry` (65,536 bytes) exists. No bundle
carries a 65,535-byte entry, so a cap one byte too strict passes; variant
`bundle-entry-cap-minus-one` survives. Every other cap in the suite has an
at-the-cap positive.

**Proof.** `work/probes/bundle-entry-at-the-cap/nas.bundle`: a 66,210-byte bundle
around a 65,535-byte `rotate` naming nas, in a two-leaf tree whose head is
signed by the log key and cosigned by all three witnesses. Base `accept`,
variant `bundle`.

**Change.** Add `proofs/entry-at-the-cap.bundle`.

### D11 (L) — boolean `prev` at replay is held only by a bundle

**Words.** §5.1 step 3: "every member of the type §4.1 gives it (`t` text, `ts`,
`after` and `prev` uint, …)".

**Gap.** `ts`, `v` and `after` have replay pairs (`log-rules/42–48`). `prev` has
only `proofs-bad/entry-prev-bool`, which is checked at binding. A reader whose
replay coerces a boolean `prev` passes; variant `replay-env-bool-prev`
survives.

**Proof.** `work/probes/signer-add-prev-false/`: the fixture genesis plus a
root-signed `signer_add` of signer3 with `prev: false`, while
`versions.signers` is 0. Base `decode`. Variant: applied, three signers.

**Change.** Add a `log-rules` pair: `prev: false`, and its uint-0 repair.

### D12 (L) — four stated rules with no vector (field and trust level)

Each rule is stated plainly; each variant survives, and each probe separates
base from variant:

- `devid-empty-ok`. §2 / §4.0: `device_id` is "1–64 bytes" and must match the regex, but no vector has an empty id. `work/probes/enroll-empty-device-id/` is a signer-signed `enroll` of a signed request with `device_id: ""`. Base `decode`; variant admits a device named "".
- `trust-log-url-syntax`. §9.1: "Norn does not parse URL syntax here". `trust-good/url-fields-are-opaque`'s invalid spelling still starts with a scheme, so a reader that requires `http(s)://` passes. `work/probes/trust-log-url-no-scheme/trust.cbor`: base valid, variant invalid.
- `trust-anchor-type-any-type`. §9.1: "The two text members are not symmetric". `type` is a text member, but no vector has a non-text `type`, so a reader that ignores `type` entirely passes. `work/probes/trust-anchor-type-uint/trust.cbor`: base invalid, variant valid.
- `vkey-name-cap-64`. §7 gives a verifier-key name no length bound, while witness short names have 64 bytes. No key name in the suite exceeds 64 bytes, so a reader that applies the short-name cap to key names passes. `work/probes/trust-long-witness-key-name/trust.cbor` (a 73-byte key name, in both halves): base valid, variant invalid.

**Change.** One vector each. For the last one, also state "a key name has no
length bound" (or bound it).

### D13 (L) — §7 says sumdb/note differs from Norn "in one place"

**Words.** §7: "These rules are **verified against `golang.org/x/mod/sumdb/note`**
… They differ in one place, where the text ends".

**Why it is wrong.** §10's own outline names a second difference, for the
every-matched-line rule: "Not 'at least one verifies': a checkpoint carrying a
valid signature AND a forgery under the same key is refused … The canonical
signed-note implementation does not impose this; Norn does." A reader who
takes §7's sentence at its word can take that library's handling of a second
line from a known key as Norn's, and accept `checkpoints-bad/16`. (This rests on
the SPEC's own text; I did not consult the library.)

**Change.** "They differ where the text ends, and in the rules §10 marks as
Norn's own".

### D14 (L) — provenance statements disagree

**Words.** §12: "**Three provenances, stated plainly.** … The `served/`,
`served-large/`, `proofs/`, `fork/`, `checkpoints-good/` and `checkpoints-bad/`
vectors come from the **Go** implementation".

**Why it is wrong.** The suite's README says "Provenance — four", adding C2SP
CCTV for `ed25519-cctv/`. It also attributes `held-policy/`,
`replayed-policy/`, `quorum-none/`, `genesis-unapplied/`, `heads-run16/`,
`grown-log/` and the `receipt-bad/` extension to `cmd/norn-genlog`; §12's list
omits them.

**Change.** Align §12 with the README's four rows.

### D15 (L) — the README's `log-cas/` row describes `log-rules/`

**Words.** `testdata/vectors/README.md`, `log-cas/` row: "run 17 restores root3,
then pairs an uppercase surplus signature kid (`decode`), roots-only enroll
(`threshold`) and embedded expires 0 (`decode`) with their accepted repairs".

**Why it is wrong.** `log-cas/manifest.json`'s 33 entries contain none of these.
They are `log-rules/19`–`25`, as §12 says.

**Change.** Delete the sentence from the `log-cas/` row.

## 4 Declared survivors — §12.1's "What is not vectored", each checked

Each bullet of §12.1's "What is not vectored", checked against the
implementation by a variant that removes exactly that rule.

| §12.1 item | check | result |
|---|---|---|
| §3.1 "vectored at every admission point item 2 names" | one variant per admission point | **False for genesis `signers`** (D2). Every other point has a catching vector: genesis roots (`genesis/23`, `24`), `root_add`/`signer_add` (`log-admission/01`, `02`), `log_key` (`log-admission/03`, `log-order/40`), rotate incoming (`log-admission/06`), policy witness (`log-admission/07`), policy log line (`log-order/15`), request (`requests-bad/small-order-device-pk`, `log-edges/10`), trust log key (`trust-bad/55`), trust witness (`trust-bad/47`), evidence policy (`fork/bad-policy-small-order-key`) |
| source-neutral checkpoint acquisition | — | agreed: static vectors cannot show transport |
| §13 reconciliation, `proven.json`, §13.1 grant bound and overlaps | — | agreed: not vectored. §13.1's bound and overlap are pure functions with no table (the spec says so) |
| §16.3 key handling | — | agreed |
| `none` as a group member, separately from "undefined" | `pol-none-member-as-undefined` | survives: confirmed. The broader `pol-none-member-ok` is caught by `bad-none-group-member` |
| CR inside a policy verifier key | — | agreed: the control-byte rule refuses it first (`pol-controls-ok` is caught) |
| OpenTimestamps attestations | digest containment checked | agreed: only the digest is pinned; both `.ots` files carry their stated digest |
| "a key contributes at most once" | `sig-count-repeats` | survives: confirmed; `log/134-bad-repeated-kid` holds the companion rule (`sigs-dup-kid-ok` is caught) |
| "must not count it even in the moment before that refusal" | `T-count-unverified` | survives: confirmed |
| order of entry 0's steps | `genesis-steps-reordered` (leaf pin before decode) | survives: confirmed |
| §3.1's canonical clauses | `ed-lenient-decode` | survives: confirmed (y ≥ p reduced, x = 0 with sign 1 accepted, order check kept) |
| a blank line inside a note's text | `note-last-blank-line` | caught only by `checkpoints-bad/45` and `46`, exactly as stated |
| "recomputed from the entries, never from a supplied proof" | — | agreed: no served path supplies a proof |
| §16.1's 32-byte `device_pk` | `req-device-pk-any-length` (point admission kept) | survives: confirmed |
| `state.net` from the anchor | `state-net-from-genesis` | survives: confirmed |
| `entry_hash` over bytes as received | `dup-reencoded-byte-key` | survives: confirmed; `log/60`, `73`, `74`, `75` and `log-republish/14` catch the lenient-decoder forms |
| `MAX_ENTRY_BYTES` on an embedded request | `cap-request-uncapped` | survives: confirmed |
| a witness key must be a cosignature key, at verification | — | agreed: unreachable, the parsers refuse it first |
| `dup-wg` for `enroll` "any device" | `enroll-dupwg-other-only` | survives: confirmed |
| entry 0's byte key | `genesis-no-byte-key` | survives: confirmed |
| two distinct keys with the same `kid` | `dupkey-by-pk`, `genesis-dup-kid-ok` | survive: confirmed |
| the separate `split ≤ size` check | `evidence-split-bound-unchecked` | survives: confirmed |
| the trust file's own witness algorithm and name rules | `trust-witness-alg-any`, `trust-witness-name-unchecked` | survive: confirmed |
| the subgroup check on R | `ed-R-no-subgroup` (canonical decode and R ≠ O kept) | survives: confirmed; `ed-skip-R-check` is caught by CCTV 304 |
| run 16 L8's list "now vectored" | `binding-enroll-only` | caught by `proofs/nas-rotate` and `proofs/laptop-revoke`: true |
| run 17 D11's list "now vectored" | `kid-uppercase-ok`, `enroll-roots-authorise`, `req-expires-*`, `note-unsigned-ok`, `grant-*`, `reader-ignore-replayed-policy`, `binding-request-raw-id`, `cbor-allow-empty-key`, `quorum-none-needs-one`, `genesis-pin-only` | all caught: true |

The list is accurate except for its first bullet (D2). It is also incomplete:
D3 to D12 are rules stated plainly that no vector holds, and none of them is
named here.

## 5 Decisions the vectors pinned, and decisions they did not

Against `work/decisions.md`, by the variants that flip each decision. "Pinned"
means at least one variant of that decision is caught, by the vector named.

**Pinned.**
- **Profile.** C06–C13: each ban by its `entries-hostile/bare-*` case and `fork/bad-simple-size`; shortest form for integers (`log/*-bad-cbor-nonshortest`) and lengths (`-nonshortest-length`); trailing bytes (`log/60`); depth (`at-`/`past-the-depth-limit`); key cap, floor and bytes-not-characters (`past-the-key-limit`, `fork/bad-empty-map-key`, `requests-bad/empty-label-key`); surrogates (`entries-utf8/bare-surrogate`).
- **Caps.** C14: entry, bundle, trust and evidence caps on both sides.
- **Envelope and fields.** C15–C21: envelope `v`, `ts` and `after` booleans at replay; the `sigs` element rules; `kid` alphabet and length; byte caps on name, reason, text, labels and values.
- **Signatures and replay.** C25–C28 signature counting. C30's two seen sets in every placement I tried: byte key before decoding (`log/112`), content key after the envelope (`log-rules/12`), recorded only on apply (`log-republish/03`, `log-rules/04`, `23`), checked before steps 4–8 (`log/117`, `log-republish/15`). C32–C35: §5.1's order, adjacent pair by adjacent pair, inside every type, and `prev` before the body for each governance type (`log-order/*`, `log-cas/*`, `log/99`–`103`, `149`–`153`).
- **State and JSON.** C37–C42: params merge, version and since rules, the abort state, and every JSON escape and key order.
- **Notes and checkpoints.** C43–C49: every framing rule (`checkpoints-bad/01`–`49`, `heads-run16`, the four stranger heads), the log-line rules and the body.
- **Witnesses and history.** C50–C55: listed witnesses, `T` (median, oldest, retroactive policy, `quorum none`), held-head line checks, the policy in force, the loop's order and the fork rules (all nine `detect/` pairs).
- **Tiles.** C56 fallback, framing, exact length, every level (`grown-log`, `served-bad`, `served-large-bad`).
- **Receipts and bundles.** C57 receipt order, pair by pair. C58–C59: every bundle step and every binding rule, including D-082 (4)'s structural limits.
- **Grants.** C61, all 49 grant cases.
- **Trust and policy.** C62–C65: trust rules (except below), the policy grammar (except name case), verifier keys, the fingerprint.
- **Rotation.** C66, rotation and learned keys: anchor kept, never retired, named the origin, no activation index.
- **Evidence.** C67–C68: every evidence step and consistency proof.
- **Freshness.** C69–C70: freshness and age.
- **Requests.** C71–C72: request and bech32m rules.
- **Ed25519.** C01–C02 order and S < L; C04 every admission point but one.

**Not pinned.**
- **Genuine survivors.** C60 condition 3's state (D1). C04 genesis signers (D2). C29/C24 zero genesis thresholds and genesis `params` flag and routes values (D3). C52 the held re-read quorum (D4). C51/C53 `T` of a later head under a replayed policy (D5). C56 a missing full tile (D6). C50 under `quorum none` (D7). C46 name case (D8). C63 policy name case (D9). C14 a bundle's inner entry cap from below (D10). C15 boolean `prev` at replay (D11). C19 the empty `device_id`, C62 URL scheme and anchor `type` typing, C64 key-name length (D12). All are separated by the probes.
- **Declared.** C01 canonical clauses and R subgroup; C25 "at most once"; C29 entry-0 order; C30 entry 0's byte key and the re-encoded byte key; C40 `dup-wg` scope; C51 unverified lines; C62 trust-level witness algorithm and name; C67 split ≤ size; C71 the 32-byte `device_pk`; C14 request cap; state `net` source; dup-key by `kid` versus public key.
- **Equivalent by construction.** C03 cofactored equation; inclusion short paths; C72 separator choice; C45 sig-line split; C64 `+` in a key name; equal-code adjacent swaps; trust-key name versus origin; strike-off correspondence.

## 6 Verdict

One defect is H: §8.1 condition 3's "that checkpoint" (D1). Two
implementations that each follow one sentence of the SPEC install different
WireGuard keys from the same log and the same bundle. One of them keeps a
revoked device or installs a superseded key, and no vector can tell them apart.
The fix is one phrase and two bundles.

The other fourteen are L. Eleven are rules the SPEC states plainly that no
vector holds (D2–D12, with D2 and D3 also over-claims in §12/§12.1), and three are
wording errors (D13–D15).

Everything else was pinned with unusual precision. 507 of 554 single
decisions are caught, nearly all by a vector built for exactly that decision.
Every §12.1 "not vectored" item I could vary survives exactly as declared, and
no composite exposes a decision that the single variants did not.

SPEC INSUFFICIENT
