# COLD GATE 6.6 — independent implementation audit of Norn SPEC v1

VERDICT: SPEC INSUFFICIENT

Independent Go implementation (stdlib only; own CBOR codec, own signed-note /
cosignature / RFC 6962 / bech32m code) written from `SPEC.md` alone, in
`impl/`. Every variant named below is a build flag in `impl/variant.go`
(`NORN_VARIANT=...`), so each claim is reproducible.

## Stage 2 — vector run

```
checks = 285   pass = 285   fail = 0
```

Breakdown: entries 48 · trust.cbor + fingerprint 4 · trust-bad 25 · log
(state.json + 97 per-entry reason codes) 98 · genesis 24 · requests 16 ·
requests-bad 23 · receipt 7 · served (checkpoint + replay) 2 ·
checkpoints-bad 9 · served-bad 2 · proofs 14 · proofs-bad 4 · fork 3 ·
proven 4 · entries-hostile 2.

Every negative is checked for its *named* reason, not merely for refusal:
`log/*.reason` via `manifest.json` (all 51), `proofs-bad`, `fork`,
`entries-hostile` by the `says` substring, `genesis/` by `bad-genesis` **and**
byte-identical `state.json`. `shasum -a 256 -c SHA256SUMS` is clean, so the
suite I ran is the suite as shipped.

I disagree with no vector. Two files (H10) are refused for a reason other than
the one `cases.json` gives; that is a vector defect, not a spec disagreement.

The obvious holes from earlier rounds are genuinely closed. Blinding entry
signatures fails 12 checks, request signatures 11, note signatures 1,
cosignatures 1, inclusion proofs 2, the genesis leaf hash 2, the quorum 3, the
`role` field 3, a lenient CBOR decoder 11. Canonical JSON is pinned hard
(`/` escaping −4, DEL escaping −2, UTF-16 key order −2). I could not construct
a signature-blind implementation that passes anything.

## Defects

### H1 — Three of the four reader steps in §11.1 are unforced, and a forged fork accusation is permanent

**Section:** §11.1 (+ §11 rule 4, §12.1's `fork/` row).

**What the prose says.** §11.1 orders four MUSTs and argues for step 3 in terms:
"Without this the reader is taking the accuser's word for the number that
matters most." §11 rule 4 says a node that concludes FORK must "refuse every
later checkpoint not consistent with the stored one — **forever**, until an
operator explicitly resets with a new trust file".

**How I know it is real.** Three separate variants pass **285/285**:

| variant | what it removes |
|---|---|
| `blind-consistency` | `VerifyConsistency` always returns true (step 3) |
| `skip-conflicting-verify` | the `conflicting` checkpoint is never verified (step 1, half of it) |
| `skip-size-equality` | `conflicting.size == size` is never checked (step 2) |

The suite's two negatives both land on the steps that *are* covered:
`bad-other-origin` fails step 1 on the **held** checkpoint, `bad-consistent`
fails step 4. Nothing in ~330 files rejects a bad consistency proof. Note the
acceptance path *is* exercised — both shipped evidence files use the
non-degenerate branch (`size` 41 and 87 against a held size of 97) — so the
suite forces you to not-reject a valid proof and never forces you to reject an
invalid one. That is the exact inversion of "no finding without proof".

I built the attack. Taking `fork/evidence.cbor` and replacing `held_root` with
32 invented bytes and flipping one byte of each `proof` element gives a file my
honest implementation refuses ("consistency proof does not chain held_root to
held's head") and the `blind-consistency` build accepts as a **genuine fork**.
The forger needs only the public trust file and two honest checkpoints. A node
that acts on it stops admitting devices until an operator ships a new trust
file — a remote, unauthenticated, permanent denial of service on the whole
network, delivered through the one artifact §11.1 says is meant to arrive from
"a stranger" with "no reason to trust whoever handed them the file".

**What it should say.** (a) §12.1 must ship negatives for steps 1 (conflicting),
2 and 3 — a tampered `proof`, an invented `held_root`, a `size` that is not
`conflicting`'s, an under-cosigned `conflicting` — or name them in "What is not
vectored"; the spec's own standard is that "an inaccurate coverage claim is the
same failure wearing a different hat". (b) §11.1 must say what a reader *does*
when a step fails: §11's four MUSTs are written for a node that observes two
checkpoints itself, and the spec never states whether accepting someone else's
evidence file arms the same permanent refusal.

### H2 — Which policy governs checkpoint verification is contradictory, and the shipped fixture makes it fatal

**Section:** §4.5 vs §9.1 / §10 / §5.3.

**What the prose says.** §4.5: the witness policy "has exactly two homes:
`norn.trust.policy`, which a node is provisioned with, and the `policy` entry
type, **which supersedes it inside the log**." §4.3: `policy` "replaces witness
policy in state". §10: "verify witness policy" — without saying which one. §5.3
derives `T` from "the policy (§9)", i.e. the trust file's.

**How I know it is real.** Variant `policy-from-log` re-verifies
`served/checkpoint` under `state.policy` after replay. It **fails**:
`state.policy` for the shipped 97-entry fixture is `log/49-policy-escaping`'s
text — `quote" backslash\ slash/ lt< gt> amp& … rtl-א\nquorum home\n` — which
is not a parseable `tlog-policy` at all. An implementer who follows §4.5
literally cannot verify this network's own checkpoint. An implementer who
ignores §4.5 passes. Both read the same sentence.

There is also a circularity the spec never addresses: you need a policy to
accept a checkpoint, and you need an accepted checkpoint to know how far to
replay to learn the policy.

**What it should say.** State outright that §10 checkpoint acceptance and §5.3's
`T` always use `norn.trust.policy`; say what `state.policy` is for, whether it
must parse as `tlog-policy` at all (today it need not — §5.1's `policy` rule
checks only `text ≤ 4096`), and from which index a superseding policy takes
effect. Or delete "supersedes".

### H3 — Which log keys may sign a checkpoint, and from when, is not in the document

**Section:** §4.3 (`log_key`), §5.3 (`log_keys`), §8.1, §16.3.

**What the prose says.** §4.3: `log_key` is "log-key rotation; both keys valid
for `overlap` (`ENROLLMENT.md` §6)". §16.3: "the `log_key` / `policy` overlap
rules" are normative in `ENROLLMENT.md`. §8.1: "verify the checkpoint note under
`norn.trust.log_key`". §5.3 goes out of its way to say `since_index` is "not a
log size, **not the index from which the key becomes valid**" — naming a
quantity the specification then never defines.

**How I know it is real.** `ENROLLMENT.md` does not ship beside the vectors, and
the preamble's list of specifications reused verbatim is c2sp/RFC only. So the
frozen v1 contract does not answer: is a checkpoint signed by a key introduced
by a `log_key` entry acceptable? The fixture cannot tell you — it has two
`log_key` entries (indices 27 and 81, the second re-adding the trust key) and
its checkpoint is signed by `trust.log_key`, so every reading passes. The two
readings are not cosmetic: under "only `trust.log_key` ever signs", the entire
`log_key` type is dead weight and a real rotation locks out every verifier;
under "state-derived keys count", one root quorum buys a checkpoint-signing key
forever, because `overlap` has no defined start instant.

**What it should say.** Give the rule inline — the set of acceptable signing keys
at checkpoint size S, how `since_index` and `overlap` bound it, and which clock
measures `overlap`. A deferral to a non-shipping document is not a frozen spec.

### H4 — §4.0 states the wrong reason code for an unsigned `enroll` (and `rotate`), and reason codes are consensus state

**Section:** §4.0, last paragraph before the field-constraints table.

**What the prose says.** "an entry with no signatures carries `sigs: []` … Which
rule depends on the type: `threshold` for `note` and the governance types, but
**`no-device-sig`** for `enroll` and `rotate`, whose first step-8 check is the
device signature (§5.1)."

**Why it is wrong.** For `enroll`, §5.1's row runs: body closed (`decode`) ·
request decodes (`decode`) · **the request's own signature** (`no-device-sig`) ·
signer count (`threshold`). An envelope with `sigs: []` still carries an intact,
correctly-signed request, so it sails past `no-device-sig` and is refused
`threshold`. For `rotate`, the first three step-8 checks are `decode`,
`unknown-device` and `not-active`, so an unsigned rotate naming a stranger is
`unknown-device`.

**How I know it is real.** I built the case the suite lacks: `entries/01-enroll`
with `sigs` replaced by `[]`, appended to the fixture. My implementation
returns `threshold`; §4.0 says `no-device-sig`. `log/52-bad-empty-sigs` — the
only empty-`sigs` vector — is a **`note`**, so nothing contradicts a reader who
believes §4.0. Reason codes land in `state.rejected`, which §5.3 requires to be
byte-identical across implementations, so this sentence alone splits
`state.json` on the same log bytes.

**What it should say.** Either drop the per-type claim and point at §5.1's
ordering, or state it correctly and ship an `enroll`-with-empty-`sigs` vector.

### H5 — §5.2's definition of a valid `device` signature contradicts §5.1's proof-of-possession rule, and a literal reader fails the vectors

**Section:** §5.2, "Signature counting, precisely".

**What the prose says.** "a signature `{kid, role, sig}` is *valid* iff the state
**before this entry** maps `kid` to a key **in that role** (for `device`: `kid`
equals `kid(device_pk)` of the device this entry names — for `enroll`, the
`device_pk` in the body) and Ed25519 verification … succeeds. Invalid
signatures are ignored."

The incoming `device_pk` on a `rotate` is by construction *not* the device's key
in the state before the entry. So by §5.2 a signature by it can never be valid,
and "Invalid signatures are ignored". But §5.1's `rotate` row requires "if the
body carries `device_pk`, a **valid** `device` signature by **that** key as well
(`no-device-sig`)", and §4.3 agrees ("the incoming `device_pk` too … proof of
possession, D-032"). The one term, "valid", is defined in §5.2 in a way that
makes §5.1's requirement unsatisfiable.

**How I know it is real.** Variant `strict-52-device-validity` implements §5.2
literally. It fails 3 checks: `log/040` (which must be accepted) becomes
`no-device-sig`, and both `state.json` comparisons break. This is the rare case
where the prose, read faithfully, produces an implementation the vectors reject
— which is exactly the failure mode this audit exists to find.

Same sentence, second bug: "for `enroll`, the `device_pk` in the body" — an
`enroll` body has exactly one key, `request`. §4.3's counting paragraph says
"inside the embedded request". Two places, two answers.

**What it should say.** "for `device`: `kid` equals `kid(device_pk)` of the
device this entry names — for `enroll`, the `device_pk` inside the embedded
request; and on `rotate`, additionally the `device_pk` the body carries."

### H6 — The encoding profile never forbids trailing bytes, and the omission splits the state

**Section:** §4.0's encoding-profile table.

**What the prose says.** Nothing. The table covers integers, floats, `null`,
strings, maps, arrays, depth and total size — every rule is about a single data
item. RFC 8949 §4.2.1, the cited base, likewise governs how one item is encoded
and is silent on what follows it. "An entry is the deterministic CBOR encoding
of: {…}" (§4.1) is the closest thing, and it is an assertion about the producer.

**How I know it is real.** Variant `allow-trailing` passes **285/285**. Under it
I appended a byte-for-byte copy of `log/27-log_key.cbor` with one `0x00` after
it to the fixture. Strict build: `decode`. Lenient build: **accepted** — the
`entry_hash` differs (`6a25ef…` vs `4da031…` for the enroll equivalent) so
`dup-entry` never fires, the preimage is recomputed from the decoded map so
every signature still verifies, and `state.log_keys` grows from 2 entries to 3.
Two conforming implementations, one log, two canonical states.

This is not a theoretical decoder. Reading one item and stopping is the default
of several mainstream CBOR APIs — including Python's `cbor2.loads`, and §12
says the entry, state, trust and request vectors "come from the Python
reference implementation".

**What it should say.** Add a row: "Framing — the input is exactly one CBOR data
item; any byte after it is `decode`." Ship a negative.

### H7 — The evaluation time `T` is unvectored, and its stated rule is self-contradictory for `quorum none`

**Section:** §5.3, "Evaluation time `T` (normative)".

**What the prose says.** "`T` is the newest instant such that the witnesses whose
cosignature timestamp is at or after it satisfy the policy … When the policy is
satisfied at **no** instant — which includes `quorum none`, where nobody vouches
for the time either — there is no clock."

With `quorum none` the policy is satisfied at *every* instant, not at none. A
reader applying the definition gets an unbounded supremum — `T = ∞` — and drops
every device carrying an `expires`. The stated conclusion (no clock, keep the
replayed status) is the opposite. The rule and its own worked case disagree.

Two further silences: the rule never says whether a cosignature must **verify**
to contribute a timestamp (§10 requires named-witness cosignatures to verify,
§5.3 says only "the witnesses whose cosignature timestamp…"), and it never says
what to do with **two cosignature lines from the same witness** carrying
different timestamps. `T` decides who is on the VPN, and §5.3 argues it must not
be the local clock precisely because that decision matters.

**How I know it is real.** `served/checkpoint` carries three cosignatures with
*identical* timestamps (1760003600), so every defensible derivation agrees; and
`proven/cases.json` supplies `t` directly (0 / 1767775999 / 1767776000 /
1767776001) rather than deriving it from any checkpoint. The derivation is
therefore executed by **zero** vectors. §12.1's "§5.3 evaluation time" row
claims this area covered and the "What is not vectored" list does not mention
it. Variant `quorum-none-is-infinite-clock` passes 285/285.

### H8 — The consumer-side origin check lives only inside §11.1

**Section:** §10, §8.1.

**What the prose says.** §10: "verify log signature (torchwood
VerifyCheckpoint)". §8.1: "verify the checkpoint note under
`norn.trust.log_key`". Neither says the checkpoint's first body line must equal
`trust.origin`. §6 states it as a rule for the log; §11.1 step 1 is the only
place it is stated as a rule for a *reader*, and only for evidence.

**How I know it is real.** Variant `blind-origin-check` passes **285/285**.
`checkpoints-bad/03-wrong-origin` is caught by the signed-note key-id binding
(the note name must equal the origin, and the key id binds the name), not by any
comparison of the origin line — so a checkpoint whose note name is right and
whose body line names another network is accepted by one implementation and
refused by another. `proofs-bad/foreign-checkpoint` likewise refuses on the
signature.

**What it should say.** Put the check in §10's loop and in §8.1's checking
recipe, as §11.1 already does.

### H9 — §8's fourth "proven" condition depends on a rule that is not in the document

**Section:** §8 condition 4, §10, §15.

**What the prose says.** "A node MUST treat a peer as proven only if … 4. the
checkpoint is not stale (part 6)." §15 sends the `fresh → degraded →
hard-stale` machine to `GOSSIP.md`, which does not ship beside the vectors.
`params.staleness` is carried in state, so the *number* is available and the
*comparison* is not.

There is also an unreconciled tension worth naming: §5.3 insists the clock is
"the log's witnesses, **never the local one** (A11)", yet any staleness
judgement must measure how old the witness time is, which only a local clock can
do. The spec never says which clock decides condition 4, and a MUST whose
predicate is undefined cannot be implemented twice the same way.

### H10 — Two `requests-bad` cases are refused by the wrong layer; the 32-label cap is unvectored

**Section:** §12.1's §16 row, `requests-bad/cases.json`.

**What the prose says.** §4.0 states the standard for the entry-profile
negatives: "A negative for one of those rules must fail for that rule **and
nothing else**, which takes care." The request negatives do not meet it.
`requests-bad/too-many-labels` and `oversize-label` carry the *base* request's
signature (`a7e758c6…`, byte-identical to `unsorted-keys`' `sig`) rather than
being re-signed over the patched preimage, so they fail Ed25519 verification.

**How I know it is real.** Variant `no-label-count-cap` passes **285/285**; my
layer probe reports `too-many-labels → SIGNATURE (field rules all passed)`.
An implementation with no label-count rule at all refuses the file, so the cap
is invisible to the suite. (`oversize-label` does trip the 256-byte value rule
before the signature, so only the count cap is completely unexercised — but
both files are refused for a reason other than the one `cases.json` names.)

## Rules the prose pins but no vector does

These are vector gaps, not prose defects — a careful reader gets them right —
but each is a variant that passes 285/285, so a *careless* reader gets no
signal, and several split the canonical state:

| variant passing 285/285 | what is unpinned |
|---|---|
| `depth-limit-4`, `depth-limit-16`, `depth-limit-64` | §4.0's depth limit is only bounded "below 200" by `deep-nesting`; the value 8 is untested in either direction |
| `size-limit-65534`, `size-limit-65536` | `MAX_ENTRY_BYTES` boundary; `oversize-entry` is ~66 KB, far from 65535 |
| `after-loose` (reject only when `after > index+1`) | §4.4's floor: the fixture's `after` values are 999, 5091 and 5 at indices 10, 91 and 75 — never at or adjacent to the boundary |
| `enroll-wg-before-id` | §5.1's `dup-id` before `dup-wg` ordering inside `enroll` |
| `skip-request-net` | §5.1's "the request's `net` equals the entry's"; `32-bad-decode-net` patches the *envelope* |
| `loose-padding` | §16.2's ≥5-bit-padding and non-zero-padding-bit rules (text-form malleability) |
| `allow-proof-at-same-size` | §11.1's "`proof` … **Empty when `size` equals `held`'s size**" |
| `skip-cosig-verify` | §10's "every cosignature by a witness the policy names **must verify**" vs merely not counting it. `08-forged-cosignature` forces you to *check*, never to *refuse*. Operationally large: one broken witness means fail-closed under one reading and business-as-usual under the other |
| `ignore-kid-match` | §5.2's requirement that a `device` signature's `kid` resolve, rather than just verifying against the key |
| `skip-tile-hash-compare` | whether `tile/<L>/…` hashes are consulted at all (fine, but unstated) |

Not vectored and not admitted in §12.1's honest-holes list, beyond the above:
replay of an **empty** entry list (§5.1 states the result normatively); §10's
`cp.size >= stored_cp.size` monotonicity, the stored-head recomputation, and the
FORK trigger; all four of §11's node MUSTs; §7's receipt has no negatives (this
one *is* admitted by omission in the table); the `anchors/` OTS files are
described but no rule consumes them.

Two more unstated constraints I had to invent an answer for:
`norn.trust.policy`'s `log` directive is never required to name `trust.log_key`
(§9.1 requires the correspondence for witnesses and says nothing about the log);
and nothing constrains a witness `name`'s character set, although §9.1 requires
`policy` to "name exactly the witnesses `witnesses` lists" while the policy
grammar separates fields on spaces and tabs — a witness named `my pi` is
expressible in CBOR and inexpressible in the policy.

## Decisions the prose did not make for me

1. **Trailing bytes** after the entry/request/trust/bundle/evidence item → reject
   (H6). Nothing says so.
2. **Cosignature message format.** §7 restates signed-note framing "so an
   implementer needs nothing else (D22)" but restates nothing for
   `tlog-cosignature`. I implemented the 4+8+64 blob and
   `"cosignature/v1\ntime <ts>\n" ‖ body` message from the external spec; it
   verifies, so I guessed right — but the parallel courtesy is missing, and the
   suite's cosignature vectors cannot tell a wrong guess from a blind verifier
   without `08-forged-cosignature`.
3. **Non-verifying cosignature by a named witness** → refuse the whole
   checkpoint (strict reading of §10) rather than merely not count it.
4. **Checkpoint origin line** compared to `trust.origin` (H8). Stated only in
   §11.1.
5. **Which policy verifies a checkpoint** → `trust.policy` (H2).
6. **Which log key verifies a checkpoint** → `trust.log_key` only (H3).
7. **`expires > ts` inside an embedded request.** §5.1 says an `enroll`'s
   request must "decode under §16.1"; whether §16.1's `expires > ts` field rule
   is part of "decodes" is not said. I enforce it. Unvectored at the entry layer
   (`requests-bad/expires-at-ts` only exercises the text layer).
8. **Checkpoint body line count.** I require exactly 3 (§6 "no extension
   lines"), which `09-extension-line` confirms, and reject a non-canonical
   decimal `size` — the latter from `tlog-checkpoint`, not from this document.
9. **`decode`-vs-`bad-genesis` scope at index 0.** I route *every* genesis
   failure, including body-schema closedness, to `bad-genesis` per §5.1's entry-0
   list. §4.0's field-constraint table's parenthetical agrees; the two are worth
   keeping in sync.
10. **`genesis` with `params: {}`.** §5.1 requires a `params` *entry* to be
    non-empty; nothing says so for the genesis body. I accept it.
11. **`revoke` body `reason`** length 0–256 from §4.0's table (`name`, `reason` →
    "1–64 / 0–256"); the pairing of names to bounds is positional and implicit.
12. **Ordering of `decode` sub-checks** inside envelope validation — immaterial
    only because they share one reason code.
13. **Duplicate cosignature lines from one witness** → first verifying one wins
    (H7).
14. **`log_urls: []`** (present but empty) → reject, from "≥ 1". `trust-bad` only
    covers the key being absent.
15. **Empty entry list** → zero state, per §5.1's explicit sentence. Unvectored.

## What the specification does genuinely well — do not break these

- **§14 canonical JSON** is the best part of the document. Every escape is
  enumerated, the non-escapes are enumerated too (`/`, `<`, `>`, `&`, DEL,
  non-ASCII), the key order is defined bytewise over UTF-8 *and* explicitly
  distinguished from §4.1's CBOR order, and the trailing `0x0A` is required.
  `log/49-policy-escaping` and `enroll-astral-labels` (the only label pair where
  UTF-8 and UTF-16 order disagree) pin it hard: four of my variants die here.
- **§4.1's map-order paragraph** — giving the wrong order explicitly
  (`after, body, net, sigs, t, ts, v`) next to the right one — saved me from the
  single most likely silent bug in the whole format.
- **§5.1's numbered, normative precedence** with vectors named
  `bad-precedence-*` for the four collisions. Getting step 7 before step 8 for
  governance types, and the `no-device-sig`-is-not-for-`revoke` note in §5.2, are
  the kind of thing every other transparency spec leaves to folklore.
- **§4.0's "note on testing these rules"** — distinguishing type bans from
  encoding bans, and stating the two constructions (canonicalises-away vs
  re-signed) with named control entries — is a standard I have not seen another
  specification set for itself. H10 is a case of the suite falling short of it,
  not of the standard being wrong.
- **§9.1's algorithm-0x01-vs-0x04 paragraph** and `trust-bad/15`,`16` — a
  genuinely subtle trap, closed with prose *and* vectors.
- **§4.3's essay on why `enroll` embeds a request** explains a design decision
  well enough that I implemented it correctly on first read.
- **§8.1's refusal to claim `tlog-proof` byte compatibility**, and §12's
  three-provenance statement, are the right instincts about what a vector proves.

## What I could not cover, and why

- **`anchors/`** — no OpenTimestamps implementation. The `.ots` files are
  described in §12 but no §-level rule consumes them beyond "advisory", so I do
  not believe anything normative is missed.
- **`trust.toml`** — §9.2's TOML→CBOR mapping is stated but TOML parsing is not
  normative and CBOR is authoritative; I checked `trust.cbor` only.
- **§7 submission** (`POST /add`, 400/409/429), §6's checkpoint-issuance cadence,
  §10's `T_g` loop, and the whole `fresh → degraded → hard-stale` machine: no
  network, no vectors, and in the last case no published rule (H9).
- **Real-witness interop.** §12 is right that the shipped cosignatures prove the
  format and not that an unmodified `transparency-dev/witness` produces one; I
  cannot check that claim from here.
- **`quorum none`** — needs a second trust anchor, which is not shipped, and the
  spec admits it. H7(a) is about the prose, not about the missing vector.
- **Multi-tile logs.** `served/` is 97 entries, one partial tile at level 0; tile
  path construction, `.p` partial-tile semantics and level-`L` stitching for a
  log past 256 entries are exercised by nothing, and §6 defers all of it to
  `tlog-tiles`. A second implementer's tile reader is untested by this suite.

## Why the verdict is INSUFFICIENT

H5 is decisive on its own: a competent implementer who takes §5.2's definition
of "valid" as normative builds an implementation that rejects every identity-key
rotation, and the only thing that tells them otherwise is a vector. H2 and H3
are worse in kind — for H2 the prose actively points at a reading that cannot
verify the network's own checkpoint, and for H3 a security-critical rule is not
in the document at all. H4 and H6 each split `state.json` between two
implementations that both pass every vector, which is the specific thing §5.3
declares a MUST. And H1 leaves the protocol's one third-party-facing artifact
with three of its four checks unforced, in a way that turns a public file into a
permanent denial of service.

None of these are the holes earlier rounds found. The signature, hash,
canonical-JSON and replay-precedence layers are now pinned properly. What is
left is the layer above: the artifacts that cross trust boundaries (fork
evidence, checkpoints, policies, log keys) and the sentences that describe them
from two places at once.
