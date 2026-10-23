# SPEC-DEFECTS-18 — cold gate run 18

Implementer: a cold reader with `SPEC.md`, `testdata/vectors/` and nothing else.
Implementation: Go 1.26.4, standard library only, `work/impl/` (≈9,700 lines,
one package, harness and probes included). Ed25519 (NORN-ED25519-v1) is implemented from RFC 8032 over a
radix-2^51 field with extended coordinates; `crypto/ed25519` is used only to
*sign* the probe inputs of §3. The RFC 6962 / RFC 9162 proof verifiers and
BIP-350 bech32m are implemented from those standards. Decisions made before
opening any vector: `work/decisions.md` (C01–C71, not edited afterwards).
Everything below was produced with no network access.

## 1 Tally

**Digests.** `shasum -a 256 -c SHA256SUMS`: 1104/1104 OK; every file in the
suite except `SHA256SUMS` itself is listed. The harness re-checks every digest
as its own check.

**First full run: pass 1302, fail 1, total 1303.** (At that point the 1104
digests were one aggregated check and the 914 CCTV vectors three.) The one
failure was a harness path error, not an implementation fault: the harness
looked for `log/state.json`, while §12's table puts the `log/` fixture's
state at the vector root (`state.json`). Fixing the path made it pass; no
implementation code changed. Every other check — every replay reason, every
state byte for byte, every closed code in every manifest — passed on the first
run.

**Final run: pass 4231, fail 0, total 4231.** Every digest and every CCTV vector
is now its own check (the CCTV area checks both the outcome and that my own
point analysis finds the deciding flag `cases.json` names).

| area | checks | area | checks |
|---|---|---|---|
| digests | 1104 | requests / requests-bad | 45 / 30 |
| keys (seed→public→kid) | 31 | receipts / receipt-bad / receipt-rotated | 2 / 21 / 2 |
| entries (canonical bytes, §14 mirrors) | 32 | anchors (§6 OTS digest range) | 3 |
| replay (log, log-edges, -republish, -rules, -order, -cas, -admission, -empty) | 515 | served (+ T, replayed-policy T) | 4 |
| genesis / genesis-good | 52 / 4 | checkpoints-bad (+ computed `signature_blind_accepts`) | 47 |
| entries-hostile | 17 | served-* heads | 16 |
| ed25519-cctv (outcome + deciding flag) | 1828 | tiles (served-large paths, served-bad, served-large-bad, grown-log) | 61 |
| grant labels | 43 | served-genesis / served-empty-entry | 4 / 4 |
| proven (times, grants, bundle keys) | 37 | detect / staleness | 17 / 15 |
| policies (accept + evaluate rows) | 78 | readers (unreached, dropped, heads-run16, replayed-policy, quorum-none, genesis-unapplied) | 25 |
| trust (fingerprint, TOML→CBOR, others) | 11 | proofs / proofs-bad / proofs-rotated | 37 / 23 / 2 |
| trust-good / trust-bad | 10 / 53 | fork | 58 |

Where a manifest names a closed code (§5.2, §7, §10.1, §11.1) the harness
compares that exact code; where it names none (`trust-bad`, `requests-bad`,
`policies`) it checks only the outcome, as §12 directs.

## 2 The sweep

**Method.** Every variant is one switch at one decision point of the base
implementation (`V("name")` in the code; `norn -list` prints all of them).
Ordered check lists (§5.1's steps and every type rule, §7's receipt steps,
§10.1's loop, bundle and checkpoint steps, §11.1's evidence steps) run through
one function with a swap variant for every adjacent pair; each check obtains
its prerequisites lazily, so a swapped check is never silently disabled. Early
sweeps found modelling errors of my own — swapped checks that skipped forever
when their prerequisite had not run, lenient-decoder variants that changed the
signature preimage instead of keeping the received one — and each was fixed;
the counts below are after the fixes. Each variant runs the whole suite in its own
process; one the suite does not catch is a survivor.

**Single variants: 523 run, 457 caught, 66 survive.**

| class | n | survivors |
|---|---|---|
| equivalent — no input distinguishes it, or only an internal error category | 34 | `b32-first-one` (the bech32 charset has no `1`), `cbor-decl-cap`, `cbor-truncated-as-size` (category only; entries are `decode`, evidence `cbor` either way), `cbor-nondecreasing`, `cosig-ts-after-verify` (same code), `ed-cofactored` and `ed-R-order-skip` (with A of order L the cofactorless equation forces R into the prime-order subgroup — §3.1 item 3's own argument), `ev-split-above-size-ok` (the conflicting split proof cannot chain from above its head), `grant-v6-dotted` (a mapped prefix never reaches the renderer), `merkle-incl-no-rightedge` (only `sn` bookkeeping; any wrong path length changes the hash), `note-split-last-space` (§7's own argument), `pol-no-utf8` (policies only arrive as CBOR text), `trust-corr-strike`, `trust-witness-alg-any`, `trust-witness-name-cap-65`, `trust-witness-name-unicode` (redundant through correspondence with the policy grammar — §12.1 says so), `vkey-name-cap-64` (an invented cap the spec does not have), and 17 order swaps whose two checks give the same code or where the later check needs the earlier one's product: enroll body/reqdecode, reqdecode/reqnet; log_key body/pkfields, dupwitness/duplogkey; note body/textcap, textcap/prev; params body/content; policy body/textcap, textcap/parse; replay decode/envelope, envelope/contentdup, contentdup/unknowntype, unknowntype/dupgenesis; revoke known/active; rotate known/active; loop entries/head; evidence cbor/version |
| declared in §12.1 "What is not vectored" | 6 | `ed-lenient-y`, `ed-accept-negzero` (canonical clauses; I also checked by computation that every y in [p, p+19) decodes leniently off the curve, to the identity or to a non-prime-order point), `qt-count-unverified`, `enroll-dupwg-other`, `gen-net-from-entry`, `req-size-unbounded` |
| order swaps with distinct codes, covered only by §5.1's generic "an ordering with no such vector is still normative, merely untested" | 6 | body before prev for `signer_add`/`root_add`, `signer_remove`, `root_remove`, `signer_thr`/`root_thr`, `log_key`; prev before unknown-key for `root_remove` (→ L11) |
| genuine, spec clear, no vector holds the rule | 15 | `gov-roots-or-signers` (L1), `enroll-envelope-device-sig-ok` (L2), `merkle-incl-no-index-check` (L3), `note-no-utf8` (L4), `pol-all-means-any` (L5), `pol-log-alg-any` (L6), `trust-log-line-pk` (L7), `trust-logurl-any-type`, `trust-maxlag-any`, `trust-witness-url-any-type` (L8), `loop-fallback-on-bad-partial` (L9), `grant-colons-two-groups-min` (L10), `cp-size-cap-minus1`, `rcpt-deadline-cap-minus1`, `cosig-ts-cap-minus1` (L12) |
| genuine, spec ambiguous | 5 | `bundle-binding-entrynet`, `bundle-binding-rotate-pk-point`, `bundle-binding-body-closed`, `bundle-binding-enroll-body-closed`, `bundle-binding-minimal-envelope` (all M1) |

The classes add to 66.

Every genuine survivor has a concrete input on which base and variant
disagree, built by `norn -probe work/probes` and signed with the suite's own
keys (`keys.json` seeds for `logkey`, `logkey3`, the three witnesses, roots,
signers and devices) where a signature is needed. The probe output is
`work/runs/probes.txt`; the inputs are under `work/probes/`.

**Composites.** *Survivor × survivor:* all 2145 pairs of the 66 survivors.
Two are caught: `ed-R-order-skip` × `ed-cofactored` (the torsion-R vectors —
the suite pins R's order exactly where the two equations part, as §3.1
intends) and the double replay swap `contentdup<>unknowntype` ×
`unknowntype<>dupgenesis` (`log-republish/15-copy-genesis-extra-sig`). The
other 2143 survive too: apart from those two, combining two undetected
readings never produces one the suite catches. *Survivor × caught:* all 30,162 pairs (66 × 457). 18 survive, and
none is new: 8 are two variants at one decision point where the survivor's
branch overrides the caught one's (`cbor-nondecreasing` × `cbor-no-dup-check`,
`cosig-ts-after-verify` × `cosig-ts-unbounded`, `ed-R-order-skip` ×
`ed-no-R-check`, `qt-count-unverified` × `qt-oldest`, `trust-corr-strike` ×
`trust-corr-subset` and × `trust-witness-dup-ok`, `bundle-binding-minimal-envelope`
× `bundle-binding-no-envelope`, `order-replay-decode<>envelope` ×
`dup-content-before-envelope`, whose check rides on the moved step); 4 are two
adjacent swaps that compose into an order equal to the base where it can be
observed (enroll reqdecode/reqnet/reqsig, evidence cbor/version/schema, loop
entries/head/fork, rotate known/active/cursig); 6 move a body, cap or set
check across `prev` by two positions while keeping the caught pair in order
(`signer_add`, `log_key`, `params`, the `policy` text cap, `signer_thr`/`root_thr`,
`root_remove`) — L11's class, one position further.

## 3 Defects

### H1 — A head re-read after its own quorum raise: the restart rule and §5.3/§9.4 disagree

**Words.** §5.3: "The policy is the one under which this checkpoint was
accepted: the trust policy for a first read, or the most recently replayed
policy for a reader that already has one (§9.4). A `policy` entry in this
checkpoint's replay range MUST NOT change this checkpoint's `T`". §9.4: "It
does not apply retroactively to the checkpoint that carried it or to that
checkpoint's `T`." §13.2: "At startup the persisted checkpoint is verified
again under the trust file, and under what its own entries publish when a key
or policy was rotated in the log; one that does not verify is reported and
ignored. Every candidate checkpoint is compared against the stored checkpoint
before anything is adopted, so an older head of the node's own log is refused
after a restart as it was before one."

**What a second implementer cannot know.** Whether re-verifying the *same
head* — at startup, on the next polling cycle when the log has not advanced
(§10's loop fetches and verifies every `T_g`), or when the head is served again
with a different set of cosignature lines — is "this checkpoint" (acceptance
policy and `T` fixed) or "a checkpoint accepted after replaying" (the policy its
own range published).
§13.2 says the latter for startup; §5.3/§9.4 say the former; nothing tells the
node which policy it accepted a head under, because §13.2 persists only the
replayed policy. The suite pins the informed reader's acceptance
(`served-superseded/` informed `quorum`, `replayed-policy/` informed `held` and
`quorum`) and labels the other value retroactive (`replayed_policy_quorum_time`).

**What a network sees.** Cosignature lines are covered by no signature, so the
log or any relaying peer can strip them. (a) *Rollback after restart:* a first
start accepts `served-superseded/checkpoint` (size 162, pi and vps only) under
the trust file's 2-of-3; replay installs the roots' 3-of-3. After a restart,
§13.2 re-verifies it "under what its own entries publish" — `quorum` (the
suite's own informed answer) — so it is "reported and ignored". The node now
holds no stored head. `probe P21` (an informed reader, with and without the
stored head): `detect/honest-earlier` (size 40) is
`rollback` with the stored head kept and **`accept`** with it ignored; a
3-of-3-cosigned head at 93 (`work/probes/p21-head-at-93/`, built over the
served entries) is `rollback` vs **`accept`, with `rootrevoked` — revoked by
the roots at index 93 — active again.** §13.2's promise that an older head is
refused after a restart is false on this input; only peer corroboration, if a
proven peer answers, repairs it. (b) *Expiry re-judged:* `probe P24`
(`work/probes/p24-log-163-late-expiry/`) appends one enrolment with
`expires = 1760003605` to the served log and cosigns the 163-entry head at the
fixture's 1760003600/607/614. First read: `T = 1760003607`, `late` expired.
The same node re-reading the same head after replaying it: `T = 1760003600`,
`late` proven again. No restart is needed for this half: the next cycle that
fetches the unchanged head re-admits an expired device, and a node that instead
compares the head's bytes and skips re-verification keeps it out — the readings
part on the most ordinary input there is.

**Smallest change.** Persist, with the stored checkpoint, the policy (and the
`T`) it was accepted under, and say in §13.2: "the persisted checkpoint is
verified again under the policy it was accepted under and the keys the node
has learned; a policy published in its own range does not apply to it
(§9.4)", and in §5.3 define "this checkpoint" as the tree head (origin, size,
root), so a re-read of the same head keeps its acceptance policy and `T`.

### H2 — A trust file "issued since" a rotation replays the same log to a different state

**Words.** §5: replay's `anchor` holds `log_key` and `policy` from the
verifier's trust file, "read by one rule only — the log/witness key invariant
at a `policy` or `log_key` entry". §5.1 `log_key`: "`pk` is not an active log
key — `anchor.log_key` or any `pk` in `log_keys` … (`dup-key`)"; `prev` "is
`versions.log_key` (`stale-state`)". §8: a bundle after a rotation "is
checkable by a reader that has replayed the log through the rotation, **or
holds a trust file issued since**"; §11.1 says the same of evidence; §8:
"Retiring a log key is a trust-file change". But §9.4: "The trust file holds
the network's **initial** log key." §5.3: "Two implementations MUST produce
byte-identical canonical JSON".

**What a second implementer cannot know.** What a trust file issued after a
rotation carries in `log_key`. It must carry the new key for §8's sentence to
be true and for retirement to be possible; then replay under it is a different
function. **`probe P22`**: `work/probes/p22-trust-issued-since.cbor` is
`trust.cbor` with `log_key` = `logkey2` under the origin (the key published at
index 27) and the policy `log` line updated; it is a valid trust file. Its
reader accepts `served-rotated/checkpoint`, but replay rejects entry 27
(`dup-key`: the published key is now `anchor.log_key`) and therefore entry 90
(`stale-state`: `versions.log_key` stayed 0), so it learns **no** log key and
its state differs from `state.json`. A head signed by `logkey3` (published at
90; `work/probes/p22-head-signed-by-logkey3.checkpoint`) is **accepted** by a
reader holding the original trust file and **refused, `log-signature`,** by a
reader holding the reissued one — two valid trust files for one network, two
answers on the network's own heads, and every later `log_key` entry whose
`prev` chains through 90 diverges with it. A node reset with a new trust file
(§11 rule 2) splits from its peers the same way.

**Smallest change.** Make replay's anchor the network's genesis-time values:
"`anchor.log_key` and `anchor.policy` are the network's initial log key and
policy; a trust file issued after a `log_key` or `policy` entry keeps them in
`log_key` and `policy` and names the keys it trusts or retires in a separate
member", or drop the anchor from the two dup-key rules and compare against
`log_keys` plus a genesis-pinned initial key.

### H3 — The frozen set after a fork does not say which key a rotated device keeps

**Words.** §11 rule 3: "the **frozen set**: the devices proven at the common
prefix **and** proven at the head the node itself holds, each with the routes
its enrollment granted as of the common prefix. … Relative to what the node was
enforcing, the frozen set may only stay the same or shrink; it MUST never grow:
whatever either branch added after the split is removed, and whatever this
node's branch revoked after it stays out."

**What a second implementer cannot know.** The set is defined over
`device_id`s; enforcement is over `wg_pk`s. A device that rotated its
WireGuard key after the split is proven at both points under two different
keys. Three readings follow the words: install the prefix key (its record "as
of the common prefix"; the rotation is something "added after the split"),
install the held head's key (the key the node was enforcing; installing any
other "grows" the set), or drop the device (no key satisfies both sentences).
**`probe P23`**: the served prefix at 40, then a valid countersigned rotation
of `nas` to the `rogue` X25519 key at 40 (`work/probes/p23-rotate-nas-after-split.cbor`):
`nas` is proven at 40 with `2a955fd2…` and at the held head with `ae5ee198…`.
Under the first reading a node reinstalls the key `nas` rotated away from — the
reason one rotates is often that the old key leaked — for as long as the node
stays frozen, which is until an operator installs a new trust file. Not
vectored (§12.1 declares the frozen set node behaviour).

**Smallest change.** "…each with its `wg_pk` and routes as of the common
prefix, and only while its `wg_pk` at the held head is that same key; a device
whose key changed after the split is removed."

### M1 — §8.1's binding decode is under-specified: five readings, no vector separates them

**Words.** §8.1: "for an `enroll`, the id inside the embedded request; for the
other device types, the `device_id` in the body"; "Decoding here is the
request's structure and field rules, §3.1's point admission included; its
signature and network are not part of it — replay judges those, and a bundle
proves inclusion, not acceptance. The entry itself must decode under §4.0's
profile and §4.1's envelope — version 1, a text `t`, a map `body` — or it
names no device".

**What a second implementer cannot know.** Whether "§4.1's envelope" is the
whole of §5.1 step 3 (closed key set, every member's type, well-formed `sigs`,
`net` = anchor) or only the parenthetical; whether a `rotate`/`revoke` body
must pass its §5.1 body check (closed, field rules, the incoming `device_pk` a
valid point — the very admission point §3.1 item 2 names, and the analogue of
the request's point admission §8.1 does state); whether an `enroll` body must
be exactly `{request}`. Each surviving variant is one of these readings, and
each disagrees with my base on a concrete bundle with a real inclusion proof
and a log-signed, three-witness-cosigned head (`work/probes/`):
`p1` an enroll whose envelope `net` is another network's (base `accept`,
variant `binding`); `p2` a rotate naming `nas` whose incoming `device_pk` has
order 8 (`accept` / `binding`); `p2b` a rotate naming `nas` with an unknown
body key (`accept` / `binding`); `p3` an enroll whose body is
`{request, x}` (`accept` / `binding`); `p4` a version-1 rotate naming `nas`
with no `ts` (`binding` / `accept`). All five entries are ones replay rejects
(`decode`), and a log is not required to refuse them (§6 "Log operator
validation is optional"), so the bundles are constructible by anyone;
condition 3 still decides what a node installs, so the disagreement is in
alerts, audit output and the closed code, not in the peer table.

**Smallest change.** One sentence in §8.1: "The entry passes §5.1 steps 2 and
3 except the `net` comparison, and its body passes its type's body check
(for `enroll`, exactly `{request}` with the request decoding under §16.1);
signatures, networks and every later step are replay's." (Or the opposite
choice, stated.) Then one vector per clause.

### L1 — The governance root quorum is never tested against a signer quorum

§5.1 step 7: "For the governance types (…): fewer than `root_thr` valid `root`
signatures → reject (`threshold`)." No entry is a governance entry carried by a
sufficient *signer* quorum and too few roots, so a reader that lets
`signer_thr` signers authorise governance passes the suite
(`gov-roots-or-signers`). `p5-params-signed-by-signers.cbor`: a `params` entry
with `prev` 0 signed by both signers and no root — base `threshold`, variant
applied. The rule is stated; the vector is missing, and §12.1 does not list
it. Change: one `log/` entry of that shape.

### L2 — An enroll's consent is only the request; §5.2's wording invites the other reading, and nothing tests it

§4.3: "The device's consent is the **embedded request**, not a signature on
this envelope". But §5.2 defines a device-role signature on an `enroll`
envelope as *valid* ("on `enroll`, the `device_pk` inside the **embedded
request**") although no rule counts one. `p6-enroll-envelope-device-sig.cbor`:
a request whose own signature is broken, plus a valid device-role envelope
signature by the request's key and a signer — base `no-device-sig`, variant
(`enroll-envelope-device-sig-ok`) applied. Change: in §5.2 say device-role
signatures on an `enroll` envelope are never consulted; add that entry to
`log/`.

### L3 — "the index is outside the tree" has no vector

§10.1 bundle step 3 and RFC 9162 §2.1.3.2 step 1. A verifier that omits the
index check accepts `p7-index-outside-tree.bundle`: a one-leaf tree whose
leaf is `log/1-enroll-nas`, bundle index 1, empty proof — the RFC loop never
runs, `sn` is 0 and the leaf is the root. Base `inclusion`, variant `accept`.
Change: add it to `proofs-bad/`.

### L4 — The note's UTF-8 rule is isolated only for signature-line names

§7: "The signed text and every signature line MUST be valid UTF-8". §12.1's
note-framing row ends "The generated notes isolate the stated framing rules";
`32-signature-name-not-utf8` is the only non-UTF-8 note, and a name check that
itself requires UTF-8 refuses it, so a reader with no whole-note check passes
(`note-no-utf8`). `p8-origin-not-utf8.checkpoint`: the served head with `0xff`
in its origin line, log-signed and cosigned by all three witnesses — base
`note`, variant `origin`. Change: ship it in `checkpoints-bad/`; soften the
row's claim.

### L5 — `all` is never evaluated with more than one member

§9.1: "`all` is `n`". The only `all` in an `evaluate` table is
`nested-group`'s `all` of one member, where `all` = 1 = `n`, and no trust or
served policy uses `all`, so `pol-all-means-any` survives. `p9`: `trust.cbor`
with `group home all pi vps friend` and the served head cosigned by pi alone —
base `quorum`, variant `accept`. Change: an `evaluate` row `{pi}` → false on a
two-member `all`.

### L6 — The `log`-line algorithm rule is not isolated; §12.1 claims it is

§9.1: "A `log` vkey MUST use algorithm `0x01`". `policies/bad-log-vkey-algorithm`
puts pi's own witness key on the `log` line, so the duplicate-key rule refuses
it as well; run 14 gave the witness side `bad-witness-vkey-algorithm-distinct`
and the log side nothing, while §12.1's grammar row lists "role-mismatched
algorithms" among the covered negatives. `pol-log-alg-any` survives, and the
divergence reaches replay: `p10-policy-log-line-alg4.cbor`, a root-signed
`policy` entry (prev 0) whose `log` line carries a distinct `0x04` key — base
`decode`, variant applied (the policy in force changes). Change: a
`bad-log-vkey-algorithm-distinct` policy and a `log-edges/`-style entry.

### L7 — The trust policy's `log` line "compared … as verifier-key text" has no vector

§9.1 `policy` row: "it MUST be `norn.trust.log_key`, and a `log` line is
compared the same way, as verifier-key text". `trust-bad/36` changes the key
itself, so comparing public keys passes the suite (`trust-log-line-pk`).
`p11-trust-log-line-renamed.cbor`: the log key's public key under another name
with its id recomputed — base invalid, variant valid. Change: the log-side
twin of `trust-bad/48-policy-witness-key-renamed`.

### L8 — Three trust-file member types are never tested

§9.1 types `log_urls` as "array of text", a witness `url` as text and
`max_lag` as "**uint seconds**"; no `trust-bad/` file breaks any of them.
`p12` (`log_urls` holding a byte string), `p13` (`max_lag` as text), `p14` (a
witness `url` as a uint): base invalid, variant valid. Change: three
`trust-bad/` files.

### L9 — "cannot fetch" before falling back to the full tile is untested

§6: "a verifier that cannot fetch `tile/<L>/<N>.p/<W>` MUST fetch
`tile/<L>/<N>`". `grown-log/` deletes the partial paths, so a verifier that
also falls back when the partial is *served but wrong* passes
(`loop-fallback-on-bad-partial`). `p15`: `grown-log/` with a malformed
`tile/0/000.p/162` beside its good full tile — base `tiles`, variant `accept`.
Change: that case in `grown-log/cases.json`.

### L10 — `::` standing for exactly one group is untested

§4.0 ("at most one `::`") with RFC 4291 and §12.1's "RFC 4291 compression
consumes at least one group". The table tests eight groups beside `::` but not
seven, so a reader requiring `::` to cover two groups (RFC 5952's *rendering*
rule applied to parsing) passes (`grant-colons-two-groups-min`). Label
`1:2:3:4:5:6:7::/128`: base `["1:2:3:4:5:6:7:0/128"]`, variant no grant.
Change: one row in `proven/grant-labels.json`.

### L11 — Six replay orderings are untested and not listed as such

§5.1 states the orders and its preamble says "An ordering with no such vector
is still normative, merely untested", but §12.1's "What is not vectored" does
not name these, and `log-order/` covers body-before-prev only for `params` and
`policy` and prev-before-unknown-key only for `signer_remove`. Each differs in
the reason code §5.3's byte-identical state records: `p17` `signer_add` with a
31-byte pk and prev 5 (`decode` / `stale-state`); `p18` `root_remove` of an
unknown kid with prev 7 (`stale-state` / `unknown-key`); `p19` `signer_thr`
`{thr: true}` with prev 9 (`decode` / `stale-state`); `p20` `log_key` with a
31-byte pk and prev 4 (`decode` / `stale-state`); likewise `root_add`,
`signer_remove` and `root_remove` body-before-prev. Change: name them in §12.1,
or add a `log-order/` pair each.

### L12 — The inclusive bound 2⁶³−1 on note numbers is vectored only from above

§6 ("at most 2⁶³−1"), §7's deadline ("at most 2⁶³−1") and cosignature
timestamp ("at most 2⁶³−1"). `33-size-above-2-63`, `deadline-above-2-63` and
`38-cosignature-time-above-2-63` sit one past the bound; nothing sits on it,
and §12.1 itself says the cosignature bound "is accepted in the cosignature
unit test" — not in the suite. A reader whose bound is one too strict passes
(`cp-size-cap-minus1`, `rcpt-deadline-cap-minus1`, `cosig-ts-cap-minus1`).
`p25-receipt-deadline-at-2-63-minus-1.note` (log-signed): base `accept`,
variant `deadline`; `p26-cosignature-at-2-63-minus-1.checkpoint` (the served
head plus a pi cosignature at 2⁶³−1): base `accept`, variant `cosignature`.
(The checkpoint size at the bound cannot be served, so only its code differs.)
Change: ship the two files as positives.

## 4 Declared survivors — §12.1 "What is not vectored", each checked

| item | checked how | result |
|---|---|---|
| §3.1 at every admission point, incl. the policy `log` line | variants removing point admission at genesis, `signer_add`/`root_add`, `log_key`, `rotate`, requests, every vkey | all caught — the claim holds |
| source-neutral acquisition; §13 reconciliation and `proven.json`; §16.3 key handling | not implementable from static vectors | node behaviour, outside this harness, as declared |
| `none` as a group member vs the earlier-definition rule | the separate rule removed alone is indistinguishable; removing both (`pol-none-member-ok`) is caught by `bad-none-group-member` | as declared |
| CR inside a policy vkey | `vkey-lax-base64` is caught by `trust-bad/44`; the policy-side CR is refused by the control-byte rule first | as declared |
| OpenTimestamps attestations | the §6 digest range is checked (`ots-signed-text`, `ots-whole-note` caught); the container is not parsed | as declared |
| §4.3 "a key contributes at most once" | `env-sigs-repeat` caught by `log/134-bad-repeated-kid` | as declared: the uniqueness rule carries it |
| §5.3 "in the moment before that refusal" | `qt-count-unverified` survives | as declared |
| order of entry 0's steps | every failure is `bad-genesis` | as declared (no variant can be seen) |
| §3.1's canonical clauses | `ed-lenient-y`, `ed-accept-negzero` survive; computed: no y ≥ p decodes leniently to a point of order L | as declared, and the stated implication is true |
| a blank line inside a note's text | `note-last-blank` is caught by `45-blank-line-between-signatures` | as declared |
| §10's root "never from a supplied proof" | no shipped file carries a proof | as declared |
| §16.1's 32-byte `device_pk` | point admission refuses a 31-byte key first | as declared |
| `state.net` from the anchor | `gen-net-from-entry` survives | as declared |
| `entry_hash` over received bytes | a strict decoder makes the two readings identical | as declared |
| `MAX_ENTRY_BYTES` on the embedded request | `req-size-unbounded` survives | as declared |
| §10's witness-is-a-cosignature-key check at verification | unreachable behind §9.1 (`trust-witness-alg-any` equivalent) | as declared |
| `dup-wg` for `enroll` "any device" | `enroll-dupwg-other` survives | as declared |
| run 16 L8 and run 17 D11 lists | every rule they name has a variant here and every one is caught | the claim "now vectored" holds |

The list is accurate in what it names; it is incomplete by L1–L11 and does not
mention H1–H3, M1.

## 5 Decisions the vectors pinned, and decisions they did not

**Pinned** (the alternative reading is a caught variant): C01 order and
identity clauses (CCTV `low_order_*`), C02 S < L (`S-plus-L-signature`,
`31-cosignature-S-plus-L`), R and A validity (CCTV, `torsion-R-signature`),
C03 every admission point, C04 every profile ban (`entries-hostile/bare-*`,
`bad-cbor-*`, `fork/bad-simple-size`), C05 the key cap outside entries
(`fork/bad-empty-map-key`), C06 depth 8 both sides, C07 every byte cap both
sides, C08–C10, C12 content duplicates only after the envelope
(`log-rules/12`), C13 entry 0 in both seen sets, C14 every envelope member type
and the closed `sigs` element, C15 roles and kid resolution, C16–C30 every
replay type rule and its order (`log-order/`, `log-cas/`, `log-rules/`,
`log/99`–`153`), C31 every genesis clause, C32 and C70 the canonical JSON
(`enroll-astral-labels`), C33–C35 the grant grammar, IPv4-mapped before
masking, RFC 5952 tie-break and text sort, C36–C42 the note framing, matching by
name and key id, exact payload lengths, `T`, every receipt step, C44–C50 the
policy grammar except L5, L6, C52 the fingerprint and TOML, C53 learned keys
named the origin and kept alongside, replaced policies, C54–C58 tiles,
fallback, loop order, fork/rollback, RFC 9162 exact consumption and the right
edge, C61–C69 bundle step 1, condition 3, evidence order and split rules,
requests and bech32m, the freshness ladder and the estimate, C71 the OTS range.

**Not pinned**: C11 (unobservable, declared); C43 (my choice to refuse
non-UTF-8 raw policy text — no Norn artifact can carry one); C59/C60, the
binding decode (M1: my choices — no `net` check, rotate/revoke only by
`device_id`, enroll body not checked for closedness, full envelope shape — are
each one reading of five); the trust-file member types and log-line text rule
(L7, L8); the `::` single group (L10); fallback only when the partial is
absent (L9); the index-in-tree check (L3); the governance root quorum against
signers (L1); the request as the only enroll consent (L2); note-text UTF-8
(L4); `all` (L5); the log-line algorithm (L6); six replay orderings (L11);
the 2⁶³−1 bound *at* the bound on note numbers (C40, C42 — L12). The
policy-and-`T` of a re-read head (H1) and the replay anchor of a reissued trust
file (H2) were not decisions I recognised as open when I wrote the log: I
followed the vectors' informed reader and the anchor as §5 defines it, and the
sweep's probes showed both. The frozen set (H3) is node behaviour my harness
does not implement; I found it reading §11 against §13 while building P23.

## 6 Verdict

Every vector passes, and the suite is strong: of 523 one-decision variants it
catches 457, every closed code is exact, and 40 of the 66 survivors are
equivalent or declared. But a second implementer reading `SPEC.md` alone can
get network-visible behaviour wrong in three places a careful reading does not
settle — the policy and `T` of a re-read head (H1: a restarted node can be
rolled back past a revocation, and a re-read re-admits an expired device), the replay
anchor of a trust file issued after a rotation (H2: two valid trust files give
two states and two answers on the network's own heads), and the key a rotated
device keeps in the frozen set (H3) — and in one more of lower consequence
(M1).

SPEC INSUFFICIENT
