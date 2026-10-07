**SPEC SUFFICIENT WITH GAPS**

The document is good enough that I built every layer it describes from the prose alone, and that build passed the suite on its first full run: 1211 of 1212 checks, and the one miss was a broken vector. But the bar for this review is "a second implementer could not reasonably have got it wrong", and the document doesn't meet it:

- **59 of 276 single-rule variants pass the whole suite.** Each one reads one rule a second plausible way.
- **18 of the 59 are places where the prose doesn't decide at all.** Several of those change the replayed state (§5.3 says two implementations MUST produce byte-identical canonical JSON of it).
- **30 more are rules the prose does state but no vector checks, and §12.1 doesn't admit them.** Four of these are security failures, not formatting ones:
  - a stranger can forge a permanent fork accusation from one honest checkpoint (D2);
  - a node can accept an equivocating log's longer branch without noticing (D4);
  - a node can accuse an honest log of forking over one corrupt entry bundle (D5);
  - one root key signing three times can meet a 3-of-3 root quorum. This needs two lax readings at once, and the suite can't detect either one (D1).
- **The remaining 11:** 9 are gaps §12.1 already admits; 2 are deliberate no-ops (one strict comparison does both jobs).

I built a concrete input for every gap I report: 46 inputs, signed with the suite's own test keys. On every one of them, my base implementation and the variant disagree.

So the core really can be implemented from this document. The gaps are listed below with suggested fixes, and none of them needs a redesign. What blocks calling v1 "frozen" is D1–D7: under them, two implementations that both pass every vector can split the network's state or its fork verdict.

---

## 1. Method

- **Build.** I wrote one Go program using only the standard library (6,400 lines, in `work/norn/`). It covers:
  - the CBOR profile codec, canonical JSON, envelope and body schemas, and replay;
  - signed notes, cosignatures and verifier keys;
  - `tlog-policy` parsing and evaluation, and the evaluation time `T`;
  - the RFC 6962 inclusion and consistency checks, and a `tlog-tiles` reader;
  - the verifier loop with the §10.1 codes, proof bundles, fork evidence with the §11.1 codes, trust files and fingerprint, receipts, freshness;
  - bech32m, enrollment requests, and a small TOML→CBOR reader for `trust.toml`.

  The only `encoding/json` use is reading `cases.json` in the test harness. `encoding/base32` is the standard library's RFC 4648 codec; the Crockford alphabet is my own code.
- **Decisions before vectors.** I wrote down every decision the prose left to me *before* opening `vectors/`: see `work/DECISIONS-PRE-VECTORS.md`, which is unedited since. After that I read the vectors only for file formats.
- **Variants.** Each rule is a runtime switch (`on("…")`) inside one implementation, so a variant is that implementation with exactly one reading changed. `-sweep` runs the whole suite once per variant; `-pairs` runs composites.
- **Divergence witnesses.** `-witnesses` builds a concrete input for each surviving variant and runs both readings on it. The inputs are new entries signed by the fixture's roots and signers, new checkpoints signed by the log key and cosigned by the three witnesses, evidence files, trust files, and requests. "Diverges" means the base and the variant produce different output: a different `state.json` hash, verdict, or refusal code.

Reproduce from `work/norn/` with `go build -o norn . && ./norn`, then `./norn -sweep`, `./norn -pairs ../pairs.txt`, and `NORN_BIG=1 ./norn -witnesses ../scratch`. The outputs are saved as `work/base-final.txt`, `work/sweep-final.txt`, `work/pairs-final.txt` and `work/witnesses-final.txt`.

## 2. Check tally

- **`SHA256SUMS`:** all 549 files match, and the set is exact, with no extra or missing files.
- **Total:** **1212 / 1212 checks pass** (549 digest checks plus 663 behaviour checks).

| group | checks | | group | checks |
|---|---|---|---|---|
| log replay, 127 entries + `state.json` | 129 | | checkpoints-bad (exact §10.1 code) | 22 |
| log `.reason` ⇔ manifest | 127 | | served-bad (exact §10.1 code) | 4 |
| genesis, 19 aborts + states | 38 | | proofs + `installs` + proven joins | 24 |
| log-empty | 1 | | proofs-bad (exact §10.1 code) + log key | 11 |
| entries (canonical, schema, sigs, JSON mirror) | 64 | | fork (2 positives + conflicting) / fork-bad (exact §11.1 code) | 3 / 17 |
| keys.json | 28 | | detect pairs | 5 |
| trust.cbor, fingerprint, TOML→CBOR byte-equal | 3 | | staleness | 9 |
| trust-good / trust-bad | 3 / 40 | | served, served-{extra-witness, name-collision, twice-cosigned, rotated, superseded} | 4 + 11 |
| policies (31 parse + 7 evaluate rows) | 38 | | proven (4 evaluation times) | 4 |
| requests / requests-bad | 30 / 25 | | receipt / receipt-bad | 3 / 1 |
| entries-hostile | 16 | | anchors (digest range, digest carried) | 3 |

**Was every negative refused for the reason it names?**

- **Exact match on a closed code** for every case that carries one: all 85 rejecting log entries, 19 genesis aborts, 22 checkpoints-bad, 4 served-bad, 10 proofs-bad and 17 fork-bad.
- **Layers without a closed vocabulary** (trust, requests, policies, hostile input, receipts): I mapped each `says` onto my own error by hand. Every case matched, with these disclosed exceptions:
  - `requests-bad/excess-padding` is refused by §4.0's trailing-byte rule, **not** by the §16.2 rule it names. That is a vector defect (D15).
  - `trust-bad/07-no-witnesses` and `08-duplicate-witness-name` each break two §9.1 rules. I refuse them for the *other* rule (the witness minimum, and uniqueness). §9.1 sets no order, so I counted either rule as a match (D21g).
  - `trust-bad/04` also breaks two rules; §12.1 says so itself.
  - For `requests-bad/missing-sig`, `short-sig` and `short-device-pk`, I accepted either "schema" or "signature". For `oversize-label-key`, either "cbor" or "schema" (D21b).

## 3. Variant sweep

| | count | undetected by the suite |
|---|---|---|
| single-rule variants | **276** | **59** |
| composites (pairs and triples, chosen where the halves might hide each other) | **86** | **16** |
| divergence witnesses built for the survivors | **46** | **46 diverge, 0 agree** |

**The 59 undetected singles, by kind:**

- **9 already admitted by §12.1:** `T.quorum-none-unbounded`, `bundle.no-size-limit`, `cosig.alg-unchecked`, `enroll.dupwg-another-device`, `entryhash.recanonical`, `note.text-ends-last-blank`, `trust.correspondence-strike-off`, `T.median`, `sig.count-duplicates`.
- **2 no-ops by design:** `cbor.no-dup-check` and `cbor.nondecreasing`. §4.1's single strict comparison covers both. Their composite *is* caught by `bad-duplicate-map-key`, so this defence works as described.
- **30 where the prose decides and the suite doesn't check, and §12.1 doesn't admit it:** see D1, D2, D4, D5, D8–D17, D19, D20.
- **18 where the prose doesn't decide:** see D3, D6, D7, D11, D14, D18 and D22.

**Composites.**

- No composite of two individually-caught variants survives. The suite's deliberate double coverage (§4.1 order + duplicates; the §9.1 D9 separator / field-count pair; `cp.root-prefix32` + `head.no-rebuild`) holds.
- 15 of the 16 surviving composites are just combinations of surviving singles.
- One composite is worse than either half: **`env.sigs-dup-ok` + `sig.count-duplicates`** (D1).

---

## 4. Defects

Severity:

- **H** — security: a false or missed fork, or a quorum met by one key.
- **M** — two conforming nodes replay to different states or reach different verdicts on a constructible input.
- **L** — a refusal code differs, or a byte bound is off by one.

### D1 (H). Repeated `kid` in `sigs` is never checked, and with it the "at most once" rule

- **Prose.** §4.0 l.139: `sigs` is "sorted by `kid` bytewise, with no repeated `kid`"; l.220: "an unsorted or repeating array is `decode`". §4.3 l.302: "a key contributes at most once". §12.1 l.1402–1407 calls the "at most once" rule untestable *because* `sigs` cannot repeat a kid: "Confirmed by deleting it: every check stays green."
- **Evidence.**
  - `env.sigs-dup-ok` (tolerate a repeated kid) passes 1212/1212. So does `sig.count-duplicates` (drop "at most once"), as §12.1 admits. Their **composite also passes 1212/1212**.
  - No entry in the 127-entry log has a repeated kid; I checked every `sigs` array.
  - Witness: append a `signer_add` for the `stranger` key, signed by **one** current root, with its `sigs` element repeated three times. At this point `root_thr` is 3.
    - base: `#127=decode`
    - `env.sigs-dup-ok` alone: `#127=threshold`
    - composite: **`accepted`**, the stranger is now a signer, `state.json` differs
- **Why it matters.** Two rules each make the other look redundant, and the suite tests neither. A reader holding the lax half of both lets any single root key meet any root threshold. That breaks the governance model completely. It is exactly the hide-each-other pattern §4.1 warns about for map keys, and here nothing defends against it.
- **Fix.** Ship `log/NN-bad-repeated-kid`: one root's signature element three times, `root_thr` 3, expected `decode`. Then correct §12.1: the "at most once" rule is redundant only while the no-repeat rule is enforced, and that rule needs its own vector.

### D2 (H). §11.1 step 3 at the held size: the `held_root` comparison is missing from the code table and from the vectors

- **Prose.** Step 3, l.1184–1186: "or, when `size` is `held`'s own size, that `held_root` is the root `held` is signed over." But the `proof` code row, l.1215, says only "the consistency proof does not chain … or a proof is carried where `size` equals the held size". The `held_root` comparison is not in it.
- **Evidence.**
  - `evidence.same-size-root-unchecked` passes 1212/1212.
  - Witness: `held` = `conflicting` = `served/checkpoint`, `size` 127, `proof` [], `held_root` = 32 bytes of `0x42`.
    - base: `refused:proof`
    - variant: **`FORK PROVEN`**
- **Why it matters.** Anyone holding one honest, cosigned checkpoint can write evidence that the variant reader accepts as a fork. By §11 rule 4 that verdict is permanent until a human installs a new trust file. A reader implementing from the code table (which §11.1 invites: "the first step whose check fails decides") misses this check, and no vector reports it missing.
- **Fix.** Add the clause to the `proof` row. Ship `fork/bad-held-root-at-same-size` with code `proof`.

### D3 (H). §11.1 never defines `size` 0

- **Prose.** §11.1's table and steps. RFC 6962 §2.1.2 defines `PROOF(m, D[n])` only for 0 < m < n. Nothing says whether `size` 0 is legal, or what `held_root` must be if it is.
- **Evidence.**
  - `evidence.size-zero-root-unchecked` (an empty proof suffices at size 0) passes 1212/1212. I wrote this reading myself first; my initial consistency verifier returned "true" for `first == 0`.
  - Witness: `conflicting` = a cosigned size-0 head, `size` 0, no proof, `held_root` = `0x42`×32.
    - base (now requiring `held_root == SHA-256("")`): `refused:proof`
    - variant: **`FORK PROVEN`**
- **Why it matters.** Logs do issue and get cosigned size-0 checkpoints; tlog-witness bootstraps from size 0. Under the lax reading, every such old checkpoint is a permanent-accusation weapon.
- **Fix.** Either "`size` MUST be ≥ 1 (`size`)", or "at size 0 `held_root` MUST be SHA-256 of the empty string (`proof`)". Ship a vector either way.

### D4 (H). Fork detection on a *longer* head is never exercised

- **Prose.** §10 l.1071–1079: `at := min(cp.size, stored_cp.size)` … `if served ≠ mine → FORK`. This applies when the served head is larger too.
- **Evidence.**
  - `fork.grown-unchecked` (accept any grown head without comparing at `stored.size`) passes 1212/1212.
  - `detect/` has a same-size fork, a shorter-branch fork, and an *honest* grown head (`accept-grown`). It has no larger head that rewrites history below the stored size.
  - Witness: stored `detect/earlier.checkpoint` (40); served = `detect/fork-same-size`'s 40 entries plus 20 more, re-signed and cosigned.
    - base: `refused:fork`
    - variant: **`accepted`**
- **Why it matters.** This is the most ordinary equivocation there is: the log shows a node a longer history that disagrees with what it already holds. A node implementing only the shapes the suite tests accepts it silently.
- **Fix.** Ship `detect/fork-on-a-longer-branch` (stored `earlier`, served = a divergent branch of size > 40, outcome `fork`).

### D5 (H). "Head before fork" (§10.1 steps 9→10) is never exercised

- **Prose.** l.1120–1127 explains why step 9 (`head`) must precede step 10 (`fork`): otherwise "a disagreement there would raise a fork against a log that did not sign two histories, only served a broken one". §12.1 l.1397 adds that the closed codes "make every ordering observable".
- **Evidence.**
  - `order.fork-before-head` passes 1212/1212. Every `served-bad` case runs without a stored checkpoint, and every `detect` case has an honest head.
  - Witness: stored `detect/current.checkpoint` (127), served = `served/` with `served-bad/tampered-entry-bundle.bin`.
    - base: `refused:head`
    - variant: **`refused:fork`**, a permanent accusation
- **Why it matters.** One corrupt byte in transit turns into a §11 alarm and a network that refuses every later checkpoint. "Observable" is not the same as "observed".
- **Fix.** Ship a `detect/` case with a stored head and a tampered bundle, outcome `head`. Reword l.1397.

### D6 (M). §5.1 step 3 doesn't say which step checks the *type* of `t`, `ts`, `after` and `body`

- **Prose.** Step 3, l.416–417: "exactly the permitted keys, `v` = 1, `net` = `anchor.net`, well-formed `sigs`". The member types from §4.1 are not listed. l.428–431: "an under-signed governance entry with a malformed body is `threshold`, not `decode`". A non-map body is plausibly a "malformed body".
- **Evidence.** Each of the three variants below passes 1212/1212, as does their triple composite. `log/94-bad-undersigned-malformed` has a map body with an extra key, so it can't separate these readings. Witnesses:
  - under-signed `signer_add` with `body` = uint 5: base `decode` vs `env.body-type-at-step8` → `threshold`
  - `t` = uint 7: `decode` vs `env.t-type-at-step4` → `unknown-type`
  - `note` with `after` = text "0": `decode` vs `env.after-type-lax` → `accepted`

  Each pair produces a different `state.json`.
- **Fix.** Step 3: "every envelope member has the type §4.1 gives it". Ship one vector per member type.

### D7 (M). The policy grammar leaves five things open, and replayed `policy` entries depend on each

Each item below changes whether a `policy` entry is `decode` or replaces `state.policy`. Each also decides whether a trust file loads. §9.1 l.900 states the stakes itself: "a character one reader refuses and another keeps is a `decode` on one node and a new quorum on the other". All of these variants pass 1212/1212, and each witness diverges:

- **(a) Where the `quorum` line may appear.** The `group` row says members must be "previously defined"; the `quorum` row (l.881, l.910) says no such thing.
  - Witness: `quorum home` placed first. Base `accepted`, `policy.quorum-previously-defined` `decode`.
- **(b) Is `none` a definable name?** It is "reserved" only as a quorum target.
  - Witness: `witness none …` / `quorum none`. Base `decode`, `policy.none-definable` `accepted`. The two readings also disagree about what `quorum none` *means* in that file.
- **(c) One namespace or two?** "each `witness` and `group` name is defined once" (l.903).
  - Witness: `group pi 1 vps` next to `witness pi …`. Base `decode`, `policy.separate-namespaces` `accepted`.
- **(d) Must a `<vkey>` parse, with its id recomputed?** §9.1 requires this for the trust file's `witnesses`, never for the grammar itself.
  - Witness: a witness vkey with one id digit changed. Base `decode`, `policy.vkey-unchecked` `accepted`.
  - Same for `log` lines: `log not-a-key` is base `accepted`, `policy.log-vkey-validated` `decode`.
- **(e) Algorithm byte per directive** (0x04 for `witness`, 0x01 for `log`) outside the trust file.
  - Witness: a note key on a witness line. Base `accepted`, `policy.vkey-alg-by-directive` `decode`.

**Fix.** Add five rows to the §9.1 table and a `policies/` case for each, both sides.

### D8 (M). Policy rules that are stated but have no vector

All variants pass 1212/1212 and each witness diverges:

- **(a) CRLF.** l.900 says `\r` "is an error anywhere in a line", but every `\r` vector puts it mid-line. A reader that strips a line-final `\r` (CRLF tolerance, the commonest real-world encounter) passes.
  - Witness: `policy.cr-stripped`. Base `decode`, variant `accepted`.
- **(b) The same key on two `log` lines.** l.904 names it as an error. `bad-duplicate-key` covers witness+witness and `bad-log-key-as-witness` covers log+witness; `two-log-lines` uses two *different* keys.
  - Witness: `policy.dup-keys-log-ok`.
- **(c) `k > n`.** Only `k = 0` is vectored.
  - Witness: `group home 3 pi vps`, which describes an unsatisfiable quorum. `policy.k-no-upper` `accepted`.

**Fix.** Ship `policies/bad-crlf`, `bad-duplicate-log-line` and `bad-k-above-n`.

### D9 (M). The check order inside `revoke` and part of `rotate` has no vector

- **Prose.** §5.1 table, l.436–437, "checks, in order".
- **Evidence.** Each variant passes 1212/1212; §12.1 doesn't list these as unvectored. Witnesses, each with a different `state.rejected` and so a different `state.json`:
  - unknown device, unsigned `revoke`: base `unknown-device` vs `order.revoke-auth-first` → `threshold`
  - revoked `laptop`, unsigned `rotate`: base `not-active` vs `order.rotate-sig-before-active` → `no-device-sig`
  - active `printer` with `rotate_needs_signer`=true, unsigned: base `no-device-sig` vs `order.rotate-threshold-before-sig` → `threshold`
- **Fix.** Ship the three precedence entries.

### D10 (M). Trust-file MUSTs with no vector

- **(a) Origin derivation.** l.848: `origin` "MUST equal" the derivation. Every origin negative uses an *unrelated* origin. Run 11 (D7) fixed this class for checkpoints and for the log key's name, but not for `origin` itself.
  - Witness: origin = derived + "a", with the log key named and the policy `log` line matching. Base `refused:origin`, `trust.origin-prefix` `accepted`.
- **(b) Keys in the correspondence check.** l.854: "MUST name **exactly** the witnesses … with the same keys". 37/39 put the damaged key in both halves, so the keys always agree.
  - Witness: `witnesses[pi].key` = the stranger's key under pi's name, policy unchanged. Base `refused:correspondence`, `trust.correspondence-names-only` `accepted`.
- **(c) Closed `anchor`.** §4.0 says unknown keys are rejected in every map, but there is no vector for an unknown `anchor` member.
  - Witness: `anchor.note = "x"`. `trust.anchor-open` `accepted`.

**Fix.** Ship one vector per item.

### D11 (M). There is no normative procedure for checking a receipt

- **Prose.** §7 gives the receipt format and the deadline spelling, and calls receipts "non-repudiable proof of log misbehaviour". It never says the origin line must equal `norn.trust.origin`, the first line must be `norn/receipt/v1`, or the leaf hash must decode to 32 bytes. `receipt-bad/` holds only `leading-zero`.
- **Evidence.**
  - `receipt.origin-unchecked`, `receipt.header-unchecked` and `receipt.leafhash-lax` each pass, and so do their composites.
  - Witnesses, both signed by this log's key:
    - a receipt for `norn/someoneelse`: base `refused:origin`, variant `accepted`
    - a receipt whose first line is `norn/checkpoint/v9`: base `refused`, variant `accepted`
- **Fix.** Add a "Checking a receipt" paragraph with closed codes, in the style of §10.1, plus a `receipt-bad/` case for each.

### D12 (M). `tlog-tiles` is exercised only for one partial tile

- **Prose.** §6 l.587–588 restates full tiles, `.p/<W>`, the `x`-prefixed groups and level-L tiles, and says the served `tile/<L>/…` hashes "MUST also agree". The suite serves exactly `tile/0/000.p/127` and `tile/entries/000.p/127`.
- **Evidence.** All four variants pass 1212/1212, and all diverge on constructed logs:
  - `tiles.full-as-partial`: honest 300-entry log, base `accepted`, variant `refused:unserved`
  - `tiles.level-ge1-unchecked`: flipped byte in `tile/1/000.p/1`, base `refused:tiles`, variant `accepted`
  - `tiles.path-no-x-prefix`: honest 256,256-entry log needing `x001/000`, base `accepted`, variant `refused:unserved`
  - `tiles.bundle-count-lax` (§6: "holds **exactly** the number of entries its path declares"): one extra entry in the bundle, base `refused:entries`, variant `accepted`
- **Why it matters.** Any real log grows past 256 entries, and these are the code paths a second verifier will hit first in production.
- **Fix.** Ship a `served-large/` with at least 300 entries (a full tile, a partial tile and a level-1 tile), and a `served-bad` case with an over-full bundle.

### D13 (M). Each RFC 6962 proof algorithm is exercised in one shape only

- **Prose.** §8.1 and §11.1 defer to RFC 6962 and warn: "a reader implementing their own ordering will reject sound evidence".
- **Evidence.**
  - `merkle.consistency-no-pow2` (drops RFC 9162's prepend-when-first-is-a-power-of-two step) passes; the only sound evidence is at size 41.
    - Witness: sound evidence at 64→127. Base `FORK PROVEN`, variant `refused:proof`.
  - `merkle.inclusion-parity-only` (no right-edge rule) passes; no bundle proves a right-edge leaf.
    - Witness: inclusion proof for index 126 of 127. Base `verifies`, variant `refused`.
- **Fix.** Ship evidence at a power-of-two `size`, and a bundle or proof for the last leaf.

### D14 (M/L). One checkpoint can still be spelled more than one way

§6 and §7 argue that two spellings of one head make gossip and caches keyed on bytes chosen by an attacker, and they closed that hole for the size line and the payload length. The gate identified these cases:

- **(a) Non-zero base64 pad bits.** "Standard base64 with padding" (l.585, l.635) doesn't say whether the pad bits must be zero (canonical).
  - Witness: the served head re-signed and cosigned with its root line spelled using non-zero pad bits. Base (strict) `refused:checkpoint`, `b64.nonstrict` `accepted`.
  - The same ambiguity applies to signature payloads and receipts. Verifier
    keys encode 33 bytes, so they have no padding or unused pad bits; their
    alternate spelling was a carriage return inside the base64 data.
  - **Resolved in d-xi-iii:** §6 root lines and §7's 68-byte note and
    76-byte cosignature payloads require canonical pad bits, with three refusal
    vectors. §7 and §9.1 now require canonical verifier-key data, pinned by
    `trust-bad/44-log-key-base64-cr`. §7 now requires canonical receipt leaf
    hashes too; `receipt-bad/leaf-hash-nonzero-pad-bits.note` is re-signed and
    refuses as `leaf-hash` while decoding to the good receipt's hash.
- **(b) A blank line after the last signature line.** l.629 says "ends in **one** `0x0A`".
  - Witness: `served/checkpoint` + `\n`. Base `refused:note`, `note.trailing-blank-ok` `accepted`.
- **(c) Which code for a known key's line of the wrong length?** E.g. a 76-byte payload under the log key's name and id. §10.1 is a closed list, so the code is part of the contract.
  - Witness: base `log-signature`, `note.length-by-algorithm` `note`.

**Fix.** Say "canonical (RFC 4648 §3.5: pad bits zero)"; ship a re-signed vector for (a) and (b); assign (c) a code.

### D15 (M). `requests-bad/excess-padding` doesn't test the rule it names, so the ≥5-bit padding rule has no vector

- **Prose.** §16.2 l.1643: "A decoder MUST reject a payload whose padding is 5 bits or more". §12.1 l.1315: the padding negatives are "the valid request with its encoding corrupted, so only §16.2 refuses them".
- **Evidence.**
  - The file has 328 data groups = 1640 bits = exactly 205 bytes. BIP-350's reference `convertbits(…, 5, 8, False)` accepts it as **205 bytes ending in `0x00`**; I verified this with the reference algorithm as BIP-173 gives it. The appended zero group joined the 3 existing pad bits into a whole byte, so there is no padding at all. What refuses it is §4.0's whole-input rule.
  - `bech32.excess-padding-ok` passes 1212/1212.
  - Witness: a request of 203 bytes (8·203 mod 5 = 4, so the minimal pad is 1 bit) plus one zero group gives 6 pad bits and no extra byte. Base `refused:text (excess padding)`, variant `accepted`.
- **Fix.** Rebuild the vector from a request whose length L has 8L mod 5 ∈ {0, 3, 4}, and correct l.1315.

### D16 (L). Byte bounds are not pinned at the boundary

Every variant below passes 1212/1212 and diverges on an exact-boundary input:

| bound | vector size | why the off-by-one passes |
|---|---|---|
| `note`/`policy` text cap 4096 | `bad-text-too-long` is **4098** bytes | a cap of 4097 still refuses it |
| `reason` cap 256 | `bad-revoke-reason-too-long` is **258** bytes; §12.1 l.1332 says 257 | a cap of 257 still refuses it |
| label value cap 256 | `oversize-label` is **258** bytes | a cap of 257 still refuses it |
| `MAX_TRUST_BYTES` / `MAX_EVIDENCE_BYTES` 65536 | only "far over" | a reader using 65535, like the entry cap, passes; witness: a 65536-byte trust file, base `accepted`, variant `refused:oversize` |
| `rotate_needs_signer` is a bool | only "bool where uint" (`bad-params-wrong-type`) is vectored | `{rotate_needs_signer: 1}`: base `decode`, `params.bool-accepts-uint` `accepted` |

**Fix.** Ship the exactly-at and one-past vectors, the way `entries-hostile` does for the entry cap.

### D17 (L). `fork/bad-size-above-held` doesn't isolate its rule

- **Evidence.** The file has `size` 128, held 127 and conflicting **41**, so step 7's second half ("conflicting's size equals `size`") refuses it with the same code. `evidence.size-above-held-ok` passes.
  - Witness: `size` 128 with a signed size-128 conflicting head. Base `size`, variant `proof`. No false fork results; only the code differs.
- **Fix.** Rebuild the vector with a conflicting head of size `size`.

### D18 (L/M). Some value checks are left unspecified

- **(a) Reserved labels `ip` and `endpoint`.** They are "advisory hints" (l.222). Whether a malformed value invalidates the request is not said, and every vector value happens to be valid.
  - Witness: enroll with `ip = "not-a-cidr"`. Base `accepted`, `labels.reserved-validated` `decode`. This is a replay divergence.
- **(b) Witness `url`.** Only `log_urls` must be non-empty.
  - Witness: witness `url` = "". Base `accepted`, `trust.witness-url-nonempty` refused.
- **(c) Policy URLs vs `witnesses[].url`.** Whether they must agree is not said either.

**Fix.** Say "not validated" for each, explicitly.

- **D18a resolved in d-ix-iii:** §4.0 now says reserved hint syntax is not
  validated during request checking or replay. A valid signed request and an
  accepted enrollment both carry malformed `ip` and `endpoint` values, and the
  Go and Python readers preserve them.

### D19 (M). U+2028 and U+2029 in canonical JSON

- **Prose.** §14.2 l.1558–1564: everything else verbatim, including non-ASCII. §14 says "nothing here may be left to a JSON library's defaults, because they differ".
- **Evidence.** Go's `encoding/json` escapes U+2028 and U+2029 even with `SetEscapeHTML(false)`. No vector contains either character. The full set of non-ASCII code points in `state.json` is U+007F, U+00ED, U+00F1, U+05D0, U+3059, U+3066, U+3068, U+65E5, U+672C, U+8A18, U+9332, U+E000, U+1F511 and U+1F512. `json.escape-u2028` passes.
  - Witness: a `policy` entry whose witness URL contains U+2028. That is content per §9.1's closed set, so it lands verbatim in `state.policy`. The two readings produce different `state.json` bytes.
- **Fix.** Add U+2028 to `log/106`'s `escapes` label.

### D20 (L). Bundle binding for `rotate`/`revoke` entries has no vector

- **Prose.** §8.1 l.713–715 says how `rotate` and `revoke` entries bind. All six bundles prove `enroll` entries.
- **Evidence.** `bundle.binding-enroll-only` passes.

### D21. Documentation inconsistencies

- **(a)** `vectors/README.md` (the `detect/` row) says the `hard-below-staleness` cases are where "`fresh` wins". SPEC §8.1, D-060 and `staleness.json` all say `hard_stale`. A reader who trusts the README implements the order the spec forbids.
- **(b)** §12.1 l.1324 says `requests-bad/oversize-label-key` "reaches the `labels` *field* rule first, which is a different check in a different layer". But §4.0's 1–23-byte map-key cap is a decoder rule that fires during decode, before any field rule; my decoder refuses it there. The two passages contradict each other. There is no observable code either way, because requests have no closed vocabulary.
- **(c)** §12.1 l.1332 says `bad-revoke-reason-too-long` is 257 bytes; it is 258 (129 × "é").
- **(d)** §9.2's example shows `genesis_hash = "4e18d55c…"` next to the real fingerprint `Y2KM-WGEJ-5GCD-X3HA`. The file that fingerprint belongs to has `f168d197…`.
- **(e)** §5.1 l.374 says "The four that carry the weight" and then lists five.
- **(f)** The title says "v0 (draft)"; the status line says frozen v1.
- **(g; resolved in d-vi).** The run-12 reading counted two faults in `trust-bad/07` and `/08`; the regenerated cases now isolate the witness minimum and duplicate-name uniqueness, and §12.1 explains why each is the only failing rule.
- **(h; resolved in d-x-iii).** At run 12, §12.1 omitted the findings in D1, D2, D4, D5 and D8–D20. Later coverage work added most of them; the final audit added the same-size held-root and replay-order rows and guards representative cases across that range.

- **D21(b), (d)–(h) resolved in d-x-i/ii/iii:** the request key-cap refusal is
  attributed to the decoder, §9.2's example matches the shipped `trust.toml`,
  §5.1 names five precedence vectors, the title says frozen v1, the trust
  negatives are isolated, and §12.1 accounts for the reviewed run-12 findings.

### D22 (L/M). Further choices the suite neither pins nor punishes

- **`cbor.bool-is-profile` (resolved in d-x-iv).** §4.0 admits booleans as CBOR profile items and assigns field-type rejection to schemas, which MUST reject them outside `params.rotate_needs_signer`. `fork/bad-bool-size.cbor` decodes in both generic CBOR readers and the fork evidence reader refuses `size: true` as `schema`.
- **Normative content outside the document (closed in d-xii).** "Every cross-reference resolves" (l.6) was not true for a reader holding only `SPEC.md` and `vectors/`. §15 now owns source-neutral checkpoint acquisition and §10's verification-before-adoption order (d-xii-i), plus the witness-time clock, peer polling and gossip endpoints (d-xii-ii). §§8.1 and 13 now own enforcement modes, failure semantics, and the published proven-set interface (d-xii-iii). §§9.4 and 16.3 now own rotation, overlap and key handling, with `ENROLLMENT.md` aligned and its unbuilt flows marked planned (d-xii-iv). The final audit (d-xii-v) declared all three companions informative in their own headers, redirected §6's last live pointer to §15, and guarded the whole document against delegation. A reader holding the spec and the vectors needs no other document.

---

## 5. Every decision the prose didn't make for me

These were written down before I opened the vectors; see `DECISIONS-PRE-VECTORS.md`. The table gives the outcome of each. "Vector-resolved" means the prose left it open and a vector happens to pin it; a guess that matched is still a guess.

| # | decision | outcome |
|---|---|---|
| P1 | Simple values other than true/false/null/undefined are refused | unvectored; a typed model refuses them anyway |
| P2 | Booleans: decoder rule or schema rule | resolved in d-x-iv: valid profile item; wrong field type is `schema` (`fork/bad-bool-size`) |
| P3 | Depth 8 accepted, 9 refused | vector-resolved (`at-/past-the-depth-limit`) |
| P4 | `MAX_ENTRY_BYTES` measured on input length vs a declared length | no consequence; the oversize vector is also long |
| P5/P6 | Key cap applies to `labels`; non-text keys refused | vector-resolved |
| P7 | Reserved additional-info values 28–30 refused | unvectored, RFC 8949 well-formedness |
| E1 | Type of `body` checked at step 3 | **open, divergent** (D6) |
| E2 | Non-text `t` is `decode` | **open, divergent** (D6) |
| E3 | Governance body checked after step 7 | vector-resolved (`94-bad-undersigned-malformed`) |
| — | Non-uint `after` is `decode` | **open, divergent** (D6) |
| T1 | `rotate` with `device_pk` equal to the current one: one signature satisfies both requirements | unvectored; no plausible rival reading |
| T2/T3 | Device self-revoke and `note` authorisation are role-matched | vector-resolved |
| T4 | Policy vkeys parsed, ids recomputed, any of algorithms 0x01/0x04 accepted | **open, divergent** (D7d/e) |
| T5 | `none` not definable | **open, divergent** (D7b) |
| T6 | One namespace for witness and group names | **open, divergent** (D7c) |
| T7 | `quorum` may precede the definitions it names | **open, divergent** (D7a) |
| T8 | `k` canonical, 1 ≤ k ≤ n | lower bound vectored; upper bound unvectored (D8c) |
| T9 | Policy URLs not validated | unvectored |
| S1/S3 | All four `params` keys always emitted; abort state | vector-resolved |
| S2 | The `.json` entry mirror renders `request` as hex bytes | vector-resolved, not stated in prose |
| Q1 | **Which policy computes `T`?** The policy under which the checkpoint was accepted: the trust file's policy for a first read, or the previously replayed policy thereafter. A `policy` entry in the checkpoint's own replay range applies to the next checkpoint and does not retroactively change its `T`. | resolved in d-x-v: §5.3/§9.4 say this, and `proofs/cases.json` plus Go checks distinguish 1760003607 under the acceptance policy from 1760003600 under the checkpoint's replayed policy |
| Q2 | Expired iff `expires != 0 && expires <= T` | stated; vectored |
| N1 | A known key's line with the other algorithm's length is a verification failure, not framing | **open, divergent** (D14c) |
| N2 | `+` in a signature-line name not checked at framing | no consequence |
| N3 | Empty note text is `note` | unvectored |
| N4 | Strict base64 (zero pad bits) | resolved in d-xi-i/ii/iii: root, note payload, verifier-key data and receipt leaf-hash spellings are canonical, with refusal vectors |
| N5/N6 | Size fits in uint64; every trusted-key line must verify | vectored |
| N7 | A hash tile of the wrong length is `tiles` | unvectored |
| — | A learned log key signs under the name `origin` | vector-resolved (`served-rotated`); not stated in prose |
| — | A learned key is usable once `state.size > since_index` | unvectored; no consequence in the suite |
| R1 | Empty witness `url` accepted | **open, divergent** (D18b) |
| R2 | Policy URLs need not equal `witnesses[].url` | unvectored, open |
| R3 | `anchor` is closed | stated generally (§4.0); unvectored (D10c) |
| R4 | The `log` line is compared to `log_key` as text | vectored (36) |
| R5 | TOML→CBOR mapping (which fields are bytes, the `[[witness]]`→`witnesses` key, map order) | worked out from §9.1 types; my reader reproduces `trust.cbor` byte-for-byte |
| B1 | An undecodable bundle entry is `binding` | unvectored |
| B2 | `index ≥ size` is `inclusion` | unvectored |
| B3 | A bundle is checked under the trust key and trust policy | vector-consistent |
| V1 | Evidence at `size` 0 | **open, divergent** (D3) |
| — | Order of trust-file checks | **unspecified**; matters only for `says` (D21g) |
| — | Request refusal layers (text, CBOR, schema, signature) for a missing or short `sig` and a short `device_pk` | unspecified; no vocabulary |
| Q-R1 | A `.txt` file's trailing newline is not part of the text | resolved by a `cases.json` comment, not by SPEC |
| Q-R2 | Reserved labels not validated | resolved in §4.0 and positively vectored at request and replay layers (D18a) |
| Q-R3 | bech32m case rules | vectored |
| — | `detect/`: the node's own branch is `served/`'s entries truncated at the stored size | inferred from a `cases.json` comment |
| M1 | No `cases.json` schema is specified anywhere in SPEC | harness only, but every runner has to reverse-engineer about 20 file formats |
| M2 | Trust, requests, policies, receipts and hostile input have no closed refusal vocabulary | "refused for its own reason" is judged by hand-mapping `says` in those layers |

## 6. What I couldn't cover, and why

- **Normative material that doesn't ship:** `GOSSIP.md` (acquisition order, the witness-time clock, gossip endpoints), `ENFORCEMENT.md`, `ENROLLMENT.md`, `THREAT-MODEL.md`, `DECISIONS.md`. Anything that lives only there is unreviewed.
- **Live-node behaviour:** §7 HTTP submission and the 400/409/429 codes, tlog-witness, monotonic-clock handling, §8.1 conditions 2 and 4 on a running node, and the §11 duties (writing evidence, alarms, permanent refusal). I tested only the artifact-level logic: the freshness table, the detect pairs and the evidence reader.
- **OpenTimestamps:** I didn't parse the container. I checked the §6 digest range and that each stated digest appears inside its `.ots`; `calendar-response.bin` wasn't examined.
- **External tooling:** under the constraints (standard library only, no network) I didn't run `x/mod/sumdb/note`, `transparency-dev/formats` or the real witness. My note and cosignature code agrees with every vector, which is all I can claim.
- **`quorum none` end to end:** that needs a second anchor, as §12.1 says. I tested `T`'s "no clock" branch only through `proven/` (t = 0) and the `T.quorum-none-unbounded` variant, which passes undetected.
- **The median vs the k-th newest timestamp** can't be separated with three witnesses (admitted in §12.1); I didn't build a four-witness network.
- **Variant coverage is mine, not exhaustive.** 276 readings, chosen rule by rule from the prose. A variant I didn't think of could still pass. Composites were chosen deliberately (86), not exhaustively; all ~37,000 pairs were not run.
