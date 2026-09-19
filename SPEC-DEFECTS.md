# SPEC.md — defect register

Raised **2026-09-19** by the checkpoint 0.6 cold-model gate: an independent agent
was given `SPEC.md` + `testdata/vectors/` and nothing else, and implemented the
protocol in Go (stdlib only, its own CBOR codec). It passed **227/227** checks —
and returned **SPEC INSUFFICIENT**, because several answers came out of the
vectors rather than out of the prose.

That is the gate working. A conformance suite exists to stop two honest
implementations from diverging; anything an implementer must reverse-engineer
from a vector is a place where they can diverge instead.

Every Tier-1 and Tier-2 item below was spot-checked against the actual files
before being accepted. Status: ⬜ open · ✅ fixed · ⛔ rejected (with reason).

## Tier 1 — load-bearing; the spec-literal reading produces non-conforming output

The agent proved each of D2, D4, D5 by building the spec-literal variant and
watching it fail against the vectors.

| # | Defect | Fix | Status |
|---|---|---|---|
| D1 ✅ | §5's state sketch says `policy_text` and `log_keys: [{pk, valid_until}]`; the real state has `policy` and `{overlap, pk, since_index}`, plus `name`, `net`, `size`, none of which appear anywhere in the spec. §5 demands byte-identical state JSON — unachievable as written. | Publish the canonical state as a **normative field table**, not a sketch. | ✅ |
| D2 ✅ | §12 says "object keys sorted" without saying which order, in a document whose §4.1 spends two paragraphs establishing *length-first* for CBOR. The JSON vectors use plain bytewise — the opposite convention. Carrying §4.1's order into §12 fails **16/16** entry mirrors. | State plainly: canonical JSON sorts by **UTF-8 code point**, unrelated to the CBOR map order. | ✅ |
| D3 ✅ | §12 says "absent fields absent", but state renders a device enrolled without labels/expires as `"expires":0,"labels":{}`. | Say that *state* fields are always present with zero values; the absent rule governs *entry* encoding. | ✅ |
| D4 ✅ | `revoke` moves `since_index`; `rotate` does not. §5 mentions `since_index` only under `enroll`. | Give `since_index` its own rule per type. | ✅ |
| D5 ✅ | `dup-entry` and `unknown-type` are in the §5.1 table but absent from §5's numbered procedure, and the position is load-bearing: vector 13 is simultaneously `dup-entry`, `dup-id` and `dup-wg`. Checking it where §5's list implies gives `dup-id`. | Fold both into the numbered procedure with explicit precedence. | ✅ |
| D6 ✅ | Replay's trust anchor is undocumented; the vectors feed it from `log/manifest.json`, a file and shape that appear nowhere in the spec. `state.net` comes from the anchor, not the genesis entry. | Document the anchor input and `manifest.json` in §12. | ✅ |

## Tier 2 — self-contradictions inside SPEC.md

| # | Defect | Fix | Status |
|---|---|---|---|
| D7 ✅ | §4.0 caps every map key at 23 bytes, then permits `labels` keys of 1–64 bytes. A 30-byte label key is unencodable. | Cap label keys at 23 bytes. | ✅ |
| D8 ✅ | §5 rejects a `rotate` whose `wg_pk` is "in `active_wg`"; §5.1 rejects only if active **for another device**. A device re-presenting its own key is accepted by one and rejected by the other. **No vector covers it** — two implementations can differ and both pass. | Take §5.1's reading; add a vector. | ✅ |
| D9 ✅ | §9's trust-file sample disagrees with the shipped file on four fields: `net_id`→`net`, `genesis_hash` base64→hex/bytes, `max_lag` `"24h"`→`86400`, and witnesses also carry `url`. The fingerprint is `H(CBOR(trust))`, so wrong field names change it. | Regenerate §9 from the real structure; add a normative CBOR field table. | ✅ |
| D10 ✅ | §4.1's "both readings give the same bytes" is true for the two readings meant, but invites a third (bytewise on the key *string*) that differs for every entry in the suite. | Delete the reassurance or name the second reading. | ✅ |

## Tier 3 — undecided by the prose *and* by the vectors

Two independent implementations can disagree on each of these and both pass the
suite clean. Each needs a spec decision **and** a vector.

| # | Question | Agent's choice | Status |
|---|---|---|---|
| D11 ✅ | `root_thr` with `thr > len(roots)` satisfies both codes | **`bad-thr` — D-033**; `root-invariant` reserved for removals. Vector 42. | ✅ |
| D12 ✅ | `revoke` with no authority at all | **`threshold`**, stated in §5.1. Vector 43. | ✅ |
| D13 ✅ | Genesis bootstrap unstated | **count against `body.roots`/`body.root_thr`; abort with `bad-genesis`** — written into §5.1, since the procedure had to state it | ✅ |
| D14 ✅ | Index 0 that fails to *decode* | **`bad-genesis`, abort** — §5.1 entry-0 step 2 | ✅ |
| D15 ✅ | Do rejected entries enter the `dup-entry` seen-set? | **yes — D-031**, decided during 0.7a because §5.1 step 1 had to state it | ✅ |
| D16 ✅ | `log_key`: append or replace? | **append**; §5.3 now states the trust file's initial key is deliberately absent from `log_keys` | ✅ |
| D17 ✅ | Re-enrolment after revoke: prior `labels`/`expires` discarded? | **yes, the record is replaced wholesale** — §5.3 | ✅ |
| D18 ✅ | Unrecognised `role` string | **`decode`** — `role` is a closed enum; §4.0 now distinguishes this from a well-formed signature whose `kid` does not resolve. Vector 44. | ✅ |
| D19 ✅ | Must a zero-signature entry carry `sigs: []`? | **yes**, `sigs` is mandatory; omitting it is `decode`, an empty array is `threshold`. Vector 45. | ✅ |
| D20 ✅ | `rotate` with a new `device_pk`: must the incoming key sign? | **yes, required — D-032** (proof of possession). Vectors 40 and 46. | ✅ |
| D21 ✅ | Check order within `enroll`/governance never tested | normative in §5.1; vectors 47 (device sig before `dup-id`) and 48 (root quorum before the per-type rule) | ✅ |

## Tier 4 — editorial and process

| # | Defect | Status |
|---|---|---|
| D22 ✅ | §7 defers the signed-note framing entirely to an external spec; the agent recovered the signed-text boundary by hashing three candidates against `receipt.json`. One normative sentence removes it. | ✅ |
| D23 ✅ | `genesis_hash` appears as raw hash (§5), base64 (§9), hex (file) and bytes (CBOR) | ✅ |
| D24 ✅ | §2 doesn't name the base32 alphabet for `origin`; §9 doesn't state Crockford's bit order. §9's worked example is doing normative work by accident. | ✅ |
| D25 ✅ | §4.0: "the 14 ASCII bytes `norn/entry/v1` + `0x0A`" — the string is 13 bytes; reads as 15 | ✅ |
| D26 ✅ | `size` never defined | defined in §5.3: `last index + 1`, or `0` if replay aborted at entry 0 | ✅ |
| D27 ✅ | §12 promises vectors that don't exist: `entries/bad-*`, `proof-*.bundle`, `fork/`, and describes `log/` as a tlog-tiles directory with tiles and a checkpoint — it has neither. **§6, §8, §10 and §11 are entirely unexercised.** "Every MUST has, or will have, a test vector" is not true today. | ✅ |
| D28 ✅ | The `.json` entry-mirror schema is undocumented | ✅ |
| D29 ✅ | §4.5 `witness_policy` vs `policy` entries: does `genesis.params.witness_policy` seed `state.policy`? Must `genesis.params` be complete? | ✅ |

## What the gate confirmed is sound

§4.0 / §4.1 / §4.2 — the encoding profile, derived values, preimage domain
separator, and §5.1's "Signature counting, precisely" paragraph. Stage 1 passed
**162/162 on the first run with no reference to any vector**. The byte-level
contract is the strongest part of the document; everything downstream is weaker.

---

## Status — all 29 closed (2026-09-19)

| tier | items | outcome |
|---|---|---|
| 1 | D1–D6 | 0.7a — §5 rewritten, §5.3 normative state schema, §12 key order pinned |
| 2 | D7–D10 | 0.7b — label cap, `dup-wg` decided **and vectored**, §9 regenerated |
| 3 | D11–D21 | 0.7a/0.7c — every question stated and vectored; D-031, D-032, D-033 |
| 4 | D22–D29 | 0.7d — note framing normative, renderings reconciled, §12.1 admits its holes, D-034 |

Decisions this register produced: **D-031** (entry usable once, closing a
resurrection replay), **D-032** (proof of possession on rotate), **D-033**
(`bad-thr` vs `root-invariant`), **D-034** (one home for the witness policy).

Next: 0.8 re-runs the gate with a *fresh* agent on a *new* isolated copy. A gate
re-run by the same agent, or against a copy it has seen, proves nothing.
