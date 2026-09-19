# SPEC.md — defect register, gate run 2

Raised **2026-09-19** by the 0.8 cold-model gate: a **fresh** agent, a **new**
isolated copy, no knowledge of run 1 or its findings. It scored **134/134** and
returned **SPEC INSUFFICIENT**.

Its method deserves recording, because it is better than run 1's: it built
**eight variant implementations**, each embodying a different but defensible
reading, and re-ran the whole suite against each. A variant that still scores
134/134 proves the *vectors* do not pin that decision; a variant that fails
proves the vector pins it, and the prose can then be checked separately. That
distinguishes "the spec told me" from "the vector told me" from "nothing tells
anyone" — which is precisely the question a conformance suite must answer.

Variants that passed anyway (⇒ unpinned): `dup-entry` after decode · JSON
HTML-escaping · device signatures matched by `kid` ignoring `role` · governance
body-decode before the root threshold · genesis `params` ignored entirely ·
`signer_remove` enforcing the quorum invariant **D-028 forbids**.

Status: **all 12 closed** — E1 and the structure linter in 0.9a, E2–E11 and the
corrected coverage claim in 0.9b-1, the remaining vector gaps in 0.9b-3.

## Blockers

| # | Defect | Status |
|---|---|---|
| E1 ✅ | **Canonical JSON did not exist.** §5.3's central MUST cross-referenced §12, a table of filenames, and the document skipped §14 entirely. Byte-string rendering (hex vs base64), the trailing newline, key ordering and **all string escaping** had to be reverse-engineered from `state.json`. Escaping remained undefined even then: an HTML-escaping variant scored 134/134, so two conforming implementations would diverge on the first policy containing `<` or `é`. | ✅ §14 restored and made complete; vectors 49/50 exercise every escape rule |
| E2 ✅ | `log_keys[].since_index` is undefined — the only definition of `since_index` in the document is about *devices*. Read off `state.json`. | ✅ |
| E3 ✅ | §5.1's "no other field is populated beyond `net`" is factually wrong: `bad-genesis/state.json` carries the full §4.5 `params` defaults and every field at its zero value. Following the sentence verbatim fails the vector. §5.3 is what actually governs. | ✅ |
| E4 ✅ | `revoke` failure has two reason codes in two normative tables: §5.2's `no-device-sig` row names "self-`revoke`", §5.1 says `threshold`. Vector 43 requires `threshold`. §5.2's row must drop "self-`revoke`". | ✅ |

## Contradictions and gaps

| # | Defect | Status |
|---|---|---|
| E5 ✅ | §4.0 states `sigs: []` → `threshold` (by decision number), but no vector covers it; vector 45 tests the *omitted* key instead. | ✅ |
| E6 ✅ | `kid` has no field constraint: is a malformed `kid` `decode`, or merely unresolvable? Unspecified, unvectored. Same for the reason code earned by an unsorted or duplicate-`kid` `sigs` array. | ✅ |
| E7 ✅ | §4.0 applies the encoding profile — including the 1–23-byte map-key cap — to "canonical state", which **cannot satisfy it**: `active_wg` is keyed by a 32-byte key and `devices` by a `device_id` of up to 64 bytes. | ✅ |
| E8 ✅ | genesis `params` is required in §4.3 and optional in §5.1. Unvectored either way, and the fixture's genesis params are exactly the defaults, so ignoring them entirely still passes. | ✅ |
| E9 ✅ | **D-028's "MUST always be possible" has no vector defending it.** Vector 21 removes a signer without ever dropping below the threshold, so a variant enforcing the forbidden invariant passes. The one security property the spec argues for at length is untested. | ✅ |
| E10 ✅ | Trust file: CBOR key is `witnesses`, the TOML rendering uses `[[witness]]`. Anyone building the CBOR from the documented human rendering produces a different key and therefore a different fingerprint. Array order significance and absent-optional rendering are also unstated. | ✅ |
| E11 ✅ | Smaller: §2 does not name `origin`'s base32 alphabet in a document that uses two · the fingerprint's `-` separator and trailing newline are inferable only from the example · `receipt.json`/entry-mirror schemas undescribed · §12 says `testdata/vectors/` but the suite ships at `vectors/` · replay of an empty log undefined · genesis step 5 (`after` ≠ 0) unvectored. | ✅ |
| E12 ✅ | **§12.1's coverage declaration is itself inaccurate.** §4's six field-constraint rows have **no** rejecting vector; the encoding profile has **zero** negative vectors, so a decoder skipping all profile enforcement scores 134/134. Two of §5.1's "normative" orderings are unexercised. Genesis has five distinct abort conditions and one vector. `expires` is `0` for every device in every state. §9 is a single positive fixture. | ✅ |

## What run 2 confirmed is sound

§4.0–§4.2 and the §5 state machine: "I implemented all of it from prose with
zero corrections." The 14-byte preimage prefix cross-checked in words, the CBOR
key-order trap written out both right and wrong, and the `role`-enum vs
unresolvable-`kid` distinction were all called out as the reason a second
implementer would *not* go wrong. Scoped to §4 and §5 proper, run 2 rates the
spec **SUFFICIENT WITH GAPS**. The insufficiency is concentrated in
serialisation — and there it was total.
