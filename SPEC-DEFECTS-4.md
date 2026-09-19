# SPEC.md — defect register, gate run 4

Raised **2026-09-19**. A fourth fresh agent on a fourth fresh copy: **335 checks,
0 failures**, then **57 variant implementations** to find which decisions the
vectors do not pin. Verdict **SPEC SUFFICIENT WITH GAPS** again — for reasons
that were almost entirely about the *suite*, not the prose.

Status: ⬜ open · ✅ fixed.

## The finding that mattered

| # | Defect | Status |
|---|---|---|
| **F1 ✅** | **A signature-blind replay passes the entire suite.** With `ed25519.Verify` stubbed to return `true`, the agent reproduced all 84 outcomes and both other stages. No vector anywhere contained a signature that resolves by `kid` and role but **fails verification**: the existing negatives are a *missing* signature, too *few* signatures, a signature by the *wrong device*, or a *mislabelled* role — every one detectable without doing any cryptography. The most security-critical MUST in §5 had nothing behind it, and §12.1 claimed otherwise. Fixed: `bad-forged-signer-sig` and `bad-forged-device-sig` carry syntactically perfect, cryptographically wrong signatures; a test now fails the build if stubbing verification ever stops changing the outcome. | ✅ |

## Vectors that did not test what they claimed

| # | Defect | Status |
|---|---|---|
| F2 ✅ | `bad-oversize-map-key` and `bad-unsorted-sigs` carried `after: 76` while sitting at indices 69 and 70 — **rejected for `after`, never reaching their own rule**. Collateral from my 0.11c renumbering: D-041 made *names* derive from the index but left `after` hard-coded. Fixed at the root: the control builders take the index as a parameter, and a test asserts no entry's `after` exceeds its index (bar the one whose purpose is to). | ✅ |
| F3 ✅ | `bad-invalid-utf8`, `bad-integer-too-large` and `bad-oversize-map-key` patched bytes **inside the signature preimage without re-signing**, so all three were rejected for a broken signature. §4.0 claimed a lenient decoder "produces a valid entry" from them — false. Fixed: those are re-signed over the patched preimage; §4.0 now names both isolation constructions; a test proves every encoding negative's signatures verify under one of them. | ✅ |
| F4 ✅ | Run 4 believed `63`–`66` were correctly isolated. Testing that claim showed **all eight** encoding negatives needed checking, and that two *different* isolation routes exist — a patch that canonicalises away keeps its original signatures; one that cannot must be re-signed. The test now accepts either and rejects neither. | ✅ |

## §12.1 — the section whose job is to be honest

| # | Defect | Status |
|---|---|---|
| F5 ✅ | **~13 vector citations were wrong**, with two different offsets (−11 and +4), because the table was written before the 0.11c renumbering and never regenerated. It also listed a negative (`bad-repeat-of-rejected`) as a *control* and put two real controls in the negatives column. Fixed systemically: §12.1 now cites vectors **by name, never by index**, and `internal/specdoc` fails the build if any citation stops resolving against the manifest. | ✅ |
| F6 ✅ | The "§4.2 signatures" row claimed a negative it did not have (it cited `wrong net`, a `decode` case). Now cites the two forged-signature vectors. | ✅ |

## Still open

| # | Defect | Status |
|---|---|---|
| F7 ◐ | Closed: body-schema ordering (**D-046** — my implementation was on the wrong side of my own spec), `params` merge-vs-replace (genesis now carries a non-default `mmd`), `log_key` append-vs-replace (a second rotation), device-signed `note`, `revoke` by root quorum. Still open, all low-severity: byte-vs-rune length caps, empty `params`, unknown keys in `genesis.body.params`, the trust file's `log_urls` minimum, `name` length, `anchor` shape and note key-id derivation. Originally: body schema validated at step 3 rather than step 8; `params` replace-vs-merge (genesis params are all at their defaults, so the overlay is invisible); `log_key` replace-vs-append (only one exists); a device-signed `note`; `revoke` with no root path; byte-vs-rune length caps; empty `params`; unknown keys in `genesis.body.params`; the trust file's `log_urls` minimum, `name` length, `anchor` shape and note key-id derivation. | ◐ |
| F8 ✅ | Trust negatives `03-short-net`, `04-origin-mismatch` and `10-missing-policy` are **over-determined** — each trips a second rule, so the `origin`-derivation MUST and the required-keys MUST have no isolated negative. | ✅ |
| F9 ✅ | `genesis/` body invariants are half covered: no duplicate *signer*, `signer_thr` above set, zero thresholds, empty `roots`/`signers`, unknown key in `genesis.body.params`. Three existing cases are over-determined (a `note` at index 0 necessarily lacks every genesis field). | ✅ |
| F10 ⬜ | §16 enrollment requests have **no vectors at all** and §12.1 does not admit it. Same for §5.1's empty-log rule and a `v != 1` negative. | ⬜ |
| F11 ✅ | Prose: §4.0's `sigs: []` claim is wrong for `enroll`/`rotate` (their first check is `no-device-sig`, not `threshold`); §4.0's field-constraint table is false at index 0, where every violation is `bad-genesis`; §5.1 and §5.2 disagree on `dup-wg` scope for `enroll`; "well-formed `sigs`" is assembled from four scattered statements and never says a signature map is itself closed; no depth or size limit is specified anywhere. | ✅ |

## What run 4 confirmed

Stage 1 passed **on the first run**, with §4.1's worked counter-example singled
out as "the single most valuable sentence in the document". The agent's one
substantive misreading — expecting a body mutant to be `decode` when the root
quorum runs first — it attributed to the spec being right and itself not having
internalised it yet: *"the subtlest correct thing in the document and it is well
written."* Structural hygiene came back clean: no orphans, no manifest
mismatches, every sidecar present and agreeing.
