# Norn — Build Log

One line per sub-checkpoint. A checkpoint is ✅ only when its "done when" is fully
true, the suite is green, and it is committed. Gates in `PLAN.md` are ticked only
when every line of the gate is true.

Method (binding): TDD (red → green → refactor), one package = one responsibility,
dependencies point inward (`cmd/` → `internal/*` → stdlib/crypto), interfaces at
boundaries only, no package imports a sibling it doesn't need. The **Python
reference implementation** under `contrib/norn-ref/` is written *from the spec,
first*, and generates the vectors the Go code must match — so the Go code never
becomes its own oracle.

## Phase 0 — Threat model, ledger decision, spec skeleton

| # | Checkpoint | Done when | Status |
|---|---|---|---|
| 0.1 | Repo skeleton | git initialised; `go.mod` = `github.com/onembyte/norn`; Apache-2.0 `LICENSE`; `Makefile` with `test` `vet` `fmt-check` `ci`; package dirs with `doc.go`; CI workflow; `make ci` green; first commit | ✅ |
| 0.2 | Spec tightened for implementation | `SPEC.md` §4 pins: deterministic-CBOR profile (which RFC 8949 §4.2.1 rules apply, integer/bytes/map encoding), `kid` derivation, signature preimage bytes, `net` encoding; open item on `labels.allowed_ips` resolved; recorded as D-026 | ✅ |
| 0.3 | Python reference: keys + entry encoding + signing | `contrib/norn-ref/` (pure Python, `cbor2` + `pynacl`); `keys.json` from fixed seeds; one valid entry vector per type, byte-exact `.cbor` + `.json`; a Python self-test that re-verifies every signature | ✅ |
| 0.4 | Python reference: replay + rejection vectors | replay state machine per `SPEC.md` §5; 40-entry fixture; `state.json`; one `bad-*.cbor` + `.reason` per reason code; canonical JSON writer pinned | ✅ |
| 0.5 | Trust file, fingerprint, receipt vectors | `trust.cbor`/`trust.toml`/`trust.fingerprint` (Crockford base32, D-029); `receipt.note` (signed note) | ✅ |
| 0.6 | Cold-model gate (run 1) | a fresh model given only `SPEC.md` + `testdata/vectors/` implements an entry verifier that passes all vectors | ❌ **FAILED** — verdict SPEC INSUFFICIENT, 29 defects (`SPEC-DEFECTS.md`) |
| 0.7a | Repair Tier 1 (D1–D6) | normative state schema; JSON key order pinned; always-present rule; `since_index` per type; complete numbered replay procedure incl. `dup-entry`/`unknown-type` precedence; replay anchor + `manifest.json` documented | ✅ |
| 0.7b | Repair Tier 2 (D7–D10) | label-key cap reconciled; `dup-wg` on self-rotation decided **and vectored**; §9 regenerated from the shipped trust file with a normative CBOR table; §4.1 reassurance fixed | ⬜ |
| 0.7c | Close Tier 3 (D11–D21) | every undecided question answered in the spec **and given a vector**, so two implementations can no longer diverge and both pass | ⬜ |
| 0.7d | Tier 4 (D22–D29) | §7 note framing stated normatively; encoding renderings reconciled; base32 alphabets named; §12 vector table made honest about what §6/§8/§11 still lack | ⬜ |
| 0.8 | Cold-model gate (run 2) | a *fresh* agent, new isolated copy, returns SPEC SUFFICIENT or SPEC SUFFICIENT WITH GAPS | ⬜ |

Log fixture (tiles + cosigned checkpoint) moves to Phase 2 where Tessera produces
it and torchwood verifies it — hand-building a tlog in Python adds no assurance.

## Phase 1 — Core library
(subdivided when Phase 0 is ✅)

---

## Journal
- **2026-09-19 · 0.1 repo skeleton** — Go 1.26.4, module `github.com/onembyte/norn`, Apache-2.0, `make ci` (fmt-check / vet / race tests) green on 10 packages, CI matrix ubuntu+macos. Bug found and fixed before the first commit: `fmt-check` used `git ls-files`, which is empty before the first commit, so `gofmt -l` blocked on stdin — now `find | xargs`. Local commit only; GitHub remote not created yet (user decision, see Phase 6).
- **2026-09-19 · 0.2 spec tightened** — added SPEC §4.0 encoding profile (byte-level contract: integer/bytes/text/map rules, `kid`, entry hash, leaf hash, preimage bytes, `sigs` ordering, field constraints), §5.1 closed reason-code list (16 codes) with the precise signature-counting rule, canonical JSON definition in §12, resolved the `labels` open item (D-026). Corrected §4.1: key ordering is RFC 8949 §4.2.1 (bytewise of encoded key), not RFC 7049 length-first; the < 24-byte-key rule (D-027) makes both agree.
- **2026-09-19 · 0.3 Python reference (keys, encoding, signing)** — `contrib/norn-ref/`: `cbor` (deterministic encoder + *strict* decoder — rejects non-shortest lengths, out-of-order/duplicate map keys, floats/tags/null/negatives, trailing bytes), `keys` (named seeds, `kid`), `entry` (envelope, preimage, sign, entry/leaf hash), `canonjson`, `fixture` (one valid entry per type), `gen_vectors`. 19 Python tests green, written before the code. 34 vector files in `testdata/vectors/`. Generation is deterministic (tested by regenerating twice into temp dirs and comparing bytes). pynacl 1.6.2 in a venv; no `cbor2` dependency — writing the encoder is the point, since it is the byte-level contract.
- **2026-09-19 · 0.4 replay + rejection vectors** — `state.py` (state owns its shape and canonical serialisation, nothing else) and `replay.py` (one handler per entry type, registry dispatch, `Reject(code)` mapping 1:1 onto SPEC §5.1). 40-entry fixture log interleaving valid entries with one rejection per code: all 17 rejections land at the expected index, all 15 non-genesis codes covered, `bad-genesis` in its own log because it aborts replay. 36 Python tests green. Vectors: 96 files; `keys.json` gained `spare`/`printer`/`nas2` (pure additions — every existing key and entry byte unchanged, verified structurally).
  - **Security finding → D-028**: my first `signer_remove` refused to drop below `signer_thr`. That would make the last signer key unremovable — precisely the key you must remove when it is stolen (A3). Invariant deleted for signers, kept for roots.
  - Three tests failed on first green and **the tests were wrong, not the code**: the fixture deliberately re-enrols `pi-cam` after revoking it (device-id reuse), and an isolation test assumed rejected entries could simply be dropped — they cannot, because `after` is position-dependent, so dropping entries shifts indices and legitimately invalidates later ones. Rewritten to assert the attempted effects are absent.
- **2026-09-19 · 0.5 trust file, fingerprint, receipts** — `note.py` (c2sp signed-note: key-id derivation, verifier-key strings, sign/split/verify, receipt body) and `trust.py` (build/validate/encode, origin derivation, Crockford fingerprint, deterministic TOML). 62 Python tests green. Vectors now 101 files: `trust.cbor`/`trust.toml`/`trust.fingerprint`, `receipt.note`. Regeneration changed exactly `keys.json` (3 witness keys added), the two `policy` entries (D-030, real tlog-policy text) and `state.json`; every other entry byte unchanged.
  - **Security finding → D-029**: the spec's fingerprint was 32 bits (and self-contradictory), which an attacker substituting a trust file could grind in minutes. Now 80 bits, Crockford base32, no wordlist to freeze.
  - **Bug caught by a test**: verifier-key parsing split on every `+`, but standard base64 key data contains `+`. Go's note package splits at most twice; mine now does too, with a regression test that searches for a key whose base64 actually contains a `+`.
  - **Carried to Phase 2**: these note encodings are so far only self-consistent. Phase 2 must cross-check them against Go's `note` package and torchwood — that is the real verification, and it is now a gate line.

### Decision resolved — 0.6 was approved and run (2026-09-19)

0.6 requires giving a **fresh model** only `SPEC.md` + `testdata/vectors/` and
having it implement an entry verifier that passes every vector. That means
spawning a subagent, which I do not do without an explicit go-ahead.

Why it matters *now* rather than later: I wrote the spec **and** the Python
reference, and I am about to write the Go implementation from the same spec.
All three share my blind spots. A genuinely cold reader is the only thing that
proves the spec is self-sufficient — and a spec gap is far cheaper to fix before
the Go code exists than after.

| Option | Consequence |
|---|---|
| **Run it now** (recommended) | One subagent run; spec gaps found before Phase 1 |
| Defer to Phase 6 | Plan already has a cold-model gate on the frozen spec; Phase 1 will surface *some* gaps, but only the ones I happen not to share |
| Skip entirely | `SPEC.md` never independently validated; the "second implementation" claim in `PUBLICATION.md` §7 weakens |

Loop paused here pending that answer.
- **2026-09-19 · 0.6 cold-model gate — FAILED.** An independent agent got `SPEC.md` + `testdata/vectors/` and nothing else (isolated copy; verified `SPEC.md` contains no reference to the Python reference, and the agent was barred from `~/norn`). It wrote ~2,100 lines of Go, stdlib only, including its own CBOR codec, and passed **227/227** checks — Stage 1 entries 162/162, Stage 2 replay 45/45 with `state.json` byte-identical, Stage 3 notes 20/20. Verdict nonetheless **SPEC INSUFFICIENT**, because several answers were reverse-engineered from the vectors rather than read from the prose.
  - **The gate is NOT passed.** Passing 227 checks is not the bar; the bar is that a second implementer could not have gotten it wrong. They could.
  - 29 defects recorded in `SPEC-DEFECTS.md`. Every Tier-1/Tier-2 item was spot-checked against the real files before being accepted — all confirmed. Sharpest three: §5's state sketch names fields that do not exist (`policy_text`, `valid_until`) and omits three that do (`name`, `net`, `size`), while §5 demands byte-identical state JSON; §12 says "keys sorted" in a document that spends two paragraphs establishing the *opposite* order for CBOR, and following §4.1 there breaks 16/16 entry mirrors; `dup-entry` and `unknown-type` are missing from §5's numbered procedure and their position decides vector 13's reason code.
  - Eleven Tier-3 items are undecided by the prose **and** by the vectors — two honest implementations can diverge on all of them and both pass clean, which is the exact failure a conformance suite exists to prevent.
  - Confirmed sound: §4.0/§4.1/§4.2 and §5.1's signature-counting paragraph. Stage 1 passed 162/162 on the first run with no reference to any vector.
  - Next: 0.7 repairs the spec, then 0.8 re-runs the gate with a *fresh* agent on a *new* isolated copy. The Go core library (Phase 1) waits until the spec it would be built from is sound.
- **2026-09-19 · 0.7a Tier-1 spec repair** — §5 rewritten: replay now states its `(anchor, entries) → state` signature and where the anchor comes from; entry 0 gets its own 8-step procedure including the previously-unstated **genesis bootstrap** (signatures counted against `body.roots`/`body.root_thr`, since there is no earlier state) and abort semantics; entries 1…n get a complete numbered list with `dup-entry` and `unknown-type` in their load-bearing positions, plus a per-type table fixing each rule's internal check order. New **§5.3 canonical state schema** — a normative field table, replacing the sketch that named two fields which do not exist and omitted three that do. §12 now pins canonical JSON key order to **UTF-8 code point** and says explicitly that it is *not* the CBOR order of §4.1, with the worked contrast; documents that schema fields are always emitted; and describes `log/manifest.json` and `bad-genesis/` instead of tiles that do not exist there.
  - **Security decision → D-031** (was open question D15): entry hashes enter the `dup-entry` seen-set **before** validation, so a rejected entry cannot be re-inserted later against a changed state. The concrete attack this closes: re-inserting the original `enroll` of a revoked device to resurrect it — `after` bounds reordering but not re-insertion further along the log. Reference implementation changed to match, with three tests including the resurrection attempt.
  - Also closed while rewriting the procedure, because it had to say something: D13 (genesis bootstrap), D14 (malformed entry 0), D16 (`log_key` appends), D17 (re-enrolment replaces the record), D26 (`size`). D21's *order* is now normative; its vectors are owed in 0.7c.
  - 65 Python tests green. Vector regeneration produced **zero** changes — the rule change altered no existing outcome and the rest was documentation.
