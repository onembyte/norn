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
| 0.6 | Cold-model gate | a fresh model given only `SPEC.md` + `testdata/vectors/` implements an entry verifier that passes all vectors (needs a subagent — confirm with user at this point) | ⬜ |

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
