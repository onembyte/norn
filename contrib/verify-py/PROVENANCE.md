# `contrib/verify-py` — provenance

An independent verifier for the protocol `SPEC.md` describes, in Python using
the standard library only, built **cold**: by a model that never saw this
implementation, the reference, the build log or any other file of this
repository — only `SPEC.md` and the vector suite. It is kept **exactly as
written**. Nobody here edits it; `internal/docclaims`'s
`TestTheIndependentVerifierIsKeptAsWritten` fails on any byte that differs
from the table below. If it ever disagrees with the suite, that is a finding
about `SPEC.md`, the vectors or the verifier, and it is recorded in
`BUILD-LOG.md`, not patched here.

`make verify-py` runs it (and `make ci` runs that): it copies this directory
and `testdata/vectors/` into a temporary directory in the sealed layout the
verifier was written for (`vectors/` beside `work/verify-py/`), runs
`harness.py`, and prints its last line. The harness runs the RFC 8032,
RFC 6962 and BIP-350 self-tests first, then one check per vector case and one
per file named in `SHA256SUMS`, and exits non-zero on any failure, any
exception, any `cases.json` it does not run, or any protocol file it never
read.

## How it was built

- **Builder:** a Codex lane, `gpt-6.1-sol`, reasoning effort high
  (`HARDENING-PLAN.md` H14, rule 12). A model family other than the one that
  wrote Norn is the more independent reader.
- **Seal:** a directory holding exactly `SPEC.md`, `vectors/` (a copy of
  `testdata/vectors/` with every digest in `SHA256SUMS` verified) and an empty
  `work/`, extracted with `git archive` from
  `89b5b999fd661c738f712aaa5bd842c81daa2d95` at 2026-10-09 01:33:54, with a
  check that no file in it names a path back into the repository. The
  directory was not a git repository.
- **Sandbox:** `codex exec -s workspace-write`, writable only in the sealed
  directory and the lane's report directory; no network.
- **A first run stopped, correctly.** Its brief said to stop at a primitive
  `SPEC.md` does not describe, and `SPEC.md` defers three algorithms to their
  standards without restating them: Ed25519 verification (RFC 8032), the
  RFC 6962 inclusion and consistency proof verifiers, and bech32m (BIP-350).
  Those are not Norn's rules, so the second brief, below, let the builder
  implement them from its own knowledge of the published standards, each
  checked against that standard's own test vectors, with Norn's rules still
  from `SPEC.md` alone.
- **Duration:** about fourteen minutes of the lane's run (01:33–01:47).

## The audit

The lane's complete log (14,641 lines) was searched before anything it wrote
was used. Every command it ran had the sealed directory as its working
directory; the only absolute paths it names are the sealed directory, its
report directory, and the repository path once, inside the brief's own
prohibition; nothing it ran imports `socket`, `urllib` or `http.client`, or
calls `curl`, `wget`, `pip` or `git clone`. It read `SPEC.md`,
`vectors/README.md` and the vectors, and wrote only under `work/` and its
report directory.

## Results

| When | Vectors | Checks | Failures |
|---|---|---|---|
| In the seal, 2026-10-09 01:47 | `89b5b99` | 1452 | 0 |
| At integration, 2026-10-09 | `c14ba84` | 1474 | 0 |

Of each total, one check per file in `SHA256SUMS` (711 at the seal) is a
digest check; the rest are protocol checks. The second row includes vectors
added after the seal — three `log/` entries and two `genesis/` aborts that
give a uint field the boolean `true` (SEC-016) — which this verifier refuses
because it reads a uint as an integer that is not a boolean.

**Controls at integration**, each on a scratch copy and restored: Ed25519
accepting every signature fails the RFC 8032 self-test and stops the run;
with that self-test also skipped, 18 vector checks fail (forged and missing
signatures in `log/`, `checkpoints-bad/`, `proven/`, `requests-bad/`,
`served/`, and `state.json`); a boolean accepted as a uint fails 14, the five
SEC-016 vectors among them. Comparing the trust file's `origin` with its
derived value case-insensitively fails nothing, because this verifier checks
the log key's note name against the *derived* origin rather than the file's
`origin` field, and that check refuses `trust-bad/45` on its own.

**Not kept:** the run's outputs — `harness.log` (the seal-time run,
SHA-256 `cef835fdee4a3c877c4ab64b39136ccbf389de560bf5d2a795faddf521cfccb6`,
last line `1452 checks; 0 FAIL`), `state.actual.json` and three `cli-*.json`
smoke outputs. `make verify-py` regenerates them in its temporary directory.

## What it found

`NOTES.md` is the builder's own list of interpretations, as valuable as the
code. One more, seen at integration: its Ed25519 check is RFC 8032 §5.1.7's
**cofactored** equation (`[8][S]B = [8]R + [8][k]A`), where Go's
`crypto/ed25519`, which this implementation uses, is cofactorless. The two
agree on every honest signature and disagree only on crafted inputs with
small-order components, which no vector holds; `SPEC.md` §3 does not say
which is required. That is D-072 c, open: a cold reader of the standard chose
differently from this implementation, and the suite cannot tell them apart.

## Files

| File | SHA-256 |
|---|---|
| `protocol.py` | `2770c329d1540665c543ed645f465797faffcb6431a220012f343a233b478ec0` |
| `harness.py` | `19d0c03bd737eaf9c30bae73faefc2f53a98e8f9de767da7f380835f92081322` |
| `verify.py` | `ab41f759a3f54d685697983ef07e8775eb8d787de69501832c12d6326d900707` |
| `cbor.py` | `46db2d7a10c8abdecc8fccb24aedbe309668018f1cd06167282cd14a7992c3e0` |
| `ed25519.py` | `eb2b1d37ebe1ef12d63db3d86db84a0a0fd36d795cf67674eb1eda0fe7503adc` |
| `merkle.py` | `820fd219bb84594bfe4a636cd1cc5f27acf8657f895bc9e8b802dacd442ef241` |
| `bech32m.py` | `1d0f76029e66b632193f84080ff258efc6589d0768bbf9ed9834febce644926f` |
| `README.md` | `71685f9f2abd0fc08acf46febd5233158ba5240feb77b3650067adfa54d844ce` |
| `NOTES.md` | `b3bb60da73744688bb74865e97f75abc66126ca1e44d6abb773c9c1b1673ed1d` |

## The brief, verbatim

~~~~text
Lane T, second run. Model: gpt-6.1-sol, reasoning high. One task, in a sealed directory. Output directory: /Users/francomichetti/norn-lanes/out/t (write t-h14.commit.txt there when done).

**Where you are.** Your working directory holds exactly three things: `SPEC.md`, `vectors/` (a copy of a test-vector suite, with `SHA256SUMS` and its own `README.md`), and an empty `work/`. That is all you may read. **You must never read, list, search or otherwise touch `/Users/francomichetti/norn` or any other copy of this project**, and you must not search the web or fetch anything from the network for it; you have no network in any case. Everything you need is in `SPEC.md` and `vectors/`. Your transcript is audited afterwards for any path outside this directory and for any network use; either voids the work.

**The standards `SPEC.md` cites but does not restate.** A first run stopped, correctly under the brief it had, because `SPEC.md` defers three algorithms to public standards: Ed25519 verification (RFC 8032), the RFC 6962 inclusion and consistency proof verifiers (with the node ordering they expect), and bech32m (BIP-350). Those are not Norn's rules; they are published standards any implementer has on the desk, and this task is about whether Norn's *own* rules can be implemented from `SPEC.md`. So implement each from your own knowledge of that standard, in pure Python, each in its own module whose header names the standard and the section it follows (for Ed25519, RFC 8032 §5.1.7's verification, including its checks on `A`, `R` and `S`; for the proofs, RFC 6962 §2.1.1 and §2.1.2, or RFC 9162 §2.1.3.2 and §2.1.4.2, which give the same algorithms as procedures). Check each against the standard's own published test vectors that you know (RFC 8032 §7.1; BIP-350's valid and invalid bech32m strings; a few hand-built trees for the proofs) in a self-test the harness runs first. Wherever `SPEC.md` says something about these primitives — a length, a canonical-encoding rule, which key a signature is checked under, which proof a bundle carries — `SPEC.md` decides; the standard only supplies the algorithm. Record in `NOTES.md` which standards you implemented from memory and which test vectors check them, so the reviewer can compare them against the documents.

**The task.** Build, in `work/verify-py/`, an independent verifier for the protocol `SPEC.md` describes, in Python 3 using the standard library only (`hashlib`, `base64`, `json`, `struct`, …; no `pip`, no third-party module — if a primitive is not in the standard library, implement it yourself in pure Python). It must, from the specification alone:

1. decode the entry encoding profile and reject what the profile forbids;
2. replay a log to its canonical state and reproduce `vectors/state.json` byte for byte, and every `genesis/*/state.json` and `genesis-good/*/state.json`;
3. verify a served log — the checkpoint note and its signatures, the witness cosignatures under the trust file's policy, the tiles and entry bundles against the signed root — reporting the closed refusal codes the spec names, so that every case under `checkpoints-bad/`, `served-bad/`, `proofs/`, `proofs-bad/`, `receipt-bad/`, `fork/`, `detect/`, `trust-bad/`, `trust-good/`, `requests/`, `requests-bad/`, `policies/`, `entries-hostile/` and `proven/` is answered as its `cases.json` says;
4. come with `work/verify-py/harness.py`, which runs every vector in `vectors/`, prints one line per case (path, expected, got, PASS/FAIL), and exits non-zero on any FAIL or any case it does not know how to run; and `work/verify-py/README.md` saying how to run it and what it covers.

Work from the spec; where the spec is ambiguous, say so in `work/verify-py/NOTES.md` with the section, what you chose and why — that list is as valuable as the code. Do not look at `vectors/` files to infer rules the spec does not state; use them only to check your reading. Keep going until the harness passes every case or you can say exactly which cases it cannot pass and which sentence of the spec is the reason.

When done, write `t-h14.commit.txt` to the output directory: what passes, what does not, the ambiguities you recorded, and the last line `Codex-Model: gpt-6.1-sol/high`. Do not edit `SPEC.md` or anything under `vectors/`.
~~~~
