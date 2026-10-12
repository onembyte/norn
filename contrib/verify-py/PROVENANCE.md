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

This is the **third** cold build (row 6.5l-xii-d). The first, sealed at
`89b5b99` on 2026-10-09, fell behind version-2 fork evidence, NORN-ED25519-v1
and the signed-note profile, and was replaced by the second (row 6.7-r), sealed
at `6ef1a16` on 2026-10-11. The second passed every check at its seal, owed two
lines to D-076's decimal bound the same day, and stopped altogether at
6.5l-xii-b, when D-077 gave §5's replay anchor two text members its harness
could not read. This build was sealed after D-077 was implemented and its
review done, and it passed every check at its seal.

`make verify-py` runs it (and `make ci` runs that): it copies this directory
and `testdata/vectors/` into a temporary directory in the sealed layout the
verifier was written for (`vectors/` beside `work/verify-py/`), runs
`harness.py`, and compares the lines it fails with
`contrib/verify-py.known-failures` — empty at this build's seal. A vector added
after the seal that this build cannot answer is recorded there, one line each,
as a debt the next cold build clears; the verifier is never edited to clear
one. The harness runs the RFC 8032, RFC 6962 and BIP-350 self-tests first,
then one check per vector case and per file named in `SHA256SUMS`, and exits
non-zero on any failure, any case it does not know how to run, or any protocol
file it never read; it ends with `TOTAL <n> checks; <m> FAIL`.

## How it was built

- **Builder:** a Codex lane, `gpt-6.1-sol`, reasoning effort high (lane BC,
  `HARDENING-PLAN.md` H15 again, rule 12). A model family other than the one
  that wrote Norn is the more independent reader.
- **Seal:** a directory holding exactly `SPEC.md`, `vectors/` (a copy of
  `testdata/vectors/` with every digest in `SHA256SUMS` verified) and an empty
  `work/`, extracted with `git archive` from
  `d4374b8696fd561c3e91955e28eb00c33cac5ca3` at 2026-10-12 03:22:18, with a
  check that no file in it names a path back into the repository. `SPEC.md` and
  the vectors there are identical to `f9024bf`'s, the head after 6.5l-xii-c; the
  commits between changed documents only. The directory was not a git
  repository. (A first launch at 00:37 was refused by the Codex usage limit
  before doing anything.)
- **Sandbox:** `codex exec -s workspace-write`, writable only in the sealed
  directory and the lane's report directory; no network.
- **The brief:** the second build's, with the output names changed, `log-cas/`
  added to the directories it must answer, and a paragraph naming what had
  changed since the second build's seal (§11.1's proof order, policy line
  endings and decimal bounds, and D-077's `prev`, versions, four-member anchor
  and log/witness disjointness). It carries the prohibition on the project's
  paths and on any network use verbatim, and the instruction to implement the
  standards `SPEC.md` defers to from the builder's own knowledge, each checked
  against that standard's published test vectors.
- **Duration:** about twenty minutes (03:22–03:42).

## The audit

The lane's complete log (8,538 lines) was searched before anything it wrote
was used. All 26 commands it ran ran inside the sealed directory. The only
absolute paths into the project it names are the two in the brief's own
prohibition, once each. It made no network call: the only `fetch` in the log
is the verifier's own function that reads a tile from the served directory.
Its `NOTES.md` says it did not read a shared rules file a general instruction
pointed it to, because the brief's sealed-read restriction came later and
took precedence — the behaviour wanted.

## Results

| When | Vectors | Checks | Failures |
|---|---|---|---|
| In the seal, 2026-10-12 03:42 | `d4374b8` (= `f9024bf`'s) | 3001 | 0 |
| At integration, 2026-10-12 | the same | 3001 | 0 |

Every canonical state the suite carries is reproduced byte for byte — the main
log's, `log-empty/`, `log-admission/`, `log-cas/`, every aborted genesis and
the accepted one — all 914 CCTV cases get their stated outcome, both
fork-evidence versions are read, and the CLI replay independently writes a
state identical to `vectors/state.json`. OpenTimestamps proofs are checked for
presence, digest range and integrity only; their validity is outside the
verifier's contract (`SPEC.md` §12.1), and the build says so.

**Controls at integration**, each on a scratch copy of the sealed layout:
Ed25519 accepting every signature fails the RFC 8032 self-test and stops the
harness; dropping the prime-order check — a cofactored reader — fails 164
checks (`log-admission/`, the CCTV cases, `genesis/`); reducing `S` modulo `L`
instead of refusing it fails the self-test, and with the self-test skipped the
vectors alone still catch it (`requests-bad/S-plus-L-signature`,
`checkpoints-bad/31-cosignature-S-plus-L`); skipping the `prev` guard fails 23
checks (`log-cas/`'s stale stories and presence cases, and the states after
them); skipping the policy entry's log/witness invariant fails 10. The same
`prev` mutation made in place turns `make verify-py` red; the file was restored
byte for byte.

**Its six readings.** `NOTES.md` records six places where the builder chose how
to read `SPEC.md` or drew a boundary: §5 calls the anchor "the pair" while its
table lists four members; §10's outline against §10.1's explicit order; §8.1's
portable bundles against replay as the source of the current key; §4.0's grant
spelling not fully settled by a shipped case; the cosignature timestamp kept as
an unsigned 64-bit field; and the OpenTimestamps boundary. They are findings
about the document, recorded in `BUILD-LOG.md` as a row, not about this
verifier.

**Not kept:** the run's outputs — `results.txt` (the seal-time run, SHA-256
`6d78d2e6acfadda0140a00b96b76e6d1ddcff36a86d56c4df3712a8935123844`) and
`replayed-state.json` (the CLI's replay) — which any run of `make verify-py`
reproduces.

## After the seal

Row 6.5l-xi-c-iii (2026-10-12) added four `served-*` directories. This build's
harness reads every `served-*` directory other than `served-bad/`,
`served-genesis/` and `served-large/` as a checkpoint served over another log
named by `serve_over`. Two of the new ones are complete logs with no such key
(`served-empty-entry/`, `served-rotated-earlier/`), and `served-large-bad/`
replaces tiles rather than the checkpoint. The harness stops at the first,
with `KeyError: 'serve_over'`, before it prints its total.

A stop is not a failed check, so `contrib/verify-py.known-failures` cannot
record it, and `make verify-py` fails with "the harness did not finish" until
the next cold build replaces this one. The directories keep their names and
shapes. `SPEC.md` defines `serve_over` for `served-bad/` alone and states no
rule by name, so the harness's rule is this builder's inference, and bending
the suite to fit it would hide what the next build must handle. The fourth
cold build is row 6.5l-xii-f, sealed after D-077's note rules (6.5l-xi-c-iv-b)
land.

## Files, as written

| File | SHA-256 |
|---|---|
| `bech32m.py` | `e29adac3a818985110eb1c90b952f099b677d510c1fa5a94948f621ffd04de72` |
| `cbor.py` | `4b631e8fe77949a18a86b66c34c6772ba154792dd817c1b1aa4fe3c51de72fb6` |
| `ed25519.py` | `129e2ac772f3df95f1ec5c0465f2fbe252d366a25b831c9620f211f11342ea13` |
| `harness.py` | `dbc7856afdc3dea3b5657ba354b78ee6e6664e5a4aee4869a1af940438ea9366` |
| `merkle.py` | `7fcb6fb0b5eb90f9a149c6db92b339d30cc26efbc150376b8d00aa859834afdc` |
| `NOTES.md` | `4e0d73d1d2e3691030403e7149f852dc59f1a63d450d75d145127e2c31b9fe55` |
| `README.md` | `56a561b2c46cb8689c99922e51ea56509bffc463acc2de08f62ce1e960778cad` |
| `verifier.py` | `77cfea37123e68685f7909138dabeec292d6755fe5bb2650d1bb70a29100d825` |
| `verify.py` | `9e39a2aa6f79add598529ebc259ae0a7b314d5ff007628c44f7a05d093eb83e3` |
