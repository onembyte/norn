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

This is the **fourth** cold build (row 6.5l-xii-f). The first, sealed at
`89b5b99` on 2026-10-09, fell behind version-2 fork evidence, NORN-ED25519-v1
and the signed-note profile, and was replaced by the second (row 6.7-r), sealed
at `6ef1a16` on 2026-10-11, which stopped when D-077 gave §5's replay anchor two
text members. The third (row 6.5l-xii-d), sealed at `d4374b8` on 2026-10-12,
passed every check at its seal and stopped later that day on
`served-empty-entry/`: its harness took every `served-*` directory but three for
a checkpoint served over another log, a rule `SPEC.md` never stated. This build
was sealed after D-077 was complete and the third build's readings were triaged
and fixed (6.5l-xi-c, 6.5l-xii-e), and it passed every check at its seal.

`make verify-py` runs it (and `make ci` runs that): it copies this directory
and `testdata/vectors/` into a temporary directory in the sealed layout the
verifier was written for (`vectors/` beside `work/verify-py/`), runs
`harness.py`, and compares the lines it fails with
`contrib/verify-py.known-failures` — empty at this build's seal. A vector added
after the seal that this build cannot answer is recorded there, one line each,
as a debt the next cold build clears; the verifier is never edited to clear
one. The harness runs the RFC 8032, RFC 6962 and BIP-350 self-tests first,
then one check per vector case and per file named in `SHA256SUMS`, and reports
any manifest it does not know how to run as a failing check. It ends with
`TOTAL <n> PASS <p> FAIL <m>`, even after an unhandled exception, which it
records as a failing check, and exits non-zero on any failure.

## How it was built

- **Builder:** a Codex lane, `gpt-6.1-sol`, reasoning effort high (lane BJ,
  `HARDENING-PLAN.md` H15 again, rule 12). A model family other than the one
  that wrote Norn is the more independent reader.
- **Seal:** a directory holding exactly `SPEC.md`, `vectors/` (a copy of
  `testdata/vectors/` with every digest in `SHA256SUMS` verified) and an empty
  `work/`, extracted with `git archive` from
  `d011a947ddb42dbbf2653127d3a0d2ea63450f7e` at 2026-10-12 09:36:32, with a
  check that no file in it names a path back into the repository. The
  directory was not a git repository.
- **Sandbox:** `codex exec -s workspace-write`, writable only in the sealed
  directory and the lane's report directory; no network.
- **The brief:** the third build's, with the output names changed, `log-edges/`
  and `proven/grant-labels.json` added to what it must answer, and a paragraph
  naming what had changed since the third seal (the grant grammar, the
  cosignature timestamp bound, the whole-note signed-note grammar, the
  four-member anchors, §10's outline, the new directories). It said why the
  third build stopped, and told the builder to read each directory's shape from
  its `cases.json` and `SPEC.md` §12 rather than from its name. It carries the
  prohibition on the project's paths and on any network use verbatim.
- **Two sessions.** The first stopped at 09:46 on a service error ("Selected
  model is at capacity"), after writing five modules. Before resuming, `SPEC.md`
  and every vector digest were checked unchanged and nothing outside `work/` was
  found. A continuation in the same sealed directory, with the full brief and a
  paragraph saying the earlier files were its own work, finished at 10:00.

## The audit

Both sessions' logs (4,874 and 23,756 lines) were searched before anything the
build wrote was used. All 40 commands it ran (8 and 32) ran inside the sealed
directory. The only absolute paths into the project they name are the two in
the brief's own prohibition, once per session. It made no network call: the only
URLs in the logs are inside vector files it printed, and its code imports no
networking module. Its `NOTES.md` says it did not read a shared rules file a
general instruction pointed it to, because the sealed-read restriction took
precedence, and that it corrected a mistranscribed RFC 8032 TEST 3 signature
in its own self-test by checking the RFC's seed with deterministic signing.

## Results

| When | Vectors | Checks | Failures |
|---|---|---|---|
| In the seal, 2026-10-12 10:00 | `d011a94` | 3184 | 0 |
| At integration, 2026-10-12 | the same | 3184 | 0 |

Every canonical state the suite carries is reproduced byte for byte, every
manifest is handled, all 914 CCTV cases get their stated outcome, every
`served-*` directory is read in the shape its own manifest gives, and the CLI
replay writes a state identical to `vectors/state.json`. OpenTimestamps proofs
are checked for their stated digests and integrity only; their validity is
outside the verifier's contract (`SPEC.md` §12.1), and the build says so.

**Controls at integration**, each on a scratch copy of the sealed layout:
Ed25519 accepting every signature, accepting points of small order, or
reducing `S` modulo `L` each fails the RFC 8032 self-test, which stops the
harness before any vector. With the self-test skipped, the vectors alone still
catch the last two: 165 checks for the cofactored reader (`ed25519-cctv/`,
`log-admission/`, `genesis/`, `requests-bad/`), and 2 for `S` mod `L`
(`requests-bad/S-plus-L-signature`, `checkpoints-bad/31-cosignature-S-plus-L`).
Skipping the `prev` guard fails 23 checks in `log-cas/`; skipping the policy
entry's log/witness invariant fails 10; allowing control bytes fails
`checkpoints-bad/43` and `44`; skipping the signature-name rule fails `39`, `41`
and `42`; dropping the timestamp bound fails `38`; trimming a grant with the
whitespace class instead of U+0020 fails 8 cases of `proven/grant-labels.json`.
The `prev` mutation made in place turns `make verify-py` red; the file was
restored byte for byte.

**Its six readings.** `NOTES.md` records six places where the builder chose how
to read `SPEC.md`: §10.1's paragraph on the head and the fork still describes
§10's outline as fetching after the fork block, which 6.5l-xii-e-b changed;
§5.3's closing phrase on `quorum none` against its earlier explanation;
§8.1's portable bundles against replay; served fixture shapes taken from their
manifests; the OpenTimestamps boundary; and §14's key order. They are findings
about the document, recorded in `BUILD-LOG.md` as a row, not about this
verifier.

**Not kept:** the run's outputs — `harness-results.txt` (the seal-time run,
SHA-256 `3b0a18ca7a1d3671f786d7a8bd1979d5171f871020258b693ca8ca9df331b722`) —
which any run of `make verify-py` reproduces.

## Files, as written

| File | SHA-256 |
|---|---|
| `bech32m.py` | `c51c1317c701011aff787442c94d1246b1d3059c45977328a854c591604b631b` |
| `cbor.py` | `e7a64c7f1500016758a904480a5492b6e16103ecf985232f77a1198b197fb011` |
| `ed25519.py` | `5118425f1ed3e2dadc922b5cace9161284225eb2f5be572853624075b6873877` |
| `harness.py` | `04956e1cded312f871ce6d196160065412f96ea442f184d0fd6d93e6635f9575` |
| `merkle.py` | `9e4d4cfb0944858f8d008f399f9b57286b2604865aac348020ff61ba4032510b` |
| `NOTES.md` | `56968973ba8906c3232a450f1d06f1ccdaeeb469b53754ceedf2cea5c33301b7` |
| `protocol.py` | `c788aff4a35846329246f9d63da30f46fd8847d4c8fa4611a007b95e5bf40e62` |
| `README.md` | `a40ff5de364f8c0c4a72d2a234eae24d70f2cc6b360f85b91689724dc70d3483` |
| `verify.py` | `b2514f8cce293d1f793c676b408c4af1a4522c11dd15de82037f4cc7034db67a` |
