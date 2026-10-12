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

This is the **second** cold build (row 6.7-r). The first, sealed at
`89b5b99` on 2026-10-09, predated version-2 fork evidence, NORN-ED25519-v1,
the signed-note profile, the key-name grammar, the CBOR allow-list, the
`genesis` code and §3.1's admission points; by 6.5m-sec-023r-g it failed 25
checks for those reasons alone, each recorded in a known-failures list that
`make verify-py` compared against. This build passed every check at its
seal, so the list emptied and was deleted — and came back two lines long the
same day, when D-076 bounded every decimal line in a note after the seal
(`contrib/verify-py.known-failures`): `make verify-py` passes only when the
harness fails exactly the lines recorded there, and the list goes again with
the next cold build.

**Since 6.5l-xii-b (D-077), this build no longer completes.** Its harness
hex-decodes every member of a manifest's `anchor`, and §5's replay anchor
gained two text members, the trust file's `log_key` and `policy`; it stops at
the first replay manifest with one line, `harness/fatal`, and never reaches its
tally. `make verify-py` is therefore red, and the two-line list is suspended
rather than owed, until the third cold build (6.5l-xii-d) replaces this one.
Nothing here was changed to make it run: an independent verifier that predates
a protocol change is supposed to stop on it.

`make verify-py` runs it (and `make ci` runs that): it copies this directory
and `testdata/vectors/` into a temporary directory in the sealed layout the
verifier was written for (`vectors/` beside `work/verify-py/`), runs
`harness.py`, and prints its last line. The harness runs the RFC 8032,
RFC 6962 and BIP-350 self-tests first, then one check per vector case and one
per file named in `SHA256SUMS`, and exits non-zero on any failure, any
exception, any `cases.json` or `manifest.json` it does not run, or any
protocol file it never read.

## How it was built

- **Builder:** a Codex lane, `gpt-6.1-sol`, reasoning effort high (lane AX,
  `HARDENING-PLAN.md` H14 again, rule 12). A model family other than the one
  that wrote Norn is the more independent reader.
- **Seal:** a directory holding exactly `SPEC.md`, `vectors/` (a copy of
  `testdata/vectors/` with every digest in `SHA256SUMS` verified) and an empty
  `work/`, extracted with `git archive` from
  `6ef1a16c0b85b02b0681ef71e4f15ad11933d123` at 2026-10-11 13:16:50, with a
  check that no file in it names a path back into the repository. The
  directory was not a git repository.
- **Sandbox:** `codex exec -s workspace-write`, writable only in the sealed
  directory and the lane's report directory; no network.
- **The brief:** the first build's second-run brief, brought up to date — both
  of the project's paths named as never to be touched, every vector directory
  added since listed, and a note that the protocol had moved since the first
  build. The standards `SPEC.md` defers to (RFC 8032 as profiled by §3.1,
  RFC 6962 proofs, BIP-350 bech32m) implemented from the builder's own
  knowledge of them, each checked against that standard's published vectors;
  Norn's own rules from `SPEC.md` alone.
- **Duration:** about fourteen minutes (13:16–13:30).

## The audit

The lane's complete log (6,593 lines) was searched before anything it wrote
was used. The only absolute paths into the project it names are the two in
the brief's own prohibition, once each; it makes no network call — nothing
it ran calls `curl` or `wget`, imports `urllib` or `http.client`, or searches
the web. It read `SPEC.md`, `vectors/README.md` and the vectors, and wrote
only under `work/` and its report directory.

## Results

| When | Vectors | Checks | Failures |
|---|---|---|---|
| In the seal, 2026-10-11 13:30 | `6ef1a16` | 1817 | 0 |
| At integration, 2026-10-11 | `4f65ce7` | 1817 | 0 |
| After D-076, 2026-10-11 | `fc4e141` + 6.7-r-f-d | 1821 | 2, recorded (the two decimal-bound vectors) |
| After D-077, 2026-10-11 | 6.5l-xii-b | — | does not complete: `harness/fatal` at the first four-member anchor |

Every canonical state the suite carries is reproduced byte for byte (28: the
main log's, `log-empty/`, `log-admission/`, 24 aborted geneses and the
accepted one); all 914 CCTV cases get their stated outcome; both fork-evidence
versions are read.

**Controls at integration**, each on a scratch copy, the build itself checked
byte-identical afterwards: Ed25519 accepting every signature fails the RFC 8032
self-test and 11 vector checks (`checkpoints-bad/`, `log/`, `state.json`,
`requests-bad/`); dropping the prime-order check — what a cofactored reader
does — fails 154 CCTV cases, six `log-admission/` checks and three `genesis/`
aborts; reducing `S` modulo `L` instead of refusing it fails the self-test, and
with the self-test also skipped the vectors alone still catch it
(`requests-bad/` and `checkpoints-bad/31`).

**Its seven readings.** `NOTES.md` records seven places where the builder had
to choose how to read `SPEC.md` — among them §11.1's prose and its code table
ordering `consistent` and the version-2 `proof` checks differently, and §12
still saying no layer outside replay has closed codes. They are findings about
the document, not about this verifier, and `BUILD-LOG.md` carries them as a
row.

**Not kept:** the run's outputs — `results.txt` (the seal-time run,
SHA-256 `269cb653207fd91e0624b04a1365f58602c0a839d7b35c3768df087ee8fb6a5b`),
`errors.txt` (empty) and `reproduced/` (the states it computed) — which any
run of `make verify-py` reproduces.

## Files, as written

| File | SHA-256 |
|---|---|
| `bech32m.py` | `3ac09400bae442b6f16819300577c8ef2a363512bd5109ab0f1d34e671bf6301` |
| `cbor.py` | `ec7d77d5d4175c9b8ab6c61c0d0888ae1922ca0fef0828ac87d6dcc6a3af7281` |
| `ed25519.py` | `2d46fdfbe3eb635affbc83d81caa4dc55a31a95a74b79505e275363785e94fb3` |
| `harness.py` | `d283ca4bf90c8936506da4f4009270823d2b55b38bb9ef196b04e3b6e15432ff` |
| `merkle.py` | `49aa29bd076d66287d686c26ab92b94c79ce13c97003d9558a8afc951116c51b` |
| `NOTES.md` | `22b1854b64041b1456344cc94e51394609c474cda0c92656f39daecec3a7847f` |
| `protocol.py` | `03d98d575ae3e104fce08a2f4fe19f43d258d957ba3f913d28121dcfca47116d` |
| `README.md` | `cf982e5ea2c53d8a52579ad7fa3fda7454259e49b87f3e0a3699bab9db6cbbed` |
| `verify.py` | `78a267c1d678dc62f572cad0ab6e137323f41e7be96f781edc2091b46a4ba543` |
