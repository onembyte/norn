# Independent sealed Norn verifier

Python 3.11 or later, standard library only. No installation or network access.
`tomllib` is used only for the harness's human trust-file rendering check.

From the sealed directory:

```sh
python3 work/verify-py/harness.py
```

The harness first runs the three primitive self-tests, then verifies every
`SHA256SUMS` entry and executes all declared cases. Each check prints its path,
expected result, actual result and PASS/FAIL. It exits nonzero on a mismatch,
unknown case declaration, uncovered data artifact or unhandled error. Large
values are displayed as hashes; comparisons use the complete original values.
The captured successful run is `results.txt`: 3,001 checks, zero failures.

Coverage includes deterministic CBOR and resource boundaries; all replay
fixtures and canonical states; entry/request mirrors and hashes; trust files,
TOML round-trip and fingerprint; policy parsing/evaluation; request text and
signatures; checkpoint notes, log signatures, cosignatures and quorum times;
entry bundles, reconstructed heads and all implied hash tiles; inclusion
bundles, receipt bindings/deadlines, both reader states after rotations;
version-1/version-2 fork evidence and every carried consistency proof;
stored-head fork/rollback decisions, witness-time freshness, expiry, grants
and installed keys; all 914 CCTV signatures. Auxiliary tiles on refused
branches are checked separately without changing refusal precedence.

OpenTimestamps is advisory: the harness checks the checkpoint's stamped byte
range/digest and every OTS file's suite checksum, and reports the unrelated
sample/calendar files as present but unvalidated. It does not parse OTS or
claim to validate an external timestamp. See `NOTES.md` for specification
choices and boundaries.

The offline command-line verifier is also available:

```sh
python3 work/verify-py/verify.py served vectors/served
python3 work/verify-py/verify.py bundle vectors/proofs/nas.bundle
python3 work/verify-py/verify.py evidence vectors/fork/evidence.cbor
python3 work/verify-py/verify.py request vectors/requests/req-minimal.txt --text
python3 work/verify-py/verify.py receipt vectors/receipt.note --entry vectors/log/0-genesis.cbor
python3 work/verify-py/verify.py replay vectors/log/manifest.json
```

`--trust` selects an authoritative trust CBOR file; the default is the sealed
suite's `trust.cbor`. `--prior vectors/served` verifies that earlier directory
under the initial trust, learns its keys/policy, and supplies its held branch
when checking a candidate served log. For example:

```sh
python3 work/verify-py/verify.py bundle vectors/proofs-rotated/nas.bundle --prior vectors/served
```

A standalone rotated checkpoint can likewise use `checkpoint` and `--prior`.
The served-head variants contain only a checkpoint, so the harness overlays
them on the directory their manifest names. `replay` takes only ordering from
the manifest and its anchor from `--trust`; use the harness for genesis
fixtures with intentionally different manifest anchors. Successful replay
prints canonical state JSON directly; other commands print a JSON result and
return 0 on acceptance, 1 on refusal/configuration errors.

`verifier.py` exposes the same pure operations for Python callers. `served`
takes a local byte-fetch callback; this implementation contains no network
client. Bundles establish inclusion and device binding; current authorization
and the installed WireGuard key come from the verified log's replay, never
from the historical bundle key. Expected answers are confined to the harness;
protocol modules neither open manifests nor consult vector outcomes.
