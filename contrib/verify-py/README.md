# Independent Norn verifier — Lane AX, 6.7-r

Run from the sealed directory with Python 3.11 or newer (standard library only):

```sh
python3 -B work/verify-py/harness.py
```

The harness runs the RFC 8032, RFC 6962 and BIP-350 self-tests first, verifies
`vectors/SHA256SUMS`, then prints `path expected=... got=... PASS/FAIL` for each
case and assertion. It returns nonzero for a mismatch, unexpected exception,
missing input, or unhandled `cases.json`/`manifest.json`. Its current result is
**1,817 checks, 0 FAIL**. Expected answers stay in the harness; the verifier
never reads them. Do not use Python's `-O` option, which disables self-test
assertions.

The harness covers every supplied manifest and case table: entry mirrors and
encoding controls; all replay logs and genesis variants; exact canonical state;
trust parsing, TOML reconstruction and fingerprint; request binary/text forms;
914 CCTV Ed25519 signatures; signed notes and receipt refusals; served entries,
tiles and roots; inclusion bundles; both fork-evidence versions; stored-head
fork/rollback comparisons; rotation with fresh and informed readers; witness
quorum times, expiry, grants and freshness. Anchor checks cover the specified
SHA-256 byte range and the unrelated sample's embedded digest. They do not
validate OpenTimestamps attestations, which the spec explicitly does not define.

Computed states are written under `work/verify-py/reproduced/`, including
`state.json`, both auxiliary replay logs, and every genesis variant. The
comparison is against complete bytes, including the final newline. The last
full run is saved in `results.txt`; `errors.txt` contains unexpected exceptions
and is empty after a successful run.

The offline CLI can also check individual artifacts:

```sh
python3 -B work/verify-py/verify.py served vectors/served
python3 -B work/verify-py/verify.py replay vectors/log/manifest.json
python3 -B work/verify-py/verify.py bundle vectors/proofs/nas.bundle
python3 -B work/verify-py/verify.py evidence vectors/fork/evidence.cbor
python3 -B work/verify-py/verify.py receipt vectors/receipt.note --entry vectors/log/0-genesis.cbor
python3 -B work/verify-py/verify.py request vectors/requests/req-minimal.txt --text
python3 -B work/verify-py/verify.py --learn-from vectors/served bundle vectors/proofs-rotated/nas.bundle
```

Successful CLI calls emit canonical JSON. Refused checkpoint, served-log,
bundle, receipt and evidence calls report the spec's closed refusal code on
stderr and exit 1. `--trust FILE` supplies another anchor; repeat
`--learn-from DIRECTORY` to verify successive served heads before checking the
target. A learned state is obtained only after verifying the head under the
keys and policy already trusted. `decode` checks only the entry CBOR profile;
`replay` emits the full state, including rejected entries.

`protocol.py` contains the reusable verifier, `cbor.py` the deterministic
encoding profile, and `ed25519.py`, `merkle.py`, `bech32m.py` the independently
implemented standards. `NOTES.md` records their provenance and the spec
interpretations. This is an offline verifier, not a node daemon, network
transport, signer, WireGuard reconciler or persistent gossip service.
