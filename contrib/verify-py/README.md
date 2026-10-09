# Independent offline Norn verifier

Requires Python 3.11 or later, standard library only. From the sealed directory:

```sh
python3 -B work/verify-py/harness.py
```

The harness runs the RFC 8032, RFC 6962/RFC 9162 and BIP-350 self-tests first.
It then prints `path expected=… got=… PASS/FAIL` for every case and exits nonzero
on a mismatch, exception, unknown case table or unhandled protocol artifact.
It verifies every file against SHA256SUMS and checks the checksum inventory.
Expected vector values live only in the harness; protocol.py does not read them.

Coverage includes deterministic CBOR and hostile boundaries, all replay reasons,
byte-identical canonical states (main, empty and every genesis), trust and policy
parsing/evaluation, requests and mirrors, receipts, checkpoint signatures/quorum
and quorum times, served bundles/tiles/roots, portable proofs, fork evidence,
stored-head comparison, key/policy rotation, current-key selection, device expiry,
grants, freshness boundaries, path construction, fingerprints and TOML rendering.
The harness writes `state.actual.json`; `harness.log` contains the last recorded run.
See NOTES.md for standards recalled from memory and interpretation/scope details.
OpenTimestamps proof parsing and the live behaviors §12.1 calls unvectored are
outside this verifier; OTS assets receive integrity checks and the checkpoint
anchor receives the specified digest-range check.

The offline CLI is also available:

```sh
python3 -B work/verify-py/verify.py served vectors/served --trust vectors/trust.cbor
python3 -B work/verify-py/verify.py replay vectors/log --trust vectors/trust.cbor
python3 -B work/verify-py/verify.py bundle vectors/proofs/nas.bundle --trust vectors/trust.cbor
python3 -B work/verify-py/verify.py evidence vectors/fork/evidence.cbor --trust vectors/trust.cbor
python3 -B work/verify-py/verify.py request vectors/requests/req-minimal.txt --text --trust vectors/trust.cbor
```

It writes canonical JSON on success, a refusal code on stderr with exit status 1,
or a local I/O/configuration error with exit status 2. Use `--learn-from` with a
previously verified served mirror to learn published log keys and replacement
policy. Served verification supports `--stored` and `--held-log` for branch
comparison; receipt verification supports `--entry` and `--now`. Run `--help`
for arguments. Replay prints rejected entries as canonical state, including a
bad-genesis abort; callers must inspect that state before adoption. Portable
bundle verification supplies historical inclusion/binding, and current peer
membership still requires full verified replay.

There is no network access in the implementation. Entry, trust, bundle and
evidence input lengths are bounded as SPEC requires; CBOR nesting and preferred
encoding are checked before schema validation. Ed25519 arithmetic is variable
time and handles public verification data only.
