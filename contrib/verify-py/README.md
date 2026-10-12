# Independent Python verifier — Lane BJ

From the sealed directory, run:

```sh
python3 work/verify-py/harness.py
```

Python 3.11 or newer is required (`tomllib` checks the trust-file rendering).
All code uses the standard library. No installation, network access, signing
service or other project checkout is used. The harness locates `vectors/`
relative to itself, runs the standards self-tests first, prints a line with
path, expected, got and PASS/FAIL for each assertion, and returns status 1 for
failures, unexpected exceptions or an unhandled manifest/case shape.
Large byte comparisons print SHA-256 digests; comparison itself is byte for byte.

Coverage includes every shipped case/manifest, every replay fixture and
canonical state, encoding-profile boundaries, all 914 CCTV signatures, entry
and request mirrors, bech32m forms, trust CBOR/TOML/fingerprint, policies and
quorum evaluation, receipts, checkpoints, hash tiles at multiple levels,
entry bundles, inclusion bundles, rotated keys and policies with both reader
histories, fork evidence versions 1 and 2, held-head comparisons, witness time,
freshness, expiry, historical versus installed keys, and grant parsing.
Served manifests decide whether a fixture is a complete log, an overlaid
checkpoint, named served directories or file replacements/removals.
`SHA256SUMS` is checked for every shipped file and for a complete inventory.

The protocol code is independent of expected outcomes:

- `cbor.py`: restricted deterministic CBOR codec.
- `ed25519.py`, `merkle.py`, `bech32m.py`: pure Python primitives and self-tests.
- `protocol.py`: trust/policy/request checking, entry envelopes, replay,
  canonical JSON, grants, proven-set derivation and freshness.
- `verify.py`: signed notes, checkpoints, receipts, proof bundles, served logs,
  tile paths and fork evidence. `Refusal.code` carries the specified code.
- `harness.py`: reads expectations and compares them with the implementation.

For example, from this directory:

```python
from pathlib import Path
from protocol import trust, canonical_json
from verify import Verifier, Files

vectors = Path("../../vectors")
anchor = trust((vectors / "trust.cbor").read_bytes())
reader = Verifier(anchor)
head, state, entries = reader.served(Files(vectors / "served"))
print(canonical_json(state).decode(), end="")
informed = Verifier(anchor, state)  # state must already have been accepted
informed.bundle((vectors / "proofs-rotated/nas.bundle").read_bytes())
```

`served(source, stored=head, stored_entries=entries)` compares a candidate with
an already accepted branch. If the held branch is unavailable at a shorter
candidate's size, it refuses rollback without accusing a fork. Learning keys
and a policy alone does not fabricate a held checkpoint. No candidate can teach
its own checkpoint verifier a key or policy before it has been accepted.

OpenTimestamps checking is limited to the assertions §12 supplies: the exact
checkpoint byte range and digest, and the declared arbitrary digest in its
opaque fixture. This does not validate OTS timestamp trees, calendar replies or
Bitcoin confirmations; SPEC does not describe that format. See `NOTES.md` for
the standards remembered, interpretations and scope limits.
