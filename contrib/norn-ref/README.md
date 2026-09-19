# norn-ref — Python reference implementation

Written from `SPEC.md` alone. It generates `testdata/vectors/`, which the Go
implementation must match byte for byte. **It must never import, consult or be
adjusted to agree with the Go code** — that is the only thing that makes the
vectors meaningful as a cross-implementation contract.

```sh
python3 -m venv .venv && .venv/bin/pip install pynacl
.venv/bin/python -m unittest discover -s tests     # unit tests
make vectors                                       # regenerate testdata/vectors (from repo root)
```

A changed vector means a changed protocol. Review the diff.

| Module | Responsibility |
|---|---|
| `cbor.py` | deterministic CBOR encoder + strict decoder for the Norn profile (SPEC §4.0) |
| `keys.py` | Ed25519/X25519 test keys from names, `kid` derivation (SPEC §3) |
| `entry.py` | envelope, signature preimage, signing, entry/leaf hashes (SPEC §4) |
| `canonjson.py` | canonical JSON for vector mirrors (SPEC §12) |
| `fixture.py` | the catalogue: one valid entry per type |
| `gen_vectors.py` | writes the files |
