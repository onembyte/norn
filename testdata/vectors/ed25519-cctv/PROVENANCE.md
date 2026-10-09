# C2SP CCTV Ed25519 vectors — provenance

The source is [C2SP/CCTV](https://github.com/C2SP/CCTV), directory `ed25519/`,
commit `50a8ecf2a220f4c8bdc4f085789b8e85c26829e7` (committed
2026-09-25T13:09:09Z). The integrator fetched these files on 2026-10-09
(UTC 18:5x, as recorded in `FETCHED.txt`) under D-072 (c)'s authorization,
via `https://raw.githubusercontent.com/C2SP/CCTV/main/ed25519/<file>`.
This lane received the local files and their fetch record without network
access, verified all three SHA-256 digests with `shasum -a 256`, and copied
them byte for byte.

The license is **BSD-3-Clause**, reproduced in `LICENSE`, with these copyright
lines exactly as that file gives them:

```text
Copyright 2019 Google LLC
Copyright 2022 Filippo Valsorda
```

These three upstream files are never edited here — a newer upstream set is
a new fetch with a new provenance.

## Files

| File | SHA-256 |
|---|---|
| `ed25519vectors.json` | `b38e84caf3e7e89170ff520292dbeae421b0a794c27408ce5ce973018fe3d7f9` |
| `LICENSE` | `9fe727c21f00a770a683a4c8491bf24203ec839628bad09b026258c5afc17076` |
| `README.md` | `12889cbe441ce9da56fc65aa00b9d16f02ecdbcb8bb19d706ac35e92380d93d0` |

## Norn's derived table

`cases.json` is generated separately from the upstream files by `gen_cases.py`,
using Python's standard library only. Regenerate it from the repository root:

```sh
python3 -I testdata/vectors/ed25519-cctv/gen_cases.py
make vectors-sums
```

`make vectors` also runs this generator. The 914 entries give §3.1's
NORN-ED25519-v1 outcomes, not RFC 8032's: 913 rejections name their first
deciding flag, and unflagged vector 305 is accepted. No signature verification
is performed by the generator or the provenance and flag guards.
