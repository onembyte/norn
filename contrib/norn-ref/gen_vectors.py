#!/usr/bin/env python3
"""Generate testdata/vectors from the reference implementation.

Usage: python3 contrib/norn-ref/gen_vectors.py testdata/vectors

Every file written here is a contract the Go implementation must satisfy. Run
`make vectors` after changing the reference, and review the diff: a changed
vector means a changed protocol.
"""

from __future__ import annotations

import pathlib
import sys

import hashlib

from nornref import canonjson, entry, fixture


def write(path: pathlib.Path, data: bytes | str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data if isinstance(data, bytes) else data.encode("utf-8"))


def write_keys(out: pathlib.Path) -> None:
    doc = {
        "comment": "TEST KEYS. Seeds are SHA-256('norn/testvector/v1\\n' + name); "
                   "WireGuard keys are X25519 from SHA-256(prefix + 'wg/' + name).",
        "ed25519": {
            name: {"seed": k.seed, "public": k.public, "kid": k.id}
            for name, k in sorted(fixture.KEYS.items())
        },
        "x25519": {name: pk for name, pk in sorted(fixture.WG.items())},
        "net": fixture.NET,
    }
    write(out / "keys.json", canonjson.dumps(doc) + "\n")


def write_entries(out: pathlib.Path) -> None:
    for name, env in fixture.catalogue():
        raw = entry.encode(env)
        write(out / "entries" / f"{name}.cbor", raw)
        write(out / "entries" / f"{name}.json", canonjson.dumps({
            "entry": env,
            "entry_hash": entry.entry_hash(raw),
            "leaf_hash": entry.leaf_hash(raw),
            "preimage_sha256": hashlib.sha256(entry.preimage(env)).digest(),
            "size": len(raw),
        }) + "\n")


def main(argv: list[str]) -> int:
    out = pathlib.Path(argv[1] if len(argv) > 1 else "testdata/vectors")
    write_keys(out)
    write_entries(out)
    count = sum(1 for _ in out.rglob("*") if _.is_file())
    print(f"wrote {count} files to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
