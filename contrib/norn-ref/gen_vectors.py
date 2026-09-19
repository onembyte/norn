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

from nornref import canonjson, entry, fixture, note, replay, trust


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


def write_log(out: pathlib.Path) -> None:
    """The replay fixture: the log, its manifest, and the state it produces."""
    items = fixture.log()
    raw = [item.raw for item in items]
    for item in items:
        write(out / "log" / f"{item.name}.cbor", item.raw)
        if item.reason:
            write(out / "log" / f"{item.name}.reason", item.reason + "\n")

    anchor = replay.Anchor(net=fixture.NET, genesis_hash=entry.leaf_hash(raw[0]))
    write(out / "log" / "manifest.json", canonjson.dumps({
        "anchor": {"net": anchor.net, "genesis_hash": anchor.genesis_hash},
        "entries": [{"index": i, "name": it.name, "reason": it.reason or ""}
                    for i, it in enumerate(items)],
    }) + "\n")
    write(out / "state.json", replay.replay(anchor, raw).to_json() + "\n")


def write_genesis_aborts(out: pathlib.Path) -> None:
    """Every way entry 0 can abort replay, one single-entry log per case."""
    index = []
    for name, raw, anchor in fixture.genesis_aborts():
        folder = out / "genesis" / name
        write(folder / "00-genesis.cbor", raw)
        write(folder / "manifest.json", canonjson.dumps({
            "anchor": {"net": anchor.net, "genesis_hash": anchor.genesis_hash},
            "entries": [{"index": 0, "name": "00-genesis", "reason": "bad-genesis"}],
        }) + "\n")
        write(folder / "state.json", replay.replay(anchor, [raw]).to_json() + "\n")
        index.append(name)
    write(out / "genesis" / "cases.json", canonjson.dumps({
        "comment": "each subdirectory is a one-entry log whose replay MUST abort "
                   "with bad-genesis; an abort stops replay, so cases cannot share a log",
        "cases": index,
    }) + "\n")


def write_trust_rejections(out: pathlib.Path) -> None:
    """Trust files a verifier MUST refuse (SPEC §9.1)."""
    cases = []
    for name, doc in fixture.trust_rejections():
        write(out / "trust-bad" / f"{name}.cbor", trust.encode(doc))
        cases.append(name)
    write(out / "trust-bad" / "cases.json", canonjson.dumps({
        "comment": "every file here is deterministic CBOR that decodes cleanly but "
                   "MUST be rejected as a trust anchor; the file name says why",
        "cases": cases,
    }) + "\n")


def write_trust(out: pathlib.Path) -> None:
    """The trust anchor, its human rendering, its fingerprint, and a receipt."""
    doc = fixture.trust_file()
    trust.validate(doc)
    write(out / "trust.cbor", trust.encode(doc))
    write(out / "trust.toml", trust.to_toml(doc))
    write(out / "trust.fingerprint", trust.fingerprint(doc) + "\n")

    genesis_leaf = doc["genesis_hash"]
    deadline = fixture.T0 + 60  # params.mmd
    text = note.receipt_text(doc["origin"], genesis_leaf, deadline)
    signed = note.sign(text, doc["origin"], fixture.KEYS["logkey"])
    write(out / "receipt.note", signed)
    write(out / "receipt.json", canonjson.dumps({
        "comment": "receipt for the genesis entry; verifies under trust.log_key",
        "origin": doc["origin"],
        "leaf_hash": genesis_leaf,
        "deadline": deadline,
        "text_sha256": __import__("hashlib").sha256(text.encode()).digest(),
    }) + "\n")


def main(argv: list[str]) -> int:
    out = pathlib.Path(argv[1] if len(argv) > 1 else "testdata/vectors")
    write_keys(out)
    write_entries(out)
    write_log(out)
    write_genesis_aborts(out)
    write_trust_rejections(out)
    write_trust(out)
    count = sum(1 for _ in out.rglob("*") if _.is_file())
    print(f"wrote {count} files to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
