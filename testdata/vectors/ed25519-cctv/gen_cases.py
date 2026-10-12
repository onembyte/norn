#!/usr/bin/env python3
"""Derive §3.1's outcomes from the untouched C2SP CCTV flag annotations.

Usage: python3 -I testdata/vectors/ed25519-cctv/gen_cases.py

This table describes NORN-ED25519-v1, not RFC 8032 or an upstream validator.
No cryptography or third-party modules are needed to classify the flags.
"""

from __future__ import annotations

import json
import pathlib


# The deciding flag is the first flag in §3.1's listing, not evaluation order.
DECIDING_FLAGS = (
    "low_order_A", "low_order_R", "non_canonical_A", "non_canonical_R",
    "low_order_component_A", "low_order_component_R",
)
AUXILIARY_FLAGS = {"low_order_residue", "reencoded_k"}


def main() -> None:
    directory = pathlib.Path(__file__).resolve().parent
    vectors = json.loads((directory / "ed25519vectors.json").read_bytes())
    assert len(vectors) == 914
    assert len({v["number"] for v in vectors}) == 914
    cases = []
    for vector in vectors:
        flags = set(vector["flags"] or [])
        assert flags <= set(DECIDING_FLAGS) | AUXILIARY_FLAGS
        first = next((flag for flag in DECIDING_FLAGS if flag in flags), None)
        # Residue and re-encoded challenges never determine an answer alone.
        if flags & AUXILIARY_FLAGS:
            assert first is not None, vector["number"]
        case = {"number": vector["number"], "outcome": "reject" if first else "accept"}
        if first:
            case["flag"] = first
        else:
            assert not flags and vector["number"] == 305
        cases.append(case)
    assert [c["number"] for c in cases if c["outcome"] == "accept"] == [305]
    table = {
        "comment": "Derived from ed25519vectors.json's flags in SPEC.md §3.1's listing order. "
                   "outcome is NORN-ED25519-v1's, not RFC 8032's. The flag names the first "
                   "flag in §3.1's listing: non_canonical and low_order mean not a valid point; "
                   "low_order_component means not of order exactly L.",
        "cases": cases,
    }
    (directory / "cases.json").write_bytes(
        (json.dumps(table, indent=2, ensure_ascii=False) + "\n").encode("utf-8"))


if __name__ == "__main__":
    main()
