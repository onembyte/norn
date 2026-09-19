"""Canonical JSON for vector mirrors (SPEC.md §12).

Keys sorted, no whitespace, UTF-8 unescaped, bytes as lowercase hex. Two
implementations must produce identical bytes, so nothing here may depend on
Python's dict ordering or json defaults.
"""

from __future__ import annotations

import json
from typing import Any


def jsonable(value: Any) -> Any:
    """Convert a decoded CBOR value to its canonical-JSON representation."""
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).hex()
    if isinstance(value, dict):
        return {k: jsonable(v) for k, v in value.items()}
    if isinstance(value, list):
        return [jsonable(v) for v in value]
    return value


def dumps(value: Any) -> str:
    """Canonical JSON text (no trailing newline)."""
    return json.dumps(jsonable(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
