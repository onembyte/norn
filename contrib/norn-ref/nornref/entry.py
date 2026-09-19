"""Log entries: envelope, signing preimage, hashing (SPEC.md §4).

This module owns the *shape* of an entry and nothing else. Whether an entry is
allowed to take effect is replay's decision (SPEC §5), not this module's.
"""

from __future__ import annotations

import hashlib
from typing import Any

from . import cbor, keys

VERSION = 1
PREIMAGE_PREFIX = b"norn/entry/v1\n"

ROLES = ("root", "signer", "device")

TYPES = (
    "genesis", "enroll", "rotate", "revoke",
    "signer_add", "signer_remove", "signer_thr",
    "root_add", "root_remove", "root_thr",
    "log_key", "policy", "params", "note",
)


class SchemaError(ValueError):
    """Entry does not match the schema in SPEC §4.3."""


def new(entry_type: str, net: bytes, ts: int, body: dict[str, Any],
        after: int | None = None) -> dict[str, Any]:
    """Build an unsigned envelope. Raises SchemaError for an unknown type."""
    if entry_type not in TYPES:
        raise SchemaError(f"unknown entry type: {entry_type}")
    if len(net) != 16:
        raise SchemaError("net must be 16 bytes")
    env: dict[str, Any] = {"v": VERSION, "t": entry_type, "net": net, "ts": ts}
    if after is not None:
        env["after"] = after
    env["body"] = body
    env["sigs"] = []
    return env


def preimage(env: dict[str, Any]) -> bytes:
    """Bytes covered by every signature: prefix + envelope without `sigs`."""
    return PREIMAGE_PREFIX + cbor.encode({k: v for k, v in env.items() if k != "sigs"})


def sign(env: dict[str, Any], key: keys.Ed25519, role: str) -> dict[str, Any]:
    """Add one signature in place, keeping `sigs` sorted by kid and unique."""
    if role not in ROLES:
        raise SchemaError(f"unknown role: {role}")
    sig = {"kid": key.id, "role": role, "sig": key.sign(preimage(env))}
    env["sigs"] = sorted(
        [s for s in env["sigs"] if s["kid"] != key.id] + [sig],
        key=lambda s: s["kid"],
    )
    return env


def verify_sig(env: dict[str, Any], sig: dict[str, Any], public: bytes) -> bool:
    """Check one signature entry against a public key."""
    return keys.kid(public) == sig.get("kid") and keys.verify(public, preimage(env), sig.get("sig", b""))


def encode(env: dict[str, Any]) -> bytes:
    """Canonical entry bytes, signatures included."""
    return cbor.encode(env)


def entry_hash(raw: bytes) -> bytes:
    """SHA-256 of the entry bytes: de-duplication identity (SPEC §4.0)."""
    return hashlib.sha256(raw).digest()


def leaf_hash(raw: bytes) -> bytes:
    """RFC 6962 §2.1 leaf hash."""
    return hashlib.sha256(b"\x00" + raw).digest()
