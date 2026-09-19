"""Signed notes and Norn receipts (c2sp.org/signed-note, SPEC.md §7).

A signed note is a block of text, a blank line, then one or more signature
lines. Norn uses the same format the transparency ecosystem uses for
checkpoints, so the same tools read a Norn receipt.

Wire check: these encodings are cross-verified against Go's `note` package and
torchwood in Phase 2. Until then this module is only self-consistent.
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass

from . import keys

ALG_ED25519 = 0x01
SIG_PREFIX = "\u2014 "  # em dash, space
RECEIPT_HEADER = "norn/receipt/v1"


class NoteError(ValueError):
    """Malformed note, malformed key, or no signature from a trusted key."""


def key_id(name: str, public: bytes) -> bytes:
    """4-byte key id binding the key to its name and algorithm."""
    return hashlib.sha256(name.encode("utf-8") + b"\n" + bytes([ALG_ED25519]) + public).digest()[:4]


def vkey(name: str, public: bytes) -> str:
    """Verifier key string: `name+<keyid hex>+<base64(alg||key)>`."""
    if "+" in name or "\n" in name or not name:
        raise NoteError(f"invalid key name: {name!r}")
    keydata = base64.b64encode(bytes([ALG_ED25519]) + public).decode("ascii")
    return f"{name}+{key_id(name, public).hex()}+{keydata}"


@dataclass(frozen=True)
class Verifier:
    name: str
    public: bytes

    @property
    def id(self) -> bytes:
        return key_id(self.name, self.public)


def parse_vkey(text: str) -> Verifier:
    """Parse a verifier key string, checking the embedded key id."""
    # Split at most twice: standard base64 key data may itself contain "+".
    parts = text.split("+", 2)
    if len(parts) != 3 or not all(parts):
        raise NoteError("verifier key must be name+keyid+keydata")
    name, keyhash, keydata = parts
    try:
        raw = base64.b64decode(keydata, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise NoteError("key data is not base64") from exc
    if len(raw) != 33 or raw[0] != ALG_ED25519:
        raise NoteError("only Ed25519 verifier keys are supported")
    public = raw[1:]
    if keyhash != key_id(name, public).hex():
        raise NoteError("key id does not match name and key")
    return Verifier(name, public)


def _check_text(text: str) -> None:
    if not text or not text.endswith("\n"):
        raise NoteError("note text must be non-empty and end with a newline")


def sign(text: str, name: str, key: keys.Ed25519) -> str:
    """Return the signed note: text, blank line, one signature line."""
    _check_text(text)
    signature = key.sign(text.encode("utf-8"))
    blob = base64.b64encode(key_id(name, key.public) + signature).decode("ascii")
    return f"{text}\n{SIG_PREFIX}{name} {blob}\n"


def split(signed: str) -> tuple[str, list[tuple[str, bytes]]]:
    """Split a signed note into its text and its (name, keyid||sig) lines."""
    text, sep, block = signed.partition("\n\n")
    if not sep:
        raise NoteError("note has no signature block")
    text += "\n"
    signatures: list[tuple[str, bytes]] = []
    for line in block.splitlines():
        if not line.startswith(SIG_PREFIX):
            raise NoteError(f"bad signature line: {line!r}")
        name, _, blob = line[len(SIG_PREFIX):].partition(" ")
        try:
            raw = base64.b64decode(blob, validate=True)
        except (ValueError, base64.binascii.Error) as exc:
            raise NoteError("signature is not base64") from exc
        if len(raw) != 68:
            raise NoteError("signature must be 4-byte key id plus 64-byte signature")
        signatures.append((name, raw))
    if not signatures:
        raise NoteError("note has no signature lines")
    return text, signatures


def verify(signed: str, vkeys: list[str]) -> str:
    """Return the note text if any listed key signed it; raise otherwise."""
    text, signatures = split(signed)
    trusted = [parse_vkey(v) for v in vkeys]
    for name, raw in signatures:
        for verifier in trusted:
            if verifier.name == name and verifier.id == raw[:4]:
                if keys.verify(verifier.public, text.encode("utf-8"), raw[4:]):
                    return text
    raise NoteError("no valid signature from a trusted key")


def receipt_text(origin: str, leaf_hash: bytes, deadline: int) -> str:
    """The body of a submission receipt (SPEC §7)."""
    if len(leaf_hash) != 32:
        raise NoteError("leaf hash must be 32 bytes")
    blob = base64.b64encode(leaf_hash).decode("ascii")
    return f"{RECEIPT_HEADER}\n{origin}\n{blob}\n{deadline}\n"
