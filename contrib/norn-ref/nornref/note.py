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

#: A *cosignature* key is a different algorithm to a plain note key
#: (`c2sp.org/tlog-cosignature` v1). It is not a detail: the byte goes into the
#: key id, so a witness's key under 0x01 and the same key under 0x04 are two
#: different identities, and a checkpoint cosigned by the real one could never
#: be attributed to the first.
ALG_COSIGNATURE = 0x04
SIG_PREFIX = "\u2014 "  # em dash, space
RECEIPT_HEADER = "norn/receipt/v1"


class NoteError(ValueError):
    """Malformed note, malformed key, or no signature from a trusted key."""


def key_id(name: str, public: bytes, alg: int = ALG_ED25519) -> bytes:
    """4-byte key id binding the key to its name and algorithm."""
    return hashlib.sha256(name.encode("utf-8") + b"\n" + bytes([alg]) + public).digest()[:4]


def vkey(name: str, public: bytes, alg: int = ALG_ED25519) -> str:
    """Verifier key string: `name+<keyid hex>+<base64(alg||key)>`."""
    if "+" in name or "\n" in name or not name:
        raise NoteError(f"invalid key name: {name!r}")
    keydata = base64.b64encode(bytes([alg]) + public).decode("ascii")
    return f"{name}+{key_id(name, public, alg).hex()}+{keydata}"


@dataclass(frozen=True)
class Verifier:
    name: str
    public: bytes
    alg: int = ALG_ED25519

    @property
    def id(self) -> bytes:
        return key_id(self.name, self.public, self.alg)


def parse_vkey(text: str) -> Verifier:
    """Parse a verifier key string, checking the embedded key id."""
    # Split at most twice: standard base64 key data may itself contain "+".
    parts = text.split("+", 2)
    if len(parts) != 3 or not all(parts):
        raise NoteError("verifier key must be name+keyid+keydata")
    name, keyhash, keydata = parts
    # SPEC 7's key-name grammar (D-074 f). It was str.isspace, whose table
    # counts U+001C-U+001F as space where Go's does not, so one trust file
    # loaded in one implementation and not the other.
    if not name or any(not 0x21 <= ord(char) <= 0x7E or char == "+" for char in name):
        raise NoteError(f"verifier key name {name!r} is not one or more ASCII "
                        "bytes 0x21-0x7E without '+'")
    try:
        raw = base64.b64decode(keydata, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise NoteError("key data is not base64") from exc
    if base64.b64encode(raw).decode("ascii") != keydata:
        raise NoteError("key data base64 is not canonical")
    if len(raw) != 33 or raw[0] not in (ALG_ED25519, ALG_COSIGNATURE):
        raise NoteError("only Ed25519 note and cosignature keys are supported")
    alg, public = raw[0], raw[1:]
    # The algorithm is part of the identity, so it is part of the id check: a
    # key published as a cosigner is a different verifier from the same bytes
    # published as a note signer.
    if keyhash != key_id(name, public, alg).hex():
        raise NoteError("key id does not match name, key and algorithm")
    return Verifier(name, public, alg)


# The complete white-space property is protocol data, not str.isspace's
# runtime table, which also includes U+001C-U+001F (D-077).
_SIGNATURE_NAME_SPACE = (
    "\u0009\u000a\u000b\u000c\u000d\u0020\u0085\u00a0\u1680"
    "\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a"
    "\u2028\u2029\u202f\u205f\u3000"
)


def _valid_signature_name(name: str) -> bool:
    return bool(name) and not any(char == "+" or char in _SIGNATURE_NAME_SPACE for char in name)


def _check_text(text: str) -> None:
    try:
        text.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise NoteError("the note is not UTF-8") from exc
    if any(ord(char) < 0x20 and char != "\n" for char in text):
        raise NoteError("the note contains an ASCII control character")
    if not text or not text.endswith("\n"):
        raise NoteError("note text must be non-empty and end with a newline")
    # A note's text lines are non-empty (SPEC 7): a blank first line is
    # malformed framing (D-078, cold gate run 15's L2).
    if text.startswith("\n"):
        raise NoteError("the note's first line is blank")


def sign(text: str, name: str, key: keys.Ed25519) -> str:
    """Return the signed note: text, blank line, one signature line."""
    _check_text(text)
    signature = key.sign(text.encode("utf-8"))
    blob = base64.b64encode(key_id(name, key.public) + signature).decode("ascii")
    return f"{text}\n{SIG_PREFIX}{name} {blob}\n"


def split(signed: str) -> tuple[str, list[tuple[str, bytes]]]:
    """Split a signed note into its text and its (name, keyid||sig) lines."""
    # Check every byte before matching names, including ignored strangers.
    _check_text(signed)
    text, sep, block = signed.partition("\n\n")
    if not sep:
        raise NoteError("note has no signature block")
    text += "\n"
    if not block.endswith("\n"):
        raise NoteError("signature block does not end in a newline")
    signatures: list[tuple[str, bytes]] = []
    # Strip exactly the final line terminator. `splitlines()` silently accepts
    # an unterminated last line, while trimming all newlines would erase an
    # extra blank line after the last signature (D14b).
    for line in block[:-1].split("\n"):
        if not line.startswith(SIG_PREFIX):
            raise NoteError(f"bad signature line: {line!r}")
        name, separator, blob = line[len(SIG_PREFIX):].partition(" ")
        if not separator or not _valid_signature_name(name):
            raise NoteError("signature line has an invalid key name")
        try:
            raw = base64.b64decode(blob, validate=True)
        except (ValueError, base64.binascii.Error) as exc:
            raise NoteError("signature is not base64") from exc
        if base64.b64encode(raw).decode("ascii") != blob:
            raise NoteError("signature base64 is not canonical")
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
