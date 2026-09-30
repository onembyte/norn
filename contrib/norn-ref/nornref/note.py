"""Signed notes and Norn receipts (c2sp.org/signed-note, SPEC.md §7).

A signed note is a block of text, a blank line, then one or more signature
lines. Norn uses the same format the transparency ecosystem uses for
checkpoints, so the same tools read a Norn receipt.

Wire check: these encodings are cross-verified against Go's `note` package and
torchwood in Phase 2. Until then this module is only self-consistent.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
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
    try:
        raw = base64.b64decode(keydata, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise NoteError("key data is not base64") from exc
    if len(raw) != 33 or raw[0] not in (ALG_ED25519, ALG_COSIGNATURE):
        raise NoteError("only Ed25519 note and cosignature keys are supported")
    alg, public = raw[0], raw[1:]
    # The algorithm is part of the identity, so it is part of the id check: a
    # key published as a cosigner is a different verifier from the same bytes
    # published as a note signer.
    if keyhash != key_id(name, public, alg).hex():
        raise NoteError("key id does not match name, key and algorithm")
    return Verifier(name, public, alg)


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
        # Exactly its encoding (SPEC 7): `validate=True` checks the alphabet
        # and not the padding bits, so one payload had two spellings (cold
        # gate run 12, D8).
        if base64.b64encode(raw).decode("ascii") != blob:
            raise NoteError("the signature line is not the encoding of its payload")
        if len(raw) != 68:
            raise NoteError("signature must be 4-byte key id plus 64-byte signature")
        signatures.append((name, raw))
    if not signatures:
        raise NoteError("note has no signature lines")
    return text, signatures


def verify(signed: str, vkeys: list[str]) -> str:
    """Return the note text if a listed key signed it; raise otherwise.

    Per line, not per key (SPEC §10, and §7 for a receipt): every line whose
    name and key id match a listed key MUST verify, and at least one must be
    present. This returned on the first line that verified, so a note carrying
    the log's signature *and* a forgery under the same name and id was
    accepted -- the reading Go's reader dropped in run 8, and which nothing
    here caught because this module never read a checkpoint.
    """
    text, signatures = split(signed)
    trusted = [parse_vkey(v) for v in vkeys]
    verified = False
    for name, raw in signatures:
        for verifier in trusted:
            if verifier.name == name and verifier.id == raw[:4]:
                if not keys.verify(verifier.public, text.encode("utf-8"), raw[4:]):
                    raise NoteError(f"a signature line naming {name} does not verify")
                verified = True
    if not verified:
        raise NoteError("no valid signature from a trusted key")
    return text


def receipt_text(origin: str, leaf_hash: bytes, deadline: int) -> str:
    """The body of a submission receipt (SPEC §7)."""
    if len(leaf_hash) != 32:
        raise NoteError("leaf hash must be 32 bytes")
    blob = base64.b64encode(leaf_hash).decode("ascii")
    return f"{RECEIPT_HEADER}\n{origin}\n{blob}\n{deadline}\n"


#: Canonical decimal: `0`, or ASCII digits with no leading zero. `[0-9]`, not
#: `\d`, which matches every Unicode digit.
_CANONICAL_DECIMAL = re.compile(r"0|[1-9][0-9]*")

#: SPEC §7: the deadline fits in 64 bits, as the cosignature timestamps it is
#: compared with do.
_UINT64_MAX = 2**64 - 1


@dataclass(frozen=True)
class Receipt:
    origin: str
    leaf_hash: bytes
    deadline: int


def check_receipt(signed: str, log_key: str, origin: str) -> Receipt:
    """Read a submission receipt the way SPEC §7 says whoever holds one must.

    No entry and no clock: whether the leaf is the submitter's entry, and
    whether the deadline has passed, are questions for the caller. Everything
    here is a property of the receipt alone, which is what `receipts-bad/`
    pins.
    """
    text = verify(signed, [log_key])
    lines = text[:-1].split("\n")
    if len(lines) != 4:
        raise NoteError(f"a receipt is exactly four lines, this one has {len(lines)}")
    header, named, leaf, deadline = lines
    if header != RECEIPT_HEADER:
        raise NoteError(f"first line is {header!r}, want {RECEIPT_HEADER!r}")
    if named != origin:
        raise NoteError(f"the receipt is for {named!r}, not {origin!r}")
    try:
        leaf_hash = base64.b64decode(leaf, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise NoteError("the leaf hash is not base64") from exc
    if len(leaf_hash) != 32:
        raise NoteError(f"the leaf hash is {len(leaf_hash)} bytes, want 32")
    # Exactly its encoding (SPEC §7): a lenient decoder maps unpadded text,
    # non-zero padding bits and skipped control characters to the same 32
    # bytes, and one promise has one spelling.
    if base64.b64encode(leaf_hash).decode("ascii") != leaf:
        raise NoteError("the leaf hash line is not the encoding of the leaf hash")
    if not _CANONICAL_DECIMAL.fullmatch(deadline):
        raise NoteError(f"the deadline {deadline!r} is not canonical decimal")
    value = int(deadline)
    if value > _UINT64_MAX:
        raise NoteError(f"the deadline {deadline} does not fit in 64 bits")
    return Receipt(named, leaf_hash, value)
