"""bech32m (BIP-350) — the text form of an enrollment request (SPEC §16.2).

Why this lives here at all: a device has to hand a signer ~150 bytes across a
room, and the only universally available channel is a phone camera. bech32m is
case-insensitive, has a strong checksum and a QR-friendly alphabet, which is
exactly that job.

Two rules from the BIP are *not* adopted, and both are SPEC §16.2 decisions:
the 90-character limit (an address-sized bound; a request is longer), and any
acceptance of plain bech32, whose only difference is the checksum constant.
"""

from __future__ import annotations

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BECH32M_CONST = 0x2BC830A3
SEPARATOR = "1"
CHECKSUM_LEN = 6

#: Printable ASCII, per BIP-173: anything outside is not a human-readable part.
_HRP_MIN, _HRP_MAX = 33, 126


class Bech32Error(ValueError):
    """The string is not a well-formed bech32m encoding."""


def _polymod(values: list[int]) -> int:
    generator = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ value
        for i, g in enumerate(generator):
            if (top >> i) & 1:
                chk ^= g
    return chk


def _hrp_expand(hrp: str) -> list[int]:
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _checksum(hrp: str, data: list[int]) -> list[int]:
    values = _hrp_expand(hrp) + data + [0] * CHECKSUM_LEN
    polymod = _polymod(values) ^ BECH32M_CONST
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(CHECKSUM_LEN)]


def encode_raw(hrp: str, data: list[int] | bytes) -> str:
    """Encode 5-bit groups. `hrp` must be lowercase printable ASCII."""
    if not hrp:
        raise Bech32Error("empty human-readable part")
    for c in hrp:
        if not _HRP_MIN <= ord(c) <= _HRP_MAX:
            raise Bech32Error(f"human-readable part character out of range: {c!r}")
        if c.isupper():
            raise Bech32Error("the human-readable part must be lowercase")
    values = list(data)
    if any(not 0 <= v <= 31 for v in values):
        raise Bech32Error("data groups must be 5-bit values")
    combined = values + _checksum(hrp, values)
    return hrp + SEPARATOR + "".join(CHARSET[v] for v in combined)


def decode_raw(text: str) -> tuple[str, list[int]]:
    """Decode to (hrp, 5-bit groups), checksum verified.

    Deliberately imposes no length limit: SPEC §16.2 drops BIP-173's 90-char
    bound, which is sized for addresses. Above it the code no longer guarantees
    detection of four errors -- the request's own Ed25519 signature is what
    actually protects the payload.
    """
    if any(not _HRP_MIN <= ord(c) <= _HRP_MAX for c in text):
        raise Bech32Error("character out of range")
    if text.lower() != text and text.upper() != text:
        raise Bech32Error("mixed case")
    text = text.lower()

    pos = text.rfind(SEPARATOR)
    if pos < 1:
        raise Bech32Error("no separator, or an empty human-readable part")
    if len(text) - pos - 1 < CHECKSUM_LEN:
        raise Bech32Error("checksum too short")

    hrp, body = text[:pos], text[pos + 1:]
    values = []
    for c in body:
        if c not in CHARSET:
            raise Bech32Error(f"invalid data character: {c!r}")
        values.append(CHARSET.index(c))
    if _polymod(_hrp_expand(hrp) + values) != BECH32M_CONST:
        raise Bech32Error("checksum mismatch")
    return hrp, values[:-CHECKSUM_LEN]


def _convertbits(values: list[int], frm: int, to: int, pad: bool) -> list[int]:
    acc = bits = 0
    out: list[int] = []
    maxv = (1 << to) - 1
    for value in values:
        if value < 0 or value >> frm:
            raise Bech32Error("value out of range for regrouping")
        acc = (acc << frm) | value
        bits += frm
        while bits >= to:
            bits -= to
            out.append((acc >> bits) & maxv)
    if pad:
        if bits:
            out.append((acc << (to - bits)) & maxv)
    elif bits >= frm:
        raise Bech32Error("too much padding")
    elif (acc << (to - bits)) & maxv:
        raise Bech32Error("non-zero padding")
    return out


def encode(hrp: str, payload: bytes) -> str:
    """Encode bytes: 8-bit groups regrouped to 5, zero-padded."""
    return encode_raw(hrp, _convertbits(list(payload), 8, 5, pad=True))


def decode(text: str) -> tuple[str, bytes]:
    """Decode to (hrp, bytes). Padding must be under 5 bits and all zero."""
    hrp, data = decode_raw(text)
    return hrp, bytes(_convertbits(data, 5, 8, pad=False))
