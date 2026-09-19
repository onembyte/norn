"""Deterministic CBOR for the Norn profile (SPEC.md §4.0).

Encoder and strict decoder for the restricted subset: unsigned integers, byte
strings, text strings, booleans, definite-length arrays and maps with text-string
keys of 1-23 bytes. No floats, tags, null, undefined, negative integers or
indefinite-length items, on either side.

The decoder is strict rather than lenient on purpose: a canonical form is only
canonical if non-canonical encodings are refused (SPEC §5 reason `decode`).
"""

from __future__ import annotations

from typing import Any

MAX_UINT = 2**63 - 1
MAX_KEY_LEN = 23

_MT_UINT, _MT_BYTES, _MT_TEXT, _MT_ARRAY, _MT_MAP, _MT_SIMPLE = 0, 2, 3, 4, 5, 7
_FALSE, _TRUE = 20, 21


class ProfileError(ValueError):
    """Value or encoding outside the Norn CBOR profile."""


def _head(major: int, n: int) -> bytes:
    if n < 24:
        return bytes([major << 5 | n])
    for threshold, extra, size in ((0x100, 24, 1), (0x10000, 25, 2), (0x100000000, 26, 4)):
        if n < threshold:
            return bytes([major << 5 | extra]) + n.to_bytes(size, "big")
    return bytes([major << 5 | 27]) + n.to_bytes(8, "big")


def encode(value: Any) -> bytes:
    """Encode a value in the Norn deterministic profile."""
    if value is True or value is False:
        return bytes([_MT_SIMPLE << 5 | (_TRUE if value else _FALSE)])
    if isinstance(value, int):
        if value < 0 or value > MAX_UINT:
            raise ProfileError(f"integer out of profile: {value}")
        return _head(_MT_UINT, value)
    if isinstance(value, (bytes, bytearray)):
        return _head(_MT_BYTES, len(value)) + bytes(value)
    if isinstance(value, str):
        raw = value.encode("utf-8")
        return _head(_MT_TEXT, len(raw)) + raw
    if isinstance(value, list):
        return _head(_MT_ARRAY, len(value)) + b"".join(encode(v) for v in value)
    if isinstance(value, dict):
        items = []
        for key, val in value.items():
            if not isinstance(key, str):
                raise ProfileError(f"map key must be a text string: {key!r}")
            raw = key.encode("utf-8")
            if not 1 <= len(raw) <= MAX_KEY_LEN:
                raise ProfileError(f"map key must be 1-{MAX_KEY_LEN} bytes: {key!r}")
            items.append((encode(key), encode(val)))
        items.sort(key=lambda kv: kv[0])
        return _head(_MT_MAP, len(items)) + b"".join(k + v for k, v in items)
    raise ProfileError(f"type outside profile: {type(value).__name__}")


class _Decoder:
    def __init__(self, buf: bytes) -> None:
        self.buf = buf
        self.pos = 0

    def take(self, n: int) -> bytes:
        if self.pos + n > len(self.buf):
            raise ProfileError("truncated")
        out = self.buf[self.pos : self.pos + n]
        self.pos += n
        return out

    def head(self) -> tuple[int, int]:
        (initial,) = self.take(1)
        major, extra = initial >> 5, initial & 0x1F
        if extra < 24:
            return major, extra
        if extra > 27:
            raise ProfileError(f"reserved or indefinite length: {extra}")
        size = 1 << (extra - 24)
        n = int.from_bytes(self.take(size), "big")
        minimum = (24, 0x100, 0x10000, 0x100000000)[extra - 24]
        if n < minimum:
            raise ProfileError("non-shortest length encoding")
        return major, n

    def value(self) -> Any:
        major, n = self.head()
        if major == _MT_UINT:
            if n > MAX_UINT:
                raise ProfileError("integer out of profile")
            return n
        if major == _MT_BYTES:
            return self.take(n)
        if major == _MT_TEXT:
            raw = self.take(n)
            try:
                return raw.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise ProfileError("invalid UTF-8") from exc
        if major == _MT_ARRAY:
            return [self.value() for _ in range(n)]
        if major == _MT_MAP:
            out: dict[str, Any] = {}
            previous = b""
            for _ in range(n):
                start = self.pos
                key = self.value()
                encoded = self.buf[start : self.pos]
                if not isinstance(key, str):
                    raise ProfileError("map key must be a text string")
                if not 1 <= len(key.encode("utf-8")) <= MAX_KEY_LEN:
                    raise ProfileError(f"map key must be 1-{MAX_KEY_LEN} bytes")
                if previous and encoded <= previous:
                    raise ProfileError("map keys out of order or duplicated")
                previous = encoded
                out[key] = self.value()
            return out
        if major == _MT_SIMPLE:
            if n == _TRUE:
                return True
            if n == _FALSE:
                return False
            raise ProfileError(f"simple value outside profile: {n}")
        raise ProfileError(f"major type outside profile: {major}")


def decode(raw: bytes) -> Any:
    """Decode one value, rejecting anything non-canonical or outside the profile."""
    dec = _Decoder(raw)
    value = dec.value()
    if dec.pos != len(raw):
        raise ProfileError("trailing bytes")
    return value
