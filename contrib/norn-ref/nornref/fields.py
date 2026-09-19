"""Field constraints from SPEC §2 and §4.0, in one place.

These rules govern two different wire formats -- entry bodies (§4.3) and
enrollment requests (§16.1) -- and were on their way to being written twice.
Two copies of a validation rule is how two implementations drift apart while
every test on both sides still passes, so replay and enrollreq both call here.

Each function raises `FieldError`; callers translate that into whatever their
layer calls a rejection (replay's reason codes, a request's parse error).
"""

from __future__ import annotations

from typing import Any

MAX_DEVICE_ID = 64
MAX_LABELS = 32
MAX_LABEL_VALUE = 256
PK_LEN = 32
SIG_LEN = 64
MAX_UINT = 2**63 - 1

_ID_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789.-")
_ID_LEAD = _ID_CHARS - frozenset(".-")


class FieldError(ValueError):
    """A field is absent, of the wrong type, or outside its range."""


def device_id(value: Any) -> str:
    """§2: UTF-8, 1-64 bytes, `[a-z0-9][a-z0-9.-]*`."""
    if not isinstance(value, str) or not value:
        raise FieldError("device_id must be a non-empty string")
    if len(value.encode("utf-8")) > MAX_DEVICE_ID:
        raise FieldError(f"device_id is longer than {MAX_DEVICE_ID} bytes")
    if value[0] not in _ID_LEAD or set(value) - _ID_CHARS:
        raise FieldError(f"device_id is not [a-z0-9][a-z0-9.-]*: {value!r}")
    return value


def labels(value: Any) -> dict[str, str] | None:
    """§4.0: optional map, at most 32 entries, values at most 256 bytes.

    Key length is capped at 23 bytes by the codec itself, so only the count and
    the values need checking here.
    """
    if value is None:
        return None
    if not isinstance(value, dict) or len(value) > MAX_LABELS:
        raise FieldError("labels must be a map of at most 32 entries")
    for key, text in value.items():
        if not isinstance(text, str):
            raise FieldError(f"label {key!r} is not a string")
        if len(text.encode("utf-8")) > MAX_LABEL_VALUE:
            raise FieldError(f"label {key!r} is longer than {MAX_LABEL_VALUE} bytes")
    return value


def public_key(value: Any, what: str) -> bytes:
    if not isinstance(value, bytes) or len(value) != PK_LEN:
        raise FieldError(f"{what} must be {PK_LEN} bytes")
    return value


def signature(value: Any) -> bytes:
    if not isinstance(value, bytes) or len(value) != SIG_LEN:
        raise FieldError(f"sig must be {SIG_LEN} bytes")
    return value


def uint(value: Any, what: str) -> int:
    """A non-negative integer -- and *not* a bool.

    `isinstance(True, int)` is true in Python, so the obvious check accepts a
    CBOR boolean wherever a uint is required. The Go implementation switches on
    type and refuses it, so without this line the two disagree about whether
    `{"expires": true}` is a valid enroll body: the reference accepted it and
    Go rejected it with `decode`. Found while extracting this module.
    """
    if isinstance(value, bool) or not isinstance(value, int):
        raise FieldError(f"{what} must be a uint")
    if not 0 <= value <= MAX_UINT:
        raise FieldError(f"{what} is out of range")
    return value
