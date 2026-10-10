"""Enrollment requests (SPEC §16): what a device hands a signer.

A request is the only Norn format produced by a *device*, and the only one that
crosses an untrusted channel before anyone has decided to trust it. Two
consequences shape this module:

* nothing here consults any state, because a request is not a log entry and
  never becomes one -- a signer reads it and writes an `enroll` entry (§4.3);
* `decode` validates structure and *nothing more*. Believing a request means
  calling `check`, which verifies the signature. The split is deliberate: it
  makes "I displayed an unverified request" a visible mistake in the caller.
"""

from __future__ import annotations

from typing import Any

from . import bech32m, cbor, fields, keys

VERSION = 1
DOMAIN = "norn/enroll-request/v1"
PREIMAGE_PREFIX = DOMAIN.encode("ascii") + b"\n"
HRP = "norn"
NET_LEN = 16

REQUIRED = frozenset({"v", "ts", "net", "sig", "wg_pk", "device_id", "device_pk"})
OPTIONAL = frozenset({"labels", "expires"})


class RequestError(ValueError):
    """The request is malformed, or its signature does not verify."""


def new(net: bytes, device_id: str, device_pk: bytes, wg_pk: bytes, ts: int,
        labels: dict[str, str] | None = None, expires: int | None = None) -> dict[str, Any]:
    """Build an unsigned request. Field rules are checked here, not at signing."""
    req: dict[str, Any] = {"v": VERSION, "net": net, "device_id": device_id,
                           "device_pk": device_pk, "wg_pk": wg_pk, "ts": ts}
    if labels is not None:
        req["labels"] = labels
    if expires is not None:
        req["expires"] = expires
    _validate(req, signed=False)
    return req


def preimage(req: dict[str, Any]) -> bytes:
    """Bytes the signature covers: the domain prefix and the request sans `sig`.

    The prefix differs from §4.2's, so a device signature over a request can
    never be replayed as a signature over an entry.
    """
    return PREIMAGE_PREFIX + cbor.encode({k: v for k, v in req.items() if k != "sig"})


def sign(req: dict[str, Any], key: keys.Ed25519, strict: bool = True) -> dict[str, Any]:
    """Sign in place with the device key.

    `strict=False` signs with a key that is not the request's `device_pk`, which
    is useful only for building negative vectors: the result is a request whose
    signature must not verify.
    """
    if strict and key.public != req.get("device_pk"):
        raise RequestError("the signing key is not the request's device_pk")
    req["sig"] = key.sign(preimage(req))
    return req


def encode(req: dict[str, Any]) -> bytes:
    return cbor.encode(req)


def to_text(req: dict[str, Any]) -> str:
    """The bech32m form a device prints as text and as a QR (SPEC §16.2)."""
    return bech32m.encode(HRP, encode(req))


def decode(raw: bytes) -> dict[str, Any]:
    """Decode and validate structure. Does **not** verify the signature."""
    if len(raw) > cbor.MAX_ENTRY_BYTES:
        raise RequestError("request is larger than MAX_ENTRY_BYTES")
    try:
        req = cbor.decode(raw)
    except cbor.ProfileError as exc:
        raise RequestError(f"not deterministic CBOR: {exc}") from None
    _validate(req, signed=True)
    return req


def decode_text(text: str) -> dict[str, Any]:
    try:
        hrp, raw = bech32m.decode(text)
    except bech32m.Bech32Error as exc:
        raise RequestError(f"not a bech32m request: {exc}") from None
    if hrp != HRP:
        raise RequestError(f"wrong human-readable part: {hrp!r}, want {HRP!r}")
    return decode(raw)


def verify(req: dict[str, Any]) -> bool:
    """Is `sig` a valid signature by `device_pk` over the preimage?"""
    public, sig = req.get("device_pk"), req.get("sig")
    if not isinstance(public, bytes) or not isinstance(sig, bytes):
        return False
    return keys.verify(public, preimage(req), sig)


def check(req: dict[str, Any], net: bytes | None = None) -> dict[str, Any]:
    """Validate, verify the signature, and optionally pin the network.

    This is the function a signer calls before showing anything to a human:
    `ENROLLMENT.md` part 7 rule 1 is *what you sign is what you see*, and a
    request displayed before its signature is checked is a request whose text
    an attacker chose.
    """
    _validate(req, signed=True)
    if net is not None and req["net"] != net:
        raise RequestError("request is for another network")
    if not verify(req):
        raise RequestError("signature does not verify under device_pk")
    return req


def _validate(req: Any, signed: bool) -> None:
    if not isinstance(req, dict):
        raise RequestError("a request is a CBOR map")
    required = REQUIRED if signed else REQUIRED - {"sig"}
    present = set(req)
    missing = required - present
    if missing:
        raise RequestError(f"missing: {', '.join(sorted(missing))}")
    unknown = present - REQUIRED - OPTIONAL
    if unknown:
        raise RequestError(f"unknown keys: {', '.join(sorted(unknown))}")

    try:
        if fields.uint(req["v"], "v") != VERSION:
            raise RequestError(f"unsupported version: {req['v']}")
        net = req["net"]
        if not isinstance(net, bytes) or len(net) != NET_LEN:
            raise RequestError("net must be 16 bytes")
        ts = fields.uint(req["ts"], "ts")
        fields.device_id(req["device_id"])
        fields.public_key(req["device_pk"], "device_pk")
        # Admission precedes proof of possession: replay must report decode,
        # not no-device-sig, for a key §3.1 refuses. wg_pk is X25519, so the
        # Ed25519 point predicate does not apply to it.
        if not keys.valid_point(req["device_pk"]):
            raise RequestError("device_pk must be a valid Ed25519 point")
        fields.public_key(req["wg_pk"], "wg_pk")
        fields.labels(req.get("labels"))
        if "expires" in req and fields.uint(req["expires"], "expires") <= ts:
            raise RequestError("expires must be after ts")
        if signed:
            fields.signature(req["sig"])
    except fields.FieldError as exc:
        raise RequestError(str(exc)) from None
