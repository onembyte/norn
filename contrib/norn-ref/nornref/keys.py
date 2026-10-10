"""Key material for the reference implementation (SPEC.md §3).

Seeds are derived from names so every vector is reproducible from this file
alone. These are TEST keys: the derivation is deliberately public.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from nacl.bindings import crypto_core_ed25519_is_valid_point
from nacl.signing import SigningKey, VerifyKey
from nacl.exceptions import BadSignatureError

SEED_PREFIX = b"norn/testvector/v1\n"
L = 2**252 + 27742317777372353535851937790883648493


def kid(public: bytes) -> str:
    """Key id: lowercase hex of SHA-256(pk)[0:8] (SPEC §4.0)."""
    return hashlib.sha256(public).digest()[:8].hex()


@dataclass(frozen=True)
class Ed25519:
    """An Ed25519 keypair. `public` is the 32-byte verify key."""

    seed: bytes
    public: bytes

    @classmethod
    def from_seed(cls, seed: bytes) -> "Ed25519":
        if len(seed) != 32:
            raise ValueError("seed must be 32 bytes")
        return cls(seed, bytes(SigningKey(seed).verify_key))

    @classmethod
    def from_name(cls, name: str) -> "Ed25519":
        return cls.from_seed(hashlib.sha256(SEED_PREFIX + name.encode("utf-8")).digest())

    @property
    def id(self) -> str:
        return kid(self.public)

    def sign(self, message: bytes) -> bytes:
        return SigningKey(self.seed).sign(message).signature


def valid_point(b: bytes) -> bool:
    """SPEC §3.1 item 1: a canonical encoding of a point of order exactly L."""
    # Libsodium checks canonical encoding, the curve, small order and main
    # subgroup membership. A mixed-order point is not a valid key even when
    # its prime-order component is honest: the two verification equations
    # disagree there, and no honest key [s]B or R = [r]B has such a component.
    return isinstance(b, bytes) and len(b) == 32 and crypto_core_ed25519_is_valid_point(b)


def verify(public: bytes, message: bytes, signature: bytes) -> bool:
    """NORN-ED25519-v1 verification; False rather than an exception on failure."""
    if len(public) != 32 or len(signature) != 64:
        return False
    # Both A and R must be valid points, whatever the library's signature
    # verifier accepts. With both of order L, the cofactored and cofactorless
    # equations agree, so every conforming verifier gives the same answer.
    if not valid_point(public):
        return False
    if not valid_point(signature[:32]):
        return False
    # S must be below L, not reduced and not merely with its top bits clear.
    # Reducing it would admit S + L and give one signature multiple encodings.
    if int.from_bytes(signature[32:], "little") >= L:
        return False
    try:
        VerifyKey(public).verify(message, signature)
    except (BadSignatureError, ValueError):
        return False
    return True


def x25519_public(name: str) -> bytes:
    """A deterministic 32-byte X25519 public key for vectors (WireGuard peer key)."""
    from nacl.public import PrivateKey

    seed = hashlib.sha256(SEED_PREFIX + b"wg/" + name.encode("utf-8")).digest()
    return bytes(PrivateKey(seed).public_key)
