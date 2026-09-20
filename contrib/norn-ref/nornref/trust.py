"""The trust file: what a node is provisioned with out of band (SPEC.md §9).

The trust file is the only thing a verifier trusts a priori (guarantee G6, no
TOFU). Everything else — the current log key, the current witness policy — is
reached by replaying the log from the genesis this file pins.
"""

from __future__ import annotations

import base64
import hashlib
from typing import Any

from . import cbor, note

VERSION = 1

#: Crockford base32: no I, L, O or U, so nothing in a fingerprint is confusable.
CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

#: 10 bytes = 80 bits = 16 characters. Enough that an attacker cannot grind a
#: substitute trust file with the same fingerprint (threat A10).
FINGERPRINT_BYTES = 10
GROUP = 4

REQUIRED = ("version", "net", "origin", "name", "genesis_hash", "log_key", "log_urls",
            "witnesses", "policy")
OPTIONAL = ("anchor",)


class TrustError(ValueError):
    """The trust file is malformed or internally inconsistent."""


def origin_for(net: bytes) -> str:
    """`norn/<base32-lowercase(net) without padding>` (SPEC §2)."""
    return "norn/" + base64.b32encode(net).decode("ascii").rstrip("=").lower()


def build(net: bytes, name: str, genesis_hash: bytes, log_key: str,
          log_urls: list[str], witnesses: list[dict[str, str]], policy: str,
          anchor: dict[str, Any] | None = None) -> dict[str, Any]:
    """Assemble a trust file. Use `validate` before trusting one you were given."""
    doc: dict[str, Any] = {
        "version": VERSION,
        "net": net,
        "origin": origin_for(net),
        "name": name,
        "genesis_hash": genesis_hash,
        "log_key": log_key,
        "log_urls": list(log_urls),
        "witnesses": [dict(w) for w in witnesses],
        "policy": policy,
    }
    if anchor:
        doc["anchor"] = dict(anchor)
    return doc


def validate(doc: dict[str, Any]) -> None:
    """Raise TrustError unless the document is a usable trust anchor."""
    if not isinstance(doc, dict):
        raise TrustError("trust file must be a map")
    missing = [k for k in REQUIRED if k not in doc]
    if missing:
        raise TrustError(f"missing fields: {missing}")
    if set(doc) - set(REQUIRED) - set(OPTIONAL):
        raise TrustError("unknown fields")
    if doc["version"] != VERSION:
        raise TrustError(f"unsupported version: {doc['version']}")
    if not isinstance(doc["net"], bytes) or len(doc["net"]) != 16:
        raise TrustError("net must be 16 bytes")
    if doc["origin"] != origin_for(doc["net"]):
        raise TrustError("origin does not match net")
    if not isinstance(doc["genesis_hash"], bytes) or len(doc["genesis_hash"]) != 32:
        raise TrustError("genesis_hash must be 32 bytes")
    if not isinstance(doc["name"], str) or not 1 <= len(doc["name"].encode()) <= 64:
        raise TrustError("name must be 1-64 bytes")
    try:
        log_key = note.parse_vkey(doc["log_key"])
    except note.NoteError as exc:
        raise TrustError(f"log_key: {exc}") from exc
    # The note name binds the key to this network: a checkpoint signed by a key
    # named for another origin must not verify here (SPEC §9.1).
    if log_key.name != doc["origin"]:
        raise TrustError(
            f"log_key note name {log_key.name!r} does not match origin {doc['origin']!r}")
    # The log signs notes; a witness signs cosignatures. Different algorithms,
    # different key ids, and a file that confused them would name keys nobody
    # can use (c2sp.org/tlog-cosignature).
    if log_key.alg != note.ALG_ED25519:
        raise TrustError("log_key is a cosignature key; the log signs checkpoints")
    if not doc["log_urls"] or not all(isinstance(u, str) and u for u in doc["log_urls"]):
        raise TrustError("log_urls must be a non-empty list of strings")
    if not doc["witnesses"]:
        raise TrustError("at least one witness is required")
    seen: set[str] = set()
    for witness in doc["witnesses"]:
        if set(witness) - {"name", "key", "url"} or "name" not in witness or "key" not in witness:
            raise TrustError("each witness needs a name and a key")
        try:
            witness_key = note.parse_vkey(witness["key"])
            if witness_key.alg != note.ALG_COSIGNATURE:
                raise note.NoteError(
                    "a witness key is a cosignature key (c2sp.org/tlog-cosignature), "
                    "not a note key")
        except note.NoteError as exc:
            raise TrustError(f"witness {witness['name']}: {exc}") from exc
        if witness["name"] in seen:
            raise TrustError(f"duplicate witness name: {witness['name']}")
        seen.add(witness["name"])
    if not isinstance(doc["policy"], str) or "quorum" not in doc["policy"]:
        raise TrustError("policy must be tlog-policy text containing a quorum line")
    _check_policy_matches_witnesses(doc)


def encode(doc: dict[str, Any]) -> bytes:
    """Canonical bytes of the trust file — what the fingerprint covers."""
    return cbor.encode(doc)


def _crockford(raw: bytes) -> str:
    bits = int.from_bytes(raw, "big")
    width = len(raw) * 8 // 5
    return "".join(CROCKFORD[(bits >> (5 * i)) & 0x1F] for i in reversed(range(width)))


def fingerprint(doc: dict[str, Any]) -> str:
    """Human-comparable fingerprint: 80 bits, Crockford base32, 4 groups of 4."""
    digest = hashlib.sha256(encode(doc)).digest()[:FINGERPRINT_BYTES]
    text = _crockford(digest)
    return "-".join(text[i:i + GROUP] for i in range(0, len(text), GROUP))


def _toml_string(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
    return f'"{escaped}"'


def to_toml(doc: dict[str, Any]) -> str:
    """Deterministic TOML rendering, for humans. CBOR remains authoritative."""
    lines = [
        f"# Norn trust file for {doc['name']}",
        f"# fingerprint = {fingerprint(doc)}",
        "# Compare the fingerprint out of band before trusting this file.",
        "",
        f"version      = {doc['version']}",
        f"net          = {_toml_string(doc['net'].hex())}",
        f"origin       = {_toml_string(doc['origin'])}",
        f"name         = {_toml_string(doc['name'])}",
        f"genesis_hash = {_toml_string(doc['genesis_hash'].hex())}",
        f"log_key      = {_toml_string(doc['log_key'])}",
        "log_urls     = [" + ", ".join(_toml_string(u) for u in doc["log_urls"]) + "]",
        f"policy       = {_toml_string(doc['policy'])}",
    ]
    if "anchor" in doc:
        anchor = doc["anchor"]
        rendered = ", ".join(
            f"{k} = " + (_toml_string(v) if isinstance(v, str) else str(v))
            for k, v in sorted(anchor.items())
        )
        lines.append("anchor       = { " + rendered + " }")
    for witness in doc["witnesses"]:
        lines += ["", "[[witness]]", f"name = {_toml_string(witness['name'])}",
                  f"key  = {_toml_string(witness['key'])}"]
        if "url" in witness:
            lines.append(f"url  = {_toml_string(witness['url'])}")
    return "\n".join(lines) + "\n"


def _check_policy_matches_witnesses(doc: dict[str, Any]) -> None:
    """`witnesses` and `policy` must name the same parties (SPEC §9.1).

    `witnesses` is where a node learns a witness's name and address; `policy`
    is where it learns whether that witness counts. A file where the two differ
    configures a quorum over parties the node cannot reach, or lists parties
    nothing requires -- either way the operator believes they set something
    they did not.
    """
    named: dict[str, str] = {}
    for line in doc["policy"].splitlines():
        fields = line.split()
        if len(fields) >= 3 and fields[0] == "witness":
            named[fields[1]] = fields[2]
    for witness in doc["witnesses"]:
        if witness["name"] not in named:
            raise TrustError(
                f"witness {witness['name']} is listed but the policy never names it")
        if named.pop(witness["name"]) != witness["key"]:
            raise TrustError(
                f"witness {witness['name']} has one key in `witnesses` and another "
                "in the policy")
    for name in named:
        raise TrustError(f"the policy names witness {name}, which `witnesses` does not list")
