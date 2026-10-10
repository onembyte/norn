"""The trust file: what a node is provisioned with out of band (SPEC.md §9).

The trust file is the only thing a verifier trusts a priori (guarantee G6, no
TOFU). Everything else — the current log key, the current witness policy — is
reached by replaying the log from the genesis this file pins.
"""

from __future__ import annotations

import base64
import hashlib
from typing import Any

from . import cbor, keys, note

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


#: SPEC §9.1. A trust file is keys, URLs, a witness list and a policy: it does
#: not wrap an entry and nothing in it scales with the log, so it does not
#: share `MAX_ENTRY_BYTES`. Stated as a number in §9.1 since cold gate run 8
#: (D3), which found all three artifact bounds promised and none given.
MAX_TRUST_BYTES = 65536


def parse(raw: bytes) -> dict[str, Any]:
    """Decode and validate a trust file from its bytes.

    The length is checked *before* decoding, so an oversized file is refused
    without anything it declares being allocated -- the same discipline §4.0
    applies to entries.
    """
    from . import cbor
    if len(raw) > MAX_TRUST_BYTES:
        raise TrustError(f"trust file exceeds {MAX_TRUST_BYTES} bytes")
    doc = cbor.decode(raw, max_bytes=MAX_TRUST_BYTES)
    validate(doc)
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
    # A trust file admits keys, not just verifier-key syntax. Keep the §3.1
    # check here: parse_vkey also reads policy entries, whose witness keys
    # are not among the admission points that item 2 names.
    if not keys.valid_point(log_key.public):
        raise TrustError("log_key must be a valid Ed25519 point")
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
        # A witness must use the same order-L predicate as the log; otherwise
        # two verifiers could disagree about the cosignature it contributes.
        if not keys.valid_point(witness_key.public):
            raise TrustError(f"witness {witness['name']}: key must be a valid Ed25519 point")
        if not 1 <= len(witness["name"].encode()) <= 64:
            # Bounded like the network name. Neither implementation capped this
            # and no file in the suite was long enough to tell (run 8, D22).
            raise TrustError("a witness name must be 1-64 bytes")
        if witness["name"] in seen:
            raise TrustError(f"duplicate witness name: {witness['name']}")
        seen.add(witness["name"])
    if not isinstance(doc["policy"], str) or "quorum" not in doc["policy"]:
        raise TrustError("policy must be tlog-policy text containing a quorum line")
    _check_policy_matches_witnesses(doc)
    # The policy's `log` line is informational -- Norn takes the log key from
    # `log_key` -- but a file whose two halves name different logs is the same
    # operator error the witness correspondence rule exists to catch.
    for line in doc["policy"].split("\n"):
        fields = line.split()
        if len(fields) >= 2 and fields[0] == "log" and fields[1] != doc["log_key"]:
            raise TrustError("the policy's log line names a different log than log_key")
    if "anchor" in doc:
        anchor = doc["anchor"]
        # All three members when present: Go required them and this did not.
        if not isinstance(anchor, dict) or set(anchor) != {"type", "max_lag", "mode"}:
            raise TrustError("anchor needs exactly type, max_lag and mode")
        if not isinstance(anchor["type"], str):
            raise TrustError("anchor.type must be text")
        if isinstance(anchor["max_lag"], bool) or not isinstance(anchor["max_lag"], int):
            raise TrustError("anchor.max_lag must be a uint of seconds")
        # An unknown `type` is ignorable -- anchoring is advisory (D-009) -- but
        # an unknown `mode` is not: guessing what an unrecognised enforcement
        # mode means is how a node enforces something nobody asked for.
        if anchor["mode"] != "advisory":
            raise TrustError(f"anchor.mode {anchor['mode']!r} is not one this version defines")


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
    # Correspondence is about *which* names appear, not how many times: the
    # uniqueness rule owns multiplicity. This used to `pop` each name as it
    # matched, so a file listing one witness twice was refused here -- meaning
    # an implementation missing the uniqueness rule was saved by this one.
    covered: set[str] = set()
    for witness in doc["witnesses"]:
        if witness["name"] not in named:
            raise TrustError(
                f"witness {witness['name']} is listed but the policy never names it")
        if named[witness["name"]] != witness["key"]:
            raise TrustError(
                f"witness {witness['name']} has one key in `witnesses` and another "
                "in the policy")
        covered.add(witness["name"])
    for name in named:
        if name not in covered:
            raise TrustError(
                f"the policy names witness {name}, which `witnesses` does not list")
