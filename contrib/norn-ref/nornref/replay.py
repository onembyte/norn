"""Replay: entries in, state out (SPEC.md §5).

A pure function. Every rule that decides whether an entry takes effect lives
here, one handler per entry type, so the reason codes in SPEC §5.1 map one to
one onto raised `Reject`s. Handlers never see raw bytes and never do crypto
beyond asking `_authorised` how many valid signatures of a role an entry has.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from . import cbor, entry, keys
from .state import DEFAULT_PARAMS, PARAM_KEYS, State

REASONS = (
    "decode", "unknown-type", "bad-genesis", "dup-genesis", "dup-entry", "after",
    "threshold", "no-device-sig", "dup-id", "dup-wg", "unknown-device", "not-active",
    "dup-key", "unknown-key", "root-invariant", "bad-thr",
)


class Reject(Exception):
    """An entry that does not take effect. `code` is one of REASONS."""

    def __init__(self, code: str) -> None:
        if code not in REASONS:  # pragma: no cover - guards typos in handlers
            raise AssertionError(f"unknown reason code: {code}")
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class Anchor:
    """The out-of-band trust anchor a verifier starts from (SPEC §9)."""

    net: bytes
    genesis_hash: bytes


# -- signature counting ---------------------------------------------------

def _valid_kids(env: dict[str, Any], role: str, known: dict[str, bytes]) -> set[str]:
    """Kids of `role` whose signature over this entry verifies under `known`."""
    out: set[str] = set()
    for sig in env.get("sigs", []):
        if sig.get("role") != role:
            continue
        public = known.get(sig.get("kid"))
        if public is not None and entry.verify_sig(env, sig, public):
            out.add(sig["kid"])
    return out


def _require(count: int, threshold: int) -> None:
    if count < threshold:
        raise Reject("threshold")


def _device_signed(env: dict[str, Any], device_pk: bytes) -> bool:
    return bool(_valid_kids(env, "device", {keys.kid(device_pk): device_pk}))


# -- envelope shape -------------------------------------------------------

_ID_OK = set("abcdefghijklmnopqrstuvwxyz0123456789.-")
_ENVELOPE_KEYS = {"v", "t", "net", "ts", "after", "body", "sigs"}
_REQUIRED_KEYS = {"v", "t", "net", "ts", "body", "sigs"}


def _check_envelope(env: Any, net: bytes) -> None:
    if not isinstance(env, dict):
        raise Reject("decode")
    if set(env) - _ENVELOPE_KEYS or not _REQUIRED_KEYS <= set(env):
        raise Reject("decode")
    if env["v"] != entry.VERSION or env["net"] != net:
        raise Reject("decode")
    if not isinstance(env["ts"], int) or not isinstance(env["body"], dict):
        raise Reject("decode")
    if not isinstance(env["sigs"], list):
        raise Reject("decode")
    seen: set[str] = set()
    for sig in env["sigs"]:
        if not isinstance(sig, dict) or set(sig) != {"kid", "role", "sig"}:
            raise Reject("decode")
        if sig["role"] not in entry.ROLES or len(sig["sig"]) != 64:
            raise Reject("decode")
        if sig["kid"] in seen:
            raise Reject("decode")
        seen.add(sig["kid"])
    if env["t"] not in entry.TYPES:
        raise Reject("unknown-type")


def _device_id(body: dict[str, Any]) -> str:
    value = body.get("device_id")
    if not isinstance(value, str) or not 1 <= len(value) <= 64:
        raise Reject("decode")
    if value[0] not in _ID_OK or value[0] in ".-" or set(value) - _ID_OK:
        raise Reject("decode")
    return value


MAX_LABELS = 32
MAX_LABEL_VALUE = 256


def _labels(body: dict[str, Any]) -> dict[str, str] | None:
    """Validate the optional `labels` map (SPEC §4.0 field constraints).

    Key length is already capped at 23 bytes by the codec, so only the count
    and the values need checking here.
    """
    labels = body.get("labels")
    if labels is None:
        return None
    if not isinstance(labels, dict) or len(labels) > MAX_LABELS:
        raise Reject("decode")
    for value in labels.values():
        if not isinstance(value, str) or len(value.encode("utf-8")) > MAX_LABEL_VALUE:
            raise Reject("decode")
    return labels


def _expires(body: dict[str, Any]) -> int | None:
    expires = body.get("expires")
    if expires is not None and not isinstance(expires, int):
        raise Reject("decode")
    return expires


def _pk(body: dict[str, Any], key: str) -> bytes:
    value = body.get(key)
    if not isinstance(value, bytes) or len(value) != 32:
        raise Reject("decode")
    return value


# -- handlers -------------------------------------------------------------

def _h_enroll(state: State, env: dict[str, Any], index: int) -> None:
    body = env["body"]
    device_id, device_pk, wg_pk = _device_id(body), _pk(body, "device_pk"), _pk(body, "wg_pk")
    labels, expires = _labels(body), _expires(body)
    if not _device_signed(env, device_pk):
        raise Reject("no-device-sig")
    _require(len(_valid_kids(env, "signer", state.signers)), state.signer_thr)
    if state.active_device(device_id):
        raise Reject("dup-id")
    if wg_pk in state.active_wg:
        raise Reject("dup-wg")
    state.add_device(device_id, device_pk, wg_pk, index, labels, expires)


def _h_rotate(state: State, env: dict[str, Any], index: int) -> None:
    body = env["body"]
    device_id, wg_pk = _device_id(body), _pk(body, "wg_pk")
    if device_id not in state.devices:
        raise Reject("unknown-device")
    device = state.active_device(device_id)
    if device is None:
        raise Reject("not-active")
    if not _device_signed(env, device["device_pk"]):
        raise Reject("no-device-sig")
    if state.params["rotate_needs_signer"]:
        _require(len(_valid_kids(env, "signer", state.signers)), state.signer_thr)
    if wg_pk in state.active_wg and state.active_wg[wg_pk] != device_id:
        raise Reject("dup-wg")
    new_device_pk = _pk(body, "device_pk") if "device_pk" in body else None
    # Proof of possession of the incoming identity key (D-032): a device that
    # installs a key it does not hold can never rotate again without a
    # signer-assisted re-enrolment. It holds both keys at this moment, so
    # requiring both signatures costs nothing.
    if new_device_pk is not None and not _device_signed(env, new_device_pk):
        raise Reject("no-device-sig")
    state.rotate_device(device_id, wg_pk, new_device_pk)


def _h_revoke(state: State, env: dict[str, Any], index: int) -> None:
    device_id = _device_id(env["body"])
    if device_id not in state.devices:
        raise Reject("unknown-device")
    device = state.active_device(device_id)
    if device is None:
        raise Reject("not-active")
    authorised = (
        len(_valid_kids(env, "signer", state.signers)) >= state.signer_thr
        or len(_valid_kids(env, "root", state.roots)) >= state.root_thr
        or _device_signed(env, device["device_pk"])
    )
    if not authorised:
        raise Reject("threshold")
    state.revoke_device(device_id, index)


def _h_signer_add(state: State, env: dict[str, Any], index: int) -> None:
    public = _pk(env["body"], "pk")
    kid = keys.kid(public)
    if kid in state.signers or kid in state.roots:
        raise Reject("dup-key")
    state.signers[kid] = public


def _h_signer_remove(state: State, env: dict[str, Any], index: int) -> None:
    kid = env["body"].get("kid")
    if kid not in state.signers:
        raise Reject("unknown-key")
    # Deliberately no quorum invariant here (D-028): removing a compromised
    # signer key must always be possible, including the last one. The network
    # then cannot enrol until roots add a signer, which is recoverable; an
    # unremovable stolen key is not.
    del state.signers[kid]


def _h_signer_thr(state: State, env: dict[str, Any], index: int) -> None:
    thr = env["body"].get("thr")
    if not isinstance(thr, int) or thr < 1 or thr > len(state.signers):
        raise Reject("bad-thr")
    state.signer_thr = thr


def _h_root_add(state: State, env: dict[str, Any], index: int) -> None:
    public = _pk(env["body"], "pk")
    kid = keys.kid(public)
    if kid in state.roots or kid in state.signers:
        raise Reject("dup-key")
    state.roots[kid] = public


def _h_root_remove(state: State, env: dict[str, Any], index: int) -> None:
    kid = env["body"].get("kid")
    if kid not in state.roots:
        raise Reject("unknown-key")
    remaining = len(state.roots) - 1
    if remaining < state.root_thr or remaining < 1:
        raise Reject("root-invariant")
    del state.roots[kid]


def _h_root_thr(state: State, env: dict[str, Any], index: int) -> None:
    thr = env["body"].get("thr")
    if not isinstance(thr, int) or thr < 1 or thr > len(state.roots):
        raise Reject("bad-thr")
    state.root_thr = thr


def _h_log_key(state: State, env: dict[str, Any], index: int) -> None:
    public = _pk(env["body"], "pk")
    overlap = env["body"].get("overlap")
    if not isinstance(overlap, int):
        raise Reject("decode")
    state.log_keys.append({"pk": public, "overlap": overlap, "since_index": index})


def _h_policy(state: State, env: dict[str, Any], index: int) -> None:
    text = env["body"].get("text")
    if not isinstance(text, str) or len(text.encode("utf-8")) > 4096:
        raise Reject("decode")
    state.policy = text


def _h_params(state: State, env: dict[str, Any], index: int) -> None:
    body = env["body"]
    if not body or set(body) - PARAM_KEYS:
        raise Reject("decode")
    for key, value in body.items():
        expected = type(DEFAULT_PARAMS.get(key, ""))
        if not isinstance(value, expected if key in DEFAULT_PARAMS else str):
            raise Reject("decode")
        state.params[key] = value


def _h_note(state: State, env: dict[str, Any], index: int) -> None:
    text = env["body"].get("text")
    if not isinstance(text, str) or len(text.encode("utf-8")) > 4096:
        raise Reject("decode")


Handler = Callable[[State, dict[str, Any], int], None]

#: Entry type -> handler. Governance types additionally need a root quorum,
#: which the loop enforces before dispatch (see ROOT_TYPES).
HANDLERS: dict[str, Handler] = {
    "enroll": _h_enroll, "rotate": _h_rotate, "revoke": _h_revoke,
    "signer_add": _h_signer_add, "signer_remove": _h_signer_remove, "signer_thr": _h_signer_thr,
    "root_add": _h_root_add, "root_remove": _h_root_remove, "root_thr": _h_root_thr,
    "log_key": _h_log_key, "policy": _h_policy, "params": _h_params, "note": _h_note,
}

#: Types that require a root quorum before their handler runs.
ROOT_TYPES = frozenset({"signer_add", "signer_remove", "signer_thr", "root_add",
                        "root_remove", "root_thr", "log_key", "policy", "params"})

#: Types whose authorisation the handler decides for itself.
SELF_AUTHORISED = frozenset({"enroll", "rotate", "revoke"})


# -- genesis --------------------------------------------------------------

def _apply_genesis(anchor: Anchor, env: dict[str, Any]) -> State:
    """Build the initial state. Raises Reject('bad-genesis') if unusable."""
    body = env["body"]
    roots, signers = body.get("roots"), body.get("signers")
    root_thr, signer_thr = body.get("root_thr"), body.get("signer_thr")
    if not isinstance(roots, list) or not isinstance(signers, list):
        raise Reject("bad-genesis")
    if not isinstance(root_thr, int) or not isinstance(signer_thr, int):
        raise Reject("bad-genesis")
    if any(not isinstance(p, bytes) or len(p) != 32 for p in roots + signers):
        raise Reject("bad-genesis")
    if not 1 <= root_thr <= len(roots) or not 1 <= signer_thr <= len(signers):
        raise Reject("bad-genesis")
    root_map = {keys.kid(p): p for p in roots}
    signer_map = {keys.kid(p): p for p in signers}
    if len(root_map) != len(roots) or len(signer_map) != len(signers):
        raise Reject("bad-genesis")
    if root_map.keys() & signer_map.keys():
        raise Reject("bad-genesis")
    if len(_valid_kids(env, "root", root_map)) < root_thr:
        raise Reject("bad-genesis")
    state = State(net=anchor.net, roots=root_map, root_thr=root_thr,
                  signers=signer_map, signer_thr=signer_thr)
    state.name = body.get("name", "") if isinstance(body.get("name"), str) else ""
    params = body.get("params") or {}
    if not isinstance(params, dict) or set(params) - PARAM_KEYS:
        raise Reject("bad-genesis")
    state.params.update(params)
    return state


# -- the loop -------------------------------------------------------------

def replay(anchor: Anchor, raw_entries: list[bytes]) -> State:
    """Replay `raw_entries` under `anchor`. Never raises; see `state.rejected`."""
    state = State(net=anchor.net)
    if not raw_entries:
        return state

    try:
        env = cbor.decode(raw_entries[0])
        _check_envelope(env, anchor.net)
        if env["t"] != "genesis":
            raise Reject("bad-genesis")
        if entry.leaf_hash(raw_entries[0]) != anchor.genesis_hash:
            raise Reject("bad-genesis")
        if "after" in env and env["after"] > 0:
            raise Reject("bad-genesis")
        state = _apply_genesis(anchor, env)
    except (cbor.ProfileError, Reject):
        state.rejected.append({"index": 0, "reason": "bad-genesis"})
        return state  # abort: without a genesis there is nothing to verify against

    state.size = 1
    seen = {entry.entry_hash(raw_entries[0])}

    for index, raw in enumerate(raw_entries[1:], start=1):
        try:
            digest = entry.entry_hash(raw)
            if digest in seen:
                raise Reject("dup-entry")
            # Recorded before validation: an exact entry is usable at most once,
            # accepted or not, so a rejected one cannot be re-inserted later to
            # take effect against a changed state (SPEC §5.1 step 1, D-031).
            seen.add(digest)
            env = cbor.decode(raw)
            _check_envelope(env, anchor.net)
            if env["t"] == "genesis":
                raise Reject("dup-genesis")
            if env.get("after", 0) > index:
                raise Reject("after")
            if env["t"] in ROOT_TYPES:
                _require(len(_valid_kids(env, "root", state.roots)), state.root_thr)
            elif env["t"] == "note":
                if not (_valid_kids(env, "signer", state.signers)
                        or _valid_kids(env, "root", state.roots)):
                    raise Reject("threshold")
            HANDLERS[env["t"]](state, env, index)
        except cbor.ProfileError:
            state.rejected.append({"index": index, "reason": "decode"})
        except Reject as exc:
            state.rejected.append({"index": index, "reason": exc.code})
        finally:
            state.size = index + 1

    return state
