"""The canonical vector fixture: one valid entry per type (SPEC.md §12).

Kept separate from the generator script so tests can import the fixture without
writing files.
"""

from __future__ import annotations

from typing import Any

from . import entry, keys

NET = bytes.fromhex("6e6f726e2d746573746e65742d303031")  # "norn-testnet-001"
T0 = 1_760_000_000

ROOTS = ["root1", "root2", "root3"]
SIGNERS = ["signer1", "signer2"]
DEVICES = ["nas", "laptop", "pi-cam"]

KEYS: dict[str, keys.Ed25519] = {
    name: keys.Ed25519.from_name(name)
    for name in ROOTS + SIGNERS + DEVICES + ["signer3", "root4", "logkey", "logkey2"]
}
WG: dict[str, bytes] = {name: keys.x25519_public(name) for name in DEVICES + ["laptop2", "rogue"]}


def _signed(env: dict[str, Any], signers: list[tuple[str, str]]) -> dict[str, Any]:
    for name, role in signers:
        entry.sign(env, KEYS[name], role)
    return env


def genesis(after: int | None = None) -> dict[str, Any]:
    env = entry.new("genesis", NET, ts=T0, after=after, body={
        "name": "norn-testnet",
        "roots": [KEYS[n].public for n in ROOTS],
        "root_thr": 2,
        "signers": [KEYS[n].public for n in SIGNERS],
        "signer_thr": 1,
        "params": {"checkpoint_interval": 60, "staleness": 600, "mmd": 60,
                   "rotate_needs_signer": False},
    })
    return _signed(env, [("root1", "root"), ("root2", "root")])


def enroll(device: str, ts_offset: int, after: int | None = None,
           labels: dict[str, str] | None = None, expires: int | None = None,
           signers: list[tuple[str, str]] | None = None) -> dict[str, Any]:
    body: dict[str, Any] = {
        "device_id": device,
        "device_pk": KEYS[device].public,
        "wg_pk": WG[device],
    }
    if labels:
        body["labels"] = labels
    if expires is not None:
        body["expires"] = expires
    env = entry.new("enroll", NET, ts=T0 + ts_offset, after=after, body=body)
    return _signed(env, signers or [(device, "device"), ("signer1", "signer")])


def catalogue() -> list[tuple[str, dict[str, Any]]]:
    """One valid entry per type, in a plausible order. Names become file names."""
    out: list[tuple[str, dict[str, Any]]] = [
        ("00-genesis", genesis()),
        ("01-enroll", enroll("nas", 60, after=1)),
        ("02-enroll-labels", enroll("laptop", 120, after=2,
                                    labels={"ip": "10.9.0.2/32", "endpoint": "192.0.2.10:51820"})),
        ("03-enroll-expires", enroll("pi-cam", 180, after=3, expires=T0 + 2_592_000)),
        ("04-rotate", _signed(entry.new("rotate", NET, ts=T0 + 240, after=4, body={
            "device_id": "laptop", "wg_pk": WG["laptop2"]}), [("laptop", "device")])),
        ("05-revoke", _signed(entry.new("revoke", NET, ts=T0 + 300, after=5, body={
            "device_id": "pi-cam", "reason": "decommissioned"}), [("signer1", "signer")])),
        ("06-signer_add", _signed(entry.new("signer_add", NET, ts=T0 + 360, after=6, body={
            "pk": KEYS["signer3"].public}), [("root1", "root"), ("root2", "root")])),
        ("07-signer_thr", _signed(entry.new("signer_thr", NET, ts=T0 + 420, after=7, body={
            "thr": 2}), [("root1", "root"), ("root2", "root")])),
        ("08-signer_remove", _signed(entry.new("signer_remove", NET, ts=T0 + 480, after=8, body={
            "kid": KEYS["signer2"].id}), [("root1", "root"), ("root3", "root")])),
        ("09-root_add", _signed(entry.new("root_add", NET, ts=T0 + 540, after=9, body={
            "pk": KEYS["root4"].public}), [("root1", "root"), ("root2", "root")])),
        ("10-root_thr", _signed(entry.new("root_thr", NET, ts=T0 + 600, after=10, body={
            "thr": 3}), [("root1", "root"), ("root2", "root")])),
        ("11-root_remove", _signed(entry.new("root_remove", NET, ts=T0 + 660, after=11, body={
            "kid": KEYS["root4"].id}), [("root1", "root"), ("root2", "root"), ("root3", "root")])),
        ("12-log_key", _signed(entry.new("log_key", NET, ts=T0 + 720, after=12, body={
            "pk": KEYS["logkey2"].public, "overlap": 2_592_000}),
            [("root1", "root"), ("root2", "root"), ("root3", "root")])),
        ("13-policy", _signed(entry.new("policy", NET, ts=T0 + 780, after=13, body={
            "text": "log norn+11111111+AAAA\nwitness pi norn+22222222+BBBB\n"
                    "witness vps norn+33333333+CCCC\ngroup home 2 pi vps\nquorum home\n"}),
            [("root1", "root"), ("root2", "root"), ("root3", "root")])),
        ("14-params", _signed(entry.new("params", NET, ts=T0 + 840, after=14, body={
            "staleness": 900, "rotate_needs_signer": True}),
            [("root1", "root"), ("root2", "root"), ("root3", "root")])),
        ("15-note", _signed(entry.new("note", NET, ts=T0 + 900, after=15, body={
            "text": "quarterly key review completed"}), [("signer1", "signer")])),
    ]
    return out
