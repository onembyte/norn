"""Replayed network state (SPEC.md §5).

State owns its own shape and its canonical serialisation, and nothing else: it
has no opinion about which entries are valid. That decision belongs to `replay`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from . import canonjson

DEFAULT_PARAMS: dict[str, Any] = {
    "checkpoint_interval": 60,
    "staleness": 600,
    "mmd": 60,
    "rotate_needs_signer": False,
}

PARAM_KEYS = frozenset(DEFAULT_PARAMS) | {"witness_policy"}

ACTIVE, REVOKED = "active", "revoked"


@dataclass
class State:
    """The result of replaying a log. Mutated only by `replay`'s handlers."""

    net: bytes
    roots: dict[str, bytes] = field(default_factory=dict)
    root_thr: int = 0
    signers: dict[str, bytes] = field(default_factory=dict)
    signer_thr: int = 0
    devices: dict[str, dict[str, Any]] = field(default_factory=dict)
    active_wg: dict[bytes, str] = field(default_factory=dict)
    params: dict[str, Any] = field(default_factory=lambda: dict(DEFAULT_PARAMS))
    log_keys: list[dict[str, Any]] = field(default_factory=list)
    policy: str = ""
    name: str = ""
    rejected: list[dict[str, Any]] = field(default_factory=list)
    size: int = 0

    # -- device helpers ---------------------------------------------------

    def active_device(self, device_id: str) -> dict[str, Any] | None:
        device = self.devices.get(device_id)
        return device if device and device["status"] == ACTIVE else None

    def add_device(self, device_id: str, device_pk: bytes, wg_pk: bytes,
                   index: int, labels: dict[str, str] | None, expires: int | None) -> None:
        self.devices[device_id] = {
            "device_pk": device_pk,
            "wg_pk": wg_pk,
            "status": ACTIVE,
            "since_index": index,
            "labels": dict(labels or {}),
            "expires": expires or 0,
        }
        self.active_wg[wg_pk] = device_id

    def rotate_device(self, device_id: str, wg_pk: bytes, device_pk: bytes | None) -> None:
        device = self.devices[device_id]
        self.active_wg.pop(device["wg_pk"], None)
        device["wg_pk"] = wg_pk
        if device_pk is not None:
            device["device_pk"] = device_pk
        self.active_wg[wg_pk] = device_id

    def revoke_device(self, device_id: str, index: int) -> None:
        device = self.devices[device_id]
        device["status"] = REVOKED
        device["since_index"] = index
        self.active_wg.pop(device["wg_pk"], None)

    # -- serialisation ----------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        """Canonical, JSON-ready view. Byte strings become hex (SPEC §12)."""
        return {
            "name": self.name,
            "net": self.net,
            "size": self.size,
            "root_thr": self.root_thr,
            "signer_thr": self.signer_thr,
            "roots": dict(sorted(self.roots.items())),
            "signers": dict(sorted(self.signers.items())),
            "params": dict(sorted(self.params.items())),
            "policy": self.policy,
            "log_keys": self.log_keys,
            "devices": {
                device_id: dict(sorted(device.items()))
                for device_id, device in sorted(self.devices.items())
            },
            "active_wg": {pk.hex(): device_id for pk, device_id in sorted(self.active_wg.items())},
            "rejected": self.rejected,
        }

    def to_json(self) -> str:
        return canonjson.dumps(self.to_dict())
