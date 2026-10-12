"""Replayed network state (SPEC.md §5).

State owns its own shape and its canonical serialisation, and nothing else: it
has no opinion about which entries are valid. That decision belongs to `replay`.
"""

from __future__ import annotations

import ipaddress

from dataclasses import dataclass, field
from typing import Any

from . import canonjson

DEFAULT_PARAMS: dict[str, Any] = {
    "checkpoint_interval": 60,
    "staleness": 600,
    "mmd": 60,
    "rotate_needs_signer": False,
    "routes": "granted",
}

#: The one text-valued parameter has a closed value set (SPEC 4.5, D-073):
#: two readers must never hold two readings of whether routes are bounded.
ROUTES_VALUES = frozenset({"granted", "advisory"})

#: Exactly the keys of DEFAULT_PARAMS. The witness policy deliberately has one
#: home only -- the `policy` entry type (D-034) -- because two places to set the
#: quorum that guards the log is how two verifiers come to disagree about it.
PARAM_KEYS = frozenset(DEFAULT_PARAMS)

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
    versions: dict[str, int] = field(default_factory=lambda: dict.fromkeys(
        ("signers", "roots", "params", "policy", "log_key"), 0))

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
            "version": index,
            "labels": dict(labels or {}),
            "expires": expires or 0,
        }
        self.active_wg[wg_pk] = device_id

    def rotate_device(self, device_id: str, wg_pk: bytes, device_pk: bytes | None, index: int) -> None:
        device = self.devices[device_id]
        self.active_wg.pop(device["wg_pk"], None)
        device["version"] = index
        device["wg_pk"] = wg_pk
        if device_pk is not None:
            device["device_pk"] = device_pk
        self.active_wg[wg_pk] = device_id

    def revoke_device(self, device_id: str, index: int) -> None:
        device = self.devices[device_id]
        device["version"] = index
        device["status"] = REVOKED
        device["since_index"] = index
        self.active_wg.pop(device["wg_pk"], None)

    # -- serialisation ----------------------------------------------------

    def grant(self, device_id: str) -> list[str]:
        """The device's grant (SPEC 4.0, D-073): the prefixes its `ip` label
        carries, each masked, duplicates removed, sorted as text.

        Parsed as a whole: a label with one part that is not a prefix is no
        grant at all, not the parts that did parse -- a bound with a hole in
        it is not the bound the signers signed. An IPv4-mapped IPv6 prefix is
        no grant either, because the two implementations' text forms of one
        differ, and a grant is compared as text.
        """
        label = self.devices[device_id].get("labels", {}).get("ip")
        if not isinstance(label, str):
            return []
        out: set[str] = set()
        for part in label.split(","):
            try:
                network = ipaddress.ip_network(part.strip(), strict=False)
            except ValueError:
                return []
            if network.version == 6 and network.network_address.ipv4_mapped is not None:
                return []
            out.add(network.with_prefixlen)
        return sorted(out)

    def proven(self, at: int) -> list[str]:
        """The devices a node would admit at evaluation time `at` (SPEC §5.3).

        `at` is the checkpoint's quorum time, never a wall clock, and `0` means
        there is no clock at all -- no instant satisfies the witness policy, so
        expiry is not judged and every active device keeps the status replay
        gave it. A device is expired exactly when `expires != 0 and expires <=
        at`, so an `expires` equal to `at` has passed.
        """
        out = []
        for device_id, device in sorted(self.devices.items()):
            if device["status"] != "active":
                continue
            expires = device.get("expires") or 0
            if at and expires and expires <= at:
                continue
            out.append(device_id)
        return out

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
            "versions": self.versions,
            "rejected": self.rejected,
        }

    def to_json(self) -> str:
        return canonjson.dumps(self.to_dict())

    def previous(self, kind: str, device_id: str | None = None) -> int | None:
        """The predecessor of the object a fresh entry changes (SPEC 4.4)."""
        if kind in ("enroll", "rotate", "revoke"):
            device = self.devices.get(device_id)
            return device["version"] if device else None
        if kind.startswith("signer_"):
            return self.versions["signers"]
        if kind.startswith("root_"):
            return self.versions["roots"]
        return self.versions.get(kind)
