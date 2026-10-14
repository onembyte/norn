"""D-077 (3): each stale vector in `log-cas/` is the attack it is named for.

`test_cas.py` proves the shipped refusals and that each one is the entry's
only fault. This file proves the other half, without which a stale vector
could be any `prev` mismatch: replayed by a reader that does not check
`prev` -- every Norn reader before D-077 -- the withheld entry does exactly the
damage its name says, and replayed under §5.1 it is refused as `stale-state`
and does none. The stories are read from the shipped files, not rebuilt from
the fixture, because the shipped files are what a second implementer has.
"""
from __future__ import annotations

import json
import unittest
from pathlib import Path
from unittest import mock

from nornref import fixture, replay

ROOT = Path(__file__).resolve().parents[3] / "testdata" / "vectors" / "log-cas"


def _load() -> tuple[replay.Anchor, list[bytes], dict[str, int]]:
    manifest = json.loads((ROOT / "manifest.json").read_text())
    a = manifest["anchor"]
    anchor = replay.Anchor(bytes.fromhex(a["net"]), bytes.fromhex(a["genesis_hash"]),
                           a["log_key"], a["policy"])
    entries = [(ROOT / f"{e['name']}.cbor").read_bytes() for e in manifest["entries"]]
    index = {e["name"]: e["index"] for e in manifest["entries"]}
    return anchor, entries, index


def _without_prev(anchor: replay.Anchor, entries: list[bytes]):
    """Replay as a reader that ignores `prev` entirely."""
    with mock.patch.object(replay, "_check_prev", lambda env, version: None):
        return replay.replay(anchor, entries)


class EachStaleVectorIsTheAttackItNames(unittest.TestCase):
    def setUp(self) -> None:
        self.anchor, self.entries, self.index = _load()

    def story(self, name: str):
        """The log up to and including the released entry, read both ways."""
        upto = self.entries[:self.index[name] + 1]
        guarded = replay.replay(self.anchor, upto)
        rejected = {r["index"]: r["reason"] for r in guarded.rejected}
        self.assertEqual(rejected.get(self.index[name]), "stale-state",
                         f"{name} is not refused as stale-state under §5.1")
        return guarded, _without_prev(self.anchor, upto)

    def test_a_withheld_rotation_would_set_the_device_back_to_a_stale_key(self):
        guarded, unguarded = self.story("03-stale-withheld-rotate")
        self.assertEqual(guarded.devices["nas"]["wg_pk"], fixture.WG["nas2"])
        self.assertEqual(unguarded.devices["nas"]["wg_pk"], fixture.WG["nas"],
                         "without prev the withheld rotation does not revert the key")

    def test_a_second_signed_add_would_reinstate_a_removed_signer(self):
        spare = fixture.KEYS["spare"].id
        guarded, unguarded = self.story("06-stale-reinstated-signer")
        self.assertNotIn(spare, guarded.signers)
        self.assertIn(spare, unguarded.signers,
                      "without prev the removed signer does not come back")

    def test_a_withheld_log_key_would_supersede_its_own_successor(self):
        # Before D-078 a reader without prev made the superseded key the newest
        # again. Learned keys are never retired, so that key is still active,
        # and since D-078 (3) re-publishing it is `dup-key` for any reader: the
        # story is closed twice, and the vector's code stays `stale-state`.
        guarded, unguarded = self.story("09-stale-superseded-log-key")
        self.assertEqual(guarded.log_keys[-1]["pk"], fixture.KEYS["logkey3"].public)
        self.assertEqual(unguarded.log_keys[-1]["pk"], fixture.KEYS["logkey3"].public)
        self.assertEqual({r["index"]: r["reason"] for r in unguarded.rejected}[self.index["09-stale-superseded-log-key"]],
                         "dup-key", "without prev the re-published log key is not dup-key")

    def test_a_withheld_revoke_would_revoke_the_re_enrolled_device(self):
        guarded, unguarded = self.story("12-stale-revoke-reenrolled-device")
        self.assertEqual(guarded.devices["nas"]["status"], "active")
        self.assertEqual(unguarded.devices["nas"]["status"], "revoked",
                         "without prev the re-enrolled device is not revoked")

    def test_a_withheld_enroll_would_re_admit_a_twice_revoked_device(self):
        guarded, unguarded = self.story("16-stale-enroll-after-second-revocation")
        self.assertEqual(guarded.devices["nas"]["status"], "revoked")
        self.assertEqual(unguarded.devices["nas"]["status"], "active",
                         "without prev the revoked device is not re-admitted")


if __name__ == "__main__":
    unittest.main()
