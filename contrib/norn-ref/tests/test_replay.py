"""RED first: replay is a pure function (anchor, entries) -> state (SPEC §5)."""
import unittest

from nornref import cbor, entry, fixture, keys, replay
from nornref.state import State


def anchor_for(log):
    """Trust anchor derived from the genesis of a log (0.5 builds the real file)."""
    return replay.Anchor(net=fixture.NET, genesis_hash=entry.leaf_hash(log[0]))


class HappyPath(unittest.TestCase):
    def setUp(self):
        self.items = fixture.log()
        self.raw = [item.raw for item in self.items]
        self.state = replay.replay(anchor_for(self.raw), self.raw)

    def test_is_pure(self):
        again = replay.replay(anchor_for(self.raw), self.raw)
        self.assertEqual(self.state.to_json(), again.to_json())

    def test_every_expected_rejection_happened_and_nothing_else(self):
        expected = [(i, it.reason) for i, it in enumerate(self.items) if it.reason]
        self.assertEqual([(r["index"], r["reason"]) for r in self.state.rejected], expected)

    def test_covers_every_reason_code_except_bad_genesis(self):
        cas = fixture.cas_log()
        extra = replay.replay(fixture.anchor_for([it.raw for it in cas]), [it.raw for it in cas])
        seen = {r["reason"] for r in self.state.rejected + extra.rejected}
        self.assertEqual(seen, set(replay.REASONS) - {"bad-genesis"})

    def test_governance_applied(self):
        self.assertEqual(self.state.signer_thr, 2)
        self.assertEqual(self.state.root_thr, 3)
        self.assertEqual(len(self.state.roots), 3)
        self.assertIn(keys.kid(fixture.KEYS["signer3"].public), self.state.signers)
        self.assertNotIn(keys.kid(fixture.KEYS["signer2"].public), self.state.signers)

    def test_rotate_replaces_the_key(self):
        nas = self.state.devices["nas"]
        self.assertEqual(nas["status"], "active")
        self.assertEqual(nas["wg_pk"], fixture.WG["nas2"])
        self.assertNotIn(fixture.WG["nas"], self.state.active_wg)

    def test_a_device_may_revoke_itself(self):
        self.assertEqual(self.state.devices["laptop"]["status"], "revoked")
        self.assertNotIn(fixture.WG["laptop2"], self.state.active_wg)

    def test_device_id_may_be_reused_after_revocation(self):
        pi = self.state.devices["pi-cam"]
        self.assertEqual(pi["status"], "active", "re-enrolled after revoke")
        self.assertEqual(pi["since_index"], 33)
        self.assertEqual(self.state.active_wg[fixture.WG["pi-cam"]], "pi-cam")

    def test_active_wg_index_matches_active_devices(self):
        expected = {d["wg_pk"]: i for i, d in self.state.devices.items() if d["status"] == "active"}
        self.assertEqual(self.state.active_wg, expected)

    def test_revoked_key_leaves_the_active_index(self):
        self.assertEqual(self.state.devices["spare"]["status"], "revoked")
        self.assertNotIn(fixture.WG["spare"], self.state.active_wg)

    def test_params_merged_not_replaced(self):
        self.assertEqual(self.state.params["staleness"], 900)
        self.assertEqual(self.state.params["checkpoint_interval"], 60)


class UintFieldsRefuseBooleans(unittest.TestCase):
    def _refuses_boolean(self, suffix, field):
        items = fixture.log()
        index = next(i for i, item in enumerate(items) if item.name.endswith(suffix))
        raw = [item.raw for item in items[:index]]
        anchor = anchor_for(raw)
        before = replay.replay(anchor, raw)
        env = cbor.decode(items[index].raw)
        self.assertIs(env["body"][field], True)
        size = len(before.roots if env["t"] == "root_thr" else before.signers)
        self.assertGreaterEqual(size, 1)

        # The uint 1 is accepted with the same body and quorum, so the bool
        # is the only fault and cannot hide behind a range or signature check.
        env["body"][field] = 1
        env["sigs"] = []
        for name in fixture.ROOTS:
            entry.sign(env, fixture.KEYS[name], "root")
        positive = replay.replay(anchor, raw + [entry.encode(env)])
        self.assertEqual(positive.rejected, before.rejected)

        after = replay.replay(anchor, raw + [items[index].raw])
        self.assertEqual(after.rejected, before.rejected + [{"index": index, "reason": "decode"}])
        self.assertEqual(after.size, index + 1)
        expected = before.to_dict()
        expected.update(size=after.size, rejected=after.rejected)
        self.assertEqual(after.to_dict(), expected)

    def test_a_boolean_signer_threshold_is_decode_and_changes_nothing(self):
        self._refuses_boolean("-bad-signer_thr-bool", "thr")

    def test_a_boolean_root_threshold_is_decode_and_changes_nothing(self):
        self._refuses_boolean("-bad-root_thr-bool", "thr")

    def test_a_boolean_log_key_overlap_is_decode_and_changes_nothing(self):
        self._refuses_boolean("-bad-log_key-overlap-bool", "overlap")


class BadGenesisAborts(unittest.TestCase):
    def test_wrong_genesis_hash_aborts_with_no_state(self):
        raw = [item.raw for item in fixture.log()]
        bad = replay.Anchor(net=fixture.NET, genesis_hash=b"\x00" * 32)
        state = replay.replay(bad, raw)
        self.assertEqual([r["reason"] for r in state.rejected], ["bad-genesis"])
        self.assertEqual(state.size, 0)
        self.assertEqual(state.devices, {})

    def test_first_entry_not_genesis_aborts(self):
        raw = [fixture.log()[1].raw]
        state = replay.replay(replay.Anchor(fixture.NET, entry.leaf_hash(raw[0])), raw)
        self.assertEqual([r["reason"] for r in state.rejected], ["bad-genesis"])


class Isolation(unittest.TestCase):
    def test_rejected_entries_leave_no_trace(self):
        """Each rejected entry in the fixture tried something; none of it happened.

        Dropping rejected entries and re-replaying is *not* a valid comparison:
        `after` is position-dependent, so removing entries shifts later indices
        and legitimately invalidates them. So assert the attempted effects.
        """
        state = replay.replay(anchor_for([i.raw for i in fixture.log()]),
                              [i.raw for i in fixture.log()])
        self.assertNotIn("ghost", state.devices, "rotate of an unknown device")
        self.assertEqual(state.devices["nas"]["since_index"], 1, "dup-id did not re-enrol")
        self.assertEqual(state.devices["printer"]["since_index"], 31,
                         "the two failed printer enrolments did not take effect")
        self.assertEqual(state.signer_thr, 2, "bad-thr 99 was not applied")
        self.assertIn(keys.kid(fixture.KEYS["root3"].public), state.roots,
                      "root-invariant removal did not happen")
        self.assertEqual(len(state.roots), 3, "under-signed signer_add added nothing")
        self.assertNotIn(fixture.KEYS["root4"].id, state.signers)

    def test_entry_for_another_network_is_a_decode_rejection(self):
        items = fixture.log()
        state = replay.replay(anchor_for([i.raw for i in items]), [i.raw for i in items])
        wrong_net = next(i for i, it in enumerate(items) if it.name.endswith("decode-net"))
        self.assertIn({"index": wrong_net, "reason": "decode"}, state.rejected)

    def test_a_log_under_the_wrong_anchor_is_entirely_rejected(self):
        raw = [item.raw for item in fixture.log()]
        other = replay.Anchor(net=b"\xff" * 16, genesis_hash=entry.leaf_hash(raw[0]))
        state = replay.replay(other, raw)
        self.assertEqual([r["reason"] for r in state.rejected], ["bad-genesis"])
        self.assertEqual(state.size, 0)


class StateShape(unittest.TestCase):
    def test_json_is_canonical_and_stable(self):
        raw = [item.raw for item in fixture.log()]
        a = replay.replay(anchor_for(raw), raw).to_json()
        b = replay.replay(anchor_for(raw), raw).to_json()
        self.assertEqual(a, b)
        self.assertIsInstance(a, str)
        self.assertNotIn(" ", a[: a.index("devices")] if "devices" in a else a)

    def test_empty_log(self):
        state = replay.replay(replay.Anchor(fixture.NET, b"\x00" * 32), [])
        self.assertEqual(state.size, 0)
        self.assertEqual(state.rejected, [])


if __name__ == "__main__":
    unittest.main()


class DuplicateEntries(unittest.TestCase):
    """An exact entry may appear in the log at most once, accepted or not.

    Otherwise a log operator could re-insert an old signed entry at a later
    index to resurrect a revoked device: `after` bounds reordering (after <=
    index) but not re-insertion further along.
    """

    def _log(self, extra):
        items = fixture.log()
        raw = [i.raw for i in items] + extra
        return replay.replay(anchor_for(raw), raw)

    def test_a_rejected_entry_cannot_be_replayed_later(self):
        items = fixture.log()
        rejected = next(i for i in items if i.reason == "dup-id")
        state = self._log([rejected.raw])
        self.assertEqual(state.rejected[-1], {"index": len(items), "reason": "dup-entry"})

    def test_an_accepted_entry_cannot_be_replayed_later(self):
        items = fixture.log()
        accepted = next(i for i in items if i.reason is None and i.name.endswith("note-final"))
        state = self._log([accepted.raw])
        self.assertEqual(state.rejected[-1], {"index": len(items), "reason": "dup-entry"})

    def test_resurrection_by_replay_is_refused(self):
        """The concrete attack: re-insert the enrolment of a revoked device."""
        items = fixture.log()
        enrol_spare = next(i for i in items if i.name.endswith("enroll-spare"))
        state = self._log([enrol_spare.raw])
        self.assertEqual(state.rejected[-1]["reason"], "dup-entry")
        self.assertEqual(state.devices["spare"]["status"], "revoked")
        self.assertNotIn(fixture.WG["spare"], state.active_wg)
