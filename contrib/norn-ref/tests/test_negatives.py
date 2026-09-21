"""RED first: every genesis abort path, expiry, and trust-file rejection.

Run 2 observed that genesis has five distinct abort conditions and one vector,
that no device in any state carries a non-zero `expires`, and that §9 is a
single positive fixture. Each of those is a place two implementations can
differ while both passing.
"""
import unittest

from nornref import cbor, entry, fixture, replay, trust


class GenesisAborts(unittest.TestCase):
    def _abort(self, raw, anchor=None):
        anchor = anchor or replay.Anchor(fixture.NET, entry.leaf_hash(raw))
        state = replay.replay(anchor, [raw])
        self.assertEqual([r["reason"] for r in state.rejected], ["bad-genesis"])
        self.assertEqual(state.size, 0)
        self.assertEqual(state.devices, {})
        self.assertEqual(state.roots, {})
        return state

    def test_all_six_cases_abort(self):
        for name, raw, anchor in fixture.genesis_aborts():
            with self.subTest(case=name):
                self._abort(raw, anchor)

    def test_the_cases_are_distinct_and_cover_each_abort_step(self):
        """Asserts the property, not a count: a count breaks on every addition
        and teaches nothing when it does."""
        cases = fixture.genesis_aborts()
        names = [n for n, _, _ in cases]
        self.assertEqual(len(names), len(set(names)), "case names must be unique")
        pairs = [(raw, a.net, a.genesis_hash) for _, raw, a in cases]
        self.assertEqual(len(pairs), len(set(pairs)),
                         "each case must differ in its entry or its anchor")
        good = fixture.log()[0].raw
        reused = [n for n, raw, _ in cases if raw == good]
        self.assertEqual(reused, ["01-hash-mismatch"],
                         "only the anchor-mismatch case may reuse a valid genesis")
        for step in ("hash-mismatch", "not-genesis", "wrong-net", "after-nonzero",
                     "root-thr-above-set", "under-root-threshold", "undecodable",
                     "duplicate-root", "role-overlap"):
            self.assertTrue(any(step in n for n in names), f"no genesis case for {step}")

    def test_aborted_state_is_fully_serialised(self):
        _, raw, anchor = fixture.genesis_aborts()[0]
        state = replay.replay(anchor, [raw])
        doc = state.to_dict()
        for field in ("name", "net", "size", "roots", "signers", "params",
                      "policy", "log_keys", "devices", "active_wg", "rejected"):
            self.assertIn(field, doc, "§5.3 requires every field, even after abort")
        self.assertEqual(doc["params"]["checkpoint_interval"], 60,
                         "params defaults survive an abort")
        self.assertEqual(doc["net"], fixture.NET, "net comes from the anchor")

    def test_a_good_genesis_under_a_good_anchor_does_not_abort(self):
        raw = fixture.log()[0].raw
        state = replay.replay(replay.Anchor(fixture.NET, entry.leaf_hash(raw)), [raw])
        self.assertEqual(state.rejected, [])
        self.assertEqual(state.size, 1)


class Expiry(unittest.TestCase):
    """A device enrolled with an expiry must carry it through to the state."""

    def test_state_has_a_device_with_a_nonzero_expires(self):
        items = fixture.log()
        raw = [i.raw for i in items]
        state = replay.replay(replay.Anchor(fixture.NET, entry.leaf_hash(raw[0])), raw)
        expiring = {i: d["expires"] for i, d in state.devices.items() if d["expires"]}
        self.assertTrue(expiring, "no device carries an expiry; §5.3's rule is untested")
        for device_id, expires in expiring.items():
            self.assertEqual(state.devices[device_id]["status"], "active")
            self.assertGreater(expires, fixture.T0)


class TrustRejections(unittest.TestCase):
    def test_every_damaged_trust_file_is_rejected(self):
        for name, doc in fixture.trust_rejections():
            with self.subTest(case=name):
                # Through `parse`, not `validate`: a trust file is bytes, and
                # the size bound belongs to the decoder (SPEC 9.1). `38-oversize`
                # is a document that validates fine and a file that must not be
                # read at all.
                with self.assertRaises(trust.TrustError):
                    trust.parse(cbor.encode(doc))

    def test_the_cases_are_distinct_and_cover_the_schema(self):
        names = [n for n, _ in fixture.trust_rejections()]
        self.assertEqual(len(names), len(set(names)))
        self.assertGreaterEqual(len(names), 7)

    def test_the_undamaged_file_still_validates(self):
        trust.validate(fixture.trust_file())


if __name__ == "__main__":
    unittest.main()
