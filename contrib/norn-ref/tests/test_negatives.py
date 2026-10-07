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

    def test_run_twelve_trust_cases_isolate_the_named_rules(self):
        cases = dict(fixture.trust_rejections())
        no_witnesses = cases["07-no-witnesses"]
        self.assertEqual(no_witnesses["witnesses"], [])
        no_witness_policy = [line.split() for line in no_witnesses["policy"].splitlines()]
        self.assertFalse(any(fields and fields[0] == "witness" for fields in no_witness_policy))
        self.assertIn(["quorum", "none"], no_witness_policy)

        duplicate = cases["08-duplicate-witness-name"]
        policy_keys = {fields[1]: fields[2]
                       for line in duplicate["policy"].splitlines()
                       if len(fields := line.split()) >= 3 and fields[0] == "witness"}
        seen = {}
        for witness in duplicate["witnesses"]:
            self.assertIn(witness["name"], policy_keys)
            self.assertEqual(witness["key"], policy_keys[witness["name"]])
            seen[witness["name"]] = seen.get(witness["name"], 0) + 1
        self.assertEqual(sum(count > 1 for count in seen.values()), 1)

        origin = cases["13-origin-only"]
        self.assertEqual(origin["origin"], fixture.ORIGIN + "a")
        self.assertEqual(origin["log_key"].split("+", 1)[0], origin["origin"])
        policy_log = next(line.split() for line in origin["policy"].splitlines()
                          if line.startswith("log "))
        self.assertEqual(policy_log[1], origin["log_key"])

        mismatch = cases["42-witness-key-mismatch"]
        keys = {fields[1]: fields[2]
                for line in mismatch["policy"].splitlines()
                if len(fields := line.split()) >= 3 and fields[0] == "witness"}
        self.assertEqual(len(keys), len(mismatch["witnesses"]))
        self.assertEqual(sum(w["key"] != keys[w["name"]] for w in mismatch["witnesses"]), 1)

        anchor = cases["43-anchor-unknown-member"]["anchor"]
        self.assertEqual(set(anchor), {"type", "max_lag", "mode", "note"})


class TrustAcceptances(unittest.TestCase):
    """The positives, through the same `parse` the negatives go through.

    The generator validates each document (`trust.validate`), which never
    sees the bytes, so parse-level rules and byte-exact URL round-trips need
    these reference checks too.
    """

    def test_every_acceptable_trust_file_is_accepted(self):
        for name, doc in fixture.trust_acceptances():
            with self.subTest(case=name):
                trust.parse(cbor.encode(doc))

    def test_url_values_are_opaque_and_independent(self):
        _, doc = next((name, doc) for name, doc in fixture.trust_acceptances()
                      if name == "url-fields-are-opaque")
        raw = cbor.encode(doc)
        parsed = trust.parse(raw)
        self.assertEqual(trust.encode(parsed), raw)
        self.assertEqual(parsed["log_urls"], ["http://[invalid"])
        self.assertEqual(parsed["witnesses"][0]["url"], "")
        self.assertEqual(parsed["witnesses"][1]["url"], "http://[invalid")
        self.assertIn("http://other.invalid", parsed["policy"])
        self.assertNotEqual(parsed["witnesses"][1]["url"], "http://other.invalid")

    def test_one_is_exactly_at_the_cap(self):
        sizes = [len(cbor.encode(doc)) for _, doc in fixture.trust_acceptances()]
        self.assertIn(trust.MAX_TRUST_BYTES, sizes)


if __name__ == "__main__":
    unittest.main()
