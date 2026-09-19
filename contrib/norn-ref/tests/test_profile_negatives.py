"""RED first: negatives that isolate the ENCODING rule they test.

Run 3's sharpest vector critique: a profile negative that puts a forbidden item
where a typed field lives is over-determined -- an implementation with strict
typing rejects it for the type and never exercises the profile rule at all. The
cases below all decode to a *valid entry* under a lenient decoder, so only a
decoder that enforces the encoding rule rejects them.
"""
import unittest

from nornref import entry, fixture, replay


def log_outcomes():
    """Replay the fixture and return {entry name: reason or None}.

    These negatives live *in* the log, so appending copies would be rejected as
    `dup-entry` (D-031) rather than for their own fault. Assert against the log.
    """
    items = fixture.log()
    raw = [i.raw for i in items]
    state = replay.replay(replay.Anchor(fixture.NET, entry.leaf_hash(raw[0])), raw)
    by_index = {r["index"]: r["reason"] for r in state.rejected}
    return {item.name: by_index.get(i) for i, item in enumerate(items)}


class IsolatingProfileNegatives(unittest.TestCase):
    """Each decodes to the same valid entry if the rule is not enforced."""

    def test_each_case_is_rejected_as_decode(self):
        outcomes = log_outcomes()
        for name, _ in fixture.profile_negatives():
            with self.subTest(case=name):
                self.assertEqual(outcomes[f"{self._index_of(name)}-bad-{name}"], "decode")

    @staticmethod
    def _index_of(name: str) -> int:
        return next(i for i, item in enumerate(fixture.log())
                    if item.name.endswith(f"-bad-{name}"))

    def test_a_lenient_decoder_would_see_a_valid_entry(self):
        """Proves the isolation claim rather than asserting it.

        Each negative must still look like a well-formed entry of its base's
        type to a decoder that skips the encoding rules -- otherwise the vector
        would be rejected for something other than the rule it names.
        """
        for name, raw in fixture.profile_negatives():
            with self.subTest(case=name):
                lenient = fixture.decode_leniently(raw)
                self.assertIn(lenient["t"], entry.TYPES)
                self.assertEqual(lenient["v"], entry.VERSION)
                self.assertEqual(lenient["net"], fixture.NET)
                self.assertTrue(lenient["sigs"], "signatures must survive the patch")
                self.assertIsInstance(lenient["body"], dict)

    def test_every_control_entry_is_accepted(self):
        """Without a control, a negative could be rejected for a fault its
        author did not intend and nobody would notice."""
        outcomes = log_outcomes()
        for control in [k for k in outcomes if k.endswith(("-profile-base", "-labelcap-base", "-two-sig-base"))]:
            with self.subTest(control=control):
                self.assertIsNone(outcomes[control])


class FieldConstraintNegatives(unittest.TestCase):
    def test_each_case_is_rejected_as_decode(self):
        outcomes = log_outcomes()
        for name, _ in fixture.field_negatives():
            with self.subTest(case=name):
                match = next(k for k in outcomes if k.endswith(f"-bad-{name}"))
                self.assertEqual(outcomes[match], "decode")

    def test_cases_cover_the_documented_constraints(self):
        names = {n for n, _ in fixture.field_negatives()}
        for want in ("device_id", "pk-length", "sig-length", "text-too-long"):
            self.assertTrue(any(want in n for n in names), f"no case for {want}")
