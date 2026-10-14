"""RED first: replay rules run 3 showed no vector exercises."""
import unittest

from nornref import entry, fixture, note, replay, trust


def outcomes():
    items = fixture.log()
    raw = [i.raw for i in items]
    state = replay.replay(replay.Anchor(fixture.NET, entry.leaf_hash(raw[0])), raw)
    by_index = {r["index"]: r["reason"] for r in state.rejected}
    return {item.name: by_index.get(i) for i, item in enumerate(items)}, state


class AfterIsAFloorNotAnEquality(unittest.TestCase):
    """§4.4: an entry is valid at index >= after. Every `after` in the fixture
    used to equal its own index, so a variant requiring equality passed."""

    def test_an_entry_with_after_below_its_index_is_accepted(self):
        got, _ = outcomes()
        name = next(k for k in got if k.endswith("-after-below-index"))
        self.assertIsNone(got[name], "after < index must be accepted")

    def test_an_entry_with_after_above_its_index_is_rejected(self):
        got, _ = outcomes()
        self.assertEqual(got[next(k for k in got if k.endswith("-bad-after"))], "after")


class SeenSetIncludesRejected(unittest.TestCase):
    """§5.1 step 1: the bytes are recorded 'whether or not it is later
    rejected' (D-031); the content only once applied (D-078)."""

    def test_repeating_a_rejected_entry_is_dup_entry(self):
        got, _ = outcomes()
        name = next(k for k in got if k.endswith("-repeat-of-rejected"))
        self.assertEqual(got[name], "dup-entry")


class PartialSignerQuorum(unittest.TestCase):
    """A count strictly between zero and the threshold -- the existing
    `threshold` negatives all carry zero valid signer signatures."""

    def test_one_signer_when_two_are_required(self):
        got, _ = outcomes()
        name = next(k for k in got if k.endswith("-one-of-two-signers"))
        self.assertEqual(got[name], "threshold")


class RoleMustMatchTheKeysCurrentRole(unittest.TestCase):
    """§4.3: 'a key counts only for the role it currently holds'."""

    def test_a_signer_key_declaring_root_is_not_counted(self):
        got, _ = outcomes()
        name = next(k for k in got if k.endswith("-role-mismatch"))
        self.assertEqual(got[name], "threshold")


class GenesisDecodeAbort(unittest.TestCase):
    def test_an_undecodable_entry_zero_aborts(self):
        names = [n for n, _, _ in fixture.genesis_aborts()]
        self.assertTrue(any("undecodable" in n for n in names))
        for name, raw, anchor in fixture.genesis_aborts():
            with self.subTest(case=name):
                state = replay.replay(anchor, [raw])
                self.assertEqual([r["reason"] for r in state.rejected], ["bad-genesis"])
                self.assertEqual(state.size, 0)

    def test_body_invariants_are_covered(self):
        names = " ".join(n for n, _, _ in fixture.genesis_aborts())
        for want in ("duplicate-root", "role-overlap"):
            self.assertIn(want, names, f"no genesis case for {want}")


class TrustLogKeyName(unittest.TestCase):
    """§9.1: the log key's note name MUST equal `origin`."""

    def test_a_log_key_named_something_else_is_rejected(self):
        doc = fixture.trust_file()
        doc["log_key"] = note.vkey("someone/else", fixture.KEYS["logkey"].public)
        with self.assertRaises(trust.TrustError):
            trust.validate(doc)

    def test_the_case_is_vectored(self):
        names = [n for n, _ in fixture.trust_rejections()]
        self.assertTrue(any("log-key-name" in n for n in names))
