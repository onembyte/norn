"""RED first: a removed signer key must be inert, and a stranger's key too.

The Phase 1 gate names 'wrong signer' and 'signer revoked in an earlier entry'
among the rejections that must be exercised. Neither had a vector -- which
means nothing tested the entire point of `signer_remove`: that after removal,
that key can no longer authorise anything.
"""
import unittest

from nornref import entry, fixture, replay


def outcomes():
    items = fixture.log()
    raw = [i.raw for i in items]
    state = replay.replay(replay.Anchor(fixture.NET, entry.leaf_hash(raw[0])), raw)
    by_index = {r["index"]: r["reason"] for r in state.rejected}
    return {it.name: by_index.get(i) for i, it in enumerate(items)}, state


def named(got, suffix):
    return next(v for k, v in got.items() if k.endswith(suffix))


class ARemovedSignerIsInert(unittest.TestCase):
    def test_signer2_was_actually_removed(self):
        _, state = outcomes()
        self.assertNotIn(fixture.KEYS["signer2"].id, state.signers,
                         "the fixture must remove signer2 for this to mean anything")

    def test_an_entry_signed_by_the_removed_signer_is_rejected(self):
        got, _ = outcomes()
        self.assertEqual(named(got, "bad-removed-signer"), "threshold")

    def test_an_equivalent_entry_is_accepted_before_the_removal(self):
        """Isolates the rule: only the removal makes signer2 powerless.

        The fixture's own entry cannot simply be relocated -- its `after` is
        its position in the full log, so moving it earlier trips the ordering
        guard instead. So build the equivalent entry at the position it would
        occupy, and watch it be accepted.
        """
        items = fixture.log()
        removal = next(i for i, it in enumerate(items)
                       if it.name.endswith("signer_remove-signer2"))
        prefix = [it.raw for it in items[:removal]]

        env = entry.new("note", fixture.NET, ts=fixture.T0,
                        after=len(prefix), body={"text": "signed by a removed signer"})
        entry.sign(env, fixture.KEYS["signer2"], "signer")
        raw = prefix + [entry.encode(env)]

        state = replay.replay(replay.Anchor(fixture.NET, entry.leaf_hash(raw[0])), raw)
        self.assertEqual([r for r in state.rejected if r["index"] == len(raw) - 1], [],
                         "while signer2 is still a signer, the same entry is valid")


class AStrangersKeyIsInert(unittest.TestCase):
    def test_an_entry_signed_by_a_key_never_in_the_set_is_rejected(self):
        got, _ = outcomes()
        self.assertEqual(named(got, "bad-stranger-signer"), "threshold")
