"""SEC-010: a rejected `params` entry changes nothing (SPEC 5.1)."""
import unittest

from nornref import entry, fixture, replay


def _state(extra):
    items = fixture.log()
    raw = [i.raw for i in items] + list(extra)
    return replay.replay(replay.Anchor(fixture.NET, entry.leaf_hash(raw[0])), raw), len(items)


class RejectedParamsChangeNothing(unittest.TestCase):
    def test_a_mixed_validity_params_entry_leaves_params_as_they_were(self):
        # `mmd` sorts before `staleness`, so a handler that writes as it goes
        # has already changed `mmd` when it meets the boolean and rejects.
        before, n = _state([])
        self.assertNotEqual(before.params["mmd"], 60)
        env = entry.new("params", fixture.NET, ts=fixture.T0 + 9000, after=None,
                        body={"mmd": 60, "staleness": True}, prev=before.versions["params"])
        for name in ("root1", "root2", "root3"):
            entry.sign(env, fixture.KEYS[name], "root")
        after, _ = _state([entry.encode(env)])
        self.assertEqual(after.rejected[-1], {"index": n, "reason": "decode"})
        self.assertEqual(after.params, before.params)
