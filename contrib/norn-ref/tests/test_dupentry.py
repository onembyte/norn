"""D-070 (SEC-001): duplicates are keyed on the signed content."""
import unittest

from nornref import cbor, entry, fixture, replay


def _log():
    items = fixture.log()
    raw = [i.raw for i in items]
    return raw, {i.name: n for n, i in enumerate(items)}


def _replay(raw):
    return replay.replay(replay.Anchor(fixture.NET, entry.leaf_hash(raw[0])), raw)


# Each variant differs from the fixture's own `bad-copy-*` entries, which are
# built the same way, or a byte-keyed replay would call these duplicates of
# those rather than of the originals.
def _with_extra_signature(raw):
    env = cbor.decode(raw)
    env["sigs"] = sorted(env["sigs"] + [{"kid": "fffffffffffffff0", "role": "signer", "sig": bytes(64)}],
                         key=lambda s: s["kid"])
    return entry.encode(env)


def _with_role_relabelled(raw):
    env = cbor.decode(raw)
    env["sigs"][-1]["role"] = "device"
    return entry.encode(env)


def _with_surplus_dropped(raw):
    env = cbor.decode(raw)
    env["sigs"] = env["sigs"][1:]
    return entry.encode(env)


class ReSignedCopiesAreDuplicates(unittest.TestCase):
    def test_every_copy_of_a_past_entry_is_dup_entry(self):
        raw, index = _log()
        before = _replay(raw)
        cases = [("37-enroll-spare", _with_extra_signature), ("37-enroll-spare", _with_role_relabelled),
                 ("28-policy", _with_extra_signature), ("35-rotate-nas", _with_extra_signature),
                 ("16-signer_add-signer3", _with_extra_signature), ("89-two-sig-base", _with_surplus_dropped)]
        for name, mutate in cases:
            with self.subTest(name=name, variant=mutate.__name__):
                copy = mutate(raw[index[name]])
                self.assertNotEqual(copy, raw[index[name]])
                after = _replay(raw + [copy])
                self.assertEqual(after.rejected[-1], {"index": len(raw), "reason": "dup-entry"})
                self.assertEqual(after.devices["spare"]["status"], before.devices["spare"]["status"])
                self.assertEqual(after.policy, before.policy)

    def test_a_different_content_is_not_a_duplicate(self):
        raw, index = _log()
        env = cbor.decode(raw[index["70-profile-base"]])
        env["ts"] += 1
        after = _replay(raw + [entry.encode(env)])
        self.assertNotEqual(after.rejected[-1]["reason"], "dup-entry")
