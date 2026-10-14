"""D-078 (3), run 15's M3: a `log_key` of an already active log key is `dup-key`."""
import hashlib
import unittest

from nacl.signing import SigningKey

from nornref import entry, fixture, replay


class ALogKeyOfAnActiveKeyIsDupKey(unittest.TestCase):
    def test_the_anchor_key_and_every_learned_key_are_refused_and_a_new_key_appends(self):
        raw = [item.raw for item in fixture.log()]
        anchor = fixture.anchor_for(raw)
        before = replay.replay(anchor, raw)
        fresh = bytes(SigningKey(hashlib.sha256(b"norn/log-key-republish-test").digest()).verify_key)
        for name, pk, want in (("the anchor's key", fixture.KEYS["logkey"].public, "dup-key"),
                               ("a learned key", fixture.KEYS["logkey2"].public, "dup-key"),
                               ("the newest learned key", fixture.KEYS["logkey3"].public, "dup-key"),
                               ("a new key", fresh, None)):
            with self.subTest(name=name):
                env = {"v": 1, "t": "log_key", "net": fixture.NET, "ts": 1790000000,
                       "prev": before.versions["log_key"], "body": {"pk": pk, "overlap": 60}, "sigs": []}
                for root in ("root1", "root2", "root3", "root4"):
                    if fixture.KEYS[root].id in before.roots:
                        entry.sign(env, fixture.KEYS[root], "root")
                after = replay.replay(anchor, raw + [entry.encode(env)])
                got = next((r["reason"] for r in after.rejected if r["index"] == len(raw)), None)
                self.assertEqual(got, want)
                if want:
                    self.assertEqual(after.log_keys, before.log_keys)
