"""Every fixture entry must encode, round-trip and verify under its own keys."""
import unittest
from nornref import cbor, entry, fixture


class Catalogue(unittest.TestCase):
    def setUp(self):
        self.items = fixture.catalogue()

    def test_covers_every_type_exactly_once(self):
        types = [env["t"] for _, env in self.items]
        self.assertCountEqual(set(types), set(entry.TYPES))
        self.assertEqual(len(types), len(entry.TYPES) + 2)  # three enroll variants

    def test_encodes_and_round_trips(self):
        for name, env in self.items:
            with self.subTest(name=name):
                raw = entry.encode(env)
                self.assertEqual(cbor.decode(raw), env)

    def test_every_signature_verifies(self):
        by_kid = {k.id: k.public for k in fixture.KEYS.values()}
        for name, env in self.items:
            with self.subTest(name=name):
                self.assertTrue(env["sigs"], "entry has no signatures")
                for sig in env["sigs"]:
                    self.assertTrue(entry.verify_sig(env, sig, by_kid[sig["kid"]]))

    def test_no_signature_verifies_against_a_different_entry(self):
        (_, first), (_, second) = self.items[1], self.items[2]
        by_kid = {k.id: k.public for k in fixture.KEYS.values()}
        self.assertFalse(entry.verify_sig(second, first["sigs"][0], by_kid[first["sigs"][0]["kid"]]))
