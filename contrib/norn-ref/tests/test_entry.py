"""RED first: keys, preimage, signing, hashing (SPEC §3, §4.0, §4.2)."""
import hashlib
import unittest
from nornref import cbor, keys, entry


class Kid(unittest.TestCase):
    def test_kid_is_first_8_bytes_of_sha256_hex(self):
        k = keys.Ed25519.from_seed(b"\x01" * 32)
        self.assertEqual(keys.kid(k.public), hashlib.sha256(k.public).digest()[:8].hex())
        self.assertEqual(len(keys.kid(k.public)), 16)

    def test_seed_derivation_is_deterministic(self):
        a = keys.Ed25519.from_name("root1"); b = keys.Ed25519.from_name("root1")
        self.assertEqual(a.public, b.public)
        self.assertNotEqual(a.public, keys.Ed25519.from_name("root2").public)


class Envelope(unittest.TestCase):
    NET = bytes(range(16))

    def note(self):
        return entry.new("note", self.NET, ts=1_700_000_000, body={"text": "hello"}, after=3)

    def test_preimage_prefix_and_body(self):
        env = self.note()
        pre = entry.preimage(env)
        self.assertTrue(pre.startswith(b"norn/entry/v1\n"))
        without = {k: v for k, v in env.items() if k != "sigs"}
        self.assertEqual(pre, b"norn/entry/v1\n" + cbor.encode(without))

    def test_sign_then_verify(self):
        env = self.note()
        s1 = keys.Ed25519.from_name("signer1")
        entry.sign(env, s1, "signer")
        self.assertEqual(len(env["sigs"]), 1)
        self.assertEqual(env["sigs"][0]["kid"], keys.kid(s1.public))
        self.assertTrue(entry.verify_sig(env, env["sigs"][0], s1.public))
        env["body"]["text"] = "tampered"
        self.assertFalse(entry.verify_sig(env, env["sigs"][0], s1.public))

    def test_sigs_sorted_by_kid_and_unique(self):
        env = self.note()
        a = keys.Ed25519.from_name("a"); b = keys.Ed25519.from_name("b")
        entry.sign(env, a, "signer"); entry.sign(env, b, "signer"); entry.sign(env, a, "signer")
        kids = [s["kid"] for s in env["sigs"]]
        self.assertEqual(kids, sorted(kids)); self.assertEqual(len(kids), 2)

    def test_encode_hash_leaf(self):
        env = self.note(); entry.sign(env, keys.Ed25519.from_name("s"), "signer")
        raw = entry.encode(env)
        self.assertEqual(cbor.decode(raw), env)
        self.assertEqual(entry.entry_hash(raw), hashlib.sha256(raw).digest())
        self.assertEqual(entry.leaf_hash(raw), hashlib.sha256(b"\x00" + raw).digest())

    def test_unknown_type_rejected_at_build(self):
        with self.assertRaises(entry.SchemaError):
            entry.new("bogus", self.NET, ts=1, body={})


if __name__ == "__main__":
    unittest.main()
