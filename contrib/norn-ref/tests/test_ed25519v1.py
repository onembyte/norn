"""SPEC §3.1: the reference and Go read the same CCTV outcome table."""
import collections
import json
import pathlib
import unittest
from unittest import mock

from nornref import keys

L = 2**252 + 27742317777372353535851937790883648493
RFC_TESTS = (
    ("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555f"
     "b8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
    ("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
     "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da0"
     "85ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
)


class Verification(unittest.TestCase):
    def test_every_CCTV_vector_gets_its_stated_outcome(self):
        directory = pathlib.Path(__file__).resolve().parents[3] / "testdata/vectors/ed25519-cctv"
        vectors = json.loads((directory / "ed25519vectors.json").read_text())
        cases = json.loads((directory / "cases.json").read_text())["cases"]
        table = {case["number"]: case for case in cases}
        self.assertEqual(len(vectors), 914)
        self.assertEqual(len(cases), 914)
        self.assertEqual(set(table), {vector["number"] for vector in vectors})
        self.assertEqual([c["number"] for c in cases if c["outcome"] == "accept"], [305])
        self.assertEqual(sum(c["outcome"] == "reject" for c in cases), 913)
        wrong = []
        for vector in vectors:
            case = table[vector["number"]]
            got = keys.verify(bytes.fromhex(vector["key"]), vector["msg"].encode("utf-8"),
                              bytes.fromhex(vector["sig"]))
            if got != (case["outcome"] == "accept"):
                wrong.append((vector["number"], case["flag"], tuple(vector["flags"])))
        # Report every deciding flag and the full flag combinations, rather
        # than stopping at the first disagreement and hiding the other 913.
        self.assertEqual(len(wrong), 0, f"{len(wrong)} CCTV outcomes wrong; deciding flags "
                         f"{dict(collections.Counter(w[1] for w in wrong))}; full flags "
                         f"{dict(collections.Counter(w[2] for w in wrong))}; "
                         f"first ten numbers {[w[0] for w in wrong[:10]]}")

    def test_RFC_8032_test_1_and_test_2_are_accepted(self):
        for number, (public, message, signature) in enumerate(RFC_TESTS, 1):
            with self.subTest(number=number):
                a, m, sig = bytes.fromhex(public), bytes.fromhex(message), bytes.fromhex(signature)
                self.assertTrue(keys.verify(a, m, sig))
                self.assertFalse(keys.verify(a, m + b"changed", sig))

    def test_S_at_or_above_L_is_refused(self):
        key = keys.Ed25519.from_name("scalar-boundary")
        message = b"norn"
        signature = key.sign(message)
        self.assertTrue(keys.verify(key.public, message, signature))
        s = int.from_bytes(signature[32:], "little")
        raised = signature[:32] + (s + L).to_bytes(32, "little")
        self.assertFalse(keys.verify(key.public, message, raised))

    def test_S_below_L_is_checked_before_the_library_verifies(self):
        key = keys.Ed25519.from_name("scalar-preflight")
        signature = key.sign(b"norn")
        self.assertTrue(keys.verify(key.public, b"norn", signature))
        # The backend also checks S, but §3.1 requires our explicit bound.
        # Isolate it so a backend upgrade cannot silently remove that rule.
        for s in (L, L + 1, 2**256 - 1):
            with self.subTest(S=s), mock.patch.object(keys, "VerifyKey") as backend:
                self.assertFalse(keys.verify(key.public, b"norn",
                                             signature[:32] + s.to_bytes(32, "little")))
                backend.assert_not_called()

    def test_an_invalid_R_is_refused_before_the_library_verifies(self):
        key = keys.Ed25519.from_name("R-boundary")
        message = b"norn"
        signature = key.sign(message)
        self.assertTrue(keys.verify(key.public, message, signature))
        # Libsodium already refuses these R values when A is valid, so the
        # CCTV set cannot hold the explicit preflight check on its own. A
        # permissive backend isolates that check, as Go isolates its redundant
        # canonical check: no invalid R may reach the verification equation.
        invalid = (
            bytes.fromhex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"),
            bytes.fromhex("0100000000000000000000000000000000000000000000000000000000000080"),
        )
        for r in invalid:
            with self.subTest(R=r.hex()), mock.patch.object(keys, "VerifyKey") as backend:
                self.assertFalse(keys.verify(key.public, message, r + signature[32:]))
                backend.assert_not_called()

    def test_wrong_key_or_signature_lengths_are_refused_before_the_library(self):
        key = keys.Ed25519.from_name("length-boundary")
        signature = key.sign(b"norn")
        for public, sig in ((key.public[:31], signature), (key.public + b"x", signature),
                            (key.public, signature[:63]), (key.public, signature + b"x")):
            with self.subTest(key_length=len(public), sig_length=len(sig)), \
                    mock.patch.object(keys, "VerifyKey") as backend:
                self.assertFalse(keys.verify(public, b"norn", sig))
                backend.assert_not_called()
