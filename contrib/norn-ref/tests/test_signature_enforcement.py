"""RED first: a signature-blind implementation must NOT pass.

Gate run 4 stubbed `ed25519.Verify` to always return true and reproduced the
entire manifest. The most security-critical MUST in the spec -- that a
signature actually verifies -- had no negative vector at all. These tests fail
if that is ever true again.
"""
import unittest

from nornref import entry, fixture, keys, replay


def replay_log(verify=None):
    """Replay the fixture, optionally with signature verification replaced."""
    real = keys.verify
    if verify is not None:
        keys.verify = verify
        entry.keys.verify = verify
    try:
        items = fixture.log()
        raw = [i.raw for i in items]
        state = replay.replay(replay.Anchor(fixture.NET, entry.leaf_hash(raw[0])), raw)
        expected = [(i, it.reason) for i, it in enumerate(items) if it.reason]
        got = [(r["index"], r["reason"]) for r in state.rejected]
        return got, expected
    finally:
        keys.verify = real
        entry.keys.verify = real


class SignatureVerificationIsLoadBearing(unittest.TestCase):
    def test_the_honest_implementation_matches_the_manifest(self):
        got, expected = replay_log()
        self.assertEqual(got, expected)

    def test_a_signature_blind_implementation_does_not(self):
        """The whole point: stubbing verification must change the outcome."""
        got, expected = replay_log(verify=lambda pk, msg, sig: True)
        self.assertNotEqual(got, expected,
                            "replay passes without checking a single signature")

    def test_the_difference_is_a_forged_signature_being_admitted(self):
        blind, expected = replay_log(verify=lambda pk, msg, sig: True)
        missed = [e for e in expected if e not in blind]
        self.assertTrue(missed, "no vector distinguishes a valid signature from a forged one")
        for index, reason in missed:
            self.assertIn(reason, {"threshold", "no-device-sig"})


class ForgedSignatureVectors(unittest.TestCase):
    def test_the_fixture_carries_forged_signature_cases(self):
        names = [item.name for item in fixture.log()]
        for want in ("bad-forged-signer-sig", "bad-forged-device-sig"):
            self.assertTrue(any(n.endswith(want) for n in names), f"no vector for {want}")

    def test_a_forged_signature_is_well_formed_but_uncounted(self):
        """Syntactically perfect -- right kid, right role, 64 bytes -- and wrong."""
        items = fixture.log()
        raw = [i.raw for i in items]
        state = replay.replay(replay.Anchor(fixture.NET, entry.leaf_hash(raw[0])), raw)
        by_index = {r["index"]: r["reason"] for r in state.rejected}
        for index, item in enumerate(items):
            if item.name.endswith("bad-forged-signer-sig"):
                self.assertEqual(by_index.get(index), "threshold")
                env = fixture.decode_leniently(item.raw)
                sig = env["sigs"][0]
                self.assertEqual(len(sig["sig"]), 64)
                self.assertEqual(sig["role"], "signer")
                self.assertEqual(sig["kid"], fixture.KEYS["signer1"].id)
            if item.name.endswith("bad-forged-device-sig"):
                self.assertEqual(by_index.get(index), "no-device-sig")
