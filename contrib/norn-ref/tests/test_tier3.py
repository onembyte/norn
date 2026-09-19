"""RED first: the questions the cold-model gate found undecided (D11-D21).

Each of these was answerable two ways by the spec *and* unexercised by the
vectors, so two honest implementations could diverge and both pass.
"""
import unittest

from nornref import cbor, entry, fixture, replay


def state_with(extra_raw):
    items = fixture.log()
    raw = [i.raw for i in items] + list(extra_raw)
    return replay.replay(replay.Anchor(fixture.NET, entry.leaf_hash(raw[0])), raw), len(items)


def build(kind, body, signers, after, ts=None):
    env = entry.new(kind, fixture.NET, ts=ts or fixture.T0 + 9000, after=after, body=body)
    for name, role in signers:
        entry.sign(env, fixture.KEYS[name], role)
    return entry.encode(env)


ROOTS3 = [("root1", "root"), ("root2", "root"), ("root3", "root")]
SIGNERS2 = [("signer1", "signer"), ("signer3", "signer")]


class D11_ThresholdValueVsSetInvariant(unittest.TestCase):
    """`root_thr` larger than the root set is a bad *value*, not a broken set."""

    def test_root_thr_above_set_size_is_bad_thr(self):
        state, n = state_with([build("root_thr", {"thr": 99}, ROOTS3, after=42)])
        self.assertEqual(state.rejected[-1], {"index": n, "reason": "bad-thr"})

    def test_root_invariant_is_reserved_for_removals(self):
        reasons = {r["reason"] for r in state_with([])[0].rejected}
        self.assertIn("root-invariant", reasons)


class D12_RevokeWithNoAuthority(unittest.TestCase):
    def test_unauthorised_revoke_is_threshold(self):
        raw = build("revoke", {"device_id": "printer", "reason": "no authority"},
                    [("laptop", "device")], after=42)
        state, n = state_with([raw])
        self.assertEqual(state.rejected[-1], {"index": n, "reason": "threshold"})
        self.assertEqual(state.devices["printer"]["status"], "active")


class D18_UnknownRole(unittest.TestCase):
    def test_unrecognised_role_string_is_a_decode_rejection(self):
        env = entry.new("note", fixture.NET, ts=fixture.T0, after=42, body={"text": "hi"})
        entry.sign(env, fixture.KEYS["signer1"], "signer")
        env["sigs"][0]["role"] = "admin"
        state, n = state_with([cbor.encode(env)])
        self.assertEqual(state.rejected[-1], {"index": n, "reason": "decode"})


class D19_SigsMandatory(unittest.TestCase):
    def test_omitting_sigs_is_a_decode_rejection(self):
        env = {"v": 1, "t": "note", "net": fixture.NET, "ts": fixture.T0,
               "after": 42, "body": {"text": "unsigned"}}
        state, n = state_with([cbor.encode(env)])
        self.assertEqual(state.rejected[-1], {"index": n, "reason": "decode"})

    def test_an_empty_sigs_array_is_well_formed_but_unauthorised(self):
        env = {"v": 1, "t": "note", "net": fixture.NET, "ts": fixture.T0,
               "after": 42, "body": {"text": "unsigned"}, "sigs": []}
        state, n = state_with([cbor.encode(env)])
        self.assertEqual(state.rejected[-1], {"index": n, "reason": "threshold"})


class D20_ProofOfPossessionOnRotate(unittest.TestCase):
    """A rotate that installs a new identity key must prove possession of it.

    Only the device can rotate (the current key must sign), so a device that
    installs a key it does not hold only harms itself — but it harms itself
    irrecoverably: it can never rotate again without a signer-assisted
    re-enrolment. Requiring the incoming key to sign costs nothing, because the
    device holds both keys at that moment, and matches D-008 for enrol.
    """

    def test_new_key_must_also_sign(self):
        raw = build("rotate", {"device_id": "printer", "wg_pk": fixture.WG["printer"],
                               "device_pk": fixture.KEYS["printer-id2"].public},
                    [("printer", "device")] + SIGNERS2, after=42)
        state, n = state_with([raw])
        self.assertEqual(state.rejected[-1], {"index": n, "reason": "no-device-sig"})

    def test_both_keys_signing_is_accepted(self):
        raw = build("rotate", {"device_id": "printer", "wg_pk": fixture.WG["printer"],
                               "device_pk": fixture.KEYS["printer-id2"].public},
                    [("printer", "device"), ("printer-id2", "device")] + SIGNERS2, after=42)
        state, n = state_with([raw])
        self.assertEqual([r for r in state.rejected if r["index"] == n], [])
        self.assertEqual(state.devices["printer"]["device_pk"],
                         fixture.KEYS["printer-id2"].public)

    def test_new_key_alone_is_not_enough(self):
        raw = build("rotate", {"device_id": "printer", "wg_pk": fixture.WG["printer"],
                               "device_pk": fixture.KEYS["printer-id2"].public},
                    [("printer-id2", "device")] + SIGNERS2, after=42)
        state, n = state_with([raw])
        self.assertEqual(state.rejected[-1], {"index": n, "reason": "no-device-sig"})

    def test_a_rotate_without_a_new_key_needs_only_the_current_one(self):
        raw = build("rotate", {"device_id": "printer", "wg_pk": fixture.WG["rogue"]},
                    [("printer", "device")] + SIGNERS2, after=42)
        state, n = state_with([raw])
        self.assertEqual([r for r in state.rejected if r["index"] == n], [])


class D21_CheckOrderIsNormative(unittest.TestCase):
    """Entries wrong in two ways at once prove which check runs first."""

    def test_enroll_missing_device_sig_and_duplicating_an_id(self):
        raw = build("enroll", {"device_id": "nas", "device_pk": fixture.KEYS["nas"].public,
                               "wg_pk": fixture.WG["rogue"]}, SIGNERS2, after=42)
        state, n = state_with([raw])
        self.assertEqual(state.rejected[-1], {"index": n, "reason": "no-device-sig"},
                         "device signature is checked before dup-id")

    def test_governance_under_threshold_and_duplicating_a_key(self):
        raw = build("signer_add", {"pk": fixture.KEYS["signer3"].public},
                    [("root1", "root")], after=42)
        state, n = state_with([raw])
        self.assertEqual(state.rejected[-1], {"index": n, "reason": "threshold"},
                         "root quorum is checked before the per-type rule")


if __name__ == "__main__":
    unittest.main()


class D29_PolicyHasOneHome(unittest.TestCase):
    """`policy` entries are the in-log mechanism; `params.witness_policy` is gone.

    Two places to set one value is how implementations diverge: a verifier
    reading `params.witness_policy` and one reading `state.policy` would
    disagree about the witness quorum, which is the thing guarding the log.
    """

    def test_witness_policy_is_no_longer_a_param(self):
        from nornref.state import PARAM_KEYS
        self.assertNotIn("witness_policy", PARAM_KEYS)

    def test_a_params_entry_setting_it_is_rejected(self):
        raw = build("params", {"witness_policy": "quorum none\n"}, ROOTS3, after=49)
        state, n = state_with([raw])
        self.assertEqual(state.rejected[-1], {"index": n, "reason": "decode"})

    def test_policy_entries_still_work(self):
        text = "log x\nwitness pi y\nquorum pi\n"
        raw = build("policy", {"text": text}, ROOTS3, after=49)
        state, n = state_with([raw])
        self.assertEqual([r for r in state.rejected if r["index"] == n], [])
        self.assertEqual(state.policy, text)
