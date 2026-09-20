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

    def test_enroll_without_device_consent_and_duplicating_an_id(self):
        """Consent is checked before `dup-id`, and a signer cannot supply it.

        The request names `nas` but is signed by a signer's key, which is the
        forgery SPEC §4.3 exists to make impossible: the entry is otherwise
        perfectly formed and authorised.
        """
        body = fixture._enroll_body("nas", wg="rogue", signer="signer1")
        raw = build("enroll", body, SIGNERS2, after=42)
        state, n = state_with([raw])
        self.assertEqual(state.rejected[-1], {"index": n, "reason": "no-device-sig"},
                         "the request's own signature is checked before dup-id")

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


class CanonicalJsonEscaping(unittest.TestCase):
    """SPEC §14.2: exactly these escapes, and no others."""

    def setUp(self):
        from nornref import canonjson
        self.dumps = canonjson.dumps
        self.state, _ = state_with([])

    def test_torture_value_survives_into_state(self):
        """The escape torture reaches `state.json` through a label value.

        It used to travel as a `policy` entry's text, which SPEC 5.1 now
        refuses: a policy entry whose text is not a policy is malformed, and
        the fixture was publishing the torture string as this network's
        witness policy. The canonical-JSON rules it exercises are the same
        wherever the value rides; a label is where free text belongs.
        """
        labels = self.state.devices["astral"]["labels"]
        self.assertEqual(labels["escapes"], fixture.ESCAPE_TORTURE)

    def test_a_policy_entry_replaces_the_states_policy(self):
        """What the old assertion was really for."""
        self.assertIn("group home 3", self.state.policy)

    def test_escapes_exactly_the_specified_characters(self):
        out = self.dumps({"k": fixture.ESCAPE_TORTURE})
        for raw, want in [('"', '\\"'), ("\\", "\\\\"), ("\b", "\\b"), ("\t", "\\t"),
                          ("\n", "\\n"), ("\f", "\\f"), ("\r", "\\r"),
                          ("\x0b", "\\u000b"), ("\x00", "\\u0000"), ("\x1f", "\\u001f")]:
            with self.subTest(char=repr(raw)):
                self.assertIn(want, out)

    def test_does_not_escape_what_it_must_not(self):
        out = self.dumps({"k": fixture.ESCAPE_TORTURE})
        for literal in ["/", "<", ">", "&", "\x7f", "ñ", "日本", "🔑", "א"]:
            with self.subTest(literal=literal):
                self.assertIn(literal, out, "must be emitted verbatim")
        self.assertNotIn("\\/", out)
        self.assertNotIn("\\u00f1", out)
        self.assertNotIn("\\u007f", out)

    def test_unicode_label_keys_sort_bytewise_over_utf8(self):
        labels = self.state.devices["escaped"]["labels"]
        rendered = self.dumps(labels)
        order = [k for k in fixture.UNICODE_LABELS]
        want = sorted(order, key=lambda k: k.encode("utf-8"))
        self.assertEqual([k for k in want if f'"{k}"' in rendered or True], want)
        positions = [rendered.index(json_key(k)) for k in want]
        self.assertEqual(positions, sorted(positions), "keys must be in bytewise UTF-8 order")

    def test_canonical_state_ends_with_exactly_one_newline(self):
        import pathlib
        raw = pathlib.Path(__file__).resolve().parents[3].joinpath(
            "testdata/vectors/state.json").read_bytes()
        self.assertTrue(raw.endswith(b"}\n"))
        self.assertFalse(raw.endswith(b"\n\n"))


def json_key(key: str) -> str:
    from nornref import canonjson
    return canonjson.dumps({key: 0}).split(":")[0][1:]


class E6_KidIsAConstrainedField(unittest.TestCase):
    """A malformed `kid` is a schema violation, not an unresolvable key.

    The two produce different reason codes, so leaving it to chance lets two
    implementations disagree about the same entry.
    """

    def _note_with_kid(self, kid):
        env = entry.new("note", fixture.NET, ts=fixture.T0, after=51, body={"text": "x"})
        entry.sign(env, fixture.KEYS["signer1"], "signer")
        env["sigs"][0]["kid"] = kid
        return cbor.encode(env)

    def test_short_kid_is_decode(self):
        state, n = state_with([self._note_with_kid("abc")])
        self.assertEqual(state.rejected[-1], {"index": n, "reason": "decode"})

    def test_uppercase_kid_is_decode(self):
        state, n = state_with([self._note_with_kid("ABCDEF0123456789")])
        self.assertEqual(state.rejected[-1], {"index": n, "reason": "decode"})

    def test_wellformed_but_unresolvable_kid_is_not_decode(self):
        state, n = state_with([self._note_with_kid("0123456789abcdef")])
        self.assertEqual(state.rejected[-1], {"index": n, "reason": "threshold"})

    def test_malformed_kid_in_a_body_is_decode(self):
        raw = build("signer_remove", {"kid": "nothex!"}, ROOTS3, after=51)
        state, n = state_with([raw])
        self.assertEqual(state.rejected[-1], {"index": n, "reason": "decode"})

    def test_unsorted_sigs_is_decode(self):
        env = entry.new("note", fixture.NET, ts=fixture.T0, after=51, body={"text": "x"})
        entry.sign(env, fixture.KEYS["signer1"], "signer")
        entry.sign(env, fixture.KEYS["root1"], "root")
        env["sigs"].reverse()
        state, n = state_with([cbor.encode(env)])
        self.assertEqual(state.rejected[-1], {"index": n, "reason": "decode"})
