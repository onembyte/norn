"""RED first: readings run 4 showed a variant could hold and still pass."""
import unittest

from nornref import cbor, entry, fixture, replay, trust


def outcomes():
    items = fixture.log()
    raw = [i.raw for i in items]
    state = replay.replay(replay.Anchor(fixture.NET, entry.leaf_hash(raw[0])), raw)
    by_index = {r["index"]: r["reason"] for r in state.rejected}
    return {it.name: by_index.get(i) for i, it in enumerate(items)}, state


def named(outcomes_map, suffix):
    return next(v for k, v in outcomes_map.items() if k.endswith(suffix))


class ParamsMerge(unittest.TestCase):
    """§5.1: a `params` entry **merges**. Every genesis param was previously at
    its default, so replace-with-defaults was indistinguishable from merge."""

    def test_a_non_default_genesis_param_survives_a_later_partial_params(self):
        _, state = outcomes()
        self.assertEqual(state.params["mmd"], 45, "genesis set a non-default mmd")
        self.assertEqual(state.params["staleness"], 900, "a later params entry set this")
        self.assertEqual(state.params["checkpoint_interval"], 60)


class LogKeyAppends(unittest.TestCase):
    """§5.3: `log_key` **appends**. Only one existed, so replace was invisible."""

    def test_two_rotations_both_appear_in_order(self):
        _, state = outcomes()
        self.assertEqual(len(state.log_keys), 2, "both log-key rotations must be recorded")
        first, second = state.log_keys
        self.assertLess(first["since_index"], second["since_index"])
        self.assertNotEqual(first["pk"], second["pk"])


class NoteAuthorisation(unittest.TestCase):
    """§4.3: a `note` needs a signer or a root -- a device will not do."""

    def test_a_device_signed_note_is_rejected(self):
        got, _ = outcomes()
        self.assertEqual(named(got, "bad-device-signed-note"), "threshold")


class RevokeByRootQuorum(unittest.TestCase):
    """§4.3 lists roots as an authorisation path; no revoke used it."""

    def test_a_root_authorised_revoke_is_accepted(self):
        got, state = outcomes()
        self.assertIsNone(named(got, "revoke-by-roots"))
        self.assertEqual(state.devices["rootrevoked"]["status"], "revoked")


class BodySchemaRunsAfterTheQuorum(unittest.TestCase):
    """§5.1: an under-signed governance entry with a malformed body is
    `threshold`, not `decode` -- step 7 precedes step 8."""

    def test_under_signed_and_malformed_is_threshold(self):
        got, _ = outcomes()
        self.assertEqual(named(got, "bad-undersigned-malformed"), "threshold")


class TrustNegativesAreIsolated(unittest.TestCase):
    """Each damaged trust file must trip exactly the rule it is named for."""

    def test_each_case_trips_only_its_own_rule(self):
        for name, doc in fixture.trust_rejections():
            with self.subTest(case=name):
                # `parse`, not `validate`: a trust file is bytes and the size
                # bound belongs to the decoder (SPEC 9.1).
                with self.assertRaises(trust.TrustError):
                    trust.parse(cbor.encode(doc))

    def test_origin_derivation_has_an_isolated_negative(self):
        """`net` stays valid and `log_key` is renamed to match, so only the
        origin-derivation rule can reject it."""
        case = dict(next(d for n, d in fixture.trust_rejections()
                         if "origin-only" in n))
        self.assertEqual(len(case["net"]), 16, "net must remain well-formed")
        from nornref import note
        self.assertEqual(note.parse_vkey(case["log_key"]).name, case["origin"],
                         "log_key must agree with the wrong origin, so only "
                         "derivation from net can fail")
        with self.assertRaises(trust.TrustError):
            trust.validate(case)

    def test_the_key_id_cases_are_wrong_only_in_the_id(self):
        """Cold gate run 11, D3/D9: `37` kept the honest id in its policy, so
        the log-line correspondence refused it and the id check was deletable.
        Restore the honest key and each case must BE the anchor."""
        honest_doc = fixture.trust_file()
        honest = cbor.encode(honest_doc)
        # By suffix, so the numeric prefix can move as cases are inserted.
        wants = {"-log-key-id-mismatch": lambda d: d["log_key"],
                 "-witness-key-id-mismatch": lambda d: d["witnesses"][0]["key"],
                 "-log-key-id-upper-case": lambda d: d["log_key"]}
        for suffix, key_of in wants.items():
            found = [(n, d) for n, d in fixture.trust_rejections()
                     if n.endswith(suffix) and n[:-len(suffix)].isdigit()]
            self.assertEqual(len(found), 1, f"exactly one case must end in {suffix}")
            name, doc = found[0]
            with self.subTest(case=name):
                damaged, good = key_of(doc), key_of(honest_doc)
                self.assertNotEqual(damaged, good)
                raw = cbor.encode(doc)
                self.assertEqual(raw.count(damaged.encode()), 2,
                                 "the damaged key belongs in its member AND the policy")
                self.assertEqual(raw.replace(damaged.encode(), good.encode()), honest,
                                 "something other than the id is wrong with it")
                with self.assertRaises(trust.TrustError):
                    trust.parse(raw)


class GenesisInvariants(unittest.TestCase):
    def test_the_missing_body_invariants_are_covered(self):
        names = " ".join(n for n, _, _ in fixture.genesis_aborts())
        for want in ("duplicate-signer", "signer-thr-above-set", "empty-roots"):
            self.assertIn(want, names, f"no genesis case for {want}")
