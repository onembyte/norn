"""SPEC §3.1 admits the same keys, with the same refusal codes, as Go."""
import copy
import unittest

from nacl.bindings import crypto_core_ed25519_add

from nornref import cbor, enrollreq, entry, fixture, keys, note, policy, replay, trust

SMALL_ORDER = bytes.fromhex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05")
HONEST = fixture.KEYS["spare"].public
KEY_CASES = (
    ("honest", HONEST, True),
    ("small-order", SMALL_ORDER, False),
    ("mixed-order", crypto_core_ed25519_add(HONEST, SMALL_ORDER), False),
)


def root_sign(env):
    env["sigs"] = []
    for name in ("root1", "root2"):
        entry.sign(env, fixture.KEYS[name], "root")
    return entry.encode(env)


def replay_with(raw, extra=()):
    anchor = replay.Anchor(fixture.NET, entry.leaf_hash(raw))
    return replay.replay(anchor, [raw, *extra])


class Admission(unittest.TestCase):
    def test_a_genesis_admits_only_valid_points_in_roots_and_signers(self):
        for role in ("roots", "signers"):
            for name, public, admitted in KEY_CASES:
                with self.subTest(role=role, key=name):
                    env = fixture.genesis()
                    # Replace root3, which does not sign: root1 and root2
                    # still meet the quorum, so only admission can refuse it.
                    env["body"][role][-1] = public
                    state = replay_with(root_sign(env))
                    if admitted:
                        self.assertEqual(state.rejected, [])
                        self.assertEqual(state.size, 1)
                        self.assertIn(public, getattr(state, role).values())
                    else:
                        self.assertEqual(state.rejected, [{"index": 0, "reason": "bad-genesis"}])
                        self.assertEqual(state.size, 0)
                        self.assertEqual(state.roots, {})
                        self.assertEqual(state.signers, {})

    def _governance_admission(self, entry_type):
        genesis = entry.encode(fixture.genesis())
        before = replay_with(genesis)
        for name, public, admitted in KEY_CASES:
            with self.subTest(entry_type=entry_type, key=name):
                body = {"pk": public}
                if entry_type == "log_key":
                    body["overlap"] = 60
                env = entry.new(entry_type, fixture.NET, fixture.T0 + 1, body)
                state = replay_with(genesis, [root_sign(env)])
                if admitted:
                    self.assertEqual(state.rejected, [])
                    if entry_type == "log_key":
                        self.assertEqual(state.log_keys[-1]["pk"], public)
                    else:
                        self.assertIn(public, getattr(state, "roots" if entry_type == "root_add"
                                                      else "signers").values())
                else:
                    self.assertEqual(state.rejected, [{"index": 1, "reason": "decode"}])
                    expected = before.to_dict()
                    expected.update(size=2, rejected=state.rejected)
                    self.assertEqual(state.to_dict(), expected)
                # Governance body validation follows the root quorum. Even
                # a malformed key is threshold when only one root signs.
                env["sigs"] = []
                entry.sign(env, fixture.KEYS["root1"], "root")
                state = replay_with(genesis, [entry.encode(env)])
                self.assertEqual(state.rejected, [{"index": 1, "reason": "threshold"}])

    def test_root_add_admits_only_a_valid_point_after_the_quorum(self):
        self._governance_admission("root_add")

    def test_signer_add_admits_only_a_valid_point_after_the_quorum(self):
        self._governance_admission("signer_add")

    def test_log_key_admits_only_a_valid_point_after_the_quorum(self):
        self._governance_admission("log_key")

    def _request(self, public):
        req = enrollreq.new(fixture.NET, "spare", HONEST, fixture.WG["spare"], fixture.T0)
        # Construct hostile bytes without asking the constructor to admit
        # them. The honest case proves possession; bad cases must not decode,
        # before their deliberately mismatched signature is considered.
        req["device_pk"] = public
        enrollreq.sign(req, fixture.KEYS["spare"], strict=False)
        return req

    def test_a_requests_device_pk_must_be_a_valid_point(self):
        for name, public, admitted in KEY_CASES:
            with self.subTest(key=name):
                req = self._request(public)
                if admitted:
                    self.assertEqual(enrollreq.decode(cbor.encode(req)), req)
                    self.assertTrue(enrollreq.verify(req))
                    self.assertEqual(enrollreq.new(fixture.NET, "spare", public,
                                                  fixture.WG["spare"], fixture.T0)["device_pk"], public)
                else:
                    with self.assertRaisesRegex(enrollreq.RequestError, "device_pk"):
                        enrollreq.decode(cbor.encode(req))
                    with self.assertRaisesRegex(enrollreq.RequestError, "device_pk"):
                        enrollreq.new(fixture.NET, "spare", public, fixture.WG["spare"], fixture.T0)
                # These exact bytes are still admitted as an X25519 wg_pk:
                # applying the Ed25519 predicate there changes the protocol.
                wg_req = self._request(HONEST)
                wg_req["wg_pk"] = public
                enrollreq.sign(wg_req, fixture.KEYS["spare"])
                self.assertEqual(enrollreq.decode(cbor.encode(wg_req)), wg_req)
                self.assertTrue(enrollreq.verify(wg_req))

    def test_an_enrollment_of_an_invalid_device_pk_is_decode(self):
        genesis = entry.encode(fixture.genesis())
        before = replay_with(genesis)
        for name, public, admitted in KEY_CASES:
            with self.subTest(key=name):
                env = entry.new("enroll", fixture.NET, fixture.T0 + 1,
                                {"request": cbor.encode(self._request(public))})
                entry.sign(env, fixture.KEYS["signer1"], "signer")
                state = replay_with(genesis, [entry.encode(env)])
                if admitted:
                    self.assertEqual(state.rejected, [])
                    self.assertEqual(state.devices["spare"]["device_pk"], public)
                else:
                    self.assertEqual(state.rejected, [{"index": 1, "reason": "decode"}])
                    expected = before.to_dict()
                    expected.update(size=2, rejected=state.rejected)
                    self.assertEqual(state.to_dict(), expected)

    def _trust_admission(self, role):
        for name, public, admitted in KEY_CASES:
            with self.subTest(role=role, key=name):
                doc = copy.deepcopy(fixture.trust_file())
                if role == "log_key":
                    old = doc[role]
                    new = note.vkey(doc["origin"], public)
                    doc[role] = new
                else:
                    witness = doc["witnesses"][0]
                    old = witness["key"]
                    new = note.vkey(note.parse_vkey(old).name, public, note.ALG_COSIGNATURE)
                    witness["key"] = new
                # Keep every occurrence in agreement, so correspondence and
                # verifier-key syntax cannot hide a missing admission check.
                doc["policy"] = doc["policy"].replace(old, new)
                if admitted:
                    trust.validate(doc)
                    self.assertEqual(trust.parse(trust.encode(doc)), doc)
                else:
                    with self.assertRaisesRegex(trust.TrustError, role):
                        trust.validate(doc)
                    with self.assertRaisesRegex(trust.TrustError, role):
                        trust.parse(trust.encode(doc))

    def test_a_trust_files_log_key_must_be_a_valid_point(self):
        self._trust_admission("log_key")

    def test_a_trust_files_witness_keys_must_be_valid_points(self):
        self._trust_admission("witness")


class RemainingAdmission(unittest.TestCase):
    def test_rotate_admits_only_valid_incoming_points_before_device_lookup(self):
        genesis = entry.encode(fixture.genesis())
        enroll = entry.new("enroll", fixture.NET, fixture.T0 + 1, fixture._enroll_body("pi-cam"))
        entry.sign(enroll, fixture.KEYS["signer1"], "signer")
        anchor = replay.Anchor(fixture.NET, entry.leaf_hash(genesis))
        raw = [genesis, entry.encode(enroll)]
        before = replay.replay(anchor, raw)
        self.assertEqual(before.rejected, [])
        for kind, public, admitted in KEY_CASES:
            for device_id in ("pi-cam", "unknown"):
                with self.subTest(key=kind, device=device_id):
                    env = entry.new("rotate", fixture.NET, fixture.T0 + 2,
                                    {"device_id": device_id, "wg_pk": fixture.WG["spare"],
                                     "device_pk": public})
                    for name in ("pi-cam", "spare"):
                        entry.sign(env, fixture.KEYS[name], "device")
                    state = replay.replay(anchor, [*raw, entry.encode(env)])
                    reason = ("unknown-device" if device_id == "unknown" else "") if admitted else "decode"
                    self.assertEqual(state.rejected, [{"index": 2, "reason": reason}] if reason else [])
                    if reason:
                        self.assertEqual(state.devices, before.devices)
                        self.assertEqual(state.active_wg, before.active_wg)
                    else:
                        self.assertEqual(state.devices[device_id]["device_pk"], public)

    def test_policy_admits_only_valid_verifier_points_after_the_quorum(self):
        genesis = entry.encode(fixture.genesis())
        for kind, public, admitted in KEY_CASES:
            for directive, algorithm in (("witness", note.ALG_COSIGNATURE), ("log", note.ALG_ED25519)):
                with self.subTest(key=kind, directive=directive):
                    key = note.vkey("admission", public, algorithm)
                    text = f"witness w {key}\nquorum w\n" if directive == "witness" else f"log {key}\nquorum none\n"
                    if admitted:
                        policy.parse(text)
                    else:
                        with self.assertRaises(policy.PolicyError):
                            policy.parse(text)
                    env = entry.new("policy", fixture.NET, fixture.T0 + 1, {"text": text})
                    state = replay_with(genesis, [root_sign(env)])
                    self.assertEqual(state.rejected, [] if admitted else [{"index": 1, "reason": "decode"}])
                    self.assertEqual(state.policy, text if admitted else "")
                    env["sigs"] = []
                    entry.sign(env, fixture.KEYS["root1"], "root")
                    self.assertEqual(replay_with(genesis, [entry.encode(env)]).rejected,
                                     [{"index": 1, "reason": "threshold"}])

    def test_a_trust_policy_cannot_hide_an_invalid_key_before_an_honest_one(self):
        doc = copy.deepcopy(fixture.trust_file())
        trust.validate(doc)
        # A text reader that keeps only the last key for a witness name can
        # hide an earlier invalid point from the correspondence check.
        invalid = note.vkey("norn-witness/pi", SMALL_ORDER, note.ALG_COSIGNATURE)
        doc["policy"] = f"witness pi {invalid}\n" + doc["policy"]
        with self.assertRaises(trust.TrustError):
            trust.validate(doc)
