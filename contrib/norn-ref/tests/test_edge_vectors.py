"""Norn's own §3.1 vectors, read from the distributed suite."""
import base64
import hashlib
import json
from pathlib import Path
import unittest
from unittest import mock

from nacl.bindings import (crypto_core_ed25519_add, crypto_core_ed25519_sub,
                          crypto_scalarmult_ed25519_base_noclamp,
                          crypto_scalarmult_ed25519_noclamp)

from nornref import bech32m, cbor, enrollreq, entry, fixture, keys, note, policy, replay, trust

ROOT = Path(__file__).resolve().parents[3] / "testdata" / "vectors"
IDENTITY = b"\x01" + bytes(31)


def replay_case(directory):
    manifest = json.loads((directory / "manifest.json").read_text())
    anchor = replay.Anchor(**{k: bytes.fromhex(v) for k, v in manifest["anchor"].items()})
    raw = [(directory / (e["name"] + ".cbor")).read_bytes() for e in manifest["entries"]]
    state = replay.replay(anchor, raw)
    return manifest, raw, state


def request_case(name):
    text = (ROOT / "requests-bad" / (name + ".txt")).read_text().strip()
    return cbor.decode(bech32m.decode(text)[1])


class ReplayEdges(unittest.TestCase):
    def test_admission_log_matches_its_manifest_and_state_byte_for_byte(self):
        directory = ROOT / "log-admission"
        manifest, raw, state = replay_case(directory)
        self.assertEqual(len(raw), 9)
        expected = [{"index": e["index"], "reason": e["reason"]}
                    for e in manifest["entries"] if e["reason"]]
        self.assertEqual(state.rejected, expected)
        self.assertEqual(expected, [{"index": i, "reason": "decode"} for i in (1, 2, 3, 6, 7)])
        self.assertEqual(len(state.signers), 3)
        self.assertIn(fixture.KEYS["signer3"].id, state.signers)
        self.assertEqual((state.to_json() + "\n").encode(), (directory / "state.json").read_bytes())
        self.assertEqual(state.policy, cbor.decode(raw[8])["body"]["text"])
        self.assertEqual(state.devices["pi-cam"]["device_pk"], fixture.KEYS["pi-cam"].public)
        self.assertEqual(state.devices["pi-cam"]["wg_pk"], fixture.WG["pi-cam"])
        for item in raw[1:]:
            env = cbor.decode(item)
            if env["t"] in ("enroll", "rotate"):
                continue
            self.assertEqual(sum(entry.verify_sig(env, sig, fixture.KEYS[name].public)
                                 for sig in env["sigs"] for name in fixture.ROOTS
                                 if sig["kid"] == fixture.KEYS[name].id), 2)

    def test_incoming_rotate_key_satisfies_only_the_cofactored_equation(self):
        env = cbor.decode((ROOT / "log-admission/06-rotate-mixed-order.cbor").read_bytes())
        public, message = env["body"]["device_pk"], entry.preimage(env)
        honest = fixture.KEYS["spare"].public
        self.assertEqual(public, crypto_core_ed25519_add(honest, fixture.ORDER_EIGHT))
        current = next(sig for sig in env["sigs"] if sig["kid"] == fixture.KEYS["pi-cam"].id)
        self.assertTrue(entry.verify_sig(env, current, fixture.KEYS["pi-cam"].public))
        incoming = next(sig for sig in env["sigs"] if sig["kid"] == keys.kid(public))
        sig = incoming["sig"]
        self.assertTrue(keys.valid_point(sig[:32]))
        self.assertLess(int.from_bytes(sig[32:], "little"), keys.L)
        k = int.from_bytes(hashlib.sha512(sig[:32] + public + message).digest(), "little") % keys.L
        sb = crypto_scalarmult_ed25519_base_noclamp(sig[32:])
        # Libsodium refuses scalar multiplication of mixed-order points.
        # Compute [k](A + T) independently as [k]A + [k mod 8]T instead.
        ka = crypto_scalarmult_ed25519_noclamp(k.to_bytes(32, "little"), honest)
        for _ in range(k % 8):
            ka = crypto_core_ed25519_add(ka, fixture.ORDER_EIGHT)
        difference = crypto_core_ed25519_sub(crypto_core_ed25519_sub(sb, sig[:32]), ka)
        self.assertNotEqual(difference, IDENTITY, "cofactorless equation must fail")
        for _ in range(3):
            difference = crypto_core_ed25519_add(difference, difference)
        self.assertEqual(difference, IDENTITY, "cofactored equation must hold")
        self.assertFalse(keys.valid_point(public))
        self.assertFalse(entry.verify_sig(env, incoming, public))

    def test_policy_vector_fails_only_for_its_small_order_witness(self):
        env = cbor.decode((ROOT / "log-admission/07-policy-small-order.cbor").read_bytes())
        key = note.vkey("norn-witness/pi", fixture.ORDER_EIGHT, note.ALG_COSIGNATURE)
        note.parse_vkey(key)
        text = f"witness pi {key}\nquorum pi\n"
        self.assertEqual(env["body"]["text"], text)
        with self.assertRaises(policy.PolicyError):
            policy.parse(text)
        policy.parse(text.replace(key, fixture.witness_vkey("pi")))

    def test_empty_log_matches_its_state_byte_for_byte(self):
        directory = ROOT / "log-empty"
        _, raw, state = replay_case(directory)
        self.assertEqual(raw, [])
        self.assertEqual((state.to_json() + "\n").encode(), (directory / "state.json").read_bytes())

    def test_genesis_edges_have_honest_root_quorums_and_abort(self):
        for name in ("23-root-order-eight", "24-root-noncanonical"):
            with self.subTest(case=name):
                directory = ROOT / "genesis" / name
                _, raw, state = replay_case(directory)
                env = cbor.decode(raw[0])
                self.assertEqual(env["body"]["roots"][:3],
                                 [fixture.KEYS[n].public for n in fixture.ROOTS])
                self.assertEqual(len(env["body"]["roots"]), 4)
                self.assertEqual(sum(entry.verify_sig(env, sig, fixture.KEYS[n].public)
                                     for sig in env["sigs"] for n in fixture.ROOTS
                                     if sig["kid"] == fixture.KEYS[n].id), 2)
                self.assertEqual(state.rejected, [{"index": 0, "reason": "bad-genesis"}])
                self.assertEqual(state.size, 0)
                self.assertEqual((state.to_json() + "\n").encode(), (directory / "state.json").read_bytes())


class RequestEdges(unittest.TestCase):
    def test_small_order_device_key_is_refused_at_decode(self):
        req = request_case("small-order-device-pk")
        with self.assertRaises(enrollreq.RequestError):
            enrollreq.decode(cbor.encode(req))

    def test_torsion_R_satisfies_only_the_cofactored_equation(self):
        import hashlib
        req = request_case("torsion-R-signature")
        enrollreq.decode(cbor.encode(req))
        sig, public, message = req["sig"], req["device_pk"], enrollreq.preimage(req)
        k = int.from_bytes(hashlib.sha512(sig[:32] + public + message).digest(), "little") % keys.L
        sb = crypto_scalarmult_ed25519_base_noclamp(sig[32:])
        ka = crypto_scalarmult_ed25519_noclamp(k.to_bytes(32, "little"), public)
        difference = crypto_core_ed25519_sub(crypto_core_ed25519_sub(sb, sig[:32]), ka)
        self.assertNotEqual(difference, IDENTITY)
        for _ in range(3):
            difference = crypto_core_ed25519_add(difference, difference)
        self.assertEqual(difference, IDENTITY, "this must be accepted by a cofactored verifier")
        self.assertFalse(enrollreq.verify(req))
        # Libsodium also refuses this R. The explicit point gate must reject
        # it even with a backend that accepts the cofactored equation.
        with mock.patch.object(keys, "VerifyKey") as backend:
            self.assertFalse(enrollreq.verify(req))
            backend.assert_not_called()

    def test_S_plus_L_is_refused_and_reduction_repairs_only_the_scalar(self):
        req = request_case("S-plus-L-signature")
        sig = req["sig"]
        self.assertGreaterEqual(int.from_bytes(sig[32:], "little"), keys.L)
        self.assertFalse(enrollreq.verify(req))
        with mock.patch.object(keys, "VerifyKey") as backend:
            self.assertFalse(enrollreq.verify(req))
            backend.assert_not_called()
        req["sig"] = sig[:32] + (int.from_bytes(sig[32:], "little") - keys.L).to_bytes(32, "little")
        self.assertTrue(enrollreq.verify(req))


class TrustEdges(unittest.TestCase):
    def test_noncanonical_witness_is_carried_into_the_policy_and_refused(self):
        doc = cbor.decode((ROOT / "trust-bad" / "47-witness-noncanonical-point.cbor").read_bytes())
        damaged = doc["witnesses"][0]["key"]
        self.assertIn("witness pi " + damaged + " ", doc["policy"])
        with self.assertRaises(trust.TrustError):
            trust.validate(doc)
        doc["witnesses"][0]["key"] = fixture.witness_vkey("pi")
        doc["policy"] = doc["policy"].replace(damaged, fixture.witness_vkey("pi"))
        trust.validate(doc)

    def test_checkpoint_scalar_is_the_only_damaged_cosignature_field(self):
        # The reference does not implement checkpoint verification. Exercise
        # its shared signature predicate on the actual cosignature preimage.
        damaged = (ROOT / "checkpoints-bad" / "31-cosignature-S-plus-L.checkpoint").read_text()
        honest = (ROOT / "served" / "checkpoint").read_text()
        body, block = damaged.split("\n\n", 1)
        honest_body, honest_block = honest.split("\n\n", 1)
        self.assertEqual(body, honest_body)
        different = [(a, b) for a, b in zip(block.splitlines(), honest_block.splitlines()) if a != b]
        self.assertEqual(len(different), 1)
        line, original = different[0]
        name, payload = line[2:].split(" ")
        honest_name, honest_payload = original[2:].split(" ")
        self.assertEqual(name, honest_name)
        payload, honest_payload = base64.b64decode(payload), base64.b64decode(honest_payload)
        self.assertEqual(payload[:44], honest_payload[:44])
        self.assertEqual(int.from_bytes(payload[44:], "little"),
                         int.from_bytes(honest_payload[44:], "little") + keys.L)
        key = note.parse_vkey(next(w["key"] for w in fixture.trust_file()["witnesses"]
                                  if note.parse_vkey(w["key"]).name == name))
        at = int.from_bytes(payload[4:12], "big")
        message = f"cosignature/v1\ntime {at}\n{body}\n".encode()
        self.assertTrue(keys.verify(key.public, message, honest_payload[12:]))
        self.assertFalse(keys.verify(key.public, message, payload[12:]))
        with mock.patch.object(keys, "VerifyKey") as backend:
            self.assertFalse(keys.verify(key.public, message, payload[12:]))
            backend.assert_not_called()
