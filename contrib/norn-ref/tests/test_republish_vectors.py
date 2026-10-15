"""D-078's distributed inputs, with answers taken from §5.1 and §9.1."""
import json
from pathlib import Path
import unittest

from nornref import cbor, entry, fixture, policy, replay, trust

ROOT = Path(__file__).resolve().parents[3] / "testdata" / "vectors"
NAMES = ["00-genesis", "01-enroll-nas", "02-revoke-stripped", "03-revoke-genuine",
         "04-note-preimage", "05-note-genuine", "06-copy-applied-extra-sig",
         "07-copy-refused-bytes", "08-log-key-anchor", "09-log-key-new",
         "10-log-key-learned", "11-policy-name-not-ascii", "12-policy-name-ascii",
         "13-params-two-byte-true", "14-params-canonical-true", "15-copy-genesis-extra-sig",
         "16-policy-text-at-the-cap", "17-policy-text-one-past-the-cap"]
CODES = ["", "", "threshold", "", "decode", "", "dup-entry", "dup-entry",
         "dup-key", "", "dup-key", "decode", "", "decode", "", "dup-entry", "", "decode"]


class RepublishVectors(unittest.TestCase):
    def test_every_republish_case_matches_and_repairs_its_named_fault(self):
        root = ROOT / "log-republish"
        manifest = json.loads((root / "manifest.json").read_text())
        a = manifest["anchor"]
        anchor = replay.Anchor(bytes.fromhex(a["net"]), bytes.fromhex(a["genesis_hash"]),
                               a["log_key"], a["policy"])
        self.assertEqual([it["name"] for it in manifest["entries"]], NAMES)
        self.assertEqual([it["reason"] for it in manifest["entries"]], CODES)
        self.assertEqual(set(manifest["rules"]), set(NAMES))
        self.assertEqual(manifest["codes"], {name: code for name, code in zip(NAMES, CODES) if code})
        raw = [(root / (name + ".cbor")).read_bytes() for name in NAMES]
        final = replay.replay(anchor, raw)

        def check(prefix, repaired, want=""):
            result = replay.replay(anchor, prefix + [repaired])
            got = next((r["reason"] for r in result.rejected if r["index"] == len(prefix)), "")
            self.assertEqual(got, want)

        for i, name in enumerate(NAMES):
            with self.subTest(case=name):
                got = next((r["reason"] for r in final.rejected if r["index"] == i), "")
                self.assertEqual(got, CODES[i], f"reference {name}: {got!r}")
                if CODES[i]:
                    self.assertEqual((root / (name + ".reason")).read_text(), CODES[i] + "\n")
                    before, after = replay.replay(anchor, raw[:i]), replay.replay(anchor, raw[:i+1])
                    after.size, after.rejected = before.size, before.rejected
                    self.assertEqual(after.to_json(), before.to_json(), "refusal changed state")
                if i in (13, 14):
                    marker = b"\x73rotate_needs_signer"
                    self.assertEqual(raw[14].count(marker + b"\xf5"), 1)
                    self.assertEqual(raw[13], raw[14].replace(marker + b"\xf5", marker + b"\xf8\x15", 1))
                    check(raw[:13], raw[14])
                elif i == 15:
                    env = cbor.decode(raw[i])
                    self.assertEqual(env["sigs"].pop(), {"kid": "ffffffffffffffff", "role": "signer", "sig": bytes(64)})
                    self.assertEqual(entry.encode(env), raw[0])
                    self.assertNotEqual(raw[i], raw[0])
                    # Removing the duplicate occurrence leaves a sound genesis.
                    repaired_anchor = replay.Anchor(anchor.net, entry.leaf_hash(raw[i]), anchor.log_key, anchor.policy)
                    alone = replay.replay(repaired_anchor, [raw[i]])
                    self.assertEqual(alone.size, 1)
                    self.assertEqual(alone.rejected, [])
                elif i in (16, 17):
                    env = cbor.decode(raw[i])
                    text = env["body"]["text"]
                    self.assertEqual(len(text.encode()), 4096+i-16)
                    self.assertLess(len(text), 4096)
                    policy.parse(text)
                    if i == 17:
                        self.assertTrue(text.endswith("x\n"))
                        env["body"]["text"] = text[:-2] + "\n"
                        env["sigs"] = []
                        for key in ("root1", "root2"):
                            entry.sign(env, fixture.KEYS[key], "root")
                        check(raw[:i], entry.encode(env))
                elif i == 2:
                    env = cbor.decode(raw[i])
                    entry.sign(env, fixture.KEYS["signer1"], "signer")
                    self.assertEqual(entry.encode(env), raw[3], "genuine changes more than signatures")
                    check(raw[:i], entry.encode(env))
                elif i in (3, 5):
                    check(raw[:i-1], raw[i])
                elif i == 4:
                    self.assertEqual(raw[i], entry.preimage(cbor.decode(raw[5])))
                    check(raw[:i], raw[5])
                elif i == 6:
                    env, original = cbor.decode(raw[i]), cbor.decode(raw[5])
                    extra = env["sigs"].pop()
                    self.assertEqual(extra, {"kid": "ffffffffffffffff", "role": "signer", "sig": bytes(64)})
                    self.assertEqual(env, original)
                    check(raw[:5], raw[i])
                elif i == 7:
                    self.assertEqual(raw[i], raw[2])
                    # Before the genuine revoke applies, only the byte set can
                    # refuse this copy. Without it threshold decides; adding
                    # only the missing signatures accepts against that prefix.
                    check(raw[:3], raw[i], "dup-entry")
                    check(raw[:2], raw[i], "threshold")
                    check(raw[:3], raw[3])
                elif i in (8, 10, 11):
                    env = cbor.decode(raw[i])
                    if i == 11:
                        env["body"]["text"] = env["body"]["text"].replace("zürich", "zurich")
                    else:
                        env["body"]["pk"] = fixture.KEYS["logkey3"].public
                    env["sigs"] = []
                    for key in ("root1", "root2"):
                        entry.sign(env, fixture.KEYS[key], "root")
                    check(raw[:i], entry.encode(env))
        self.assertIs(final.params["rotate_needs_signer"], True)
        self.assertEqual(final.devices["nas"]["status"], "revoked")
        self.assertEqual((final.to_json() + "\n").encode(), (root / "state.json").read_bytes())

    def test_shipped_policy_names_have_only_their_named_fault(self):
        root = ROOT / "policies"
        manifest = json.loads((root / "cases.json").read_text())
        cases = {c["name"]: c["accept"] for c in manifest["cases"]}
        for name, bad, good, accept in (
                ("bad-witness-name-not-ascii", "zürich", "zurich", False),
                ("bad-group-name-plus", "a+b", "ab", False),
                ("bad-witness-name-one-past-the-cap", "a" * 65, "a" * 64, False),
                ("witness-name-at-the-cap", "a" * 64, "a" * 64, True)):
            with self.subTest(case=name):
                self.assertIn(name, cases)
                self.assertEqual(cases[name], accept)
                text = (root / (name + ".txt")).read_text()
                self.assertIn(bad, text)
                if accept:
                    policy.parse(text)
                else:
                    with self.assertRaises(policy.PolicyError):
                        policy.parse(text)
                policy.parse(text.replace(bad, good))

    def test_shipped_trust_witness_name_repairs_with_the_policy(self):
        root = ROOT / "trust-bad"
        name = "54-witness-name-not-ascii"
        self.assertIn(name, json.loads((root / "cases.json").read_text())["cases"])
        raw = (root / (name + ".cbor")).read_bytes()
        doc = cbor.decode(raw)
        self.assertEqual(doc["witnesses"][0]["name"], "zürich")
        self.assertIn("witness zürich ", doc["policy"])
        with self.assertRaises(trust.TrustError):
            trust.parse(raw)
        doc["witnesses"][0]["name"] = "zurich"
        doc["policy"] = doc["policy"].replace("zürich", "zurich")
        trust.parse(trust.encode(doc))

    def test_trust_log_key_small_order_repairs_only_the_point(self):
        root = ROOT / "trust-bad"
        name = "55-log-key-small-order"
        self.assertIn(name, json.loads((root / "cases.json").read_text())["cases"])
        raw = (root / (name + ".cbor")).read_bytes()
        doc = cbor.decode(raw)
        from nornref import note
        key = note.parse_vkey(doc["log_key"])
        self.assertEqual(key.name, doc["origin"])
        self.assertEqual(key.public, fixture.ORDER_EIGHT)
        self.assertFalse(any(line.startswith("log ") for line in doc["policy"].splitlines()))
        with self.assertRaisesRegex(trust.TrustError, "log_key must be a valid Ed25519 point"):
            trust.parse(raw)
        doc["log_key"] = fixture.log_vkey()
        trust.parse(trust.encode(doc))
