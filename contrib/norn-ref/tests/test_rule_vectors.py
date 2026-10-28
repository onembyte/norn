"""Runs 16 and 17's plainly stated rules, read from the distributed replay fixture."""
import json
from pathlib import Path
import unittest

from nornref import cbor, entry, enrollreq, fixture, replay, policy, note

ROOT = Path(__file__).resolve().parents[3] / "testdata" / "vectors" / "log-rules"
NAMES = ["00-genesis", "01-enroll-nas", "02-enroll-laptop",
         "03-revoke-nas-by-laptop", "04-revoke-nas-by-self",
         "05-signer-add-without-prev", "06-signer-add-prev-zero",
         "07-note-without-ts", "08-note-with-ts", "09-enroll-empty-label-value",
         "10-policy-preannounces-log-key", "11-log-key-preannounced",
         "12-copy-enroll-unsorted-sigs", "13-copy-enroll-sorted-sigs",
         "14-root-threshold-full", "15-root-remove-unknown-before-invariant",
         "16-root-remove-known-at-full-threshold", "17-root-threshold-repaired",
         "18-root-remove-known", "19-root-restore-known",
         "20-note-uppercase-kid", "21-note-without-surplus-kid",
         "22-enroll-by-roots", "23-enroll-with-signer",
         "24-enroll-expires-zero", "25-enroll-without-expires", "26-policy-trailing-space",
         "27-params-by-signers", "28-enroll-envelope-device-sig", '29-enroll-unknown-body-key', '30-note-long-hex-kid', '31-revoke-uppercase-device-id', '32-rotate-uppercase-device-id', '33-policy-log-key-was-witness', '34-params-staleness-zero', '35-params-checkpoint-interval-zero', '36-params-mmd-zero']
CODES = ["", "", "", "threshold", "", "stale-state", "", "decode", "", "", "", "",
         "decode", "dup-entry", "", "unknown-key", "root-invariant", "", "", "", "decode", "", "threshold", "", "decode", "", "", "threshold", "no-device-sig", "decode", "decode", "decode", "decode", "", "", "", ""]

NAMES += ['37-params-without-prev', '38-params-stale-prev', '39-params-current-prev', '40-note-ts-two-to-63', '41-note-ts-at-the-cap', '42-note-after-bool', '43-note-after-uint', '44-enroll-expired-before-entry-ts']
CODES += ['stale-state', 'stale-state', '', 'decode', '', 'decode', '', '']

class RuleVectors(unittest.TestCase):
    def test_every_rule_case_matches_and_each_refusal_repairs(self):
        manifest = json.loads((ROOT / "manifest.json").read_text())
        a = manifest["anchor"]
        self.assertEqual(set(a), {"net", "genesis_hash", "log_key", "policy"})
        anchor = replay.Anchor(bytes.fromhex(a["net"]), bytes.fromhex(a["genesis_hash"]),
                               a["log_key"], a["policy"])
        self.assertEqual([it["name"] for it in manifest["entries"]], NAMES)
        self.assertEqual([it["reason"] for it in manifest["entries"]], CODES)
        self.assertEqual(manifest["codes"], {n: c for n, c in zip(NAMES, CODES) if c})
        self.assertEqual(set(manifest["rules"]), set(NAMES))
        spec = (ROOT.parents[2] / "SPEC.md").read_text()
        raw = [(ROOT / (name + ".cbor")).read_bytes() for name in NAMES]
        final = replay.replay(anchor, raw)

        def check(prefix, value, want=""):
            result = replay.replay(anchor, prefix + [value])
            got = next((r["reason"] for r in result.rejected if r["index"] == len(prefix)), "")
            self.assertEqual(got, want)

        for i, name in enumerate(NAMES):
            with self.subTest(case=name):
                self.assertEqual(manifest["entries"][i]["index"], i)
                rule = manifest["rules"][name]
                heading = ("### " if "." in rule["section"] else "## ") + rule["section"] + " "
                section = spec.split(heading, 1)[1].split("\n##", 1)[0]
                self.assertTrue(rule["says"])
                self.assertTrue(any(rule["says"] in line for line in section.splitlines()))
                got = next((r["reason"] for r in final.rejected if r["index"] == i), "")
                self.assertEqual(got, CODES[i], f"reference {name}: {got!r}")
                if i >= 37:
                    from test_run20_vectors import check_rule
                    check_rule(self, anchor, raw, i)
                if not CODES[i]:
                    continue
                self.assertEqual((ROOT / (name + ".reason")).read_text(), CODES[i] + "\n")
                before, after = replay.replay(anchor, raw[:i]), replay.replay(anchor, raw[:i+1])
                after.size, after.rejected = before.size, before.rejected
                self.assertEqual(after.to_json(), before.to_json(), "refusal changed state")
                if i >= 37:
                    continue
                env = cbor.decode(raw[i])
                if i == 3:
                    env["sigs"] = []
                    entry.sign(env, fixture.KEYS["nas"], "device")
                    self.assertEqual(entry.encode(env), raw[4])
                    check(raw[:i], raw[4])
                elif i == 5:
                    self.assertNotIn("prev", env)
                    env["prev"] = 0
                    env["sigs"] = []
                    fixture._signed(env, [("root1", "root"), ("root2", "root")])
                    self.assertEqual(entry.encode(env), raw[6])
                    check(raw[:i], raw[6])
                elif i == 7:
                    self.assertNotIn("ts", env)
                    repaired = cbor.decode(raw[8])
                    env["ts"] = repaired["ts"]
                    env["sigs"] = []
                    entry.sign(env, fixture.KEYS["signer1"], "signer")
                    self.assertEqual(entry.encode(env), raw[8])
                    check(raw[:i], raw[8])
                elif i == 12:
                    self.assertEqual(env["sigs"], list(reversed(cbor.decode(raw[1])["sigs"])))
                    env["sigs"].reverse()
                    self.assertEqual(entry.encode(env), raw[1])
                    self.assertEqual(raw[13], raw[1])
                    check(raw[:i], raw[13], "dup-entry")
                    check(raw[:1], raw[13])
                elif i == 13:
                    check(raw[:1], raw[i])
                elif i == 15:
                    env["body"]["kid"] = fixture.KEYS["root3"].id
                    env["sigs"] = []
                    fixture._signed(env, [(key, "root") for key in fixture.ROOTS])
                    self.assertEqual(entry.encode(env), raw[16])
                    check(raw[:i], raw[16], "root-invariant")
                    check(raw[:18], raw[18])
                elif i == 16:
                    check(raw[:18], raw[18])
                elif i == 20:
                    self.assertEqual(len(env["sigs"]), 2)
                    surplus = next(s for s in env["sigs"] if s["kid"] != fixture.KEYS["signer1"].id)
                    self.assertEqual(surplus["kid"], fixture.KEYS["signer1"].id.upper())
                    self.assertNotEqual(surplus["kid"], surplus["kid"].lower())
                    env["sigs"].remove(surplus)
                    self.assertEqual(entry.encode(env), raw[21])
                    check(raw[:i], raw[21])
                elif i == 22:
                    before = replay.replay(anchor, raw[:i])
                    self.assertEqual(set(before.roots), {fixture.KEYS[k].id for k in fixture.ROOTS})
                    self.assertEqual({s["kid"] for s in env["sigs"]}, set(before.roots))
                    self.assertEqual({s["role"] for s in env["sigs"]}, {"root"})
                    req = enrollreq.decode(env["body"]["request"])
                    self.assertNotIn(req["device_id"], before.devices)
                    self.assertNotIn(req["wg_pk"], before.active_wg)
                    self.assertTrue(enrollreq.verify(req))
                    entry.sign(env, fixture.KEYS["signer1"], "signer")
                    self.assertEqual(entry.encode(env), raw[23])
                    check(raw[:i], raw[23])
                elif i == 24:
                    req = cbor.decode(env["body"]["request"])
                    self.assertEqual(req["expires"], 0)
                    self.assertGreater(req["ts"], 0)
                    del req["expires"]
                    enrollreq.sign(req, fixture.KEYS["sundial"])
                    env["body"]["request"] = cbor.encode(req)
                    env["sigs"] = []
                    entry.sign(env, fixture.KEYS["signer1"], "signer")
                    self.assertEqual(entry.encode(env), raw[25])
                    check(raw[:i], raw[25])
                elif i in (27, 28):
                    self.assertGreaterEqual(len(replay._valid_kids(env, "signer", before.signers)), before.signer_thr)
                    if i == 27:
                        self.assertEqual(len(env["sigs"]), 2)
                        self.assertEqual({sig["role"] for sig in env["sigs"]}, {"signer"})
                        self.assertEqual(replay._valid_kids(env, "root", before.roots), set())
                        fixture._signed(env, [("root1", "root"), ("root2", "root")])
                    else:
                        req = enrollreq.decode(env["body"]["request"])
                        self.assertFalse(enrollreq.verify(req))
                        self.assertTrue(replay._device_signed(env, req["device_pk"]))
                        enrollreq.sign(req, fixture.KEYS["spare"])
                        env["body"]["request"] = cbor.encode(req)
                        env["sigs"] = []
                        fixture._signed(env, [("spare", "device"), ("signer1", "signer")])
                    check(raw[:i], entry.encode(env))
                elif i == 29:
                    self.assertEqual(set(env["body"]), {"request", "x"})
                    self.assertTrue(enrollreq.verify(enrollreq.decode(env["body"]["request"])))
                    del env["body"]["x"]
                    env["sigs"] = []
                    fixture._signed(env, [("signer1", "signer")])
                    check(raw[:i], entry.encode(env))
                elif i == 30:
                    self.assertEqual(len(env["sigs"]), 2)
                    self.assertEqual([s["kid"] for s in env["sigs"]], sorted({s["kid"] for s in env["sigs"]}))
                    surplus = next(s for s in env["sigs"] if len(s["kid"]) == 17)
                    self.assertTrue(set(surplus["kid"]) <= set("0123456789abcdef"))
                    env["sigs"].remove(surplus)
                    check(raw[:i], entry.encode(env))
                elif i in (31, 32):
                    self.assertEqual(env["body"]["device_id"], "NAS")
                    env["body"]["device_id"] = "unknown-device"
                    env["sigs"] = []
                    fixture._signed(env, [("signer1", "signer")] if i == 31 else [("nas", "device")])
                    check(raw[:i], entry.encode(env), "unknown-device")
                    env["body"]["device_id"] = "laptop"
                    env["prev"] = before.devices["laptop"]["version"]
                    env["sigs"] = []
                    fixture._signed(env, [("signer1", "signer")] if i == 31 else [("laptop", "device")])
                    check(raw[:i], entry.encode(env))
                else:
                    self.fail("refusal has no repair")
        self.assertEqual((final.to_json() + "\n").encode(), (ROOT / "state.json").read_bytes())

        before = replay.replay(anchor, raw[:33])
        self.assertTrue(replay._witness_holds(before.policy, fixture.KEYS["witness-pi"].public))
        env = cbor.decode(raw[33])
        text = env["body"]["text"]
        policy.parse(text)
        self.assertFalse(replay._witness_holds(text, fixture.KEYS["witness-pi"].public))
        publics = [note.parse_vkey(parts[1] if parts[0] == "log" else parts[2]).public
                   for line in text.split("\n") if (parts := line.split()) and parts[0] in ("log", "witness")]
        self.assertEqual(len(publics), len(set(publics)))
        self.assertIn(fixture.KEYS["witness-pi"].public, publics)
        self.assertEqual(final.policy, text)
        self.assertEqual(final.versions["policy"], 33)
        for i, key in enumerate(("staleness", "checkpoint_interval", "mmd"), 34):
            self.assertEqual(cbor.decode(raw[i])["body"], {key: 0})
            state = replay.replay(anchor, raw[:i+1])
            self.assertEqual(state.params[key], 0)
            self.assertEqual(state.versions["params"], i)
            self.assertEqual(state.policy, text)
            self.assertEqual(cbor.decode(raw[i])["prev"], 0 if i == 34 else i-1)
        self.assertTrue(all(replay.replay(anchor, raw[:37]).params[key] == 0 for key in ("staleness", "checkpoint_interval", "mmd")))
