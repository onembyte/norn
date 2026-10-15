"""Run 16's plainly stated rules, read from the distributed replay fixture."""
import json
from pathlib import Path
import unittest

from nornref import cbor, entry, fixture, replay

ROOT = Path(__file__).resolve().parents[3] / "testdata" / "vectors" / "log-rules"
NAMES = ["00-genesis", "01-enroll-nas", "02-enroll-laptop",
         "03-revoke-nas-by-laptop", "04-revoke-nas-by-self",
         "05-signer-add-without-prev", "06-signer-add-prev-zero",
         "07-note-without-ts", "08-note-with-ts", "09-enroll-empty-label-value",
         "10-policy-preannounces-log-key", "11-log-key-preannounced",
         "12-copy-enroll-unsorted-sigs", "13-copy-enroll-sorted-sigs",
         "14-root-threshold-full", "15-root-remove-unknown-before-invariant",
         "16-root-remove-known-at-full-threshold", "17-root-threshold-repaired",
         "18-root-remove-known"]
CODES = ["", "", "", "threshold", "", "stale-state", "", "decode", "", "", "", "",
         "decode", "dup-entry", "", "unknown-key", "root-invariant", "", ""]


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
                if not CODES[i]:
                    continue
                self.assertEqual((ROOT / (name + ".reason")).read_text(), CODES[i] + "\n")
                before, after = replay.replay(anchor, raw[:i]), replay.replay(anchor, raw[:i+1])
                after.size, after.rejected = before.size, before.rejected
                self.assertEqual(after.to_json(), before.to_json(), "refusal changed state")
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
                else:
                    self.fail("refusal has no repair")
        self.assertEqual((final.to_json() + "\n").encode(), (ROOT / "state.json").read_bytes())
