"""D-080 (1) and (4), exercised through reference-generated inputs."""
import json
from pathlib import Path
import unittest

from nornref import cbor, entry, fixture, policy, replay, trust

ROOT = Path(__file__).resolve().parents[3] / "testdata/vectors"
TRAILING = "| trailing whitespace | spaces and tabs after the last field are not part of it and add no field (D-080) |"
TRUST_CAP = "Its length is bounded only by `MAX_TRUST_BYTES`"


class D080Vectors(unittest.TestCase):
    def rule(self, rule, says):
        self.assertEqual(rule, {"section": "9.1", "says": says})
        section = (ROOT.parents[1] / "SPEC.md").read_text().split("### 9.1 ", 1)[1].split("\n##", 1)[0]
        self.assertTrue(any(says in line for line in section.splitlines()))

    def trailing(self, name, suffix):
        path = ROOT / "policies" / f"{name}.txt"
        self.assertTrue(path.is_file(), f"missing policies/{name}.txt")
        text = path.read_bytes().decode()
        base = fixture.policy_text()
        self.assertEqual(text, "".join(line + suffix + "\n" for line in base.splitlines()))
        policy.parse(text)
        policy.parse(base)
        # The reference parser validates grammar without returning a model.
        # Compare every field, including URLs and quorum, after both parse.
        self.assertEqual([policy.SEPARATORS.split(line.strip(" \t")) for line in text.splitlines()],
                         [policy.SEPARATORS.split(line) for line in base.splitlines()])
        doc = json.loads((ROOT / "policies/cases.json").read_text())
        case = next(c for c in doc["cases"] if c["name"] == name)
        self.assertTrue(case["accept"])
        self.assertTrue(case["says"])
        self.rule(doc["rules"][name], TRAILING)

    def test_trailing_spaces_leave_every_policy_field_unchanged(self):
        self.trailing("trailing-space", "  ")

    def test_a_trailing_tab_leaves_every_policy_field_unchanged(self):
        self.trailing("trailing-tab", "\t")

    def test_a_root_signed_policy_with_trailing_spaces_applies(self):
        name = "26-policy-trailing-space"
        folder = ROOT / "log-rules"
        self.assertTrue((folder / f"{name}.cbor").is_file(), f"missing log-rules/{name}.cbor")
        manifest = json.loads((folder / "manifest.json").read_text())
        self.assertEqual(len(manifest["entries"]), 45)
        self.assertEqual(manifest["entries"][25]["name"], "25-enroll-without-expires")
        self.assertEqual(manifest["entries"][26], {"index": 26, "name": name, "reason": ""})
        self.rule(manifest["rules"][name], TRAILING)
        a = manifest["anchor"]
        anchor = replay.Anchor(bytes.fromhex(a["net"]), bytes.fromhex(a["genesis_hash"]), a["log_key"], a["policy"])
        raw = [(folder / (c["name"] + ".cbor")).read_bytes() for c in manifest["entries"]]
        env = cbor.decode(raw[26])
        before = replay.replay(anchor, raw[:26])
        self.assertEqual(env["t"], "policy")
        self.assertEqual(env["prev"], before.versions["policy"])
        self.assertEqual(len(env["sigs"]), before.root_thr)
        for sig in env["sigs"]:
            self.assertEqual(sig["role"], "root")
            self.assertTrue(entry.verify_sig(env, sig, before.roots[sig["kid"]]))
        text = env["body"]["text"]
        self.assertEqual(text, "".join(line + " \n" for line in fixture.policy_text().splitlines()))
        # Entry 33 intentionally supersedes this policy. Its own prefix
        # must still preserve every trailing-space and version obligation.
        at_policy = replay.replay(anchor, raw[:27])
        self.assertFalse(any(r["index"] == 26 for r in at_policy.rejected))
        self.assertEqual(at_policy.versions["policy"], 26)
        self.assertEqual(at_policy.policy, text)
        policy.parse(at_policy.policy)
        self.assertEqual(at_policy.policy.replace(" \n", "\n"), fixture.policy_text())
        final = replay.replay(anchor, raw)
        self.assertEqual(final.versions["policy"], 33)
        self.assertEqual(final.policy, cbor.decode(raw[33])["body"]["text"])
        self.assertEqual((final.to_json() + "\n").encode(), (folder / "state.json").read_bytes())

    def test_a_trust_policy_above_the_entry_text_cap_is_valid(self):
        name = "policy-over-4096"
        path = ROOT / "trust-good" / f"{name}.cbor"
        self.assertTrue(path.is_file(), f"missing trust-good/{name}.cbor")
        raw = path.read_bytes()
        self.assertLess(len(raw), trust.MAX_TRUST_BYTES)
        doc = trust.parse(raw)
        self.assertEqual(len(doc["policy"].encode()), 4097)
        honest = trust.parse((ROOT / "trust.cbor").read_bytes())
        self.assertTrue(doc["policy"].startswith(honest["policy"] + "#"))
        self.assertEqual(len(doc["policy"][len(honest["policy"]):].splitlines()), 1)
        policy.parse(doc["policy"])
        doc["policy"] = honest["policy"]
        self.assertEqual(doc, honest)
        cases = json.loads((ROOT / "trust-good/cases.json").read_text())
        self.assertIn(name, cases["cases"])
        self.assertIn("comment", cases["says"][name])
        self.rule(cases["rules"][name], TRUST_CAP)
