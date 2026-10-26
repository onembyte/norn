"""Run 15's replay order is read from the distributed fixture, then repaired."""
import copy
import json
from pathlib import Path
import unittest

from nornref import cbor, enrollreq, entry, fixture, replay, policy, note

ROOT = Path(__file__).resolve().parents[3] / "testdata" / "vectors" / "log-order"
# Each pair is the first and second check's answer, independently of the manifest.
CASES = {
    "02-rotate-incoming-only": ("no-device-sig", ""),
    "04-rotate-threshold-before-prev": ("threshold", "stale-state"),
    "05-enroll-threshold-before-prev": ("threshold", "stale-state"),
    "06-enroll-prev-before-dup-id": ("stale-state", "dup-id"),
    "07-revoke-threshold-before-prev": ("threshold", "stale-state"),
    "08-signer-add-after-before-threshold": ("after", "threshold"),
    "09-params-body-before-prev": ("decode", "stale-state"),
    "10-policy-parse-before-prev": ("decode", "stale-state"),
    "11-policy-prev-before-dup-key": ("stale-state", "dup-key"),
    "12-signer-remove-prev-before-unknown-key": ("stale-state", "unknown-key"),
    "13-signer-thr-prev-before-bad-thr": ("stale-state", "bad-thr"),
    "14-log-key-prev-before-dup-key": ("stale-state", "dup-key"),
    "15-policy-log-identity": ("decode", ""),
    "16-signer-add-body-before-prev": ("decode", "stale-state"),
    "17-root-add-body-before-prev": ("decode", "stale-state"),
    "18-signer-remove-body-before-prev": ("decode", "stale-state"),
    "19-root-remove-body-before-prev": ("decode", "stale-state"),
    "20-signer-thr-body-before-prev": ("decode", "stale-state"),
    "21-root-thr-body-before-prev": ("decode", "stale-state"),
    "22-log-key-fields-before-prev": ("decode", "stale-state"),
    "23-root-remove-prev-before-unknown-key": ("stale-state", "unknown-key"),
    "24-enroll-body-before-request-signature": ("decode", "no-device-sig"),
    "25-enroll-body-before-threshold": ("decode", "threshold"),
    "26-enroll-body-before-prev": ("decode", "stale-state"),
    "27-enroll-body-before-dup-id": ("decode", "dup-id"),
    "28-enroll-body-before-dup-wg": ("decode", "dup-wg"),
    "29-log-key-body-before-prev": ("decode", "stale-state"),
    "30-log-key-body-before-witness-key": ("decode", "dup-key"),
    "31-log-key-body-before-active-log-key": ("decode", "dup-key"),
    "32-policy-body-before-prev": ("decode", "stale-state"),
    "33-policy-body-before-dup-key": ("decode", "dup-key"),
    "34-policy-cap-before-prev": ("decode", "stale-state"),
    "35-policy-cap-before-dup-key": ("decode", "dup-key"),
    "36-revoke-body-before-not-active": ("decode", "not-active"),
    "37-rotate-body-before-not-active": ("decode", "not-active"),
    "38-envelope-invalid-note": ("decode", ""),
    "39-byte-copy-before-envelope": ("dup-entry", ""),
}


class ReplayOrderVectors(unittest.TestCase):
    def test_every_order_case_matches_and_exposes_only_its_named_faults(self):
        manifest = json.loads((ROOT / "manifest.json").read_text())
        a = manifest["anchor"]
        anchor = replay.Anchor(bytes.fromhex(a["net"]), bytes.fromhex(a["genesis_hash"]),
                               a["log_key"], a["policy"])
        raw = [(ROOT / (e["name"] + ".cbor")).read_bytes() for e in manifest["entries"]]
        self.assertEqual(len(raw), 42)
        self.assertEqual(manifest["codes"], {name: codes[0] for name, codes in CASES.items()})
        self.assertEqual(set(manifest["rules"]), set(CASES))
        self.assertEqual({e["name"]: e["reason"] for e in manifest["entries"] if e["reason"]},
                         {name: codes[0] for name, codes in CASES.items()})
        final = replay.replay(anchor, raw)
        spec = (ROOT.parents[2] / "SPEC.md").read_text()
        for index, it in enumerate(manifest["entries"]):
            self.assertEqual(it["index"], index)
            if it["name"] in CASES:
                self.assertEqual((ROOT / (it["name"] + ".reason")).read_text(), it["reason"] + "\n")
                rule = manifest["rules"][it["name"]]
                heading = ("### " if "." in rule["section"] else "## ") + rule["section"] + " "
                section = spec.split(heading, 1)[1].split("\n##", 1)[0]
                self.assertTrue(rule["says"])
                self.assertTrue(any(rule["says"] in line for line in section.split("\n")))
            i, name = it["index"], it["name"]
            outcome = next((r["reason"] for r in final.rejected if r["index"] == i), "")
            if name not in CASES:
                self.assertEqual(outcome, it["reason"], name)
                continue
            with self.subTest(case=name):
                self.assertEqual(outcome, it["reason"], name)
                if name in NEW_CASES:
                    check_run19_case(self, anchor, raw, i, name)
                    continue
                first, second = CASES[name]
                before = replay.replay(anchor, raw[:i])
                original = cbor.decode(raw[i])

                def previous(env):
                    value = fixture.previous_for(before, env["t"], env["body"])
                    env.pop("prev", None)
                    if value is not None:
                        env["prev"] = value

                def repair(env, fault):
                    if fault == "stale-state":
                        previous(env)
                    elif fault == "threshold":
                        signers = [("root1", "root"), ("root2", "root")] if env["t"] == "signer_add" else [("signer1", "signer")]
                        for key, role in signers:
                            entry.sign(env, fixture.KEYS[key], role)
                    elif fault == "after":
                        env["after"] = i
                    elif fault == "no-device-sig":
                        entry.sign(env, fixture.KEYS["nas"], "device")
                    elif fault == "decode":
                        if env["t"] in ("signer_add", "root_add", "log_key"):
                            key = {"signer_add": "signer3", "root_add": "spare", "log_key": "logkey2"}[env["t"]]
                            env["body"]["pk"] = fixture.KEYS[key].public
                        elif env["t"] in ("signer_remove", "root_remove"):
                            key = "root3" if env["t"] == "root_remove" else "signer1"
                            env["body"]["kid"] = fixture.KEYS[key].id
                        elif env["t"] in ("signer_thr", "root_thr"):
                            env["body"]["thr"] = 1
                        elif env["t"] == "params":
                            env["body"] = {"mmd": 46}
                        elif name.endswith("log-identity"):
                            env["body"]["text"] = "log " + fixture.log_vkey() + "\nquorum none\n"
                        else:
                            env["body"]["text"] = "quorum none\n"
                    elif fault == "dup-id":
                        req = cbor.decode(env["body"]["request"])
                        req["device_id"] = "spare"
                        req["sig"] = fixture.KEYS["nas"].sign(enrollreq.preimage(req))
                        env["body"]["request"] = cbor.encode(req)
                        # The id changes its predecessor domain; a correct prev
                        # must move with it, while a stale one remains stale.
                        if env.get("prev") == before.devices["nas"]["version"]:
                            previous(env)
                    elif fault == "dup-key":
                        if env["t"] == "policy":
                            env["body"]["text"] = "quorum none\n"
                        else:
                            env["body"]["pk"] = fixture.KEYS["logkey2"].public
                    elif fault == "unknown-key":
                        key = "root3" if env["t"] == "root_remove" else "signer1"
                        env["body"]["kid"] = fixture.KEYS[key].id
                    elif fault == "bad-thr":
                        env["body"]["thr"] = 1
                    else:
                        self.fail("missing repair " + fault)

                def check(env, want):
                    signatures = env["sigs"]
                    env["sigs"] = []
                    for sig in signatures:
                        key = next(k for k in fixture.KEYS.values() if k.id == sig["kid"])
                        entry.sign(env, key, sig["role"])
                    result = replay.replay(anchor, raw[:i] + [entry.encode(env)])
                    got = next((r["reason"] for r in result.rejected if r["index"] == i), "")
                    self.assertEqual(got, want)
                    if want:
                        result.size, result.rejected = before.size, before.rejected
                        self.assertEqual(result.to_json(), before.to_json(), "rejection changed state")

                check(copy.deepcopy(original), first)
                env = copy.deepcopy(original)
                repair(env, first)
                check(env, second)
                if second:
                    repair(env, second)
                    check(env, "")
                    env = copy.deepcopy(original)
                    repair(env, second)
                    check(env, first)
        self.assertEqual((final.to_json() + "\n").encode(), (ROOT / "state.json").read_bytes())


NEW_CASES = {name for name in CASES if int(name[:2]) >= 24}


def check_run19_case(test, anchor, raw, i, name, repairs_only=False):
    """Keep each named fault and its repairs at the same replay position."""
    before = replay.replay(anchor, raw[:i])
    original = cbor.decode(raw[i])
    first, second = CASES[name]
    test.assertEqual(original["after"], i if first != "dup-entry" else i-1)

    def check(env, want):
        env["sigs"] = []
        if env["t"] in ("policy", "log_key"):
            fixture._signed(env, [("root1", "root"), ("root2", "root")])
        elif not name.startswith("25-") or want == "":
            fixture._signed(env, [("signer1", "signer"), ("nas", "device")])
        result = replay.replay(anchor, raw[:i] + [entry.encode(env)])
        got = next((r["reason"] for r in result.rejected if r["index"] == i), "")
        test.assertEqual(got, want, name)
        if want:
            result.size, result.rejected = before.size, before.rejected
            test.assertEqual(result.to_json(), before.to_json(), "refusal changed state")

    if name.startswith(("38-", "39-")):
        predecessor = i if name.startswith("38-") else i-1
        test.assertEqual(raw[predecessor], raw[predecessor+1])
        test.assertEqual(cbor.decode(raw[predecessor])["v"], 2)
        for position, want in ((predecessor, "decode"), (predecessor+1, "dup-entry")):
            result = replay.replay(anchor, raw[:position+1])
            test.assertEqual(result.rejected[-1], {"index": position, "reason": want})
        repaired = copy.deepcopy(original)
        repaired["v"] = 1
        check(repaired, "")
        return
    if original["t"] in ("revoke", "rotate"):
        test.assertEqual(before.devices[original["body"]["device_id"]]["status"], "revoked")
    if "cap-before" in name:
        test.assertEqual(len(original["body"]["text"].encode()), 4097)
        policy.parse(original["body"]["text"])
    else:
        test.assertIn("x", original["body"])

    def repair_first(env):
        if "cap-before" in name:
            text = env["body"]["text"]
            test.assertTrue(text.endswith("x\n"))
            env["body"]["text"] = text[:-2] + "\n"
        else:
            del env["body"]["x"]

    def repair_second(env):
        if second == "stale-state":
            value = fixture.previous_for(before, env["t"], env["body"])
            env.pop("prev", None)
            if value is not None:
                env["prev"] = value
        elif second == "threshold":
            entry.sign(env, fixture.KEYS["signer1"], "signer")
        elif second in ("no-device-sig", "dup-id", "dup-wg"):
            req = cbor.decode(env["body"]["request"])
            if second == "dup-id":
                req["device_id"] = "order-repair"
                env.pop("prev", None)
            elif second == "dup-wg":
                req["wg_pk"] = fixture.WG["spare"]
            key = next(k for k in fixture.KEYS.values() if k.public == req["device_pk"])
            enrollreq.sign(req, key)
            env["body"]["request"] = cbor.encode(req)
        elif second == "dup-key":
            if env["t"] == "log_key":
                env["body"]["pk"] = fixture.KEYS["logkey2"].public
            else:
                old = note.vkey("order-witness", fixture.KEYS["logkey"].public, note.ALG_COSIGNATURE)
                new = note.vkey("order-witness", fixture.KEYS["spare"].public, note.ALG_COSIGNATURE)
                test.assertIn(old, env["body"]["text"])
                env["body"]["text"] = env["body"]["text"].replace(old, new)
        elif second == "not-active":
            env["body"]["device_id"] = "nas"
            env["prev"] = before.devices["nas"]["version"]
        else:
            test.fail("missing second repair " + second)

    if not repairs_only:
        result = replay.replay(anchor, raw[:i+1])
        test.assertEqual(result.rejected[-1], {"index": i, "reason": first})
    env = copy.deepcopy(original)
    repair_first(env)
    check(env, second)
    repair_second(env)
    check(env, "")
    env = copy.deepcopy(original)
    repair_second(env)
    # Threshold repair must retain the added signer while re-signing content.
    if second == "threshold":
        env["sigs"] = []
        fixture._signed(env, [("signer1", "signer")])
        result = replay.replay(anchor, raw[:i] + [entry.encode(env)])
        test.assertEqual(result.rejected[-1]["reason"], first)
    else:
        check(env, first)
