"""Run 15's replay order is read from the distributed fixture, then repaired."""
import copy
import json
from pathlib import Path
import unittest

from nornref import cbor, enrollreq, entry, fixture, replay

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
}


class ReplayOrderVectors(unittest.TestCase):
    def test_every_order_case_matches_and_exposes_only_its_named_faults(self):
        manifest = json.loads((ROOT / "manifest.json").read_text())
        a = manifest["anchor"]
        anchor = replay.Anchor(bytes.fromhex(a["net"]), bytes.fromhex(a["genesis_hash"]),
                               a["log_key"], a["policy"])
        raw = [(ROOT / (e["name"] + ".cbor")).read_bytes() for e in manifest["entries"]]
        self.assertEqual(len(raw), 24)
        self.assertEqual({e["name"]: e["reason"] for e in manifest["entries"] if e["reason"]},
                         {name: codes[0] for name, codes in CASES.items()})
        final = replay.replay(anchor, raw)
        for it in manifest["entries"]:
            i, name = it["index"], it["name"]
            outcome = next((r["reason"] for r in final.rejected if r["index"] == i), "")
            if name not in CASES:
                self.assertEqual(outcome, it["reason"], name)
                continue
            with self.subTest(case=name):
                self.assertEqual(outcome, it["reason"], name)
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
