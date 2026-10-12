"""Distributed replay anchors must be fields a trust file could supply (§5)."""

import json
from pathlib import Path
import unittest

from nornref import note, policy, trust

ROOT = Path(__file__).resolve().parents[3] / "testdata" / "vectors"
FIELDS = {"net", "genesis_hash", "log_key", "policy"}


class ShippedAnchors(unittest.TestCase):
    def test_every_shipped_anchor_is_one_a_trust_file_could_give(self):
        anchors = {}
        for path in sorted(ROOT.rglob("manifest.json")):
            doc = json.loads(path.read_text())
            if "anchor" in doc:
                anchors[path.parent.relative_to(ROOT).as_posix()] = doc["anchor"]
        for name in ("log", "log-cas", "log-edges", "log-admission", "log-empty"):
            self.assertIn(name, anchors)
        for parent in ("genesis", "genesis-good"):
            dirs = [d for d in (ROOT / parent).iterdir() if d.is_dir()]
            self.assertTrue(dirs, f"{parent} has no case directories")
            for directory in dirs:
                self.assertIn(directory.relative_to(ROOT).as_posix(), anchors)
        refused = 0
        for name, anchor in anchors.items():
            with self.subTest(anchor=name):
                errors = self.anchor_errors(anchor)
                refused += bool(errors)
                self.assertFalse(errors, "; ".join(errors))
        print(f"refused {refused} of {len(anchors)} shipped anchors", flush=True)

    def anchor_errors(self, anchor):
        self.assertIsInstance(anchor, dict)
        if set(anchor) != FIELDS:
            return [f"anchor fields: missing {sorted(FIELDS - set(anchor))}, "
                    f"extra {sorted(set(anchor) - FIELDS)}"]
        for field, size in (("net", 16), ("genesis_hash", 32)):
            self.assertIsInstance(anchor[field], str)
            self.assertEqual(len(anchor[field]), 2 * size, f"{field} must be {size} bytes of hex")
            try:
                raw = bytes.fromhex(anchor[field])
            except ValueError as exc:
                self.fail(f"{field}: {exc}")
            self.assertEqual(len(raw), size)
        for field in ("log_key", "policy"):
            self.assertIsInstance(anchor[field], str)
        errors = []
        try:
            key = note.parse_vkey(anchor["log_key"])
        except note.NoteError as exc:
            errors.append(f"log_key: {exc}")
        try:
            policy.parse(anchor["policy"])
        except policy.PolicyError as exc:
            errors.append(f"policy: {exc}")
        if errors:
            return errors
        witnesses = []
        for line in anchor["policy"].splitlines():
            fields = line.strip(" \t").split()
            if fields and fields[0] == "witness":
                witnesses.append({"name": fields[1], "key": fields[2]})
        doc = trust.build(bytes.fromhex(anchor["net"]), "shipped anchor",
                          bytes.fromhex(anchor["genesis_hash"]), anchor["log_key"],
                          ["https://example.invalid/log"], witnesses, anchor["policy"])
        try:
            trust.validate(doc)
        except trust.TrustError as exc:
            errors.append(str(exc))
        # Preserve the public key so earlier name/algorithm checks cannot
        # mask disjointness. The trust validator owns both sets of checks.
        doc["log_key"] = note.vkey(doc["origin"], key.public)
        if doc["log_key"] != anchor["log_key"]:
            try:
                trust.validate(doc)
            except trust.TrustError as exc:
                errors.append(f"public-key invariant: {exc}")
        return errors
