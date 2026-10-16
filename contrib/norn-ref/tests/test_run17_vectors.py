"""Run 17's reference-owned framing rule, read from the distributed receipt."""
import json
from pathlib import Path
import unittest

from nornref import fixture, note

ROOT = Path(__file__).resolve().parents[3] / "testdata/vectors"


class RunSeventeen(unittest.TestCase):
    def test_a_receipt_without_signature_lines_is_malformed(self):
        name = "no-signature-line.note"
        raw = (ROOT / "receipt-bad" / name).read_text()
        honest = (ROOT / "receipt.note").read_text()
        self.assertEqual(raw, "".join(line for line in honest.splitlines(keepends=True)
                                      if not line.startswith(note.SIG_PREFIX)))
        manifest = json.loads((ROOT / "receipt-bad/cases.json").read_text())
        self.assertEqual(manifest["codes"][name], "note")
        rule = manifest["rules"][name]
        self.assertEqual(rule["section"], "7")
        self.assertTrue(rule["says"])
        spec = (ROOT.parents[1] / "SPEC.md").read_text().split("## 7. ", 1)[1].split("\n## ", 1)[0]
        self.assertTrue(any(rule["says"] in line for line in spec.splitlines()))
        key = [fixture.trust_file()["log_key"]]
        note.verify(honest, key)
        # The reference exposes the framing layer rather than receipt codes.
        # It must fail split itself, before trusted signature lookup.
        with self.assertRaises(note.NoteError):
            note.split(raw)
