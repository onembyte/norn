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

    def test_every_matched_receipt_line_verifies_at_its_exact_length(self):
        import base64
        manifest = json.loads((ROOT / "receipt-bad/cases.json").read_text())
        key = [fixture.trust_file()["log_key"]]
        honest = (ROOT / "receipt.note").read_text()
        honest_text, honest_lines = note.split(honest)
        for name in ("two-log-lines.note", "payload-69.note"):
            with self.subTest(name=name):
                self.assertIn(name, {c["name"] for c in manifest["cases"]})
                self.assertEqual(manifest["codes"][name], "log-signature")
                raw = (ROOT / "receipt-bad" / name).read_text()
                text, lines = note.split(raw)
                self.assertEqual(text, honest_text)
                self.assertTrue(all(n == honest_lines[0][0] and r[:4] == honest_lines[0][1][:4]
                                    for n, r in lines))
                with self.assertRaises(note.NoteError):
                    note.verify(raw, key)
                if name == "two-log-lines.note":
                    self.assertEqual(len(lines), 2)
                    self.assertEqual(lines[0], honest_lines[0])
                    self.assertEqual(len(lines[1][1]), 68)
                    self.assertEqual(lines[1][1][:-1], lines[0][1][:-1])
                    self.assertNotEqual(lines[1][1][-1], lines[0][1][-1])
                    repaired_lines = [lines[0], (lines[1][0], lines[0][1])]
                else:
                    self.assertEqual(len(lines), 1)
                    self.assertEqual(len(lines[0][1]), 69)
                    self.assertEqual(lines[0][1][:-1], honest_lines[0][1])
                    repaired_lines = [(lines[0][0], lines[0][1][:-1])]
                repaired = text + "\n" + "".join(note.SIG_PREFIX + n + " " + base64.b64encode(r).decode() + "\n"
                                                  for n, r in repaired_lines)
                self.assertEqual(note.verify(repaired, key), honest_text)
