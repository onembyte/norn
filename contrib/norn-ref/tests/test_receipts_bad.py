"""SPEC §7's receipt rules, read from the files the suite ships (cold gate run 11, D4).

Every file is read exactly as `receipts-bad/cases.json` says: under
`trust.cbor`'s log key and origin, with no entry in hand and no clock. The
shape of each case is checked before its verdict, so a refusal is attributable
to the one rule the case is named after.
"""
import base64
import json
import pathlib
import unittest

from nornref import note, trust

ROOT = pathlib.Path(__file__).resolve().parents[3] / "testdata" / "vectors"

#: What each refusal must be about. A case refused for another reason is
#: refused by a rule it was not built to isolate.
REFUSALS = {
    "two-log-signatures": "does not verify",
    "extension-line": "this one has 5",
    "wrong-version": "first line is",
    "origin-with-a-suffix": "the receipt is for",
    "origin-in-upper-case": "the receipt is for",
    "origin-truncated": "the receipt is for",
    "leaf-hash-too-long": "the leaf hash is 33 bytes",
    "deadline-leading-zero": "is not canonical decimal",
    "deadline-plus-sign": "is not canonical decimal",
    "deadline-above-uint64": "does not fit in 64 bits",
    "leaf-hash-too-short": "the leaf hash is 31 bytes",
    "leaf-hash-unpadded": "is not base64",
    "leaf-hash-non-canonical-pad-bits": "is not the encoding of the leaf hash",
    "leaf-hash-carriage-return": "is not base64",
}


def _anchor() -> dict:
    return trust.parse((ROOT / "trust.cbor").read_bytes())


def _lines(text: str) -> list[str]:
    return text[:-1].split("\n")


class ShippedReceipts(unittest.TestCase):
    def setUp(self):
        self.anchor = _anchor()
        self.honest = (ROOT / "receipt.note").read_bytes().decode("utf-8")
        self.meta = json.loads((ROOT / "receipt.json").read_bytes().decode("utf-8"))
        manifest = json.loads((ROOT / "receipts-bad" / "cases.json").read_bytes().decode("utf-8"))
        self.names = [c["name"] for c in manifest["cases"]]

    def test_the_honest_receipt_is_accepted(self):
        held = note.check_receipt(self.honest, self.anchor["log_key"], self.anchor["origin"])
        self.assertEqual(held.origin, self.meta["origin"])
        self.assertEqual(held.leaf_hash.hex(), self.meta["leaf_hash"])
        self.assertEqual(held.deadline, self.meta["deadline"])

    def test_the_manifest_names_every_file(self):
        on_disk = sorted(p.stem for p in (ROOT / "receipts-bad").glob("*.note"))
        self.assertEqual(sorted(self.names), on_disk)
        self.assertEqual(sorted(self.names), sorted(REFUSALS))

    def test_every_negative_is_refused_for_its_own_rule(self):
        log_key, origin = self.anchor["log_key"], self.anchor["origin"]
        verifier = note.parse_vkey(log_key)
        honest_text, honest_sigs = note.split(self.honest)
        honest = _lines(honest_text)
        for name in self.names:
            with self.subTest(case=name):
                signed = (ROOT / "receipts-bad" / f"{name}.note").read_bytes().decode("utf-8")
                text, sigs = note.split(signed)
                lines = _lines(text)
                # Shape first.
                if name == "two-log-signatures":
                    self.assertEqual(text, honest_text)
                    self.assertEqual(len(sigs), 2)
                    self.assertEqual(sigs[0], honest_sigs[0])
                    for sig_name, raw in sigs:
                        self.assertEqual((sig_name, raw[:4]), (verifier.name, verifier.id))
                    from nornref import keys
                    self.assertFalse(keys.verify(verifier.public, text.encode(), sigs[1][1][4:]))
                else:
                    self.assertEqual(note.verify(signed, [log_key]), text,
                                     "the signature must verify, or it refuses the case first")
                    self.assertEqual(len(sigs), 1)
                    changed = sum(1 for a, b in zip(lines, honest) if a != b)
                    added = len(lines) - len(honest)
                    self.assertGreaterEqual(added, 0)
                    self.assertEqual(changed + added, 1, "a negative differs in exactly one line")
                if name == "leaf-hash-too-long":
                    raw = base64.b64decode(lines[2], validate=True)
                    self.assertEqual((len(raw), raw[:32].hex()), (33, self.meta["leaf_hash"]))
                if name == "deadline-leading-zero":
                    self.assertEqual(int(lines[3]), self.meta["deadline"])
                    self.assertNotEqual(lines[3], str(int(lines[3])))
                if name == "deadline-plus-sign":
                    self.assertEqual(lines[3], "+" + str(self.meta["deadline"]))
                if name == "deadline-above-uint64":
                    self.assertEqual(lines[3], str(2**64))
                if name == "leaf-hash-too-short":
                    raw = base64.b64decode(lines[2], validate=True)
                    self.assertEqual((len(raw), raw.hex()), (31, self.meta["leaf_hash"][:62]))
                if name == "leaf-hash-unpadded":
                    self.assertEqual(lines[2], honest[2].rstrip("="))
                if name == "leaf-hash-non-canonical-pad-bits":
                    self.assertEqual(len(lines[2]), len(honest[2]))
                    self.assertEqual(base64.b64decode(lines[2]).hex(), self.meta["leaf_hash"])
                if name == "leaf-hash-carriage-return":
                    self.assertEqual(lines[2].replace("\r", ""), honest[2])
                if name.startswith("origin-"):
                    self.assertNotEqual(lines[1], origin)
                # Then the verdict, and its reason.
                with self.assertRaises(note.NoteError) as caught:
                    note.check_receipt(signed, log_key, origin)
                self.assertIn(REFUSALS[name], str(caught.exception))


class PerLineVerification(unittest.TestCase):
    """`verify` is per line: a valid line does not excuse a forged one."""

    def test_a_forged_line_beside_a_valid_one_is_refused(self):
        signed = (ROOT / "receipts-bad" / "two-log-signatures.note").read_bytes().decode("utf-8")
        with self.assertRaises(note.NoteError):
            note.verify(signed, [_anchor()["log_key"]])


if __name__ == "__main__":
    unittest.main()
