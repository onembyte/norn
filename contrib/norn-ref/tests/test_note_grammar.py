"""D-077's framing rules apply before a stranger's line can be ignored."""
import base64
import unittest

from nornref import keys, note


class NoteGrammar(unittest.TestCase):
    def test_malformed_stranger_names_fail_framing_and_repair(self):
        signed = note.sign("hello\n", "log", keys.Ed25519.from_name("logkey"))
        blob = base64.b64encode(bytes(68)).decode()
        for name in ("", "a\tb", "a\u00a0b", "a+b", "a\x00b"):
            with self.subTest(name=repr(name)):
                with self.assertRaises(note.NoteError):
                    note.split(signed + note.SIG_PREFIX + name + " " + blob + "\n")
                self.assertEqual(note.split(signed + note.SIG_PREFIX + "stranger " + blob + "\n")[0], "hello\n")

    def test_control_bytes_fail_in_text_names_and_payloads(self):
        blob = base64.b64encode(bytes(68)).decode()
        for value in range(0x20):
            if value == 10:
                continue
            char = chr(value)
            for signed in ("hello" + char + "\n\n" + note.SIG_PREFIX + "stranger " + blob + "\n",
                           "hello\n\n" + note.SIG_PREFIX + "stranger" + char + " " + blob + "\n",
                           "hello\n\n" + note.SIG_PREFIX + "stranger " + blob[:4] + char + blob[4:] + "\n"):
                with self.subTest(value=value, signed=repr(signed)), self.assertRaises(note.NoteError):
                    note.split(signed)
            with self.subTest(value=value), self.assertRaises(note.NoteError):
                note._check_text("hello" + char + "\n")

    def test_the_name_property_does_not_depend_on_python_isspace(self):
        # U+001C is outside the written name property, but the whole-note
        # control-byte rule refuses it. Python's isspace conflates the rules.
        self.assertTrue("\x1c".isspace())
        self.assertTrue(note._valid_signature_name("a\x1cb"))
        self.assertTrue(note._valid_signature_name("a\u180eb"))
        for name in ("", "a+b", "a\u00a0b"):
            self.assertFalse(note._valid_signature_name(name))

    def test_signature_names_use_the_written_white_space_property(self):
        spaces = (0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x20, 0x85, 0xa0, 0x1680,
                  0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005, 0x2006,
                  0x2007, 0x2008, 0x2009, 0x200a, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000)
        blob = base64.b64encode(bytes(68)).decode()
        for value in spaces:
            with self.subTest(value=value), self.assertRaises(note.NoteError):
                note.split("hello\n\n" + note.SIG_PREFIX + "a" + chr(value) + "b " + blob + "\n")
        for char in ("ü", "\u180e", "\u200b", "\x7f"):
            self.assertEqual(note.split("hello\n\n" + note.SIG_PREFIX + "a" + char + "b " + blob + "\n")[0], "hello\n")


class NoteGrammarVectors(unittest.TestCase):
    def test_the_stranger_vectors_fail_framing_and_accept_a_name_repair(self):
        import json
        from pathlib import Path
        from nornref import fixture
        root = Path(__file__).resolve().parents[3] / "testdata" / "vectors"
        base = (root / "served/checkpoint").read_bytes().decode()
        manifest = json.loads((root / "checkpoints-bad/cases.json").read_text())
        names = ("39-signature-name-empty", "40-signature-name-tab", "41-signature-name-nbsp",
                 "42-signature-name-plus", "43-signature-name-nul")
        # The reference has no checkpoint verifier or cosignature parser.
        # Retain the actual body, log signature and stranger's 68-byte line;
        # leave the witness lines to Go rather than its receipt-only parser.
        body, block = base.split("\n\n", 1)
        log_line = block.split("\n")[0]
        projected = body + "\n\n" + log_line + "\n"
        trust = fixture.trust_file()
        for name in names:
            with self.subTest(name=name):
                head = (root / "checkpoints-bad" / (name + ".checkpoint")).read_bytes().decode()
                self.assertTrue(head.startswith(base))
                extra = head[len(base):]
                self.assertEqual(manifest["codes"][name], "note")
                with self.assertRaises(note.NoteError):
                    note.split(projected + extra)
                _, _, blob = extra[len(note.SIG_PREFIX):].partition(" ")
                repaired = projected + note.SIG_PREFIX + "stranger " + blob
                self.assertEqual(note.verify(repaired, [trust["log_key"]]), body + "\n")
