"""D-074 (f): key names are ASCII by grammar, and key ids are lowercase hex."""
import unittest

from nornref import keys, note

PUBLIC = keys.Ed25519.from_name("keyname-grammar").public


class KeyNameGrammar(unittest.TestCase):
    # It was str.isspace, whose table counts U+001C-U+001F as space where
    # Go's unicode.IsSpace does not, so one trust file loaded in one
    # implementation and not the other. A grammar has no table to disagree.

    def test_ascii_names_from_0x21_to_0x7e_are_accepted(self):
        for name in ("pi", "norn-witness/pi", "norn/nzxxe3rnorsxg5domv2c2mbqge", "!~"):
            with self.subTest(name=name):
                self.assertEqual(note.parse_vkey(note.vkey(name, PUBLIC)).name, name)

    def test_every_other_name_is_refused(self):
        for name in ("a\x1cb", "a b", "a b", "café", "a\tb", "a\x7fb", "tab\u0085x"):
            with self.subTest(name=repr(name)):
                with self.assertRaisesRegex(note.NoteError, "key name"):
                    note.parse_vkey(note.vkey(name, PUBLIC))

    def test_an_uppercase_key_id_is_refused(self):
        name, key_id, data = note.vkey("pi", PUBLIC).split("+", 2)
        self.assertNotEqual(key_id.upper(), key_id, "the id has no letter to change")
        with self.assertRaises(note.NoteError):
            note.parse_vkey(f"{name}+{key_id.upper()}+{data}")


if __name__ == "__main__":
    unittest.main()
