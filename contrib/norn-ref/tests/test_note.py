"""RED first: signed notes (c2sp.org/signed-note) and Norn receipts (SPEC §7)."""
import base64
import hashlib
import unittest

from nornref import keys, note


class VerifierKey(unittest.TestCase):
    def setUp(self):
        self.key = keys.Ed25519.from_name("logkey")
        self.name = "norn/testnet"

    def test_key_id_binds_name_and_algorithm(self):
        want = hashlib.sha256(
            self.name.encode() + b"\n" + bytes([note.ALG_ED25519]) + self.key.public
        ).digest()[:4]
        self.assertEqual(note.key_id(self.name, self.key.public), want)

    def test_key_id_changes_with_the_name(self):
        self.assertNotEqual(note.key_id("a", self.key.public), note.key_id("b", self.key.public))

    def test_vkey_round_trips(self):
        vkey = note.vkey(self.name, self.key.public)
        parsed = note.parse_vkey(vkey)
        self.assertEqual(parsed.name, self.name)
        self.assertEqual(parsed.public, self.key.public)

    def test_vkey_round_trips_when_key_data_contains_plus(self):
        """Standard base64 emits "+", so parsing must split at most twice."""
        with_plus = next(
            k for k in (keys.Ed25519.from_name(f"plus-probe-{i}") for i in range(200))
            if "+" in base64.b64encode(bytes([note.ALG_ED25519]) + k.public).decode()
        )
        vkey = note.vkey(self.name, with_plus.public)
        self.assertIn("+", vkey.split("+", 2)[2])
        self.assertEqual(note.parse_vkey(vkey).public, with_plus.public)

    def test_vkey_layout(self):
        vkey = note.vkey(self.name, self.key.public)
        name, keyhash, keydata = vkey.split("+", 2)
        self.assertEqual(name, self.name)
        self.assertEqual(keyhash, note.key_id(self.name, self.key.public).hex())
        self.assertEqual(base64.b64decode(keydata),
                         bytes([note.ALG_ED25519]) + self.key.public)

    def test_rejects_malformed_vkey(self):
        for bad in ["", "a+b", "a+zz+AAAA", "name+00000000+notbase64!"]:
            with self.subTest(bad=bad), self.assertRaises(note.NoteError):
                note.parse_vkey(bad)

    def test_vkey_data_rejects_ignored_line_breaks(self):
        for alg in (note.ALG_ED25519, note.ALG_COSIGNATURE):
            key = note.vkey(self.name, self.key.public, alg)
            name, key_id, data = key.split("+", 2)
            self.assertEqual(len(data), 44)
            self.assertNotIn("=", data)
            original = base64.b64decode(data)
            self.assertEqual(len(original), 33)
            for line_break in ("\r", "\n"):
                with self.subTest(alg=alg, line_break=repr(line_break)):
                    mutated_data = data[:12] + line_break + data[12:]
                    self.assertEqual(base64.b64decode(mutated_data), original)
                    with self.assertRaises(note.NoteError):
                        note.parse_vkey(f"{name}+{key_id}+{mutated_data}")


class SignAndVerify(unittest.TestCase):
    TEXT = "norn/receipt/v1\nnorn/abc\ndGVzdA==\n1760000000\n"

    def setUp(self):
        self.key = keys.Ed25519.from_name("logkey")
        self.name = "norn/testnet"

    def test_text_must_end_with_newline(self):
        with self.assertRaises(note.NoteError):
            note.sign("no trailing newline", self.name, self.key)

    def test_signed_note_layout(self):
        signed = note.sign(self.TEXT, self.name, self.key)
        self.assertTrue(signed.startswith(self.TEXT))
        body, _, sigblock = signed.partition("\n\n")
        self.assertEqual(body + "\n", self.TEXT)
        self.assertTrue(sigblock.startswith(note.SIG_PREFIX))
        self.assertTrue(sigblock.endswith("\n"))

    def test_a_note_whose_first_line_is_blank_is_refused(self):
        # D-078 (4), run 15's L2: a note's text lines are non-empty (SPEC 7),
        # so a blank first line is malformed framing, as in Go.
        signed = note.sign(self.TEXT, self.name, self.key)
        note.split(signed)
        for bad in ("\n" + signed, "\n\n" + signed.partition("\n\n")[2]):
            with self.assertRaises(note.NoteError):
                note.split(bad)
        with self.assertRaises(note.NoteError):
            note.sign("\n" + self.TEXT, self.name, self.key)

    def test_signature_block_requires_exactly_one_final_newline(self):
        signed = note.sign(self.TEXT, self.name, self.key)
        with self.assertRaises(note.NoteError):
            note.split(signed[:-1])
        with self.assertRaises(note.NoteError):
            note.split(signed + "\n")

    def test_verify_accepts_its_own_signature(self):
        signed = note.sign(self.TEXT, self.name, self.key)
        text = note.verify(signed, [note.vkey(self.name, self.key.public)])
        self.assertEqual(text, self.TEXT)

    def test_every_line_selecting_a_listed_key_must_verify(self):
        signed = note.sign(self.TEXT, self.name, self.key)
        raw = note.key_id(self.name, self.key.public) + bytes(64)
        forged = note.SIG_PREFIX + self.name + " " + base64.b64encode(raw).decode() + "\n"
        with self.assertRaises(note.NoteError):
            note.verify(signed + forged, [note.vkey(self.name, self.key.public)])

    def test_a_strangers_payload_length_is_ignored_after_framing(self):
        signed = note.sign(self.TEXT, self.name, self.key)
        raw = note.key_id("stranger", self.key.public) + bytes(68)
        stranger = note.SIG_PREFIX + "stranger " + base64.b64encode(raw).decode() + "\n"
        self.assertEqual(len(raw), 72)
        self.assertEqual(note.verify(signed + stranger, [note.vkey(self.name, self.key.public)]),
                         self.TEXT)

    def test_a_matched_payload_length_is_checked_by_verify_not_split(self):
        signed = note.sign(self.TEXT, self.name, self.key)
        text, lines = note.split(signed)
        raw = lines[0][1] + b"x"
        long_line = note.SIG_PREFIX + self.name + " " + base64.b64encode(raw).decode() + "\n"
        malformed = text + "\n" + long_line
        self.assertEqual(note.split(malformed), (self.TEXT, [(self.name, raw)]))
        with self.assertRaises(note.NoteError):
            note.verify(malformed, [note.vkey(self.name, self.key.public)])

    def test_verify_rejects_tampered_text(self):
        signed = note.sign(self.TEXT, self.name, self.key).replace("1760000000", "1799999999")
        with self.assertRaises(note.NoteError):
            note.verify(signed, [note.vkey(self.name, self.key.public)])

    def test_verify_rejects_an_unknown_key(self):
        signed = note.sign(self.TEXT, self.name, self.key)
        other = keys.Ed25519.from_name("logkey2")
        with self.assertRaises(note.NoteError):
            note.verify(signed, [note.vkey(self.name, other.public)])

    def test_signature_is_over_the_text_only(self):
        signed = note.sign(self.TEXT, self.name, self.key)
        line = signed.split("\n\n", 1)[1].strip()
        raw = base64.b64decode(line[len(note.SIG_PREFIX):].split(" ", 1)[1])
        self.assertTrue(keys.verify(self.key.public, self.TEXT.encode(), raw[4:]))

    def test_split_rejects_nonzero_signature_payload_pad_bits(self):
        signed = note.sign(self.TEXT, self.name, self.key)
        body, separator, block = signed.partition("\n\n")
        self.assertTrue(separator)
        prefix, blob = block[:-1].rsplit(" ", 1)
        raw = base64.b64decode(blob, validate=True)
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        padding = len(blob) - len(blob.rstrip("="))
        position = len(blob) - padding - 1
        value = alphabet.index(blob[position])
        mask = (1 << (padding * 2)) - 1
        mutated = blob[:position] + alphabet[(value & ~mask) | 1] + blob[position + 1:]
        self.assertEqual(base64.b64decode(mutated, validate=True), raw)
        malformed = body + "\n\n" + prefix + " " + mutated + "\n"
        with self.assertRaises(note.NoteError):
            note.split(malformed)


class Receipt(unittest.TestCase):
    def test_receipt_body_shape(self):
        body = note.receipt_text("norn/abc", b"\x01" * 32, deadline=1_760_000_060)
        lines = body.split("\n")
        self.assertEqual(lines[0], "norn/receipt/v1")
        self.assertEqual(lines[1], "norn/abc")
        self.assertEqual(base64.b64decode(lines[2]), b"\x01" * 32)
        self.assertEqual(lines[3], "1760000060")
        self.assertEqual(lines[4], "")
        self.assertTrue(body.endswith("\n"))


if __name__ == "__main__":
    unittest.main()
