"""RED first: bech32m (BIP-350), checked against the BIP's own vectors.

The point of this file is that the vectors are *not mine*. An encoder and a
decoder that agree with each other prove only self-consistency; these strings
come from the specification, so passing them means agreeing with everyone else
who implemented it.
"""
import unittest

from nornref import bech32m

# BIP-350, "Test vectors for Bech32m".
BIP350_VALID = [
    "A1LQFN3A",
    "a1lqfn3a",
    "an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11sg7hg6",
    "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx",
    "11llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllludsr8",
    "split1checkupstagehandshakeupstreamerranterredcaperredlc445v",
    "?1v759aa",
]

#: Same source, reasons kept: one of them is a rule Norn deliberately drops.
BIP350_INVALID = [
    ("\x201xj0phk", "HRP character out of range"),
    ("\x7f1g6xzxy", "HRP character out of range"),
    ("\x801vctc34", "HRP character out of range"),
    ("an84characterslonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11d6pts4",
     "overall max length exceeded"),
    ("qyrz8wqd2c9m", "no separator character"),
    ("1qyrz8wqd2c9m", "empty HRP"),
    ("y1b0jsk6g", "invalid data character"),
    ("lt1igcx5c0", "invalid data character"),
    ("in1muywd", "too short checksum"),
    ("mm1crxm3i", "invalid character in checksum"),
    ("au1s5cgom", "invalid character in checksum"),
    ("M1VUXWEZ", "checksum calculated with uppercase form of HRP"),
    ("16plkw9", "empty HRP"),
    ("1p2gdwpf", "empty HRP"),
]

#: BIP-173's valid *bech32* strings. Every one must fail here: the two
#: encodings differ only in the checksum constant, so a decoder that accepts
#: both accepts exactly the corruption the constant was introduced to catch.
BIP173_VALID_BECH32 = [
    "A12UEL5L",
    "a12uel5l",
    "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
    "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
    "11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j",
    "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w",
    "?1ezyfcl",
]

MAX_BIP173_LENGTH = 90
TOO_LONG = BIP350_INVALID[3][0]


class PublishedVectors(unittest.TestCase):
    def test_valid_round_trip(self):
        for s in BIP350_VALID:
            with self.subTest(s=s[:24]):
                hrp, data = bech32m.decode_raw(s)
                self.assertEqual(bech32m.encode_raw(hrp, data), s.lower())

    def test_invalid_rejected(self):
        for s, reason in BIP350_INVALID:
            if reason == "overall max length exceeded":
                continue  # see TheOneRuleNornDrops
            with self.subTest(reason=reason):
                with self.assertRaises(bech32m.Bech32Error):
                    bech32m.decode_raw(s)

    def test_plain_bech32_rejected(self):
        for s in BIP173_VALID_BECH32:
            with self.subTest(s=s[:24]):
                with self.assertRaises(bech32m.Bech32Error):
                    bech32m.decode_raw(s)


class TheOneRuleNornDrops(unittest.TestCase):
    """SPEC §16.2: BIP-173's 90-character limit does not apply to Norn."""

    def test_over_long_string_decodes(self):
        # Asserted, not merely written down -- and asserted narrowly: this one
        # string must decode and must exceed the limit, while every other
        # invalid vector above still fails. That pins the deviation to one rule.
        hrp, data = bech32m.decode_raw(TOO_LONG)
        self.assertGreater(len(TOO_LONG), MAX_BIP173_LENGTH)
        self.assertEqual(bech32m.encode_raw(hrp, data), TOO_LONG)


class NornRules(unittest.TestCase):
    def test_uppercase_accepted_and_identical(self):
        # QR alphanumeric mode has no lowercase letters (SPEC §16.2).
        payload = bytes(range(40))
        lower = bech32m.encode("norn", payload)
        self.assertEqual(lower, lower.lower())
        self.assertEqual(bech32m.decode(lower.upper()), ("norn", payload))

    def test_mixed_case_rejected(self):
        s = bech32m.encode("norn", b"\x01\x02\x03")
        mixed = s[:6] + s[6:].upper()
        self.assertNotIn(mixed, (s, s.upper()))
        with self.assertRaises(bech32m.Bech32Error):
            bech32m.decode(mixed)

    def test_bytes_round_trip(self):
        for n in (0, 1, 2, 31, 32, 33, 255, 256):
            with self.subTest(n=n):
                payload = bytes((i * 7 + 3) % 256 for i in range(n))
                self.assertEqual(bech32m.decode(bech32m.encode("norn", payload)),
                                 ("norn", payload))

    def test_single_flipped_character_caught(self):
        s = bech32m.encode("norn", b"payload for a flip test")
        other = "q" if s[-1] != "q" else "p"
        with self.assertRaises(bech32m.Bech32Error):
            bech32m.decode(s[:-1] + other)

    def test_padding_must_be_zero_and_short(self):
        hrp, data = bech32m.decode_raw(bech32m.encode("norn", b"\x00"))
        self.assertEqual(len(data), 2)  # 8 bits -> two groups, 2 bits padding

        bad = list(data)
        bad[-1] |= 1  # a non-zero tail is a value pretending to be padding
        with self.assertRaises(bech32m.Bech32Error):
            bech32m.decode(bech32m.encode_raw(hrp, bad))

        with self.assertRaises(bech32m.Bech32Error):  # 5 bits of padding
            bech32m.decode(bech32m.encode_raw(hrp, list(data) + [0]))

    def test_hrp_is_returned_not_assumed(self):
        self.assertEqual(bech32m.decode(bech32m.encode("other", b"\x09"))[0], "other")


if __name__ == "__main__":
    unittest.main()
