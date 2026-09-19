"""RED first: deterministic CBOR for the Norn subset (SPEC §4.0/§4.1)."""
import unittest
from nornref import cbor


def h(s: str) -> bytes:
    return bytes.fromhex(s)


class EncodeExamples(unittest.TestCase):
    # RFC 8949 Appendix A examples that fall inside the Norn subset.
    CASES = [
        (0, "00"), (1, "01"), (23, "17"), (24, "1818"), (255, "18ff"),
        (256, "190100"), (65535, "19ffff"), (65536, "1a00010000"),
        (2**32, "1b0000000100000000"), (2**63 - 1, "1b7fffffffffffffff"),
        (b"", "40"), (b"\x01\x02\x03\x04", "4401020304"),
        ("", "60"), ("a", "6161"), ("IETF", "6449455446"), ("ü", "62c3bc"),
        (False, "f4"), (True, "f5"),
        ([], "80"), ([1, 2, 3], "83010203"),
        ({}, "a0"), ({"a": 1, "b": [2, 3]}, "a26161016162820203"),
        ("x" * 23, "77" + "78" * 23), ("x" * 24, "7818" + "78" * 24),
    ]

    def test_examples(self):
        for value, hexed in self.CASES:
            with self.subTest(value=value):
                self.assertEqual(cbor.encode(value), h(hexed))

    def test_map_keys_sorted_by_encoded_bytes(self):
        # "b" (0x61 0x62) sorts before "aa" (0x62 0x61 0x61): bytewise on the encoding,
        # which for keys < 24 bytes equals shorter-first-then-bytewise.
        self.assertEqual(cbor.encode({"aa": 1, "b": 2}), h("a2616202626161" "01"))
        self.assertEqual(cbor.encode({"b": 1, "a": 2}), h("a2616102616201"))


class EncodeRejects(unittest.TestCase):
    def test_outside_subset(self):
        for bad in [-1, 2**63, 1.5, None, {1: 2}, {"k" * 24: 1}, (1, 2), {"a": None}, set()]:
            with self.subTest(bad=bad):
                with self.assertRaises(cbor.ProfileError):
                    cbor.encode(bad)


class DecodeStrict(unittest.TestCase):
    def test_roundtrip(self):
        for value, _ in EncodeExamples.CASES:
            self.assertEqual(cbor.decode(cbor.encode(value)), value)

    def test_rejects_non_canonical_and_out_of_profile(self):
        for bad in ["1801", "20", "f6", "f97e00", "9f01ff", "a10102", "a2616101616101", "a2616202616101", "c100"]:
            with self.subTest(bad=bad):
                with self.assertRaises(cbor.ProfileError):
                    cbor.decode(h(bad))

    def test_rejects_trailing_bytes(self):
        with self.assertRaises(cbor.ProfileError):
            cbor.decode(h("0100"))


if __name__ == "__main__":
    unittest.main()
