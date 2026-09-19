"""RED first: the §2/§4.0 field rules, in one place.

These rules were written twice -- once inside replay for entry bodies, once
(about to be) for enrollment requests. Two copies of a validation rule is how
implementations drift apart while every test still passes, so they live here
and both callers use them.
"""
import unittest

from nornref import fields


class DeviceID(unittest.TestCase):
    GOOD = ["a", "pi-cam", "laptop.local", "a" * 64, "0", "x9-.-9x"]
    BAD = [
        ("", "empty"),
        ("a" * 65, "over 64 bytes"),
        ("Pi-Cam", "uppercase"),
        (".hidden", "leading dot"),
        ("-lead", "leading dash"),
        ("pi cam", "space"),
        ("pi_cam", "underscore"),
        ("café", "non-ASCII"),
        (b"pi-cam", "bytes, not text"),
        (None, "absent"),
        (7, "not a string"),
    ]

    def test_accepted(self):
        for value in self.GOOD:
            with self.subTest(value=value[:12]):
                self.assertEqual(fields.device_id(value), value)

    def test_rejected(self):
        for value, why in self.BAD:
            with self.subTest(why=why):
                with self.assertRaises(fields.FieldError):
                    fields.device_id(value)


class Labels(unittest.TestCase):
    def test_absent_is_none(self):
        self.assertIsNone(fields.labels(None))

    def test_accepted(self):
        value = {f"k{i}": "v" for i in range(32)}
        self.assertEqual(fields.labels(value), value)
        self.assertEqual(fields.labels({"ip": "x" * 256}), {"ip": "x" * 256})

    def test_rejected(self):
        cases = [
            ({f"k{i}": "v" for i in range(33)}, "33 labels"),
            ({"ip": "x" * 257}, "value over 256 bytes"),
            ({"ip": "é" * 129}, "258 bytes in UTF-8, though 129 characters"),
            ({"ip": 1}, "non-string value"),
            ([("ip", "1")], "not a map"),
        ]
        for value, why in cases:
            with self.subTest(why=why):
                with self.assertRaises(fields.FieldError):
                    fields.labels(value)


class Keys(unittest.TestCase):
    def test_public_key(self):
        self.assertEqual(fields.public_key(b"\x01" * 32, "pk"), b"\x01" * 32)
        for value, why in [(b"\x01" * 31, "short"), (b"\x01" * 33, "long"),
                           ("a" * 32, "text not bytes"), (None, "absent")]:
            with self.subTest(why=why):
                with self.assertRaises(fields.FieldError):
                    fields.public_key(value, "pk")

    def test_signature(self):
        self.assertEqual(fields.signature(b"\x02" * 64), b"\x02" * 64)
        for value, why in [(b"\x02" * 63, "short"), (b"\x02" * 65, "long"),
                           (None, "absent")]:
            with self.subTest(why=why):
                with self.assertRaises(fields.FieldError):
                    fields.signature(value)


class Uints(unittest.TestCase):
    def test_accepted(self):
        self.assertEqual(fields.uint(0, "ts"), 0)
        self.assertEqual(fields.uint(2**63 - 1, "ts"), 2**63 - 1)

    def test_rejected(self):
        for value, why in [(-1, "negative"), (True, "bool is not a uint"),
                           ("7", "text"), (None, "absent"), (2**63, "too large")]:
            with self.subTest(why=why):
                with self.assertRaises(fields.FieldError):
                    fields.uint(value, "ts")


if __name__ == "__main__":
    unittest.main()
