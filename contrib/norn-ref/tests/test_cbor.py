"""RED first: deterministic CBOR for the Norn subset (SPEC §4.0/§4.1)."""
from pathlib import Path
import json
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

    def test_two_byte_simple_values_are_named_as_simple_values(self):
        for n in (16, 20, 21, 32, 255):
            with self.subTest(n=n):
                with self.assertRaisesRegex(cbor.ProfileError,
                                            rf"^simple value outside profile: {n}$"):
                    cbor.decode(bytes([0xf8, n]))

    def test_rejects_trailing_bytes(self):
        with self.assertRaises(cbor.ProfileError):
            cbor.decode(h("0100"))

    def test_boolean_in_fork_size_is_a_valid_profile_item(self):
        vector = (Path(__file__).resolve().parents[3] / "testdata" / "vectors"
                  / "fork" / "bad-bool-size.cbor")
        decoded = cbor.decode(vector.read_bytes())
        self.assertIs(type(decoded["size"]), bool)
        self.assertIs(decoded["size"], True)


if __name__ == "__main__":
    unittest.main()


class ResourceLimits(unittest.TestCase):
    """SPEC §4.0: a decoder must bound its own nesting and input size.

    Neither limit is reachable by a valid entry; they exist so a hostile input
    cannot exhaust a verifier. A spec that states a limit and an implementation
    that ignores it is the defect this whole exercise keeps finding.
    """

    def test_depth_beyond_the_limit_is_rejected(self):
        deep = b"\x81" * (cbor.MAX_DEPTH + 1) + b"\x00"
        with self.assertRaises(cbor.ProfileError):
            cbor.decode(deep)

    def test_depth_at_the_limit_is_accepted(self):
        ok = b"\x81" * cbor.MAX_DEPTH + b"\x00"
        self.assertIsInstance(cbor.decode(ok), list)

    def test_input_beyond_the_size_limit_is_rejected(self):
        with self.assertRaises(cbor.ProfileError):
            cbor.decode(cbor.encode(b"\x00" * (cbor.MAX_ENTRY_BYTES + 1)))

    def test_a_truncated_length_header_does_not_allocate(self):
        """A 2**32-byte string header with no payload must fail fast."""
        with self.assertRaises(cbor.ProfileError):
            cbor.decode(b"\x5a\xff\xff\xff\xff")


class HostileInputVectors(unittest.TestCase):
    """Both implementations answer from `entries-hostile/` and `entries-utf8/`.

    Cold gate run 8 (D15): the profile's banned items were reachable only
    through an entry, where a later rule refuses them too and the reason code
    is the same either way. The bare cases have no schema above them, so the
    profile is the only thing that can refuse -- and this asserts the reference
    refuses each for *its own* reason, exactly as the Go side does.
    """

    def test_every_case_behaves_as_its_table_says(self):
        from nornref import fixture
        vectors = Path(__file__).resolve().parents[3] / "testdata/vectors"
        root = vectors / "entries-utf8"
        manifest = json.loads((root / "cases.json").read_text())
        self.assertIn("bare-surrogate", {case["name"] for case in manifest["cases"]})
        raw = (root / "bare-surrogate.cbor").read_bytes()
        self.assertEqual(raw.hex(), "63eda080")
        with self.assertRaises(cbor.ProfileError):
            cbor.decode(raw)
        repair = bytearray(raw); repair[1:3] = bytes.fromhex("ee80")
        self.assertEqual(cbor.decode(bytes(repair)), "\ue000")
        self.assertEqual(manifest["cases"], [
            {"name": name, "says": says} for name, _, says in fixture.utf8_inputs()
        ])
        self.assertEqual(manifest["rules"]["bare-surrogate"],
                         {"section": "4.0", "says": "valid UTF-8"})
        self.assertFalse((root / "manifest.json").exists())
        hostile = fixture.hostile_inputs()
        self.assertEqual(len(hostile), 17)
        self.assertNotIn("bare-surrogate", {name for name, _, _ in hostile})
        for directory, inputs in (("entries-hostile", hostile),
                                  ("entries-utf8", fixture.utf8_inputs())):
            for name, raw, says in inputs:
                self.assertEqual((vectors / directory / (name + ".cbor")).read_bytes(), raw)
                with self.subTest(directory=directory, name=name):
                    if says is None:
                        cbor.decode(raw)  # at a limit: MUST be accepted
                        continue
                    with self.assertRaises(cbor.ProfileError) as caught:
                        cbor.decode(raw)
                    self.assertIn(says, str(caught.exception),
                                  f"{name} was refused for the wrong rule")


class AllowListVectors(unittest.TestCase):
    ROOT = Path(__file__).resolve().parents[3] / "testdata" / "vectors"

    def test_two_byte_booleans_are_bare_profile_refusals(self):
        # Cold gate run 16, M1. The bare heads are tested here rather than
        # shipped in `entries-hostile/`, whose every case the fourth cold
        # build's harness names in its own code (row 6.5l-xiv-c);
        # `log-republish/13` and `14` carry the rule to every reader.
        for i in range(2):
            with self.subTest(value=20+i):
                with self.assertRaisesRegex(cbor.ProfileError, "simple value"):
                    cbor.decode(bytes((0xf8, 20+i)))
                self.assertIs(cbor.decode(bytes((0xf4+i,))), bool(i))

    def test_bare_simple_value_is_refused_only_by_the_profile(self):
        raw = (self.ROOT / "entries-hostile" / "bare-simple.cbor").read_bytes()
        self.assertEqual(raw, b"\xf0")
        with self.assertRaisesRegex(cbor.ProfileError, "^simple value outside profile: 16$"):
            cbor.decode(raw)
        self.assertIs(cbor.decode(b"\xf5"), True)

    def test_simple_fork_size_is_refused_before_the_schema(self):
        root = self.ROOT / "fork"
        manifest = json.loads((root / "cases.json").read_text())
        self.assertEqual(manifest["codes"].get("bad-simple-size"), "cbor")
        raw = (root / "bad-simple-size.cbor").read_bytes()
        with self.assertRaisesRegex(cbor.ProfileError, "^simple value outside profile: 16$"):
            cbor.decode(raw)
        item = b"\x64size\xf0"
        self.assertEqual(raw.count(item), 1)
        boolean = raw.replace(item, b"\x64size\xf5", 1)
        self.assertEqual(boolean, (root / "bad-bool-size.cbor").read_bytes())
        self.assertEqual(manifest["codes"]["bad-bool-size"], "schema")
        decoded = cbor.decode(boolean)
        self.assertIs(decoded["size"], True)
        self.assertIsNot(type(decoded["size"]), int)
        sound = cbor.decode((root / "evidence-v1.cbor").read_bytes())
        decoded["size"] = sound["size"]
        self.assertEqual(decoded, sound)

    def test_every_named_profile_ban_has_a_shipped_refusal(self):
        root = self.ROOT / "entries-hostile"
        manifest = json.loads((root / "cases.json").read_text())
        cases = {case["name"]: case for case in manifest["cases"]}
        for name in ("bare-negative-integer", "bare-tag", "bare-float", "bare-null",
                     "bare-undefined", "bare-indefinite-text", "bare-simple"):
            with self.subTest(name=name):
                self.assertIn(name, cases)
                self.assertNotIn("accepted", cases[name])
                with self.assertRaises(cbor.ProfileError) as caught:
                    cbor.decode((root / f"{name}.cbor").read_bytes())
                self.assertIn(cases[name]["says"], str(caught.exception))
