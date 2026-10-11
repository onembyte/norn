"""RED first: the trust file and its fingerprint (SPEC §9)."""
import copy
import pathlib
import unittest

from nornref import cbor, fixture, note, trust


class Build(unittest.TestCase):
    def setUp(self):
        self.trust = fixture.trust_file()

    def test_origin_is_base32_of_net_without_padding(self):
        self.assertTrue(self.trust["origin"].startswith("norn/"))
        suffix = self.trust["origin"][len("norn/"):]
        self.assertNotIn("=", suffix)
        self.assertEqual(suffix, suffix.lower())

    def test_round_trips_through_canonical_cbor(self):
        raw = trust.encode(self.trust)
        self.assertEqual(cbor.decode(raw), self.trust)

    def test_validate_accepts_the_fixture(self):
        trust.validate(self.trust)

    def test_origin_case_is_the_only_fault(self):
        # Cold gate run 13, D18: one letter of the origin changes case, and the
        # log key's note name and the policy's `log` line agree with it, so
        # only the exact derivation of `origin` from `net` can refuse the file.
        damaged = dict(fixture.trust_rejections()).get("45-origin-case-changed")
        self.assertIsNotNone(damaged, "the origin-case negative is missing")
        root = pathlib.Path(__file__).resolve().parents[3] / "testdata" / "vectors"
        raw = (root / "trust-bad" / "45-origin-case-changed.cbor").read_bytes()
        self.assertEqual(cbor.decode(raw), damaged)
        origin, derived = damaged["origin"], self.trust["origin"]
        self.assertEqual(origin.casefold(), derived.casefold())
        self.assertEqual(sum(a != b for a, b in zip(origin, derived)), 1)
        self.assertEqual(note.parse_vkey(damaged["log_key"]).name, origin)
        self.assertIn(f"log {damaged['log_key']} ", damaged["policy"])
        with self.assertRaisesRegex(trust.TrustError, "origin does not match net"):
            trust.validate(damaged)
        with self.assertRaisesRegex(trust.TrustError, "origin does not match net"):
            trust.parse(raw)

    def test_log_key_name_case_is_the_only_fault(self):
        # The other half: `origin` is honest and the log key's note name
        # differs from it only in one letter's case, the policy agreeing, so
        # only "its note name MUST equal `origin`" can refuse the file.
        damaged = dict(fixture.trust_rejections()).get("46-log-key-name-case-changed")
        self.assertIsNotNone(damaged, "the log-key-name-case negative is missing")
        root = pathlib.Path(__file__).resolve().parents[3] / "testdata" / "vectors"
        raw = (root / "trust-bad" / "46-log-key-name-case-changed.cbor").read_bytes()
        self.assertEqual(cbor.decode(raw), damaged)
        self.assertEqual(damaged["origin"], self.trust["origin"])
        name = note.parse_vkey(damaged["log_key"]).name
        self.assertEqual(name.casefold(), damaged["origin"].casefold())
        self.assertEqual(sum(a != b for a, b in zip(name, damaged["origin"])), 1)
        self.assertIn(f"log {damaged['log_key']} ", damaged["policy"])
        with self.assertRaisesRegex(trust.TrustError, "does not match origin"):
            trust.validate(damaged)

    def test_a_policy_key_under_another_name_is_the_only_fault(self):
        # D-074 (d): "the same keys" is the same verifier key -- name,
        # algorithm and public key -- compared as canonical text. The policy
        # carries pi's own public key under another key name; the witness entry
        # is honest. A reader comparing parsed public keys accepts the file.
        damaged = dict(fixture.trust_rejections()).get("48-policy-witness-key-renamed")
        self.assertIsNotNone(damaged, "the renamed-policy-key negative is missing")
        root = pathlib.Path(__file__).resolve().parents[3] / "testdata" / "vectors"
        raw = (root / "trust-bad" / "48-policy-witness-key-renamed.cbor").read_bytes()
        self.assertEqual(cbor.decode(raw), damaged)
        self.assertEqual(damaged["witnesses"], self.trust["witnesses"])
        listed = self.trust["witnesses"][0]
        renamed = [line.split()[2] for line in damaged["policy"].split("\n")
                   if line.split()[:2] == ["witness", listed["name"]]]
        self.assertEqual(len(renamed), 1)
        a, b = note.parse_vkey(listed["key"]), note.parse_vkey(renamed[0])
        self.assertEqual(a.public, b.public)
        self.assertNotEqual(a.name, b.name)
        with self.assertRaisesRegex(trust.TrustError, "another in the policy"):
            trust.validate(damaged)
        repaired = dict(damaged, policy=damaged["policy"].replace(renamed[0], listed["key"]))
        trust.validate(repaired)

    def test_key_id_and_key_name_vectors_are_their_only_fault(self):
        # D-074 (f): a key id is lowercase hex and a key name is one or more
        # ASCII bytes 0x21-0x7E without '+'. Each case breaks one of those on
        # pi's key, in the witnesses and the policy alike, and putting the
        # honest key back in both places repairs the file.
        root = pathlib.Path(__file__).resolve().parents[3] / "testdata" / "vectors"
        cases = dict(fixture.trust_rejections())
        listed = self.trust["witnesses"][0]["key"]
        faults = {
            "49-witness-key-id-uppercase": lambda name, kid: kid != kid.lower(),
            "50-witness-key-name-not-ascii": lambda name, kid: any(ord(c) > 0x7E for c in name),
        }
        for case, fault in faults.items():
            with self.subTest(case=case):
                damaged = cases.get(case)
                self.assertIsNotNone(damaged, f"{case} is missing")
                raw = (root / "trust-bad" / f"{case}.cbor").read_bytes()
                self.assertEqual(cbor.decode(raw), damaged)
                key = damaged["witnesses"][0]["key"]
                name, kid, _ = key.split("+", 2)
                self.assertTrue(fault(name, kid), f"{key!r} does not carry the fault")
                self.assertIn(f"witness pi {key} ", damaged["policy"])
                with self.assertRaises(trust.TrustError):
                    trust.parse(raw)
                repaired = copy.deepcopy(damaged)
                repaired["witnesses"][0]["key"] = listed
                repaired["policy"] = damaged["policy"].replace(key, listed)
                trust.validate(repaired)

    def test_validate_rejects_damage(self):
        for mutate in [
            lambda t: t.update(version=2),
            lambda t: t.update(net=b"\x00" * 8),
            lambda t: t.update(genesis_hash=b"\x00" * 8),
            lambda t: t.update(origin="wrong/origin"),
            lambda t: t.update(log_key="not-a-vkey"),
            lambda t: t.update(witnesses=[]),
            lambda t: t.pop("policy"),
        ]:
            damaged = dict(self.trust)
            mutate(damaged)
            with self.subTest(damaged=sorted(set(damaged) ^ set(self.trust)) or "value"):
                with self.assertRaises(trust.TrustError):
                    trust.validate(damaged)


class Fingerprint(unittest.TestCase):
    def setUp(self):
        self.trust = fixture.trust_file()

    def test_shape_is_four_groups_of_four(self):
        fp = trust.fingerprint(self.trust)
        groups = fp.split("-")
        self.assertEqual(len(groups), 4)
        self.assertTrue(all(len(g) == 4 for g in groups))

    def test_uses_crockford_alphabet_only(self):
        fp = trust.fingerprint(self.trust).replace("-", "")
        self.assertTrue(set(fp) <= set(trust.CROCKFORD))
        self.assertFalse(set(fp) & set("ILOU"), "confusable letters must be excluded")

    def test_is_deterministic(self):
        self.assertEqual(trust.fingerprint(self.trust), trust.fingerprint(dict(self.trust)))

    def test_changes_when_any_field_changes(self):
        base = trust.fingerprint(self.trust)
        for field, value in [("log_key", "other+00000000+AQ=="),
                             ("genesis_hash", b"\x02" * 32),
                             ("policy", "quorum none\n")]:
            changed = dict(self.trust)
            changed[field] = value
            with self.subTest(field=field):
                self.assertNotEqual(trust.fingerprint(changed), base)

    def test_is_80_bits(self):
        self.assertEqual(trust.FINGERPRINT_BYTES * 8, 80)


class Toml(unittest.TestCase):
    def test_renders_and_is_parseable(self):
        import tomllib
        text = trust.to_toml(fixture.trust_file())
        parsed = tomllib.loads(text)
        self.assertEqual(parsed["version"], 1)
        self.assertEqual(parsed["origin"], fixture.trust_file()["origin"])
        self.assertEqual(len(parsed["witness"]), 3)
        self.assertIn("fingerprint", text)

    def test_is_deterministic(self):
        self.assertEqual(trust.to_toml(fixture.trust_file()), trust.to_toml(fixture.trust_file()))


if __name__ == "__main__":
    unittest.main()


class ReceiptVector(unittest.TestCase):
    """The generated receipt must verify under the trust file's own log key."""

    def test_receipt_verifies_under_the_trust_log_key(self):
        from nornref import note
        doc = fixture.trust_file()
        text = note.receipt_text(doc["origin"], doc["genesis_hash"], fixture.T0 + 60)
        signed = note.sign(text, doc["origin"], fixture.KEYS["logkey"])
        self.assertEqual(note.verify(signed, [doc["log_key"]]), text)

    def test_receipt_does_not_verify_under_a_witness_key(self):
        from nornref import note
        doc = fixture.trust_file()
        text = note.receipt_text(doc["origin"], doc["genesis_hash"], fixture.T0 + 60)
        signed = note.sign(text, doc["origin"], fixture.KEYS["logkey"])
        with self.assertRaises(note.NoteError):
            note.verify(signed, [doc["witnesses"][0]["key"]])
