"""RED first: the trust file and its fingerprint (SPEC §9)."""
import unittest

from nornref import cbor, fixture, trust


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
