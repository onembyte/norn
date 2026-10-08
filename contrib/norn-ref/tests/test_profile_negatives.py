"""RED first: negatives that isolate the ENCODING rule they test.

Run 3's sharpest vector critique: a profile negative that puts a forbidden item
where a typed field lives is over-determined -- an implementation with strict
typing rejects it for the type and never exercises the profile rule at all. The
cases below all decode to a *valid entry* under a lenient decoder, so only a
decoder that enforces the encoding rule rejects them.
"""
import unittest

from nornref import entry, fixture, replay


def log_outcomes():
    """Replay the fixture and return {entry name: reason or None}.

    These negatives live *in* the log, so appending copies would be rejected as
    `dup-entry` (D-031) rather than for their own fault. Assert against the log.
    """
    items = fixture.log()
    raw = [i.raw for i in items]
    state = replay.replay(replay.Anchor(fixture.NET, entry.leaf_hash(raw[0])), raw)
    by_index = {r["index"]: r["reason"] for r in state.rejected}
    return {item.name: by_index.get(i) for i, item in enumerate(items)}


def base_after() -> int:
    """Index of the control entry the encoding negatives are patches of."""
    return next(i for i, item in enumerate(fixture.log())
                if item.name.endswith("-profile-base"))


class IsolatingProfileNegatives(unittest.TestCase):
    """Each decodes to the same valid entry if the rule is not enforced."""

    def test_each_case_is_rejected_as_decode(self):
        outcomes = log_outcomes()
        for name, _ in fixture.profile_negatives(base_after()):
            with self.subTest(case=name):
                self.assertEqual(outcomes[f"{self._index_of(name)}-bad-{name}"], "decode")

    @staticmethod
    def _index_of(name: str) -> int:
        return next(i for i, item in enumerate(fixture.log())
                    if item.name.endswith(f"-bad-{name}"))

    def test_a_lenient_decoder_would_see_a_valid_entry(self):
        """Proves the isolation claim rather than asserting it.

        Each negative must still look like a well-formed entry of its base's
        type to a decoder that skips the encoding rules -- otherwise the vector
        would be rejected for something other than the rule it names.
        """
        for name, raw in fixture.profile_negatives(base_after()):
            with self.subTest(case=name):
                lenient = fixture.decode_leniently(raw)
                self.assertIn(lenient["t"], entry.TYPES)
                self.assertEqual(lenient["v"], entry.VERSION)
                self.assertEqual(lenient["net"], fixture.NET)
                self.assertTrue(lenient["sigs"], "signatures must survive the patch")
                self.assertIsInstance(lenient["body"], dict)
                self.assertLessEqual(lenient.get("after", 0), self._index_of(name),
                                     "after must not fire before the rule under test")

    def test_every_control_entry_is_accepted(self):
        """Without a control, a negative could be rejected for a fault its
        author did not intend and nobody would notice."""
        outcomes = log_outcomes()
        for control in [k for k in outcomes if k.endswith(("-profile-base", "-labelcap-base", "-two-sig-base"))]:
            with self.subTest(control=control):
                self.assertIsNone(outcomes[control])


class FieldConstraintNegatives(unittest.TestCase):
    def test_each_case_is_rejected_as_decode(self):
        outcomes = log_outcomes()
        for name, _ in fixture.field_negatives():
            with self.subTest(case=name):
                match = next(k for k in outcomes if k.endswith(f"-bad-{name}"))
                self.assertEqual(outcomes[match], "decode")

    def test_cases_cover_the_documented_constraints(self):
        names = {n for n, _ in fixture.field_negatives()}
        for want in ("device_id", "pk-length", "sig-length", "text-too-long"):
            self.assertTrue(any(want in n for n in names), f"no case for {want}")


class NegativesAreNotOverDetermined(unittest.TestCase):
    """Each encoding negative must fail for its rule and nothing else.

    Gate run 4 found four that did not: two carried `after` values left behind
    by a renumbering, and two had signatures invalidated by the very patch they
    were testing. Both make the vector applaud an implementation that skips the
    rule entirely.
    """

    #: Vectors whose purpose *is* a stale `after`: the plain ones, and the four
    #: precedence cases that pair it with a second fault so §5.1's step 6 can
    #: be shown to decide after steps 3, 4 and 5 and before step 7. A
    #: precedence vector is over-determined ON PURPOSE -- that is what makes
    #: an ordering observable -- so the exemption is by name and stays short.
    AFTER_IS_THE_POINT = ("-bad-after", "-bad-precedence-after-before-threshold",
                          "-bad-precedence-decode-before-after", "-bad-after-by-one",
                          "-bad-precedence-unknown-type-before-after",
                          "-bad-precedence-dup-genesis-before-after")

    def test_after_never_exceeds_the_index(self):
        """Except in the vectors whose whole purpose is to exceed it."""
        for index, item in enumerate(fixture.log()):
            if item.name.endswith(self.AFTER_IS_THE_POINT):
                continue
            after = fixture.decode_leniently(item.raw).get("after")
            if not isinstance(after, int):
                continue  # a non-integer `after` is the fault under test
            with self.subTest(name=item.name):
                self.assertLessEqual(after, index,
                                     "a stale `after` rejects the entry before its own rule")

    @staticmethod
    def _preimage_from_raw(raw: bytes) -> bytes:
        """Strip the `sigs` pair at the byte level to recover the preimage.

        Re-encoding from a decoded model cannot work here: a negative that
        deliberately carries invalid UTF-8 or a non-canonical integer does not
        survive a round trip, which is the whole point of it.
        """
        from nornref import cbor, entry as E

        key = cbor.encode("sigs")
        at = raw.index(key)
        rest = raw[at + len(key):]
        # The signature array is definite-length with fewer than 24 elements.
        count = rest[0] & 0x1F
        end = 1
        for _ in range(count):
            element_end = len(cbor.encode(cbor.decode(_scan(rest, end))))
            end += element_end
        pairs = raw[0] & 0x1F
        return E.PREIMAGE_PREFIX + bytes([0xA0 | (pairs - 1)]) + raw[1:at] + rest[end:]

    @staticmethod
    def _canonical_preimage(env: dict) -> bytes | None:
        """The preimage a lenient decoder computes after canonicalising.

        Patches that *round-trip* -- a stripped tag, a joined indefinite string,
        a resolved duplicate key, reordered signatures -- land back on the base
        entry, so the original signatures verify against this.
        """
        from nornref import cbor, entry as E

        try:
            return E.PREIMAGE_PREFIX + cbor.encode(
                {k: v for k, v in env.items() if k != "sigs"})
        except cbor.ProfileError:
            return None  # the patch cannot be canonicalised; see _preimage_from_raw

    def test_encoding_negatives_carry_verifying_signatures(self):
        """The patch must be the only fault, by one of two routes.

        Either the patch canonicalises away, so the original signatures still
        verify; or it cannot, and the entry was re-signed over the patched
        preimage. A negative satisfying neither is rejected for its broken
        signature rather than for the rule it names -- which is precisely how
        four of these slipped through before.
        """
        from nornref import keys

        by_kid = {k.id: k.public for k in fixture.KEYS.values()}
        for name, raw in fixture.profile_negatives(base_after()):
            with self.subTest(case=name):
                env = fixture.decode_leniently(raw)
                candidates = [p for p in (self._canonical_preimage(env),
                                          self._preimage_from_raw(raw)) if p]
                verified = any(
                    all(keys.verify(by_kid[sig["kid"]], preimage, sig["sig"])
                        for sig in env["sigs"])
                    for preimage in candidates)
                self.assertTrue(verified,
                                f"{name}: no preimage makes its signatures verify, so the "
                                "vector is rejected for the signature, not its named rule")


def _scan(buf: bytes, start: int) -> bytes:
    """Return the bytes of one CBOR item beginning at `start`."""
    from nornref import cbor

    for end in range(start + 1, len(buf) + 1):
        try:
            cbor.decode(buf[start:end])
        except cbor.ProfileError:
            continue
        return buf[start:end]
    raise AssertionError("no complete item found")
