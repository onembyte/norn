"""RED first: enrollment requests (SPEC §16).

A request is the only Norn format a *device* produces, and the only one that
crosses an untrusted channel (a phone camera) before anybody has decided to
trust it. So the tests here care about two things above all: that the signature
is checked before anything is believed, and that a request can never be
mistaken for -- or replayed as -- a log entry.
"""
import unittest
from pathlib import Path

from nornref import bech32m, cbor, enrollreq, entry, fixture, keys

NET = fixture.NET
DEV = fixture.KEYS["laptop"]
WG = fixture.WG["spare"]
TS = fixture.T0
VECTOR_ROOT = Path(__file__).resolve().parents[3] / "testdata" / "vectors"


def a_request(**over):
    body = dict(net=NET, device_id="pi-cam", device_pk=DEV.public, wg_pk=WG, ts=TS)
    body.update(over)
    return enrollreq.new(**body)


def signed(**over):
    return enrollreq.sign(a_request(**over), DEV)


class RoundTrip(unittest.TestCase):
    def test_bytes_and_text(self):
        req = signed(labels={"ip": "10.9.0.14/32"}, expires=TS + 30 * 86400)
        raw = enrollreq.encode(req)
        self.assertEqual(enrollreq.decode(raw), req)

        text = enrollreq.to_text(req)
        self.assertTrue(text.startswith("norn1"))
        self.assertEqual(enrollreq.decode_text(text), req)
        self.assertEqual(enrollreq.decode_text(text.upper()), req)

    def test_optional_fields_may_be_absent(self):
        req = signed()
        self.assertNotIn("labels", req)
        self.assertNotIn("expires", req)
        self.assertTrue(enrollreq.verify(req))

    def test_text_stays_small_enough_for_a_qr(self):
        # ENROLLMENT.md promises a request fits on a phone screen as a QR.
        # Version 11 alphanumeric at level M holds 468 characters; this is the
        # bound that keeps `norn enroll` printable, so it is asserted.
        req = signed(labels={"ip": "10.9.0.14/32"}, expires=TS + 30 * 86400)
        self.assertLess(len(enrollreq.to_text(req)), 468)


class Signature(unittest.TestCase):
    def test_preimage_is_domain_separated(self):
        req = signed()
        self.assertTrue(enrollreq.preimage(req).startswith(b"norn/enroll-request/v1\n"))
        unsigned = {k: v for k, v in req.items() if k != "sig"}
        self.assertEqual(enrollreq.preimage(req),
                         b"norn/enroll-request/v1\n" + cbor.encode(unsigned))

    def test_a_request_signature_is_not_an_entry_signature(self):
        """The whole point of the domain prefix (SPEC §16.1)."""
        req = signed()
        env = entry.new("enroll", NET, ts=TS, body={
            "device_id": req["device_id"], "device_pk": req["device_pk"],
            "wg_pk": req["wg_pk"]})
        forged = {"kid": DEV.id, "role": "device", "sig": req["sig"]}
        self.assertFalse(entry.verify_sig(env, forged, DEV.public))

    def test_a_flipped_field_breaks_the_signature(self):
        req = signed()
        req["wg_pk"] = fixture.WG["rogue"]
        self.assertFalse(enrollreq.verify(req))

    def test_signature_by_another_key_is_refused(self):
        # strict=False exists only to build negative vectors; see sign().
        req = enrollreq.sign(a_request(), fixture.KEYS["nas"], strict=False)
        self.assertFalse(enrollreq.verify(req))
        with self.assertRaises(enrollreq.RequestError):
            enrollreq.check(req, net=NET)

    def test_sign_refuses_a_key_that_is_not_the_device_key(self):
        with self.assertRaises(enrollreq.RequestError):
            enrollreq.sign(a_request(), fixture.KEYS["nas"])


class Structure(unittest.TestCase):
    def bad(self, mutate):
        req = signed()
        mutate(req)
        with self.assertRaises(enrollreq.RequestError):
            enrollreq.decode(cbor.encode(req))

    def test_rejections(self):
        cases = {
            "unknown key": lambda r: r.update(extra=1),
            "missing device_pk": lambda r: r.pop("device_pk"),
            "missing sig": lambda r: r.pop("sig"),
            "wrong version": lambda r: r.update(v=2),
            "short net": lambda r: r.update(net=NET[:8]),
            "uppercase device_id": lambda r: r.update(device_id="Pi-Cam"),
            "leading dash in device_id": lambda r: r.update(device_id="-cam"),
            "short device_pk": lambda r: r.update(device_pk=DEV.public[:31]),
            "short wg_pk": lambda r: r.update(wg_pk=WG[:31]),
            "short sig": lambda r: r.update(sig=r["sig"][:63]),
            "boolean expires": lambda r: r.update(expires=True),
            "expires at ts": lambda r: r.update(expires=r["ts"]),
            "expires before ts": lambda r: r.update(expires=r["ts"] - 1),
            "too many labels": lambda r: r.update(labels={f"k{i}": "v" for i in range(33)}),
            "oversize label": lambda r: r.update(labels={"ip": "x" * 257}),
            "non-string label": lambda r: r.update(labels={"ip": 1}),
            "ts is text": lambda r: r.update(ts="now"),
        }
        for why, mutate in cases.items():
            with self.subTest(why=why):
                self.bad(mutate)

    def test_non_canonical_cbor_is_refused(self):
        # A lenient decoder here would accept two encodings of one request,
        # which is two signatures over one meaning (SPEC §4.0).
        req = signed()
        raw = bytearray(cbor.encode(req))
        raw[0] = 0xBF  # indefinite-length map
        with self.assertRaises(enrollreq.RequestError):
            enrollreq.decode(bytes(raw))

    def test_trailing_bytes_are_refused(self):
        with self.assertRaises(enrollreq.RequestError):
            enrollreq.decode(cbor.encode(signed()) + b"\x00")


class TextForm(unittest.TestCase):
    def test_wrong_hrp_refused(self):
        raw = enrollreq.encode(signed())
        with self.assertRaises(enrollreq.RequestError):
            enrollreq.decode_text(bech32m.encode("nrn", raw))

    def test_plain_bech32_refused(self):
        """The *same request*, checksummed with bech32's constant, is refused.

        A made-up string would fail for any reason at all; this one differs
        from the accepted encoding in exactly the constant (SPEC §16.2).
        """
        raw = enrollreq.encode(signed())
        data = bech32m._convertbits(list(raw), 8, 5, pad=True)
        values = bech32m._hrp_expand("norn") + data + [0] * 6
        polymod = bech32m._polymod(values) ^ 1  # bech32, not bech32m
        checksum = [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]
        as_bech32 = "norn1" + "".join(bech32m.CHARSET[v] for v in data + checksum)

        self.assertNotEqual(as_bech32, enrollreq.to_text(signed()))
        self.assertEqual(as_bech32[:-6], enrollreq.to_text(signed())[:-6])
        with self.assertRaises(enrollreq.RequestError):
            enrollreq.decode_text(as_bech32)

    def test_one_character_corrupted(self):
        text = enrollreq.to_text(signed())
        other = "q" if text[10] != "q" else "p"
        with self.assertRaises(enrollreq.RequestError):
            enrollreq.decode_text(text[:10] + other + text[11:])


class ShippedPaddingVector(unittest.TestCase):
    def test_excess_padding_appends_one_group_without_changing_the_signed_request(self):
        base_text = (VECTOR_ROOT / "requests" / "req-padding-base.txt").read_text().strip()
        bad_text = (VECTOR_ROOT / "requests-bad" / "excess-padding.txt").read_text().strip()

        base_hrp, base_groups = bech32m.decode_raw(base_text)
        base_raw = bech32m.decode(base_text)[1]
        self.assertEqual((8 * len(base_raw)) % 5, 4)
        request = enrollreq.decode(base_raw)
        self.assertEqual(enrollreq.check(request, net=NET), request)

        bad_hrp, bad_groups = bech32m.decode_raw(bad_text)
        self.assertEqual(bad_hrp, base_hrp)
        self.assertEqual(bad_groups, base_groups + [0])
        with self.assertRaisesRegex(bech32m.Bech32Error, "too much padding"):
            bech32m.decode(bad_text)


class ShippedLabelBoundary(unittest.TestCase):
    def test_label_value_limit_is_256_utf8_bytes(self):
        base_text = (VECTOR_ROOT / "requests" / "req-label-at-cap.txt").read_text().strip()
        request = enrollreq.decode_text(base_text)
        self.assertEqual(enrollreq.check(request, net=NET), request)
        base_label = request["labels"]["ip"]
        self.assertEqual(len(base_label.encode("utf-8")), 256)
        self.assertEqual(len(base_label), 128)

        bad_text = (VECTOR_ROOT / "requests-bad" / "oversize-label.txt").read_text().strip()
        bad_raw = bech32m.decode(bad_text)[1]
        bad_request = cbor.decode(bad_raw)
        bad_label = bad_request["labels"]["ip"]
        self.assertEqual(len(bad_label.encode("utf-8")), 257)
        self.assertEqual(len(bad_label), 129)
        self.assertTrue(enrollreq.verify(bad_request),
                        "the negative must be correctly signed before the cap rejects it")
        with self.assertRaisesRegex(enrollreq.RequestError, "longer than 256 bytes"):
            enrollreq.decode_text(bad_text)


class ShippedReservedHints(unittest.TestCase):
    def test_malformed_reserved_hints_are_accepted_as_opaque_signed_text(self):
        text = (VECTOR_ROOT / "requests" / "req-reserved-hints.txt").read_text().strip()
        request = enrollreq.decode_text(text)
        self.assertEqual(enrollreq.check(request, net=NET), request)
        self.assertTrue(enrollreq.verify(request))
        self.assertEqual(request["labels"], {
            "ip": "not-a-cidr",
            "endpoint": "not-an-endpoint",
        })


class ShippedMapKeyCap(unittest.TestCase):
    def test_oversize_request_label_key_is_refused_by_the_cbor_profile(self):
        text = (VECTOR_ROOT / "requests-bad" / "oversize-label-key.txt").read_text().strip()
        with self.assertRaisesRegex(enrollreq.RequestError, "map key must be 1-23 bytes"):
            enrollreq.decode_text(text)


class Check(unittest.TestCase):
    def test_accepts_a_good_request(self):
        req = signed()
        self.assertEqual(enrollreq.check(req, net=NET), req)

    def test_refuses_another_network(self):
        with self.assertRaises(enrollreq.RequestError):
            enrollreq.check(signed(), net=bytes(16))


if __name__ == "__main__":
    unittest.main()
