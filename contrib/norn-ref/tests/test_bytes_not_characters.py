"""Cold gate run 11, D6: SPEC §4.0's text caps are bytes of UTF-8.

Every over-long vector was ASCII, so a reader that counted characters passed
the suite; no value sat at a cap, so a reader that refused one did too; and no
`policy` entry was over its cap at all. Each cap now ships as a pair, read here
from the SHIPPED files: a positive at exactly the cap, and a negative that is
the same value with one ASCII `x` made `Ж` -- one byte over, same characters.
"""

import json
import pathlib
import unicodedata
import unittest

from nornref import bech32m, cbor, enrollreq, policy, replay, trust

VECTORS = pathlib.Path(__file__).resolve().parents[3] / "testdata" / "vectors"


def _units(text: str) -> int:
    return len(text.encode("utf-16-le")) // 2


class PairShape(unittest.TestCase):
    def assert_pair(self, pos: str, neg: str, cap: int) -> None:
        self.assertEqual(len(pos.encode()), cap)
        self.assertEqual(len(neg.encode()), cap + 1)
        # Same code points and UTF-16 units: a character counter cannot tell them apart.
        self.assertEqual(len(pos), len(neg))
        self.assertEqual(_units(pos), _units(neg))
        differ = [(a, b) for a, b in zip(pos, neg) if a != b]
        self.assertEqual(len(differ), 1)
        a, b = differ[0]
        self.assertEqual((len(a.encode()), len(b.encode())), (1, 2))
        self.assertEqual({len(c.encode()) for c in pos}, {1, 2, 3, 4})
        # Measured as encoded (SPEC §4.0): normalised first, the positive is over the cap.
        self.assertGreater(len(unicodedata.normalize("NFD", pos).encode()), cap)


def _log():
    man = json.loads((VECTORS / "log" / "manifest.json").read_text())
    anchor = replay.Anchor(bytes.fromhex(man["anchor"]["net"]),
                           bytes.fromhex(man["anchor"]["genesis_hash"]))
    raws = [(VECTORS / "log" / f"{e['name']}.cbor").read_bytes() for e in man["entries"]]
    return man["entries"], anchor, raws


def _named(entries, name):
    for i, e in enumerate(entries):
        if e["name"].split("-", 1)[1] == name:
            return i
    raise AssertionError(f"no log entry named {name}")


class TheLogsTextCaps(PairShape):
    def test_each_pair_is_one_byte_apart_and_only_the_positive_is_accepted(self):
        entries, anchor, raws = _log()
        state = replay.replay(anchor, raws)
        refused = {r["index"]: r["reason"] for r in state.rejected}
        for pos, neg, field, cap in [
            ("revoke-by-roots", "bad-revoke-reason-too-long", "reason", 256),
            ("note", "bad-text-too-long", "text", 4096),
            ("policy-rotated", "bad-policy-text-too-long", "text", 4096),
        ]:
            with self.subTest(neg):
                p, n = _named(entries, pos), _named(entries, neg)
                pos_text = cbor.decode(raws[p])["body"][field]
                neg_text = cbor.decode(raws[n])["body"][field]
                self.assert_pair(pos_text, neg_text, cap)
                # The same body shape: the revoke pair names two devices on
                # purpose (the positive really revokes one), so keys, not values.
                self.assertEqual(sorted(cbor.decode(raws[p])["body"]),
                                 sorted(cbor.decode(raws[n])["body"]))
                if neg == "bad-policy-text-too-long":
                    # The extra byte is in the comment; every directive is the positive's,
                    # and the negative is a policy, so only the cap can refuse it.
                    def directives(text):
                        return [ln for ln in text.split("\n") if not ln.lstrip(" \t").startswith("#")]
                    self.assertEqual(directives(pos_text), directives(neg_text))
                    policy.parse(neg_text)
                self.assertNotIn(p, refused)
                self.assertEqual(refused.get(n), "decode")


class TheGenesisNameCap(PairShape):
    def test_the_pair(self):
        def case(folder):
            man = json.loads((folder / "manifest.json").read_text())
            anchor = replay.Anchor(bytes.fromhex(man["anchor"]["net"]),
                                   bytes.fromhex(man["anchor"]["genesis_hash"]))
            raw = (folder / "00-genesis.cbor").read_bytes()
            return cbor.decode(raw)["body"]["name"], replay.replay(anchor, [raw])
        pos, good = case(VECTORS / "genesis-good" / "name-at-the-cap")
        neg, bad = case(VECTORS / "genesis" / "14-name-too-long")
        self.assert_pair(pos, neg, 64)
        bodies = [dict(cbor.decode((VECTORS / d / "00-genesis.cbor").read_bytes())["body"])
                  for d in ("genesis-good/name-at-the-cap", "genesis/14-name-too-long")]
        for b in bodies:
            del b["name"]
        self.assertEqual(bodies[0], bodies[1])
        self.assertEqual((good.rejected, good.size), ([], 1))
        self.assertEqual(bad.rejected, [{"index": 0, "reason": "bad-genesis"}])


class TheTrustNameCaps(PairShape):
    def test_the_pairs(self):
        for pos, neg, get in [
            ("name-at-the-cap", "26-name-too-long", lambda d: d["name"]),
            ("witness-name-at-the-cap", "32-witness-name-too-long",
             lambda d: d["witnesses"][0]["name"]),
        ]:
            with self.subTest(neg):
                good = (VECTORS / "trust-good" / f"{pos}.cbor").read_bytes()
                bad = (VECTORS / "trust-bad" / f"{neg}.cbor").read_bytes()
                gd, bd = cbor.decode(good), cbor.decode(bad)
                self.assert_pair(get(gd), get(bd), 64)
                # Equal but for the name, and the policy naming the witness.
                gd, bd = dict(gd), dict(bd)
                if pos == "name-at-the-cap":
                    del gd["name"], bd["name"]
                else:
                    self.assertEqual(bd["policy"], gd["policy"].replace(get(gd), get(bd)))
                    gd["witnesses"] = [dict(gd["witnesses"][0], name=""), *gd["witnesses"][1:]]
                    bd["witnesses"] = [dict(bd["witnesses"][0], name=""), *bd["witnesses"][1:]]
                    del gd["policy"], bd["policy"]
                self.assertEqual(gd, bd)
                trust.parse(good)
                with self.assertRaisesRegex(trust.TrustError, "1-64 bytes"):
                    trust.parse(bad)


class TheLabelValueCap(PairShape):
    def test_the_pair(self):
        net = bytes.fromhex(json.loads((VECTORS / "keys.json").read_text())["net"])

        def read(path):
            text = path.read_text().strip()
            return text, cbor.decode(bech32m.decode(text)[1])
        good, pos = read(VECTORS / "requests" / "req-label-at-the-cap.txt")
        bad, neg = read(VECTORS / "requests-bad" / "oversize-label.txt")
        self.assert_pair(pos["labels"]["owner"], neg["labels"]["owner"], 256)
        # Equal but for the label value and the signature over it.
        pos, neg = dict(pos), dict(neg)
        for m in (pos, neg):
            del m["labels"], m["sig"]
        self.assertEqual(pos, neg)
        enrollreq.check(enrollreq.decode_text(good), net)
        with self.assertRaisesRegex(enrollreq.RequestError, "longer than 256 bytes"):
            enrollreq.check(enrollreq.decode_text(bad), net)


if __name__ == "__main__":
    unittest.main()
