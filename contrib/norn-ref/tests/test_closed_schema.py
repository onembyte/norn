"""RED first: bodies are closed schemas, and `thr: 0` is `bad-thr`.

Run 3 built a variant that left entry *bodies* open to unknown keys and scored a
clean pass -- while this implementation also left them open. Two implementations
agreeing by accident is not the same as a pinned rule, and the next one may
close them. So: decide, state, enforce, vector.
"""
import unittest

from nornref import cbor, entry, fixture, replay

ROOTS3 = [("root1", "root"), ("root2", "root"), ("root3", "root")]
SIGNERS2 = [("signer1", "signer"), ("signer3", "signer")]


def state_with(extra):
    items = fixture.log()
    raw = [i.raw for i in items] + list(extra)
    return replay.replay(replay.Anchor(fixture.NET, entry.leaf_hash(raw[0])), raw), len(items)


def signed(kind, body, signers, after):
    env = entry.new(kind, fixture.NET, ts=fixture.T0 + 9000, after=after, body=body)
    for name, role in signers:
        entry.sign(env, fixture.KEYS[name], role)
    return entry.encode(env)


class BodiesAreClosed(unittest.TestCase):
    def test_unknown_key_in_a_note_body(self):
        raw = signed("note", {"text": "hi", "surprise": "extra"},
                     [("signer1", "signer")], after=59)
        state, n = state_with([raw])
        self.assertEqual(state.rejected[-1], {"index": n, "reason": "decode"})

    def test_unknown_key_in_an_enroll_body(self):
        raw = signed("enroll", {"device_id": "extra", "device_pk": fixture.KEYS["spare"].public,
                                "wg_pk": fixture.WG["rogue"], "bonus": 1},
                     [("spare", "device")] + SIGNERS2, after=59)
        state, n = state_with([raw])
        self.assertEqual(state.rejected[-1], {"index": n, "reason": "decode"})

    def test_unknown_key_in_a_governance_body(self):
        raw = signed("signer_thr", {"thr": 2, "note": "why"}, ROOTS3, after=59)
        state, n = state_with([raw])
        self.assertEqual(state.rejected[-1], {"index": n, "reason": "decode"})

    def test_known_keys_still_accepted(self):
        raw = signed("note", {"text": "plain"}, [("signer1", "signer")], after=59)
        state, n = state_with([raw])
        self.assertEqual([r for r in state.rejected if r["index"] == n], [])


class UnknownEnvelopeKey(unittest.TestCase):
    def test_unknown_envelope_key_is_decode(self):
        env = entry.new("note", fixture.NET, ts=fixture.T0, after=59, body={"text": "x"})
        entry.sign(env, fixture.KEYS["signer1"], "signer")
        env["extra"] = 1
        state, n = state_with([cbor.encode(env)])
        self.assertEqual(state.rejected[-1], {"index": n, "reason": "decode"})


class ZeroThreshold(unittest.TestCase):
    """`thr: 0` is `bad-thr` -- a replay decision, not a decode violation."""

    def test_signer_thr_zero(self):
        state, n = state_with([signed("signer_thr", {"thr": 0}, ROOTS3, after=59)])
        self.assertEqual(state.rejected[-1], {"index": n, "reason": "bad-thr"})

    def test_root_thr_zero(self):
        state, n = state_with([signed("root_thr", {"thr": 0}, ROOTS3, after=59)])
        self.assertEqual(state.rejected[-1], {"index": n, "reason": "bad-thr"})
