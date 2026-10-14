"""D-070 (SEC-001): duplicates are keyed on the signed content."""
import hashlib
import unittest

from nornref import cbor, entry, fixture, replay


def _log():
    items = fixture.log()
    raw = [i.raw for i in items]
    return raw, {i.name: n for n, i in enumerate(items)}


def _replay(raw):
    return replay.replay(replay.Anchor(fixture.NET, entry.leaf_hash(raw[0])), raw)


# Each variant differs from the fixture's own `bad-copy-*` entries, which are
# built the same way, or a byte-keyed replay would call these duplicates of
# those rather than of the originals.
def _with_extra_signature(raw):
    env = cbor.decode(raw)
    env["sigs"] = sorted(env["sigs"] + [{"kid": "fffffffffffffff0", "role": "signer", "sig": bytes(64)}],
                         key=lambda s: s["kid"])
    return entry.encode(env)


def _with_role_relabelled(raw):
    env = cbor.decode(raw)
    env["sigs"][-1]["role"] = "device"
    return entry.encode(env)


def _with_surplus_dropped(raw):
    env = cbor.decode(raw)
    env["sigs"] = env["sigs"][1:]
    return entry.encode(env)


class ReSignedCopiesAreDuplicates(unittest.TestCase):
    def test_every_copy_of_a_past_entry_is_dup_entry(self):
        raw, index = _log()
        before = _replay(raw)
        cases = [("37-enroll-spare", _with_extra_signature), ("37-enroll-spare", _with_role_relabelled),
                 ("28-policy", _with_extra_signature), ("35-rotate-nas", _with_extra_signature),
                 ("16-signer_add-signer3", _with_extra_signature), ("89-two-sig-base", _with_surplus_dropped)]
        for name, mutate in cases:
            with self.subTest(name=name, variant=mutate.__name__):
                copy = mutate(raw[index[name]])
                self.assertNotEqual(copy, raw[index[name]])
                after = _replay(raw + [copy])
                self.assertEqual(after.rejected[-1], {"index": len(raw), "reason": "dup-entry"})
                self.assertEqual(after.devices["spare"]["status"], before.devices["spare"]["status"])
                self.assertEqual(after.policy, before.policy)

    def test_a_different_content_is_not_a_duplicate(self):
        raw, index = _log()
        env = cbor.decode(raw[index["70-profile-base"]])
        env["ts"] += 1
        after = _replay(raw + [entry.encode(env)])
        self.assertNotEqual(after.rejected[-1]["reason"], "dup-entry")


def _signed(before, env):
    """Sign `env` with every fixture signer key that is a signer in `before`."""
    for name in ("signer1", "signer2", "signer3"):
        if fixture.KEYS[name].id in before.signers:
            entry.sign(env, fixture.KEYS[name], "signer")
    return env


class RefusedCopiesBurnNothing(unittest.TestCase):
    """D-078 (1): a refused entry records its bytes, never its signed content."""

    def test_a_stripped_copy_does_not_cancel_the_genuine_entry(self):
        # Run 15's H2: the copy is `threshold`; the genuine revoke applies.
        raw, _ = _log()
        before = _replay(raw)
        self.assertEqual(before.devices["printer"]["status"], "active")
        genuine = _signed(before, {"v": 1, "t": "revoke", "net": fixture.NET, "ts": 1790000000,
                                   "prev": before.devices["printer"]["version"],
                                   "body": {"device_id": "printer"}, "sigs": []})
        stripped = dict(genuine, sigs=[])
        after = _replay(raw + [entry.encode(stripped), entry.encode(genuine)])
        self.assertEqual(after.rejected[-1], {"index": len(raw), "reason": "threshold"})
        self.assertEqual(after.devices["printer"]["status"], "revoked")

    def test_an_entry_after_its_own_preimage_is_not_a_duplicate(self):
        # Run 15's H1: the preimage's entry hash is the note's content hash,
        # and the two kinds of key are never compared.
        raw, _ = _log()
        before = _replay(raw)
        note = _signed(before, {"v": 1, "t": "note", "net": fixture.NET, "ts": 1790000000,
                                "body": {"text": "after its own preimage"}, "sigs": []})
        pre = entry.preimage(note)
        self.assertEqual(entry.entry_hash(pre), hashlib.sha256(pre).digest())
        after = _replay(raw + [pre, entry.encode(note)])
        self.assertEqual(after.rejected[-1], {"index": len(raw), "reason": "decode"})

    def test_a_re_signed_copy_of_the_genesis_is_dup_entry(self):
        # Entry 0 is applied, so its content counts: a copy under another
        # signature list is `dup-entry` at step 1, never `dup-genesis`.
        raw, _ = _log()
        after = _replay(raw + [_with_extra_signature(raw[0])])
        self.assertEqual(after.rejected[-1], {"index": len(raw), "reason": "dup-entry"})
