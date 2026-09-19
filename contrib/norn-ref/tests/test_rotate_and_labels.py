"""RED first: self-rotation (D8) and label field constraints (D7)."""
import unittest

from nornref import entry, fixture, keys, replay
from nornref.state import DEFAULT_PARAMS


def state_of(extra_envs):
    items = fixture.log()
    raw = [i.raw for i in items] + [entry.encode(e) for e in extra_envs]
    anchor = replay.Anchor(fixture.NET, entry.leaf_hash(raw[0]))
    return replay.replay(anchor, raw), len(items)


def rotate(index, device, wg_name, device_pk=None, signers=None):
    body = {"device_id": device, "wg_pk": fixture.WG[wg_name]}
    if device_pk is not None:
        body["device_pk"] = device_pk
    env = entry.new("rotate", fixture.NET, ts=fixture.T0 + 9000, after=index, body=body)
    for name, role in (signers or []):
        entry.sign(env, fixture.KEYS[name], role)
    return env


class SelfRotation(unittest.TestCase):
    """A device may rotate its identity key while keeping its WireGuard key.

    Otherwise moving a device from a software key to a hardware key would be
    impossible without also churning the WireGuard key and every peer's table.
    """

    def test_rotating_only_the_device_key_is_accepted(self):
        new_id = fixture.KEYS["printer-id2"]
        env = rotate(42, "printer", "printer", device_pk=new_id.public,
                     signers=[("printer", "device"), ("printer-id2", "device"),
                              ("signer1", "signer"), ("signer3", "signer")])
        state, n = state_of([env])
        self.assertEqual([r for r in state.rejected if r["index"] == n], [])
        self.assertEqual(state.devices["printer"]["device_pk"], new_id.public)
        self.assertEqual(state.devices["printer"]["wg_pk"], fixture.WG["printer"],
                         "the WireGuard key is unchanged")

    def test_the_superseded_device_key_can_no_longer_sign(self):
        """Fixture entry 40 rotated `nas`'s identity key; the old key is dead."""
        env = rotate(42, "nas", "nas2",
                     signers=[("nas", "device"), ("signer1", "signer"), ("signer3", "signer")])
        state, n = state_of([env])
        self.assertEqual(state.rejected[-1], {"index": n, "reason": "no-device-sig"})

    def test_the_new_device_key_signs_after_rotation(self):
        env = rotate(42, "nas", "nas2",
                     signers=[("nas-id2", "device"), ("signer1", "signer"), ("signer3", "signer")])
        state, n = state_of([env])
        self.assertEqual([r for r in state.rejected if r["index"] == n], [])

    def test_taking_another_active_device_key_is_dup_wg(self):
        env = rotate(42, "printer", "nas2",
                     signers=[("printer", "device"), ("signer1", "signer"), ("signer3", "signer")])
        state, n = state_of([env])
        self.assertEqual(state.rejected[-1], {"index": n, "reason": "dup-wg"})

    def test_since_index_is_untouched_by_rotation(self):
        """`nas` is enrolled at 1 and rotated at 35 and 40; since_index stays 1."""
        state, _ = state_of([])
        self.assertEqual(state.devices["nas"]["since_index"], 1)
        self.assertEqual(state.devices["nas"]["device_pk"], fixture.KEYS["nas-id2"].public)


class LabelConstraints(unittest.TestCase):
    """SPEC §4.0 constrains labels; replay must actually enforce it."""

    def _enroll(self, labels):
        """An enrolment whose request carries these labels (SPEC §4.3).

        The request is built field by field rather than through
        `enrollreq.new`, because the rejecting cases are exactly the ones a
        validating constructor refuses to build: they can only come from a
        hostile or broken device, and replay is what must catch them.
        """
        from nornref import cbor, enrollreq
        request = {"v": 1, "ts": fixture.T0 + 9000, "net": fixture.NET,
                   "device_id": "labelled", "device_pk": fixture.KEYS["spare"].public,
                   "wg_pk": fixture.WG["rogue"], "labels": labels}
        request["sig"] = fixture.KEYS["spare"].sign(enrollreq.preimage(request))
        env = entry.new("enroll", fixture.NET, ts=fixture.T0 + 9000, after=42,
                        body={"request": cbor.encode(request)})
        for name, role in (("signer1", "signer"), ("signer3", "signer")):
            entry.sign(env, fixture.KEYS[name], role)
        return env

    def test_within_limits_is_accepted(self):
        state, n = state_of([self._enroll({"ip": "10.9.0.9/32"})])
        self.assertEqual([r for r in state.rejected if r["index"] == n], [])
        self.assertEqual(state.devices["labelled"]["labels"], {"ip": "10.9.0.9/32"})

    def test_too_many_labels_is_a_decode_rejection(self):
        state, n = state_of([self._enroll({f"k{i}": "v" for i in range(33)})])
        self.assertEqual(state.rejected[-1], {"index": n, "reason": "decode"})

    def test_oversized_value_is_a_decode_rejection(self):
        state, n = state_of([self._enroll({"ip": "x" * 257})])
        self.assertEqual(state.rejected[-1], {"index": n, "reason": "decode"})

    def test_non_string_value_is_a_decode_rejection(self):
        state, n = state_of([self._enroll({"ip": 1})])
        self.assertEqual(state.rejected[-1], {"index": n, "reason": "decode"})

    def test_label_keys_cannot_exceed_the_cbor_map_key_cap(self):
        """The codec caps map keys at 23 bytes, so a 30-byte label key is
        unencodable — the old 1-64 field constraint was dead text (D7)."""
        from nornref import cbor
        with self.assertRaises(cbor.ProfileError):
            self._enroll({"k" * 24: "v"})


class ParamsDefaults(unittest.TestCase):
    def test_genesis_params_merge_over_defaults(self):
        state, _ = state_of([])
        for key, value in DEFAULT_PARAMS.items():
            self.assertIn(key, state.params, f"{key} must always be present")
        self.assertEqual(state.params["mmd"], 45,
                         "genesis overlays a non-default value onto the §4.5 defaults")


if __name__ == "__main__":
    unittest.main()
