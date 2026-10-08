"""D-073: a device's grant is its `ip` label, parsed as a whole, masked, sorted."""
import unittest

from nornref import entry, fixture, replay


class Grants(unittest.TestCase):
    def setUp(self):
        raw = [item.raw for item in fixture.log()]
        self.state = replay.replay(replay.Anchor(fixture.NET, entry.leaf_hash(raw[0])), raw)

    def test_a_grant_is_masked_and_sorted(self):
        self.assertEqual(self.state.grant("router"), ["10.9.1.0/24", "fd00::/64"])

    def test_a_label_that_does_not_parse_as_a_whole_is_no_grant(self):
        self.assertEqual(self.state.grant("badgrant"), [])

    def test_no_label_is_no_grant(self):
        self.assertEqual(self.state.grant("nas"), [])
