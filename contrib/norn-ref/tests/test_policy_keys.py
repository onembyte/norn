"""Cold gate run 12, D10: a `policy` entry's witness keys are cosignature keys.

SPEC 9.1's grammar never parses a key; SPEC 5.1 refuses a `policy` entry
naming one no cosignature line could match. Read from the shipped log.
"""

import json
import pathlib
import unittest

from nornref import cbor, note, policy, replay

VECTORS = pathlib.Path(__file__).resolve().parents[3] / "testdata" / "vectors"


class PolicyWitnessKeys(unittest.TestCase):
    def test_a_note_key_on_a_witness_line_is_decode_and_only_that(self):
        man = json.loads((VECTORS / "log" / "manifest.json").read_text())
        anchor = replay.Anchor(bytes.fromhex(man["anchor"]["net"]),
                               bytes.fromhex(man["anchor"]["genesis_hash"]))
        raws = [(VECTORS / "log" / f"{e['name']}.cbor").read_bytes() for e in man["entries"]]
        (index,) = [e["index"] for e in man["entries"]
                    if e["name"].endswith("-bad-policy-witness-key-not-a-cosigner")]
        text = cbor.decode(raws[index])["body"]["text"]
        policy.parse(text)  # the grammar accepts it
        algs = [note.parse_vkey(k).alg for k in policy.witness_keys(text)]
        self.assertEqual(algs.count(note.ALG_ED25519), 1, "exactly one witness key is a note key")
        self.assertEqual(algs.count(note.ALG_COSIGNATURE), len(algs) - 1)
        state = replay.replay(anchor, raws)
        self.assertIn({"index": index, "reason": "decode"}, state.rejected)


if __name__ == "__main__":
    unittest.main()
