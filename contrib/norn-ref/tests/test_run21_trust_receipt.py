"""Run 21's trust association and authenticated receipt-width guards."""
import base64
import json
from pathlib import Path
import unittest
from nornref import cbor, fixture, note, trust

ROOT = Path(__file__).resolve().parents[3] / 'testdata/vectors'


class RunTwentyOneTrustReceipt(unittest.TestCase):
    def test_swapped_directive_names_preserve_both_sets_but_not_the_association(self):
        name = '61-witness-names-swapped'
        m = json.loads((ROOT / 'trust-bad/cases.json').read_text())
        self.assertEqual(m['cases'].count(name), 1)
        self.assertEqual(m['rules'][name], {'section': '9.1', 'says': 'The `witness` directive is matched on **its own `<name>`**'})
        raw = (ROOT / 'trust-bad' / (name + '.cbor')).read_bytes()
        doc = cbor.decode(raw)
        standard = trust.parse((ROOT / 'trust.cbor').read_bytes())
        witnesses = {w['name']: w['key'] for w in doc['witnesses']}
        lines = [l.split() for l in doc['policy'].splitlines() if l.startswith('witness ')]
        named = {p[1]: p[2] for p in lines}
        self.assertEqual(set(witnesses), set(named))
        self.assertEqual(set(witnesses.values()), set(named.values()))
        self.assertEqual(len(witnesses), 3)
        self.assertEqual(named['pi'], witnesses['vps'])
        self.assertEqual(named['vps'], witnesses['pi'])
        self.assertEqual(named['friend'], witnesses['friend'])
        with self.assertRaises(trust.TrustError):
            trust.parse(raw)
        doc['policy'] = doc['policy'].replace('witness vps ', 'witness TEMP ', 1).replace('witness pi ', 'witness vps ', 1).replace('witness TEMP ', 'witness pi ', 1)
        self.assertEqual(doc, standard)
        self.assertEqual(cbor.encode(doc), (ROOT / 'trust.cbor').read_bytes())
        trust.parse(cbor.encode(doc))
        prior = cbor.decode((ROOT / 'trust-bad/42-witness-key-mismatch.cbor').read_bytes())
        self.assertEqual(prior['witnesses'][0]['name'], standard['witnesses'][0]['name'])
        self.assertNotEqual(prior['witnesses'][0]['key'], standard['witnesses'][0]['key'])
        prior['witnesses'][0]['key'] = standard['witnesses'][0]['key']
        self.assertEqual(cbor.encode(prior), (ROOT / 'trust.cbor').read_bytes())
        trust.parse(cbor.encode(prior))

    def test_an_overlong_leaf_has_a_real_signature_and_a_suffix_only_repair(self):
        name = 'leaf-33-bytes.note'
        m = json.loads((ROOT / 'receipt-bad/cases.json').read_text())
        self.assertEqual([c['name'] for c in m['cases']].count(name), 1)
        self.assertEqual(m['codes'][name], 'leaf-hash')
        self.assertEqual(m['rules'][name], {'section': '7', 'says': 'The leaf hash MUST be standard base64 and decode to exactly 32 bytes'})
        raw = (ROOT / 'receipt-bad' / name).read_text()
        text = note.verify(raw, [fixture.log_vkey()])
        lines = text.splitlines()
        leaf = base64.b64decode(lines[2], validate=True)
        self.assertEqual(len(leaf), 33)
        self.assertEqual(base64.b64encode(leaf).decode(), lines[2])
        good = (ROOT / 'receipt.note').read_text()
        good_text = note.verify(good, [fixture.log_vkey()])
        self.assertEqual(leaf, base64.b64decode(good_text.splitlines()[2]) + b'\0')
        lines[2] = base64.b64encode(leaf[:-1]).decode()
        repair = note.sign('\n'.join(lines) + '\n', fixture.ORIGIN, fixture.KEYS['logkey'])
        self.assertEqual(repair, good)
        # The reference verifies note signatures; receipt semantics are Go's.
        self.assertEqual(note.verify(repair, [fixture.log_vkey()]), good_text)
        self.assertEqual(len(base64.b64decode(note.verify((ROOT / 'receipt-bad/leaf-31-bytes.note').read_text(), [fixture.log_vkey()]).splitlines()[2])), 31)
