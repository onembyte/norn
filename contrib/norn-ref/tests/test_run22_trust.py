"""Trust's short labels, verifier names and URL strings have separate rules."""
import json
import unittest
from pathlib import Path

from nornref import cbor, fixture, note, trust

ROOT = Path(__file__).resolve().parents[3] / 'testdata/vectors'
RULES = {
    'log-url-no-scheme': {'section': '9.1', 'says': 'Norn does not parse URL syntax here'},
    'long-witness-key-name': {'section': '7', 'says': 'A key name is one or more ASCII bytes'},
    'witness-names-differ-in-case': {'section': '9.1', 'says': 'Nothing here is case-folded'},
    '62-anchor-type-uint': {'section': '9.1', 'says': 'The two text members are not symmetric'},
}


class RunTwentyTwoTrust(unittest.TestCase):
    def test_the_trust_cases_repair_only_their_named_fields(self):
        base_raw = (ROOT / 'trust.cbor').read_bytes()
        base = cbor.decode(base_raw)
        for name, rule in RULES.items():
            with self.subTest(case=name):
                folder = ROOT / ('trust-bad' if name.startswith('62') else 'trust-good')
                m = json.loads((folder / 'cases.json').read_text())
                self.assertEqual(m['cases'].count(name), 1, 'missing trust case ' + name)
                self.assertEqual(m['rules'][name], rule)
                raw = (folder / (name + '.cbor')).read_bytes()
                doc = cbor.decode(raw)
                if name.startswith('62'):
                    self.assertIs(type(doc['anchor']['type']), int)
                    self.assertEqual(doc['anchor']['type'], 7)
                    with self.assertRaises(trust.TrustError):
                        trust.parse(raw)
                    doc['anchor']['type'] = base['anchor']['type']
                else:
                    self.assertTrue(m['says'][name])
                    trust.parse(raw)
                    if name == 'log-url-no-scheme':
                        self.assertEqual(doc['log_urls'], ['log.norn.example/testnet'])
                        doc['log_urls'] = base['log_urls']
                    elif name == 'long-witness-key-name':
                        witness = doc['witnesses'][0]
                        key = note.parse_vkey(witness['key'])
                        self.assertEqual(key.name, 'norn-witness/' + 'p' * 60)
                        self.assertEqual(len(key.name.encode()), 73)
                        self.assertEqual(witness['name'], 'pi')
                        self.assertEqual(key.public, fixture.KEYS['witness-pi'].public)
                        self.assertIn('witness pi ' + witness['key'] + ' ', doc['policy'])
                        doc['policy'] = doc['policy'].replace(witness['key'], base['witnesses'][0]['key'])
                        witness['key'] = base['witnesses'][0]['key']
                    else:
                        self.assertEqual([w['name'] for w in doc['witnesses']], ['pi', 'PI', 'friend'])
                        self.assertIn('witness PI ' + base['witnesses'][1]['key'] + ' ', doc['policy'])
                        self.assertIn('group home 2 pi PI friend\n', doc['policy'])
                        doc['witnesses'][1]['name'] = 'vps'
                        doc['policy'] = doc['policy'].replace(' PI', ' vps')
                self.assertEqual(trust.encode(doc), base_raw, 'repair must recover trust.cbor exactly')
                trust.parse(trust.encode(doc))
