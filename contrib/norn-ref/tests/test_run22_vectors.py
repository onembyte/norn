"""The distributed replay stories pin run 22's schema and name rules."""
import json
import unittest
from pathlib import Path

from nornref import cbor, entry, enrollreq, fixture, policy, replay

ROOT = Path(__file__).resolve().parents[3] / 'testdata/vectors'
NAME_RULE = {'section': '9.1', 'says': 'Nothing here is case-folded'}
STORIES = {
    'policy-names-differ-in-case': (['00-genesis', '01-policy-pi-PI'], NAME_RULE),
    'signer-add-prev-bool': (['00-genesis', '01-signer-add-prev-false', '02-signer-add-prev-zero'],
                             {'section': '5.1', 'says': '`ts`, `after` and `prev` uint'}),
    'enroll-empty-device-id': (['00-genesis', '01-enroll-empty-device-id', '02-enroll-sundial'],
                               {'section': '2', 'says': 'UTF-8 string, 1–64 bytes'}),
}


class RunTwentyTwoReplay(unittest.TestCase):
    def test_the_replay_stories_have_their_signed_repairs(self):
        for name, (names, rule) in STORIES.items():
            with self.subTest(case=name):
                folder = ROOT / 'log-run22' / name
                self.assertTrue((folder / 'manifest.json').is_file(), 'missing replay story ' + name)
                m = json.loads((folder / 'manifest.json').read_text())
                self.assertEqual([e['name'] for e in m['entries']], names)
                raw = [(folder / (n + '.cbor')).read_bytes() for n in names]
                a = m['anchor']
                anchor = fixture.anchor_for(raw)
                self.assertEqual(a, dict(net=anchor.net.hex(), genesis_hash=anchor.genesis_hash.hex(),
                                         log_key=anchor.log_key, policy=anchor.policy))
                self.assertEqual(raw[0], entry.encode(fixture.genesis()))
                self.assertEqual(m['rules']['00-genesis'], {'section': '5.1', 'says': 'Otherwise the state is initialised from the body'})
                for i, row in enumerate(m['entries']):
                    self.assertEqual(row['index'], i)
                    reason = 'decode' if i == 1 and len(raw) == 3 else ''
                    self.assertEqual(row['reason'], reason)
                    if i:
                        self.assertEqual(m['codes'][names[i]], reason or 'accept')
                        self.assertEqual(m['rules'][names[i]], rule)
                    if reason:
                        self.assertEqual((folder / (names[i] + '.reason')).read_text(), reason + '\n')
                self.assertEqual(set(m['codes']), set(names[1:]))
                self.assertEqual(set(m['rules']), set(names))
                final = replay.replay(anchor, raw)
                self.assertEqual(final.to_json() + '\n', (folder / 'state.json').read_text())
                self.assertEqual(final.size, len(raw))
                self.assertEqual(final.rejected, [] if len(raw) == 2 else [dict(index=1, reason='decode')])
                env = cbor.decode(raw[1])
                role = 'signer' if name == 'enroll-empty-device-id' else 'root'
                holders = fixture.SIGNERS if role == 'signer' else fixture.ROOTS
                self.assertEqual({s['kid'] for s in env['sigs']}, {fixture.KEYS[n].id for n in holders})
                for sig in env['sigs']:
                    self.assertEqual(sig['role'], role)
                    key = next(k for k in fixture.KEYS.values() if k.id == sig['kid'])
                    self.assertTrue(entry.verify_sig(env, sig, key.public))
                if len(raw) == 2:
                    text = (ROOT / 'policies/names-differ-in-case.txt').read_text()
                    self.assertEqual(env['body']['text'], text)
                    self.assertEqual(env['prev'], 0)
                    self.assertEqual((final.policy, final.versions['policy']), (text, 1))
                    env['body']['text'] = text.replace('PI', 'upper')
                    env['sigs'] = []
                    fixture._signed(env, [(n, 'root') for n in fixture.ROOTS])
                    repaired = replay.replay(anchor, [raw[0], cbor.encode(env)])
                    self.assertEqual(repaired.rejected, [])
                    self.assertEqual(repaired.policy, env['body']['text'])
                    continue
                before = replay.replay(anchor, raw[:1])
                refused = replay.replay(anchor, raw[:2])
                refused.size, refused.rejected = before.size, before.rejected
                self.assertEqual(refused.to_json(), before.to_json())
                if name == 'signer-add-prev-bool':
                    self.assertIs(env['prev'], False)
                    self.assertEqual(env['body'], {'pk': fixture.KEYS['signer3'].public})
                    env['prev'] = 0
                    self.assertEqual(len(final.signers), 3)
                    self.assertEqual(final.versions['signers'], 2)
                else:
                    req = cbor.decode(env['body']['request'])
                    self.assertEqual(req['device_id'], '')
                    self.assertTrue(enrollreq.verify(req))
                    req['device_id'] = 'sundial'
                    enrollreq.sign(req, fixture.KEYS['sundial'])
                    env['body']['request'] = cbor.encode(req)
                    self.assertEqual(final.devices['sundial']['status'], 'active')
                    self.assertEqual(final.devices['sundial']['version'], 2)
                env['sigs'] = []
                fixture._signed(env, [(n, role) for n in holders])
                fixed = cbor.encode(env)
                self.assertEqual(fixed, raw[2], 'only the named field and renewed signatures change')
                for prefix in (raw[:1], raw[:2]):
                    result = replay.replay(anchor, prefix + [fixed])
                    self.assertNotIn(len(prefix), [r['index'] for r in result.rejected])

    def test_policy_case_distinctions_have_four_evaluation_rows(self):
        m = json.loads((ROOT / 'policies/cases.json').read_text())
        cases = [c for c in m['cases'] if c['name'] == 'names-differ-in-case']
        self.assertEqual(len(cases), 1, 'missing case-distinct policy')
        case = cases[0]
        self.assertTrue(case['accept'])
        self.assertEqual(m['rules'][case['name']], NAME_RULE)
        text = (ROOT / 'policies/names-differ-in-case.txt').read_text()
        policy.parse(text)
        expected = ('witness pi ' + fixture.witness_vkey('pi') + '\n'
                    'witness PI ' + fixture.witness_vkey('vps') + '\n'
                    'group home 2 pi PI\nquorum home\n')
        self.assertEqual(text, expected)
        self.assertEqual([(e['cosigners'], e['satisfied']) for e in case['evaluate']],
                         [([], False), (['pi'], False), (['PI'], False), (['pi', 'PI'], True)])
        self.assertTrue(all(e['why'] for e in case['evaluate']))
        policy.parse(text.replace('PI', 'upper'))

