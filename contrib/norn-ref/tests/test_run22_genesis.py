"""Run 22's genesis faults have honest quorums and field-only repairs."""
import copy
import json
import unittest
from pathlib import Path

from nornref import cbor, entry, fixture, replay

ROOT = Path(__file__).resolve().parents[3] / 'testdata/vectors'
CASES = ('28-signer-order-eight', '29-root-thr-zero', '30-signer-thr-zero',
         '31-params-flag-uint', '32-params-routes-open')
RULES = (
    {'section': '3.1', 'says': 'of a point of order exactly `L`'},
    {'section': '5.1', 'says': '`1 ≤ root_thr ≤ len(roots)`'},
    {'section': '5.1', 'says': '`1 ≤ signer_thr ≤ len(signers)`'},
    {'section': '4.5', 'says': 'whether `rotate` needs a signer countersignature'},
    {'section': '4.5', 'says': 'any text but `granted` or `advisory`'},
)


class RunTwentyTwoGenesis(unittest.TestCase):
    def test_the_genesis_bodies_are_their_only_faults(self):
        index = json.loads((ROOT / 'genesis/cases.json').read_text())
        for name, rule in zip(CASES, RULES):
            with self.subTest(case=name):
                self.assertEqual(index['cases'].count(name), 1)
                self.assertEqual(index['rules'][name], rule)
                folder = ROOT / 'genesis' / name
                manifest = json.loads((folder / 'manifest.json').read_text())
                self.assertEqual(manifest['entries'], [dict(index=0, name='00-genesis', reason='bad-genesis')])
                raw = (folder / '00-genesis.cbor').read_bytes()
                env = cbor.decode(raw)
                a = manifest['anchor']
                self.assertEqual(a, dict(net=fixture.NET.hex(), genesis_hash=entry.leaf_hash(raw).hex(),
                                         log_key=fixture.log_vkey(), policy=fixture.policy_text()))
                anchor = fixture.anchor_for([raw])
                self.assertEqual(len(env['sigs']), 3)
                for sig in env['sigs']:
                    self.assertEqual(sig['role'], 'root')
                    key = next(k for k in fixture.KEYS.values() if k.id == sig['kid'])
                    self.assertTrue(entry.verify_sig(env, sig, key.public))
                before = replay.replay(anchor, [raw])
                self.assertEqual(before.to_json() + '\n', (folder / 'state.json').read_text())
                self.assertEqual(before.size, 0)
                self.assertEqual(before.rejected, [dict(index=0, reason='bad-genesis')])
                zero = replay.replay(anchor, [])
                zero.rejected = before.rejected
                self.assertEqual(before.to_json(), zero.to_json())
                repaired = copy.deepcopy(env)
                body = repaired['body']
                base = fixture.genesis()['body']
                if name.startswith('28'):
                    self.assertEqual(body['signers'], base['signers'] + [fixture.ORDER_EIGHT])
                    body['signers'].pop()
                elif name.startswith(('29', '30')):
                    field = 'root_thr' if name.startswith('29') else 'signer_thr'
                    self.assertIs(type(body[field]), int)
                    self.assertEqual(body[field], 0)
                    body[field] = base[field]
                elif name.startswith('31'):
                    self.assertIs(type(body['params']['rotate_needs_signer']), int)
                    self.assertEqual(body['params']['rotate_needs_signer'], 1)
                    body['params']['rotate_needs_signer'] = False
                    base['params'] = {'rotate_needs_signer': False}
                else:
                    self.assertEqual(body['params']['routes'], 'open')
                    body['params']['routes'] = 'granted'
                    base['params'] = {'routes': 'granted'}
                self.assertEqual(body, base)
                repaired['sigs'] = []
                fixture._signed(repaired, [(r, 'root') for r in fixture.ROOTS])
                fixed = cbor.encode(repaired)
                fixed_anchor = fixture.anchor_for([fixed])
                good = replay.replay(fixed_anchor, [fixed])
                self.assertEqual((good.size, good.rejected), (1, []))
                if name.startswith('30'):
                    unsigned = cbor.decode((ROOT / 'log/1-enroll-nas.cbor').read_bytes())
                    unsigned['sigs'] = []
                    extra = cbor.encode(unsigned)
                    self.assertEqual(replay.replay(anchor, [raw, extra]).to_json(), before.to_json())
                    continued = replay.replay(fixed_anchor, [fixed, extra])
                    self.assertEqual(continued.rejected, [dict(index=1, reason='threshold')])
                    self.assertEqual(continued.size, 2)
                    self.assertEqual(continued.devices, {})

