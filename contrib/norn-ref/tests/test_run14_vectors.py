"""Run 14's unambiguous boundary rules, read from the distributed suite."""
import json
from pathlib import Path
import unittest

from nornref import cbor, enrollreq, entry, fixture as f, note, policy, replay, trust

ROOT = Path(__file__).resolve().parents[3] / 'testdata/vectors'


def load_log(directory):
    manifest = json.loads((directory / 'manifest.json').read_text())
    anchor = replay.Anchor(**{k: bytes.fromhex(v) if k in ('net', 'genesis_hash') else v
                             for k, v in manifest['anchor'].items()})
    raw = [(directory / (it['name'] + '.cbor')).read_bytes() for it in manifest['entries']]
    return manifest, anchor, raw


def check_edge_log(self):
    directory = ROOT / 'log-edges'
    manifest, anchor, raw = load_log(directory)
    self.assertEqual(len(raw), 13)
    state = replay.replay(anchor, raw)
    self.assertEqual(state.to_json() + '\n', (directory / 'state.json').read_text())
    self.assertEqual(state.rejected, [{'index': it['index'], 'reason': it['reason']}
                                     for it in manifest['entries'] if it['reason']])
    self.assertEqual(state.devices['nas']['labels'], {})
    for it in manifest['entries']:
        if not it['reason']:
            continue
        with self.subTest(name=it['name']):
            i = it['index']
            env = cbor.decode(raw[i])
            if env['t'] == 'enroll':
                req = cbor.decode(env['body']['request'])
                if 'device-id-newline' in it['name']:
                    self.assertEqual(req['device_id'], 'nas2\n')
                    self.assertTrue(f.KEYS['spare'].public == req['device_pk'])
                    self.assertTrue(enrollreq.verify(req))
                    req['device_id'] = 'nas2'
                else:
                    self.assertEqual(req['device_pk'], b'\x01' + bytes(31))
                    self.assertFalse(enrollreq.verify(req))
                    req['device_pk'] = f.KEYS['spare'].public
                req['sig'] = f.KEYS['spare'].sign(enrollreq.preimage(req))
                env['body']['request'] = cbor.encode(req)
            elif env['t'] in ('rotate', 'revoke'):
                del env['body']['extra']
                env['sigs'] = []
                signers = [('spare', 'device')] if env['t'] == 'rotate' else [('signer1', 'signer')]
                f._signed(env, signers)
                outcome = replay.replay(anchor, raw[:i] + [entry.encode(env)])
                self.assertEqual(outcome.rejected[-1], {'index': i, 'reason': 'unknown-device'})
                env['body']['device_id'] = 'nas2'
            else:
                env['body']['text'] = 'witness w ' + note.vkey('edge-witness', f.KEYS['spare'].public, note.ALG_COSIGNATURE) + '\nquorum w\n'
            before = replay.replay(anchor, raw[:i])
            env.pop('prev', None)
            prev = f.previous_for(before, env['t'], env['body'])
            if prev is not None:
                env['prev'] = prev
            env['sigs'] = []
            signers = [('signer1', 'signer')]
            if env['t'] == 'rotate': signers = [('spare', 'device')]
            if env['t'] == 'policy': signers = [('root1', 'root'), ('root2', 'root')]
            f._signed(env, signers)
            after = replay.replay(anchor, raw[:i] + [entry.encode(env)])
            self.assertEqual(after.rejected, before.rejected)


class RunFourteen(unittest.TestCase):
    def test_edge_log_matches_manifest_state_and_each_negative_repairs(self):
        check_edge_log(self)

    def test_grant_label_table_is_a_pure_function(self):
        doc = json.loads((ROOT / 'proven/grant-labels.json').read_text())
        from nornref.state import grant_from_label
        self.assertTrue(doc['comment'])
        self.assertGreaterEqual(len(doc['cases']), 36)
        section = (ROOT.parents[1] / 'SPEC.md').read_text().split('### 4.0', 1)[1].split('### 4.1', 1)[0]
        for case in doc['cases']:
            with self.subTest(label=case['label']):
                self.assertEqual(grant_from_label(case['label']), case['grant'])
            with self.subTest(rule=case['label']):
                self.assertTrue(case['says'])
                self.assertNotIn('\n', case['says'])
                self.assertIn(case['says'], section)

    def test_genesis_boundaries_accept_and_extra_body_key_repairs(self):
        _, anchor, raw = load_log(ROOT / 'genesis-good/02-name-one-byte')
        state = replay.replay(anchor, raw)
        self.assertEqual((state.size, state.rejected, len(state.name.encode())), (1, [], 1))
        _, anchor, raw = load_log(ROOT / 'genesis/26-body-unknown-key')
        self.assertEqual(replay.replay(anchor, raw).rejected, [{'index': 0, 'reason': 'bad-genesis'}])
        env = cbor.decode(raw[0]); del env['body']['extra']; env['sigs'] = []
        f._signed(env, [('root1', 'root'), ('root2', 'root')])
        repaired = entry.encode(env)
        self.assertEqual(replay.replay(f.anchor_for([repaired]), [repaired]).rejected, [])

    def test_trust_boundaries_and_algorithm_negatives_repair(self):
        for name, length, witness in [('name-at-the-cap',64,False), ('name-one-byte',1,False),
                                      ('witness-name-at-the-cap',64,True), ('witness-name-one-byte',1,True)]:
            with self.subTest(name=name):
                doc = trust.parse((ROOT / 'trust-good' / (name + '.cbor')).read_bytes())
                self.assertEqual(len((doc['witnesses'][0]['name'] if witness else doc['name']).encode()), length)
        for name in ('52-name-one-past-the-cap', '53-log-cosignature-without-policy-log'):
            raw = (ROOT / 'trust-bad' / (name + '.cbor')).read_bytes()
            with self.subTest(name=name):
                with self.assertRaises(trust.TrustError): trust.parse(raw)
                doc = cbor.decode(raw)
                if name.startswith('52'):
                    self.assertEqual(len(doc['name'].encode()),65)
                    doc['name'] = doc['name'][:64]
                else:
                    self.assertFalse(any(line.startswith('log ') for line in doc['policy'].splitlines()))
                    key = note.parse_vkey(doc['log_key'])
                    doc['log_key'] = note.vkey(key.name, key.public)
                trust.parse(cbor.encode(doc))

    def test_distinct_policy_witness_fails_only_its_algorithm(self):
        text = (ROOT / 'policies/bad-witness-vkey-algorithm-distinct.txt').read_text()
        with self.assertRaises(policy.PolicyError): policy.parse(text)
        fields = text.split()
        self.assertEqual(len(fields),5)
        key = note.parse_vkey(fields[2])
        repaired = text.replace(fields[2],note.vkey(key.name,key.public,note.ALG_COSIGNATURE))
        policy.parse(repaired)

    def test_receipt_signed_body_boundaries_and_repairs(self):
        # The reference exposes note verification, not a receipt checker.
        # Check §7's body predicates after verifying the log signature.
        doc = f.trust_file()
        key = [doc['log_key']]
        honest = note.verify((ROOT / 'receipt.note').read_text(), key)
        manifest = json.loads((ROOT / 'receipt-bad/cases.json').read_text())
        for name, code in [('fifth-line.note','receipt'),('origin-case-changed.note','origin')]:
            with self.subTest(name=name):
                text = note.verify((ROOT / 'receipt-bad' / name).read_text(), key)
                lines = text.splitlines()
                actual = 'receipt' if len(lines) != 4 else 'origin' if lines[1] != doc['origin'] else ''
                self.assertEqual(actual, code)
                self.assertEqual(manifest['codes'][name], code)
                if code == 'receipt':
                    self.assertEqual(len(lines),5); lines = lines[:4]
                else:
                    self.assertEqual(lines[1].lower(), doc['origin']); lines[1] = doc['origin']
                self.assertEqual('\n'.join(lines)+'\n', honest)
