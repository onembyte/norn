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
    self.assertEqual(len(raw), 15)
    self.assertEqual(manifest['entries'][14], {'index': 14, 'name': '14-enroll-c1-label', 'reason': ''})
    self.assertEqual({it['name']: it['reason'] for it in manifest['entries'] if it['reason']}, {
        name: 'decode' for name in ('01-enroll-device-id-newline', '07-rotate-unknown-open-body',
                                   '08-revoke-unknown-open-body', '10-enroll-request-identity',
                                   '11-policy-witness-note-key', '13-policy-log-cosignature-key')})
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
            elif it['name'] == '13-policy-log-cosignature-key':
                text = env['body']['text']
                old = next(line.split()[1] for line in text.splitlines() if line.startswith('log '))
                key = note.parse_vkey(old)
                self.assertEqual(key.alg, note.ALG_COSIGNATURE)
                with self.assertRaises(policy.PolicyError):
                    policy.parse(text)
                env['body']['text'] = text.replace(old, note.vkey(key.name, key.public), 1)
                policy.parse(env['body']['text'])
                before = replay.replay(anchor, raw[:i])
                self.assertEqual(env['prev'], before.versions['policy'])
                self.assertGreaterEqual(len(replay._valid_kids(cbor.decode(raw[i]), 'root', before.roots)), before.root_thr)
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
        self.assertGreaterEqual(len(doc['cases']), 49)
        self.assertTrue({'::ffff:a00:1/128', '0:0:0:0:0:ffff:a00:1/128', '10.0.0.0/8,  fd00::/64', '  10.0.0.0/8  ', '::1.2.3.4/128', '1:2:3:4:5:6:7::/128', '9.0.0.0/8, 1::/16', '1:2:3:4:5:6:7::8/128', '9.0.0.0/8, 10.0.0.0/8', '2001:db8:0:1:1:1:1:1/128',
                         '2001:db8:0:0:1:1:1:1/128', '1:0:0:2:3:0:0:4/128',
                         '10.0.0.1/8, 10.0.0.2/8'} <= {c['label'] for c in doc['cases']})
        expected = {'::ffff:a00:1/128': [], '0:0:0:0:0:ffff:a00:1/128': [], '10.0.0.0/8,  fd00::/64': ['10.0.0.0/8', 'fd00::/64'],
                    '  10.0.0.0/8  ': ['10.0.0.0/8'],
                    '::1.2.3.4/128': ['::102:304/128'],
                    '1:2:3:4:5:6:7::/128': ['1:2:3:4:5:6:7:0/128'],
                    '9.0.0.0/8, 1::/16': ['1::/16', '9.0.0.0/8'],
                    '1:2:3:4:5:6:7::8/128': [],
                    '1:0:0:2:3:0:0:4/128': ['1::2:3:0:0:4/128'],
                    '10.0.0.1/8, 10.0.0.2/8': ['10.0.0.0/8']}
        for case in doc['cases']:
            if case['label'] in expected:
                self.assertEqual(case['grant'], expected[case['label']])
        section = (ROOT.parents[1] / 'SPEC.md').read_text().split('### 4.0', 1)[1].split('### 4.1', 1)[0]
        for case in doc['cases']:
            with self.subTest(label=case['label']):
                self.assertEqual(grant_from_label(case['label']), case['grant'])
                if case['label'] in ('::ffff:a00:1/128', '0:0:0:0:0:ffff:a00:1/128'):
                    self.assertEqual(grant_from_label('::fffe:a00:1/128'), ['::fffe:a00:1/128'])
                repairs = {'10.0.0.0/8,  fd00::/64': '10.0.0.0/8,fd00::/64',
                           '  10.0.0.0/8  ': '10.0.0.0/8',
                           '::1.2.3.4/128': '::102:304/128'}
                if case['label'] in repairs:
                    self.assertEqual(grant_from_label(repairs[case['label']]), case['grant'])
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

    def test_go_owned_run_fourteen_vectors_use_shared_note_and_replay_rules(self):
        # The reference has no served-log, bundle or evidence verifier. Walk
        # the new artifacts through the shared layers it does implement.
        def read(path):
            return (ROOT / path).read_bytes()
        def verify_log(head, keys):
            # Witness cosignatures are checked by Go; project these heads
            # onto the log signatures this reference can verify.
            text, separator, block = head.partition('\n\n')
            lines = [line for line in block.splitlines()
                     if not line.startswith('— norn-witness/')]
            return note.verify(text+separator+'\n'.join(lines)+'\n', keys)
        anchor = f.trust_file()
        learned = note.vkey(anchor['origin'], f.KEYS['logkey2'].public)
        for directory, answer in [('served-rotated-wrong-name',False), ('served-rotated-earlier',True)]:
            with self.subTest(directory=directory):
                manifest = json.loads(read(directory + '/cases.json'))
                head = read(directory + '/checkpoint').decode()
                self.assertEqual(manifest['fresh'], 'log-signature')
                with self.assertRaises(note.NoteError): verify_log(head,[anchor['log_key']])
                if answer:
                    self.assertEqual(verify_log(head,[anchor['log_key'],learned]).splitlines()[1],'20')
                else:
                    with self.assertRaises(note.NoteError): verify_log(head,[anchor['log_key'],learned])
        with self.subTest(directory='served-empty-entry'):
            directory = ROOT / 'served-empty-entry'
            manifest = json.loads((directory / 'cases.json').read_bytes())
            raw = (directory / 'tile/entries/000.p/4').read_bytes()
            entries = []
            while raw:
                width = int.from_bytes(raw[:2],'big')
                self.assertGreaterEqual(len(raw),2+width)
                entries.append(raw[2:2+width]); raw=raw[2+width:]
            self.assertEqual(entries[2],b'')
            _, replay_anchor, _ = load_log(ROOT / 'log')
            state = replay.replay(replay_anchor,entries)
            self.assertEqual(state.rejected,[{'index':2,'reason':'decode'}])
            self.assertEqual(state.to_json()+'\n',(directory/'state.json').read_text())
            verify_log((directory/'checkpoint').read_bytes().decode(),[anchor['log_key']])
        for name in ['34-four-lines-and-wrong-origin','35-wrong-origin-and-forged-pi','36-no-quorum-and-size-163','37-crlf']:
            with self.subTest(checkpoint=name):
                head=read('checkpoints-bad/'+name+'.checkpoint').decode()
                if name=='37-crlf':
                    with self.assertRaises(note.NoteError): note.split(head)
                else:
                    verify_log(head,[anchor['log_key']])
        with self.subTest(bundle='wrong-version-and-untrusted-checkpoint'):
            bundle=cbor.decode(read('proofs-bad/wrong-version-and-untrusted-checkpoint.bundle'))
            self.assertEqual(bundle['v'],2)
            with self.assertRaises(note.NoteError): verify_log(bundle['checkpoint'],[anchor['log_key']])
        for name in ['bad-policy-unparseable-and-unknown-key','bad-unverifiable-conflicting-and-size-mismatch','bad-size-zero-empty-held']:
            with self.subTest(evidence=name):
                ev=cbor.decode(read('fork/'+name+'.cbor'))
                if 'unknown-key' in name:
                    self.assertIn('surprise',ev)
                    with self.assertRaises(policy.PolicyError): policy.parse(ev['policy'])
                elif 'mismatch' in name:
                    with self.assertRaises(note.NoteError): verify_log(ev['conflicting'],[anchor['log_key']])
                else:
                    heads=[verify_log(ev[field],[anchor['log_key']]).splitlines() for field in ['held','conflicting']]
                    self.assertEqual([head[1] for head in heads],['0','0'])
                    self.assertNotEqual(heads[0][2],heads[1][2])
        for name in ['other-genesis-missing-tile','other-genesis-tampered-tile']:
            with self.subTest(detect=name):
                verify_log(read('detect/'+name+'/checkpoint').decode(),[anchor['log_key']])
        with self.subTest(directory='served-large-bad'):
            manifest=json.loads(read('served-large-bad/cases.json'))
            for case in manifest['cases']:
                honest=read(manifest['serve_over']+'/'+case['path'])
                damaged=read('served-large-bad/'+case['file'])
                if case['name']=='level-one-byte-changed':
                    # Run 16, L8: one byte of the level-1 tile, nothing appended.
                    self.assertEqual(len(damaged),len(honest))
                    self.assertEqual(sum(a!=b for a,b in zip(honest,damaged)),1)
                else:
                    self.assertTrue(damaged.startswith(honest)); self.assertGreater(len(damaged),len(honest))
