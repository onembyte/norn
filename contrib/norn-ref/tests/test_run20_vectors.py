"""Run 20's distributed cases and repairs at the reference's supported layers."""
import base64
import copy
import json
from pathlib import Path
import unittest

from nornref import cbor, entry, enrollreq, fixture, keys, note, replay, trust

ROOT = Path(__file__).resolve().parents[3] / 'testdata/vectors'


def check_rule(test, anchor, raw, i):
    before = replay.replay(anchor, raw[:i])
    source = raw[i]
    above = bytes.fromhex('6274731b8000000000000000')
    cap = bytes.fromhex('6274731b7fffffffffffffff')
    if i == 40:
        test.assertEqual(source.count(above), 1)
        source = source.replace(above, cap, 1)
    env = cbor.decode(source)

    def sign(names=('signer1',), role='signer'):
        env['sigs'] = []
        fixture._signed(env, [(name, role) for name in names])
        return entry.encode(env)

    def check(value):
        result = replay.replay(anchor, raw[:i] + [value])
        test.assertNotIn(i, [r['index'] for r in result.rejected])

    if i in (37, 38):
        if i == 37:
            test.assertNotIn('prev', env)
        else:
            test.assertNotEqual(env['prev'], before.versions['params'])
        env['prev'] = before.versions['params']
        check(sign(('root1', 'root2'), 'root'))
    elif i == 39:
        test.assertEqual(env['prev'], before.versions['params'])
        test.assertEqual(replay.replay(anchor, raw[:i+1]).versions['params'], i)
    elif i == 40:
        message = entry.preimage(env).replace(cap, above, 1)
        test.assertTrue(keys.verify(fixture.KEYS['signer1'].public, message, env['sigs'][0]['sig']))
        repair = sign()
        test.assertEqual(repair, raw[41])
        check(repair)
    elif i == 41:
        test.assertEqual(env['ts'], 2**63-1)
    elif i == 42:
        test.assertIs(env['after'], True)
        env['after'] = 1
        repair = sign()
        test.assertEqual(repair, raw[43])
        check(repair)
    elif i == 43:
        test.assertIs(type(env['after']), int)
        test.assertEqual(env['after'], 1)
    elif i == 44:
        req = enrollreq.decode(env['body']['request'])
        test.assertTrue(enrollreq.verify(req))
        test.assertEqual((req['ts'], req['expires']), (100, 200))
        test.assertGreater(env['ts'], req['expires'])
        device = replay.replay(anchor, raw[:i+1]).devices[req['device_id']]
        test.assertEqual((device['status'], device['expires'], device['version']), ('active', 200, i))
        env['ts'] = 150
        check(sign())


def check_order(test, anchor, raw, i):
    before = replay.replay(anchor, raw[:i])
    original = cbor.decode(raw[i])
    test.assertNotEqual(original['prev'], before.versions['log_key'])

    def check(env, want):
        env['sigs'] = []
        fixture._signed(env, [('root1', 'root'), ('root2', 'root')])
        encoded = entry.encode(env)
        result = replay.replay(anchor, raw[:i] + [encoded])
        got = next((r['reason'] for r in result.rejected if r['index'] == i), '')
        test.assertEqual(got, want)
        return encoded

    if i == 42:
        test.assertEqual(original['body']['pk'], fixture.ORDER_EIGHT)
        env = copy.deepcopy(original)
        env['body']['pk'] = fixture.KEYS['logkey2'].public
        test.assertEqual(check(env, 'stale-state'), raw[43])
        env = copy.deepcopy(original)
        env['prev'] = before.versions['log_key']
        check(env, 'decode')
    original['body']['pk'] = fixture.KEYS['logkey2'].public
    original['prev'] = before.versions['log_key']
    check(original, '')


class RunTwenty(unittest.TestCase):
    def test_trust_readings_and_no_log_composites_repair_only_the_named_fault(self):
        standard = cbor.decode((ROOT / 'trust.cbor').read_bytes())
        for name in ('name-non-ascii', 'policy-without-log'):
            with self.subTest(name=name):
                manifest = json.loads((ROOT / 'trust-good/cases.json').read_text())
                self.assertIn(name, manifest['cases'])
                doc = trust.parse((ROOT / 'trust-good' / (name + '.cbor')).read_bytes())
                if name == 'name-non-ascii':
                    self.assertEqual(doc['name'], 'réseau-de-test')
                    doc['name'] = standard['name']
                else:
                    self.assertFalse(any(l.startswith('log ') for l in doc['policy'].splitlines()))
                    self.assertEqual(doc['policy'], ''.join(l for l in standard['policy'].splitlines(True) if not l.startswith('log ')))
                    doc['policy'] = standard['policy']
                self.assertEqual(doc, standard)
        names = ('60-witness-short-name-mismatch', '44-log-key-base64-cr',
                 '51-witness-key-is-log-key', '53-log-cosignature-without-policy-log', '55-log-key-small-order')
        for name in names:
            with self.subTest(name=name):
                doc = cbor.decode((ROOT / 'trust-bad' / (name + '.cbor')).read_bytes())
                with self.assertRaises(trust.TrustError):
                    trust.parse(cbor.encode(doc))
                if name.startswith('60'):
                    self.assertEqual(doc['witnesses'][0]['name'], 'pj')
                    doc['witnesses'][0]['name'] = 'pi'
                    self.assertEqual(doc, standard)
                else:
                    self.assertFalse(any(l.startswith('log ') for l in doc['policy'].splitlines()))
                    if name.startswith('51'):
                        old = doc['witnesses'][0]['key']
                        doc['witnesses'][0]['key'] = standard['witnesses'][0]['key']
                        doc['policy'] = doc['policy'].replace(old, doc['witnesses'][0]['key'])
                    elif name.startswith('44'):
                        self.assertEqual(doc['log_key'].count('\r'), 1)
                        doc['log_key'] = doc['log_key'].replace('\r', '')
                    else:
                        doc['log_key'] = standard['log_key']
                trust.parse(cbor.encode(doc))

    def test_receipt_leaf_boundary_has_a_genuine_note_and_a_length_only_repair(self):
        raw = (ROOT / 'receipt-bad/leaf-31-bytes.note').read_text()
        text = note.verify(raw, [fixture.log_vkey()])
        lines = text.splitlines()
        leaf = base64.b64decode(lines[2], validate=True)
        self.assertEqual(len(leaf), 31)
        self.assertEqual(base64.b64encode(leaf).decode(), lines[2])
        lines[2] = base64.b64encode(leaf + b'\0').decode()
        repair = note.sign('\n'.join(lines) + '\n', fixture.ORIGIN, fixture.KEYS['logkey'])
        self.assertEqual(note.verify(repair, [fixture.log_vkey()]), '\n'.join(lines) + '\n')
        self.assertEqual(len(base64.b64decode(lines[2])), 32)

    def test_empty_signed_text_has_a_framed_genuine_signature(self):
        raw = (ROOT / 'receipt-bad/empty-signed-text.note').read_text()
        self.assertTrue(raw.startswith('\n' + note.SIG_PREFIX))
        line = raw[1:]
        name, payload = line[len(note.SIG_PREFIX):].rstrip('\n').split(' ')
        data = base64.b64decode(payload, validate=True)
        self.assertEqual(name, fixture.ORIGIN)
        self.assertEqual(len(data), 68)
        self.assertTrue(keys.verify(fixture.KEYS['logkey'].public, b'', data[4:]))
        with self.assertRaises(note.NoteError):
            note.split(raw)
        # Replacing only the text and renewing its signature produces an
        # ordinary accepted receipt; there is no reference receipt checker.
        text = note.receipt_text(fixture.ORIGIN, fixture.trust_file()['genesis_hash'], fixture.T0 + 60)
        repair = note.sign(text, fixture.ORIGIN, fixture.KEYS['logkey'])
        self.assertEqual(note.verify(repair, [fixture.log_vkey()]), text)
