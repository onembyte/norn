"""Run 21's schema fields are checked on their signed replay inputs."""
import unittest
import json
from pathlib import Path
from nornref import cbor, entry, enrollreq, fixture, replay

ROOT = Path(__file__).resolve().parents[3] / "testdata/vectors/log-rules"


class RunTwentyOneReplay(unittest.TestCase):
    def test_an_envelope_version_boolean_is_decode(self):
        genesis = entry.encode(fixture.genesis())
        anchor = fixture.anchor_for([genesis])
        env = entry.new('note', fixture.NET, ts=0, body={'text': 'v is true'})
        env['v'] = True
        fixture._signed(env, [('signer1', 'signer')])
        self.assertTrue(entry.verify_sig(env, env['sigs'][0], fixture.KEYS['signer1'].public))
        result = replay.replay(anchor, [genesis, cbor.encode(env)])
        self.assertEqual(result.rejected, [{'index': 1, 'reason': 'decode'}])
        env['v'] = 1
        env['sigs'] = []
        fixture._signed(env, [('signer1', 'signer')])
        self.assertEqual(replay.replay(anchor, [genesis, cbor.encode(env)]).rejected, [])

    def test_the_six_replay_fields_have_their_signed_pairs(self):
        m = json.loads((ROOT / 'manifest.json').read_text())
        self.assertEqual(len(m['entries']), 57)
        a = m['anchor']
        anchor = replay.Anchor(bytes.fromhex(a['net']), bytes.fromhex(a['genesis_hash']), a['log_key'], a['policy'])
        raw = [(ROOT / (e['name'] + '.cbor')).read_bytes() for e in m['entries']]
        for i in range(45, 57, 2):
            with self.subTest(case=m['entries'][i]['name']):
                check_rule(self, anchor, raw, i)


def check_rule(test, anchor, raw, i):
    if i % 2 == 0:
        return
    env = cbor.decode(raw[i])
    test.assertEqual(len(env['sigs']), 1)
    test.assertTrue(entry.verify_sig(env, env['sigs'][0], fixture.KEYS['signer1'].public))
    before = replay.replay(anchor, raw[:i])
    after = replay.replay(anchor, raw[:i+1])
    test.assertEqual(after.rejected[-1], {'index': i, 'reason': 'decode'})
    after.size, after.rejected = before.size, before.rejected
    test.assertEqual(after.to_json(), before.to_json())
    if i in (45, 47):
        field, hostile, repair = ('ts', False, 0) if i == 45 else ('v', True, 1)
        test.assertIs(env[field], hostile)
        env[field] = repair
    elif i in (49, 51, 53):
        req = cbor.decode(env['body']['request'])
        test.assertTrue(enrollreq.verify(req))
        test.assertNotIn(req['device_id'], before.devices)
        test.assertNotIn(req['wg_pk'], before.active_wg)
        field = 'v' if i == 49 else 'ts'
        if i == 53:
            test.assertNotIn(field, req)
        else:
            test.assertIs(req[field], i == 49)
        req[field] = 1 if i == 49 else 0
        enrollreq.sign(req, fixture.KEYS['sundial'])
        env['body']['request'] = cbor.encode(req)
    else:
        test.assertEqual(env['body'], {})
        env['body']['text'] = ''
    env['sigs'] = []
    fixture._signed(env, [('signer1', 'signer')])
    repaired = cbor.encode(env)
    test.assertEqual(repaired, raw[i+1], 'only the named field and renewed signatures may change')
    for prefix in (raw[:i], raw[:i+1]):
        result = replay.replay(anchor, prefix + [repaired])
        test.assertNotIn(len(prefix), [r['index'] for r in result.rejected])
        if i in (49, 51, 53):
            test.assertEqual(result.devices[req['device_id']]['status'], 'active')
            test.assertEqual(result.devices[req['device_id']]['version'], len(prefix))
