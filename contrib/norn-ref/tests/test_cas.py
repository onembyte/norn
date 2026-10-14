"""D-077: an authorised transition binds its source, and signing roles stay disjoint."""
import copy
import unittest

from nornref import entry, fixture as f, note, replay as r, trust
from nornref.state import State


def setup(typ):
    st = State(f.NET, roots={f.KEYS['root1'].id:f.KEYS['root1'].public}, root_thr=1,
               signers={f.KEYS['signer1'].id:f.KEYS['signer1'].public}, signer_thr=1)
    st.versions = dict.fromkeys(('roots','signers','params','policy','log_key'), 3)
    st.add_device('nas', f.KEYS['nas'].public, f.WG['nas'], 3, None, None)
    st.devices['nas']['version'] = 3
    bodies = {
        'enroll':f._enroll_body('nas', wg='nas2'),
        'rotate':{'device_id':'nas','wg_pk':f.WG['nas2']},
        'revoke':{'device_id':'nas'},
        'signer_add':{'pk':f.KEYS['root2'].public},
        'root_add':{'pk':f.KEYS['root2'].public},
        'signer_remove':{'kid':f.KEYS['signer1'].id},
        'root_remove':{'kid':f.KEYS['root2'].id},
        'signer_thr':{'thr':1}, 'root_thr':{'thr':1},
        'params':{'mmd':23}, 'policy':{'text':'quorum none\n'},
        'log_key':{'pk':f.KEYS['root2'].public,'overlap':60}, 'note':{'text':'x'},
    }
    if typ == 'enroll': st.revoke_device('nas',3)
    if typ == 'root_remove': st.roots[f.KEYS['root2'].id] = f.KEYS['root2'].public
    env = entry.new(typ, f.NET, 10, bodies[typ])
    env['prev'] = 3
    sign(env)
    return st, env


def sign(env):
    env['sigs'] = []
    for name, role in [('root1','root'),('signer1','signer'),('nas','device')]:
        entry.sign(env,f.KEYS[name],role)


class CAS(unittest.TestCase):
    def test_each_handler_checks_presence_and_staleness_and_advances_only_on_accept(self):
        for typ in r.HANDLERS.keys() - {'note'}:
            for prev in (None, 0):
                with self.subTest(typ=typ, prev=prev):
                    st, env = setup(typ)
                    if prev is None: del env['prev']
                    else: env['prev'] = prev
                    sign(env)
                    before = st.to_json()
                    with self.assertRaises(r.Reject) as caught:
                        r.HANDLERS[typ](st,env,9)
                    self.assertEqual(caught.exception.code,'stale-state')
                    self.assertEqual(st.to_json(),before)
            with self.subTest(typ=typ, accepted=True):
                st, env = setup(typ)
                r.HANDLERS[typ](st,env,9)
                if typ in ('enroll','rotate','revoke'):
                    self.assertEqual(st.devices['nas']['version'],9)
                else:
                    obj = 'signers' if typ.startswith('signer_') else 'roots' if typ.startswith('root_') else typ
                    self.assertEqual(st.versions[obj],9)

    def test_enroll_presence_includes_revoked_records_and_note_has_no_prev(self):
        st,env = setup('enroll');del st.devices['nas']
        with self.assertRaises(r.Reject) as caught: r._h_enroll(st,env,9)
        self.assertEqual(caught.exception.code,'stale-state')
        del env['prev'];sign(env);r._h_enroll(st,env,9)
        st,env = setup('note')
        with self.assertRaises(r.Reject) as caught:r._h_note(st,env,9)
        self.assertEqual(caught.exception.code,'decode')

    def test_genesis_prev_aborts_with_matching_hash_and_signature(self):
        env = f.genesis();env['prev'] = 0;env['sigs'] = []
        f._signed(env,[('root1','root'),('root2','root')]);raw=entry.encode(env)
        st=r.replay(r.Anchor(f.NET,entry.leaf_hash(raw)),[raw])
        self.assertEqual(st.size,0)
        self.assertEqual(st.rejected,[{'index':0,'reason':'bad-genesis'}])

    def test_rotate_uses_one_signature_per_distinct_key(self):
        st,env=setup('rotate');env['body']['device_pk']=f.KEYS['nas'].public
        env['sigs']=[];entry.sign(env,f.KEYS['nas'],'device');r._h_rotate(st,env,9)
        self.assertEqual(st.devices['nas']['wg_pk'],f.WG['nas2'])

    def test_trust_disjointness_is_independent_of_names_ids_and_policy_log_line(self):
        doc=f.trust_file();key=note.vkey('alias',f.KEYS['logkey'].public,note.ALG_COSIGNATURE)
        doc['witnesses']=[{'name':'w','key':key}];doc['policy']=f'witness w {key}\nquorum w\n'
        with self.assertRaises(trust.TrustError):trust.validate(doc)
        key=f.witness_vkey('pi');doc['witnesses'][0]['key']=key;doc['policy']=f'witness w {key}\nquorum w\n'
        trust.validate(doc)

    def test_state_versions_are_always_canonical(self):
        st=State(f.NET)
        self.assertIn('"versions":{"log_key":0,"params":0,"policy":0,"roots":0,"signers":0}',st.to_json())
        st.add_device('nas',f.KEYS['nas'].public,f.WG['nas'],7,None,None)
        self.assertIn('"version":7',st.to_json())

    def test_log_witness_invariant_checks_both_anchor_and_learned_roles(self):
        pk=f.KEYS['root2'].public
        text='witness w '+note.vkey('different-name',pk,note.ALG_COSIGNATURE)+'\nquorum w\n'
        for learned in (False,True):
            st,env=setup('policy');env['body']['text']=text
            anchor=r.Anchor(f.NET,bytes(32),note.vkey('log',pk),'quorum none\n')
            if learned:
                anchor=r.Anchor(f.NET,bytes(32),f.log_vkey(),'quorum none\n')
                st.log_keys=[{'pk':pk,'overlap':60,'since_index':2}]
            with self.subTest(learned=learned,typ='policy'):
                with self.assertRaises(r.Reject) as caught:r._h_policy(st,env,9,anchor)
                self.assertEqual(caught.exception.code,'dup-key')
                env['body']['text']='quorum none\n';r._h_policy(st,env,9,anchor)
            st,env=setup('log_key')
            anchor=r.Anchor(f.NET,bytes(32),f.log_vkey(),text)
            if learned:st.policy=text;anchor=r.Anchor(f.NET,bytes(32),f.log_vkey(),'quorum none\n')
            with self.subTest(learned=learned,typ='log_key'):
                with self.assertRaises(r.Reject) as caught:r._h_log_key(st,env,9,anchor)
                self.assertEqual(caught.exception.code,'dup-key')
                env['body']['pk']=f.KEYS['root3'].public;r._h_log_key(st,env,9,anchor)

    def test_cas_manifest_and_every_negative_repair(self):
        from test_run14_vectors import check_edge_log
        with self.subTest(directory="log-edges"):
            check_edge_log(self)
        import json
        from pathlib import Path
        directory=Path(__file__).resolve().parents[3]/'testdata/vectors/log-cas'
        manifest=json.loads((directory/'manifest.json').read_text())
        raw=[(directory/(it['name']+'.cbor')).read_bytes() for it in manifest['entries']]
        anchor=r.Anchor(**{**manifest['anchor'],'net':bytes.fromhex(manifest['anchor']['net']),
                          'genesis_hash':bytes.fromhex(manifest['anchor']['genesis_hash'])})
        st=r.replay(anchor,raw)
        self.assertEqual(st.to_json()+'\n',(directory/'state.json').read_text())
        self.assertEqual({x['index']:x['reason'] for x in st.rejected},
                         {it['index']:it['reason'] for it in manifest['entries'] if it['reason']})
        self.assertEqual(st.devices['nas']['version'],32)
        for it in manifest['entries']:
            if not it['reason']:continue
            with self.subTest(name=it['name']):
                before=r.replay(anchor,raw[:it['index']])
                from nornref import cbor
                env=cbor.decode(raw[it['index']])
                prev=f.previous_for(before,env['t'],env['body'])
                env.pop('prev',None)
                if prev is not None:env['prev']=prev
                if it['reason']=='dup-key':
                    if env['t']=='log_key':env['body']['pk']=f.KEYS['stranger'].public
                    else:env['body']['text']='witness w '+note.vkey('repaired',f.KEYS['stranger'].public,note.ALG_COSIGNATURE)+'\nquorum w\n'
                if 'stale-before-dup-key' in it['name']:env['body']['pk']=f.KEYS['root4'].public
                # D-078 (3): the superseded key is still active (never retired), so
                # re-publishing it is dup-key too; the repair publishes a new key.
                if 'superseded-log-key' in it['name']:env['body']['pk']=f.KEYS['stranger'].public
                if 'stale-before-dup-wg' in it['name']:env['body']['wg_pk']=bytes([4])*32
                env['sigs']=[]
                signatures=[('root1','root'),('root2','root')]
                if env['t'] in ('enroll','revoke','note'):signatures=[('signer1','signer')]
                if env['t']=='rotate':
                    signatures=[('nas','device')]
                    if 'device_pk' in env['body']:signatures.append(('spare','device'))
                f._signed(env,signatures)
                after=r.replay(anchor,raw[:it['index']]+[entry.encode(env)])
                self.assertEqual(len(after.rejected),len(before.rejected))

    def test_precedence_cases_expose_both_faults_separately(self):
        from nornref import cbor
        items=f.cas_log();raw=[it.raw for it in items];anchor=f.anchor_for(raw)
        other={'25-threshold-before-stale':'threshold','28-current-signature-before-stale':'no-device-sig',
               '29-stale-before-incoming-proof':'no-device-sig','30-stale-before-dup-key':'dup-key','31-stale-before-dup-wg':'dup-wg'}
        def resign(env):
            sigs=env['sigs'];env['sigs']=[]
            for sig in sigs:
                key=next(key for key in f.KEYS.values() if key.id==sig['kid'])
                entry.sign(env,key,sig['role'])
        for i,it in enumerate(items):
            if it.name not in other:continue
            with self.subTest(name=it.name):
                before=r.replay(anchor,raw[:i]);env=cbor.decode(it.raw)
                env['prev']=f.previous_for(before,env['t'],env['body']);resign(env)
                after=r.replay(anchor,raw[:i]+[entry.encode(env)])
                self.assertEqual(after.rejected[-1],{'index':i,'reason':other[it.name]})
                env=cbor.decode(it.raw)
                if i==25:entry.sign(env,f.KEYS['root2'],'root')
                elif i==28:entry.sign(env,f.KEYS['nas'],'device')
                elif i==29:entry.sign(env,f.KEYS['spare'],'device')
                elif i==30:env['body']['pk']=f.KEYS['root4'].public;resign(env)
                elif i==31:env['body']['wg_pk']=bytes([4])*32;resign(env)
                after=r.replay(anchor,raw[:i]+[entry.encode(env)])
                self.assertEqual(after.rejected[-1],{'index':i,'reason':'stale-state'})

    def test_prev_is_optional_unsigned_and_part_of_the_signature(self):
        from nornref import cbor
        genesis=entry.encode(f.genesis())
        enrollment=entry.encode(f.enroll('nas',60,after=1))
        anchor=f.anchor_for([genesis,enrollment])
        for bad in (True,'1'):
            with self.subTest(prev=bad):
                env=entry.new('rotate',f.NET,f.T0+120,
                              {'device_id':'nas','wg_pk':f.WG['nas2']},prev=bad)
                entry.sign(env,f.KEYS['nas'],'device')
                state=r.replay(anchor,[genesis,enrollment,entry.encode(env)])
                self.assertEqual(state.rejected,[{'index':2,'reason':'decode'}])
        env=entry.new('rotate',f.NET,f.T0+120,{'device_id':'nas','wg_pk':f.WG['nas2']},prev=1)
        entry.sign(env,f.KEYS['nas'],'device')
        self.assertTrue(entry.verify_sig(env,env['sigs'][0],f.KEYS['nas'].public))
        self.assertEqual(r.replay(anchor,[genesis,enrollment,entry.encode(env)]).rejected,[])
        env['prev']=2
        self.assertFalse(entry.verify_sig(env,env['sigs'][0],f.KEYS['nas'].public))
        env=entry.new('enroll',f.NET,f.T0,f._enroll_body('nas'),prev=None)
        self.assertNotIn('prev',cbor.decode(entry.encode(env)))
