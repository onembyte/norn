#!/usr/bin/env python3
"""Run the sealed suite. Expected data never enters the protocol verifier."""
from pathlib import Path
import hashlib, json, sys, tomllib, traceback
import cbor, ed25519 as ed, merkle, bech32m, protocol as p
from verify import Verifier, Files, tile_path, groups

ROOT=Path(__file__).resolve().parents[2]/'vectors'

class Harness:
    def __init__(self):
        self.total=0; self.failures=0; self.manifests=set()
    def display(self,v):
        if isinstance(v,bytes): return 'sha256:'+hashlib.sha256(v).hexdigest()
        s=json.dumps(p.jsonable(v),ensure_ascii=False,separators=(',',':'))
        return s if len(s)<=300 else 'sha256:'+hashlib.sha256(s.encode()).hexdigest()
    def check(self,path,expected,fn):
        self.total+=1
        try:
            got=fn(); passed=got==expected
        except Exception as ex:
            got=f'ERROR {type(ex).__name__}: {ex}'; passed=False
        if not passed: self.failures+=1
        print(f'{path} expected={self.display(expected)} got={self.display(got)} '+('PASS' if passed else 'FAIL'),flush=True)
    def outcome(self,fn):
        try: fn(); return 'accept'
        except p.Refusal as ex: return ex.code
    def accept(self,fn):
        try: fn(); return True
        except ValueError: return False
    def manifest(self,path):
        path=Path(path); self.manifests.add(path.resolve())
        return json.loads(path.read_text())
    def log(self,path):
        d=self.manifest(path/'manifest.json'); anchor=d['anchor'].copy()
        for k in ('net','genesis_hash'): anchor[k]=bytes.fromhex(anchor[k])
        entries=[(path/(e['name']+'.cbor')).read_bytes() for e in d['entries']]
        state=p.replay(anchor,entries); reasons={e['index']:e['reason'] for e in state['rejected']}
        for i,e in enumerate(d['entries']):
            label=(path/(e['name']+'.cbor')).relative_to(ROOT)
            self.check(label,e['reason'] or 'accept',lambda e=e: reasons.get(e['index'],'accept'))
            self.check(str(label)+'#index',i,lambda e=e:e['index'])
            if 'codes' in d and e['name'] in d['codes']:
                self.check(str(label)+'#manifest-code',d['codes'][e['name']],lambda e=e:reasons.get(e['index'],'accept'))
            reason_path=path/(e['name']+'.reason')
            if reason_path.is_file():
                self.check(reason_path.relative_to(ROOT),e['reason']+'\n',lambda f=reason_path:f.read_text())
        state_path=ROOT/'state.json' if path==ROOT/'log' else path/'state.json'
        self.check(state_path.relative_to(ROOT),state_path.read_bytes(),lambda:p.canonical_json(state))
        return state,entries

def request_layer(s):
    try: hrp,data=bech32m.decode(s,max_length=None)
    except ValueError: return 'text'
    if hrp!='norn': return 'hrp'
    try: raw=bytes(bech32m.convert(data,5,8,False))
    except ValueError: return 'padding'
    try: cbor.decode(raw)
    except ValueError: return 'profile'
    try: p.request(raw,verify=False)
    except ValueError: return 'schema'
    try: p.request(raw)
    except ValueError: return 'signature'
    return 'accept'

# Explicit mapping of semantic hints to independently defined validation layers.
REQUEST_LAYERS={
    **dict.fromkeys(('small-order-device-pk','unknown-key','missing-sig','wrong-version','short-net',
                    'uppercase-device-id','leading-dash-device-id','long-device-id','short-device-pk',
                    'short-wg-pk','short-sig','bool-expires','expires-at-ts','empty-labels',
                    'too-many-labels','oversize-label','non-string-label','ts-is-text'),'schema'),
    **dict.fromkeys(('empty-label-key','unsorted-keys','oversize-label-key'),'profile'),
    **dict.fromkeys(('torsion-R-signature','S-plus-L-signature','forged-signature'),'signature'),
    **dict.fromkeys(('plain-bech32','mixed-case','corrupt-character'),'text'),
    **dict.fromkeys(('excess-padding','non-zero-padding'),'padding'), 'wrong-hrp':'hrp'}
HOSTILE={
    **dict.fromkeys(('bare-null','bare-simple','bare-undefined'),'simple'),
    'bare-float':'float','bare-negative-integer':'major type','bare-tag':'major type',
    'bare-indefinite-text':'indefinite','bare-nontext-map-key':'key type','bare-invalid-utf8':'utf8',
    **dict.fromkeys(('oversize-entry','past-the-size-limit'),'length'),
    **dict.fromkeys(('deep-nesting','past-the-depth-limit'),'depth'), 'past-the-key-limit':'key length'}

def cbor_result(raw):
    try: cbor.decode(raw); return 'accept'
    except cbor.DecodeError as ex: return str(ex)

def run(h):
    # Primitive standards tests are run before even opening a vector artifact.
    for module in (ed,bech32m,merkle):
        h.check('selftest/'+module.__name__,'pass',lambda m=module:(m.selftest(),'pass')[1])
    if h.failures: return

    # SHA256SUMS is an integrity assertion for every shipped file, including
    # auxiliary prose and opaque OpenTimestamps containers.
    checksum_paths=set()
    for line in (ROOT/'SHA256SUMS').read_text().splitlines():
        digest,name=line.split(None,1); name=name.lstrip('*'); file=ROOT/name
        checksum_paths.add(file.resolve())
        h.check(name+'#SHA256SUMS',digest,lambda f=file:hashlib.sha256(f.read_bytes()).hexdigest())
    actual={f.resolve() for f in ROOT.rglob('*') if f.is_file() and f.name!='SHA256SUMS'}
    h.check('SHA256SUMS#complete',[],lambda:sorted(str(f.relative_to(ROOT)) for f in actual-checksum_paths))
    h.check('SHA256SUMS#no-extra',[],lambda:sorted(str(f) for f in checksum_paths-actual))

    raw_trust=(ROOT/'trust.cbor').read_bytes(); anchor=p.trust(raw_trust)
    fresh=Verifier(anchor)
    h.check('trust.cbor','accept',lambda:h.outcome(lambda:p.trust(raw_trust)))
    alphabet='0123456789ABCDEFGHJKMNPQRSTVWXYZ'
    n=int.from_bytes(hashlib.sha256(raw_trust).digest()[:10],'big')
    fp=''.join(alphabet[(n>>(5*(15-i)))&31] for i in range(16))
    fp='-'.join(fp[i:i+4] for i in range(0,16,4))+'\n'
    h.check('trust.fingerprint',(ROOT/'trust.fingerprint').read_text(),lambda:fp)
    toml=tomllib.loads((ROOT/'trust.toml').read_text())
    toml['witnesses']=toml.pop('witness')
    for k in ('net','genesis_hash'): toml[k]=bytes.fromhex(toml[k])
    h.check('trust.toml#CBOR',raw_trust,lambda:cbor.encode(toml))

    state,entries=h.log(ROOT/'log')
    informed=Verifier(anchor,state)
    for path in sorted(ROOT.rglob('manifest.json')):
        if path.resolve() not in h.manifests: h.log(path.parent)
    for dirname in ('genesis','genesis-good'):
        d=h.manifest(ROOT/dirname/'cases.json')
        actual_cases={q.parent.name for q in (ROOT/dirname).glob('*/manifest.json')}
        h.check(dirname+'/cases.json#complete',sorted(d['cases']),lambda:sorted(actual_cases))

    cp,served_state,served_entries=fresh.served(Files(ROOT/'served'))
    h.check('served/checkpoint','accept',lambda:h.outcome(lambda:fresh.served(Files(ROOT/'served'))))
    h.check('served#replay',p.canonical_json(state),lambda:p.canonical_json(served_state))
    h.check('served#entries',entries,lambda:served_entries)

    keys=json.loads((ROOT/'keys.json').read_text())
    publics={v['kid']:bytes.fromhex(v['public']) for v in keys['ed25519'].values()}
    for name,row in keys['ed25519'].items():
        pk=bytes.fromhex(row['public'])
        h.check('keys.json/'+name+'/kid',row['kid'],lambda pk=pk:p.kid(pk))
        h.check('keys.json/'+name+'/point',True,lambda pk=pk:ed.valid_point(pk))
    h.check('keys.json/net',keys['net'],lambda:anchor['net'].hex())
    for f in sorted((ROOT/'entries').glob('*.cbor')):
        raw=f.read_bytes(); e=p.envelope(raw,anchor['net']); mirror=json.loads(f.with_suffix('.json').read_text())
        got=dict(entry=p.jsonable(e),entry_hash=hashlib.sha256(raw).hexdigest(),leaf_hash=merkle.leaf(raw).hex(),
                 preimage_sha256=hashlib.sha256(p.preimage(e)).hexdigest(),size=len(raw))
        h.check(f.with_suffix('.json').relative_to(ROOT),mirror,lambda got=got:got)
        h.check(str(f.relative_to(ROOT))+'#canonical',raw,lambda e=e:cbor.encode(e))
        h.check(str(f.relative_to(ROOT))+'#signatures',True,
                lambda e=e:all(ed.verify(publics[s['kid']],p.preimage(e),s['sig']) for s in e['sigs']))

    for dirname,accept in (('trust-bad',False),('trust-good',True)):
        d=h.manifest(ROOT/dirname/'cases.json')
        for name in d['cases']:
            f=ROOT/dirname/(name+'.cbor')
            h.check(f.relative_to(ROOT),accept,lambda f=f:h.accept(lambda:p.trust(f.read_bytes())))
    d=h.manifest(ROOT/'entries-hostile/cases.json')
    for case in d['cases']:
        f=ROOT/'entries-hostile'/(case['name']+'.cbor')
        expected='accept' if case.get('accepted') else HOSTILE[case['name']]
        h.check(f.relative_to(ROOT),expected,lambda f=f:cbor_result(f.read_bytes()))
    d=h.manifest(ROOT/'policies/cases.json')
    for case in d['cases']:
        f=ROOT/'policies'/(case['name']+'.txt')
        h.check(f.relative_to(ROOT),case['accept'],lambda f=f:h.accept(lambda:p.Policy(f.read_bytes().decode('utf-8'))))
        if case['accept']:
            policy=p.Policy(f.read_bytes().decode('utf-8'))
            for i,row in enumerate(case.get('evaluate',[])):
                h.check(str(f.relative_to(ROOT))+f'#evaluate-{i}',row['satisfied'],
                        lambda row=row,policy=policy:policy.satisfied(set(row['cosigners'])))

    d=h.manifest(ROOT/'requests/cases.json')
    for case in d['cases']:
        f=ROOT/'requests'/(case['name']+'.txt'); text=f.read_text().removesuffix('\n')
        r,raw=p.request_text(text); expected=(f.with_suffix('.cbor')).read_bytes()
        h.check(f.relative_to(ROOT),'accept',lambda text=text:request_layer(text))
        h.check(str(f.relative_to(ROOT))+'#bytes',expected,lambda raw=raw:raw)
        mirror=json.loads(f.with_suffix('.json').read_text())
        got=dict(request=p.jsonable(r),preimage_sha256=hashlib.sha256(b'norn/enroll-request/v1\n'+cbor.encode({k:v for k,v in r.items() if k!='sig'})).hexdigest(),size=len(raw),text=text)
        h.check(f.with_suffix('.json').relative_to(ROOT),mirror,lambda got=got:got)
        if case['form'] not in ('canonical','uppercase'): raise ValueError('Unknown request form')
        canonical=bech32m.encode('norn',bech32m.convert(raw,8,5,True))
        h.check(str(f.relative_to(ROOT))+'#form',text,lambda canonical=canonical,case=case:canonical.upper() if case['form']=='uppercase' else canonical)
        if 'same_request_as' in case:
            h.check(str(f.relative_to(ROOT))+'#same-request',expected,
                    lambda case=case:(ROOT/'requests'/(case['same_request_as']+'.cbor')).read_bytes())
    d=h.manifest(ROOT/'requests-bad/cases.json')
    for case in d['cases']:
        f=ROOT/'requests-bad'/(case['name']+'.txt')
        h.check(f.relative_to(ROOT),REQUEST_LAYERS[case['name']],lambda f=f:request_layer(f.read_text().removesuffix('\n')))

    receipt=fresh.receipt((ROOT/'receipt.note').read_bytes(),anchor['genesis_hash'])
    mirror=json.loads((ROOT/'receipt.json').read_text()); mirror.pop('comment')
    h.check('receipt.note#parsed',mirror,lambda:p.jsonable(receipt))
    d=h.manifest(ROOT/'receipt-bad/cases.json')
    for case in d['cases']:
        f=ROOT/'receipt-bad'/case['name']
        h.check(f.relative_to(ROOT),d['codes'][case['name']],
                lambda f=f,case=case:h.outcome(lambda:fresh.receipt(f.read_bytes(),anchor['genesis_hash'],case.get('now_unix',0))))
    d=h.manifest(ROOT/'checkpoints-bad/cases.json')
    for name in d['cases']:
        f=ROOT/'checkpoints-bad'/(name+'.checkpoint')
        h.check(f.relative_to(ROOT),d['codes'][name],
                lambda f=f:h.outcome(lambda:fresh.served(Files(ROOT/'served',{'checkpoint':f}))))

    d=h.manifest(ROOT/'proofs/cases.json')
    for device in d['devices']:
        f=ROOT/'proofs'/(device+'.bundle')
        h.check(f.relative_to(ROOT),'accept',lambda f=f:h.outcome(lambda:fresh.bundle(f.read_bytes())))
        h.check(str(f.relative_to(ROOT))+'#installed-key',d['installs'][device],lambda device=device:served_state['devices'][device]['wg_pk'].hex())
    h.check('proofs#origin',d['origin'],lambda:cp['origin'])
    h.check('proofs#size',d['size'],lambda:cp['size'])
    h.check('proofs#quorum-time',d['checkpoint_quorum_time'],lambda:cp['time'])
    h.check('proofs#next-policy-quorum-time',d['replayed_policy_quorum_time'],
            lambda:informed.checkpoint((ROOT/'served/checkpoint').read_bytes())['time'])
    f=ROOT/'proofs'/d['at_the_cap']['file']
    h.check(f.relative_to(ROOT),'accept',lambda:h.outcome(lambda:fresh.bundle(f.read_bytes())))
    h.check(str(f.relative_to(ROOT))+'#length',d['at_the_cap']['bytes'],lambda:len(f.read_bytes()))
    f=ROOT/'proofs'/d['right_edge_inclusion']['file']; edge=json.loads(f.read_text())
    leaf=merkle.leaf(p.b64(edge['entry_b64']))
    h.check(str(f.relative_to(ROOT))+'#leaf',edge['leaf_hash'],lambda:leaf.hex())
    h.check(f.relative_to(ROOT),True,lambda:merkle.inclusion(leaf,edge['index'],edge['size'],list(map(bytes.fromhex,edge['proof'])),bytes.fromhex(edge['root'])))
    d=h.manifest(ROOT/'proofs-bad/cases.json')
    for case in d['cases']:
        f=ROOT/'proofs-bad'/(case['name']+'.bundle')
        h.check(f.relative_to(ROOT),d['codes'][case['name']],lambda f=f:h.outcome(lambda:fresh.bundle(f.read_bytes())))
    for dirname,method,field in (('proofs-rotated','bundle','bundle'),('receipt-rotated','receipt','receipt')):
        d=h.manifest(ROOT/dirname/'cases.json'); f=ROOT/dirname/d[field]
        for reader,v in (('fresh',fresh),('informed',informed)):
            h.check(dirname+'/'+d[field]+'#'+reader,d[reader],lambda v=v,method=method,f=f:h.outcome(lambda:getattr(v,method)(f.read_bytes())))

    # Shapes come from manifests (§12), never from served-* directory names.
    for f in sorted(ROOT.glob('served-*/cases.json')):
        d=h.manifest(f); folder=f.parent; label=folder.name
        if 'serve_over' in d:
            base=ROOT/d['serve_over']
        else:
            base=folder
        if 'cases' in d and any('serve' in c for c in d['cases']):
            for c in d['cases']:
                h.check(label+'/'+c['name'],d['codes'][c['name']],
                        lambda c=c:h.outcome(lambda:fresh.served(Files(folder/c['serve']))))
        elif 'cases' in d and any('path' in c or 'files' in c for c in d['cases']):
            for c in d['cases']:
                replacements={}; removed=[]
                if 'files' in c:
                    replacements={item['path']:folder/item['file'] for item in c['files']}
                elif c.get('remove'): removed=[c['path']]
                else: replacements={c['path']:folder/c['file']}
                h.check(label+'/'+c['name'],d['codes'][c['name']],
                        lambda replacements=replacements,removed=removed,base=base:h.outcome(lambda:fresh.served(Files(base,replacements,removed))))
        else:
            if 'cases' in d and not ('fresh' in d and 'informed' in d) and 'replay_codes' not in d:
                raise ValueError(f'Unknown served case shape: {label}')
            overrides={'checkpoint':folder/'checkpoint'} if 'serve_over' in d else {}
            if 'fresh' in d and 'informed' in d:
                for reader,v in (('fresh',fresh),('informed',informed)):
                    h.check(label+'#'+reader,d[reader],lambda v=v,base=base,overrides=overrides:h.outcome(lambda:v.served(Files(base,overrides))))
                if 'informed_reads_served' in d:
                    h.check(label+'#informed_reads_served',d['informed_reads_served'],lambda:h.outcome(lambda:informed.served(Files(ROOT/'served'))))
                if 'cases' in d:
                    h.check(label+'#reader-cases',['fresh','informed'],lambda d=d:[c['name'] for c in d['cases']])
                    for c in d['cases']:
                        h.check(label+'/'+c['name']+'#code',d['codes'][c['name']],lambda d=d,c=c:d[c['name']])
            else:
                h.check(label,'accept',lambda base=base,overrides=overrides:h.outcome(lambda:fresh.served(Files(base,overrides))))
            if 'size' in d or 'quorum_time' in d or 'replay_codes' in d or 'tiles' in d:
                head,st,es=fresh.served(Files(base,overrides))
                if 'size' in d: h.check(label+'#size',d['size'],lambda:head['size'])
                if 'quorum_time' in d: h.check(label+'#quorum-time',d['quorum_time'],lambda:head['time'])
                if 'replay_codes' in d:
                    h.check(label+'#replay-codes',d['replay_codes'],lambda:{str(r['index']):r['reason'] for r in st['rejected']})
                    h.check(label+'/state.json',(folder/'state.json').read_bytes(),lambda:p.canonical_json(st))
                    for c in d['cases']:
                        h.check(label+'/'+c['name'],d['codes'][c['name']],lambda base=base,overrides=overrides:h.outcome(lambda:fresh.served(Files(base,overrides))))
                if 'tiles' in d:
                    rows=[]; n=head['size']; level=0
                    while n:
                        rows += [dict(path=tile_path(level,i,w),width=w) for i,w in groups(n)]
                        n//=256; level+=1
                    h.check(label+'#implied-tiles',d['tiles'],lambda:rows)
            if 'paths' in d:
                for i,row in enumerate(d['paths']):
                    h.check(label+f'#path-{i}',row['path'],lambda row=row:tile_path('entries' if row['kind']=='entries' else row['level'],row['index'],row['width']))

    d=h.manifest(ROOT/'detect/cases.json')
    for c in d['cases']:
        stored=fresh.checkpoint((ROOT/'detect'/c['stored']).read_bytes())
        held=None if c.get('held')=='none' else served_entries
        expected=d['codes'].get(c['name'],'accept')
        h.check('detect/'+c['name'],expected,lambda c=c,stored=stored,held=held:h.outcome(lambda:fresh.served(Files(ROOT/'detect'/c['serve']),stored,held)))
    d=json.loads((ROOT/'detect/staleness.json').read_text())
    for c in d['cases']:
        elapsed=(max(q+c['now']-m for q,m in c['observed'])-c['held']) if 'observed' in c else c['elapsed']
        h.check('detect/staleness.json/'+c['name']+'#age',c['elapsed'],lambda elapsed=elapsed:elapsed)
        h.check('detect/staleness.json/'+c['name'],c['expect'],
                lambda c=c,elapsed=elapsed:p.freshness(elapsed if c.get('have_clock',True) else None,d['staleness'],c.get('hard',d['hard'])))
    d=h.manifest(ROOT/'fork/cases.json')
    for name in d['sound']:
        f=ROOT/'fork'/(name+'.cbor'); h.check(f.relative_to(ROOT),'accept',lambda f=f:h.outcome(lambda:fresh.evidence(f.read_bytes())))
    for c in d['cases']:
        f=ROOT/'fork'/(c['name']+'.cbor'); h.check(f.relative_to(ROOT),d['codes'][c['name']],lambda f=f:h.outcome(lambda:fresh.evidence(f.read_bytes())))
    h.check('fork/conflicting.checkpoint','accept',lambda:h.outcome(lambda:fresh.checkpoint((ROOT/'fork/conflicting.checkpoint').read_bytes())))

    d=h.manifest(ROOT/'ed25519-cctv/cases.json')
    upstream={row['number']:row for row in json.loads((ROOT/'ed25519-cctv/ed25519vectors.json').read_text())}
    for c in d['cases']:
        row=upstream[c['number']]
        h.check('ed25519-cctv/'+str(c['number']),c['outcome'],
                lambda row=row:'accept' if ed.verify(bytes.fromhex(row['key']),row['msg'].encode(),bytes.fromhex(row['sig'])) else 'reject')
    h.check('ed25519-cctv#complete',sorted(upstream),lambda:sorted(c['number'] for c in d['cases']))

    d=h.manifest(ROOT/'proven/cases.json')
    for c in d['cases']:
        h.check('proven/'+c['name'],c['proven'],lambda c=c:sorted(p.proven(state,c['t'] or None)))
    for id_,expected in d['grants'].items():
        h.check('proven/grants/'+id_,expected,lambda id_=id_:p.grant(state['devices'][id_]['labels'].get('ip')))
    for id_,row in d['bundles'].items():
        b,head=fresh.bundle((ROOT/row['file']).read_bytes()); e=p.envelope(b['entry']); r=p.request(e['body']['request'])
        got=dict(bundle_wg_pk=r['wg_pk'].hex(),state_wg_pk=state['devices'][id_]['wg_pk'].hex(),proves_index=b['index'],rotated_since=r['wg_pk']!=state['devices'][id_]['wg_pk'])
        h.check('proven/bundles/'+id_,{k:row[k] for k in got},lambda got=got:got)
    d=json.loads((ROOT/'proven/grant-labels.json').read_text())
    for i,c in enumerate(d['cases']): h.check('proven/grant-labels.json/'+str(i),c['grant'],lambda c=c:p.grant(c['label']))

    d=h.manifest(ROOT/'anchors/cases.json')
    for c in d['cases']:
        if 'over' in c:
            raw=(ROOT/c['over']).read_bytes(); leading=raw.split(b'\n\n',1)[0]+b'\n\n'
            h.check('anchors/'+c['name']+'#stamped-digest',c['digest'],lambda:hashlib.sha256(leading).hexdigest())
        else:
            # §12 explicitly permits checking this digest without an OTS parser.
            # Match the declared SHA-256 digest in the external opaque artifact.
            h.check('anchors/'+c['name']+'#declared-digest',True,
                    lambda c=c:bytes.fromhex(c['digest']) in (ROOT/'anchors'/c['name']).read_bytes())

    all_manifests={f.resolve() for name in ('cases.json','manifest.json') for f in ROOT.rglob(name)}
    for f in sorted(all_manifests-h.manifests):
        h.check(str(f.relative_to(ROOT))+'#unhandled','handled',lambda:'UNKNOWN CASE FORMAT')

if __name__=='__main__':
    harness=Harness()
    try: run(harness)
    except Exception as ex:
        harness.check('harness#unhandled-exception','none',lambda:f'{type(ex).__name__}: {ex}')
        traceback.print_exc()
    print(f'TOTAL {harness.total} PASS {harness.total-harness.failures} FAIL {harness.failures}')
    sys.exit(1 if harness.failures else 0)
