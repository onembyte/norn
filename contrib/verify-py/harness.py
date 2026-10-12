#!/usr/bin/env python3
"""Execute every declared sealed vector; unknown declarations/files fail closed."""
from pathlib import Path
import hashlib
import json
import sys
import traceback
import cbor
import ed25519
import merkle
import bech32m
import verifier as v

ROOT=Path(__file__).resolve().parents[2]/'vectors'
# All paths originate inside the vector root, never from the ambient filesystem.
def path(name):
    p=(ROOT/name).resolve()
    if not p.is_relative_to(ROOT.resolve()): raise ValueError('vector path escapes sealed suite')
    return p
used=set()
semantic_used=set()
tracking=False
def read(name):
    p=path(name); n=p.relative_to(ROOT).as_posix(); used.add(n)
    if tracking: semantic_used.add(n)
    return p.read_bytes()
def jread(name): return json.loads(read(name))
def label(x):
    if type(x) is bytes:
        return 'bytes:'+str(len(x))+':sha256:'+hashlib.sha256(x).hexdigest()
    result=json.dumps(v.jsonable(x),ensure_ascii=False,separators=(',',':'))
    if len(result)>240:
        return 'value-sha256:'+hashlib.sha256(result.encode()).hexdigest()
    return result
checks=failures=0

def check(name,expected,fn):
    global checks,failures
    checks+=1
    try: got=fn()
    except Exception as e: got='ERROR:'+type(e).__name__+':'+str(e)
    passed=got==expected
    if not passed: failures+=1
    print(f'{name} expected={label(expected)} got={label(got)} {"PASS" if passed else "FAIL"}',flush=True)
    return passed

def outcome(fn):
    try: fn(); return 'accept'
    except v.Refusal as e: return e.code

def boolean(fn):
    try: fn(); return True
    except (ValueError,TypeError): return False

def getter(directory,overrides=None):
    overrides=overrides or {}
    def get(p):
        if p in overrides: return overrides[p]
        n=str(Path(directory)/p)
        if not path(n).is_file(): return None
        return read(n)
    return get

known_manifests=set()
def cases(directory):
    n=directory+'/cases.json'; known_manifests.add(n); return jread(n)

replayed={}
def replay_manifest(n):
    known_manifests.add(n); m=jread(n); directory=str(Path(n).parent)
    anchor={k:bytes.fromhex(x) if k in ('net','genesis_hash') else x for k,x in m['anchor'].items()}
    entries=[read(directory+'/'+e['name']+'.cbor') for e in m['entries']]
    s=v.replay(anchor,entries); replayed[directory]=(s,entries)
    reasons={e['index']:e['reason'] for e in s['rejected']}
    for pos,e in enumerate(m['entries']):
        check(directory+'/'+e['name']+'.cbor',e['reason'] or 'accept',lambda e=e:reasons.get(e['index'],'') or 'accept')
        check(directory+'/'+e['name']+'#index',pos,lambda e=e:e['index'])
        nreason=directory+'/'+e['name']+'.reason'
        if path(nreason).is_file(): check(nreason,e['reason']+'\n',lambda nreason=nreason:read(nreason).decode())
    for name,code in m.get('codes',{}).items():
        e=next((e for e in m['entries'] if e['name']==name),None)
        check(directory+'/'+name+'#code',code,lambda e=e:reasons.get(e['index'],'') if e else 'UNKNOWN CASE')
    state_file='state.json' if directory=='log' else directory+'/state.json'
    # Compare every byte; display a compact result instead of whole states.
    wanted=read(state_file); actual=v.canonical(s)
    check(state_file,'byte-identical',lambda:'byte-identical' if actual==wanted else 'different sha256='+hashlib.sha256(actual).hexdigest())
    if not m['entries']: check(directory+'#empty-replay',[],lambda:s['rejected'])
    return s,entries

def main():
    global tracking
    # Must run before any protocol-vector parsing.
    for mod in (ed25519,merkle,bech32m):
        check('selftest/'+mod.__name__,'PASS',lambda mod=mod:(mod.selftest(),'PASS')[1])
    if failures: return 1

    # Integrity is checked before using the suite. SHA256SUMS names support files too.
    sums={}
    for line in read('SHA256SUMS').decode().splitlines():
        digest,n=line.split(None,1); n=n.lstrip('*'); sums[n]=digest
        check(n+'#sha256',digest,lambda n=n:hashlib.sha256(read(n)).hexdigest())
    if failures: return 1

    tracking=True
    t=v.trust(read('trust.cbor'))
    check('trust.cbor','accept',lambda:outcome(lambda:v.trust(read('trust.cbor'))))
    # Python 3.11's standard-library TOML reader, never a dependency.
    import tomllib
    rendering=tomllib.loads(read('trust.toml').decode())
    rendering.pop('fingerprint',None)
    rendering['witnesses']=rendering.pop('witness')
    for k in ('net','genesis_hash'): rendering[k]=bytes.fromhex(rendering[k])
    check('trust.toml','byte-identical',lambda:'byte-identical' if cbor.dumps(rendering)==read('trust.cbor') else 'different')
    number=int.from_bytes(hashlib.sha256(read('trust.cbor')).digest()[:10],'big')
    alphabet='0123456789ABCDEFGHJKMNPQRSTVWXYZ'; chars=''.join(alphabet[(number>>(5*i))&31] for i in reversed(range(16)))
    fingerprint='-'.join(chars[i:i+4] for i in range(0,16,4))+'\n'
    check('trust.fingerprint',read('trust.fingerprint').decode(),lambda:fingerprint)

    keys=jread('keys.json')
    check('keys.json#network',keys['net'],lambda:t['net'].hex())
    for name,key in keys['ed25519'].items():
        pk=bytes.fromhex(key['public'])
        check('keys.json#'+name+'-valid-point',True,lambda pk=pk:ed25519.valid(pk))
        check('keys.json#'+name+'-kid',key['kid'],lambda pk=pk:v.kid(pk))
    for name,key in keys['x25519'].items():
        check('keys.json#'+name+'-wg-key-length',32,lambda key=key:len(bytes.fromhex(key)))

    s,entries=replay_manifest('log/manifest.json')
    for n in ('log-empty','log-admission','log-cas'): replay_manifest(n+'/manifest.json')
    for directory in ('genesis','genesis-good'):
        m=cases(directory)
        for name in m['cases']: replay_manifest(directory+'/'+name+'/manifest.json')

    for directory,expected in (('trust-bad',False),('trust-good',True)):
        m=cases(directory)
        for name in m['cases']:
            n=directory+'/'+name+'.cbor'; check(n,expected,lambda n=n:boolean(lambda:v.trust(read(n))))

    for p in sorted(path('entries').glob('*.cbor')):
        n=p.relative_to(ROOT).as_posix(); mirror=jread(str(Path(n).with_suffix('.json'))); raw=read(n)
        def entry_mirror(raw=raw):
            e=v.envelope(raw,t['net'])
            return dict(entry=v.jsonable(e),entry_hash=hashlib.sha256(raw).hexdigest(),leaf_hash=merkle.leaf(raw).hex(),
                        preimage_sha256=hashlib.sha256(v.preimage(e)).hexdigest(),size=len(raw))
        check(n+'#mirror',mirror,entry_mirror)
        check(n+'#deterministic',raw,lambda raw=raw:cbor.dumps(cbor.loads(raw)))

    m=cases('entries-hostile')
    for row in m['cases']:
        n='entries-hostile/'+row['name']+'.cbor'
        check(n,row.get('accepted',False),lambda n=n:boolean(lambda:cbor.loads(read(n))))

    m=cases('policies')
    for row in m['cases']:
        n='policies/'+row['name']+'.txt'; raw=read(n).decode()
        check(n,row['accept'],lambda raw=raw:boolean(lambda:v.Policy(raw)))
        for i,e in enumerate(row.get('evaluate',[])):
            check(n+'#evaluate-'+str(i),e['satisfied'],lambda raw=raw,e=e:v.Policy(raw).satisfied(set(e['cosigners'])))

    m=cases('requests')
    for row in m['cases']:
        n='requests/'+row['name']; raw=read(n+'.cbor'); txt=read(n+'.txt').decode()
        mirror=jread(n+'.json')
        def request_mirror(raw=raw,txt=txt):
            r=v.request(raw,t['net']); pre=b'norn/enroll-request/v1\n'+cbor.dumps({k:x for k,x in r.items() if k!='sig'})
            return dict(request=v.jsonable(r),preimage_sha256=hashlib.sha256(pre).hexdigest(),text=txt.removesuffix('\n'),size=len(raw))
        check(n+'.cbor',True,lambda raw=raw:boolean(lambda:v.request(raw,t['net'])))
        check(n+'.txt',raw,lambda txt=txt:bech32m.payload(txt.removesuffix('\n')))
        check(n+'.json',mirror,request_mirror)
        expected=bech32m.encode('norn',raw)
        if row['form']=='uppercase': expected=expected.upper()
        elif row['form']!='canonical': check(n+'#form','known','UNKNOWN CASE')
        check(n+'#text-form',expected+'\n',lambda txt=txt:txt)
        if 'same_request_as' in row:
            check(n+'#same-request',read('requests/'+row['same_request_as']+'.cbor'),lambda raw=raw:raw)
    m=cases('requests-bad')
    for row in m['cases']:
        n='requests-bad/'+row['name']+'.txt'
        check(n,False,lambda n=n:boolean(lambda:v.request(bech32m.payload(read(n).decode().removesuffix('\n')),t['net'])))

    maincp,servedstate,servedentries=v.served(getter('served'),t)
    check('served/checkpoint','accept',lambda:outcome(lambda:v.served(getter('served'),t)))
    check('served/#canonical-state','byte-identical',lambda:'byte-identical' if v.canonical(servedstate)==read('state.json') else 'different')
    check('served/#manifest-entries',entries,lambda:servedentries)
    for p in sorted(ROOT.glob('served-*/cases.json')):
        directory=p.parent.name
        if directory in ('served-bad','served-genesis'): continue
        m=cases(directory)
        if directory=='served-large':
            cp,ls,le=v.served(getter(directory),t)
            check(directory+'/checkpoint','accept',lambda:outcome(lambda:v.served(getter(directory),t)))
            check(directory+'#size',m['size'],lambda:cp['size'])
            for row in m['tiles']:
                check(directory+'/'+row['path']+'#width',row['width']*32,lambda row=row:len(read(directory+'/'+row['path'])))
            for i,row in enumerate(m['paths']):
                check(directory+'#path-'+str(i),row['path'],lambda row=row:v.tile_path('entries' if row['kind']=='entries' else row['level'],row['index'],row['width']))
            continue
        base=m['serve_over']; override={'checkpoint':read(directory+'/checkpoint')}
        if 'fresh' in m:
            for reader,prior in (('fresh',None),('informed',s)):
                check(directory+'/checkpoint#'+reader,m[reader],lambda prior=prior,base=base,override=override:outcome(lambda:v.served(getter(base,override),t,prior)))
        else:
            check(directory+'/checkpoint','accept',lambda base=base,override=override:outcome(lambda:v.served(getter(base,override),t)))
        if 'informed_reads_served' in m:
            check(directory+'#informed_reads_served',m['informed_reads_served'],lambda:outcome(lambda:v.served(getter('served'),t,s)))
        if 'quorum_time' in m:
            check(directory+'#quorum_time',m['quorum_time'],lambda override=override:v.checkpoint(override['checkpoint'],t)['time'])
        if 'signed_by' in m:
            check(directory+'#learned-key',True,lambda m=m:any(k['pk'].hex()==m['signed_by'] and k['since_index']==m['since_index'] and k['overlap']==m['overlap'] for k in s['log_keys']))

    m=cases('checkpoints-bad')
    for name in m['cases']:
        n='checkpoints-bad/'+name+'.checkpoint'; raw=read(n)
        check(n,m['codes'][name],lambda raw=raw:outcome(lambda:v.served(getter('served',{'checkpoint':raw}),t)))
    m=cases('served-bad')
    for row in m['cases']:
        directory='served-bad'; overrides={}
        for f in row.get('files',[]): overrides[f['path']]=read(directory+'/'+f['file'])
        if 'path' in row: overrides[row['path']]=None if row.get('remove') else read(directory+'/'+row['file'])
        check(directory+'/'+row['name'],m['codes'][row['name']],lambda overrides=overrides,m=m:outcome(lambda:v.served(getter(m['serve_over'],overrides),t)))
    m=cases('served-genesis')
    for row in m['cases']:
        directory='served-genesis/'+row['serve']
        check('served-genesis/'+row['name'],m['codes'][row['name']],lambda directory=directory:outcome(lambda:v.served(getter(directory),t)))

    m=cases('proofs')
    for id in m['devices']:
        n='proofs/'+id+'.bundle'; check(n,'accept',lambda n=n:outcome(lambda:v.bundle(read(n),t)))
        check(n+'#installs',m['installs'][id],lambda id=id:s['devices'][id]['wg_pk'].hex())
    cap=m['at_the_cap']; n='proofs/'+cap['file']
    check(n,'accept',lambda:outcome(lambda:v.bundle(read(n),t)))
    check(n+'#length',cap['bytes'],lambda:len(read(n)))
    check('proofs/#checkpoint-time',m['checkpoint_quorum_time'],lambda:maincp['time'])
    check('proofs/#replayed-policy-time',m['replayed_policy_quorum_time'],lambda:v.checkpoint(read('served/checkpoint'),t,s)['time'])
    edge=jread('proofs/'+m['right_edge_inclusion']['file']); h=merkle.leaf(v.b64(edge['entry_b64']))
    check('proofs/right-edge.json#leaf',edge['leaf_hash'],lambda:h.hex())
    check('proofs/right-edge.json#inclusion',True,lambda:merkle.inclusion(h,edge['index'],edge['size'],[bytes.fromhex(p) for p in edge['proof']],bytes.fromhex(edge['root'])))
    m=cases('proofs-bad')
    for row in m['cases']:
        n='proofs-bad/'+row['name']+'.bundle'
        check(n,m['codes'][row['name']],lambda n=n:outcome(lambda:v.bundle(read(n),t)))
    m=cases('proofs-rotated'); n='proofs-rotated/'+m['bundle']
    for reader,prior in (('fresh',None),('informed',s)):
        check(n+'#'+reader,m[reader],lambda prior=prior:outcome(lambda:v.bundle(read(n),t,prior)))

    parsed=v.receipt(read('receipt.note'),t,entry=entries[0]); mirror=jread('receipt.json'); mirror.pop('comment',None)
    check('receipt.note#mirror',mirror,lambda:v.jsonable(parsed))
    m=cases('receipt-bad')
    for row in m['cases']:
        n='receipt-bad/'+row['name']
        check(n,m['codes'][row['name']],lambda n=n,row=row:outcome(lambda:v.receipt(read(n),t,entry=entries[0],now=row.get('now_unix',0))))
    m=cases('receipt-rotated'); n='receipt-rotated/'+m['receipt']
    for reader,prior in (('fresh',None),('informed',s)):
        check(n+'#'+reader,m[reader],lambda prior=prior:outcome(lambda:v.receipt(read(n),t,prior,entries[0])))

    m=cases('fork')
    for name in m['sound']:
        n='fork/'+name+'.cbor'; check(n,'accept',lambda n=n:outcome(lambda:v.evidence(read(n),t)))
    for row in m['cases']:
        n='fork/'+row['name']+'.cbor'; check(n,m['codes'][row['name']],lambda n=n:outcome(lambda:v.evidence(read(n),t)))
    # The separately shipped checkpoint is also independently checked.
    check('fork/conflicting.checkpoint','accept',lambda:outcome(lambda:v.checkpoint(read('fork/conflicting.checkpoint'),t)))

    m=cases('detect')
    for row in m['cases']:
        stored=v.checkpoint(read('detect/'+row['stored']),t)
        held=None if row.get('held')=='none' else entries[:stored['size']]
        n='detect/'+row['name']; expected=m['codes'].get(row['name'],'accept')
        check(n,expected,lambda row=row,stored=stored,held=held:outcome(lambda:v.served(getter('detect/'+row['serve']),t,stored=stored,stored_entries=held)))
        # Compare the broad manifest outcome independently from the closed code.
        def broad(row=row,stored=stored,held=held):
            result=outcome(lambda:v.served(getter('detect/'+row['serve']),t,stored=stored,stored_entries=held))
            return result if result in ('fork','accept') else 'refuse'
        check(n+'#outcome',row['outcome'],broad)
        candidate_get=getter('detect/'+row['serve'])
        candidate_cp=v.checkpoint(candidate_get('checkpoint'),t)
        candidate_entries=[]
        for group in range((candidate_cp['size']+255)//256):
            width=min(256,candidate_cp['size']-group*256)
            raw=candidate_get(v.tile_path('entries',group,width)); pos=0
            while pos<len(raw):
                count=int.from_bytes(raw[pos:pos+2],'big'); pos+=2
                candidate_entries.append(raw[pos:pos+count]); pos+=count
        tile_expected='tiles' if row['name']=='tampered-bundle-under-a-stored-head' else 'accept'
        check(n+'#isolated-tile-consistency',tile_expected,
              lambda get=candidate_get,es=candidate_entries:outcome(lambda:v.verify_tiles(get,list(map(merkle.leaf,es)))))
    known_manifests.add('detect/staleness.json'); m=jread('detect/staleness.json')
    for row in m['cases']:
        age=None if not row.get('have_clock',True) else (max(q+row['now']-learned for q,learned in row['observed'])-row['held'] if 'observed' in row else row['elapsed'])
        check('detect/staleness.json#'+row['name'],row['expect'],lambda row=row,age=age:v.freshness(age,m['staleness'],row.get('hard',m['hard'])))
        if 'observed' in row: check('detect/staleness.json#'+row['name']+'-elapsed',row['elapsed'],lambda age=age:age)

    m=cases('proven')
    for row in m['cases']:
        check('proven/'+row['name'],row['proven'],lambda row=row:sorted(v.proven(s,row['t'] or None)))
    for id,expected in m['grants'].items(): check('proven/#grant-'+id,expected,lambda id=id:v.grant(s['devices'][id]))
    for id,row in m['bundles'].items():
        b,cp=v.bundle(read(row['file']),t); e=v.envelope(b['entry'],t['net']); r=v.request(e['body']['request'],t['net'])
        check('proven/#bundle-'+id,dict(bundle_wg_pk=row['bundle_wg_pk'],state_wg_pk=row['state_wg_pk'],proves_index=row['proves_index'],rotated_since=row['rotated_since']),
              lambda b=b,r=r,id=id:dict(bundle_wg_pk=r['wg_pk'].hex(),state_wg_pk=s['devices'][id]['wg_pk'].hex(),proves_index=b['index'],rotated_since=r['wg_pk']!=s['devices'][id]['wg_pk']))

    m=cases('ed25519-cctv'); source=jread('ed25519-cctv/ed25519vectors.json'); by_number={r['number']:r for r in source}
    check('ed25519-cctv/#numbers',sorted(by_number),lambda:sorted(r['number'] for r in m['cases']))
    for row in m['cases']:
        r=by_number[row['number']]
        check('ed25519-cctv/'+str(row['number']),row['outcome'],lambda r=r:'accept' if ed25519.verify(bytes.fromhex(r['key']),r['msg'].encode(),bytes.fromhex(r['sig'])) else 'reject')

    m=cases('anchors')
    for row in m['cases']:
        n='anchors/'+row['name']
        read(n)
        if 'over' in row:
            raw=read(row['over']); cut=raw.index(b'\n\n')
            check(n+'#stamped-digest',row['digest'],lambda raw=raw,cut=cut:hashlib.sha256(raw[:cut+2]).hexdigest())
        else:
            # SPEC §12.1 explicitly excludes OTS parsing. Integrity was checked above.
            check(n+'#advisory-only','present; OTS not validated',lambda n=n:'present; OTS not validated' if read(n) else 'empty')
    check('anchors/calendar-response.bin#advisory-only','present; OTS not validated',lambda:'present; OTS not validated' if read('anchors/calendar-response.bin') else 'empty')

    # No cases/manifest can disappear silently when the suite is extended.
    for p in sorted(ROOT.rglob('*.json')):
        n=p.relative_to(ROOT).as_posix()
        if p.name in ('cases.json','manifest.json') and n not in known_manifests:
            check(n,'runner registered',lambda:'UNKNOWN CASE FILE')
    # Every data file was integrity checked; all protocol artifacts must additionally
    # have been consumed by a runner, not just passed through the checksum loop.
    supports={'README.md','SHA256SUMS','ed25519-cctv/README.md','ed25519-cctv/PROVENANCE.md','ed25519-cctv/LICENSE','ed25519-cctv/gen_cases.py'}
    for p in sorted(ROOT.rglob('*')):
        if not p.is_file(): continue
        n=p.relative_to(ROOT).as_posix()
        if n not in sums and n!='SHA256SUMS': check(n+'#inventory','listed in SHA256SUMS',lambda:'UNLISTED FILE')
        if n not in semantic_used and n not in supports:
            check(n+'#coverage','runner consumed artifact',lambda:'UNRUN ARTIFACT')
    print(f'TOTAL {checks} checks; {failures} FAIL',flush=True)
    return int(failures!=0)

if __name__=='__main__':
    try: sys.exit(main())
    except Exception:
        traceback.print_exc(); print('harness expected=complete got=UNHANDLED ERROR FAIL'); sys.exit(1)
