#!/usr/bin/env python3
"""Offline complete vector runner. Expected values never enter protocol.py."""
import hashlib
import json
from pathlib import Path
import sys
import traceback
import cbor
import ed25519
import merkle
import bech32m
import protocol as p

ROOT=Path(__file__).resolve().parents[2]
V=ROOT/'vectors'
WORK=Path(__file__).resolve().parent
checks=failures=0
seen=set()
case_tables=set()

def read(path):
    path=Path(path)
    if not path.is_absolute(): path=V/path
    path=path.resolve()
    if not path.is_relative_to(V): raise ValueError('vector path escapes sealed vector directory')
    seen.add(path.relative_to(V).as_posix())
    return path.read_bytes()

def data(path): return json.loads(read(path))

def table(folder):
    case_tables.add(folder+'/cases.json')
    return data(folder+'/cases.json')

def check(path,expected,fn):
    global checks,failures
    checks+=1
    try: got=fn()
    except p.Refusal as err: got=err.code
    except Exception as err:
        got='ERROR '+type(err).__name__+': '+str(err)
    passed=got==expected
    if not passed: failures+=1
    def fmt(x): return json.dumps(x,ensure_ascii=False,separators=(',',':'))
    print(f'{path} expected={fmt(expected)} got={fmt(got)} {"PASS" if passed else "FAIL"}',flush=True)
    return passed

def accept(fn):
    fn(); return 'accept'

def normalize(obj): return json.loads(p.json_bytes(obj))

def manifest(folder):
    m=data(folder+'/manifest.json')
    anchor={k:bytes.fromhex(v) for k,v in m['anchor'].items()}
    entries=[read(folder+'/'+r['name']+'.cbor') for r in m['entries']]
    state=p.replay(anchor,entries)
    reasons={r['index']:r['reason'] for r in state['rejected']}
    for r in m['entries']:
        check(folder+'/'+r['name']+'.cbor',r['reason'] or 'accept',lambda r=r:reasons.get(r['index'],'accept'))
        reasonfile=V/folder/(r['name']+'.reason')
        if reasonfile.exists():
            check(folder+'/'+r['name']+'.reason',r['reason']+'\n',lambda f=reasonfile:read(f).decode())
    expected_file='state.json' if folder=='log' else folder+'/state.json'
    expected=read(expected_file)
    check(expected_file,'byte-identical',lambda:'byte-identical' if p.json_bytes(state)==expected else 'different')
    if folder=='log': (WORK/'state.actual.json').write_bytes(p.json_bytes(state))
    return state,entries

class TrackedMirror(p.Mirror):
    def read(self,path):
        # Mark only existing underlying assets actually used by the verifier.
        if path not in self.overlay:
            underlying=(self.path/path).resolve()
            if underlying.is_relative_to(V) and underlying.exists(): seen.add(underlying.relative_to(V).as_posix())
        return super().read(path)

def main():
    # No Norn test vector is consulted until the standards' self-tests pass.
    for name,module in [('RFC8032',ed25519),('RFC6962',merkle),('BIP350',bech32m)]:
        check('selftest/'+name,'accept',lambda m=module:accept(m.selftest))
    if failures: return 1
    trust_bytes=read('trust.cbor'); t=p.trust(trust_bytes)
    check('trust.cbor','accept',lambda:accept(lambda:p.trust(trust_bytes)))
    check('trust.fingerprint',read('trust.fingerprint').decode(),lambda:p.fingerprint(trust_bytes))
    # The human TOML is an input rendering, not a source of protocol rules.
    def toml_roundtrip():
        import tomllib
        human=tomllib.loads(read('trust.toml').decode())
        human['witnesses']=human.pop('witness')
        for key in ('net','genesis_hash'): human[key]=bytes.fromhex(human[key])
        return 'byte-identical' if cbor.dumps(human)==trust_bytes else 'different'
    check('trust.toml','byte-identical',toml_roundtrip)
    keys=data('keys.json')
    def key_mirrors():
        for name,k in keys['ed25519'].items():
            if len(bytes.fromhex(k['seed']))!=32 or len(bytes.fromhex(k['public']))!=32 or p.kid(bytes.fromhex(k['public']))!=k['kid']: return False
        return True
    check('keys.json',True,key_mirrors)
    state,entries=manifest('log')
    manifest('log-empty')
    for folder in ('genesis','genesis-good'):
        for name in table(folder)['cases']: manifest(folder+'/'+name)
    for folder,expected in [('trust-bad','trust'),('trust-good','accept')]:
        for name in table(folder)['cases']:
            raw=read(folder+'/'+name+'.cbor')
            check(folder+'/'+name+'.cbor',expected,lambda raw=raw:accept(lambda:p.trust(raw)))
    for file in sorted((V/'entries').glob('*.cbor')):
        raw=read(file); e=p.envelope(raw,t['net']); mirror=data(file.with_suffix('.json'))
        got={'entry':normalize(e),'entry_hash':hashlib.sha256(raw).hexdigest(),'leaf_hash':merkle.leaf(raw).hex(),'preimage_sha256':hashlib.sha256(p.preimage(e)).hexdigest(),'size':len(raw)}
        check(file.relative_to(V).as_posix(),mirror,lambda got=got:got)
        check(file.with_suffix('.json').relative_to(V).as_posix(),'canonical',lambda mirror=mirror,file=file:'canonical' if p.json_bytes(mirror)==read(file.with_suffix('.json')) else 'different')
    hostile_reasons={'bare-null':'null','bare-undefined':'undefined','bare-float':'float/simple item','bare-negative-integer':'negative integer','bare-tag':'tag','bare-indefinite-text':'indefinite length','bare-nontext-map-key':'nontext map key','bare-invalid-utf8':'invalid utf8','oversize-entry':'size limit','deep-nesting':'depth limit','past-the-depth-limit':'depth limit','past-the-size-limit':'size limit','past-the-key-limit':'map key limit'}
    for case in table('entries-hostile')['cases']:
        raw=read('entries-hostile/'+case['name']+'.cbor')
        def decode(raw=raw):
            try: cbor.loads(raw); return 'accept'
            except cbor.Error as err: return str(err)
        expected='accept' if case.get('accepted') else hostile_reasons.get(case['name'],'UNKNOWN CASE')
        check('entries-hostile/'+case['name'],expected,decode)
    for case in table('policies')['cases']:
        raw=read('policies/'+case['name']+'.txt').decode()
        check('policies/'+case['name'],'accept' if case['accept'] else 'refuse',lambda raw=raw:policy_result(raw))
        if case['accept']:
            policy=p.Policy(raw)
            for i,ev in enumerate(case.get('evaluate',[])):
                check('policies/'+case['name']+'/evaluate/'+str(i),ev['satisfied'],lambda ev=ev,policy=policy:policy.satisfied(set(ev['cosigners'])))
    for case in table('requests')['cases']:
        name=case['name']; raw=read('requests/'+name+'.cbor'); txt=read('requests/'+name+'.txt').decode().removesuffix('\n'); mirror=data('requests/'+name+'.json')
        def positive_request(raw=raw,txt=txt,mirror=mirror,case=case):
            req=p.request(raw); textual=p.request_text(txt)
            msg=b'norn/enroll-request/v1\n'+cbor.dumps({k:v for k,v in req.items() if k!='sig'})
            encoded=bech32m.encode('norn',raw)
            expected_txt=encoded.upper() if case['form']=='uppercase' else encoded
            actual={'request':normalize(req),'preimage_sha256':hashlib.sha256(msg).hexdigest(),'size':len(raw),'text':txt}
            return req==textual and txt==expected_txt and actual==mirror and cbor.dumps(req)==raw
        check('requests/'+name,True,positive_request)
        check('requests/'+name+'.json','canonical',lambda mirror=mirror,name=name:'canonical' if p.json_bytes(mirror)==read('requests/'+name+'.json') else 'different')
    for case in table('requests-bad')['cases']:
        txt=read('requests-bad/'+case['name']+'.txt').decode().removesuffix('\n')
        def bad_request(txt=txt):
            try: p.request_text(txt); return 'accept'
            except ValueError: return 'refuse'
        check('requests-bad/'+case['name'],'refuse',bad_request)
    cp,served_state,served_entries=p.served(TrackedMirror(V/'served'),t)
    check('served','accept',lambda:'accept')
    check('served/replayed-state','byte-identical',lambda:'byte-identical' if p.json_bytes(served_state)==read('state.json') else 'different')
    check('served/entry-bundles','same-log',lambda:'same-log' if served_entries==entries else 'different')
    cases=table('checkpoints-bad')
    for name in cases['cases']:
        raw=read('checkpoints-bad/'+name+'.checkpoint')
        check('checkpoints-bad/'+name,cases['codes'][name],lambda raw=raw:accept(lambda:p.served(TrackedMirror(V/'served',{'checkpoint':raw}),t)))
    check('served-large','accept',lambda:accept(lambda:p.served(TrackedMirror(V/'served-large'),t)))
    large=table('served-large')
    check('served-large/size',large['size'],lambda:p.checkpoint(read('served-large/checkpoint'),t)['size'])
    for i,row in enumerate(large['paths']):
        check('served-large/paths/'+str(i),row['path'],lambda row=row:p.entry_path(row['index'],row['width']) if row['kind']=='entries' else p.tile_path(row['level'],row['index'],row['width']))
    for row in large['tiles']:
        check('served-large/'+row['path']+'/width',row['width']*32,lambda row=row:len(read('served-large/'+row['path'])))
    cases=table('served-bad')
    for case in cases['cases']:
        overlay={}
        if case.get('remove'): overlay[case['path']]=None
        elif 'file' in case: overlay[case['path']]=read('served-bad/'+case['file'])
        else:
            for f in case['files']: overlay[f['path']]=read('served-bad/'+f['file'])
        check('served-bad/'+case['name'],cases['codes'][case['name']],lambda overlay=overlay:accept(lambda:p.served(TrackedMirror(V/cases['serve_over'],overlay),t)))
    for folder in ('served-extra-witness','served-name-collision','served-twice-cosigned','served-rotated','served-superseded'):
        case=table(folder); raw=read(folder+'/checkpoint'); mirror=TrackedMirror(V/case['serve_over'],{'checkpoint':raw})
        check(folder+'/bootstrap','log-signature' if folder=='served-rotated' else 'accept',lambda mirror=mirror:accept(lambda:p.served(mirror,t)))
        if folder in ('served-rotated','served-superseded'):
            check(folder+'/after-replay','quorum' if folder=='served-superseded' else 'accept',lambda mirror=mirror:accept(lambda:p.served(mirror,t,state)))
        if 'quorum_time' in case:
            check(folder+'/quorum-time',case['quorum_time'],lambda raw=raw:p.checkpoint(raw,t)['quorum_time'])
        if folder=='served-rotated':
            check(folder+'/publication',{'pk':case['signed_by'],'since_index':case['since_index'],'overlap':case['overlap']},lambda:normalize(state['log_keys'][0]))
    proofcases=table('proofs')
    check('proofs/checkpoint-quorum-time',proofcases['checkpoint_quorum_time'],lambda:cp['quorum_time'])
    check('proofs/next-policy-quorum-time',proofcases['replayed_policy_quorum_time'],lambda:p.checkpoint(read('served/checkpoint'),t,state)['quorum_time'])
    bundles={}
    for name in proofcases['devices']:
        raw=read('proofs/'+name+'.bundle')
        check('proofs/'+name+'.bundle','accept',lambda raw=raw:accept(lambda:p.bundle(raw,t)))
        bundles[name]=p.bundle(raw,t)[0]
        check('proofs/'+name+'/installs',proofcases['installs'][name],lambda name=name:state['devices'][name]['wg_pk'].hex())
    cap=proofcases['at_the_cap']; raw=read('proofs/'+cap['file'])
    check('proofs/'+cap['file'],'accept',lambda:accept(lambda:p.bundle(raw,t)))
    check('proofs/'+cap['file']+'/size',cap['bytes'],lambda:len(raw))
    edge=data('proofs/'+proofcases['right_edge_inclusion']['file']); raw=p.b64(edge['entry_b64'])
    check('proofs/right-edge/leaf',edge['leaf_hash'],lambda:merkle.leaf(raw).hex())
    check('proofs/right-edge/inclusion',True,lambda:merkle.inclusion(merkle.leaf(raw),edge['index'],edge['size'],[bytes.fromhex(h) for h in edge['proof']],bytes.fromhex(edge['root'])))
    cases=table('proofs-bad')
    for case in cases['cases']:
        raw=read('proofs-bad/'+case['name']+'.bundle')
        check('proofs-bad/'+case['name'],cases['codes'][case['name']],lambda raw=raw:accept(lambda:p.bundle(raw,t)))
    view=table('proven')
    for case in view['cases']:
        check('proven/'+case['name'],case['proven'],lambda case=case:sorted(p.proven(state,case['t'] or None)))
    for name,expected in view['grants'].items():
        check('proven/'+name+'/grant',expected,lambda name=name:p.grant(state['devices'][name]['labels']))
    for name,case in view['bundles'].items():
        b=bundles[name]; historical=p.request(p.envelope(b['entry'],t['net'])['body']['request'])
        got={'bundle_wg_pk':historical['wg_pk'].hex(),'state_wg_pk':state['devices'][name]['wg_pk'].hex(),'proves_index':b['index'],'rotated_since':historical['wg_pk']!=state['devices'][name]['wg_pk']}
        check('proven/'+name+'/bundle-binding',{k:case[k] for k in got},lambda got=got:got)
    rec=data('receipt.json'); submitted=merkle.leaf(entries[0])
    check('receipt.note',{k:v for k,v in rec.items() if k!='comment'},lambda:normalize(p.receipt(read('receipt.note'),t,submitted)))
    cases=table('receipt-bad')
    for case in cases['cases']:
        raw=read('receipt-bad/'+case['name'])
        check('receipt-bad/'+case['name'],cases['codes'][case['name']],lambda raw=raw,case=case:accept(lambda:p.receipt(raw,t,submitted,case.get('now_unix',0))))
    cases=table('fork')
    for name in cases['sound']:
        raw=read('fork/'+name+'.cbor')
        check('fork/'+name,'accept',lambda raw=raw:accept(lambda:p.evidence(raw,t)))
    check('fork/conflicting.checkpoint','accept',lambda:accept(lambda:p.checkpoint(read('fork/conflicting.checkpoint'),t)))
    for case in cases['cases']:
        raw=read('fork/'+case['name']+'.cbor')
        check('fork/'+case['name'],cases['codes'][case['name']],lambda raw=raw:accept(lambda:p.evidence(raw,t)))
    cases=table('detect')
    deliberately_unreached=set()
    for case in cases['cases']:
        stored=p.checkpoint(read('detect/'+case['stored']),t)
        held=None if case.get('held')=='none' else entries
        check('detect/'+case['name'],cases['codes'].get(case['name'],'accept'),lambda case=case,stored=stored,held=held:accept(lambda:p.served(TrackedMirror(V/'detect'/case['serve']),t,stored=stored,held_entries=held)))
        # A refused branch must stop before step 11. Its remaining tile files
        # are known supporting assets, covered by SHA256SUMS below, not
        # executable cases omitted from the runner. Derive their names from
        # the checked checkpoint, rather than a whitelist of vector filenames.
        if cases['codes'].get(case['name']) in ('head','fork','rollback'):
            branch=(V/'detect'/case['serve']).resolve()
            candidate=p.checkpoint(read(branch/'checkpoint'),t)
            count=candidate['size']; level=0
            while count:
                for start in range(0,count,256):
                    asset=branch/p.tile_path(level,start//256,min(256,count-start))
                    if asset.exists(): deliberately_unreached.add(asset.relative_to(V).as_posix())
                count//=256; level+=1
    stale=data('detect/staleness.json')
    for case in stale['cases']:
        check('detect/staleness/'+case['name'],case['expect'],lambda case=case:p.freshness(case['elapsed'] if case.get('have_clock',True) else None,stale['staleness'],case.get('hard',stale['hard'])))
    anchors=table('anchors')
    for case in anchors['cases']:
        if 'over' in case:
            raw=read(case['over']); end=raw.index(b'\n\n')+2
            check('anchors/'+case['name']+'/digest',case['digest'],lambda raw=raw,end=end:hashlib.sha256(raw[:end]).hexdigest())
        else:
            # SPEC §12 calls this an arbitrary, unrelated OTS parser fixture.
            # OTS itself is outside this spec: exercise only opaque asset integrity.
            check('anchors/'+case['name']+'/opaque-asset',True,lambda case=case:bool(read('anchors/'+case['name'])))
    # Ensure no newly added case table can silently go unrun.
    actual_tables={f.relative_to(V).as_posix() for f in V.rglob('cases.json')}
    check('coverage/case-tables',sorted(actual_tables),lambda:sorted(case_tables))
    # Every distributed byte is checked, even auxiliary informative OTS data.
    checksum_files=set()
    for line in read('SHA256SUMS').decode().splitlines():
        digest,filename=line.split('  ',1); checksum_files.add(filename)
        check(filename+'/SHA256',digest,lambda filename=filename:hashlib.sha256(read(filename)).hexdigest())
    actual_files={f.relative_to(V).as_posix() for f in V.rglob('*') if f.is_file()}-{'SHA256SUMS'}
    check('coverage/SHA256SUMS',sorted(actual_files),lambda:sorted(checksum_files))
    # Integrity alone must not disguise an unhandled executable artifact.
    semantic_files=actual_files & {f for f in actual_files if f.endswith(('.cbor','.bundle','.checkpoint','.note','.txt','.reason')) or '/tile/' in '/'+f or f.endswith('/checkpoint')}
    check('coverage/protocol-artifacts',[],lambda:sorted(semantic_files-semantic_seen-deliberately_unreached))
    print(f'{checks} checks; {failures} FAIL',flush=True)
    return int(bool(failures))

def policy_result(raw):
    try: p.Policy(raw); return 'accept'
    except ValueError: return 'refuse'

# Snapshot semantics before integrity reads so the coverage check above is useful.
semantic_seen=set()
original_check=check

def check(path,expected,fn):
    result=original_check(path,expected,fn)
    if not path.endswith('/SHA256') and not path.startswith('coverage/'):
        semantic_seen.update(seen)
    return result

if __name__=='__main__':
    try: sys.exit(main())
    except Exception:
        traceback.print_exc()
        sys.exit(1)
