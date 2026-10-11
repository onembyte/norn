#!/usr/bin/env python3
"""Exhaustive sealed-vector runner; expected answers never enter protocol.py."""
import sys
sys.dont_write_bytecode=True
import argparse
import base64
import hashlib
import json
import traceback
from pathlib import Path
import cbor
import ed25519
import merkle
import bech32m
import protocol as p

class Harness:
    def __init__(self,v): self.v=v; self.total=0; self.failures=0; self.handled=set()
    def read(self,path): return (self.v/path).read_bytes()
    def data(self,path): return json.loads(self.read(path))
    def report(self,name,expected,got):
        ok=expected==got; self.total+=1; self.failures+=not ok
        def compact(x):
            if isinstance(x,bytes): return 'bytes:'+str(len(x))+':sha256='+p.sha(x).hex()
            return json.dumps(x,ensure_ascii=False,separators=(',',':'))
        print(f'{name} expected={compact(expected)} got={compact(got)} {"PASS" if ok else "FAIL"}',flush=True)
    def check(self,name,expected,fn):
        try: got=fn()
        except Exception as ex:
            got=f'ERROR:{type(ex).__name__}:{ex}'; traceback.print_exc(file=sys.stderr)
        self.report(name,expected,got)
    def outcome(self,fn,coded=True):
        try: fn(); return 'accept'
        except p.Refusal as ex: return ex.code if coded else 'reject'
        except cbor.DecodeError: return 'decode' if coded else 'reject'
        except ValueError:
            if coded: raise
            return 'reject'
    def cases(self,dirname):
        path=dirname+'/cases.json'; self.handled.add(path); return self.data(path)
    def integrity(self):
        lines=self.read('SHA256SUMS').decode().splitlines(); problems=[]; named=set()
        for line in lines:
            digest,name=line.split(None,1); name=name.lstrip('*'); named.add(name)
            f=Path(name)
            if f.is_absolute() or '..' in f.parts: problems.append('unsafe '+name); continue
            try:
                if hashlib.sha256(self.read(name)).hexdigest()!=digest: problems.append('digest '+name)
            except OSError: problems.append('missing '+name)
        files={str(f.relative_to(self.v)) for f in self.v.rglob('*') if f.is_file() and f.name!='SHA256SUMS'}
        problems+=['unlisted '+n for n in sorted(files-named)]
        self.report('vectors/SHA256SUMS',[],problems)
    def replay_manifest(self,path):
        self.handled.add(path); m=self.data(path); dirname=str(Path(path).parent)
        anchor={k:bytes.fromhex(v) for k,v in m['anchor'].items()}
        entries=[]
        for i,e in enumerate(m['entries']):
            p.require(e['index']==i); entries.append(self.read(dirname+'/'+e['name']+'.cbor'))
        st=p.replay(anchor,entries); reasons={r['index']:r['reason'] for r in st['rejected']}
        for e in m['entries']:
            self.report(dirname+'/'+e['name'],e['reason'] or 'accept',reasons.get(e['index'],'accept'))
            reasonpath=self.v/dirname/(e['name']+'.reason')
            if reasonpath.exists(): self.check(str(reasonpath.relative_to(self.v)),e['reason']+'\n',reasonpath.read_text)
        statepath='state.json' if dirname=='log' else dirname+'/state.json'
        computed=p.canonical_json(st)
        self.check(statepath,self.read(statepath),lambda:computed)
        destination=Path(__file__).resolve().parent/'reproduced'/statepath
        destination.parent.mkdir(parents=True,exist_ok=True)
        destination.write_bytes(computed)
        return st,entries
    def run(self):
        # Standard self-tests run before any vector is parsed, including checksums.
        for name,fn in [('RFC8032',ed25519.selftest),('RFC6962',merkle.selftest),('BIP350',bech32m.selftest)]:
            self.check('selftest/'+name,'accept',lambda fn=fn: (fn(),'accept')[1])
        self.integrity()
        t=p.trust(self.read('trust.cbor')); fresh=p.Reader(t)
        self.report('trust.cbor','accept','accept')
        self.check('trust.fingerprint',self.read('trust.fingerprint'),lambda:p.fingerprint(self.read('trust.cbor')).encode())
        # TOML rendering uses Python 3.11's standard library; mirrors are byte contracts.
        try:
            import tomllib
            human=tomllib.loads(self.read('trust.toml').decode())
            human['witnesses']=human.pop('witness')
            for k in ('net','genesis_hash'): human[k]=bytes.fromhex(human[k])
            self.check('trust.toml/CBOR',self.read('trust.cbor'),lambda:cbor.dumps(human))
        except ImportError: self.report('trust.toml','standard-library TOML support','unavailable: Python 3.11 required')
        st,entries=self.replay_manifest('log/manifest.json')
        for path in sorted(self.v.rglob('manifest.json')):
            rel=str(path.relative_to(self.v))
            if rel!='log/manifest.json': self.replay_manifest(rel)
        for dirname in ('genesis','genesis-good'):
            d=self.cases(dirname)
            for name in d['cases']:
                m=self.data(dirname+'/'+name+'/manifest.json')
                anchor={k:bytes.fromhex(v) for k,v in m['anchor'].items()}
                raw=[self.read(dirname+'/'+name+'/'+e['name']+'.cbor') for e in m['entries']]
                state=p.replay(anchor,raw)
                self.report(dirname+'/'+name+'/outcome','reject' if dirname=='genesis' else 'accept','reject' if state['size']==0 else 'accept')
        for dirname,expected in [('trust-bad','reject'),('trust-good','accept')]:
            d=self.cases(dirname)
            for name in d['cases']:
                self.check(dirname+'/'+name+'.cbor',expected,lambda name=name,dirname=dirname:self.outcome(lambda:p.trust(self.read(dirname+'/'+name+'.cbor')),False))
        for f in sorted((self.v/'entries').glob('*.cbor')):
            raw=f.read_bytes(); name=str(f.relative_to(self.v)); mirror=self.data(str(f.with_suffix('.json').relative_to(self.v)))
            def entry_mirror(raw=raw):
                e=p.envelope(raw,t['net']); p.body(e)
                return dict(entry=p.jsonable(e),entry_hash=p.sha(raw).hex(),leaf_hash=merkle.leaf(raw).hex(),preimage_sha256=p.sha(p.preimage(e)).hex(),size=len(raw))
            self.check(name+'/mirror',mirror,entry_mirror)
            self.check(name+'/canonical',raw,lambda raw=raw:cbor.dumps(cbor.loads(raw)))
        d=self.cases('entries-hostile')
        for c in d['cases']:
            self.check('entries-hostile/'+c['name'],'accept' if c.get('accepted') else 'reject',lambda c=c:self.outcome(lambda:cbor.loads(self.read('entries-hostile/'+c['name']+'.cbor')),False))
        d=self.cases('policies')
        for c in d['cases']:
            name='policies/'+c['name']; s=self.read(name+'.txt').decode()
            self.check(name,'accept' if c['accept'] else 'reject',lambda s=s:self.outcome(lambda:p.Policy(s),False))
            for i,row in enumerate(c.get('evaluate',[])):
                self.check(name+'/evaluate/'+str(i),row['satisfied'],lambda s=s,row=row:p.Policy(s).satisfied(set(row['cosigners'])))
        d=self.cases('requests')
        for c in d['cases']:
            name='requests/'+c['name']; raw=self.read(name+'.cbor'); txt=self.read(name+'.txt').decode()
            # Exactly one file terminator, not bech32 whitespace normalization.
            s=txt[:-1] if txt.endswith('\n') else txt
            mirror=self.data(name+'.json')
            self.check(name+'.cbor','accept',lambda raw=raw:self.outcome(lambda:p.request(raw),False))
            self.check(name+'.txt','accept',lambda s=s:self.outcome(lambda:p.request_text(s),False))
            self.check(name+'/decoded-bytes',raw,lambda s=s:bech32m.payload(s))
            self.check(name+'/mirror',mirror,lambda raw=raw,s=s:dict(request=p.jsonable(p.request(raw)),preimage_sha256=p.sha(p.request_preimage(p.request(raw))).hex(),size=len(raw),text=s))
            self.check(name+'/text-form',s,lambda raw=raw,c=c:bech32m.encode('norn',raw).upper() if c['form']=='uppercase' else bech32m.encode('norn',raw))
            if 'same_request_as' in c: self.report(name+'/same-request',self.read('requests/'+c['same_request_as']+'.cbor'),raw)
        d=self.cases('requests-bad')
        for c in d['cases']:
            name='requests-bad/'+c['name']+'.txt'; txt=self.read(name).decode(); txt=txt[:-1] if txt.endswith('\n') else txt
            self.check(name,'reject',lambda txt=txt:self.outcome(lambda:p.request_text(txt),False))
        d=self.cases('ed25519-cctv'); upstream=self.data('ed25519-cctv/ed25519vectors.json'); table={v['number']:v for v in upstream}
        self.report('ed25519-cctv/case-coverage',sorted(table),sorted(c['number'] for c in d['cases']))
        for c in d['cases']:
            v=table[c['number']]
            self.check('ed25519-cctv/'+str(c['number']),c['outcome'],lambda v=v:'accept' if ed25519.verify(bytes.fromhex(v['key']),v['msg'].encode(),bytes.fromhex(v['sig'])) else 'reject')
        # Bootstrap must verify a head before learning any keys or policy from it.
        verified=fresh.served(self.v/'served')
        self.report('served/checkpoint','accept','accept')
        self.report('served/state.json',p.canonical_json(st),p.canonical_json(verified['state']))
        informed=p.Reader(t,verified['state'])
        d=self.cases('checkpoints-bad')
        for name in d['cases']:
            self.check('checkpoints-bad/'+name,d['codes'][name],lambda name=name:self.outcome(lambda:fresh.served(self.v/'served',checkpoint=self.read('checkpoints-bad/'+name+'.checkpoint'))))
        d=self.cases('served-large')
        large=fresh.served(self.v/'served-large'); self.report('served-large/checkpoint','accept','accept')
        self.report('served-large/size',d['size'],large['checkpoint']['size'])
        for row in d['tiles']:
            self.check('served-large/'+row['path']+'/width',row['width'],lambda row=row:len(self.read('served-large/'+row['path']))//32)
        for i,row in enumerate(d['paths']):
            self.check('served-large/paths/'+str(i),row['path'],lambda row=row:p.tile_path('entries' if row['kind']=='entries' else row['level'],row['index'],row['width']))
        for dirname in ('served-extra-witness','served-name-collision','served-unknown-algorithm','served-stranger-name','served-twice-cosigned','served-rotated','served-superseded'):
            d=self.cases(dirname); cp=self.read(dirname+'/checkpoint'); source=self.v/d['serve_over']
            if 'fresh' in d:
                for label,reader in [('fresh',fresh),('informed',informed)]:
                    self.check(dirname+'/'+label,d[label],lambda reader=reader,source=source,cp=cp:self.outcome(lambda:reader.served(source,checkpoint=cp)))
            else: self.check(dirname+'/checkpoint','accept',lambda source=source,cp=cp:self.outcome(lambda:fresh.served(source,checkpoint=cp)))
            if 'quorum_time' in d:
                self.check(dirname+'/quorum-time',d['quorum_time'],lambda cp=cp:fresh.checkpoint(cp)['quorum_time'])
            if 'informed_reads_served' in d:
                self.check(dirname+'/informed-reads-served',d['informed_reads_served'],lambda:self.outcome(lambda:informed.served(self.v/'served')))
            if 'signed_by' in d:
                self.report(dirname+'/learned-key',d['signed_by'],verified['state']['log_keys'][0]['pk'].hex())
                self.report(dirname+'/since-index',d['since_index'],verified['state']['log_keys'][0]['since_index'])
                self.report(dirname+'/overlap',d['overlap'],verified['state']['log_keys'][0]['overlap'])
        d=self.cases('served-bad')
        for c in d['cases']:
            changes={}; removed=set()
            if c.get('remove'): removed.add(c['path'])
            if 'file' in c: changes[c['path']]=self.read('served-bad/'+c['file'])
            for f in c.get('files',[]): changes[f['path']]=self.read('served-bad/'+f['file'])
            def fetch(path,changes=changes,removed=removed,source=d['serve_over']):
                if path in removed: raise FileNotFoundError(path)
                return changes[path] if path in changes else self.read(source+'/'+path)
            self.check('served-bad/'+c['name'],d['codes'][c['name']],lambda fetch=fetch:self.outcome(lambda:fresh.served(fetch)))
        d=self.cases('served-genesis')
        for c in d['cases']:
            self.check('served-genesis/'+c['name'],d['codes'][c['name']],lambda c=c:self.outcome(lambda:fresh.served(self.v/'served-genesis'/c['serve'])))
        d=self.cases('proofs')
        for id in d['devices']:
            name='proofs/'+id+'.bundle'
            self.check(name,'accept',lambda name=name:self.outcome(lambda:fresh.bundle(self.read(name))))
            self.report(name+'/installs',d['installs'][id],verified['state']['devices'][id]['wg_pk'].hex())
        cap=d['at_the_cap']; raw=self.read('proofs/'+cap['file'])
        self.report('proofs/'+cap['file']+'/size',cap['bytes'],len(raw))
        self.check('proofs/'+cap['file'],'accept' if cap['accept'] else 'reject',lambda:self.outcome(lambda:fresh.bundle(raw),False))
        self.report('proofs/checkpoint-quorum-time',d['checkpoint_quorum_time'],verified['checkpoint']['quorum_time'])
        self.report('proofs/replayed-policy-quorum-time',d['replayed_policy_quorum_time'],informed.checkpoint(self.read('served/checkpoint'))['quorum_time'])
        edge=self.data('proofs/'+d['right_edge_inclusion']['file'])
        self.report('proofs/right-edge/leaf',edge['leaf_hash'],merkle.leaf(base64.b64decode(edge['entry_b64'])).hex())
        self.check('proofs/right-edge/inclusion',True,lambda:merkle.inclusion(bytes.fromhex(edge['leaf_hash']),edge['index'],edge['size'],list(map(bytes.fromhex,edge['proof'])),bytes.fromhex(edge['root'])))
        for k in ('index','size'): self.report('proofs/right-edge/'+k,d['right_edge_inclusion'][k],edge[k])
        d=self.cases('proofs-bad')
        for c in d['cases']:
            name='proofs-bad/'+c['name']+'.bundle'
            self.check(name,d['codes'][c['name']],lambda name=name:self.outcome(lambda:fresh.bundle(self.read(name))))
        d=self.cases('proofs-rotated')
        for label,reader in [('fresh',fresh),('informed',informed)]:
            self.check('proofs-rotated/'+label,d[label],lambda reader=reader:self.outcome(lambda:reader.bundle(self.read('proofs-rotated/'+d['bundle']))))
        self.report('proofs-rotated/learned-key',d['signed_by'],verified['state']['log_keys'][0]['pk'].hex())
        self.report('proofs-rotated/since-index',d['since_index'],verified['state']['log_keys'][0]['since_index'])
        rd=self.data('receipt.json'); submitted=merkle.leaf(entries[0])
        receipt=fresh.receipt(self.read('receipt.note'),submitted)
        self.report('receipt.note','accept','accept')
        self.report('receipt.json/leaf',rd['leaf_hash'],receipt['leaf_hash'].hex())
        self.report('receipt.json/deadline',rd['deadline'],receipt['deadline'])
        self.report('receipt.json/origin',rd['origin'],t['origin'])
        self.report('receipt.json/text-sha256',rd['text_sha256'],p.sha(receipt['signed']).hex())
        d=self.cases('receipt-bad')
        for c in d['cases']:
            name='receipt-bad/'+c['name']
            self.check(name,d['codes'][c['name']],lambda name=name,c=c:self.outcome(lambda:fresh.receipt(self.read(name),submitted,c.get('now_unix',0))))
        d=self.cases('receipt-rotated')
        for label,reader in [('fresh',fresh),('informed',informed)]:
            raw=(self.v/'receipt-rotated'/d['receipt']).read_bytes()
            self.check('receipt-rotated/'+label,d[label],lambda reader=reader,raw=raw:self.outcome(lambda:reader.receipt(raw,submitted)))
        self.report('receipt-rotated/learned-key',d['signed_by'],verified['state']['log_keys'][0]['pk'].hex())
        if 'since_index' in d: self.report('receipt-rotated/since-index',d['since_index'],verified['state']['log_keys'][0]['since_index'])
        d=self.cases('fork')
        for name in d['sound']:
            self.check('fork/'+name+'.cbor','accept',lambda name=name:self.outcome(lambda:fresh.evidence(self.read('fork/'+name+'.cbor'))))
        for c in d['cases']:
            name='fork/'+c['name']+'.cbor'
            self.check(name,d['codes'][c['name']],lambda name=name:self.outcome(lambda:fresh.evidence(self.read(name))))
        d=self.cases('detect')
        for c in d['cases']:
            stored=fresh.checkpoint(self.read('detect/'+c['stored']))
            held=None if c.get('held')=='none' else entries[:stored['size']]
            expected='accept' if c['outcome']=='accept' else d['codes'][c['name']]
            self.check('detect/'+c['name'],expected,lambda c=c,stored=stored,held=held:self.outcome(lambda:fresh.served(self.v/'detect'/c['serve'],stored=stored,held_entries=held)))
        s=self.data('detect/staleness.json')
        for c in s['cases']:
            elapsed=c['elapsed'] if c.get('have_clock',True) else None
            if 'observed' in c:
                clock=p.WitnessClock()
                for q,m in c['observed']: clock.observe(q,m)
                elapsed=clock.age(c['held'],c['now'])
                self.report('detect/staleness/'+c['name']+'/age',c['elapsed'],elapsed)
            self.report('detect/staleness/'+c['name'],c['expect'],p.freshness(elapsed,s['staleness'],c.get('hard',s['hard'])))
        d=self.cases('proven')
        for c in d['cases']:
            self.report('proven/'+c['name'],c['proven'],sorted(p.proven(st,c['t'] or None)))
        for id,expected in d['grants'].items(): self.report('proven/grants/'+id,expected,p.grant(st['devices'][id]))
        for id,row in d['bundles'].items():
            b=fresh.bundle(self.read(row['file'])); e=p.envelope(b['entry'],t['net']); r=p.request(e['body']['request'])
            self.report('proven/bundles/'+id+'/index',row['proves_index'],b['index'])
            self.report('proven/bundles/'+id+'/historical-key',row['bundle_wg_pk'],r['wg_pk'].hex())
            self.report('proven/bundles/'+id+'/current-key',row['state_wg_pk'],st['devices'][id]['wg_pk'].hex())
            self.report('proven/bundles/'+id+'/rotated',row['rotated_since'],r['wg_pk']!=st['devices'][id]['wg_pk'])
        d=self.cases('anchors')
        for c in d['cases']:
            if 'over' in c:
                raw=self.read(c['over']); start=raw.index(b'\n\n')+2
                self.report('anchors/'+c['name']+'/digest',c['digest'],p.sha(raw[:start]).hex())
                # §12 supplies digests expressly to avoid requiring an OTS parser.
            else:
                # The unrelated sample has no Norn preimage to hash. Its supplied
                # digest is checked against the detached SHA-256 header bytes.
                raw=self.read('anchors/'+c['name'])
                self.report('anchors/'+c['name']+'/declared-digest',True,bytes.fromhex(c['digest']) in raw)
        discovered={str(f.relative_to(self.v)) for f in self.v.rglob('*') if f.name in ('cases.json','manifest.json')}
        for unknown in sorted(discovered-self.handled): self.report(unknown,'known runner','UNKNOWN')
        self.report('harness/manifest-coverage',sorted(discovered),sorted(self.handled))
        print(f'{self.total} checks, {self.failures} FAIL',flush=True)
        return bool(self.failures)

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--vectors',type=Path,default=Path(__file__).resolve().parents[2]/'vectors')
    args=ap.parse_args(); h=Harness(args.vectors)
    try: return h.run()
    except Exception as ex:
        h.report('harness/fatal','complete',f'{type(ex).__name__}:{ex}'); traceback.print_exc(); return 1

if __name__=='__main__': sys.exit(main())
