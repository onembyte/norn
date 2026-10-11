"""Independent Norn verifier. Rules derived solely from sealed SPEC.md."""
import base64
import hashlib
import ipaddress
import json
import re
from pathlib import Path
import cbor
import ed25519
import merkle
import bech32m

class Refusal(ValueError):
    def __init__(self,code): self.code=code; super().__init__(code)

def require(ok,code='decode'):
    if not ok: raise Refusal(code)

def uint(x): return type(x) is int and 0<=x<2**63

def octets(x,n): return isinstance(x,bytes) and len(x)==n

def text(x,lo=0,hi=None):
    return isinstance(x,str) and len(x.encode('utf-8'))>=lo and (hi is None or len(x.encode('utf-8'))<=hi)

def closed(x,required,optional=()):
    return isinstance(x,dict) and set(required)<=x.keys() and x.keys()<=set(required)|set(optional)

def ident(x): return isinstance(x,str) and re.fullmatch('[a-z0-9][a-z0-9.-]{0,63}',x) is not None

def kid(pk): return hashlib.sha256(pk).digest()[:8].hex()

def kid_ok(x): return isinstance(x,str) and re.fullmatch('[0-9a-f]{16}',x) is not None

def sha(b): return hashlib.sha256(b).digest()

def preimage(e): return b'norn/entry/v1\n'+cbor.dumps({k:v for k,v in e.items() if k!='sigs'})

def request_preimage(r): return b'norn/enroll-request/v1\n'+cbor.dumps({k:v for k,v in r.items() if k!='sig'})

def b64(s):
    require(isinstance(s,str))
    try: b=base64.b64decode(s,validate=True)
    except (ValueError,UnicodeEncodeError): raise Refusal('decode')
    require(base64.b64encode(b).decode()==s)
    return b

def decimal(s):
    require(isinstance(s,str) and re.fullmatch('0|[1-9][0-9]*',s) is not None)
    # Textual sizes/deadlines have no bit-width limit stated in §§6–7.
    # The 63-bit limit belongs to CBOR integers, not decimal note lines.
    return int(s)

def vkey(s,alg):
    require(isinstance(s,str))
    parts=s.split('+',2); require(len(parts)==3)
    name,hexid,data=parts
    require(bool(name) and all(33<=ord(c)<=126 and c!='+' for c in name))
    require(re.fullmatch('[0-9a-f]{8}',hexid) is not None)
    raw=b64(data); require(len(raw)==33 and raw[0]==alg)
    require(ed25519.valid_point(raw[1:]))
    keyid=sha(name.encode()+b'\n'+raw)[:4]
    require(keyid.hex()==hexid)
    return {'name':name,'id':keyid,'pk':raw[1:],'alg':alg,'text':s}

def make_vkey(name,pk,alg=1):
    raw=bytes([alg])+pk
    return name+'+'+sha(name.encode()+b'\n'+raw)[:4].hex()+'+'+base64.b64encode(raw).decode()

class Policy:
    def __init__(self,s):
        require(text(s) and (not s or s.endswith('\n')))
        require(not any((ord(c)<32 and c not in '\t\n') or ord(c)==127 for c in s))
        self.witnesses={}; self.groups={}; self.logs=[]; self.quorum=None
        names={'none'}; keys=set()
        for line in s.split('\n'):
            line=line.strip(' \t')
            if not line or line.startswith('#'): continue
            f=re.split('[ \t]+',line); cmd=f[0]
            if cmd in ('log','witness'):
                require(len(f) in ((2,3) if cmd=='log' else (3,4)))
                k=vkey(f[1] if cmd=='log' else f[2],1 if cmd=='log' else 4)
                require(k['pk'] not in keys); keys.add(k['pk'])
                if cmd=='log': self.logs.append(k)
                else:
                    name=f[1]; require(name not in names); names.add(name); self.witnesses[name]=k
            elif cmd=='group':
                require(len(f)>=4)
                name=f[1]; threshold=f[2]; members=f[3:]
                require(name not in names and len(set(members))==len(members))
                require(all(m in names and m!='none' for m in members))
                k=len(members) if threshold=='all' else 1 if threshold=='any' else decimal(threshold)
                require(1<=k<=len(members)); names.add(name); self.groups[name]=(k,members)
            elif cmd=='quorum':
                require(len(f)==2 and self.quorum is None and f[1] in names)
                self.quorum=f[1]
            else: raise Refusal('decode')
        require(self.quorum is not None)
    def satisfied(self,cosigners):
        def sat(n):
            if n=='none': return True
            if n in self.witnesses: return n in cosigners
            k,ms=self.groups[n]; return sum(sat(m) for m in ms)>=k
        return sat(self.quorum)
    def quorum_time(self,times):
        if self.quorum=='none': return None
        for t in sorted(set(times.values()),reverse=True):
            if self.satisfied({n for n,v in times.items() if v>=t}): return t
        return None

def trust(raw):
    t=cbor.loads(raw,65536)
    require(closed(t,('version','net','origin','name','genesis_hash','log_key','log_urls','witnesses','policy'),('anchor',)))
    require(uint(t['version']) and t['version']==1 and octets(t['net'],16) and octets(t['genesis_hash'],32))
    require(text(t['name'],1,64))
    origin='norn/'+base64.b32encode(t['net']).decode().lower().rstrip('=')
    require(t['origin']==origin)
    lk=vkey(t['log_key'],1); require(lk['name']==origin)
    require(isinstance(t['log_urls'],list) and t['log_urls'] and all(text(u,1) for u in t['log_urls']))
    require(isinstance(t['witnesses'],list) and t['witnesses'])
    ws={}
    for w in t['witnesses']:
        require(closed(w,('name','key'),('url',)) and text(w['name'],1,64))
        require(w['name'] not in ws and ('url' not in w or text(w['url'])))
        ws[w['name']]=vkey(w['key'],4)['text']
    p=Policy(t['policy'])
    require(ws=={n:k['text'] for n,k in p.witnesses.items()})
    require(all(k['text']==lk['text'] for k in p.logs))
    if 'anchor' in t:
        a=t['anchor']; require(closed(a,('type','mode','max_lag')))
        require(text(a['type']) and a['mode']=='advisory' and uint(a['max_lag']))
    return t

def fingerprint(raw):
    abc='0123456789ABCDEFGHJKMNPQRSTVWXYZ'; n=int.from_bytes(sha(raw)[:10],'big')
    s=''.join(abc[(n>>(5*(15-i)))&31] for i in range(16))
    return '-'.join(s[i:i+4] for i in range(0,16,4))+'\n'

def labels(x):
    require(isinstance(x,dict) and 1<=len(x)<=32)
    require(all(text(k,1,23) and text(v,0,256) for k,v in x.items()))

def request(raw,net=None,check_sig=True):
    r=cbor.loads(raw)
    require(closed(r,('v','ts','net','sig','wg_pk','device_id','device_pk'),('labels','expires')))
    require(uint(r['v']) and r['v']==1 and uint(r['ts']) and octets(r['net'],16))
    require(net is None or r['net']==net)
    require(octets(r['sig'],64) and octets(r['wg_pk'],32) and ident(r['device_id']))
    require(ed25519.valid_point(r['device_pk']))
    if 'labels' in r: labels(r['labels'])
    if 'expires' in r: require(uint(r['expires']) and r['expires']>r['ts'])
    if check_sig: require(ed25519.verify(r['device_pk'],request_preimage(r),r['sig']),'no-device-sig')
    return r

def request_text(s): return request(bech32m.payload(s))

DEFAULTS={'checkpoint_interval':60,'staleness':600,'mmd':60,'rotate_needs_signer':False,'routes':'granted'}
GOV={'signer_add','signer_remove','signer_thr','root_add','root_remove','root_thr','log_key','policy','params'}
TYPES=GOV|{'genesis','enroll','rotate','revoke','note'}

def params(b):
    require(isinstance(b,dict) and b and b.keys()<=DEFAULTS.keys())
    for k,v in b.items():
        require(type(v) is bool if k=='rotate_needs_signer' else v in ('granted','advisory') and type(v) is str if k=='routes' else uint(v))

def envelope(raw,net):
    e=cbor.loads(raw)
    require(closed(e,('v','t','net','ts','body','sigs'),('after',)))
    require(uint(e['v']) and e['v']==1 and text(e['t']) and octets(e['net'],16) and e['net']==net)
    require(uint(e['ts']) and isinstance(e['body'],dict) and isinstance(e['sigs'],list))
    require('after' not in e or uint(e['after']))
    prev=''
    for s in e['sigs']:
        require(closed(s,('kid','role','sig')) and kid_ok(s['kid']) and s['kid']>prev)
        require(s['role'] in ('root','signer','device') and octets(s['sig'],64)); prev=s['kid']
    return e

def body(e):
    b=e['body']; t=e['t']
    fields={
      'genesis':(('name','roots','root_thr','signers','signer_thr'),('params',)),
      'enroll':(('request',),()),'rotate':(('device_id','wg_pk'),('device_pk',)),
      'revoke':(('device_id',),('reason',)),
      'root_add':(('pk',),()),'signer_add':(('pk',),()),
      'root_remove':(('kid',),()),'signer_remove':(('kid',),()),
      'root_thr':(('thr',),()),'signer_thr':(('thr',),()),
      'log_key':(('pk','overlap'),()),'policy':(('text',),()),'note':(('text',),())}
    if t=='params': params(b); return b
    require(closed(b,*fields[t]))
    for k,v in b.items():
        if k=='device_id': require(ident(v))
        elif k in ('pk','device_pk'): require(ed25519.valid_point(v))
        elif k=='wg_pk': require(octets(v,32))
        elif k=='kid': require(kid_ok(v))
        elif k in ('thr','overlap','root_thr','signer_thr'): require(uint(v))
        elif k=='request': require(isinstance(v,bytes))
        elif k=='text': require(text(v,0,4096))
        elif k=='reason': require(text(v,0,256))
        elif k=='name': require(text(v,1,64))
        elif k in ('roots','signers'):
            require(isinstance(v,list) and v and all(ed25519.valid_point(pk) for pk in v))
            require(len(set(v))==len(v))
        elif k=='params': params(v)
    if t=='policy': Policy(b['text'])
    return b

def zero(anchor):
    return dict(name='',net=anchor['net'],size=0,root_thr=0,signer_thr=0,roots={},signers={},params=DEFAULTS.copy(),policy='',log_keys=[],devices={},active_wg={},rejected=[])

def signatures(e,keys,role):
    msg=preimage(e)
    return {s['kid'] for s in e['sigs'] if s['role']==role and s['kid'] in keys and ed25519.verify(keys[s['kid']],msg,s['sig'])}

def replay(anchor,entries):
    st=zero(anchor); seen=set()
    for i,raw in enumerate(entries):
        e=None
        try: e=envelope(raw,anchor['net'])
        except (ValueError,TypeError): pass
        duplicate=sha(preimage(e)) if e is not None else sha(raw)
        try:
            require(duplicate not in seen,'dup-entry'); seen.add(duplicate)
            require(e is not None)
            t=e['t']; b=e['body']
            if i==0:
                require(t=='genesis' and merkle.leaf(raw)==anchor['genesis_hash'])
                require(e.get('after',0)==0); body(e)
                require(not set(b['roots'])&set(b['signers']))
                require(1<=b['root_thr']<=len(b['roots']) and 1<=b['signer_thr']<=len(b['signers']))
                ks={kid(pk):pk for pk in b['roots']}
                require(len(signatures(e,ks,'root'))>=b['root_thr'])
                st.update(name=b['name'],roots=ks,signers={kid(pk):pk for pk in b['signers']},root_thr=b['root_thr'],signer_thr=b['signer_thr'])
                st['params'].update(b.get('params',{}))
            else:
                require(t in TYPES,'unknown-type'); require(t!='genesis','dup-genesis')
                require(e.get('after',0)<=i,'after')
                rs=signatures(e,st['roots'],'root'); ss=signatures(e,st['signers'],'signer')
                root_ok=len(rs)>=st['root_thr']; signer_ok=len(ss)>=st['signer_thr']
                if t in GOV: require(root_ok,'threshold')
                if t=='note': require(rs or ss,'threshold')
                body(e)
                if t=='enroll':
                    r=request(b['request'],anchor['net'],False)
                    require(ed25519.verify(r['device_pk'],request_preimage(r),r['sig']),'no-device-sig')
                    require(signer_ok,'threshold'); id=r['device_id']
                    require(id not in st['devices'] or st['devices'][id]['status']!='active','dup-id')
                    require(r['wg_pk'] not in st['active_wg'],'dup-wg')
                    st['devices'][id]={k:r[k] for k in ('wg_pk','device_pk')}
                    st['devices'][id].update(status='active',since_index=i,labels=r.get('labels',{}),expires=r.get('expires',0))
                elif t in ('rotate','revoke'):
                    id=b['device_id']; require(id in st['devices'],'unknown-device'); d=st['devices'][id]
                    require(d['status']=='active','not-active')
                    current=d['device_pk']; ds=signatures(e,{kid(current):current},'device')
                    if t=='revoke':
                        require(root_ok or signer_ok or ds,'threshold'); d.update(status='revoked',since_index=i)
                    else:
                        require(ds,'no-device-sig')
                        if st['params']['rotate_needs_signer']: require(signer_ok,'threshold')
                        require(b['wg_pk'] not in st['active_wg'] or st['active_wg'][b['wg_pk']]==id,'dup-wg')
                        if 'device_pk' in b:
                            incoming=b['device_pk']; require(signatures(e,{kid(incoming):incoming},'device'),'no-device-sig'); d['device_pk']=incoming
                        d['wg_pk']=b['wg_pk']
                elif t in ('root_add','signer_add'):
                    k=kid(b['pk']); require(k not in st['roots'] and k not in st['signers'],'dup-key')
                    st['roots' if t=='root_add' else 'signers'][k]=b['pk']
                elif t in ('root_remove','signer_remove'):
                    ks=st['roots' if t=='root_remove' else 'signers']; require(b['kid'] in ks,'unknown-key')
                    if t=='root_remove': require(len(ks)-1>=st['root_thr'],'root-invariant')
                    del ks[b['kid']]
                elif t in ('root_thr','signer_thr'):
                    ks=st['roots' if t=='root_thr' else 'signers']; require(1<=b['thr']<=len(ks),'bad-thr'); st[t]=b['thr']
                elif t=='params': st['params'].update(b)
                elif t=='policy': st['policy']=b['text']
                elif t=='log_key': st['log_keys'].append(dict(pk=b['pk'],overlap=b['overlap'],since_index=i))
            st['active_wg']={d['wg_pk']:id for id,d in st['devices'].items() if d['status']=='active'}
        except (ValueError,TypeError) as ex:
            if i==0:
                st=zero(anchor); st['rejected']=[dict(index=0,reason='bad-genesis')]; return st
            st['rejected'].append(dict(index=i,reason=ex.code if isinstance(ex,Refusal) else 'decode'))
        st['size']=i+1
    return st

def jsonable(x):
    if isinstance(x,bytes): return x.hex()
    if isinstance(x,list): return list(map(jsonable,x))
    if isinstance(x,dict): return {(k.hex() if isinstance(k,bytes) else k):jsonable(v) for k,v in x.items()}
    return x

def canonical_json(x):
    # Unicode scalar order agrees with UTF-8 byte order for valid Unicode text.
    return (json.dumps(jsonable(x),sort_keys=True,ensure_ascii=False,separators=(',',':'))+'\n').encode('utf-8')

class Reader:
    def __init__(self,t,state=None):
        self.trust=t; self.log_keys=[vkey(t['log_key'],1)]
        if state:
            self.log_keys += [vkey(make_vkey(t['origin'],k['pk']),1) for k in state['log_keys']]
        self.policy=Policy(state['policy'] if state and state['policy'] else t['policy'])
    def log_verify(self,signed,lines):
        found=False
        for name,payload in lines:
            matches=[k for k in self.log_keys if name==k['name'] and payload[:4]==k['id']]
            if matches:
                found=True
                require(len(payload)==68 and ed25519.verify(matches[0]['pk'],signed,payload[4:]),'log-signature')
        require(found,'log-signature')
    def checkpoint(self,raw):
        signed,lines=note(raw); self.log_verify(signed,lines)
        try:
            f=signed.decode().split('\n')[:-1]; require(len(f)==3)
            size=decimal(f[1]); h=b64(f[2]); require(len(h)==32)
        except (ValueError,TypeError): raise Refusal('checkpoint')
        require(f[0]==self.trust['origin'],'origin')
        times={}
        for name,payload in lines:
            for short,k in self.policy.witnesses.items():
                if k['name']!=name or k['id']!=payload[:4]: continue
                require(len(payload)==76,'cosignature')
                t=int.from_bytes(payload[4:12],'big')
                msg=b'cosignature/v1\ntime '+str(t).encode()+b'\n'+signed
                require(ed25519.verify(k['pk'],msg,payload[12:]),'cosignature')
                times[short]=max(t,times.get(short,0))
        require(self.policy.satisfied(set(times)),'quorum')
        return dict(origin=f[0],size=size,root=h,quorum_time=self.policy.quorum_time(times),times=times)
    def receipt(self,raw,submitted=None,now=0):
        signed,lines=note(raw); self.log_verify(signed,lines)
        f=signed.decode().split('\n')[:-1]
        require(len(f)==4 and f[0]=='norn/receipt/v1','receipt')
        require(f[1]==self.trust['origin'],'origin')
        try: h=b64(f[2]); require(len(h)==32)
        except ValueError: raise Refusal('leaf-hash')
        try: deadline=decimal(f[3])
        except ValueError: raise Refusal('deadline')
        require(submitted is None or h==submitted,'entry')
        require(not now or now<deadline,'expired')
        return dict(leaf_hash=h,deadline=deadline,signed=signed)
    def bundle(self,raw):
        try:
            b=cbor.loads(raw,81919)
            require(closed(b,('v','device','index','entry','proof','checkpoint')))
            require(uint(b['v']) and b['v']==1 and ident(b['device']) and uint(b['index']))
            require(isinstance(b['entry'],bytes) and len(b['entry'])<=65535 and text(b['checkpoint']) and hashes(b['proof']))
        except (ValueError,TypeError): raise Refusal('bundle')
        cp=self.checkpoint(b['checkpoint'].encode())
        require(merkle.inclusion(merkle.leaf(b['entry']),b['index'],cp['size'],b['proof'],cp['root']),'inclusion')
        try:
            e=envelope(b['entry'],self.trust['net']); body(e)
            id=request(e['body']['request'],self.trust['net'],False)['device_id'] if e['t']=='enroll' else e['body'].get('device_id')
            require(id==b['device'])
        except (ValueError,TypeError,KeyError): raise Refusal('binding')
        return b
    def evidence(self,raw):
        require(len(raw)<=65536,'oversize')
        try: e=cbor.loads(raw,65536); require(isinstance(e,dict))
        except ValueError: raise Refusal('cbor')
        require(uint(e.get('version')) and e['version'] in (1,2),'version')
        fields={'version','held','conflicting','size','held_root','proof','policy'}
        if e['version']==2: fields|={'split','split_root','split_proof_held','split_proof_conflicting'}
        require(set(e)==fields,'schema')
        require(uint(e['size']) and octets(e['held_root'],32) and hashes(e['proof']) and all(text(e[k]) for k in ('held','conflicting','policy')),'schema')
        if e['version']==2:
            require(uint(e['split']) and octets(e['split_root'],32) and hashes(e['split_proof_held']) and hashes(e['split_proof_conflicting']),'schema')
        try: Policy(e['policy'])
        except ValueError: raise Refusal('policy')
        try: h=self.checkpoint(e['held'].encode())
        except ValueError: raise Refusal('held')
        try: c=self.checkpoint(e['conflicting'].encode())
        except ValueError: raise Refusal('conflicting')
        require(e['size']<=h['size'] and e['size']==c['size'],'size')
        require(merkle.consistency(e['size'],h['size'],e['held_root'],h['root'],e['proof']),'proof')
        # §11.1 closed-code table places all split proof checks before consistent.
        if e['version']==2:
            s=e['split']; require(s<=e['size'],'proof')
            if s==0:
                require(e['split_root']==bytes(32) and not e['split_proof_held'] and not e['split_proof_conflicting'],'proof')
            else:
                require(merkle.consistency(s,h['size'],e['split_root'],h['root'],e['split_proof_held']),'proof')
                require(merkle.consistency(s,c['size'],e['split_root'],c['root'],e['split_proof_conflicting']),'proof')
        require(e['held_root']!=c['root'],'consistent')
        return e
    def served(self,source,checkpoint=None,stored=None,held_entries=None):
        fetch=source if callable(source) else lambda p: (Path(source)/p).read_bytes()
        def read(p):
            try: return fetch(p)
            except (OSError,KeyError): raise Refusal('unserved')
        cp=self.checkpoint(checkpoint if checkpoint is not None else read('checkpoint'))
        n=cp['size']; entries=[]
        for start in range(0,n,256):
            w=min(n-start,256); data=read(tile_path('entries',start//256,w)); pos=0; batch=[]
            while pos<len(data):
                require(pos+2<=len(data),'entries'); sz=int.from_bytes(data[pos:pos+2],'big'); pos+=2
                require(pos+sz<=len(data),'entries'); batch.append(data[pos:pos+sz]); pos+=sz
            require(len(batch)==w,'entries'); entries+=batch
        hs=list(map(merkle.leaf,entries)); require(merkle.root(hs)==cp['root'],'head')
        if stored:
            at=min(n,stored['size']); mine=None
            if at==stored['size']: mine=stored['root']
            elif held_entries is not None and len(held_entries)>=at: mine=merkle.root(list(map(merkle.leaf,held_entries[:at])))
            if mine is not None: require(merkle.root(hs[:at])==mine,'fork')
            require(n>=stored['size'],'rollback')
        require(entries and replay(self.trust,entries[:1])['size']==1,'genesis')
        level=0; row=hs
        while row:
            for start in range(0,len(row),256):
                tile=row[start:start+256]
                require(read(tile_path(level,start//256,len(tile)))==b''.join(tile),'tiles')
            row=[merkle.root(row[i:i+256]) for i in range(0,len(row)-255,256)]
            level+=1
        state=replay(self.trust,entries)
        return dict(checkpoint=cp,entries=entries,state=state,proven=proven(state,cp['quorum_time']))

def hashes(x): return isinstance(x,list) and all(octets(h,32) for h in x)

def note(raw):
    try:
        s=raw.decode('utf-8'); require('\n\n' in s and s.endswith('\n'))
        signed,block=s.split('\n\n',1); signed+='\n'
        require(signed!='\n' and block and all(signed.split('\n')[:-1]))
        lines=[]
        for line in block.split('\n')[:-1]:
            require(line.startswith('— ')); tail=line[2:]; require(' ' in tail)
            name,data=tail.split(' ',1); require(bool(name)); payload=b64(data); require(len(payload)>=4)
            lines.append((name,payload))
        require(lines); return signed.encode(),lines
    except (ValueError,UnicodeError,TypeError): raise Refusal('note')

def tile_path(level,index,width=256):
    require(uint(index) and 1<=width<=256)
    groups=[f'{index%1000:03d}']; index//=1000
    while index: groups.insert(0,f'x{index%1000:03d}'); index//=1000
    p='tile/'+str(level)+'/'+'/'.join(groups)
    return p if width==256 else p+'.p/'+str(width)

def proven(state,t):
    return {id:d for id,d in state['devices'].items() if d['status']=='active' and (t is None or not d['expires'] or d['expires']>t)}

def grant(d):
    try:
        s=d['labels'].get('ip',''); parts=s.split(','); nets=[]
        for part in parts:
            n=ipaddress.ip_network(part.strip(),strict=False)
            if n.version==6 and n.network_address.ipv4_mapped is not None: return []
            nets.append(str(n))
        return sorted(set(nets))
    except ValueError: return []

def freshness(elapsed,staleness,hard=0):
    if elapsed is None: return 'unknown'
    if hard and elapsed>hard: return 'hard_stale'
    return 'fresh' if elapsed<=staleness else 'degraded'

class WitnessClock:
    def __init__(self,persisted=None): self.bounds=[] if persisted is None else [(persisted,0)]
    def observe(self,q,monotonic):
        if q is not None: self.bounds.append((q,monotonic))
    def now(self,m): return max((q+m-at for q,at in self.bounds),default=None)
    def age(self,q,m):
        now=self.now(m)
        return None if q is None or now is None else max(0,now-q)
