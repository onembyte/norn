"""Independent Norn v1 verifier, implemented from SPEC.md only.

The filesystem reader accepts a local mirror or explicit byte overlays. It
never performs network I/O. Refused operations raise Refusal with closed codes.
"""
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
    def __init__(self,code,detail=''):
        self.code,self.detail=code,detail
        super().__init__(code+(': '+detail if detail else ''))

def require(condition,code='decode',detail=''):
    if not condition: raise Refusal(code,detail)

def uint(x): return type(x)==int and 0<=x<=2**63-1

def blob(x,n): return type(x)==bytes and len(x)==n

def text(x,low=0,high=None):
    return type(x)==str and low<=len(x.encode('utf-8')) and (high is None or len(x.encode('utf-8'))<=high)

def closed(x,required,optional=(),code='decode'):
    require(type(x)==dict and set(required)<=set(x)<=set(required)|set(optional),code)

def decimal(s):
    require(type(s)==str and re.fullmatch(r'0|[1-9][0-9]*',s) is not None,'decimal')
    return int(s)

def b64(s):
    try:
        b=base64.b64decode(s,validate=True)
        require(base64.b64encode(b).decode()==s,'base64')
        return b
    except (ValueError,TypeError):
        raise Refusal('base64') from None

def kid(pk): return hashlib.sha256(pk).digest()[:8].hex()

def preimage(e): return b'norn/entry/v1\n'+cbor.dumps({k:v for k,v in e.items() if k!='sigs'})

def json_bytes(obj):
    def normalize(x):
        if type(x)==bytes: return x.hex()
        if type(x)==list: return [normalize(v) for v in x]
        if type(x)==dict: return {k.hex() if type(k)==bytes else k:normalize(v) for k,v in x.items()}
        return x
    # Unicode scalar order equals UTF-8 bytewise order for valid UTF-8 strings.
    return (json.dumps(normalize(obj),sort_keys=True,ensure_ascii=False,separators=(',',':'))+'\n').encode('utf-8')

def vkey(s,alg=None):
    try:
        name,ident,data=s.split('+',2)
        require(name and not any(c.isspace() or c=='+' for c in name),'key')
        require(re.fullmatch('[0-9a-fA-F]{8}',ident) is not None,'key')
        raw=b64(data)
        require(len(raw)==33 and raw[0] in (1,4),'key')
        require(alg is None or raw[0]==alg,'key')
        computed=hashlib.sha256(name.encode()+b'\n'+raw).digest()[:4]
        require(bytes.fromhex(ident)==computed,'key')
        return {'name':name,'id':computed,'alg':raw[0],'pk':raw[1:]}
    except (ValueError,TypeError,AttributeError):
        raise Refusal('key') from None

def make_vkey(name,pk,alg=1):
    raw=bytes([alg])+pk
    return name+'+'+hashlib.sha256(name.encode()+b'\n'+raw).digest()[:4].hex()+'+'+base64.b64encode(raw).decode()

class Policy:
    def __init__(self,s):
        require(type(s)==str,'policy')
        raw=s.encode('utf-8')
        require(not any(b<32 and b not in (9,10) or b==127 for b in raw),'policy')
        require(s.endswith('\n'),'policy')
        self.witnesses={}; self.groups={}; self.logs=[]; self.quorum=None
        names={'none'}; public=set()
        for line in s.split('\n')[:-1]:
            line=line.strip(' \t')
            if not line or line.startswith('#'): continue
            fields=re.split('[ \t]+',line); command=fields[0]; f=fields[1:]
            if command in ('witness','log'):
                require(len(f) in ((2,3) if command=='witness' else (1,2)),'policy')
                key=vkey(f[1] if command=='witness' else f[0],4 if command=='witness' else 1)
                require(key['pk'] not in public,'policy'); public.add(key['pk'])
                if command=='log': self.logs.append(key)
                else:
                    require(f[0] not in names,'policy'); names.add(f[0]); self.witnesses[f[0]]=key
            elif command=='group':
                require(len(f)>=3 and f[0] not in names,'policy')
                members=f[2:]
                require(len(set(members))==len(members) and all(m in names and m!='none' for m in members),'policy')
                try: k=len(members) if f[1]=='all' else 1 if f[1]=='any' else decimal(f[1])
                except ValueError: raise Refusal('policy') from None
                require(1<=k<=len(members),'policy')
                self.groups[f[0]]=(k,members); names.add(f[0])
            elif command=='quorum':
                require(len(f)==1 and self.quorum is None and f[0] in names,'policy')
                self.quorum=f[0]
            else: raise Refusal('policy')
        require(self.quorum is not None,'policy')
    def satisfied(self,cosigners):
        def met(name):
            if name=='none': return True
            if name in self.groups:
                k,members=self.groups[name]
                return sum(met(m) for m in members)>=k
            return name in cosigners
        return met(self.quorum)
    def time(self,timestamps):
        if self.quorum=='none': return None
        for t in sorted(set(timestamps.values()),reverse=True):
            if self.satisfied({n for n,v in timestamps.items() if v>=t}): return t
        return None

def trust(data):
    try:
        t=cbor.loads(data,65536)
        closed(t,('version','net','origin','name','genesis_hash','log_key','log_urls','witnesses','policy'),('anchor',),'trust')
        require(uint(t['version']) and t['version']==1 and blob(t['net'],16) and blob(t['genesis_hash'],32),'trust')
        require(text(t['name'],1,64),'trust')
        origin='norn/'+base64.b32encode(t['net']).decode().lower().rstrip('=')
        require(t['origin']==origin,'trust')
        key=vkey(t['log_key'],1); require(key['name']==origin,'trust')
        require(type(t['log_urls'])==list and len(t['log_urls'])>=1 and all(text(s,1) for s in t['log_urls']),'trust')
        require(type(t['witnesses'])==list and len(t['witnesses'])>=1,'trust')
        ws={}
        for w in t['witnesses']:
            closed(w,('name','key'),('url',),'trust')
            require(text(w['name'],1,64) and w['name'] not in ws,'trust')
            require('url' not in w or text(w['url']),'trust')
            ws[w['name']]=vkey(w['key'],4)
        p=Policy(t['policy'])
        require(p.witnesses==ws and all(k==key for k in p.logs),'trust')
        if 'anchor' in t:
            a=t['anchor']; closed(a,('type','max_lag','mode'),code='trust')
            require(text(a['type']) and uint(a['max_lag']) and a['mode']=='advisory','trust')
        return t
    except (ValueError,TypeError): raise Refusal('trust') from None

def fingerprint(data):
    alphabet='0123456789ABCDEFGHJKMNPQRSTVWXYZ'
    n=int.from_bytes(hashlib.sha256(data).digest()[:10],'big')
    s=''.join(alphabet[(n>>(5*(15-i)))&31] for i in range(16))
    return '-'.join(s[i:i+4] for i in range(0,16,4))+'\n'

DEFAULTS={'checkpoint_interval':60,'staleness':600,'mmd':60,'rotate_needs_signer':False,'routes':'granted'}
TYPES={'genesis','enroll','rotate','revoke','signer_add','signer_remove','signer_thr','root_add','root_remove','root_thr','log_key','policy','params','note'}
GOV=TYPES-{'genesis','enroll','rotate','revoke','note'}

def params(p):
    require(type(p)==dict and p and set(p)<=set(DEFAULTS))
    for k,v in p.items():
        require(type(v)==bool if k=='rotate_needs_signer' else v in ('granted','advisory') if k=='routes' else uint(v))

def labels(l):
    require(type(l)==dict and len(l)<=32 and all(text(k,1,23) and text(v,0,256) for k,v in l.items()))

def device_id(s): return text(s) and re.fullmatch('[a-z0-9][a-z0-9.-]{0,63}',s) is not None

def request(data,net=None,verify=True):
    try: r=cbor.loads(data)
    except ValueError: raise Refusal('decode') from None
    closed(r,('v','ts','net','sig','wg_pk','device_id','device_pk'),('labels','expires'))
    require(uint(r['v']) and r['v']==1 and uint(r['ts']) and blob(r['net'],16) and (net is None or r['net']==net))
    require(blob(r['sig'],64) and blob(r['wg_pk'],32) and blob(r['device_pk'],32) and device_id(r['device_id']))
    if 'labels' in r: labels(r['labels'])
    if 'expires' in r: require(uint(r['expires']) and r['expires']>r['ts'])
    if verify:
        msg=b'norn/enroll-request/v1\n'+cbor.dumps({k:v for k,v in r.items() if k!='sig'})
        require(ed25519.verify(r['device_pk'],msg,r['sig']),'no-device-sig')
    return r

def request_text(s,net=None): return request(bech32m.payload(s),net)

def envelope(data,net):
    try: e=cbor.loads(data)
    except ValueError: raise Refusal('decode') from None
    closed(e,('v','t','net','ts','body','sigs'),('after',))
    require(uint(e['v']) and e['v']==1 and text(e['t']) and e['net']==net and blob(e['net'],16) and uint(e['ts']) and type(e['body'])==dict)
    require('after' not in e or uint(e['after']))
    require(type(e['sigs'])==list)
    previous=''
    for sig in e['sigs']:
        closed(sig,('kid','role','sig'))
        require(text(sig['kid']) and re.fullmatch('[0-9a-f]{16}',sig['kid']) is not None and sig['kid']>previous)
        previous=sig['kid']
        require(sig['role'] in ('root','signer','device') and blob(sig['sig'],64))
    return e

def valid_sigs(e,keys,role):
    msg=preimage(e)
    return {s['kid'] for s in e['sigs'] if s['role']==role and s['kid'] in keys and ed25519.verify(keys[s['kid']],msg,s['sig'])}

def zero(net):
    return {'name':'','net':net,'size':0,'root_thr':0,'signer_thr':0,'roots':{},'signers':{},'params':DEFAULTS.copy(),'policy':'','log_keys':[],'devices':{},'active_wg':{},'rejected':[]}

def replay(anchor,entries):
    state=zero(anchor['net']); seen=set()
    for i,raw in enumerate(entries):
        e=None
        try: e=envelope(raw,anchor['net'])
        except Refusal: pass
        duplicate=hashlib.sha256(preimage(e) if e is not None else raw).digest()
        try:
            require(duplicate not in seen,'dup-entry'); seen.add(duplicate)
            require(e is not None)
            t,b=e['t'],e['body']
            if i==0:
                require(t=='genesis' and merkle.leaf(raw)==anchor['genesis_hash'])
                require(e.get('after',0)==0)
                closed(b,('name','roots','root_thr','signers','signer_thr'),('params',))
                require(text(b['name'],1,64))
                for role in ('roots','signers'):
                    keys=b[role]
                    require(type(keys)==list and all(blob(k,32) for k in keys) and len(set(keys))==len(keys))
                require(not set(b['roots'])&set(b['signers']))
                for role,thr in [('roots','root_thr'),('signers','signer_thr')]:
                    require(uint(b[thr]) and 1<=b[thr]<=len(b[role]))
                if 'params' in b: params(b['params'])
                roots={kid(p):p for p in b['roots']}
                require(len(valid_sigs(e,roots,'root'))>=b['root_thr'])
                state.update(name=b['name'],roots=roots,signers={kid(p):p for p in b['signers']},root_thr=b['root_thr'],signer_thr=b['signer_thr'])
                state['params'].update(b.get('params',{}))
            else:
                require(t in TYPES,'unknown-type'); require(t!='genesis','dup-genesis')
                require(e.get('after',0)<=i,'after')
                roots=valid_sigs(e,state['roots'],'root')
                signers=valid_sigs(e,state['signers'],'signer')
                rq=len(roots)>=state['root_thr']; sq=len(signers)>=state['signer_thr']
                if t in GOV: require(rq,'threshold')
                if t=='note': require(roots or signers,'threshold')
                if t=='enroll':
                    closed(b,('request',)); require(type(b['request'])==bytes)
                    r=request(b['request'],e['net'])
                    require(sq,'threshold'); ident=r['device_id']
                    require(ident not in state['devices'] or state['devices'][ident]['status']!='active','dup-id')
                    require(r['wg_pk'] not in state['active_wg'],'dup-wg')
                    state['devices'][ident]={'device_pk':r['device_pk'],'wg_pk':r['wg_pk'],'status':'active','since_index':i,'labels':r.get('labels',{}),'expires':r.get('expires',0)}
                elif t in ('rotate','revoke'):
                    closed(b,('device_id','wg_pk') if t=='rotate' else ('device_id',),('device_pk',) if t=='rotate' else ('reason',))
                    require(device_id(b['device_id']))
                    if t=='rotate': require(blob(b['wg_pk'],32) and ('device_pk' not in b or blob(b['device_pk'],32)))
                    else: require('reason' not in b or text(b['reason'],0,256))
                    ident=b['device_id']; require(ident in state['devices'],'unknown-device'); d=state['devices'][ident]
                    require(d['status']=='active','not-active')
                    device=bool(valid_sigs(e,{kid(d['device_pk']):d['device_pk']},'device'))
                    if t=='revoke':
                        require(sq or rq or device,'threshold'); d.update(status='revoked',since_index=i)
                    else:
                        require(device,'no-device-sig')
                        if state['params']['rotate_needs_signer']: require(sq,'threshold')
                        require(b['wg_pk'] not in state['active_wg'] or state['active_wg'][b['wg_pk']]==ident,'dup-wg')
                        if 'device_pk' in b: require(valid_sigs(e,{kid(b['device_pk']):b['device_pk']},'device'),'no-device-sig')
                        d['wg_pk']=b['wg_pk']
                        if 'device_pk' in b: d['device_pk']=b['device_pk']
                elif t in ('root_add','signer_add'):
                    closed(b,('pk',)); require(blob(b['pk'],32)); k=kid(b['pk'])
                    require(k not in state['roots'] and k not in state['signers'],'dup-key')
                    state['roots' if t=='root_add' else 'signers'][k]=b['pk']
                elif t in ('root_remove','signer_remove'):
                    closed(b,('kid',)); require(text(b['kid']) and re.fullmatch('[0-9a-f]{16}',b['kid']) is not None)
                    keys=state['roots' if t=='root_remove' else 'signers']; require(b['kid'] in keys,'unknown-key')
                    if t=='root_remove': require(len(keys)-1>=max(state['root_thr'],1),'root-invariant')
                    del keys[b['kid']]
                elif t in ('root_thr','signer_thr'):
                    closed(b,('thr',)); require(uint(b['thr']))
                    require(1<=b['thr']<=len(state['roots' if t=='root_thr' else 'signers']),'bad-thr'); state[t]=b['thr']
                elif t=='log_key':
                    closed(b,('pk','overlap')); require(blob(b['pk'],32) and uint(b['overlap']))
                    state['log_keys'].append(dict(b,since_index=i))
                elif t=='params': params(b); state['params'].update(b)
                elif t in ('note','policy'):
                    closed(b,('text',)); require(text(b['text'],0,4096))
                    if t=='policy':
                        try: Policy(b['text'])
                        except ValueError: raise Refusal('decode') from None
                        state['policy']=b['text']
            state['active_wg']={d['wg_pk']:ident for ident,d in state['devices'].items() if d['status']=='active'}
        except Refusal as error:
            if i==0:
                state=zero(anchor['net']); state['rejected']=[{'index':0,'reason':'bad-genesis'}]; return state
            state['rejected'].append({'index':i,'reason':error.code})
        state['size']=i+1
    return state

def note(data):
    try:
        if type(data)==str: data=data.encode('utf-8')
        require(data.endswith(b'\n') and b'\n\n' in data,'note')
        signed,block=data.split(b'\n\n',1); signed+=b'\n'
        require(signed and all(signed[:-1].split(b'\n')) and block,'note')
        lines=block[:-1].decode('utf-8').split('\n'); sigs=[]
        for line in lines:
            require(line.startswith('\u2014 '),'note')
            name,payload=line[2:].split(' ',1)
            require(name and not any(c.isspace() for c in name),'note')
            raw=b64(payload); require(len(raw) in (68,76),'note')
            sigs.append((name,raw))
        require(sigs,'note'); signed.decode('utf-8')
        return signed,sigs
    except (ValueError,TypeError): raise Refusal('note') from None

def log_signatures(signed,sigs,keys):
    found=False
    for name,raw in sigs:
        for key in keys:
            if name==key['name'] and raw[:4]==key['id']:
                found=True
                require(len(raw)==68 and ed25519.verify(key['pk'],signed,raw[4:]),'log-signature')
    require(found,'log-signature')

def checkpoint(data,t,accepted=None):
    signed,sigs=note(data)
    keys=[vkey(t['log_key'],1)]
    if accepted:
        keys += [vkey(make_vkey(t['origin'],k['pk']),1) for k in accepted['log_keys']]
    log_signatures(signed,sigs,keys)
    try:
        lines=signed.decode('utf-8').split('\n')[:-1]
        require(len(lines)==3,'checkpoint')
        size=decimal(lines[1]); root=b64(lines[2]); require(len(root)==32,'checkpoint')
    except ValueError: raise Refusal('checkpoint') from None
    require(lines[0]==t['origin'],'origin')
    p=Policy(accepted['policy'] if accepted and accepted['policy'] else t['policy'])
    times={}
    for name,raw in sigs:
        for witness,key in p.witnesses.items():
            if name==key['name'] and raw[:4]==key['id']:
                require(len(raw)==76,'cosignature')
                timestamp=int.from_bytes(raw[4:12],'big')
                msg=b'cosignature/v1\ntime '+str(timestamp).encode()+b'\n'+signed
                require(ed25519.verify(key['pk'],msg,raw[12:]),'cosignature')
                times[witness]=max(times.get(witness,0),timestamp)
    require(p.satisfied(set(times)),'quorum')
    return {'origin':lines[0],'size':size,'root':root,'quorum_time':p.time(times),'signed':signed,'timestamps':times}

def receipt(data,t,submitted=None,now=0):
    signed,sigs=note(data); log_signatures(signed,sigs,[vkey(t['log_key'],1)])
    lines=signed.decode().split('\n')[:-1]
    require(len(lines)==4 and lines[0]=='norn/receipt/v1','receipt')
    require(lines[1]==t['origin'],'origin')
    try: h=b64(lines[2]); require(len(h)==32,'leaf-hash')
    except ValueError: raise Refusal('leaf-hash') from None
    try: deadline=decimal(lines[3])
    except ValueError: raise Refusal('deadline') from None
    require(submitted is None or submitted==h,'entry')
    require(not now or now<deadline,'expired')
    return {'origin':lines[1],'leaf_hash':h,'deadline':deadline,'text_sha256':hashlib.sha256(signed).digest()}

def group_path(n):
    require(type(n)==int and n>=0,'path')
    parts=[f'{n%1000:03d}']; n//=1000
    while n:
        parts.insert(0,f'x{n%1000:03d}'); n//=1000
    return '/'.join(parts)

def tile_path(level,index,width=256):
    return 'tile/'+str(level)+'/'+group_path(index)+('' if width==256 else '.p/'+str(width))

def entry_path(index,width=256):
    return 'tile/entries/'+group_path(index)+('' if width==256 else '.p/'+str(width))

class Mirror:
    def __init__(self,path,overlay=None): self.path=Path(path); self.overlay=overlay or {}
    def read(self,path):
        if path in self.overlay:
            data=self.overlay[path]; require(data is not None,'unserved',path); return data
        try: return (self.path/path).read_bytes()
        except FileNotFoundError: raise Refusal('unserved',path) from None

def served(mirror,t,accepted=None,stored=None,held_entries=None):
    cp=checkpoint(mirror.read('checkpoint'),t,accepted)
    entries=[]
    for start in range(0,cp['size'],256):
        width=min(256,cp['size']-start); raw=mirror.read(entry_path(start//256,width)); offset=0; bundle=[]
        while offset<len(raw):
            require(offset+2<=len(raw),'entries'); n=int.from_bytes(raw[offset:offset+2],'big'); offset+=2
            require(offset+n<=len(raw),'entries'); bundle.append(raw[offset:offset+n]); offset+=n
        require(len(bundle)==width,'entries'); entries+=bundle
    hashes=[merkle.leaf(e) for e in entries]
    require(merkle.root(hashes)==cp['root'],'head')
    if stored:
        at=min(cp['size'],stored['size'])
        mine=stored['root'] if at==stored['size'] else merkle.root([merkle.leaf(e) for e in held_entries[:at]]) if held_entries is not None and len(held_entries)>=at else None
        if mine is not None: require(merkle.root(hashes[:at])==mine,'fork')
        require(cp['size']>=stored['size'],'rollback')
    level=0; level_hashes=hashes
    while level_hashes:
        for start in range(0,len(level_hashes),256):
            width=min(256,len(level_hashes)-start)
            raw=mirror.read(tile_path(level,start//256,width))
            require(raw==b''.join(level_hashes[start:start+width]),'tiles')
        level_hashes=[merkle.root(level_hashes[i:i+256]) for i in range(0,len(level_hashes)-255,256)]
        level+=1
    state=replay(t,entries)
    # Replay failure is carried by canonical state; it has no additional §10 code.
    return cp,state,entries

def bundle(data,t,accepted=None):
    try:
        b=cbor.loads(data,81919)
        closed(b,('v','device','index','entry','proof','checkpoint'),code='bundle')
        require(uint(b['v']) and b['v']==1 and text(b['device']) and uint(b['index']) and type(b['entry'])==bytes and type(b['checkpoint'])==str and type(b['proof'])==list and all(blob(p,32) for p in b['proof']),'bundle')
    except ValueError: raise Refusal('bundle') from None
    cp=checkpoint(b['checkpoint'],t,accepted)
    require(merkle.inclusion(merkle.leaf(b['entry']),b['index'],cp['size'],b['proof'],cp['root']),'inclusion')
    try:
        e=envelope(b['entry'],t['net'])
        ident=request(e['body']['request'],t['net'],False)['device_id'] if e['t']=='enroll' else e['body'].get('device_id') if e['t'] in ('rotate','revoke') else None
        require(ident==b['device'],'binding')
    except (ValueError,KeyError): raise Refusal('binding') from None
    return b,cp

def evidence(data,t,accepted=None):
    require(len(data)<=65536,'oversize')
    try: e=cbor.loads(data,65536); require(type(e)==dict,'cbor')
    except ValueError: raise Refusal('cbor') from None
    require(uint(e.get('version')) and e['version']==1,'version')
    closed(e,('version','held','conflicting','size','held_root','proof','policy'),code='schema')
    require(text(e['held']) and text(e['conflicting']) and uint(e['size']) and blob(e['held_root'],32) and type(e['proof'])==list and all(blob(p,32) for p in e['proof']) and text(e['policy']),'schema')
    try: Policy(e['policy'])
    except ValueError: raise Refusal('policy') from None
    try: held=checkpoint(e['held'],t,accepted)
    except Refusal as err: raise Refusal('held',err.code) from None
    try: conflicting=checkpoint(e['conflicting'],t,accepted)
    except Refusal as err: raise Refusal('conflicting',err.code) from None
    require(e['size']<=held['size'] and e['size']==conflicting['size'],'size')
    require(merkle.consistency(e['size'],held['size'],e['held_root'],held['root'],e['proof']),'proof')
    require(e['held_root']!=conflicting['root'],'consistent')
    return e

def freshness(elapsed,staleness,hard=0):
    if elapsed is None: return 'unknown'
    if hard and elapsed>hard: return 'hard_stale'
    if elapsed<=staleness: return 'fresh'
    return 'degraded'

def proven(state,T=None):
    return {i:d for i,d in state['devices'].items() if d['status']=='active' and (T is None or not d['expires'] or d['expires']>T)}

def grant(labels):
    if 'ip' not in labels: return []
    try:
        out=set()
        for part in labels['ip'].split(','):
            # Reject mapped source addresses even if masking hides the mapping.
            s=part.strip(); address=ipaddress.ip_address(s.split('/')[0])
            if isinstance(address,ipaddress.IPv6Address) and address.ipv4_mapped is not None: return []
            net=ipaddress.ip_network(s,strict=False)
            if isinstance(net,ipaddress.IPv6Network) and net.network_address.ipv4_mapped is not None: return []
            out.add(str(net))
        return sorted(out)
    except ValueError: return []
