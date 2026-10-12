"""Independent Norn verifier built solely from sealed SPEC.md."""
import base64
import hashlib
import ipaddress
import json
import re
import struct
import cbor
import ed25519
import merkle
import bech32m

class Refusal(ValueError):
    def __init__(self,code): self.code=code; super().__init__(code)
def need(condition,code='decode'):
    if not condition: raise Refusal(code)
def uint(x): return type(x) is int and 0<=x<=cbor.MAXINT
def blob(x,n): return type(x) is bytes and len(x)==n
def text(x,lo=0,hi=4096): return type(x) is str and lo<=len(x.encode())<=hi
def closed(x,required,optional=()):
    need(type(x) is dict and set(required)<=x.keys() and x.keys()<=set(required)|set(optional))
def kid(pk): return hashlib.sha256(pk).digest()[:8].hex()
def is_kid(x): return type(x) is str and re.fullmatch('[0-9a-f]{16}',x) is not None
def device_id(x): return type(x) is str and re.fullmatch('[a-z0-9][a-z0-9.-]{0,63}',x) is not None
def b64(s,n=None):
    if type(s) is not str: raise ValueError('base64')
    raw=base64.b64decode(s,validate=True)
    if base64.b64encode(raw).decode()!=s or (n is not None and len(raw)!=n): raise ValueError('base64')
    return raw
def decimal(s):
    if re.fullmatch('0|[1-9][0-9]*',s) is None or len(s)>19: raise ValueError('decimal')
    n=int(s)
    if n>cbor.MAXINT: raise ValueError('decimal bound')
    return n

def jsonable(x):
    if type(x) is bytes: return x.hex()
    if type(x) is dict: return {(k.hex() if type(k) is bytes else k):jsonable(v) for k,v in x.items()}
    if type(x) is list: return [jsonable(v) for v in x]
    return x
def canonical(x):
    return (json.dumps(jsonable(x),sort_keys=True,ensure_ascii=False,separators=(',',':'))+'\n').encode()

DEFAULTS={'checkpoint_interval':60,'staleness':600,'mmd':60,'rotate_needs_signer':False,'routes':'granted'}
def params(x):
    need(type(x) is dict and bool(x) and x.keys()<=DEFAULTS.keys())
    for k,v in x.items():
        need(type(v) is bool if k=='rotate_needs_signer' else
             v in ('granted','advisory') if k=='routes' else uint(v))
def labels(x):
    need(type(x) is dict and 1<=len(x)<=32)
    for k,v in x.items(): need(text(k,1,23) and text(v,0,256))
def request(raw,net=None,signature=True):
    try: r=cbor.loads(raw)
    except ValueError: raise Refusal('decode')
    closed(r,('v','ts','net','sig','wg_pk','device_id','device_pk'),('labels','expires'))
    need(uint(r['v']) and r['v']==1 and uint(r['ts']) and blob(r['net'],16) and blob(r['sig'],64))
    need(blob(r['wg_pk'],32) and device_id(r['device_id']) and ed25519.valid(r['device_pk']))
    if net is not None: need(r['net']==net)
    if 'labels' in r: labels(r['labels'])
    if 'expires' in r: need(uint(r['expires']) and r['expires']>r['ts'])
    if signature:
        pre=b'norn/enroll-request/v1\n'+cbor.dumps({k:v for k,v in r.items() if k!='sig'})
        need(ed25519.verify(r['device_pk'],pre,r['sig']),'no-device-sig')
    return r

def vkey(s,algorithm=None):
    need(type(s) is str)
    fields=s.split('+',2); need(len(fields)==3)
    name,ident,data=fields
    need(bool(name) and all(33<=ord(c)<=126 and c!='+' for c in name))
    need(re.fullmatch('[0-9a-f]{8}',ident) is not None)
    raw=b64(data,33); alg=raw[0]; pk=raw[1:]
    need(alg in (1,4) and (algorithm is None or alg==algorithm) and ed25519.valid(pk))
    actual=hashlib.sha256(name.encode()+b'\n'+bytes([alg])+pk).digest()[:4]
    need(ident==actual.hex())
    return {'name':name,'id':actual,'pk':pk,'alg':alg,'text':s}
def makekey(name,pk):
    raw=b'\x01'+pk; ident=hashlib.sha256(name.encode()+b'\n'+raw).digest()[:4].hex()
    return vkey(name+'+'+ident+'+'+base64.b64encode(raw).decode(),1)

class Policy:
    def __init__(self,s):
        need(type(s) is str and s.endswith('\n'))
        need(not any((ord(c)<32 and c not in '\t\n') or ord(c)==127 for c in s))
        self.witnesses={}; self.logs=[]; self.groups={}; names={'none'}; used=set(); quorum=None
        for line in s.split('\n')[:-1]:
            line=line.strip(' \t')
            if not line or line.startswith('#'): continue
            f=re.split('[ \t]+',line); cmd=f[0]
            if cmd=='log':
                need(len(f) in (2,3)); key=vkey(f[1],1)
                need(key['pk'] not in used); used.add(key['pk']); self.logs.append(key)
            elif cmd=='witness':
                need(len(f) in (3,4)); name=f[1]; need(name not in names)
                key=vkey(f[2],4); need(key['pk'] not in used)
                used.add(key['pk']); names.add(name); self.witnesses[name]=key
            elif cmd=='group':
                need(len(f)>=4); name,thr=f[1:3]; members=f[3:]
                need(name not in names and len(set(members))==len(members))
                need(all(m in names and m!='none' for m in members))
                k=len(members) if thr=='all' else 1 if thr=='any' else decimal(thr)
                need(1<=k<=len(members)); names.add(name); self.groups[name]=(k,members)
            elif cmd=='quorum':
                need(len(f)==2 and quorum is None and f[1] in names); quorum=f[1]
            else: raise Refusal('decode')
        need(quorum is not None); self.quorum=quorum
    def satisfied(self,seen):
        # References only point backwards, so a topological pass also bounds
        # stack use for arbitrarily nested groups inside the artifact byte cap.
        met={'none':True}
        met.update({name:name in seen for name in self.witnesses})
        for name,(k,members) in self.groups.items():
            met[name]=sum(met[m] for m in members)>=k
        return met[self.quorum]
    def time(self,times):
        if self.quorum=='none': return None
        for t in sorted(set(times.values()),reverse=True):
            if self.satisfied({n for n,v in times.items() if v>=t}): return t
        return None

def trust(raw):
    t=cbor.loads(raw,65536)
    closed(t,('version','net','origin','name','genesis_hash','log_key','log_urls','witnesses','policy'),('anchor',))
    need(uint(t['version']) and t['version']==1 and blob(t['net'],16) and blob(t['genesis_hash'],32))
    need(t['origin']=='norn/'+base64.b32encode(t['net']).decode().lower().rstrip('='))
    need(text(t['name'],1,64)); key=vkey(t['log_key'],1); need(key['name']==t['origin'])
    need(type(t['log_urls']) is list and bool(t['log_urls']) and all(type(u) is str and bool(u) for u in t['log_urls']))
    need(type(t['witnesses']) is list and bool(t['witnesses'])); witnesses={}
    for w in t['witnesses']:
        closed(w,('name','key'),('url',)); need(text(w['name'],1,64) and w['name'] not in witnesses)
        if 'url' in w: need(type(w['url']) is str)
        wk=vkey(w['key'],4); need(wk['pk']!=key['pk']); witnesses[w['name']]=w['key']
    pol=Policy(t['policy']); need({n:k['text'] for n,k in pol.witnesses.items()}==witnesses)
    need(all(k['text']==t['log_key'] for k in pol.logs))
    if 'anchor' in t:
        a=t['anchor']; closed(a,('type','max_lag','mode'))
        need(type(a['type']) is str and uint(a['max_lag']) and a['mode']=='advisory')
    return t

def envelope(raw,net):
    e=cbor.loads(raw); closed(e,('v','t','net','ts','body','sigs'),('after','prev'))
    need(uint(e['v']) and e['v']==1 and type(e['t']) is str and e['net']==net and blob(e['net'],16))
    need(uint(e['ts']) and type(e['body']) is dict and type(e['sigs']) is list)
    for k in ('after','prev'):
        if k in e: need(uint(e[k]))
    last=''
    for s in e['sigs']:
        closed(s,('kid','role','sig')); need(is_kid(s['kid']) and s['kid']>last)
        need(s['role'] in ('root','signer','device') and blob(s['sig'],64)); last=s['kid']
    return e

def preimage(e): return b'norn/entry/v1\n'+cbor.dumps({k:v for k,v in e.items() if k!='sigs'})
def signed(e,role,keys):
    msg=preimage(e)
    return {s['kid'] for s in e['sigs'] if s['role']==role and s['kid'] in keys and ed25519.verify(keys[s['kid']],msg,s['sig'])}

def zero(net):
    return dict(name='',net=net,size=0,root_thr=0,signer_thr=0,roots={},signers={},params=DEFAULTS.copy(),
                policy='',log_keys=[],devices={},active_wg={},versions={k:0 for k in ('signers','roots','params','policy','log_key')},rejected=[])
BODY={
    'genesis':(('name','roots','root_thr','signers','signer_thr'),('params',)),
    'enroll':(('request',),()),'rotate':(('device_id','wg_pk'),('device_pk',)),
    'revoke':(('device_id',),('reason',)),
    'signer_add':(('pk',),()),'root_add':(('pk',),()),'signer_remove':(('kid',),()),'root_remove':(('kid',),()),
    'signer_thr':(('thr',),()),'root_thr':(('thr',),()),'params':((),tuple(DEFAULTS)),
    'note':(('text',),()),'policy':(('text',),()),'log_key':(('pk','overlap'),())}
GOV={'signer_add','signer_remove','signer_thr','root_add','root_remove','root_thr','params','policy','log_key'}

def genesis(e,raw,anchor,s):
    need(e['t']=='genesis' and merkle.leaf(raw)==anchor['genesis_hash'])
    need(e.get('after',0)==0 and 'prev' not in e)
    b=e['body']; closed(b,*BODY['genesis']); need(text(b['name'],1,64))
    for role in ('roots','signers'):
        need(type(b[role]) is list and bool(b[role]) and all(ed25519.valid(p) for p in b[role]))
        need(len(set(b[role]))==len(b[role]))
        thr=b['root_thr' if role=='roots' else 'signer_thr']; need(uint(thr) and 1<=thr<=len(b[role]))
    need(not set(b['roots'])&set(b['signers']))
    if 'params' in b: params(b['params'])
    roots={kid(p):p for p in b['roots']}; need(len(signed(e,'root',roots))>=b['root_thr'])
    s.update(name=b['name'],roots=roots,signers={kid(p):p for p in b['signers']},root_thr=b['root_thr'],signer_thr=b['signer_thr'],size=1)
    s['params'].update(b.get('params',{}))

def apply(e,i,s,anchor):
    t=e['t']; need(t in BODY,'unknown-type'); need(t!='genesis','dup-genesis')
    need(e.get('after',0)<=i,'after')
    roots=signed(e,'root',s['roots']); signers=signed(e,'signer',s['signers'])
    if t in GOV: need(len(roots)>=s['root_thr'],'threshold')
    if t=='note': need(bool(roots or signers),'threshold')
    b=e['body']; closed(b,*BODY[t])
    def guard(v): need(e.get('prev')==v and (('prev' in e)==(v is not None)),'stale-state')
    if t=='enroll':
        need(type(b['request']) is bytes); r=request(b['request'],e['net'])
        need(len(signers)>=s['signer_thr'],'threshold'); id=r['device_id']; old=s['devices'].get(id)
        guard(old['version'] if old else None)
        need(not old or old['status']!='active','dup-id'); need(r['wg_pk'] not in s['active_wg'],'dup-wg')
        s['devices'][id]={'device_pk':r['device_pk'],'wg_pk':r['wg_pk'],'status':'active','since_index':i,
                          'version':i,'labels':r.get('labels',{}),'expires':r.get('expires',0)}
    elif t in ('rotate','revoke'):
        need(device_id(b['device_id'])); id=b['device_id']
        if t=='rotate':
            need(blob(b['wg_pk'],32))
            if 'device_pk' in b: need(ed25519.valid(b['device_pk']))
        else:
            if 'reason' in b: need(text(b['reason'],0,256))
        need(id in s['devices'],'unknown-device'); d=s['devices'][id]; need(d['status']=='active','not-active')
        current=bool(signed(e,'device',{kid(d['device_pk']):d['device_pk']}))
        if t=='rotate':
            need(current,'no-device-sig')
            if s['params']['rotate_needs_signer']: need(len(signers)>=s['signer_thr'],'threshold')
            guard(d['version']); need(b['wg_pk'] not in s['active_wg'] or s['active_wg'][b['wg_pk']]==id,'dup-wg')
            if 'device_pk' in b:
                need(bool(signed(e,'device',{kid(b['device_pk']):b['device_pk']})),'no-device-sig')
            d['wg_pk']=b['wg_pk']; d['device_pk']=b.get('device_pk',d['device_pk']); d['version']=i
        else:
            need(current or len(signers)>=s['signer_thr'] or len(roots)>=s['root_thr'],'threshold')
            guard(d['version']); d.update(status='revoked',since_index=i,version=i)
    elif t.startswith(('signer_','root_')):
        role='signers' if t.startswith('signer_') else 'roots'; op=t.split('_')[1]
        if op=='add': need(ed25519.valid(b['pk']))
        elif op=='remove': need(is_kid(b['kid']))
        else: need(uint(b['thr']))
        guard(s['versions'][role])
        if op=='add':
            k=kid(b['pk']); need(k not in s['roots'] and k not in s['signers'],'dup-key'); s[role][k]=b['pk']
        elif op=='remove':
            need(b['kid'] in s[role],'unknown-key')
            if role=='roots': need(len(s[role])-1>=s['root_thr'],'root-invariant')
            del s[role][b['kid']]
        else:
            need(1<=b['thr']<=len(s[role]),'bad-thr'); s['signer_thr' if role=='signers' else 'root_thr']=b['thr']
        s['versions'][role]=i
    elif t=='params':
        params(b); guard(s['versions']['params']); s['params'].update(b); s['versions']['params']=i
    elif t in ('note','policy'):
        need(text(b['text']))
        if t=='note': need('prev' not in e)
        else:
            pol=Policy(b['text']); guard(s['versions']['policy'])
            logs={vkey(anchor['log_key'],1)['pk']}|{k['pk'] for k in s['log_keys']}
            need(all(k['pk'] not in logs for k in pol.witnesses.values()),'dup-key')
            s['policy']=b['text']; s['versions']['policy']=i
    elif t=='log_key':
        need(ed25519.valid(b['pk']) and uint(b['overlap'])); guard(s['versions']['log_key'])
        pol=Policy(s['policy'] or anchor['policy']); need(all(k['pk']!=b['pk'] for k in pol.witnesses.values()),'dup-key')
        s['log_keys'].append(dict(pk=b['pk'],overlap=b['overlap'],since_index=i)); s['versions']['log_key']=i
    s['active_wg']={d['wg_pk']:id for id,d in s['devices'].items() if d['status']=='active'}

def replay(anchor,entries):
    s=zero(anchor['net']); seen=set()
    for i,raw in enumerate(entries):
        try: e=envelope(raw,anchor['net']); key=hashlib.sha256(preimage(e)).digest(); error=None
        except (ValueError,TypeError): e=None; key=hashlib.sha256(raw).digest(); error='decode'
        if i and key in seen: s['rejected'].append({'index':i,'reason':'dup-entry'}); s['size']=i+1; continue
        seen.add(key)
        if i==0:
            try:
                need(e is not None); genesis(e,raw,anchor,s)
            except (ValueError,TypeError):
                s=zero(anchor['net']); s['rejected']=[{'index':0,'reason':'bad-genesis'}]; return s
        else:
            try:
                need(error is None); apply(e,i,s,anchor)
            except Refusal as err: s['rejected'].append({'index':i,'reason':err.code})
            except (ValueError,TypeError): s['rejected'].append({'index':i,'reason':'decode'})
            s['size']=i+1
    return s

def split_note(raw):
    try:
        need(type(raw) is bytes,'note'); raw.decode('utf-8')
        cut=raw.find(b'\n\n'); need(cut>0 and raw.endswith(b'\n'),'note')
        signed_text=raw[:cut+1]; block=raw[cut+2:-1]
        need(all(signed_text.split(b'\n')[:-1]),'note')
        need(bool(block),'note'); lines=[]
        for line in block.decode().split('\n'):
            need(line.startswith('— '),'note'); fields=line[2:].split(' ',1)
            need(len(fields)==2 and bool(fields[0]),'note'); payload=b64(fields[1]); need(len(payload)>=4,'note')
            lines.append((fields[0],payload))
        return signed_text,lines
    except (ValueError,UnicodeError): raise Refusal('note')

def log_signature(signed_text,lines,keys):
    matched=0
    lookup={(k['name'],k['id']):k for k in keys}
    for name,payload in lines:
        key=lookup.get((name,payload[:4]))
        if key is None: continue
        matched+=1
        need(len(payload)==68 and ed25519.verify(key['pk'],signed_text,payload[4:]),'log-signature')
    need(matched>0,'log-signature')

def context(t,state=None,policy_override=None):
    keys=[vkey(t['log_key'],1)]
    if state: keys.extend(makekey(t['origin'],k['pk']) for k in state['log_keys'])
    pol=Policy(policy_override if policy_override is not None else (state['policy'] if state and state['policy'] else t['policy']))
    return keys,pol

def checkpoint(raw,t,state=None,policy_override=None):
    keys,pol=context(t,state,policy_override); signed_text,lines=split_note(raw); log_signature(signed_text,lines,keys)
    body=signed_text.decode().split('\n')[:-1]
    try:
        need(len(body)==3,'checkpoint'); size=decimal(body[1]); root=b64(body[2],32)
    except ValueError: raise Refusal('checkpoint')
    need(body[0]==t['origin'],'origin')
    times={}; lookup={(k['name'],k['id']):(name,k) for name,k in pol.witnesses.items()}
    for name,payload in lines:
        match=lookup.get((name,payload[:4]))
        if match is None: continue
        short,key=match; need(len(payload)==76,'cosignature'); stamp=int.from_bytes(payload[4:12],'big')
        msg=b'cosignature/v1\ntime '+str(stamp).encode()+b'\n'+signed_text
        need(ed25519.verify(key['pk'],msg,payload[12:]),'cosignature'); times[short]=max(stamp,times.get(short,0))
    need(pol.satisfied(set(times)),'quorum')
    return dict(origin=body[0],size=size,root=root,time=pol.time(times),times=times)

def receipt(raw,t,state=None,entry=None,now=0):
    keys,_=context(t,state); signed_text,lines=split_note(raw); log_signature(signed_text,lines,keys)
    body=signed_text.decode().split('\n')[:-1]
    need(len(body)==4 and body[0]=='norn/receipt/v1','receipt'); need(body[1]==t['origin'],'origin')
    try: h=b64(body[2],32)
    except ValueError: raise Refusal('leaf-hash')
    try: deadline=decimal(body[3])
    except ValueError: raise Refusal('deadline')
    if entry is not None: need(h==merkle.leaf(entry),'entry')
    need(not now or now<deadline,'expired')
    return dict(origin=body[1],leaf_hash=h,deadline=deadline,text_sha256=hashlib.sha256(signed_text).digest())

def bundle(raw,t,state=None):
    try:
        b=cbor.loads(raw,81919); closed(b,('v','device','index','entry','proof','checkpoint'))
        need(uint(b['v']) and b['v']==1 and type(b['device']) is str and uint(b['index']))
        need(type(b['entry']) is bytes and type(b['checkpoint']) is str and hashes(b['proof']))
    except (ValueError,TypeError): raise Refusal('bundle')
    cp=checkpoint(b['checkpoint'].encode(),t,state)
    need(merkle.inclusion(merkle.leaf(b['entry']),b['index'],cp['size'],b['proof'],cp['root']),'inclusion')
    try:
        e=envelope(b['entry'],t['net'])
        if e['t']=='enroll': id=request(e['body']['request'],t['net'],signature=False)['device_id']
        elif e['t'] in ('rotate','revoke'): id=e['body']['device_id']
        else: id=None
        need(id==b['device'],'binding')
    except (ValueError,KeyError,TypeError): raise Refusal('binding')
    return b,cp

def hashes(x): return type(x) is list and all(blob(v,32) for v in x)

def evidence(raw,t,state=None):
    need(len(raw)<=65536,'oversize')
    try: e=cbor.loads(raw,65536); need(type(e) is dict)
    except ValueError: raise Refusal('cbor')
    need(uint(e.get('version')) and e['version'] in (1,2),'version')
    extra=('split','split_root','split_proof_held','split_proof_conflicting') if e['version']==2 else ()
    try:
        closed(e,('version','held','conflicting','size','held_root','proof','policy')+extra)
        need(all(type(e[k]) is str for k in ('held','conflicting','policy')) and uint(e['size']))
        need(blob(e['held_root'],32) and hashes(e['proof']))
        if extra: need(uint(e['split']) and blob(e['split_root'],32) and hashes(e['split_proof_held']) and hashes(e['split_proof_conflicting']))
    except (ValueError,TypeError): raise Refusal('schema')
    try: Policy(e['policy'])
    except (ValueError,TypeError): raise Refusal('policy')
    try: held=checkpoint(e['held'].encode(),t,state)
    except ValueError: raise Refusal('held')
    try: conflicting=checkpoint(e['conflicting'].encode(),t,state)
    except ValueError: raise Refusal('conflicting')
    need(e['size']<=held['size'] and conflicting['size']==e['size'],'size')
    need(merkle.consistency(e['size'],held['size'],e['held_root'],held['root'],e['proof']),'proof')
    if extra:
        split=e['split']; need(split<=e['size'],'proof')
        if split==0: need(e['split_root']==bytes(32) and not e['split_proof_held'] and not e['split_proof_conflicting'],'proof')
        else:
            for name,cp in (('held',held),('conflicting',conflicting)):
                need(merkle.consistency(split,cp['size'],e['split_root'],cp['root'],e['split_proof_'+name]),'proof')
    need(e['held_root']!=conflicting['root'],'consistent')
    return e

def tile_path(level,index,width=256):
    groups=[f'{index%1000:03d}']; index//=1000
    while index: groups.append(f'x{index%1000:03d}'); index//=1000
    return 'tile/'+str(level)+'/'+'/'.join(reversed(groups))+('' if width==256 else '.p/'+str(width))

def served(get,t,state=None,stored=None,stored_entries=None):
    def fetch(path):
        raw=get(path); need(raw is not None,'unserved'); return raw
    cp=checkpoint(fetch('checkpoint'),t,state); entries=[]
    for group in range((cp['size']+255)//256):
        width=min(256,cp['size']-group*256); raw=fetch(tile_path('entries',group,width)); pos=0; batch=[]
        while pos<len(raw):
            need(len(raw)-pos>=2,'entries'); size=int.from_bytes(raw[pos:pos+2],'big'); pos+=2
            need(size<=len(raw)-pos,'entries'); batch.append(raw[pos:pos+size]); pos+=size
        need(len(batch)==width,'entries'); entries.extend(batch)
    hs=list(map(merkle.leaf,entries)); need(merkle.root(hs)==cp['root'],'head')
    if stored is not None:
        at=min(cp['size'],stored['size']); mine=None
        if at==stored['size']: mine=stored['root']
        elif stored_entries is not None and len(stored_entries)>=at: mine=merkle.root(list(map(merkle.leaf,stored_entries[:at])))
        if mine is not None: need(merkle.root(hs[:at])==mine,'fork')
        need(cp['size']>=stored['size'],'rollback')
    need(bool(entries),'genesis'); initial=replay(t,entries[:1]); need(initial['size']==1,'genesis')
    verify_tiles(fetch,hs)
    result=replay(t,entries)
    return cp,result,entries

def verify_tiles(fetch,hashes):
    level=0; layer=hashes
    while layer:
        for group in range((len(layer)+255)//256):
            width=min(256,len(layer)-group*256); path=tile_path(level,group,width)
            need(fetch(path)==b''.join(layer[group*256:group*256+width]),'tiles')
        layer=[merkle.root(layer[i:i+256]) for i in range(0,len(layer)-255,256)]; level+=1

def proven(state,T):
    return {id:d for id,d in state['devices'].items() if d['status']=='active' and
            (T is None or d['expires']==0 or d['expires']>T)}
def grant(d):
    value=d['labels'].get('ip')
    if value is None: return []
    try:
        parts=[part.strip() for part in value.split(',')]
        if any('/' not in part for part in parts): return []
        interfaces=[ipaddress.ip_interface(part) for part in parts]
        if any(i.version==6 and i.ip.ipv4_mapped is not None for i in interfaces): return []
        return sorted(set(str(i.network) for i in interfaces))
    except ValueError: return []
def freshness(age,S,hard=0):
    if age is None: return 'unknown'
    if hard and age>hard: return 'hard_stale'
    return 'fresh' if age<=S else 'degraded'

