"""Independent implementation of the sealed SPEC.md, §§2–16."""
import base64, hashlib, json, re, ipaddress
import cbor, ed25519 as ed, bech32m, merkle
MAX=cbor.MAX_INT
class Refusal(ValueError):
    def __init__(self,code): self.code=code; super().__init__(code)
def require(ok,code='decode'):
    if not ok: raise Refusal(code)
def uint(v): return type(v) is int and 0<=v<=MAX
def blob(v,n): return type(v) is bytes and len(v)==n
def text(v,lo=0,hi=4096): return type(v) is str and lo<=len(v.encode())<=hi
def closed(v,required,optional=()): return type(v) is dict and set(required)<=v.keys() and v.keys()<=set(required)|set(optional)
def device_id(v): return type(v) is str and re.fullmatch('[a-z0-9][a-z0-9.-]{0,63}',v) is not None
def kid(pk): return hashlib.sha256(pk).digest()[:8].hex()
def origin(net): return 'norn/'+base64.b32encode(net).decode().lower().rstrip('=')
def b64(s):
    require(type(s) is str)
    try: b=base64.b64decode(s,validate=True)
    except (ValueError,UnicodeEncodeError): raise Refusal('decode')
    require(base64.b64encode(b).decode()==s); return b
def decimal(s):
    require(type(s) is str and re.fullmatch('0|[1-9][0-9]*',s) is not None)
    require(len(s)<=19 and int(s)<=MAX); return int(s)
def verifier_key(s,alg=None):
    require(type(s) is str)
    parts=s.split('+',2); require(len(parts)==3)
    name,id_,data=parts
    require(name and all(33<=ord(c)<=126 and c!='+' for c in name))
    require(re.fullmatch('[0-9a-f]{8}',id_) is not None)
    raw=b64(data); require(len(raw)==33 and raw[0] in (1,4))
    require(alg is None or raw[0]==alg)
    pk=raw[1:]; require(ed.valid_point(pk))
    require(hashlib.sha256(name.encode()+b'\n'+raw).digest()[:4].hex()==id_)
    return {'name':name,'id':bytes.fromhex(id_),'alg':raw[0],'pk':pk,'text':s}
def make_key(name,pk,alg=1):
    raw=bytes([alg])+pk; id_=hashlib.sha256(name.encode()+b'\n'+raw).digest()[:4].hex()
    return verifier_key(name+'+'+id_+'+'+base64.b64encode(raw).decode(),alg)
class Policy:
    def __init__(self,s):
        require(type(s) is str and s.endswith('\n'))
        require(not any(ord(c)<32 and c not in '\t\n' or ord(c)==127 for c in s))
        self.witnesses={}; self.groups={}; self.logs=[]; self.quorum=None; used=set(); names=set()
        for line in s.split('\n')[:-1]:
            line=line.strip(' \t')
            if not line or line.startswith('#'): continue
            parts=re.split('[ \t]+',line); cmd=parts[0]; args=parts[1:]
            if cmd=='log':
                require(len(args) in (1,2)); k=verifier_key(args[0],1)
                require(k['pk'] not in used); used.add(k['pk']); self.logs.append(k)
            elif cmd=='witness':
                require(len(args) in (2,3)); n=args[0]; k=verifier_key(args[1],4)
                require(n!='none' and n not in names and k['pk'] not in used)
                used.add(k['pk']); names.add(n); self.witnesses[n]=k
            elif cmd=='group':
                require(len(args)>=3); n,thr,*members=args
                require(n!='none' and n not in names and len(set(members))==len(members) and all(m in names for m in members))
                count=len(members) if thr=='all' else 1 if thr=='any' else decimal(thr)
                require(1<=count<=len(members)); self.groups[n]=(count,members); names.add(n)
            elif cmd=='quorum':
                require(len(args)==1 and self.quorum is None and (args[0]=='none' or args[0] in names)); self.quorum=args[0]
            else: raise Refusal('decode')
        require(self.quorum is not None)
    def satisfied(self,cosigners):
        def met(n):
            if n=='none': return True
            if n in self.witnesses: return n in cosigners
            k,m=self.groups[n]; return sum(met(a) for a in m)>=k
        return met(self.quorum)
    def quorum_time(self,times):
        if self.quorum=='none': return None
        for t in sorted(set(times.values()),reverse=True):
            if self.satisfied({n for n,v in times.items() if v>=t}): return t
        return None

def trust(raw):
    t=cbor.decode(raw,65536)
    require(closed(t,('version','net','origin','name','genesis_hash','log_key','log_urls','witnesses','policy'),('anchor',)))
    require(uint(t['version']) and t['version']==1 and blob(t['net'],16) and blob(t['genesis_hash'],32) and text(t['name'],1,64))
    require(t['origin']==origin(t['net']))
    log=verifier_key(t['log_key'],1); require(log['name']==t['origin'])
    require(type(t['log_urls']) is list and t['log_urls'] and all(type(u) is str and u for u in t['log_urls']))
    require(type(t['witnesses']) is list and t['witnesses'])
    witnesses={}
    for w in t['witnesses']:
        require(closed(w,('name','key'),('url',)) and text(w['name'],1,64) and ('url' not in w or type(w['url']) is str))
        require(w['name'] not in witnesses); k=verifier_key(w['key'],4)
        require(k['pk']!=log['pk']); witnesses[w['name']]=k
    p=Policy(t['policy'])
    require({n:k['text'] for n,k in witnesses.items()}=={n:k['text'] for n,k in p.witnesses.items()})
    require(all(k['text']==t['log_key'] for k in p.logs))
    if 'anchor' in t:
        a=t['anchor']; require(closed(a,('type','max_lag','mode')) and type(a['type']) is str and uint(a['max_lag']) and a['mode']=='advisory')
    return t

def labels(v):
    return type(v) is dict and 1<=len(v)<=32 and all(text(k,1,23) and text(x,0,256) for k,x in v.items())
def request(raw,net=None,verify=True):
    r=cbor.decode(raw)
    require(closed(r,('v','ts','net','sig','wg_pk','device_id','device_pk'),('labels','expires')))
    require(uint(r['v']) and r['v']==1 and uint(r['ts']) and blob(r['net'],16) and blob(r['sig'],64) and blob(r['wg_pk'],32))
    require(device_id(r['device_id']) and blob(r['device_pk'],32) and ed.valid_point(r['device_pk']))
    require('labels' not in r or labels(r['labels']))
    require('expires' not in r or uint(r['expires']) and r['expires']>r['ts'])
    require(net is None or r['net']==net)
    if verify: require(ed.verify(r['device_pk'],b'norn/enroll-request/v1\n'+cbor.encode({k:v for k,v in r.items() if k!='sig'}),r['sig']),'no-device-sig')
    return r
def request_text(s):
    hrp,data=bech32m.decode(s,max_length=None); require(hrp=='norn')
    raw=bytes(bech32m.convert(data,5,8,False)); return request(raw),raw

def envelope(raw,net=None):
    e=cbor.decode(raw)
    require(closed(e,('v','t','ts','net','body','sigs'),('after','prev')))
    require(uint(e['v']) and e['v']==1 and type(e['t']) is str and uint(e['ts']) and blob(e['net'],16) and type(e['body']) is dict)
    require(net is None or e['net']==net)
    require(all(k not in e or uint(e[k]) for k in ('after','prev')))
    require(type(e['sigs']) is list)
    last=''
    for s in e['sigs']:
        require(closed(s,('kid','role','sig')) and type(s['kid']) is str and re.fullmatch('[0-9a-f]{16}',s['kid']) is not None)
        require(s['kid']>last and s['role'] in ('root','signer','device') and blob(s['sig'],64)); last=s['kid']
    return e
def preimage(e): return b'norn/entry/v1\n'+cbor.encode({k:v for k,v in e.items() if k!='sigs'})
DEFAULTS={'checkpoint_interval':60,'staleness':600,'mmd':60,'rotate_needs_signer':False,'routes':'granted'}
GOV={'signer_add','signer_remove','signer_thr','root_add','root_remove','root_thr','params','policy','log_key'}
TYPES=GOV|{'genesis','enroll','rotate','revoke','note'}
def params(p):
    return type(p) is dict and bool(p) and p.keys()<=DEFAULTS.keys() and all(type(v) is bool if k=='rotate_needs_signer' else type(v) is str and v in ('granted','advisory') if k=='routes' else uint(v) for k,v in p.items())
def zero(anchor):
    return dict(name='',net=anchor['net'],size=0,root_thr=0,signer_thr=0,roots={},signers={},params=DEFAULTS.copy(),policy='',log_keys=[],devices={},active_wg={},versions=dict.fromkeys(('signers','roots','params','policy','log_key'),0),rejected=[])
def count(e,role,keys):
    msg=preimage(e)
    return sum(s['role']==role and s['kid'] in keys and ed.verify(keys[s['kid']],msg,s['sig']) for s in e['sigs'])
def device_sig(e,pk): return count(e,'device',{kid(pk):pk})>0

def replay(anchor,entries):
    state=zero(anchor); seen=set()
    for i,raw in enumerate(entries):
        try: e=envelope(raw,anchor['net']); identity=hashlib.sha256(preimage(e)).digest()
        except (ValueError,TypeError): e=None; identity=hashlib.sha256(raw).digest()
        duplicate=identity in seen; seen.add(identity)
        if i==0:
            try:
                require(e is not None and e['t']=='genesis' and merkle.leaf(raw)==anchor['genesis_hash'] and e.get('after',0)==0 and 'prev' not in e)
                b=e['body']; require(closed(b,('name','roots','root_thr','signers','signer_thr'),('params',)) and text(b['name'],1,64))
                for role in ('roots','signers'):
                    ks=b[role]; require(type(ks) is list and ks and all(blob(k,32) and ed.valid_point(k) for k in ks) and len(set(ks))==len(ks))
                    thr=b['root_thr' if role=='roots' else 'signer_thr']; require(uint(thr) and 1<=thr<=len(ks))
                require(not set(b['roots'])&set(b['signers']) and ('params' not in b or params(b['params'])))
                roots={kid(k):k for k in b['roots']}; require(count(e,'root',roots)>=b['root_thr'])
                state.update(name=b['name'],roots=roots,signers={kid(k):k for k in b['signers']},root_thr=b['root_thr'],signer_thr=b['signer_thr'],size=1)
                state['params'].update(b.get('params',{}))
            except (ValueError,TypeError,KeyError): state['rejected']=[{'index':0,'reason':'bad-genesis'}]; return state
            continue
        try:
            require(not duplicate,'dup-entry'); require(e is not None)
            t=e['t']; b=e['body']; require(t in TYPES,'unknown-type'); require(t!='genesis','dup-genesis'); require(e.get('after',0)<=i,'after')
            roots=count(e,'root',state['roots']); signers=count(e,'signer',state['signers'])
            if t in GOV: require(roots>=state['root_thr'],'threshold')
            if t=='note': require(roots+signers>0,'threshold')
            def prev(v): require(e.get('prev')==v,'stale-state')
            if t=='enroll':
                require(closed(b,('request',)) and type(b['request']) is bytes)
                r=request(b['request'],e['net']); require(signers>=state['signer_thr'],'threshold')
                id_=r['device_id']; d=state['devices'].get(id_); prev(d['version'] if d else None)
                require(d is None or d['status']!='active','dup-id'); require(r['wg_pk'] not in state['active_wg'],'dup-wg')
                state['devices'][id_]=dict(device_pk=r['device_pk'],wg_pk=r['wg_pk'],status='active',since_index=i,version=i,labels=r.get('labels',{}),expires=r.get('expires',0))
            elif t in ('rotate','revoke'):
                if t=='rotate':
                    require(closed(b,('device_id','wg_pk'),('device_pk',)) and blob(b['wg_pk'],32) and ('device_pk' not in b or blob(b['device_pk'],32) and ed.valid_point(b['device_pk'])))
                else: require(closed(b,('device_id',),('reason',)) and ('reason' not in b or text(b['reason'],0,256)))
                require(device_id(b['device_id'])); id_=b['device_id']; require(id_ in state['devices'],'unknown-device'); d=state['devices'][id_]
                require(d['status']=='active','not-active'); ds=device_sig(e,d['device_pk'])
                if t=='rotate':
                    require(ds,'no-device-sig'); require(not state['params']['rotate_needs_signer'] or signers>=state['signer_thr'],'threshold'); prev(d['version'])
                    require(b['wg_pk'] not in state['active_wg'] or state['active_wg'][b['wg_pk']]==id_,'dup-wg')
                    require('device_pk' not in b or device_sig(e,b['device_pk']),'no-device-sig')
                    d['wg_pk']=b['wg_pk']; d['device_pk']=b.get('device_pk',d['device_pk'])
                else:
                    require(ds or signers>=state['signer_thr'] or roots>=state['root_thr'],'threshold'); prev(d['version']); d.update(status='revoked',since_index=i)
                d['version']=i
            elif t.endswith(('_add','_remove','_thr')):
                role='roots' if t.startswith('root_') else 'signers'; action=t.rsplit('_',1)[1]; ks=state[role]; field={'add':'pk','remove':'kid','thr':'thr'}[action]
                require(closed(b,(field,)))
                if action=='add': require(blob(b['pk'],32) and ed.valid_point(b['pk']))
                elif action=='remove': require(type(b['kid']) is str and re.fullmatch('[0-9a-f]{16}',b['kid']) is not None)
                else: require(uint(b['thr']))
                prev(state['versions'][role])
                if action=='add':
                    id_=kid(b['pk']); require(id_ not in state['roots'] and id_ not in state['signers'],'dup-key'); ks[id_]=b['pk']
                elif action=='remove':
                    require(b['kid'] in ks,'unknown-key'); require(role!='roots' or len(ks)-1>=state['root_thr'],'root-invariant'); del ks[b['kid']]
                else:
                    require(1<=b['thr']<=len(ks),'bad-thr'); state['root_thr' if role=='roots' else 'signer_thr']=b['thr']
                state['versions'][role]=i
            elif t=='params':
                require(params(b)); prev(state['versions']['params']); state['params'].update(b); state['versions']['params']=i
            elif t in ('note','policy'):
                require(closed(b,('text',)) and text(b['text']))
                if t=='note': require('prev' not in e)
                else:
                    p=Policy(b['text']); prev(state['versions']['policy'])
                    logpks={verifier_key(anchor['log_key'],1)['pk']}|{k['pk'] for k in state['log_keys']}
                    require(all(k['pk'] not in logpks for k in p.witnesses.values()),'dup-key')
                    state['policy']=b['text']; state['versions']['policy']=i
            elif t=='log_key':
                require(closed(b,('pk','overlap')) and blob(b['pk'],32) and ed.valid_point(b['pk']) and uint(b['overlap'])); prev(state['versions']['log_key'])
                p=Policy(state['policy'] or anchor['policy']); require(all(k['pk']!=b['pk'] for k in p.witnesses.values()),'dup-key')
                state['log_keys'].append(dict(pk=b['pk'],overlap=b['overlap'],since_index=i)); state['versions']['log_key']=i
            state['active_wg']={d['wg_pk']:id_ for id_,d in state['devices'].items() if d['status']=='active'}
        except Refusal as ex: state['rejected'].append({'index':i,'reason':ex.code})
        except (ValueError,TypeError,KeyError): state['rejected'].append({'index':i,'reason':'decode'})
        state['size']=i+1
    return state

def jsonable(v):
    if type(v) is bytes: return v.hex()
    if type(v) is list: return [jsonable(x) for x in v]
    if type(v) is dict: return {k.hex() if type(k) is bytes else k:jsonable(x) for k,x in v.items()}
    return v
def canonical_json(v): return (json.dumps(jsonable(v),sort_keys=True,ensure_ascii=False,separators=(',',':'))+'\n').encode()
def grant(label):
    if type(label) is not str: return []
    result=set()
    try:
        for part in label.split(','):
            s=part.strip(' '); addr,length=s.split('/')
            require(re.fullmatch('0|[1-9][0-9]*',length) is not None and '%' not in addr)
            require(re.fullmatch('[0-9a-fA-F:.]+',addr) is not None)
            ip=ipaddress.ip_address(addr); n=int(length); require(n<=ip.max_prefixlen)
            require(not isinstance(ip,ipaddress.IPv6Address) or ip.ipv4_mapped is None)
            result.add(str(ipaddress.ip_network((ip,n),strict=False)))
        return sorted(result)
    except (ValueError,TypeError): return []
def proven(state,T):
    return {id_:d for id_,d in state['devices'].items() if d['status']=='active' and (T is None or d['expires']==0 or d['expires']>T)}
def freshness(elapsed,S,hard=0):
    if elapsed is None: return 'unknown'
    if hard and elapsed>hard: return 'hard_stale'
    return 'fresh' if elapsed<=S else 'degraded'
