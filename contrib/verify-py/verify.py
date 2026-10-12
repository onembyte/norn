"""Offline verifier for SPEC §§6–11. No transport or implicit trust bootstrap."""
from pathlib import Path
import hashlib
import cbor, merkle, ed25519 as ed
from protocol import (Refusal, require, uint, blob, closed, device_id, b64,
                      decimal, verifier_key, make_key, Policy, replay, envelope,
                      request, proven, grant)

WHITE = set(range(9,14)) | {32,133,160,5760,8232,8233,8239,8287,12288} | set(range(8192,8203))

def at_code(code, fn):
    try: return fn()
    except (ValueError, TypeError, KeyError, OverflowError): raise Refusal(code) from None

def split_note(raw):
    """§7: frame every line before selecting any trusted key."""
    def parse():
        s = raw.decode('utf-8') if type(raw) is bytes else raw
        require(type(s) is str and s.endswith('\n'))
        require(not any(ord(c)<32 and c!='\n' for c in s))
        text, block = s.split('\n\n',1)
        require(text and block)
        lines = text.split('\n'); require(all(lines))
        signatures=[]
        for line in block.split('\n')[:-1]:
            require(line.startswith('— '))
            name,payload=line[2:].split(' ',1)
            require(name and all(c!='+' and ord(c) not in WHITE for c in name))
            payload=b64(payload); require(len(payload)>=4)
            signatures.append((name,payload))
        require(signatures)
        return (text+'\n').encode('utf-8'),lines,signatures
    return at_code('note',parse)

class Verifier:
    def __init__(self, trust, state=None, policy=None):
        self.trust=trust
        self.logs=[verifier_key(trust['log_key'],1)]
        if state:
            self.logs += [make_key(trust['origin'],k['pk']) for k in state['log_keys']]
        self.policy=Policy(policy if policy is not None else
                           state['policy'] if state and state['policy'] else trust['policy'])

    def log_signature(self,text,signatures):
        matched=False
        for name,payload in signatures:
            for key in self.logs:
                if name==key['name'] and payload[:4]==key['id']:
                    matched=True
                    require(len(payload)==68 and ed.verify(key['pk'],text,payload[4:]),'log-signature')
        require(matched,'log-signature')

    def checkpoint(self, raw):
        text,lines,sigs=split_note(raw)
        self.log_signature(text,sigs)
        def body():
            require(len(lines)==3)
            size=decimal(lines[1]); root=b64(lines[2]); require(len(root)==32)
            return size,root
        size,root=at_code('checkpoint',body)
        require(lines[0]==self.trust['origin'],'origin')
        times={}
        for name,payload in sigs:
            for witness,key in self.policy.witnesses.items():
                if name==key['name'] and payload[:4]==key['id']:
                    require(len(payload)==76,'cosignature')
                    timestamp=int.from_bytes(payload[4:12],'big')
                    require(uint(timestamp),'cosignature')
                    message=b'cosignature/v1\ntime '+str(timestamp).encode()+b'\n'+text
                    require(ed.verify(key['pk'],message,payload[12:]),'cosignature')
                    times[witness]=max(times.get(witness,0),timestamp)
        require(self.policy.satisfied(set(times)),'quorum')
        return dict(origin=lines[0],size=size,root=root,time=self.policy.quorum_time(times),text=text)

    def receipt(self,raw,leaf_hash=None,now=0):
        text,lines,sigs=split_note(raw); self.log_signature(text,sigs)
        require(len(lines)==4 and lines[0]=='norn/receipt/v1','receipt')
        require(lines[1]==self.trust['origin'],'origin')
        def leaf():
            h=b64(lines[2]); require(len(h)==32); return h
        h=at_code('leaf-hash',leaf)
        deadline=at_code('deadline',lambda: decimal(lines[3]))
        require(leaf_hash is None or leaf_hash==h,'entry')
        require(not now or now<deadline,'expired')
        return dict(origin=lines[1],leaf_hash=h,deadline=deadline,text_sha256=hashlib.sha256(text).hexdigest())

    def bundle(self,raw):
        def schema():
            b=cbor.decode(raw,81919)
            require(closed(b,('v','device','index','entry','proof','checkpoint')))
            require(uint(b['v']) and b['v']==1 and device_id(b['device']) and uint(b['index']))
            require(type(b['entry']) is bytes and len(b['entry'])<=65535 and type(b['checkpoint']) is str)
            require(type(b['proof']) is list and all(blob(p,32) for p in b['proof']))
            return b
        b=at_code('bundle',schema); cp=self.checkpoint(b['checkpoint'])
        require(merkle.inclusion(merkle.leaf(b['entry']),b['index'],cp['size'],b['proof'],cp['root']),'inclusion')
        def binding():
            e=envelope(b['entry'],self.trust['net'])
            if e['t']=='enroll':
                require(closed(e['body'],('request',)))
                id_=request(e['body']['request'],self.trust['net'],verify=False)['device_id']
            elif e['t'] in ('rotate','revoke'):
                id_=e['body']['device_id']; require(device_id(id_))
            else: raise Refusal('binding')
            require(id_==b['device'])
        at_code('binding',binding)
        return b,cp

    def served(self,source,stored=None,stored_entries=None):
        """source is a local read adapter; stored heads are already verified."""
        cp=self.checkpoint(source.read('checkpoint'))
        entries=[]
        for group,width in groups(cp['size']):
            raw=source.read(tile_path('entries',group,width)); pos=0; bundle=[]
            while pos<len(raw):
                require(len(raw)-pos>=2,'entries')
                n=int.from_bytes(raw[pos:pos+2],'big'); pos+=2
                require(len(raw)-pos>=n,'entries')
                bundle.append(raw[pos:pos+n]); pos+=n
            require(len(bundle)==width,'entries'); entries.extend(bundle)
        hashes=[merkle.leaf(e) for e in entries]
        require(merkle.root(hashes)==cp['root'],'head')
        if stored is not None:
            at=min(cp['size'],stored['size'])
            if at==stored['size']: mine=stored['root']
            elif stored_entries is not None: mine=merkle.root([merkle.leaf(e) for e in stored_entries[:at]])
            else: mine=None
            if mine is not None: require(merkle.root(hashes[:at])==mine,'fork')
            require(cp['size']>=stored['size'],'rollback')
        require(entries and not replay(self.trust,entries[:1])['rejected'],'genesis')
        level=0; layer=hashes
        while layer:
            for group,width in groups(len(layer)):
                raw=source.read(tile_path(level,group,width))
                require(raw==b''.join(layer[group*256:group*256+width]),'tiles')
            layer=[merkle.root(layer[i:i+256]) for i in range(0,len(layer)-255,256)]
            level+=1
        state=replay(self.trust,entries)
        return cp,state,entries

    def evidence(self,raw):
        require(len(raw)<=65536,'oversize')
        def decode():
            e=cbor.decode(raw,65536); require(type(e) is dict); return e
        e=at_code('cbor',decode)
        require(uint(e.get('version')) and e['version'] in (1,2),'version')
        keys=('version','held','conflicting','size','held_root','proof','policy')
        extra=('split','split_root','split_proof_held','split_proof_conflicting') if e['version']==2 else ()
        require(closed(e,keys+extra),'schema')
        require(all(type(e[k]) is str for k in ('held','conflicting','policy')) and uint(e['size']) and blob(e['held_root'],32),'schema')
        proof_keys=['proof']
        if extra:
            require(uint(e['split']) and blob(e['split_root'],32),'schema')
            proof_keys+=['split_proof_held','split_proof_conflicting']
        require(all(type(e[k]) is list and all(blob(p,32) for p in e[k]) for k in proof_keys),'schema')
        at_code('policy',lambda: Policy(e['policy']))
        held=at_code('held',lambda: self.checkpoint(e['held']))
        conflict=at_code('conflicting',lambda: self.checkpoint(e['conflicting']))
        require(e['size']<=held['size'] and e['size']==conflict['size'],'size')
        require(merkle.consistency(e['size'],held['size'],e['held_root'],held['root'],e['proof']),'proof')
        if extra:
            require(e['split']<=e['size'],'proof')
            if e['split']==0:
                require(e['split_root']==bytes(32) and not e['split_proof_held'] and not e['split_proof_conflicting'],'proof')
            else:
                for cp,k in ((held,'split_proof_held'),(conflict,'split_proof_conflicting')):
                    require(merkle.consistency(e['split'],cp['size'],e['split_root'],cp['root'],e[k]),'proof')
        require(e['held_root']!=conflict['root'],'consistent')
        return e

def groups(size):
    for offset in range(0,size,256): yield offset//256,min(256,size-offset)

def tile_path(level,index,width=256):
    chunks=[f'{index%1000:03d}']; index//=1000
    while index:
        chunks.insert(0,f'x{index%1000:03d}'); index//=1000
    return f'tile/{level}/'+ '/'.join(chunks) + (f'.p/{width}' if width<256 else '')

class Files:
    """Read-only local directory, optionally overlaid with manifest replacements."""
    def __init__(self,root,replacements=None,removed=()):
        self.root=Path(root); self.replacements=replacements or {}; self.removed=set(removed)
    def read(self,path):
        if path in self.removed: raise Refusal('unserved')
        try: return Path(self.replacements.get(path,self.root/path)).read_bytes()
        except OSError: raise Refusal('unserved') from None
