"""Norn §4.0: bounded core-deterministic CBOR allow-list."""
MAXINT=2**63-1

def dumps(x):
    def head(t,n):
        if n<24: return bytes([t*32+n])
        for bits,ai in ((8,24),(16,25),(32,26),(64,27)):
            if n<1<<bits: return bytes([t*32+ai])+n.to_bytes(bits//8,'big')
        raise ValueError('too large')
    if type(x) is bool: return bytes([245 if x else 244])
    if type(x) is int and 0<=x<=MAXINT: return head(0,x)
    if type(x) is bytes: return head(2,len(x))+x
    if type(x) is str:
        b=x.encode(); return head(3,len(b))+b
    if type(x) is list: return head(4,len(x))+b''.join(map(dumps,x))
    if type(x) is dict:
        pairs=sorted((dumps(k),dumps(v)) for k,v in x.items())
        return head(5,len(pairs))+b''.join(k+v for k,v in pairs)
    raise ValueError('unsupported CBOR value')

def loads(raw,limit=65535):
    if len(raw)>limit: raise ValueError('size')
    pos=0
    def item(depth):
        nonlocal pos
        if pos>=len(raw): raise ValueError('truncated')
        start=pos; h=raw[pos]; pos+=1; t=h>>5; ai=h&31
        if t==7 and ai in (20,21): return ai==21
        if t not in (0,2,3,4,5) or ai>27: raise ValueError('forbidden type')
        if ai<24: n=ai
        else:
            width=1<<(ai-24)
            if pos+width>len(raw): raise ValueError('truncated head')
            n=int.from_bytes(raw[pos:pos+width],'big'); pos+=width
            if n < (24 if width==1 else 1<<(8*(width//2))): raise ValueError('nonshortest')
        if n>MAXINT: raise ValueError('integer')
        if t==0: return n
        if t in (2,3):
            if n>len(raw)-pos: raise ValueError('truncated string')
            b=raw[pos:pos+n]; pos+=n
            return b if t==2 else b.decode('utf-8')
        depth+=1
        if depth>8: raise ValueError('depth')
        if n>len(raw)-pos: raise ValueError('container length')
        if t==4: return [item(depth) for _ in range(n)]
        result={}; last=b''
        for _ in range(n):
            at=pos; key=item(depth); encoded=raw[at:pos]
            if type(key) is not str or not 1<=len(key.encode())<=23: raise ValueError('map key')
            if encoded<=last: raise ValueError('map order')
            last=encoded; result[key]=item(depth)
        return result
    result=item(0)
    if pos!=len(raw): raise ValueError('trailing')
    return result
