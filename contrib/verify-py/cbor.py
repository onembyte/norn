"""Norn §4.0 / RFC 8949 §4.2.1 allow-listed deterministic CBOR."""
class DecodeError(ValueError): pass

def dumps(x):
    def head(t,n):
        if n<24: return bytes([t<<5|n])
        for a,w in ((24,1),(25,2),(26,4),(27,8)):
            if n<1<<(8*w): return bytes([t<<5|a])+n.to_bytes(w,'big')
        raise ValueError('argument')
    if type(x) is bool: return b'\xf5' if x else b'\xf4'
    if type(x) is int and 0<=x<2**63: return head(0,x)
    if isinstance(x,bytes): return head(2,len(x))+x
    if isinstance(x,str):
        b=x.encode('utf-8'); return head(3,len(b))+b
    if isinstance(x,list): return head(4,len(x))+b''.join(map(dumps,x))
    if isinstance(x,dict):
        pairs=sorted((dumps(k),dumps(v)) for k,v in x.items())
        return head(5,len(x))+b''.join(k+v for k,v in pairs)
    raise ValueError('type')

def loads(data,limit=65535):
    if len(data)>limit: raise DecodeError('size')
    pos=0
    def take(n):
        nonlocal pos
        if n>len(data)-pos: raise DecodeError('truncated')
        out=data[pos:pos+n]; pos+=n; return out
    def item(depth):
        nonlocal pos
        h=take(1)[0]; t=h>>5; a=h&31
        if t==7:
            if a==20: return False
            if a==21: return True
            raise DecodeError('simple/float')
        if t not in (0,2,3,4,5): raise DecodeError('type')
        if a<24: n=a
        elif a in (24,25,26,27):
            w=1<<(a-24); n=int.from_bytes(take(w),'big')
            if n < (24 if w==1 else 1<<(8*(w//2))): raise DecodeError('nonshortest')
        else: raise DecodeError('indefinite/reserved')
        if t==0:
            if n>=2**63: raise DecodeError('integer too large')
            return n
        if t in (2,3):
            b=take(n)
            if t==2: return b
            try: return b.decode('utf-8')
            except UnicodeDecodeError: raise DecodeError('UTF-8')
        depth+=1
        if depth>8: raise DecodeError('depth')
        # Every member requires at least one byte; avoid huge declared allocations.
        if n*(2 if t==5 else 1)>len(data)-pos: raise DecodeError('container length')
        if t==4: return [item(depth) for _ in range(n)]
        out={}; prev=None
        for _ in range(n):
            start=pos; k=item(depth); raw=data[start:pos]
            if not isinstance(k,str) or not 1<=len(k.encode())<=23: raise DecodeError('map key')
            if prev is not None and raw<=prev: raise DecodeError('map order/duplicate')
            prev=raw; out[k]=item(depth)
        return out
    x=item(0)
    if pos!=len(data): raise DecodeError('trailing bytes')
    return x
