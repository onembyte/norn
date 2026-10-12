"""Norn SPEC §4.0 deterministic CBOR allow-list; no external codec."""
MAX_INT=2**63-1
class DecodeError(ValueError): pass
def head(major,n):
    if n<24: return bytes([(major<<5)|n])
    for a,w in ((24,1),(25,2),(26,4),(27,8)):
        if n<1<<(8*w): return bytes([(major<<5)|a])+n.to_bytes(w,'big')
    raise ValueError('integer')
def encode(v):
    if type(v) is bool: return b'\xf5' if v else b'\xf4'
    if type(v) is int:
        if not 0<=v<=MAX_INT: raise ValueError('integer')
        return head(0,v)
    if type(v) is bytes: return head(2,len(v))+v
    if type(v) is str:
        b=v.encode(); return head(3,len(b))+b
    if type(v) is list: return head(4,len(v))+b''.join(map(encode,v))
    if type(v) is dict:
        pairs=sorted((encode(k),encode(x)) for k,x in v.items())
        return head(5,len(pairs))+b''.join(k+x for k,x in pairs)
    raise ValueError('type')
def decode(data,limit=65535):
    if len(data)>limit: raise DecodeError('length')
    pos=0
    def take(n):
        nonlocal pos
        if n>len(data)-pos: raise DecodeError('truncated')
        b=data[pos:pos+n]; pos+=n; return b
    def item(depth=0):
        lead=take(1)[0]; major=lead>>5; a=lead&31
        if major==7:
            if a in (20,21): return a==21
            if a in (25,26,27): raise DecodeError('float')
            raise DecodeError('simple')
        if major not in (0,2,3,4,5): raise DecodeError('major type')
        if a==31: raise DecodeError('indefinite')
        if a>=28: raise DecodeError('type')
        if a<24: n=a
        else:
            w={24:1,25:2,26:4,27:8}[a]; n=int.from_bytes(take(w),'big')
            if n<({24:24,25:256,26:65536,27:2**32}[a]): raise DecodeError('nonshortest')
        if major==0:
            if n>MAX_INT: raise DecodeError('integer')
            return n
        if major in (2,3):
            b=take(n)
            if major==2: return b
            try: return b.decode('utf-8')
            except UnicodeDecodeError: raise DecodeError('utf8')
        depth+=1
        if depth>8: raise DecodeError('depth')
        if n>len(data)-pos: raise DecodeError('container length')
        if major==4: return [item(depth) for _ in range(n)]
        result={}; prev=b''
        for _ in range(n):
            start=pos; k=item(depth); enc=data[start:pos]
            if type(k) is not str: raise DecodeError('key type')
            if not 1<=len(k.encode())<=23: raise DecodeError('key length')
            if enc<=prev: raise DecodeError('key order')
            prev=enc; result[k]=item(depth)
        return result
    v=item()
    if pos!=len(data): raise DecodeError('trailing')
    return v
