"""Norn §4.0 restricted RFC 8949 §4.2.1 deterministic encoding."""
class Error(ValueError):
    pass

def loads(data, limit=65535):
    if len(data)>limit:
        raise Error('size limit')
    pos = 0
    def read(depth):
        nonlocal pos
        if pos>=len(data):
            raise Error('truncated')
        start=pos
        h=data[pos]; pos+=1
        major,ai=h>>5,h&31
        if major==7:
            if ai in (20,21):
                return ai==21
            raise Error({22:'null',23:'undefined'}.get(ai,'float/simple item'))
        if major==1:
            raise Error('negative integer')
        if major==6:
            raise Error('tag')
        if ai==31:
            raise Error('indefinite length')
        if ai<24:
            n=ai
        elif ai in (24,25,26,27):
            count=1<<(ai-24)
            if pos+count>len(data):
                raise Error('truncated head')
            n=int.from_bytes(data[pos:pos+count],'big'); pos+=count
            if n < {24:24,25:256,26:65536,27:2**32}[ai]:
                raise Error('nonshortest')
        else:
            raise Error('reserved argument')
        if major==0:
            if n>2**63-1:
                raise Error('integer limit')
            return n
        if major in (2,3):
            if n>len(data)-pos:
                raise Error('truncated string')
            b=data[pos:pos+n]; pos+=n
            if major==2:
                return b
            try:
                return b.decode('utf-8')
            except UnicodeDecodeError:
                raise Error('invalid utf8') from None
        if major in (4,5):
            depth+=1
            if depth>8:
                raise Error('depth limit')
            if n>len(data)-pos:
                raise Error('truncated container')
            if major==4:
                return [read(depth) for _ in range(n)]
            out={}; previous=b''
            for _ in range(n):
                begin=pos
                k=read(depth)
                if type(k)!=str:
                    raise Error('nontext map key')
                if not 1<=len(k.encode('utf-8'))<=23:
                    raise Error('map key limit')
                encoded=data[begin:pos]
                if encoded<=previous:
                    raise Error('map key order/duplicate')
                previous=encoded
                out[k]=read(depth)
            return out
        raise Error('major type')
    obj=read(0)
    if pos!=len(data):
        raise Error('trailing bytes')
    return obj

def dumps(obj):
    def head(major,n):
        if n<24: return bytes([major*32+n])
        for ai,size in [(24,1),(25,2),(26,4),(27,8)]:
            if n<1<<(8*size): return bytes([major*32+ai])+n.to_bytes(size,'big')
        raise Error('argument limit')
    if type(obj)==bool: return b'\xf5' if obj else b'\xf4'
    if type(obj)==int and 0<=obj<=2**63-1: return head(0,obj)
    if type(obj)==bytes: return head(2,len(obj))+obj
    if type(obj)==str:
        b=obj.encode('utf-8'); return head(3,len(b))+b
    if type(obj)==list: return head(4,len(obj))+b''.join(dumps(v) for v in obj)
    if type(obj)==dict:
        pairs=sorted((dumps(k),dumps(v)) for k,v in obj.items())
        return head(5,len(pairs))+b''.join(k+v for k,v in pairs)
    raise Error('unsupported value')
