"""RFC 6962 §§2.1, 2.1.1 and 2.1.2 (RFC 9162 procedures equivalent).
SHA-256 tree hashing, inclusion and consistency verification from memory.
"""
from hashlib import sha256
def leaf(x): return sha256(b'\0'+x).digest()
def node(a,b): return sha256(b'\1'+a+b).digest()
def root(hashes):
    if not hashes: return sha256(b'').digest()
    if len(hashes)==1: return hashes[0]
    k=1<<((len(hashes)-1).bit_length()-1)
    return node(root(hashes[:k]),root(hashes[k:]))
def inclusion(h,index,size,proof,want):
    if not 0<=index<size: return False
    fn=index; sn=size-1; r=h
    for p in proof:
        if sn==0 or len(p)!=32: return False
        if fn&1 or fn==sn:
            r=node(p,r)
            while fn and not fn&1: fn>>=1; sn>>=1
        else: r=node(r,p)
        fn>>=1; sn>>=1
    return sn==0 and r==want
def consistency(m,n,old,new,proof):
    if not 0<m<=n: return False
    if m==n: return not proof and old==new
    fn=m-1; sn=n-1
    while fn&1: fn>>=1; sn>>=1
    it=iter(proof)
    if fn==0: fr=sr=old
    else:
        try: fr=sr=next(it)
        except StopIteration: return False
    for p in it:
        if sn==0 or len(p)!=32: return False
        if fn&1 or fn==sn:
            fr=node(p,fr); sr=node(p,sr)
            while fn and not fn&1: fn>>=1; sn>>=1
        else: sr=node(sr,p)
        fn>>=1; sn>>=1
    return sn==0 and fr==old and sr==new
# Recursive proof builders only for independent hand-built self-tests.
def audit(h,i):
    if len(h)==1: return []
    k=1<<((len(h)-1).bit_length()-1)
    return audit(h[:k],i)+[root(h[k:])] if i<k else audit(h[k:],i-k)+[root(h[:k])]
def subproof(h,m,complete=True):
    if m==len(h): return [] if complete else [root(h)]
    k=1<<((len(h)-1).bit_length()-1)
    if m<=k: return subproof(h[:k],m,complete)+[root(h[k:])]
    return subproof(h[k:],m-k,False)+[root(h[:k])]
def selftest():
    assert root([]).hex()=='e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    assert leaf(b'').hex()=='6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d'
    assert root([])==sha256(b'').digest()
    a,b,c=[leaf(x) for x in (b'a',b'b',b'c')]
    assert root([a,b,c])==node(node(a,b),c)
    assert audit([a,b,c],2)==[node(a,b)]
    for n in (1,2,3,4,5,7,8,9,15,16,17):
        h=[leaf(bytes([i])) for i in range(n)]; r=root(h)
        for i in range(n):
            p=audit(h,i); assert inclusion(h[i],i,n,p,r)
            assert not inclusion(h[i],i,n,p+[b'\0'*32],r)
        for m in range(1,n+1):
            p=subproof(h,m); assert consistency(m,n,root(h[:m]),r,p)
            assert not consistency(m,n,b'\0'*32,r,p)
