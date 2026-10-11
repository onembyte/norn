"""RFC 6962 §2.1 hashing, §2.1.1 inclusion, §2.1.2 consistency.
Procedural verifiers (RFC 9162 §2.1.3.2/§2.1.4.2), from memory.
Proof ordering is the recursive RFC SUBPROOF / PATH order, bottom to top.
"""
from hashlib import sha256

def leaf(b): return sha256(b'\x00'+b).digest()
def node(a,b): return sha256(b'\x01'+a+b).digest()
def root(hashes):
    n=len(hashes)
    if not n: return sha256(b'').digest()
    if n==1: return hashes[0]
    k=1<<((n-1).bit_length()-1)
    return node(root(hashes[:k]),root(hashes[k:]))

def inclusion(h,index,size,proof,target):
    if not 0<=index<size: return False
    fn=index; sn=size-1
    for p in proof:
        if sn==0 or len(p)!=32: return False
        if fn&1 or fn==sn:
            h=node(p,h)
            while fn and not fn&1: fn>>=1; sn>>=1
        else: h=node(h,p)
        fn>>=1; sn>>=1
    return sn==0 and h==target

def consistency(m,n,old,new,proof):
    if m<=0 or m>n: return False
    if m==n: return not proof and old==new
    fn=m-1; sn=n-1
    while fn&1: fn>>=1; sn>>=1
    pos=0
    if fn==0: fr=sr=old
    else:
        if not proof: return False
        fr=sr=proof[0]; pos=1
    for p in proof[pos:]:
        if sn==0 or len(p)!=32: return False
        if fn&1 or fn==sn:
            fr=node(p,fr); sr=node(p,sr)
            while fn and not fn&1: fn>>=1; sn>>=1
        else: sr=node(sr,p)
        fn>>=1; sn>>=1
    return sn==0 and fr==old and sr==new

def path(h,i):
    if len(h)==1: return []
    k=1<<((len(h)-1).bit_length()-1)
    return path(h[:k],i)+[root(h[k:])] if i<k else path(h[k:],i-k)+[root(h[:k])]

def subproof(h,m,complete=True):
    n=len(h)
    if m==n: return [] if complete else [root(h)]
    k=1<<((n-1).bit_length()-1)
    if m<=k: return subproof(h[:k],m,complete)+[root(h[k:])]
    return subproof(h[k:],m-k,False)+[root(h[:k])]

def selftest():
    a,b,c,d=map(leaf,[b'a',b'b',b'c',b'd'])
    assert root([a,b,c])==node(node(a,b),c)
    assert inclusion(c,2,3,[node(a,b)],root([a,b,c]))
    assert consistency(2,3,node(a,b),root([a,b,c]),[c])
    assert consistency(3,4,root([a,b,c]),root([a,b,c,d]),[c,d,node(a,b)])
    for n in range(1,34):
        h=[leaf(bytes([i])) for i in range(n)]
        for i in range(n):
            p=path(h,i)
            assert inclusion(h[i],i,n,p,root(h))
            assert not inclusion(h[i],i,n,p+[a],root(h))
        for m in range(1,n+1):
            p=subproof(h,m)
            assert consistency(m,n,root(h[:m]),root(h),p)
            assert not consistency(m,n,root(h[:m]),root(h),p+[a])
