"""RFC 6962 §§2.1, 2.1.1, 2.1.2; verification procedures as RFC 9162
§§2.1.3.2 and 2.1.4.2, implemented from memory. Proofs are bottom-up.
"""
from hashlib import sha256

def leaf(e): return sha256(b'\0'+e).digest()
def node(a,b): return sha256(b'\1'+a+b).digest()
def root(hashes):
    n=len(hashes)
    if not n: return sha256(b'').digest()
    if n==1: return hashes[0]
    k=1<<((n-1).bit_length()-1)
    return node(root(hashes[:k]),root(hashes[k:]))

def inclusion(h,index,size,proof,expected):
    if not 0<=index<size: return False
    fn=index; sn=size-1; r=h
    for p in proof:
        if sn==0: return False
        if fn&1 or fn==sn:
            r=node(p,r)
            while fn and not fn&1: fn>>=1; sn>>=1
        else: r=node(r,p)
        fn>>=1; sn>>=1
    return sn==0 and r==expected

def consistency(m,n,old,new,proof):
    if not 0<m<=n: return False
    if m==n: return not proof and old==new
    fn=m-1; sn=n-1
    while fn&1: fn>>=1; sn>>=1
    if fn==0: fr=sr=old; rest=proof
    else:
        if not proof: return False
        fr=sr=proof[0]; rest=proof[1:]
    for p in rest:
        if sn==0: return False
        if fn&1 or fn==sn:
            fr=node(p,fr); sr=node(p,sr)
            while fn and not fn&1: fn>>=1; sn>>=1
        else: sr=node(sr,p)
        fn>>=1; sn>>=1
    return sn==0 and fr==old and sr==new

def selftest():
    a,b,c,d=[leaf(bytes([i])) for i in range(4)]
    r3=node(node(a,b),c); r4=node(node(a,b),node(c,d))
    assert root([a,b,c])==r3 and root([a,b,c,d])==r4
    for i,p in enumerate(([b,c],[a,c],[node(a,b)])):
        assert inclusion([a,b,c][i],i,3,p,r3)
        assert not inclusion([a,b,c][i],i,3,p+[d],r3)
    assert consistency(1,3,a,r3,[b,c])
    assert consistency(2,3,node(a,b),r3,[c])
    assert consistency(3,4,r3,r4,[c,d,node(a,b)])
    assert consistency(4,4,r4,r4,[])
    assert not consistency(3,4,r3,r4,[d,c,node(a,b)])
    assert not consistency(0,4,b'\0'*32,r4,[])
