"""RFC 6962 §2.1 hashing, §2.1.1 inclusion, §2.1.2 consistency.

Proof procedures follow RFC 9162 §2.1.3.2 and §2.1.4.2 node ordering.
"""
from hashlib import sha256

def leaf(entry):
    return sha256(b'\x00'+entry).digest()

def node(left,right):
    return sha256(b'\x01'+left+right).digest()

def root(hashes):
    n = len(hashes)
    if not n:
        return sha256(b'').digest()
    if n == 1:
        return hashes[0]
    k = 1 << ((n-1).bit_length()-1)
    return node(root(hashes[:k]),root(hashes[k:]))

def inclusion(h, index, size, proof, expected):
    if not 0 <= index < size or any(len(p)!=32 for p in proof):
        return False
    fn, sn = index, size-1
    for p in proof:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            h = node(p,h)
            while fn and not fn & 1:
                fn >>= 1
                sn >>= 1
        else:
            h = node(h,p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and h == expected

def consistency(old_size,new_size,old_root,new_root,proof):
    if not 0 < old_size <= new_size or any(len(p)!=32 for p in proof):
        return False
    if old_size == new_size:
        return not proof and old_root == new_root
    fn, sn = old_size-1,new_size-1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    if fn == 0:
        fr = sr = old_root
    else:
        if not proof:
            return False
        fr = sr = proof[0]
        proof = proof[1:]
    for p in proof:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr = node(p,fr)
            sr = node(p,sr)
            while fn and not fn & 1:
                fn >>= 1
                sn >>= 1
        else:
            sr = node(sr,p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and fr == old_root and sr == new_root

def audit_path(hashes,i):
    if len(hashes)==1:
        return []
    k = 1 << ((len(hashes)-1).bit_length()-1)
    if i < k:
        return audit_path(hashes[:k],i)+[root(hashes[k:])]
    return audit_path(hashes[k:],i-k)+[root(hashes[:k])]

def consistency_path(hashes,m,complete=True):
    n = len(hashes)
    if m==n:
        return [] if complete else [root(hashes)]
    k = 1 << ((n-1).bit_length()-1)
    if m<=k:
        return consistency_path(hashes[:k],m,complete)+[root(hashes[k:])]
    return consistency_path(hashes[k:],m-k,False)+[root(hashes[:k])]

def selftest():
    a,b,c,d = [leaf(bytes([i])) for i in range(4)]
    assert root([a,b,c]) == node(node(a,b),c)
    assert inclusion(c,2,3,[node(a,b)],root([a,b,c]))
    assert consistency(2,3,node(a,b),root([a,b,c]),[c])
    assert consistency(3,4,root([a,b,c]),node(node(a,b),node(c,d)),[c,d,node(a,b)])
    for n in range(1,18):
        hs = [leaf(bytes([i])) for i in range(n)]
        for i in range(n):
            p = audit_path(hs,i)
            assert inclusion(hs[i],i,n,p,root(hs))
            assert not inclusion(hs[i],i,n,p+[a],root(hs))
        for m in range(1,n+1):
            p = [] if m==n else consistency_path(hs,m)
            assert consistency(m,n,root(hs[:m]),root(hs),p)
            assert not consistency(m,n,root(hs[:m]),root(hs),p+[a])
