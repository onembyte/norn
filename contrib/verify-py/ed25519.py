"""RFC 8032 §§5.1.3, 5.1.7; PureEdDSA verification from memory.
Norn §3.1 further requires A and R to have exactly prime order L.
"""
from hashlib import sha512
from functools import lru_cache
P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, P-2, P) % P
I = pow(2, (P-1)//4, P)
O = (0,1,1,0)
def add(p,q):
    x,y,z,t=p; X,Y,Z,T=q
    a=(y-x)*(Y-X)%P; b=(y+x)*(Y+X)%P
    c=2*D*t*T%P; d=2*z*Z%P
    e=b-a; f=d-c; g=d+c; h=b+a
    return (e*f%P,g*h%P,f*g%P,e*h%P)
def mul(p,n):
    q=O
    while n:
        if n&1: q=add(q,p)
        p=add(p,p); n>>=1
    return q
def eq(p,q):
    return (p[0]*q[2]-q[0]*p[2])%P==0 and (p[1]*q[2]-q[1]*p[2])%P==0
@lru_cache(maxsize=8192)
def decode(s):
    if not isinstance(s,bytes) or len(s)!=32: raise ValueError('point length')
    n=int.from_bytes(s,'little'); y=n&((1<<255)-1); sign=n>>255
    if y>=P: raise ValueError('noncanonical y')
    yy=y*y%P; xx=(yy-1)*pow(D*yy+1,P-2,P)%P
    x=pow(xx,(P+3)//8,P)
    if (x*x-xx)%P: x=x*I%P
    if (x*x-xx)%P or (x==0 and sign): raise ValueError('point')
    if x&1 != sign: x=P-x
    return (x,y,1,x*y%P)
B=decode(bytes.fromhex('5866666666666666666666666666666666666666666666666666666666666666'))
@lru_cache(maxsize=8192)
def valid_point(s):
    try:
        p=decode(s)
        return not eq(p,O) and eq(mul(p,L),O)
    except (ValueError,TypeError): return False
def verify(pk,msg,sig):
    if not isinstance(sig,bytes) or len(sig)!=64 or not valid_point(pk) or not valid_point(sig[:32]): return False
    s=int.from_bytes(sig[32:],'little')
    if s>=L: return False
    k=int.from_bytes(sha512(sig[:32]+pk+msg).digest(),'little')%L
    return eq(mul(B,s),add(decode(sig[:32]),mul(decode(pk),k)))
def selftest():
    # RFC 8032 §7.1 TEST 1, TEST 2, TEST 3 (empty, one-byte, two-byte messages).
    rows=[
    ('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a','',
     'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b'),
    ('3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c','72',
     '92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00'),
    ('fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025','af82',
     '6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a')]
    for a,m,s in rows:
        a,m,s=map(bytes.fromhex,(a,m,s)); assert verify(a,m,s)
        assert not verify(a,m+b'\0',s)
        assert not verify(a,m,s[:32]+(int.from_bytes(s[32:],'little')+L).to_bytes(32,'little'))
    assert not valid_point(b'\x01'+b'\0'*31)
    assert not valid_point(b'\0'*32)
