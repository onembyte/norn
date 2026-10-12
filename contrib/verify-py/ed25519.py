"""RFC 8032 §§5.1.3, 5.1.7 (cofactorless verification), implemented from memory.
Norn §3.1 adds canonical encoding and exact prime-order checks on A and R.
"""
import hashlib
from functools import lru_cache
P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, P-2, P) % P
I = pow(2, (P-1)//4, P)
O = (0, 1, 1, 0)

def add(a,b):
    x,y,z,t=a; X,Y,Z,T=b
    aa=(y-x)*(Y-X)%P; bb=(y+x)*(Y+X)%P
    cc=2*D*t*T%P; dd=2*z*Z%P
    e=bb-aa; f=dd-cc; g=dd+cc; h=bb+aa
    return e*f%P,g*h%P,f*g%P,e*h%P

def mul(p,n):
    q=O
    while n:
        if n&1: q=add(q,p)
        p=add(p,p); n>>=1
    return q

def equal(a,b):
    return (a[0]*b[2]-b[0]*a[2])%P==0 and (a[1]*b[2]-b[1]*a[2])%P==0

def decode(s):
    if type(s) is not bytes or len(s)!=32: raise ValueError('point length')
    n=int.from_bytes(s,'little'); sign=n>>255; y=n&((1<<255)-1)
    if y>=P: raise ValueError('noncanonical y')
    y2=y*y%P; x2=(y2-1)*pow(D*y2+1,P-2,P)%P
    x=pow(x2,(P+3)//8,P)
    if x*x%P!=x2: x=x*I%P
    if x*x%P!=x2 or (x==0 and sign): raise ValueError('invalid point')
    if x&1!=sign: x=P-x
    return x,y,1,x*y%P
B=decode(bytes.fromhex('58'+'66'*31))

@lru_cache(maxsize=8192)
def point(s):
    try:
        q=decode(s)
        if equal(q,O) or not equal(mul(q,L),O): return None
        return q
    except ValueError: return None

def valid(s): return type(s) is bytes and point(s) is not None

@lru_cache(maxsize=16384)
def verify(a,m,s):
    if len(s)!=64: return False
    A=point(a); R=point(s[:32]); scalar=int.from_bytes(s[32:],'little')
    if A is None or R is None or scalar>=L: return False
    k=int.from_bytes(hashlib.sha512(s[:32]+a+m).digest(),'little')%L
    return equal(mul(B,scalar),add(R,mul(A,k)))

def selftest():
    # RFC 8032 §7.1 TEST 1 (empty message) and TEST 2 (message 72).
    vectors=[('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a','',
      'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b'),
      ('3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c','72',
      '92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00')]
    for a,m,s in vectors:
        a,m,s=map(bytes.fromhex,(a,m,s)); assert verify(a,m,s)
        assert not verify(a,m+b'\0',s)
        assert not verify(a,m,s[:32]+(int.from_bytes(s[32:],'little')+L).to_bytes(32,'little'))
    assert not valid(b'\x01'+b'\0'*31)
