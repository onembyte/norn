"""RFC 8032 §5.1.3 decoding and §5.1.7 verification, implemented from memory.
Norn §3.1 adds canonical, nonidentity, prime-order A/R and uses [S]B=R+[k]A.
No cofactor clearing, scalar reduction of S, or permissive point decoding.
"""
from hashlib import sha512
from functools import lru_cache
P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, P-2, P) % P
I = pow(2, (P-1)//4, P)
O = (0, 1, 1, 0)

def add(a, b):
    x,y,z,t = a; u,v,w,s = b
    aa=(y-x)*(v-u)%P; bb=(y+x)*(v+u)%P
    cc=2*D*t*s%P; dd=2*z*w%P
    e=(bb-aa)%P; f=(dd-cc)%P; g=(dd+cc)%P; h=(bb+aa)%P
    return (e*f%P,g*h%P,f*g%P,e*h%P)

def mul(a,n):
    r=O
    while n:
        if n&1: r=add(r,a)
        a=add(a,a); n >>= 1
    return r

def eq(a,b):
    return (a[0]*b[2]-b[0]*a[2])%P==0 and (a[1]*b[2]-b[1]*a[2])%P==0

def decode(raw):
    if not isinstance(raw,bytes) or len(raw)!=32: raise ValueError('point length')
    v=int.from_bytes(raw,'little'); sign=v>>255; y=v&((1<<255)-1)
    if y>=P: raise ValueError('noncanonical y')
    x2=(y*y-1)*pow(D*y*y+1,P-2,P)%P
    x=pow(x2,(P+3)//8,P)
    if x*x%P!=x2: x=x*I%P
    if x*x%P!=x2 or (x==0 and sign): raise ValueError('invalid point')
    if x&1!=sign: x=P-x
    return (x,y,1,x*y%P)

B=decode((4*pow(5,P-2,P)%P).to_bytes(32,'little'))

@lru_cache(maxsize=8192)
def point(raw):
    a=decode(raw)
    if eq(a,O) or not eq(mul(a,L),O): raise ValueError('not prime order')
    return a

def valid_point(raw):
    try: point(raw); return True
    except (ValueError,TypeError): return False

@lru_cache(maxsize=8192)
def verify(pk,msg,sig):
    try:
        if len(sig)!=64: return False
        a=point(pk); r=point(sig[:32]); s=int.from_bytes(sig[32:],'little')
        if s>=L: return False
        k=int.from_bytes(sha512(sig[:32]+pk+msg).digest(),'little')%L
        return eq(mul(B,s),add(r,mul(a,k)))
    except (ValueError,TypeError): return False

def selftest():
    # RFC 8032 §7.1 TEST 1 (empty) and TEST 2 (one-byte message).
    tests=[
        ('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a','',
         'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555f' 
         'b8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b'),
        ('3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c','72',
         '92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da' 
         '085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00')]
    for pk,m,s in tests:
        pk,m,s=map(bytes.fromhex,(pk,m,s))
        assert verify(pk,m,s)
        assert not verify(pk,m+b'x',s)
        assert not verify(pk,m,s[:32]+(int.from_bytes(s[32:],'little')+L).to_bytes(32,'little'))
    assert not valid_point(b'\x01'+b'\0'*31)
    assert not valid_point(P.to_bytes(32,'little'))
    assert not valid_point(b'\0'*32)
