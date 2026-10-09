"""Pure Python RFC 8032 §5.1.7 verification; point decoding §5.1.3.

Uses the permitted cofactored verification equation, not a stricter subgroup
policy. Canonical A/R encodings and S < L are checked before group arithmetic.
Variable-time: suitable for public-data verification, not secret-key signing.
"""
import hashlib

P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, P-2, P) % P
I = pow(2, (P-1)//4, P)
IDENTITY = (0, 1, 1, 0)

def decode(s):
    if len(s) != 32:
        raise ValueError('point length')
    n = int.from_bytes(s, 'little')
    sign, y = n >> 255, n & (2**255-1)
    if y >= P:
        raise ValueError('noncanonical y')
    x2 = (y*y-1)*pow(D*y*y+1, P-2, P) % P
    x = pow(x2, (P+3)//8, P)
    if (x*x-x2) % P:
        x = x*I % P
    if (x*x-x2) % P or (x == 0 and sign):
        raise ValueError('point decoding')
    if x & 1 != sign:
        x = P-x
    return (x, y, 1, x*y % P)

def add(a, b):
    x,y,z,t = a
    X,Y,Z,T = b
    A = (y-x)*(Y-X) % P
    B = (y+x)*(Y+X) % P
    C = 2*D*t*T % P
    E = B-A
    F = 2*z*Z-C
    G = 2*z*Z+C
    H = B+A
    return E*F%P, G*H%P, F*G%P, E*H%P

def mul(a, n):
    r = IDENTITY
    while n:
        if n & 1:
            r = add(r, a)
        a = add(a, a)
        n >>= 1
    return r

def equal(a,b):
    return (a[0]*b[2]-b[0]*a[2]) % P == 0 and (a[1]*b[2]-b[1]*a[2]) % P == 0

B = decode(bytes.fromhex('58'+'66'*31))

def verify(pk, message, signature):
    try:
        if len(signature) != 64:
            return False
        A, R = decode(pk), decode(signature[:32])
        S = int.from_bytes(signature[32:], 'little')
        if S >= L:
            return False
        k = int.from_bytes(hashlib.sha512(signature[:32]+pk+message).digest(), 'little') % L
        return equal(mul(B, 8*S), add(mul(R,8), mul(A,8*k)))
    except (ValueError, TypeError):
        return False

def selftest():
    # RFC 8032 §7.1 TEST 1 and TEST 2 (empty and 1-byte messages).
    tests = [
        ('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a', '',
         'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b'),
        ('3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c', '72',
         '92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00')
]
    for p,m,s in tests:
        p,m,s = bytes.fromhex(p),bytes.fromhex(m),bytes.fromhex(s)
        assert verify(p,m,s)
        assert not verify(p,m+b'\0',s)
        assert not verify(p,m,s[:32]+L.to_bytes(32,'little'))
    for s in [P.to_bytes(32,'little'), (2**255+1).to_bytes(32,'little')]:
        assert not verify(s,m,signature=bytes.fromhex(tests[1][2]))
        assert not verify(p,m,s+bytes.fromhex(tests[1][2])[32:])
        try:
            decode(s)
        except ValueError:
            pass
        else:
            raise AssertionError('noncanonical point admitted')
