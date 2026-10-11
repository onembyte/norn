"""BIP-350: bech32m checksum and published test vectors, from memory.
BIP-173 inherited HRP expansion/charset/polymod/convertbits; Norn §16.2
omits the address length bound and requires HRP norn and strict padding.
"""
CHARSET='qpzry9x8gf2tvdw0s3jn54khce6mua7l'
CONST=0x2bc830a3

def polymod(v):
    chk=1
    for x in v:
        top=chk>>25; chk=((chk&0x1ffffff)<<5)^x
        for i,g in enumerate((0x3b6a57b2,0x26508e6d,0x1ea119fa,0x3d4233dd,0x2a1462b3)):
            if top>>i&1: chk^=g
    return chk

def expand(hrp): return [ord(c)>>5 for c in hrp]+[0]+[ord(c)&31 for c in hrp]

def decode(s):
    if not s or any(not 33<=ord(c)<=126 for c in s): raise ValueError('ASCII')
    if s!=s.lower() and s!=s.upper(): raise ValueError('mixed case')
    s=s.lower(); sep=s.rfind('1')
    if sep<1 or len(s)-sep<7: raise ValueError('separator/checksum')
    try: v=[CHARSET.index(c) for c in s[sep+1:]]
    except ValueError: raise ValueError('charset')
    hrp=s[:sep]
    if polymod(expand(hrp)+v)!=CONST: raise ValueError('checksum')
    return hrp,v[:-6]

def convert(v,src,dst,pad):
    acc=bits=0; out=[]
    for x in v:
        if x<0 or x>>src: raise ValueError('group')
        acc=((acc<<src)|x)&((1<<(src+dst-1))-1); bits+=src
        while bits>=dst:
            bits-=dst; out.append((acc>>bits)&((1<<dst)-1))
    if pad:
        if bits: out.append((acc<<(dst-bits))&((1<<dst)-1))
    elif bits>=src or (acc<<(dst-bits))&((1<<dst)-1): raise ValueError('padding')
    return out

def encode(hrp,data):
    v=convert(data,8,5,True)
    chk=polymod(expand(hrp)+v+[0]*6)^CONST
    return hrp+'1'+''.join(CHARSET[x] for x in v+[(chk>>(5*(5-i)))&31 for i in range(6)])

def payload(s):
    hrp,v=decode(s)
    if hrp!='norn': raise ValueError('HRP')
    b=bytes(convert(v,5,8,False))
    if len(b)>65535: raise ValueError('size')
    return b

def selftest():
    # Published BIP-350 checksum strings; generic decoder, no HRP restriction.
    for s in ('A1LQFN3A','a1lqfn3a','?1v759aa',
              'split1checkupstagehandshakeupstreamerranterredcaperredlc445v',
              'abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx'):
        decode(s)
    for s in (' 1xj0phk','\x7f1g6xzxy','\x801vctc34','qyrz8wqd2c9m','1qyrz8wqd2c9m','y1b0jsk6g','lt1igcx5c0','in1muywd','mm1crxm3i','au1s5cgom','M1VUXWEZ'):
        try: decode(s)
        except ValueError: pass
        else: raise AssertionError(s)
    for n in range(40):
        b=bytes(range(n)); assert payload(encode('norn',b))==b
