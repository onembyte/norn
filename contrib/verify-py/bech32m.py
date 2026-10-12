"""BIP-350, Specification / Bech32m and Test vectors: from memory.
Norn §16.2 removes the address length bound and fixes HRP norn.
"""
CHARSET='qpzry9x8gf2tvdw0s3jn54khce6mua7l'
GEN=(0x3b6a57b2,0x26508e6d,0x1ea119fa,0x3d4233dd,0x2a1462b3)
CONST=0x2bc830a3
def polymod(v):
    chk=1
    for a in v:
        top=chk>>25; chk=(chk&0x1ffffff)<<5 ^ a
        for i,g in enumerate(GEN):
            if (top>>i)&1: chk^=g
    return chk
def expand(hrp): return [ord(c)>>5 for c in hrp]+[0]+[ord(c)&31 for c in hrp]
def decode(s,max_length=90):
    if max_length is not None and len(s)>max_length: raise ValueError('length')
    if not s or any(ord(c)<33 or ord(c)>126 for c in s) or (s!=s.lower() and s!=s.upper()): raise ValueError('bech32m characters')
    s=s.lower(); pos=s.rfind('1')
    if pos<1 or pos+7>len(s): raise ValueError('separator')
    hrp=s[:pos]
    try: data=[CHARSET.index(c) for c in s[pos+1:]]
    except ValueError: raise ValueError('charset')
    if polymod(expand(hrp)+data)!=CONST: raise ValueError('checksum')
    return hrp,data[:-6]
def convert(data,frombits,tobits,pad):
    acc=bits=0; result=[]; mask=(1<<tobits)-1
    for v in data:
        if v<0 or v>>frombits: raise ValueError('groups')
        acc=((acc<<frombits)|v)&((1<<(frombits+tobits-1))-1); bits+=frombits
        while bits>=tobits:
            bits-=tobits; result.append((acc>>bits)&mask)
    if pad:
        if bits: result.append((acc<<(tobits-bits))&mask)
    elif bits>=frombits or (acc<<(tobits-bits))&mask: raise ValueError('padding')
    return result
def encode(hrp,data):
    p=polymod(expand(hrp)+data+[0]*6)^CONST
    return hrp+'1'+''.join(CHARSET[v] for v in data+[(p>>(5*(5-i)))&31 for i in range(6)])
def selftest():
    # Published BIP-350 valid generic strings, plus invalid vectors.
    good=['A1LQFN3A','a1lqfn3a',
          'an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11sg7hg6',
          'abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx',
          '11llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllludsr8',
          'split1checkupstagehandshakeupstreamerranterredcaperredlc445v','?1v759aa']
    bad=['\x201xj0phk','\x7f1g6xzxy','\x801vctc34',
         'an84characterslonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11d6pts4',
         'qyrz8w','1qyrz8w','y1b0jsk6g','lt1igcx5c0','in1muywd','mm1crxm3i','au1s5cgom','M1VUXWEZ','16plkw9','1p2gdwpf']
    for s in good: decode(s)
    for s in bad:
        try: decode(s)
        except ValueError: pass
        else: raise AssertionError(s)
    for raw in (b'',b'\0',bytes(range(256))): assert bytes(convert(convert(raw,8,5,True),5,8,False))==raw
