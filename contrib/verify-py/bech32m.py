"""BIP-350: Bech32m checksum/decoding and BIP-173 bit conversion, from memory.
Norn §16.2 removes the 90-character bound and requires HRP norn.
"""
CHARS='qpzry9x8gf2tvdw0s3jn54khce6mua7l'
GEN=(0x3b6a57b2,0x26508e6d,0x1ea119fa,0x3d4233dd,0x2a1462b3)
CONST=0x2bc830a3

def polymod(values):
    chk=1
    for v in values:
        top=chk>>25; chk=((chk&0x1ffffff)<<5)^v
        for i,g in enumerate(GEN):
            if top>>i&1: chk^=g
    return chk

def expand(hrp): return [ord(c)>>5 for c in hrp]+[0]+[ord(c)&31 for c in hrp]
def decode(text):
    if any(ord(c)<33 or ord(c)>126 for c in text): raise ValueError('range')
    if text.lower()!=text and text.upper()!=text: raise ValueError('mixed case')
    text=text.lower(); sep=text.rfind('1')
    if sep<1 or len(text)-sep-1<6: raise ValueError('separator')
    try: data=[CHARS.index(c) for c in text[sep+1:]]
    except ValueError: raise ValueError('charset')
    if polymod(expand(text[:sep])+data)!=CONST: raise ValueError('checksum')
    return text[:sep],data[:-6]
def convert(data,frombits,tobits,pad):
    acc=bits=0; out=[]; mask=(1<<tobits)-1
    for v in data:
        if v<0 or v>>frombits: raise ValueError('range')
        acc=((acc<<frombits)|v)&((1<<(frombits+tobits-1))-1); bits+=frombits
        while bits>=tobits: bits-=tobits; out.append((acc>>bits)&mask)
    if pad:
        if bits: out.append((acc<<(tobits-bits))&mask)
    elif bits>=frombits or ((acc<<(tobits-bits))&mask): raise ValueError('padding')
    return out

def encode(hrp,raw):
    data=convert(raw,8,5,True); n=polymod(expand(hrp)+data+[0]*6)^CONST
    return hrp+'1'+''.join(CHARS[x] for x in data+[(n>>(5*(5-i)))&31 for i in range(6)])
def payload(text):
    hrp,data=decode(text)
    if hrp!='norn': raise ValueError('hrp')
    raw=bytes(convert(data,5,8,False))
    if len(raw)>65535: raise ValueError('size')
    return raw

def selftest():
    # BIP-350's generic valid and invalid Bech32m strings (not witness addresses).
    for s in ('A1LQFN3A','a1lqfn3a','abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx',
              'split1checkupstagehandshakeupstreamerranterredcaperredlc445v','?1v759aa'):
        decode(s)
    for s in ('A1G7SGD8','1p2gdwpf','x1b4n0q5','li1dgmt3','de1lg7wt\xff','a1lqfn3A','a12uel5l'):
        try: decode(s)
        except ValueError: pass
        else: raise AssertionError('invalid BIP-350 string accepted: '+s)
    for raw in (b'',b'\0',b'\xff',b'hello world'):
        assert payload(encode('norn',raw))==raw
    for data in ([0],[0,0,0],[1,1]):
        try: convert(data,5,8,False)
        except ValueError: pass
        else: raise AssertionError('padding accepted')
