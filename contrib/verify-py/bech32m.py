"""BIP-350 'Bech32m' checksum and test vectors; BIP-173 bit regrouping.

Norn §16.2 overrides the address-length limit and requires HRP norn.
The generic decoder keeps the standard 90-character bound for self-tests.
"""
CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'
CONSTANT = 0x2bc830a3

def polymod(values):
    chk = 1
    for v in values:
        top = chk >> 25
        chk = ((chk & 0x1ffffff)<<5)^v
        for i,g in enumerate([0x3b6a57b2,0x26508e6d,0x1ea119fa,0x3d4233dd,0x2a1462b3]):
            if (top>>i)&1:
                chk ^= g
    return chk

def expand(hrp):
    return [ord(c)>>5 for c in hrp]+[0]+[ord(c)&31 for c in hrp]

def decode(text,max_length=90):
    if max_length is not None and len(text)>max_length:
        raise ValueError('bech32m length')
    if any(not 33<=ord(c)<=126 for c in text):
        raise ValueError('bech32m character')
    if text!=text.lower() and text!=text.upper():
        raise ValueError('bech32m mixed case')
    text = text.lower()
    pos = text.rfind('1')
    if pos<1 or len(text)-pos-1<6:
        raise ValueError('bech32m separator')
    hrp = text[:pos]
    try:
        values = [CHARSET.index(c) for c in text[pos+1:]]
    except ValueError:
        raise ValueError('bech32m charset') from None
    if polymod(expand(hrp)+values)!=CONSTANT:
        raise ValueError('bech32m checksum')
    return hrp, values[:-6]

def convert(data,from_bits,to_bits,pad):
    acc = bits = 0
    out = []
    for v in data:
        if not 0<=v<1<<from_bits:
            raise ValueError('group range')
        acc = ((acc<<from_bits)|v)&((1<<(from_bits+to_bits-1))-1)
        bits += from_bits
        while bits>=to_bits:
            bits -= to_bits
            out.append((acc>>bits)&((1<<to_bits)-1))
    if pad:
        if bits:
            out.append((acc<<(to_bits-bits))&((1<<to_bits)-1))
    elif bits>=from_bits or ((acc<<(to_bits-bits))&((1<<to_bits)-1)):
        raise ValueError('bech32m padding')
    return out

def encode(hrp,data):
    values = convert(data,8,5,True)
    p = polymod(expand(hrp)+values+[0]*6)^CONSTANT
    return hrp+'1'+''.join(CHARSET[v] for v in values+[(p>>(5*(5-i)))&31 for i in range(6)])

def payload(text):
    # Bound text before regrouping a hostile input; bytes are capped separately.
    hrp,data = decode(text,4+1+(65535*8+4)//5+6)
    if hrp!='norn':
        raise ValueError('bech32m hrp')
    return bytes(convert(data,5,8,False))

def selftest():
    # BIP-350 generic valid/invalid strings recalled from the published list.
    valid = ['A1LQFN3A','a1lqfn3a',
      'an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11sg7hg6',
      'abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx',
      '11llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllludsr8',
      'split1checkupstagehandshakeupstreamerranterredcaperredlc445v','?1v759aa']
    invalid = ['\x201xj0phk','\x7f1g6xzxy','\x801vctc34',
      'an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx',
      'qyrz8wqd2c9m','1qyrz8wqd2c9m','y1b0jsk6g','lt1igcx5c0','in1muywd','mm1crxm3i','au1s5cgom','M1VUXWEZ','16plkw9','1p2gdwpf']
    for s in valid:
        decode(s)
    for s in invalid:
        try:
            decode(s)
        except ValueError:
            pass
        else:
            raise AssertionError('invalid BIP-350 string admitted: '+repr(s))
    for n in range(10):
        b = bytes(range(n))
        assert payload(encode('norn',b))==b
