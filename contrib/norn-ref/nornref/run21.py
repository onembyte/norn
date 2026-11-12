"""The signed field-only replay pairs from cold gate run 21."""
from . import cbor, enrollreq, entry, fixture

BOOLEAN_RULE = ('4.0', 'schemas MUST reject them outside `params.rotate_needs_signer`')


def append_rules(b):
    """Append to the actual prefix, keeping request identities and keys fresh."""
    signer = [('signer1', 'signer')]
    phrases = []

    def pair(negative, positive, env, repair, rule):
        b.add(negative, env, 'decode')
        repair['sigs'] = []
        fixture._signed(repair, signer)
        b.add(positive, repair)
        phrases.extend([rule, rule])

    for index, field, hostile, sound, text in (
            (45, 'ts', False, 0, 'ts is false'),
            (47, 'v', True, 1, 'v is true')):
        env = entry.new('note', fixture.NET, ts=0, after=b.index, body={'text': text})
        env[field] = hostile
        fixture._signed(env, signer)
        pair(f'{index}-note-{field}-bool', f'{index+1}-note-{field}-uint',
             env, dict(env, **{field: sound}), BOOLEAN_RULE)

    # These are the reader's sundial consent constructions, with fresh IDs
    # and unused WireGuard keys so the repairs also apply in this shared log.
    for index, field, wg in ((49, 'v', 'rogue'), (51, 'ts', 'escaped'), (53, 'missing-ts', 'contractor')):
        req = fixture._request(f'run21-{field}', 'sundial', wg, 0)
        req['ts'] = 0
        if field == 'missing-ts':
            del req['ts']
            negative, positive = 'without-ts', 'with-ts'
            rule = ('16.1', '| `ts` | uint | ✓ |')
        else:
            req[field] = field == 'v'
            negative, positive = f'{field}-bool', f'{field}-uint'
            rule = BOOLEAN_RULE
        req['sig'] = fixture.KEYS['sundial'].sign(enrollreq.preimage(req))
        env = b.build('enroll', {'request': cbor.encode(req)}, signer)
        req['ts' if field == 'missing-ts' else field] = 1 if field == 'v' else 0
        enrollreq.sign(req, fixture.KEYS['sundial'])
        repair = dict(env, body={'request': cbor.encode(req)})
        pair(f'{index}-enroll-request-{negative}', f'{index+1}-enroll-request-{positive}', env, repair, rule)

    env = b.build('note', {}, signer)
    pair('55-note-without-text', '56-note-empty-text', env, dict(env, body={'text': ''}),
         ('4.3', 'an absent `text` is `decode`'))
    return phrases
