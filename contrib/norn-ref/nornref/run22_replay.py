"""One replay story per run-22 field rule, with genuinely signed twins."""
from . import cbor, entry, enrollreq, fixture, run22_policy

GENESIS_RULE = {'section': '5.1', 'says': 'Otherwise the state is initialised from the body'}
PREV_RULE = {'section': '5.1', 'says': '`ts`, `after` and `prev` uint'}
ID_RULE = {'section': '2', 'says': 'UTF-8 string, 1–64 bytes'}


def stories():
    """Keep these logs separate from the served fixture and its versions."""
    roots = [(n, 'root') for n in fixture.ROOTS]
    signers = [(n, 'signer') for n in fixture.SIGNERS]

    def row(name, env, reason, rule):
        return name, entry.encode(env), reason, rule

    def genesis():
        return row('00-genesis', fixture.genesis(), '', GENESIS_RULE)

    policy = entry.new('policy', fixture.NET, ts=fixture.T0 + 2, prev=0,
                       body={'text': run22_policy.text()})
    fixture._signed(policy, roots)
    out = [('policy-names-differ-in-case', [genesis(),
            row('01-policy-pi-PI', policy, '', run22_policy.NAME_RULE)])]

    signer = entry.new('signer_add', fixture.NET, ts=fixture.T0 + 4,
                       body={'pk': fixture.KEYS['signer3'].public})
    signer['prev'] = False
    fixture._signed(signer, roots)
    bad = row('01-signer-add-prev-false', signer, 'decode', PREV_RULE)
    signer['prev'], signer['sigs'] = 0, []
    fixture._signed(signer, roots)
    out.append(('signer-add-prev-bool', [genesis(), bad,
                row('02-signer-add-prev-zero', signer, '', PREV_RULE)]))

    request = fixture._request('sundial', 'sundial', 'sundial', 0)
    request['device_id'] = ''
    enrollreq.sign(request, fixture.KEYS['sundial'])
    enroll = entry.new('enroll', fixture.NET, ts=fixture.T0 + 1,
                       body={'request': cbor.encode(request)})
    fixture._signed(enroll, signers)
    bad = row('01-enroll-empty-device-id', enroll, 'decode', ID_RULE)
    request['device_id'] = 'sundial'
    enrollreq.sign(request, fixture.KEYS['sundial'])
    enroll['body'], enroll['sigs'] = {'request': cbor.encode(request)}, []
    fixture._signed(enroll, signers)
    out.append(('enroll-empty-device-id', [genesis(), bad,
                row('02-enroll-sundial', enroll, '', ID_RULE)]))
    return out
