"""Single-entry genesis aborts promoted from cold gate run 22."""
from . import entry, fixture

RULES = {
    '28-signer-order-eight': {'section': '3.1', 'says': 'of a point of order exactly `L`'},
    '29-root-thr-zero': {'section': '5.1', 'says': '`1 ≤ root_thr ≤ len(roots)`'},
    '30-signer-thr-zero': {'section': '5.1', 'says': '`1 ≤ signer_thr ≤ len(signers)`'},
    '31-params-flag-uint': {'section': '4.5', 'says': 'whether `rotate` needs a signer countersignature'},
    '32-params-routes-open': {'section': '4.5', 'says': 'any text but `granted` or `advisory`'},
}


def cases():
    """Retain the fixture roots and sign over each isolated body fault."""
    out = []
    for name in RULES:
        env = fixture.genesis()
        body = env['body']
        if name.startswith('28'):
            body['signers'].append(fixture.ORDER_EIGHT)
        elif name.startswith('29'):
            body['root_thr'] = 0
        elif name.startswith('30'):
            body['signer_thr'] = 0
        elif name.startswith('31'):
            body['params'] = {'rotate_needs_signer': 1}
        else:
            body['params'] = {'routes': 'open'}
        env['sigs'] = []
        fixture._signed(env, [(r, 'root') for r in fixture.ROOTS])
        raw = entry.encode(env)
        out.append((name, raw, fixture.anchor_for([raw])))
    return out
