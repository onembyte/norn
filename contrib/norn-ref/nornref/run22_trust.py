"""Run 22's trust cases preserve every field outside their named change."""
from . import fixture, note, run22_policy

GOOD_RULES = {
    'log-url-no-scheme': {'section': '9.1', 'says': 'Norn does not parse URL syntax here'},
    # G30 adds the explicit length sentence; cite the current key-name grammar.
    'long-witness-key-name': {'section': '7', 'says': 'A key name is one or more ASCII bytes'},
    'witness-names-differ-in-case': run22_policy.NAME_RULE,
}
SAYS = {
    'log-url-no-scheme': 'a nonempty log URL needs no scheme',
    'long-witness-key-name': 'the verifier-key name has 73 bytes; the witness short name remains pi',
    'witness-names-differ-in-case': 'pi and PI are distinct witness names with distinct public keys',
}
BAD_RULES = {'62-anchor-type-uint': {'section': '9.1', 'says': 'The two text members are not symmetric'}}


def good_cases():
    url = fixture.trust_file()
    url['log_urls'] = ['log.norn.example/testnet']
    long = fixture.trust_file()
    witness = long['witnesses'][0]
    old = witness['key']
    witness['key'] = note.vkey('norn-witness/' + 'p' * 60,
                              fixture.KEYS['witness-pi'].public, note.ALG_COSIGNATURE)
    long['policy'] = long['policy'].replace(old, witness['key'])
    names = fixture.trust_file()
    names['witnesses'][1]['name'] = 'PI'
    names['policy'] = names['policy'].replace('witness vps ', 'witness PI ').replace(' pi vps friend', ' pi PI friend')
    return [('log-url-no-scheme', url), ('long-witness-key-name', long),
            ('witness-names-differ-in-case', names)]


def bad_cases():
    doc = fixture.trust_file()
    doc['anchor']['type'] = 7
    return [('62-anchor-type-uint', doc)]
