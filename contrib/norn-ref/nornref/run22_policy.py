"""Case-distinct short labels refer to distinct fixture witness keys."""
from . import fixture

# The names-row clarification belongs to G30; this is the existing phrase.
NAME_RULE = {'section': '9.1', 'says': 'Nothing here is case-folded'}
NAME = 'names-differ-in-case'


def text():
    return (f'witness pi {fixture.witness_vkey("pi")}\n'
            f'witness PI {fixture.witness_vkey("vps")}\n'
            'group home 2 pi PI\nquorum home\n')


def cases():
    return [(NAME, text(), True, 'pi and PI are distinct witness names with distinct public keys')]


def evaluations():
    return {NAME: [
        {'cosigners': [], 'satisfied': False, 'why': 'neither pi nor PI cosigned'},
        {'cosigners': ['pi'], 'satisfied': False, 'why': 'pi alone does not supply PI'},
        {'cosigners': ['PI'], 'satisfied': False, 'why': 'PI alone does not supply pi'},
        {'cosigners': ['pi', 'PI'], 'satisfied': True, 'why': 'both distinct members cosigned'},
    ]}
