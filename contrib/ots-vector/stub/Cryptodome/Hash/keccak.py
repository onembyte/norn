"""Stub for `Cryptodome.Hash.keccak`.

python-opentimestamps imports it at module load for `OpKECCAK256`, an operation
Norn's proofs never use -- they are SHA-256, append and prepend. Installing
pycryptodomex to satisfy an import that never runs is not worth it, so this
fails loudly if anything ever does call it.
"""


def new(*args, **kwargs):
    raise RuntimeError("keccak256 is not an operation in any Norn proof; "
                       "install pycryptodomex if a proof really needs it")
