"""Just enough of `pycryptodomex` for `python-opentimestamps` to import.

Upstream imports `Cryptodome.Hash.keccak` at module load for `OpKECCAK256`,
an operation `generate.py` never uses. Installing the real package to write a
few hundred bytes is the same trade the `bitcoin` stub beside this one refuses.
"""
