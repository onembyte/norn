"""Enough of python-bitcoinlib's surface for the OTS serializer to import.

`opentimestamps.core.timestamp` imports these names for code paths that build
Bitcoin block attestations from real blocks. Serializing a timestamp never
touches them.
"""


class CTransaction:
    pass


class SerializationError(Exception):
    pass


class CBlock:
    pass


class CBlockHeader:
    pass


def b2lx(b):
    return b[::-1].hex()


def b2x(b):
    return b.hex()
