"""Norn reference implementation (Python).

Written from SPEC.md, independently of the Go code, and used to generate the test
vectors in testdata/vectors/. It is the oracle: the Go implementation must match
it byte for byte, so this package must never import or consult the Go code.
"""
