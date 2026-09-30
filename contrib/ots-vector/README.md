# Generating `testdata/vectors/anchors/*.ots`

These are written by **`python-opentimestamps`**, the reference implementation
of a format neither of Norn's implementations owns. They are in the suite for
the same reason as every other cross-check here: a parser checked only against
its own writer agrees with itself and with nobody.

Nothing regenerates them automatically — `make vectors` leaves them alone
(`KEEP` in `gen_vectors.py`, excluded in the Makefile). To rebuild:

```sh
git clone --depth 1 https://github.com/opentimestamps/python-opentimestamps /tmp/ots
PYTHONPATH=/tmp/ots:$(pwd)/contrib/ots-vector/stub python3 contrib/ots-vector/generate.py
```

The stub exists because `python-opentimestamps` imports `python-bitcoinlib`, and
since upstream `3af46432` also `Cryptodome.Hash.keccak` (for `OpKECCAK256`), for
code paths its serializer never touches; installing those trees to obtain a few
hundred bytes is not a trade worth making. The `Cryptodome` stub raises if
anything ever calls it. With both stubs, upstream `3af46432` reproduces the
committed anchors byte for byte (checked 2026-09-30).

Re-stamp whenever the served checkpoint changes -- the log gaining an entry is
enough, because the stamped bytes carry the tree size. `generate.py` reads the
size from `served/checkpoint`, deletes the stale `checkpoint-<size>.ots` and
rewrites `cases.json`; run `make vectors-sums` afterwards.
