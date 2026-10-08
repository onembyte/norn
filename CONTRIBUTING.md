# Contributing

## Gate

All of these must be green before merge:

```sh
make vectors && make vectors-log    # and make vectors-sums when a vector changed
make test
make vectors-check ref-test lint fmt-check vet
```

These are the targets defined by the [Makefile](Makefile) and the gate in
[HARDENING-PLAN.md §1](HARDENING-PLAN.md#1-rules-for-every-checkpoint).

## Changes

Start with a failing test. For every new rule, add a control: break one
essential line, run the named test and see it fail, then restore the line
exactly. Generated files under `testdata/vectors/` are never hand-edited; use
their generator — and the OpenTimestamps anchors only
`contrib/ots-vector/generate.py`, which `python-opentimestamps` writes. The
suite has two Norn provenances: the Python reference
writes entries, state, trust files and enrollment requests; Go writes served
logs, proofs and checkpoints. The split exists because producing a tiled log
requires a log, while independent implementations must agree on the other
vectors ([SPEC.md §12](SPEC.md#12-test-vectors-deliverable-of-phase-01)).

`SPEC.md` is frozen. Change it only with a recorded decision in
[`DECISIONS.md`](DECISIONS.md), in the format **what · why · rejected**. A
change to what a conforming implementation accepts or refuses is a decision,
not a fix.

Make one logical change per commit. Do not add AI attribution trailers. Say
what was wrong, which test was red, what fixed it, and which tests each
control failed.

Outside contributions are reviewed line by line. Unsolicited large changes
are unlikely to be merged before v0.1; small, focused contributions are easier
to review. Contributions are under the [Apache-2.0 license](LICENSE).
