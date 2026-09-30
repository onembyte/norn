# Contributing to Norn

Norn is pre-release and has one maintainer. Before changing anything, read
`README.md`, the gates in `PLAN.md`, the latest entries in `BUILD-LOG.md`,
`docs/audit/ROADMAP.md` and `DECISIONS.md`. An AI agent should also read
`COWORKER.md`, the maintainer's plan for agents working here. Report security
problems as `SECURITY.md` says, not in a public issue.

## Build and test

You need Go at the version `go.mod` names (1.26), and Python 3 for the
reference implementation (CI uses 3.13). The reference implementation expects
a virtualenv at `contrib/norn-ref/.venv` with its one dependency installed:

```sh
python3 -m venv contrib/norn-ref/.venv
contrib/norn-ref/.venv/bin/pip install pynacl
```

| Command | What it does |
|---|---|
| `go build ./...` | builds everything. The programs are `cmd/norn` (CLI), `cmd/nornd` (node daemon), `cmd/norn-log` (log server) and `cmd/norn-genlog` (vector generator). `cmd/norn-witness` is an empty placeholder |
| `make ci` | `fmt-check`, `vet`, then `go test -race -count=1 -timeout 30m ./...`. `cmd/norn` alone takes about five minutes on a quiet machine |
| `make lint` | staticcheck 2025.1.1, through `go run` |
| `make ref-test` | the Python reference's unit tests |
| `make vectors` | regenerates the vectors the Python reference owns into `testdata/vectors/` |
| `make vectors-log` | regenerates the vector directories the Go implementation owns (`served/`, `proofs/`, `fork/`, `checkpoints-bad/`, `detect/` and the rest of `GO_VECTOR_DIRS` in the `Makefile`) |
| `make vectors-check` | regenerates both halves into scratch directories and diffs them against what is committed |
| `make vectors-sums` | rewrites `testdata/vectors/SHA256SUMS`. A test in `internal/specdoc` fails if it is stale |
| `make witness` | builds a pinned, unmodified `transparency-dev/witness` into `build/`. Without it, `internal/interop` skips; set `NORN_REQUIRE_WITNESS=1` to make that a failure |

CI (`.github/workflows/ci.yml`) runs `make ci` and `make lint` on Ubuntu and
macOS, and `make ref-test` and `make vectors-check` on Ubuntu. It sets
`NORN_REQUIRE_SSH_AGENT=1`, so the tests that drive OpenSSH's real
`ssh-agent` fail instead of skipping when it is missing (D-053). Set the same
variable locally if you change `internal/sshagent`.

When the fixture log changes, regenerate in this order: `make vectors`,
`make vectors-log`, then re-stamp `anchors/` by hand as
`contrib/ots-vector/README.md` describes (the stamped bytes carry the tree
size), then `make vectors-sums` and `make vectors-check`. A changed vector is
a changed protocol, so review the diff.

## How work is done here

**Tests first.** Every change goes red, then green, then refactor
(`BUILD-LOG.md`, "Method"). A security fix starts with the regression test
that proves the failure. `docs/audit/ROADMAP.md` names that test for each
task.

**The Python reference is the oracle.** `contrib/norn-ref/` is written from
`SPEC.md` alone. It must never import, consult or be adjusted to agree with
the Go code. When Go and Python disagree, `SPEC.md` decides. When `SPEC.md` is
silent, record the gap as a defect; do not pick a side.

**A negative vector differs from a valid artifact in exactly one way**, so
that only the rule it is named for can refuse it (D-044). Either the change
canonicalises away and the original signatures still verify, or the artifact
is re-signed over the changed bytes so that the signature cannot refuse it
first. When a `trust-bad/` case damages a key, it carries the same damaged
key into the policy, so that the correspondence rules do not refuse it first.
The Go and Python tests check each file's shape before they ask for its
verdict.

**Every negative names its rule.** In each directory's `cases.json`, a
`rules` map gives every negative the `SPEC.md` section that states its rule,
and a `says` phrase that appears verbatim in that section.
`TestEveryNegativeDeclaresTheSectionThatStatesItsRule` enforces this. A
case's `about` is a hint in this implementation's words and is not normative
(SPEC §12, since 6.5l-vi). Vector names derive from their index,
and `SPEC.md` cites vectors by name, never by number (D-041, D-045).

**Mutation controls.** For every new vector or rule, mutate the
implementation to the lax reading, once in Go and once in the Python
reference, and show that exactly the intended files go red. Then restore it.
The `BUILD-LOG.md` entry records the count, as in "Fifteen controls, fifteen
exact". Stubbing signature verification must change the outcome (D-043).
`TestTheSignatureBlindSetIsComputedNotAsserted` works out which
`checkpoints-bad/` files a reader that checks no signature would accept, and
requires `cases.json`'s `signature_blind_accepts` to list exactly those.

**A `SPEC.md` change comes with vectors and guards.** State the rule in the
section that owns it, not only in §12.1's coverage table
(`TestEveryVectoredRuleIsStatedWhereItLives`). Give it a vector, or admit in
§12.1 that it has none. `internal/specdoc` checks the document's structure on
every `make ci`: numbering, cross-references, required sections, vector
citations, coverage counts, and the log size the text states (D-035, D-042).
Rules the prose has lost or garbled before have a specdoc test that fails if
their sentence goes missing, for example
`TestTheShortestFormRuleIsStatedForEveryArgumentNotJustIntegers`. Add one for
a rule of that kind. Every file in `testdata/vectors/` must be described in
`testdata/vectors/README.md` (`TestEveryVectorIsDescribed`).

**`BUILD-LOG.md` gets an entry for every checkpoint.** Each phase table has one
line per sub-checkpoint. A checkpoint is ✅ only when its "done when" is fully
true, the suite is green and the work is committed. Mark it in the checkpoint's
own row and append a journal entry saying what was built and what it got wrong
first. Do not rewrite an earlier entry. A `PLAN.md` gate is ticked only when
every line of it is true, and it is unticked when a line turns out to be false.

**Decisions.** `DECISIONS.md` records what was decided, why, and what was
rejected, newest at the bottom. Entries are superseded, never deleted. A
change to the protocol, to a recorded decision or to a public claim is the
maintainer's to make, not something to slip into a fix. Record it as a
"Decision needed" section in `BUILD-LOG.md` or as a row in the ROADMAP's
decision table, and wait.

**Claims are checked.** `internal/docclaims` compares the README's package
count, test count and "gate lines" count with the repository and `PLAN.md`,
and runs the README's quickstart commands. If you add a `func Test…`, update
the README's test count.

**Dependencies are measured before they are taken** (D-049, D-053, D-059).
Hand-write wire formats, never cryptographic primitives, and never a kernel
protocol you cannot test. `internal/depgraph` keeps `wgctrl` out of the CLI,
the log server and the enforcement logic.

**Commits** are named after their checkpoint, as in
`6.5m-iv: fork evidence in both directions -- ...`. The body says which
defects or findings the commit closes, what changed, the controls, and the
README test count.

## License

Norn is licensed under the Apache License 2.0 (`LICENSE`, D-025). Section 5
of that license covers contributions submitted for inclusion.
