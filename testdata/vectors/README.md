# Norn test vectors

This directory is the **cross-implementation contract** (`SPEC.md` §12). A
second implementation that reproduces everything here agrees with Norn on every
byte that matters, and one that does not has found either a bug or a hole in
the specification — both of which are worth knowing.

Nothing here needs this repository. The files are plain CBOR, JSON, text and
`tlog-tiles` directories; `SPEC.md` beside them is the only document required
to interpret any of it.

## Provenance — three, stated plainly

A vector proves a format, not a fact about the world, and how much it proves
depends on who wrote the bytes.

| Produced by | What | Why it matters |
|---|---|---|
| **`contrib/norn-ref`** (the Python reference) | entries, state, trust, enrollment requests | Written from `SPEC.md` by a second implementation; the Go code must match them, not the other way round |
| **`cmd/norn-genlog`** (this project's Go) | `served/`, `proofs/`, `fork/`, `checkpoints-bad/` | Producing a tiled log requires a log. Validated against libraries neither implementation wrote: `transparency-dev/formats` parses the checkpoint and `x/mod/sumdb/tlog` checks every inclusion proof |
| **`python-opentimestamps`** (the OTS reference) | `anchors/` | Norn reads `.ots` files and never writes them, so the suite's copies come from the implementation that owns the format |

Regenerate the first two with `make vectors` and `make vectors-log`. The third
is never regenerated — see `contrib/ots-vector/`, and the reason is the point
of having it.

## Layout

| Path | What it is |
|---|---|
| `keys.json` | every test key: Ed25519 `{seed, public, kid}` by name, X25519 public keys, and `net` |
| `entries/` | one valid entry per type, canonical bytes, each with a `.json` mirror carrying its hashes and preimage |
| `log/` | the 94-entry replay fixture. **Read the order from `manifest.json`**, never by sorting filenames; entries that must be refused carry a `.reason` file |
| `state.json` | the state those 94 entries replay to, in canonical JSON (§14) |
| `entries-hostile/` | input that is not an entry and never could be: an oversized one and a 200-deep nest, for §4.0's two resource limits. Neither limit is reachable by a valid entry, so these are the only vectors that reach them |
| `genesis/` | twelve ways a genesis entry is refused |
| `trust.cbor`, `trust.toml`, `trust.fingerprint` | the anchor in both encodings, and the fingerprint an operator compares out of band (§9.3) |
| `trust-bad/` | 18 anchors that must be rejected, each otherwise perfectly valid |
| `requests/`, `requests-bad/` | enrollment requests (§16) and 23 refusals across all four layers |
| `receipt.note`, `receipt.json` | a submission receipt (§7) and its parsed form |
| `served/` | the log as a static site: `checkpoint`, entry bundles and hash tiles |
| `checkpoints-bad/` | eight checkpoints that MUST be refused, each served in place of `served/checkpoint` over the honest tiles. `cases.json` says what each one is. **Start here if you are checking your verifier**: `04` and `08` are the only files in the suite that a verifier which never checks a note or cosignature signature will accept |
| `proofs/` | one self-contained proof bundle per proven device (§8) |
| `fork/` | `evidence.cbor` and `conflicting.checkpoint`: a second branch of this same network, proving the evidence format is checkable by anybody holding `trust.cbor` |
| `anchors/` | OpenTimestamps proofs, and a calendar's reply, written by `python-opentimestamps` |

## `SHA256SUMS`

For somebody who downloaded this directory and does not have the generators:
`shasum -a 256 -c SHA256SUMS` from inside it says whether the set is whole and
unmodified. Regenerate with `make vectors-sums` after any change; a test fails
if it is stale.

## Using them

Start at `keys.json` and `entries/`: they need no network, no log and no
crypto beyond Ed25519 and SHA-256. Then `log/manifest.json` and `state.json`,
which together are §5's replay in one comparison. `served/` and `proofs/` need
a `tlog-tiles` reader. `trust-bad/`, `requests-bad/` and `log/*.reason` are the
half most implementations get wrong: each is a file that **must be refused**,
and for the stated reason.

A file being absent from this list is a bug in the list — a test in
`internal/specdoc` fails if anything here is undescribed.
