# Norn test vectors

This directory is the **cross-implementation contract** (`SPEC.md` §12). A
second implementation that reproduces everything here agrees with Norn on every
byte that matters, and one that does not has found either a bug or a hole in
the specification — both of which are worth knowing.

Nothing here needs this repository. The files are plain CBOR, JSON, text and
`tlog-tiles` directories, and `SPEC.md` beside them is the only document *of
this project* required to interpret any of it.

It is not self-contained, and says so: §16.2 states plainly that "a reader who
does not fetch BIP-350 cannot implement this section", and §8.1 and §11.1 defer
their proof algorithms to RFC 6962 rather than restating them. The preamble
lists every such dependency. `SPEC.md` tells you what Norn decides; the
standards it names tell you what it reuses.

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
| `log/` | the 125-entry replay fixture. **Read the order from `manifest.json`**, never by sorting filenames; entries that must be refused carry a `.reason` file |
| `state.json` | the state those 125 entries replay to, in canonical JSON (§14) |
| `proven/` | the devices a node admits at four evaluation times, including the boundary where `expires == T`. `state.json` is clock-independent on purpose, so this is the only vector that exercises expiry — the rule that decides when a device stops being admitted |
| `entries-hostile/` | input the profile must refuse: the eight `bare-` cases are one banned item each — null, undefined, float, negative integer, tag, indefinite length, a non-text map key and invalid UTF-8 — with no schema above them, so only the profile can refuse. The rest are input at and past §4.0's three resource limits — the entry size, the nesting depth and the map-key cap. A case with `says` must be refused for that reason; one marked `accepted` sits exactly at a limit and must be accepted, which is what bounds the limit from below |
| `genesis/` | eighteen ways a genesis entry is refused |
| `trust.cbor`, `trust.toml`, `trust.fingerprint` | the anchor in both encodings, and the fingerprint an operator compares out of band (§9.3) |
| `log-empty/` | a log with no entries at all, and the zero state §5.1 says it replays to. A reader that treats no genesis as a missing one reports `bad-genesis` instead |
| `trust-good/` | trust files §9.1 **permits**: a witness with no `url`, and an `anchor` whose `type` this version does not know. A reader that requires an optional member refuses files this document allows, and only a positive shows it |
| `trust-bad/` | 38 anchors that must be rejected, each otherwise perfectly valid — including every mandatory §9.1 key, missing one at a time, and five whose single defect is the *only* rule that can refuse them |
| `policies/` | SPEC §9.1's restated `tlog-policy` grammar, one whole policy per rule and both sides of each. `cases.json` says which MUST parse and which MUST be refused, and why. Some cases turn on whether the file ends in a newline, so read the bytes rather than a trimmed string . A case with an `evaluate` table also says what its quorum **means** — a set of cosigner names and whether they satisfy it, which is the only way a reader's arithmetic can be checked|
| `requests/`, `requests-bad/` | enrollment requests (§16) and 25 refusals across all four layers. Each positive case carries a `form`: `canonical` for §16.2's lowercase text, or `uppercase` for the same request in the form §16.2 says a reader MUST also accept |
| `receipt.note`, `receipt.json` | a submission receipt (§7) and its parsed form |
| `served/` | the log as a static site: `checkpoint`, entry bundles and hash tiles |
| `checkpoints-bad/` | sixteen checkpoints that MUST be refused. `cases.json`'s `rules` map names, for each, the SPEC section that states the rule it is about and a phrase that appears there — so a negative cannot exist without the rule being written where a reader will look, each served in place of `served/checkpoint` over the honest tiles. `cases.json` says what each one is. **Start here if you are checking your verifier**: `04`, `08`, `11`, `12` and `16` are the files in the suite that a verifier which never checks a note or cosignature signature will accept — `cases.json` lists them under `signature_blind_accepts`, so the two cannot drift apart |
| `proofs/` | one self-contained proof bundle per proven device (§8) |
| `proofs-bad/` | nine bundles that MUST be refused (§8): a wrong entry, a foreign checkpoint, a tampered proof, a checkpoint signed by a key the anchor does not name, one with no witness quorum and one whose checkpoint names another origin. `cases.json` gives the log key and what each refusal must be about |
| `detect/` | **pairs**, not single artifacts: a checkpoint the reader already holds and one it is then offered, each branch served with its own tiles. Accepting a grown head, refusing a shrunk one *without* calling it a fork, and proving a fork from either side. `staleness.json` is §8.1 condition 4's ladder as a table |
| `served-rotated/` | the served head signed by a key the roots published in the log (§9.4). The only vector with two correct answers: refuse it holding only `trust.cbor`, accept it having replayed this log |
| `served-extra-witness/` | the served head plus one more cosignature line, from a witness the policy never names. It MUST be **accepted**: an unknown line is ignored, not refused, because a witness cosigning a log this node does not list is normal in a shared log. Serve it over `served/`'s tiles |
| `served-twice-cosigned/` | the served head where one witness answers **twice** and both lines verify. It MUST be accepted; `cases.json` gives the evaluation time §5.3's tie-break produces, and the one an oldest-line reader would get instead. Serve it over `served/`'s tiles |
| `served-superseded/` | the served head cosigned by two of three witnesses: accepted by a reader holding only `trust.cbor`, refused by one that has replayed the roots raising the quorum (§9.4) |
| `served-bad/` | §6's three refusals: a tampered entry bundle, a missing one, and a tampered hash tile. A served log is a directory, so each case names the path to replace with `file` or delete with `remove`, over an otherwise honest copy of `served/` |
| `fork/` | `evidence.cbor` and `conflicting.checkpoint`: a second branch of this same network, proving the evidence format (§11.1) is checkable by anybody holding `trust.cbor` — plus twelve that must be **refused**: one per reader step, one carrying a consistency proof where §11.1 requires none, and two about the carried `policy`: `bad-other-origin` and `bad-unverifiable-conflicting` (step 1), `bad-size-mismatch` (step 2), `bad-forged-proof` (step 3), `bad-consistent` (step 4), `bad-policy-says-quorum-none` and `bad-policy-unparseable`. `cases.json` says what each refusal must be about. `policy-not-the-readers.cbor` is the positive twin: a carried policy the reader does not share, which MUST still prove the fork |
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
