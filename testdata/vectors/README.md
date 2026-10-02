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
| `log/` | the 138-entry replay fixture. **Read the order from `manifest.json`**, never by sorting filenames; entries that must be refused carry a `.reason` file. The last one is the §4.2 case: a `root_add` signed by two of three roots and by the key in its own body, which is `threshold` because signatures resolve against the state BEFORE the entry |
| `state.json` | the state those 138 entries replay to, in canonical JSON (§14) |
| `proven/` | the devices a node admits at four evaluation times, including the boundary where `expires == T`. `state.json` is clock-independent on purpose, so this is the only vector that exercises expiry — the rule that decides when a device stops being admitted |
| `entries-hostile/` | input the profile must refuse: the eight `bare-` cases are one banned item each — null, undefined, float, negative integer, tag, indefinite length, a non-text map key and invalid UTF-8 — with no schema above them, so only the profile can refuse. The rest are input at and past §4.0's three resource limits — the entry size, the nesting depth and the map-key cap. A case with `says` must be refused for that reason; one marked `accepted` sits exactly at a limit and must be accepted, which is what bounds the limit from below |
| `genesis/` | nineteen ways a genesis entry is refused. `18` and `19` are step 7's two halves — the **role** a signature declares and the **key set** it resolves against |
| `trust.cbor`, `trust.toml`, `trust.fingerprint` | the anchor in both encodings, and the fingerprint an operator compares out of band (§9.3) |
| `log-empty/` | a log with no entries at all, and the zero state §5.1 says it replays to. A reader that treats no genesis as a missing one reports `bad-genesis` instead |
| `trust-good/` | trust files §9.1 **permits**: a witness with no `url`, an `anchor` whose `type` this version does not know, and `at-the-cap`, exactly `MAX_TRUST_BYTES` long (`trust-bad/41-one-past-the-cap` is the same file one byte longer). A reader that requires an optional member refuses files this document allows, and only a positive shows it |
| `trust-bad/` | 41 anchors that must be rejected, each otherwise perfectly valid — including every mandatory §9.1 key, missing one at a time, and five whose single defect is the *only* rule that can refuse them. `40` is the origin one: the log key named for this origin plus a character, so only equality refuses it. `37` and `39` are the key-id pair — one hex digit of a declared id changed, in the log key and in a witness key, carried into the policy too so only the recompute can refuse them |
| `policies/` | SPEC §9.1's restated `tlog-policy` grammar, one whole policy per rule and both sides of each. `cases.json` says which MUST parse and which MUST be refused, and why. Some cases turn on whether the file ends in a newline, so read the bytes rather than a trimmed string. A case with an `evaluate` table also says what its quorum **means** — a set of cosigner names and whether they satisfy it, which is the only way a reader's arithmetic can be checked. Each of the three error characters (`0x0B`, `0x0C`, `0x0D`, and no others) ships **twice**, on purpose. Between a `quorum` line's two fields, reading it as a separator gives a policy that *parses*. Inside a URL (`-in-url`), reading it as ordinary content parses. A reader has to refuse both, which only the error reading does. `nbsp-is-content` is the other side: U+00A0 is not in the set, so it is content. A verifier key may appear only once in a policy (`bad-duplicate-key`, `bad-log-key-as-witness`), but `log` lines may repeat (`two-log-lines`) |
| `requests/`, `requests-bad/` | enrollment requests (§16) and 25 refusals across all four layers. Each positive case carries a `form`: `canonical` for §16.2's lowercase text, or `uppercase` for the same request in the form §16.2 says a reader MUST also accept |
| `receipt.note`, `receipt.json` | a submission receipt (§7) and its parsed form |
| `receipt-bad/` | receipts that MUST be refused. Each is `receipt.note` with one thing changed and **re-signed**, so the signature is impeccable and only the named rule can refuse it — today that is the deadline's spelling, which §6 fixes for a checkpoint's size line and §7 had left open |
| `served/` | the log as a static site: `checkpoint`, entry bundles and hash tiles |
| `checkpoints-bad/` | twenty-two checkpoints that MUST be refused. `cases.json`'s `rules` map names, for each, the SPEC section that states the rule it is about and a phrase that appears there — so a negative cannot exist without the rule being written where a reader will look, each served in place of `served/checkpoint` over the honest tiles. `cases.json` says what each one is, and its `codes` map names the SPEC §10.1 code each MUST be refused with — the first step that fails decides, so `01-unsigned` is `note` and not `log-signature`, and `03-wrong-origin` (signed under another origin's name) is `log-signature` and not `origin`. **Start here if you are checking your verifier**: `04`, `08`, `11`, `12` and `16` are the files in the suite that a verifier which never checks a note or cosignature signature will accept — `cases.json` lists them under `signature_blind_accepts`, so the two cannot drift apart |
| `proofs/` | one self-contained proof bundle per proven device (§8) |
| `proofs-bad/` | twelve bundles that MUST be refused (§8): a wrong entry, a foreign checkpoint, a tampered proof, a checkpoint signed by a key the anchor does not name, one with no witness quorum and one whose checkpoint names another origin. `cases.json` gives the log key, what each refusal must be about, and in `codes` the SPEC §10.1 code each MUST be refused with. Three fail two steps and are coded with the earlier one, which is how §10.1's bundle order is checkable: `foreign-checkpoint` is `log-signature` and not `origin`, `wrong-entry` is `inclusion` and not `binding`, and `no-quorum-tampered-proof` — no cosignature and a tampered proof — is `quorum` and not `inclusion`. `rotate-entry-other-device` and `revoke-entry-other-device` prove a `rotate` and a `revoke` under another device's label (`binding`): §8.1 binds those through the body's `device_id`, not an embedded request |
| `detect/` | **pairs**, not single artifacts: a checkpoint the reader already holds and one it is then offered, each branch served with its own tiles. Accepting a grown head, refusing a shrunk one *without* calling it a fork, and proving a fork from either side — at the same size, on a shorter branch, and on a longer one (`fork-on-a-longer-branch`). `cases.json`'s `codes` names the SPEC §10.1 code for every case that is not accepted; `tampered-bundle-under-a-stored-head` is this log with one corrupt byte, and it is `head`, **not** `fork` — the head is checked before the branches are compared, so one bad byte in transit is never an accusation. `staleness.json` is §8.1 condition 4's ladder as a table, read top to bottom: the two cases with `hard` 700 under `staleness` 900 sit where `fresh` and `hard_stale` can both hold, and `hard_stale` wins (D-060) — `hard-below-staleness` is `hard_stale` at 800 seconds, and `at-the-hard-boundary` is still `fresh` at exactly 700, because the limit is a strict `>` |
| `served-rotated/` | the served head signed by a key the roots published in the log (§9.4). The only vector with two correct answers: refuse it holding only `trust.cbor`, accept it having replayed this log |
| `served-extra-witness/` | the served head plus one more cosignature line, from a witness the policy never names. It MUST be **accepted**: an unknown line is ignored, not refused, because a witness cosigning a log this node does not list is normal in a shared log. Serve it over `served/`'s tiles |
| `served-name-collision/` | the served head plus one more line carrying a **listed** witness's name under a key the policy does not publish for it — the same key `served-extra-witness/` uses, under a borrowed name. §7 makes the key id bind the name, so the line names nobody: it MUST be **accepted**, ignored exactly like a stranger's. Two lines carry the name and one carries the key id. A reader matching on the name alone refuses this head, which would let anyone deny a checkpoint to every node on the network by cosigning it under a name they do not hold. Serve it over `served/`'s tiles |
| `served-twice-cosigned/` | the served head where one witness answers **twice** and both lines verify. It MUST be accepted; `cases.json` gives the evaluation time §5.3's tie-break produces, and the one an oldest-line reader would get instead. Serve it over `served/`'s tiles |
| `served-superseded/` | the served head cosigned by two of three witnesses: accepted by a reader holding only `trust.cbor`, refused by one that has replayed the roots raising the quorum (§9.4) |
| `served-bad/` | §6's four refusals: a tampered entry bundle, a missing one, a tampered hash tile, and a log tampered **consistently** — entries and level-0 tile changed together, so the served directory agrees with itself and not with the head the checkpoint is signed over. That last one is the only case only the rebuild-and-compare rule can refuse; the other tamper cases *can* be caught by the tile rule alone. `cases.json`'s `codes` names the SPEC §10.1 code each MUST be refused with, and §10.1 compares the head **before** it opens a tile: `tampered-entry-bundle` fails both, and is `head` — a reader that checks tiles first, or never rebuilds the tree, answers `tiles`. A served log is a directory, so each case names the path to replace with `file`, the paths to replace with `files`, or the path to delete with `remove`, over an otherwise honest copy of `served/` |
| `fork/` | `evidence.cbor` and `conflicting.checkpoint`: a second branch of this same network, proving the evidence format (§11.1) is checkable by anybody holding `trust.cbor` — plus twenty that must be **refused**, at least one for every SPEC §11.1 code: `bad-oversize`, `bad-oversize-and-not-cbor` and `bad-one-past-the-cap` — sound evidence exactly one byte past `MAX_EVIDENCE_BYTES` — (`oversize`); `bad-non-canonical-cbor` (`cbor`) — the sound evidence with `size` written longer than its shortest form, which a reader with a lenient CBOR decoder accepts; `bad-wrong-version` and `bad-version-and-unknown-key` (`version`); `bad-open-schema`, `bad-short-held-root-and-size-above-held` and `bad-short-proof-hash` (`schema`); `bad-policy-unparseable` (`policy`); `bad-other-origin` and `bad-policy-says-quorum-none` (`held`); `bad-unverifiable-conflicting` (`conflicting`); `bad-size-above-held` and `bad-size-mismatch` (`size`); `bad-forged-proof`, `bad-proof-at-same-size`, `bad-held-root-at-same-size` (at the held size, a `held_root` that is not the root `held` is signed over — the one comparison there is) and `bad-size-zero` (`proof`); `bad-consistent` (`consistent`). `cases.json`'s `says` is what each refusal must be about, a semantic hint, and its `codes` map names the SPEC §11.1 code each MUST be refused with — the first failing step decides. These four are built to fail more than one step, and are coded with the earliest (others fail more than one incidentally — `bad-open-schema` and `bad-wrong-version` are built on `bad-consistent`): `bad-oversize-and-not-cbor` is `oversize` and not `cbor`, because the size bound is checked before any parse; `bad-other-origin`, wrong in both checkpoints, is `held` and not `conflicting`; `bad-version-and-unknown-key` is `version` and not `schema`, because a key set is only closed relative to a version; `bad-short-held-root-and-size-above-held` is `schema` and not `size`, because a hash's length is part of the schema. `cases.json`'s `sound` names the four files that MUST prove a fork: `evidence`, `policy-not-the-readers`, `evidence-at-64` and `evidence-at-the-cap`, exactly `MAX_EVIDENCE_BYTES` long — the last at a power-of-two size below the held one, the consistency-proof shape RFC 6962 handles with its own branch. `policy-not-the-readers.cbor` is the positive twin: a carried policy the reader does not share, which MUST still prove the fork |
| `anchors/` | OpenTimestamps proofs, and a calendar's reply, written by `python-opentimestamps`. **Start at `cases.json`**: it gives each proof's digest in hex and names the bytes that produce it, so you can check the rule without parsing the OpenTimestamps container — a format `SPEC.md` does not describe. The checkpoint proof is over `served/checkpoint` **through the newline that terminates the blank separator line** — the three body lines plus the blank line, four `0x0A`. That is not the three-line body and not §7's signed text; anchoring is advisory, so a reader that picks the wrong one of the three never matches a stamp and never says so |

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

**`cases.json`'''s `says` field is a semantic hint**, not the bytes your
implementation must produce. §5.2 gives replay a closed list of reason codes and
no other layer has one, so outside replay there is nothing to compare: map each
`says` onto your own error by hand, once. What it is for is the discipline it
enforces here — a negative must be refused for its own rule and nothing else,
and a phrase naming that rule is how the generators check it.

A file being absent from this list is a bug in the list — a test in
`internal/specdoc` fails if anything here is undescribed.
