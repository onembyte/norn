# Implementation record

The implementation was built from the sealed `SPEC.md`. Core protocol code was
written before reading the vector cases. The suite was subsequently read to
wire inputs and expected answers into the harness and to check the reading.
Neither generators nor any other project implementation were consulted. No
network operations or dependency installations were used. All cryptography is
pure Python with standard-library hashes; test seeds are not used to manufacture
answers or bypass verification.

## Standards implemented from memory

* **RFC 8032 §5.1.3 and §5.1.7**, in `ed25519.py`: compressed Edwards-point
  decoding, SHA-512 challenge, little-endian scalar and cofactorless equation.
  Norn §3.1 is the deciding profile: canonical y below p, no negative zero,
  curve membership, nonidentity, `[L]P = O` for both A and R, and S strictly
  below L. Extended Edwards coordinates implement group operations.
  The first self-test verifies the published **§7.1 TEST 1**, public key
  `d75a9801…`, empty message, signature `e5564300…`; then **TEST 2**, public key
  `3d4017c3…`, message `72`, signature `92a009a9…`. Their complete published
  values are embedded in the module. Changed messages, S+L, identity, y=p,
  and the all-zero encoding add negative controls. The separate vector phase
  checks all 914 untouched CCTV signatures using actual key/message/signature
  bytes; expected flags do not enter the verifier.
* **RFC 6962 §2.1, §2.1.1 and §2.1.2** (equivalent procedural formulations in
  RFC 9162 §2.1.3.2 and §2.1.4.2), in `merkle.py`: domain-separated hashing,
  inclusion and consistency verifiers with the right-edge collapse and exact
  proof consumption. Manual trees check `MTH(a,b,c) = H1(H1(a,b),c)`, the
  last-leaf proof `[H1(a,b)]`, the 2-to-3 consistency proof `[c]`, and the
  3-to-4 consistency proof `[c,d,H1(a,b)]`, where a…d denote leaf hashes.
  Recursive RFC PATH/SUBPROOF generation additionally exercises every inclusion
  index and every positive old size in trees of sizes 1…33, with extra-node
  rejection controls. These are hand-built/generated trees, not claims about
  a published RFC tree-vector table. The distributed 127-leaf right-edge proof
  and fork evidence provide independent proof producers.
* **BIP-350**, in `bech32m.py`: bech32m checksum selection and test-vector
  sections, together with inherited BIP-173 HRP expansion, polymod, charset and
  bit regrouping. Published valid checksum strings used are `A1LQFN3A`,
  `a1lqfn3a`, `?1v759aa`,
  `split1checkupstagehandshakeupstreamerranterredcaperredlc445v`, and
  `abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx`.
  Published invalid strings used are a space / DEL / U+0080 followed by their
  checksum forms (` 1xj0phk`, `\x7f1g6xzxy`, `\x801vctc34`),
  `qyrz8wqd2c9m`, `1qyrz8wqd2c9m`, `y1b0jsk6g`, `lt1igcx5c0`, `in1muywd`,
  `mm1crxm3i`, `au1s5cgom`, and `M1VUXWEZ`.
  They test the generic checksum decoder. Norn's HRP, omitted 90-character
  limit, case allowance, byte bound and strict padding are imposed separately.
  Round trips of lengths 0…39 add local regrouping checks.

All three self-tests run before any vector file is parsed. They are implemented
from remembered standards, not retrieved documents. The reviewer can compare
the embedded constants, vectors and algorithms directly with those standards.

## Ambiguities and conflicting wording

1. **§11.1 split-check precedence.** The prose numbered reader procedure checks
   that the roots disagree (step 4) before checking version-2 split proofs
   (step 5). The closed refusal-code table puts every split-proof failure in
   step 8 `proof`, before step 9 `consistent`, and explicitly says its order
   decides the first failure. The implementation follows the closed-code table:
   all proof checks precede `consistent`. No supplied case fails both those
   checks, so passing the suite does not resolve that conflict.
2. **§11.1 version-row example.** The version table admits versions 1 and 2,
   and the schema explicitly admits eleven version-2 fields. Its `version`
   refusal description nevertheless says a file with `version: 2` and a key
   version 1 lacks is `version`. That example is inconsistent with the
   version-2 definition. The implementation checks supported version first,
   then the exact key set for that version; an extra version-2 key is `schema`.
   It preserves the stated seven-field version-1 format.
3. **§12's “no other refusing layer has [reason codes]”.** This sentence and
   the nearby “outside replay there is nothing … to compare” are stale against
   §7's closed receipt codes, §10.1's closed checkpoint/bundle codes, and
   §11.1's closed evidence codes. The implementation follows those specific
   normative tables and uses `cases.json.codes` as expectations, never the
   prose in `says` as an error vocabulary.
4. **§3.1 item 2 admission “where the entry … is decoded” and §5.1 ordering.**
   This could be read as checking every body's key during the envelope check,
   before a governance threshold. §5.1 explicitly makes an under-signed
   governance entry with a malformed body `threshold`, and defines the
   duplicate key using only the profile and envelope steps. I therefore check
   admitted keys during that type's body validation, at its stated position,
   never allow an invalid key into state, and do not include body validity in
   the decodable-content duplicate identity. Requests check their keys before
   signatures, as §16 requires.
5. **§9.1 final LF with trailing comments.** The grammar requires every
   directive line to terminate in LF and separately ignores comment lines.
   It does not explicitly decide a final comment lacking LF. The parser
   requires a nonempty policy document to end in LF, including a trailing
   comment, choosing uniform line framing. Every supplied policy obeys or
   violates the directive-line rule without separating these readings.
6. **§§6–7 decimal bit width.** Size and deadline lines are canonical unsigned
   decimals, without a stated numeric bit-width ceiling. The CBOR 63-bit cap
   is expressly the CBOR profile, and witness cosignature timestamps expressly
   use 64 bits. The decimal parser does not import either cap into note lines;
   CBOR integers and timestamp payloads retain their own specified widths.
   Python's default very-large-decimal conversion resource limit still applies.
7. **§§6, 12 anchors.** The spec defines the checkpoint digest's preimage but
   deliberately does not define an OpenTimestamps parser. Accordingly, the
   checkpoint anchor case hashes the bytes through the first blank separator;
   the unrelated sample's supplied digest is checked for its presence in the
   checked artifact. SHA256SUMS checks all anchor files, including the calendar
   response. This answers the provided digest cases; it does not claim to
   validate the OTS timestamp tree or calendar/Bitcoin attestations.

## Scope and validation

Every supplied `cases.json` and `manifest.json` is dispatched; unknown tables
fail the harness. Every replay state is compared as complete canonical bytes,
not parsed JSON equality, and is also written under `reproduced/`. Array order
is preserved. JSON keys are sorted recursively; Python Unicode scalar ordering
agrees with UTF-8 byte ordering for valid Unicode strings, and the configured
JSON escaping matches §14, including literal non-ASCII and DEL.

The trust TOML reconstruction uses standard-library `tomllib`, hence the
harness's Python 3.11 minimum. The algorithms themselves use no external
packages. Entry/request, bundle, trust and evidence bounds are separate. The
CBOR decoder consumes all bytes, checks shortest length/value heads and
strict encoded-key ordering, and bounds depth and declared allocations.

Fresh and informed readers are tested separately. The informed reader is built
from a state obtained after accepting a served head under the fresh reader's
keys and policy; the candidate cannot authorize its own signing key or policy.
The log-key set accumulates while the policy replaces. Stored-head comparison
uses rebuilt served entries, with `head` before `fork`, `fork` before
`rollback`, and genesis binding before tile checks. Quorum timestamps use only
verified lines and the newest timestamp per witness.

The implementation provides offline protocol verification, not daemon
persistence, fork freeze enforcement, network polling, SSH-agent interaction,
private-key loading, submission, WireGuard changes, or OTS attestation
validation. These behaviors are not represented by the supplied static answer
cases. No supplied case is skipped or assigned a constant expected answer in
the verifier.
