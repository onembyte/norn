# Sources, choices and boundaries

This implementation was cold-built from the sealed `SPEC.md`. Vector files
were used to supply test inputs, expected outcomes and fixture transport
ordering, not to derive protocol rules. No other project copy, shared project
rules file, implementation or network source was consulted. The later sealed
read restriction takes precedence over the earlier general request to read a
shared rules file. There was no delegation and no dependency installation.
`SPEC.md` and the vector files were not edited; all 850 entries in
`SHA256SUMS` verify.

## Public standards implemented from memory

* `ed25519.py`: RFC 8032 §§5.1.3 and 5.1.7, with the cofactorless equation
  `[S]B = R + [k]A`. Extended Edwards coordinates implement addition and scalar
  multiplication. Both A and R are decoded canonically and checked for exact
  prime order (`[L]P = O`, `P != O`); S must be below L. These additional
  admissibility restrictions come from Norn §3.1. No library verification or
  reduction of an out-of-range S occurs. The initial self-test embeds RFC
  8032 §7.1 TEST 1 (empty message, public key d75a9801...) and TEST 2 (message
  0x72, public key 3d4017c3...), checks both signatures, then rejects changed
  messages and S+L. It also rejects the identity. The harness subsequently
  executes every CCTV vector using its actual key, message and signature,
  without using flags to decide verification.
* `merkle.py`: RFC 6962 §§2.1, 2.1.1 and 2.1.2, using the equivalent iterative
  verification procedures in RFC 9162 §§2.1.3.2 and 2.1.4.2. Inclusion paths
  are leaf-to-root, with the right-edge collapse; consistency paths initialize
  from the old root for a power-of-two old size and otherwise from the first
  proof node. Proof consumption is exact. Initial self-tests use four leaves
  `SHA256(0x00 || single-byte i)`, i=0..3: all three paths in a three-leaf
  tree; consistency 1->3, 2->3, 3->4 and 4->4; surplus/reordered proofs and
  size-zero rejection. These are hand-built trees, not downloaded fixtures.
  The suite also checks its 127-leaf right edge and all sound/corrupt evidence
  proofs, including power-of-two, same-size and version-2 split proofs.
* `bech32m.py`: BIP-350's Bech32m decoding/checksum, including its inherited
  BIP-173 HRP expansion and bit conversion. The module implements the last
  separator, ASCII range, case rule, charset, generators, checksum constant
  and exact zero-padding checks. Norn §16.2 supplies HRP `norn`, the decoded
  byte cap and removal of the address-length limit. Initial self-tests embed
  the published valid strings `A1LQFN3A`, `a1lqfn3a`,
  `abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx`,
  `split1checkupstagehandshakeupstreamerranterredcaperredlc445v`, and
  `?1v759aa`; published invalid strings `A1G7SGD8`, `1p2gdwpf`, `x1b4n0q5`,
  `li1dgmt3` and `de1lg7wt` followed by byte 0xff. Additional tests reject
  mixed case and the Bech32 (not Bech32m) string `a12uel5l`, test byte
  round-trips and reject excessive/nonzero padding. The harness then runs all
  positive/negative Norn request forms.

These recollected test vectors and algorithms are stated explicitly so a
reviewer can compare them to the published standards; none was fetched.

## Specification choices and ambiguities

1. **§5 anchor wording and old empty fixture.** The prose still says “pair”
   while its normative table has four fields. The table governs: trusted
   replay needs net, genesis_hash, log_key and policy. The last two are used
   only at key/policy invariant checks, as §5 expressly says. The existing
   `log-empty/manifest.json` supplies only the older two byte fields. Its empty
   replay needs neither text field, so the harness passes that input directly
   to the pure replay operation and checks the zero state; it does not infer
   missing keys/policy from other fixtures. Real CLI verification validates
   the complete trust file and supplies its four fields. Empty strings in
   single-genesis fixture anchors are likewise unused, not verifier keys.
2. **§10 pseudocode versus §10.1 ordering.** The outline places fetching after
   its fork block, but §10.1 explicitly explains that entries must frame and
   hash to the signed head first. The numbered refusal procedure governs:
   signatures/body/quorum, entry framing, head, fork/rollback, genesis, tiles.
   Hash tiles for a branch already refused at fork/rollback/head are checked
   in a separate harness check, never as a reason to change its first code.
3. **§8.1 portable bundles versus full authorization.** A portable bundle
   cannot reconstruct all prior signer keys or object versions. Its standalone
   operation checks the specified checkpoint, inclusion and entry-device
   binding. Binding an enroll decodes its request structurally; it does not
   substitute for replay's signer/device-consent authorization. Proven sets
   and installed keys come only from full verified replay. An old enrollment
   key differing from the current key is valid historical evidence, as §8.1
   expressly requires. No additional bundle refusal codes were invented.
4. **§4.0 grants.** “CIDR”/“prefix” is read to require an explicit `/` length;
   a bare host address is not a grant. Masking uses the parsed interface's
   network. An IPv4-mapped IPv6 address is rejected before masking, including
   a prefix length that would mask away the mapped marker. All comma-separated
   parts must parse; one failure discards the whole grant. The shipped grants
   check masking/deduplication/order and whole-list refusal, but do not settle
   every accepted spelling of CIDR; the explicit-slash choice is recorded.
5. **§7 witness timestamp bound.** Checkpoint size and receipt deadline are
   decimal note lines and obey the stated 2^63-1 bound. A witness's timestamp
   is explicitly an unsigned 64-bit binary field; it retains that range.
   Its derived `time <decimal>` signing header is not an extra note-body line.
6. **§12.1 OpenTimestamps boundary.** The spec explicitly says the OTS
   timestamp/calendar format is not supplied and readers are not asked to
   validate it. The checkpoint digest is computed over all three body LFs
   plus the separator LF and compared to `anchors/cases.json`. For the sample
   whose digest has no Norn preimage and the calendar response, only presence
   and suite SHA-256 integrity are asserted. Their timestamp claims are not
   called verified. This is the spec's stated exclusion, not an omitted
   failing Norn case.

No declared protocol case is blocked by these choices. The full harness has
3,001 checks and zero failures, including all four replay fixtures, 25 bad
and one good genesis state, every refusal code, all reader-state pairs, and
all 914 CCTV signatures. No unrecognized case or uncovered data artifact
remains. Self-tests and vector checks show conformance to these supplied
artifacts; they are not a claim of formal verification or of real witness/
calendar behavior. The implementation is an offline verifier, not a signing
tool, gossip daemon, WireGuard enforcer or timestamp client.
