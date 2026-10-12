# Implementation notes — Lane BJ, row 6.5l-xii-f

This continues the five modules left by the interrupted earlier session. They
were read first and retained. No other project copy, shared rules outside the
seal, web page, network resource or third-party package was read. The later
sealed-directory prohibition takes precedence over the earlier instruction to
read a shared rules file elsewhere. SPEC and the fixture files were not edited.
Rules were implemented from the current SPEC before examining vector outcomes;
manifests subsequently supplied input ordering, fixture shape and expectations.

## Standards implemented from memory

- **RFC 8032 §§5.1.3 and 5.1.7**, PureEdDSA Ed25519 point decoding and the
  cofactorless verification equation. SPEC §3.1 adds exact-prime-order checks
  for A and R: canonical y, canonical zero-x sign, on-curve point, nonidentity,
  and `[L]P = O`. S is checked strictly below L without reduction. Extended
  Edwards coordinates implement addition and scalar multiplication.
  `ed25519.selftest()` uses RFC 8032 §7.1 TEST 1, TEST 2 and TEST 3, their
  public keys, messages (empty, `72`, `af82`) and published signatures.
  The signature in TEST 3 was mistranscribed in the interrupted work. It was
  corrected locally by checking RFC TEST 3's remembered seed
  `c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7`
  against deterministic RFC §5.1.6 signing during diagnosis; signing is not a
  dependency of the self-test or verifier. All three exact signatures remain
  visible in the self-test for comparison against the RFC. Each test also
  rejects a changed message and S+L. Identity and order-four encodings fail
  point admission. The separate fixture check executes all 914 untouched
  upstream CCTV signatures, rather than deriving answers from flags.

- **RFC 6962 §2.1, §2.1.1 and §2.1.2** (equivalent to RFC 9162 §2.1.3.2 and
  §2.1.4.2): SHA-256 leaf/internal/empty hashing, leaf-to-root inclusion
  verification and old-to-new consistency verification. The proof verifier
  follows the `fn`/`sn` bit-walking procedures, including non-power-of-two
  right edges and the old-size power-of-two initialization branch.
  `merkle.selftest()` checks the known SHA-256 empty-tree and empty-leaf
  digests, the explicit three-leaf shape `node(node(a,b),c)` and the final
  leaf's one-node proof. For sizes 1, 2, 3, 4, 5, 7, 8, 9, 15, 16 and 17 it
  checks every inclusion index and every positive old size, using recursive
  proof construction independent of the iterative verifiers. Extra proof
  nodes and changed roots must fail. Fixture proofs add the 127-leaf right
  edge and version-1/version-2 fork evidence at ordinary, same and power-of-two
  sizes. No empty-tree consistency proof is accepted (§11.1).

- **BIP-350, Specification / Bech32m and Test vectors**, with the BIP-173
  checksum-polynomial and HRP-expansion machinery it retains. The self-test's
  seven published generic valid strings are `A1LQFN3A`, `a1lqfn3a`, the
  83-character HRP ending `...bioandnumber11sg7hg6`, `abcdef1l7aum6...zd3ryx`,
  `11llll...udsr8`, `split1checkup...lc445v`, and `?1v759aa`. The complete
  strings are embedded in `bech32m.py`. Invalid published strings cover the
  ASCII range, 84-character HRP, absent separator, empty HRP, charset, short
  checksum and uppercase-HRP checksum cases; the self-test also covers an
  absent-separator spelling. A newly added long-HRP self-test string was
  initially the BIP-173 version and was corrected to the remembered BIP-350
  string above before the final run. There is no lookup or network dependency.
  Byte/group conversion round-trips empty, zero and all 256 byte values.
  The generic decoder enforces length 90; Norn explicitly disables that limit
  in §16.2 and bounds the decoded request instead. Shipped request cases test
  canonical lowercase, required uppercase acceptance, mixed case, wrong HRP,
  the wrong checksum constant and both forbidden padding forms.

All three primitive self-tests run before the harness opens any vector file.
No external standard document was consulted. The reviewer can compare the
embedded constants, procedures and exact test literals with the named standards.

## Interpretations and ambiguities

1. **§10.1, “Why the head comes before the fork.”** Its explanatory paragraph
   still says the pseudocode lists entry fetching after the fork block, although
   current §10's outline fetches first. I follow §10.1's explicit numbered
   order: framing and signed head, branch comparison, genesis, hash tiles.
   This is a stale explanatory sentence, not a conflicting operative rule.

2. **§5.3, no evaluation clock.** The closing phrase “satisfied at no instant —
   which includes quorum none” is mathematically inconsistent with the earlier
   explanation that `none` is satisfied at every instant. I use the explicit
   rule “Under quorum none there is no clock”: `None` internally means no
   witness time, and expiry is not judged. The proven fixture's t=0 sentinel
   is translated to `None` by the harness only; an actual signed Unix time 0
   remains a real timestamp in the verifier.

3. **§§8.1 and 10.1, bundle binding versus authorization.** The portable bundle
   check verifies its checkpoint, inclusion and named-device binding. It does
   not conclude current membership or install the historical entry's key.
   Embedded enrollment requests are structurally decoded to obtain their id;
   their signature is checked during replay, where entry authorization belongs.
   Full served-log replay supplies current membership and installed keys. The
   spec's three bundle refusal stages do not define an additional independent
   entry-authorization refusal code.

4. **§§6 and 12, served fixture shape.** No shape is inferred from a directory
   name. `serve_over` selects a base; `serve` selects a case's complete
   directory; `path`/`file`, `files` and `remove` describe overlays; otherwise
   checkpoint/tile fixtures are complete local logs. Fresh/informed answers
   describe knowledge of keys/policy, not an implicit stored checkpoint. Thus
   the informed 20-entry rotated head can pass, while a candidate explicitly
   supplied with a larger held head would undergo the fork/rollback checks.
   A previously verified state supplies learned keys; candidate replay never
   bootstraps its own checkpoint trust.

5. **§§6 and 12, anchors.** SPEC expressly supplies the stamped digest and byte
   range so that no OTS parser is required. The harness hashes the checkpoint
   through the separator's final LF (four LFs total). For the arbitrary sample
   it checks that the declared digest occurs in the opaque shipped proof, and
   checks SHA256SUMS for both proofs and the calendar reply. It makes no claim
   about timestamp-tree validity or Bitcoin attestation. No normative OTS
   decoding or reply-verification algorithm is given by SPEC.

6. **§14, UTF-8 object-key order.** Python's scalar Unicode ordering has the
   same order as UTF-8 bytes for the valid Unicode strings admitted by strict
   UTF-8 decoding. Therefore `json.dumps(sort_keys=True, ensure_ascii=False)`
   with compact separators supplies the specified order and escaping; no
   normalization or HTML escaping is performed. All canonical state files
   are compared as raw bytes with their final LF.

No ambiguity prevents answering a shipped case. Where the suite supplies only
semantic hints, the harness uses local diagnostics, not hint-string matching:
request failures are mapped explicitly to text/HRP/padding/profile/schema/
signature layers; hostile CBOR inputs are mapped to the codec's own reason.
Closed refusal codes are compared exactly wherever the manifest defines them.

## Scope

This is an offline verifier and suite runner. It does not implement log
submission, key custody, signing ceremonies, HTTP/gossip services, WireGuard
enforcement, durable daemon state, or OTS/Bitcoin validation. These services
are not required to decide the supplied verifier vectors; SPEC §12.1 names
unvectored operational requirements. Passing the suite does not claim those
services or every unvectored MUST has been implemented.
