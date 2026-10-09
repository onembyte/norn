# Implementation notes

This implementation was written from `SPEC.md`, read before the vector payloads.
Vector README/case tables supplied fixture locations and expected results, not
protocol rules. No external project copy, standard document, package, skill,
network endpoint or reference implementation was read. The three standard
algorithms below were implemented from memory. The vector suite is unchanged.

## Standards and independent self-tests

- `ed25519.py`: RFC 8032 §5.1.7, with compressed point decoding from §5.1.3.
  Checks 32-byte A, 64-byte signature, canonical y < p for A/R, existence of x,
  invalid x=0/sign=1, and S < L. Uses the explicitly permitted cofactored
  equation [8S]B = [8]R + [8k]A. It does not invent a stricter subgroup rule.
  The harness first runs §7.1 TEST 1 (empty message, public key d75a9801…)
  and TEST 2 (message 72, public key 3d4017c3…), with their published signatures.
  It also checks changed messages, S=L, y=p, and x=0 with the sign bit set.
  A mistyped TEST 1 signature was corrected during development. A third
  recalled signature was unreliable and was removed; it is not counted as
  an independent standard vector. No fixture was used to repair these tests.
- `merkle.py`: RFC 6962 §2.1, §2.1.1 and §2.1.2; procedure ordering from
  RFC 9162 §2.1.3.2 and §2.1.4.2, recalled from memory. Self-tests use
  explicitly assembled three/four-leaf trees, including the right edge and
  the non-power-of-two consistency proof [c,d,H(a,b)]. Recursively generated
  paths then exercise all indices and old sizes for tree sizes 1–17, rejecting
  extra proof nodes. These generated-path tests supplement the hand-built
  assertions; they are not claimed to be published standard vectors.
- `bech32m.py`: BIP-350's “Bech32m” checksum section, with the bit conversion
  inherited from BIP-173. All seven generic valid strings and fourteen generic
  invalid strings transcribed in `selftest()` are the remembered BIP-350
  vectors. The long valid HRP string was initially misremembered and corrected
  before running Norn tests. Generic tests keep the 90-character bound; Norn
  requests use §16.2's own payload bound and permit uppercase. Round trips for
  payload sizes 0–9 supplement, rather than replace, the published tests.

The primitives are separate modules. Python's hashlib supplies SHA-256/SHA-512;
all elliptic curve operations, CBOR, proof verification and bech32m are local
pure Python. The verifier does not implement signing or X25519: X25519 keys
are opaque 32-byte identities in these verification operations (§3).

## Interpretations, ambiguities and scope

1. **§12/README error vocabulary versus §§7, 10.1, 11.1.** Some explanatory
   paragraphs still say only replay has closed codes. The normative tables
   explicitly give closed codes and precedence for receipts, checkpoints,
   bundles and evidence. Those tables decide; `says` is never string-matched.
   Direct trust, policy, and request cases specify acceptance/refusal rather
   than an additional closed code vocabulary.
2. **§4.2 versus §5.1 bootstrap/incoming key exceptions.** “State before this
   entry” has explicit exceptions: genesis uses its own roots and rotate may
   require an incoming device identity signature. These specific rules take
   precedence over the general statement. An enroll envelope needs signer
   authority, and the embedded request supplies device consent.
3. **§10 outline versus §10.1 execution order.** The outline puts entry fetching
   after branch comparison, but §10.1 explicitly explains why bundles and the
   signed head must verify first. The numbered refusal table decides. Fixtures
   stopping at head/fork/rollback deliberately do not open hash tiles as a
   protocol check; the harness still checks these auxiliary bytes' SHA-256.
4. **§5.3 no-clock representation.** Internally no quorum time is `None`.
   `proven/cases.json` uses zero as its no-clock test convention, so the
   harness translates that zero to `None`. The protocol API preserves a real
   verifying cosignature timestamp of zero as an actual instant.
5. **§6/§10 replay abort.** §10 has no extra closed refusal code for bad genesis.
   `served()` returns canonical replay state with `bad-genesis` at index zero;
   it does not synthesize a new checkpoint code. Callers must inspect the
   replay result before adoption. The CLI refuses to learn new keys/policy
   from an unusable genesis. The static verifier does not run an adoption loop.
6. **§8.1 portable bundle versus current membership.** Bundle checking verifies
   checkpoint, inclusion and device binding, not historical-entry signatures
   against an unavailable historical state. Current membership and installed
   keys require separately verified full replay. The harness checks that
   replay's current key is used even when the enrollment bundle names an old
   WireGuard key. A bundle alone cannot authorize installing a peer.
7. **§7 text integers.** Canonical unsigned decimal is checked, with no invented
   protocol width limit for checkpoint size or receipt deadline. §4.0's 63-bit
   bound belongs to CBOR integers; cosignature timestamps independently occupy
   the specified eight bytes. Python's normal resource limits remain in effect.
8. **§4.0 grants.** Prefixes are parsed using standard-library `ipaddress` with
   host bits masked; any failing part makes the entire grant empty. A mapped
   IPv6 source address is rejected before masking can erase the mapping, as
   well as checking the masked network. Sorting is by textual CIDR.
9. **§12 anchors and unprovided formats.** SPEC explicitly says an implementer
   need not parse OpenTimestamps to check its rule. The harness checks the
   checkpoint anchor digest over the exact specified blank-separator range.
   `sample.ots` and `calendar-response.bin` have no Norn verification algorithm
   defined in SPEC: they are opaque auxiliary OTS fixtures, integrity-checked
   through SHA256SUMS. No OTS proof/calendar validation is claimed. The sample's
   case is labeled `opaque-asset`, not cryptographic proof acceptance.
10. **§15/§13/§16.3 operational scope.** This is an offline protocol verifier,
    not a daemon, HTTP server, WireGuard reconciler, SSH agent, signing tool,
    persistence manager, gossip scheduler or OTS client. Those live behaviors
    are explicitly unvectored in §12.1. It provides primitives for comparison,
    expiry, freshness and grant decisions; it does not claim to exercise
    wall/monotonic-clock persistence or enforcement on a real interface.
11. **General standards-precedence sentence versus restated rules.** SPEC says
    its reused C2SP standards win conflicts, yet discusses rules that may
    differ (notably policy comments). Under this sealed brief the documents
    cannot be consulted. The complete local normative rules, especially §9.1's
    explicit comment grammar, are implemented. No other external C2SP behavior
    has been inferred. This is a document-level ambiguity for a reviewer to
    compare with the cited standards, not a failing Norn vector.

No failing protocol case currently requires a rule absent from SPEC. The
interpretations above record API boundaries and conflicting explanatory text,
not rules learned from vector bytes.
