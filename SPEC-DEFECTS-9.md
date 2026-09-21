# Norn v1 — adversarial specification review

Independent Go implementation (standard library only: own CBOR codec, canonical
JSON, signed-note/cosignature parser, RFC 6962 Merkle + inclusion + consistency
proofs, bech32m, `tlog-policy` parser, `tlog-tiles` reader, TOML->CBOR rebuilder).
Sources under `work/norn/`. Run: `nornv <vectors-dir> [variant|list]`.

## 1. Verdict

**SPEC INSUFFICIENT**

Not because the vectors are weak — they are the strongest suite I have seen for a
document this size — but because there are four places where the vectors require
behaviour the prose does not state, one place where a vector's required refusal
reason contradicts a numbered ordering the prose calls normative, and one place
where the suite's claim about itself is arithmetically false. Three of the four
unstated rules I only got right because the vector is *named after* the rule
(`36-policy-log-key-mismatch`, `32-witness-name-too-long`,
`33-log-url-empty-string`). That is reverse-engineering from filenames, not
conformance to a document.

## 2. Check tally

- Primary reading: **255 harness checks, 255 passed, 0 failed**.
- **327 distinct vector cases** across 22 directories.
- `SHA256SUMS`: **verified** — 495 entries, all present and matching; every file
  in the tree except `SHA256SUMS` itself is listed, nothing listed is missing.
- Every negative refused for its named reason: `entries-hostile/` (`says`),
  `fork/` (`says`), `proofs-bad/` (`says`), all 81 `log/*.reason` (checked against
  `manifest.json` and against the `.reason` sidecars independently), `genesis/`
  (18 abort states byte-compared), `trust-bad/` (37), `requests-bad/` (25),
  `checkpoints-bad/` (16), `policies/` (8), `served-bad/` (3).
- Byte-identical outputs: `state.json`, 18 `genesis/*/state.json`,
  `log-empty/state.json`, 16 `entries/*.json` mirrors, 5 `requests/*.json`
  mirrors, `trust.fingerprint`; `trust.toml` rebuilt to `trust.cbor` byte for byte.
- 12 self-claims checked arithmetically — 11 true, 1 false (D6).
- **197 variants run; 47 still pass everything.**

## 3. Defects

### D1 — §9.1: `trust-bad/36-policy-log-key-mismatch` is refusable only by a rule the document does not have, and which §9.1 elsewhere forbids
Prose: §9.1's `policy` row constrains the policy only against *witnesses*
("MUST name exactly the witnesses `witnesses` lists, with the same keys"), and
the grammar restatement says of `log` lines: "Norn takes the log key from
`norn.trust`, **never from here**". The vector is byte-identical to `trust.cbor`
except the policy's `log` line carries a different verifier key, and MUST be
refused. Variant **`trust-no-policy-log-key`** — dropping the invented rule,
keeping every rule §9.1 states — fails on exactly one check: `trust-bad/36`.
§12.1 files 36 under "the members the table shows and **never constrained**".
Fix: §9.1 must say "any `log` directive in the policy MUST carry the same
verifier key as `log_key`", or the vector must go.
Second-order: because I had to invent that rule it masks rules the document does
state. `trust-no-origin-check` and `trust-no-log-key-name` and `keyid-not-checked`
each pass alone; only `pair-origin-and-policylog` (exposes `13-origin-only`),
`pair-logkeyname-and-policylog` (exposes `11`) and `pair-keyid-and-policy-log`
(exposes `37`) separate them. One invented rule is load-bearing for four vectors.

### D2 — §9.1: a witness `name` has no stated length bound, but `32-witness-name-too-long` must be refused
§9.1's `witnesses` row says `{name, key, url?}` and "`name` unique within the
file" — no length. Grep confirms the only 1–64 byte bound in §9.1 is the
*network* `name`. The vector is a witness named `w`x65, renamed in the policy too
so correspondence and uniqueness both hold. Variant
**`trust-witness-name-unbounded`** fails on exactly that one check.
Fix: "`name` is text, 1–64 bytes, unique within the file".

### D3 — §9.1: nothing forbids an empty string inside `log_urls`, but `33-log-url-empty-string` must be refused
"`log_urls` | array of text, >= 1" — `log_urls = [""]` satisfies that exactly.
Variant **`trust-empty-url-string-ok`** fails on exactly that one check.
Fix: "array of text, >= 1, each member non-empty".

### D4 — §9.1: `anchor.type` and `anchor.mode` are presented identically, yet one is open and the other closed
"`anchor` | `{type, max_lag, mode}` | `type` text (`"opentimestamps"`), `max_lag`
uint, `mode` text (`"advisory"`)". `trust-good/anchor-unknown-type` MUST be
accepted; `trust-bad/35-anchor-unknown-mode` MUST be refused. The asymmetry is
stated only in a parenthetical inside §12.1's *coverage* table. Two variants, one
failure each: **`trust-anchor-type-known`** fails `trust-good/anchor-unknown-type`;
**`trust-anchor-mode-any`** fails `trust-bad/35`. A reader of §9.1 alone has a
coin flip.
Fix: state in §9.1 that an unrecognised `type` MUST be ignored and an
unrecognised `mode` MUST cause rejection.

### D5 — §11.1: the numbered reader order contradicts `fork/bad-size-above-held`
§11.1: "A reader MUST, **in this order**: 1 verify both checkpoints, 2 check
`conflicting`'s size equals `size`, 3 check `proof` chains, 4 conclude a fork
only if…". No step bounds `size` by the held head's size. The vector has
`size = 124`, held size 123, **conflicting size 41** — so step 2 fires first and
the refusal is a size mismatch, which is what `bad-size-mismatch` already covers.
`cases.json` nevertheless requires the refusal to be about "can only speak for
what it holds". Variant **`evidence-steps-literal`** implements §11.1's order
literally and fails on exactly that one check. My primary passes only because I
put an unnumbered held-size check ahead of step 2 — a guess from the filename.
Fix: make the held-size bound a numbered step before the conflicting-size check,
or give the vector a `conflicting` whose size really is 124.

### D6 — `checkpoints-bad/cases.json` and `README.md` make a false claim about `signature_blind_accepts`
Claim: "a reader that never calls Ed25519 accepts **exactly those, and nothing
else here**" — listing 04, 08, 11, 12. But `16-two-log-signatures.checkpoint` is
the honest checkpoint plus one appended line identical to the log's own signature
except the final base64 character (`...GHRgo=` -> `...GHRgs=`): same name, same
4-byte key id, 68-byte payload. Its only defect is a signature that does not
verify. I implemented the signature-blind reader the comment describes and ran it
over all 16 files: it accepts `{04, 08, 11, 12, **16**}`. §12.1 even concedes
their own implementation accepted 16 until run 8.
Fix: add `16-two-log-signatures` to the list, or drop "exactly those".

### D7 — §9.1 claims `policies/` vectors its grammar "from both sides"; it does not
Eight further defensible readings still pass the whole suite. Four change what a
quorum *means*:
- **`pol-dup-member-ok`** — §9.1 says "no member twice"; unvectored. `group home 2 pi pi` is then satisfied by one witness.
- **`pol-k-zero-ok`** — §9.1 says `1 <= k <= n`; unvectored. `group g 0 a b` is satisfied by nobody, so an uncosigned head passes.
- **`pol-nested-group-flat`** — §9.1 says a nested group "counts as **one** member"; `policies/nested-group.txt` is parse-only and nothing in the suite evaluates a nested group against cosignatures.
- **`pol-cr-ok` / `pol-blank-is-any-ws`** — §9.1 names `\r`, `\v`, `\f` as errors; `bad-vertical-tab` covers `\v` only. A CRLF-saved policy parses on one implementation and not the other.
Plus **`pol-one-log-line`** (§9.1 says more than one `log` line is legal; refusing
a second is undetectable), **`pol-keywords-any-case`**, **`pol-all-any-any-case`**,
**`pol-k-leading-zero-ok`** (case-sensitivity and canonical decimal unstated).
The first three are exploitable, not merely incompatible.

### D8 — three of the four stated byte caps have no vector, and §12.1 does not admit it
`MAX_ENTRY_BYTES` is vectored at and past the boundary. `MAX_BUNDLE_BYTES`
(81919), `MAX_TRUST_BYTES` (65536) and `MAX_EVIDENCE_BYTES` (65536) are not
vectored at all: variants **`bundle-max-1000000`**, **`trust-max-1000000`**,
**`evidence-max-1000000`** each raise the cap to a million bytes and pass. §11.1
calls its cap the thing that "matters more here than anywhere else in the
document… a denial of service anybody can post", and §12.1's "what is not
vectored" list — which names six other holes — does not mention any of the three.

### D9 — §8.1's `S_hard = 0` asymmetry is normative, safety-critical and unvectored
§8.1: "zero means not configured, and a node that was never configured for it
stays `degraded` for ever… crossing `S_hard` drops every peer, so a log
unreachable over a weekend must not take a network down by itself".
`detect/staleness.json` carries `hard: 3600` in all five cases; none has
`hard: 0`. Variant **`hard-stale-when-zero`** passes everything — and that
reading drops every peer. §12.1 claims coverage of §8.1 condition 4 and does not
list this hole. Related and benign: **`freshness-hard-first`** also passes, so
the ladder's evaluation order is unpinned.

### D10 — §10's "a node that does not hold `at` … MUST NOT accuse" is unreachable
`at := min(cp.size, stored_cp.size)`, and §10's own loop only stores a checkpoint
after replaying `entries[0:cp.size]`, so a node holding `stored_cp` holds every
entry up to `stored_cp.size >= at`. The branch can never be taken. Variant
**`detect-accuse-when-short`** inverts the rule (accuse instead of refuse) and
passes everything. Fix: delete the clause or say what state it is really about.

### D11 — §5.1's `root_remove` ">= 1 root" clause is dead
`root_thr >= 1` is guaranteed at genesis and by `bad-thr`, so
`left < 1 => left < root_thr`. Variant **`root-remove-only-thr`** (drop the ">= 1"
half) passes everything; **`root-remove-only-one`** (drop the threshold half)
fails 32 checks. §4.0 labels its own unreachable type bans "belt-and-braces"; this
clause deserves the same note.

### D12 — §4.0's "`entry_hash` … of the entry **as received** … not of a re-encoded canonical form" is unobservable
The step-1 *ordering* is vectored (`bad-repeat-of-undecodable`,
`bad-repeat-of-genesis`; `dup-entry-after-decode` fails 4 checks). The "as
received vs re-canonicalised" half is not: variant **`entry-hash-recanonical`**
passes everything. It is unobservable by construction — the only entry whose raw
bytes differ from its canonical encoding violates the profile and is `decode`
before its hash is ever compared. `60-bad-trailing-byte` is refused by the
whole-input rule, not by the hash. Fix: move this to §12.1's "not vectored" list.

### D13 — `vectors/README.md` claims `SPEC.md` is self-sufficient; §16.2 says it is not
README: "`SPEC.md` beside them is the only document required to interpret any of
it." §16.2: "a reader who does not fetch BIP-350 cannot implement this section."
Also required and not restated: RFC 6962's proof algorithms and node ordering
(§11.1 says so), and `tlog-tiles`' path syntax and framing (D14).

### D14 — §6 does not state the endianness of the entry-bundle length prefix, nor the tile path syntax
"Entry bundles are uint16-length-prefixed entry bytes" — not which byte comes
first, though §4.0 leans on that framing to justify 65535. The
`tile/<L>/<NNN>[.p/<W>]` syntax, the base-1000 `x`-prefixed grouping and
level 0's meaning are all `tlog-tiles`'. Legitimate deferral, but it makes D13's
claim false.

### D15 — §16.1's `expires > ts` is not enforced at the entry layer by any vector
`requests-bad/expires-at-ts` pins it standalone. Variant
**`enroll-skip-expires-rule`** — the rule applied to standalone requests and not
to one embedded in an `enroll` — passes everything. Same shape:
**`enroll-request-unbounded`** (MAX_ENTRY_BYTES not applied to an embedded
request, which §4.0 explicitly requires) also passes. A reader who
over-generalises §4.3's "the request's `ts` is not constrained against the
entry's" into "the entry layer does not police request timestamps" builds exactly
this variant.

### D16 — `anchor` is OPTIONAL and no vector omits it
§12.1 claims the row catches "a reader that requires an optional member", citing
`trust-good/witness-without-url` and `trust-good/anchor-unknown-type` — but the
second *has* an anchor. All 40 trust files in the suite carry one. Variant
**`trust-anchor-required`** passes everything. Fix: ship `trust-good/no-anchor.cbor`.

### D17 — §10 says nothing about a signature line naming a key the reader does not know
§10 constrains only "every cosignature LINE naming a witness the policy names".
`07-unnamed-witness-only` is refused either way (the quorum is unmet), so the
suite cannot separate "ignore it" from "refuse the checkpoint over it". Variant
**`cp-refuse-unknown-lines`** passes everything. This is not cosmetic: the moment
a witness cosigns that this node's policy does not list — normal in a shared log —
the refusing implementation stops accepting heads the other accepts. Related:
**`cp-log-sig-must-be-first`** also passes; nothing pins line order.
Fix: state that an unattributable line is ignored, and ship a positive for it.

### D18 — §4.0's 23-byte map-key cap: bytes or runes is unvectored
`at-the-key-limit` is 23 ASCII bytes and `past-the-key-limit` 24 ASCII bytes, so
**`key-cap-runes`** and **`label-key-cap-64`** (the `labels` field rule's own cap)
both pass. §12.1 half-notices the second without concluding the field rule is
unpinned. Fix: a key of 23 multi-byte runes that MUST be refused.

### D19 — minor: §4.0's claim about the deepest legal structure is wrong
"The deepest structure the entry schema itself allows is a request's `labels`
map, at depth 2 of that inner document." In the outer document an entry reaches
depth 3: envelope (1) -> `sigs` array (2) -> a `{kid,role,sig}` map (3).

## 4. Variant table

197 variants; nine flip more than one knob (`pair-…`) to isolate which rule does
the work. **47 still pass.**

### 4a. Still passing (the finding)

| variant | reading | note |
|---|---|---|
| trust-no-origin-check | `origin` need not equal base32(`net`) | masked; `pair-origin-and-policylog` exposes `13` |
| trust-no-log-key-name | log key's note name need not equal `origin` | masked; `pair-logkeyname-and-policylog` exposes `11` |
| keyid-not-checked | verifier-key id not recomputed | masked; `pair-keyid-and-policy-log` exposes `37` |
| trust-strike-off | correspondence as a multiset | §12.1 admits |
| trust-anchor-open | `anchor` is an open schema | only `witnesses` has an open-schema negative |
| trust-anchor-required | `anchor` is mandatory | D16 |
| trust-max-1000000 | MAX_TRUST_BYTES unenforced | D8 |
| trust-log-urls-unique | `log_urls` may not repeat | stricter than the document; undetectable |
| trust-witness-url-nonempty | a present witness `url` must be non-empty | stricter; undetectable |
| bundle-max-1000000 | MAX_BUNDLE_BYTES unenforced | D8 |
| evidence-max-1000000 | MAX_EVIDENCE_BYTES unenforced | D8 |
| bundle-entry-bounded | MAX_ENTRY_BYTES applied to a bundle's entry | §8.1 ambiguous |
| evidence-held-differs | `held` != `conflicting` note required | extra check |
| detect-accuse-when-short | accuse when the node lacks `at` | D10 (unreachable) |
| hard-stale-when-zero | `S_hard = 0` still applies | D9 |
| freshness-hard-first | `hard_stale` before `fresh` | ladder order unpinned |
| t-median | `T` = median | §12.1 admits |
| t-quorum-none-unbounded | `quorum none` -> unbounded `T` | §5.3 forbids in prose; unvectored |
| net-from-genesis | `state.net` from the genesis body | §12.1 admits |
| enroll-dupwg-other | enroll `dup-wg` = "another device" | §12.1 admits |
| enroll-skip-expires-rule | §16.1 `expires>ts` not applied in an enroll | D15 |
| enroll-request-unbounded | embedded request unbounded | D15 |
| entry-hash-recanonical | `entry_hash` over re-encoded bytes | D12 |
| entry-ts-nonzero | `ts` must be non-zero | nothing bounds `ts` |
| size-limit-after | size cap checked after decoding | §4.0 does not say "before allocation" for entries |
| active-wg-derived | `active_wg` recomputed at output | §5.3 defines it as derived |
| dedupe-by-leaf-hash | de-duplicate on the leaf hash | injective either way |
| count-role-by-pk | dedupe signatures by pk not kid | unobservable |
| device-id-runes | `device_id` length in runes | ASCII charset |
| key-cap-runes | map-key cap in runes | D18 |
| label-key-cap-64 | `labels` field-rule key cap 64 | D18 |
| cp-refuse-unknown-lines | refuse an unattributable signature line | D17 |
| cp-log-sig-must-be-first | log signature must be first | D17 |
| receipt-origin-unchecked | receipt origin line unchecked | §7 binds it to nothing |
| root-remove-only-thr | drop the ">= 1 root" half | D11 |
| bech-sep-first | separator = first `1` | unreachable (`1` not in the charset) |
| bech-no-min-data | no minimum data length | BIP-350's; checksum catches it |
| pol-dup-member-ok | a group member may repeat | **D7, quorum-changing** |
| pol-k-zero-ok | `k = 0` legal | **D7, quorum-changing** |
| pol-nested-group-flat | nested members count individually | **D7, quorum-changing** |
| pol-cr-ok | `\r` is a separator | **D7, CRLF** |
| pol-blank-is-any-ws | a `\r`-only line is blank | D7 |
| pol-one-log-line | at most one `log` line | D7 |
| pol-keywords-any-case | `WITNESS` accepted | D7 |
| pol-all-any-any-case | `ALL`/`ANY` accepted | D7 |
| pol-k-leading-zero-ok | `02` accepted as k=2 | D7 |

### 4b. Caught by the suite (150) — variant -> first vector that caught it (failing checks)

```
after-required -> entries/00-genesis (95)
after-strictly-less -> log/1-enroll-nas (96)
bad-utf8-ok -> log/75-bad-invalid-utf8 (5)
bech-90-limit -> requests/req-minimal text (5)
bech-allow-bech32 -> requests-bad/plain-bech32 (1)
bech-allow-mixed -> requests-bad/mixed-case (1)
bech-no-pad-check -> requests-bad/non-zero-padding (1)
bech-pad-len-only -> requests-bad/non-zero-padding (1)
big-uint-ok -> log/76-bad-integer-too-large (4)
bundle-no-device-bind -> proofs-bad/device-not-in-entry (1)
bundle-no-quorum -> served quorum time (12)
bundle-no-version -> proofs-bad/wrong-version (1)
bundle-open -> proofs-bad/open-schema (1)
cosig-time-padded -> served/checkpoint verifies (25)
cp-count-only-good-lines -> checkpoints-bad/11 (2)
cp-extension-lines-ok -> checkpoints-bad/09-extension-line (1)
cp-first-valid-log-sig -> checkpoints-bad/16-two-log-signatures (1)
cp-leading-zero-size-ok -> checkpoints-bad/15-size-leading-zero (1)
cp-no-quorum -> served quorum time (12)
cp-origin-before-sig -> proofs-bad/foreign-checkpoint (1)
cp-refuse-dup-witness-lines -> served-twice-cosigned accepted (1)
depth-16 -> entries-hostile/past-the-depth-limit (1)
depth-4 -> entries-hostile/at-the-depth-limit (1)
depth-counts-scalars -> entries-hostile/at-the-depth-limit (1)
dup-entry-after-decode -> log/110-bad-repeat-of-undecodable (4)
dup-map-keys-ok -> log/74-bad-duplicate-map-key (4)
dupwg-before-dupid -> log/58-bad-dup-id-and-wg (4)
empty-text-rejected -> log/116-note-empty-text (4)
enroll-ts-constrained -> log/115-enroll-request-from-the-future (5)
evidence-carried-policy -> fork/policy-not-the-readers (2)
evidence-no-differ -> fork/bad-consistent (1)
evidence-no-proof -> fork/bad-proof-at-same-size (2)
evidence-no-size-check -> fork/bad-size-mismatch (1)
evidence-no-version -> fork/bad-wrong-version (1)
evidence-open -> fork/bad-open-schema (1)
evidence-proof-at-same-ok -> fork/bad-proof-at-same-size (1)
evidence-size-above-ok -> fork/bad-size-above-held (1)
evidence-steps-literal -> fork/bad-size-above-held (1)   [D5]
expires-strict-gt -> proven/at-the-deadline (1)
expires-zero-expired -> proven/before-the-deadline (3)
fingerprint-lower / -rfc4648 / -ungrouped -> trust fingerprint (1 each)
float-ok -> entries-hostile/bare-float (1)
genesis-after-any -> genesis/04-after-nonzero (1)
genesis-after-required -> log/0-genesis (94)
genesis-hash-not-seen -> log/111-bad-repeat-of-genesis (4)
genesis-name-unbounded -> genesis/14-name-too-long (2)
genesis-no-disjoint -> genesis/09-role-overlap (1)
genesis-no-dup-check -> genesis/10-duplicate-signer (1)
genesis-params-replace -> state.json (2)
indefinite-ok -> log/72-bad-indefinite-text (6)
invalid-sig-fatal -> log/96-bad-forged-signer-sig (4)
json-escape-del -> state.json (2)
json-escape-nonascii -> state.json / entry mirrors (3)
json-escape-solidus -> entries/13-policy mirror (4)
json-no-final-nl -> entries/00-genesis mirror (42)
json-sort-utf16 -> state.json / astral labels (2)
json-upper-hex -> state.json (2)
key-cap-64 -> entries-hostile/past-the-key-limit (1)
keyid-ignores-alg -> trust.cbor parses (2)
keyid-no-name -> trust.cbor parses (2)
log-key-since-is-size -> state.json (2)
log-keys-replace -> state.json (3)
max-entry-65536 -> entries-hostile/past-the-size-limit (1)
negative-int-ok -> entries-hostile/bare-negative-integer (1)
no-after-check -> log/10-bad-after (6)
no-device-kid-check -> log/59-bad-device-sig-wrong-kid (4)
no-expires-gt-ts -> requests-bad/expires-at-ts (1)
no-kid-format-body -> log/112-bad-kid-format-in-body (4)
no-kid-format-check -> log/61-bad-kid-format (4)
no-label-value-cap -> requests-bad/oversize-label (1)
no-labels-cap -> requests-bad/too-many-labels (1)
no-policy-parse-on-entry -> log/50-bad-policy-unparseable (5)
no-reason-cap -> log/114-bad-revoke-reason-too-long (10)
no-request-net-check -> log/57-bad-request-net (10)
no-role-enum-check -> log/44-bad-unknown-role (4)
no-role-match -> log/86-bad-role-mismatch (6)
no-rotate-pop -> log/46-bad-rotate-no-new-key-sig (6)
no-seen-for-rejected -> log/84-bad-repeat-of-rejected (5)
no-sigs-closed-check -> log/119-bad-sigs-fourth-key (4)
no-sigs-sort-check -> log/77-bad-unsorted-sigs (4)
no-text-cap -> log/82-bad-text-too-long (4)
no-tile-hash-check -> served-bad/tampered-hash-tile (1)
non-shortest-ok -> log/64-bad-cbor-nonshortest (4)
nontext-map-key-ok -> entries-hostile/bare-nontext-map-key (1)
note-ascii-dash-ok -> checkpoints-bad/13-ascii-dash-signature (1)
note-needs-signer-only -> log/38-note-final (4)
note-text-includes-blank -> receipt.note signature (30)
note-unterminated-ok -> checkpoints-bad/14-unterminated-signature-block (1)
null-ok -> entries-hostile/bare-null (1)
origin-no-prefix / origin-padded / origin-upper -> trust.cbor parses (2 each)
pair-alg-and-keyid -> trust-bad/15 (1)
pair-all-three-trust-keys -> trust-bad/04,11,13,36,37 (5)
pair-correspondence-and-unique -> trust-bad/08 (4)
pair-cosig-lines-and-oldest -> checkpoints-bad/11 (3)
pair-keyid-and-policy-log -> trust-bad/36,37 (2)
pair-logkeyname-and-policylog -> trust-bad/11,36 (2)
pair-origin-and-log-key-name -> trust-bad/04 (1)
pair-origin-and-policylog -> trust-bad/13,36 (2)
pair-witness-name-and-corr -> trust-bad/17 (3)
params-replace -> state.json (2)
pol-comment-col-1 -> policies/comment-and-indent (1)
pol-dup-name-ok -> policies/bad-duplicate-name (1)
pol-empty-group-ok -> policies/bad-empty-group (1)
pol-forward-ref-ok -> policies/bad-forward-reference (1)
pol-ignore-unknown-kw -> policies/bad-unknown-keyword (1)
pol-many-quorums-ok -> policies/bad-two-quorums (1)
pol-no-comments -> policies/comment-and-indent (1)
pol-no-quorum-ok -> policies/bad-no-quorum (1)
pol-quorum-none-is-name -> fork/bad-policy-says-quorum-none (1)
pol-require-final-nl -> policies/no-trailing-newline (1)
pol-require-log -> policies/no-log-line (1)
proven-includes-revoked -> proven/no-clock (5)
reenrol-merges -> state.json (5)
req-labels-max-64 -> requests-bad/too-many-labels (1)
req-no-sig-check -> log/6-bad-no-device-sig (15)
revoke-roots-excluded -> log/92-revoke-by-roots (11)
root-remove-only-one -> log/25-bad-root-invariant (32)
rotate-dupwg-any -> log/40-rotate-device-key-only (5)
rotate-pop-before-dupwg -> log/109-bad-rotate-dupwg-and-no-new-key-sig (4)
signer-remove-invariant -> log/62-signer_remove-below-threshold (5)
since-index-on-rotate -> state.json (3)
size-rule-before-fork -> detect/fork-on-a-shorter-branch (1)
sort-bare-keys -> trust.cbor parses (107)
stale-boundary-strict -> staleness/at-the-staleness-boundary (1)
staleness-from-default -> staleness/at-the-staleness-boundary (2)
t-oldest-line -> served-twice-cosigned quorum time (1)
tags-ok -> log/71-bad-tag-wrapped-value (5)
thr-as-schema -> log/19-bad-thr (6)
threshold-before-type -> log/107-bad-enroll-unsigned-request-no-signers (4)
tile-width-16 -> served entries read (13)
trailing-data-ok -> log/60-bad-trailing-byte (5)
trust-anchor-mode-any -> trust-bad/35 (1)   [D4]
trust-anchor-type-known -> trust-good/anchor-unknown-type (1)  [D4]
trust-empty-url-string-ok -> trust-bad/33 (1)  [D3]
trust-empty-urls-ok -> trust-bad/28-empty-log-urls (1)
trust-name-unbounded -> trust-bad/26-name-too-long (2)
trust-no-alg-check -> trust-bad/15-witness-key-is-a-note-key (1)
trust-no-correspondence -> trust-bad/17-witness-not-in-policy (2)
trust-no-name-unique -> trust-bad/30-duplicate-witness-name-only (1)
trust-no-policy-log-key -> trust-bad/36 (1)  [D1]
trust-no-witness-min -> trust-bad/29-no-witnesses-only (1)
trust-witness-name-unbounded -> trust-bad/32 (1)  [D2]
trust-witness-open -> trust-bad/31-witness-open-schema (1)
undefined-ok -> entries-hostile/bare-undefined (1)
unsorted-keys-ok -> log/66-bad-cbor-unsorted-keys (5)
vkey-split-all-plus -> trust.cbor parses (2)
```

## 5. Every decision the prose did not make for me

CBOR/encoding: depth counting of scalars (pinned); map-key cap bytes vs runes
(open, D18); size cap before vs after decode (open); duplicate-vs-unsorted
reporting (unobservable); `sigs` sort as text vs bytes (identical); canonical map
order (stated, and §4.1's paragraph is worth 107 checks).

Entry/replay: `ts` may be 0 (open); `after` mandatory (pinned); genesis `after`
mandatory (pinned); where "invalid signatures are ignored" sits relative to the
type rules (pinned only because `96` is a `note`); §16.1 rules inside an `enroll`
(open, D15); `since_index` on rotate (pinned); enroll `dup-wg` any/another (open,
admitted); re-enrolment replace vs merge (pinned); `log_key.since_index` index vs
size (pinned); `state.net` source (open, admitted); seen-set for rejected
entries / entry 0 / hash-before-decode (all pinned) but received-vs-recanonical
bytes (open, D12); `active_wg` stored vs derived (open, equivalent).

Canonical JSON: every §14 rule I flipped is pinned. Exemplary section.

Notes/checkpoints: signed text vs blank line (pinned); unknown signature line
ignored vs fatal (open, D17); log signature position (open, D17); cosignature
timestamp rendering (pinned); verifier-key `+` splitting (pinned); key-id
recomputation (open in my build, pinned for a spec-only build by `37`).

`T`: newest-satisfying vs k-th-newest vs median (open, admitted); newest vs
oldest line per witness (pinned); `quorum none` no-clock vs unbounded (open);
`expires == T` (pinned); `expires == 0` (pinned).

Trust: D1–D4, D16; `log_urls` uniqueness and non-emptiness (open both ways);
`anchor` closed schema (open); witness name bound (open, D2).

Policy: D7; `none` as an ordinary name (pinned, by `fork/bad-policy-says-quorum-none`);
extra fields on a `witness` line (open); keyword and `all`/`any` case (open).

Bundles/evidence/verifier: held-size check placement (contradicts prose, D5);
`held` != `conflicting` (open); the three byte caps (open, D8); freshness ladder
order (open); `S_hard = 0` (open, D9).

Log: entry-bundle endianness (not stated, D14); tile path syntax (not stated,
D14); level-0 hash-tile checking (stated, pinned).

## 6. What I could not cover

- `anchors/sample.ots` (a proof over an arbitrary digest) and
  `anchors/calendar-response.bin` (no format in SPEC.md). `anchors/checkpoint-123.ots`
  **is** covered: I parsed its file-hash op and confirmed the stamped digest is
  SHA-256 of the checkpoint note text **up to and including the blank line** —
  what §6 says, and deliberately *not* §7's signed text. §6 is correct here.
  The OTS attestation chain is out of scope: §6 makes anchoring advisory and
  states no verifier obligation.
- **§11 rules 1–4 over time** — "keep the stored checkpoint unchanged", "raise a
  FORK alarm", and "refuse every later checkpoint not consistent with the stored
  one, **forever**". No vector is a sequence of three or more checkpoints, so the
  permanence rule — the one that takes a network down until a human intervenes —
  is untestable from the suite. `detect/` is pairs only.
- **§7's receipt semantics** (`deadline = now + mmd`; absence after the deadline
  as proof of misbehaviour) — needs two artifacts separated in time.
- **§6's liveness duties** and **§9.4's `overlap`** — log-side obligations with
  no verifier-observable artifact.
- **§8.1 condition 2** (a bundle's checkpoint consistent with the node's stored
  checkpoint) — no vector pairs a bundle with a stored head.
- **`quorum none` accepting an uncosigned head** — admitted in §12.1.
- **Tiling above one tile.** Every log in the suite is < 256 entries, so only
  partial tiles at index 0 are read. Full-tile paths, the `x`-prefixed base-1000
  grouping and levels >= 1 are never exercised — a second implementer's tile-path
  code is entirely untested by this suite.
- **§16.2's error-detection claim above 90 characters** — no vector probes it.

## 7. Rules I got right from outside knowledge, not from the document

No web sources were consulted; this is prior knowledge of the named public
standards, which the brief permits, recorded because a rule I got right from
outside may be one the document failed to state.

1. **RFC 6962 §2.1.1 / §2.1.2** — inclusion and consistency proof verification,
   node ordering, the "first is a power of two" case. §8.1/§11.1 defer explicitly.
2. **RFC 6962 §2.1** tree construction — `MTH({}) = SHA-256()`, the `0x01`
   internal-node prefix, and the split at the largest power of two strictly below
   n. §6 gives only the leaf prefix.
3. **BIP-350** — data charset, HRP expansion, the five generator constants,
   polymod, the six-character checksum, printable ASCII 33–126, separator = last
   `1`. §16.2 declares this dependency openly.
4. **`c2sp.org/tlog-tiles`** — path syntax, base-1000 `x`-prefixed grouping,
   level 0 = leaf hashes, and **big-endian** uint16 bundle framing (D14).
5. **`c2sp.org/signed-note`** — that the base64 is standard (padded), that a
   signature line's name ends at the first space, and that extra/unrecognised
   signature lines are tolerated. §7 claims to be complete ("restated here so an
   implementer needs nothing else") and states none of these three. The third is
   D17, and it is the one that bites.
6. **RFC 4648 §6** — MSB-first 5-bit grouping and what "unpadded" means. §2 gives
   the alphabet twice but not the bit order (the result is pinned by
   `origin-padded` / `origin-upper` / `origin-no-prefix`).
7. **RFC 8949 §4.2.1** — that "shortest form" covers lengths as well as integer
   values, and that map ordering is over the *encoded* key item. §4.0/§4.1 do
   state both.
8. **Ed25519 (RFC 8032)** via `crypto/ed25519`.

Things I got right from vector **filenames** rather than the prose — filed as
defects: D1 (policy log key), D2 (witness name bound), D3 (non-empty log URL),
D4 (type/mode asymmetry), D5 (held-size check placement).

## 8. Credit where it is due

- §4.1's paragraph on map ordering and §14.1's on JSON ordering, with the warning
  that the two "MUST NOT be conflated": I tried to break them and could not.
  `sort-bare-keys` costs 107 checks; `json-sort-utf16` is caught by exactly the
  astral-label vector §12.1 says was built for it.
- §5.1's numbered ordering plus the precedence vectors: every ordering flip I
  tried (`dupwg-before-dupid`, `rotate-pop-before-dupwg`, `threshold-before-type`,
  `dup-entry-after-decode`, `size-rule-before-fork`, `cp-origin-before-sig`) is
  caught, each by the vector §12.1 says exists for it. The one ordering that is
  not pinned is §11.1's — and that is because the prose and the vector disagree
  (D5), not because the vectors are weak.
