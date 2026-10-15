# Cold gate run 16 — decisions log

Written after reading `SPEC.md` in full and before opening `testdata/vectors/README.md`,
any manifest or any vector. Each entry: section, the exact words, what I chose, why.
Not edited after the first vector was opened; later doubts go in the report.

## §3.1 NORN-ED25519-v1

**C01 — §3.1 item 3 / item 4: is `A` checked at verification time?**
Words: "A signature `R ‖ S` (64 bytes) verifies under a key `A` over a message `M` only if `R` is a valid point; `S` … MUST be less than `L` …" and item 4: "rejects every vector … that carries a flag — `low_order_A`, `low_order_R`, `non_canonical_A` …".
Choice: the verification predicate also requires `A` to be a valid point (item 1), not only `R`.
Why: item 3 names only `R`, but item 4 says every `*_A` CCTV vector is rejected, and a low-order or non-canonical `A` need not break the equation. Item 2 makes admitted keys valid anyway, so inside Norn the two readings coincide; only the CCTV set separates them.

**C02 — §3.1 item 1: how a point is decoded.**
Words: "the encoded `y` is below `p`, the sign bit is 0 when `x` is 0, the bytes decode to a point on the curve, and that point is not the identity and has no component of order 2, 4 or 8 — `[L]P = O` and `P ≠ O`."
Choice: strict RFC 8032 §5.1.3 decode (reject `y ≥ p`, reject no square root, reject `x = 0` with sign bit 1), then compute `[L]P` and require the identity, and require `P ≠ O`. Implemented from RFC 8032 with `math/big` (no library decoder consulted).
Why: the spec names both a decode-and-check route and a libsodium-style route; mine is the decode route, all clauses applied.

**C03 — §3.1 item 3: which bytes go into `k`.**
Words: "`k = SHA-512(R ‖ A ‖ M)` read little-endian and reduced mod `L`, `[S]B = R + [k]A`."
Choice: `R` and `A` are the 32 encoded bytes exactly as received; cofactorless equation checked by comparing `[S]B` with `R + [k]A` in projective form.
Why: RFC 8032 §5.1.7; the spec names the cofactorless form as the definition.

## §4.0 Encoding profile

**C04 — §4.0 simple values in the two-byte form.**
Words: "every other simple value (0–19, and 32–255 in the two-byte form)".
Choice: any head `0xf8 xx` is refused, including `0xf8 0x14` / `0xf8 0x15` and `0xf8 0x00–0x1f`; only `0xf4` and `0xf5` pass.
Why: values 20–31 in the two-byte form are not well-formed CBOR (RFC 8949 §3.3) and are not "the two simple values `false` (20) and `true` (21)" in shortest form either.

**C05 — §4.0 scope of the map-key cap.**
Words: "every **map key** is a text string of 1–23 bytes" (Text strings row), in a profile that governs "All Norn CBOR structures — entries, enrollment requests, trust files, proof bundles (§8.1) and fork evidence (§11.1)".
Choice: one decoder for all five artifacts; it refuses a non-text map key and a key of 0 or more than 23 bytes before any schema runs. So an empty label key and a 24-byte label key are decoder failures.
Why: the row is in the shared profile; §12.1 says `requests-bad/oversize-label-key` "is refused by the decoder before the `labels` field rule".

**C06 — §4.0 integer bound.**
Words: "major type 0 only; shortest form; ≤ 2⁶³−1".
Choice: the decoder refuses any unsigned integer argument above 2⁶³−1 (a profile failure, not a schema failure). Length arguments that large are refused earlier by the size caps.
Why: it is in the profile table; §4.0 lists "an integer above 2⁶³−1" among patches that "cannot canonicalise", i.e. a decoder-level rule.

**C07 — §4.0 nesting depth.**
Words: "**Nesting depth is at most 8**, counted in **containers**. The top-level map is depth 1 … **A scalar does not add depth**".
Choice: entering a container (array or map, empty or not) whose depth would be 9 is refused. Scalars at depth 8 inside a depth-8 container are fine. The embedded request is decoded by a separate call starting at depth 1.
Why: literal reading; an empty container is still a container.

**C08 — §4.0 size cap mechanics.**
Words: "**`MAX_ENTRY_BYTES` is 65535**, and an **entry** is at most that many bytes" and §12.1: "`entries-hostile/oversize-entry` (a header promising 65536 bytes, refused on length before anything is allocated)".
Choice: (1) the whole input longer than the artifact's cap is refused before parsing; (2) while parsing, a declared byte/text length greater than the cap is a size refusal, checked before comparing with the bytes remaining; (3) a declared length that merely exceeds the remaining input is a truncation (malformed) refusal. Caps: entry and request 65535, bundle 81919, trust 65536, evidence 65536.
Why: refusing on the declared length first is what "before anything is allocated" asks.

**C09 — §4.0 "valid UTF-8".**
Words: "definite length; valid UTF-8".
Choice: Go `unicode/utf8.Valid` semantics: no overlong forms, no surrogate code points (U+D800–DFFF), nothing above U+10FFFF. Noncharacters (U+FFFE etc.) are valid.
Why: that is the RFC 3629 definition of UTF-8.

**C10 — §4.0 the order of checks inside the decoder.**
Words: none explicit; §12.1: hostile inputs are each "refused for **its own** rule".
Choice: whole-input size first, then a single left-to-right parse in which the first violation met decides the reason (head well-formedness, banned major type/simple/indefinite, shortest form, integer bound, length caps and truncation, depth on container entry, map key type/length, key order, UTF-8), then trailing bytes.
Why: the spec gives no order inside the decoder; a streaming parse is the natural implementation and each hostile vector is meant to carry one fault.

**C11 — §4.0 `content_hash` bytes.**
Words: "`content_hash` | `SHA-256` of the signature preimage below" — "the 14-byte prefix `norn/entry/v1\n` … then the envelope encoded **without** the `sigs` key".
Choice: re-encode the decoded envelope minus `sigs` canonically. Because the decoder accepts only the canonical encoding, this equals the corresponding slice of the received bytes.
Why: equivalent under a strict decoder; re-encoding is the definition.

**C12 — §4.0 `sigs` ordering.**
Words: "`sigs` is an array of maps `{"kid","role","sig"}` sorted by `kid` bytewise, with no repeated `kid`."
Choice: compare the `kid` text strings bytewise; require strictly increasing (repeat or descent → `decode`).
Why: kid is 16 lowercase hex characters, so text order equals the order of the 8 bytes it names.

**C13 — §4.0 a `sigs` element missing a member.**
Words: "Each element of `sigs` is itself a **closed map** of exactly `{kid, role, sig}`".
Choice: all three members required; a missing one is `decode` like an extra one.
Why: "exactly".

**C14 — §4.0 field constraints at entry 0.**
Words: "violations → reason `decode` — **except at index 0**, where every failure is `bad-genesis`".
Choice: every failure of entry 0 (decode, envelope, net, hash, after/prev, body including `name` 1–64 bytes, closed body, key validity, params, signatures) is `bad-genesis` and aborts.
Why: explicit.

**C15 — §4.0 grant derivation details (D-077).**
Words: "the label split on commas, each part trimmed and parsed as an IPv4 or IPv6 prefix, masked to its prefix, duplicates removed, sorted as text"; "once U+0020 is removed from both of its ends and nothing else is"; "groups of one to four hexadecimal digits in either case, at most one `::`, a dotted quad allowed in place of the last 32 bits, and no zone"; "An IPv4-mapped IPv6 prefix is no grant either"; §12.1 "IPv4-mapped addresses before masking".
Choices: (a) split on every `,`; an empty part (after trimming spaces) makes the whole label no grant; (b) IPv6 groups may carry leading zeros up to four digits (only dotted-quad octets and lengths forbid a leading zero); (c) `::` must stand for at least one zero group: with `::` at most 7 explicit groups (a dotted quad counts 2), without it exactly 8; (d) the IPv4-mapped test (`::ffff:0:0/96`, i.e. 80 zero bits then `ffff`) is applied to the address as written, before masking; IPv4-compatible `::a.b.c.d` is allowed; (e) masking clears host bits; canonical text is the dotted quad, or RFC 5952 (lowercase, no leading zeros, the longest run of two or more zero groups compressed, the first on a tie, a single zero group not compressed, embedded dotted quads written as hex groups); (f) duplicates removed after canonicalisation; sorted bytewise as text; (g) an absent `ip` label is no grant (empty list).
Why: (b) and (c) follow RFC 4291 §2.2 as cited; (d) follows the §12.1 wording.

## §4.1–§4.5 Envelope, types, guards, params

**C16 — §4.1/§5.1 step 3: envelope member types.**
Words: "exactly the permitted keys, **every member of the type §4.1 gives it** (`t` text, `ts`, `after` and `prev` uint, `body` a map), `v` = 1, `net` = `anchor.net`, well-formed `sigs`".
Choice: `v` must be the uint 1; `net` must be a 16-byte byte string equal to `anchor.net`; `sigs` an array of well-formed elements; all failures `decode`.
Why: §4.1 types `net` as `<bytes16 net_id>`.

**C17 — §4.3 signature counting for roles a type does not use.**
Words: "a signature … is *valid* iff `kid` names a key this entry may be signed by **in that role**" and "For `device` it is the `device_pk` of the device this entry names … otherwise, the device's `device_pk` from the state."
Choice: a `device`-role signature on a governance entry, a `note` or a `genesis` resolves to no key and is ignored; on `enroll` a `device`-role envelope signature is checked against the request's `device_pk` but nothing in `enroll`'s rule consumes it.
Why: those types name no device.

**C18 — §4.3/§5.1 `revoke` authorisation.**
Words: "≥ `signer_thr` signers, **or** the device itself, **or** ≥ `root_thr` roots".
Choice: three independent tests, never pooled; "the device itself" means at least one valid `device`-role signature whose `kid` is `kid(current device_pk)` of the named device.
Why: §12.1 `bad-revoke-neither-quorum` describes exactly the pooled reading as wrong.

**C19 — §4.3 `rotate` device signatures.**
Words: "one valid signature for each *distinct* key among the two, so an incoming key that is the current key needs its one signature and no other".
Choice: the current-key check needs a `device`-role signature with `kid = kid(current device_pk)` that verifies; the incoming-key check needs a `device`-role signature with `kid = kid(new device_pk)` that verifies; when the two keys are equal the same signature satisfies both.
Why: kids are unique in `sigs`, so "distinct key" and "distinct kid" coincide.

**C20 — §4.3/§5.1 `signer_add`/`root_add` duplicate test.**
Words: "`kid(pk)` not already a root or signer (`dup-key`)".
Choice: compare by `kid`, across both roles.
Why: explicit; with SHA-256 the kid comparison and the key comparison agree on any real input.

**C21 — §4.4 `prev` on non-device objects before their first change.**
Words: "**present and equal** where the object exists, **absent** where it does not — which is only an `enroll` of a `device_id` that no accepted entry has ever named"; "the genesis sets every member of `versions` to 0".
Choice: every `signer_*`, `root_*`, `params`, `policy`, `log_key` entry must carry `prev` equal to the current version, which is 0 until the first accepted change — including `policy` before any policy entry.
Why: explicit "only an enroll".

**C22 — §4.4 device record existence for `enroll`.**
Words: "the record's `version`: the index of the last accepted entry naming that `device_id`".
Choice: once a device record exists it persists through revocation; an `enroll` of a revoked id needs `prev` = the record's version (the revoke's index); a never-named id needs `prev` absent.
Why: "no accepted entry has ever named the id".

**C23 — §4.5 params types.**
Words: table: `checkpoint_interval`, `staleness`, `mmd` uint s; `rotate_needs_signer` bool; `routes` text with closed value set.
Choice: uint params refuse booleans; `rotate_needs_signer` refuses anything but a boolean; `routes` must be text equal to `granted` or `advisory`. Same rules at genesis (`bad-genesis`) and in a `params` entry (`decode`).
Why: explicit.

## §5 Replay

**C24 — §5.1 entry 0 and the content key.**
Words: entry 0 step 1: "The duplicate key of §5.1 step 1 is recorded as seen." Step 1 for later entries: "An entry that replay **applies** adds its `content_hash` to the second when it is applied".
Choice: entry 0 records its `entry_hash` at step 1 and, once applied (step 8), its `content_hash` too. So a copy of the genesis at index > 0 with a different signature list is `dup-entry` (step 1), not `dup-genesis` (step 5).
Why: the genesis is an entry replay applies, and the content rule's purpose ("an applied entry is applied once") covers it. The entry-0 sentence is singular ("the duplicate key") and could be read as entry_hash only — flagged as a decision a vector may or may not pin.

**C25 — §5.1 step 1: content duplicates that fail the envelope.**
Words: "the hash is the one of an entry steps 2 and 3 accept — it decodes per §4.0 and its envelope passes §4.1, `net` included".
Choice: the content-key test applies only after steps 2 and 3 pass; a copy of an applied entry whose `sigs` are malformed (unsorted, bad kid) is `decode`, not `dup-entry`.
Why: explicit.

**C26 — §5.1 step 7 for `note`.**
Words: "For `note`: no valid `signer` or `root` signature → reject (`threshold`)."
Choice: one valid signature in either role (by a current signer, or a current root, in its declared role) suffices.
Why: explicit.

**C27 — §5.1 `enroll` request decoding.**
Words: "the request decodes under §16.1 and its `net` equals the entry's (`decode`)"; §3.1 item 2 (request `device_pk` valid point); §16.1 `expires` "MUST be > `ts`"; §4.0 cap and depth restart.
Choice: `request` must be a byte string; its decode is the full §16.1 check except the signature: profile (own call, depth from 1, 65535 cap), closed schema, member types, `device_id` grammar, labels caps and non-empty, `expires > ts`, `device_pk` a valid point, `net` equal to the entry's `net`. All `decode`; then the signature (`no-device-sig`).
Why: §12.1 `log-edges/10` "admits no identity point (`decode`, before `no-device-sig`)".

**C28 — §5.1 `log_key` witness comparison.**
Words: "`pk` is not the public key of any witness the policy in force names — `policy` when it is non-empty, else `anchor.policy`".
Choice: only `witness` directive keys are compared (not `log` lines); comparison on the 32 public-key bytes.
Why: "witness".

**C29 — §5.1 `policy` entry duplicate test.**
Words: "no witness the text names has the public key of an active log key — `anchor.log_key` or any `pk` in `log_keys`".
Choice: only `witness` lines are compared; a `log` line in a `policy` entry may name an active log key (that is what `policy-two-log-lines` does).
Why: §9.1's `log` lines row: "a `policy` entry (§5.1) has no such correspondence".

**C30 — §5.1 `policy` entry key points.**
Words: "`text` MUST parse as `c2sp.org/tlog-policy`, every verifier key it carries a valid point (§3.1) (`decode`)".
Choice: `log` line keys are point-checked too.
Why: "every verifier key"; §12.1 cites `log-order/15-policy-log-identity`.

**C31 — §5.1 precedence inside `note`.**
Words: note row: "body well-formed and closed (`decode`) · `text` ≤ 4096 bytes (`decode`) · `prev` absent (`decode`)".
Choice: an unsigned `note` with `prev` is `threshold` (step 7 first); a signed one is `decode`.
Why: step 7 precedes step 8.

**C32 — §5.1 `rotate` body.**
Words: "body well-formed and closed, its `device_pk` when present a valid point (§3.1) (`decode`)".
Choice: `device_id` matches §4.0's grammar, `wg_pk` is a 32-byte byte string (no X25519 validation), `device_pk` if present a 32-byte valid point, no other key.
Why: nothing asks for X25519 point checks; §3 says the WireGuard key never signs.

**C33 — §5.3 abort and empty states.**
Words: "The state is still serialised in full per §5.3 — every field present, at its zero value, with `net` from the anchor and `params` at the §4.5 defaults."
Choice: zero state = name `""`, size 0, thresholds 0, empty maps/arrays, policy `""`, versions all 0, params defaults; abort adds `rejected = [{index 0, bad-genesis}]`, the empty log has `rejected = []`.
Why: explicit.

**C34 — §5.3 evaluation time `T`.**
Words: "the newest instant such that the witnesses whose cosignature timestamp is at or after it satisfy the policy"; "A witness counts once … are its newest"; "Under `quorum none` there is no clock."
Choice: per witness named by the policy (its `witness` lines), keep the newest verifying timestamp; `T` = the largest such timestamp `t` for which the set `{w : ts_w ≥ t}` satisfies the policy; none → no clock; `quorum none` → no clock regardless of cosignatures.
Why: satisfaction is monotone in the set, so the newest instant is one of the timestamps.

**C35 — §5.3 which policy computes `T`.**
Words: "the trust policy for a first read, or the most recently replayed policy for a reader that already has one (§9.4). A `policy` entry in this checkpoint's replay range MUST NOT change this checkpoint's `T`".
Choice: `T` uses the policy the checkpoint was accepted under (trust policy for a fresh reader; for an informed reader the replayed state's `policy` when non-empty, else the trust policy).
Why: explicit.

**C36 — §5.3 expiry.**
Words: "A device is expired exactly when `expires != 0 && expires <= T`"; no clock → "expiry is not judged at all".
Choice: as written.

## §6 The log

**C37 — §6 which hash tiles are checked.**
Words: "The served `tile/<L>/…` hashes MUST also agree with the tree it rebuilt"; §10.1 step 12.
Choice: every tile `tlog-tiles` defines for the checkpoint's size, at every level that has at least one node: level `L` has `n_L = floor(size / 256^L)` nodes, served as `floor(n_L/256)` full tiles plus one partial of width `n_L mod 256` when non-zero. Each is fetched at its exact path (no full tile substituted for a partial); missing → `unserved`; content must equal the rebuilt hashes byte for byte, length included.
Why: the spec restates the paths and widths; it does not invite substitution.

**C38 — §6 entry bundles.**
Words: "A partial bundle holds **exactly** the number of entries its path declares."
Choice: full bundles must hold exactly 256 frames and nothing after; partial exactly `W`; any excess or truncation is `entries`; a missing bundle is `unserved`.

**C39 — §6 checkpoint size line.**
Words: "the tree size in decimal with **no leading zeroes** and at most 2⁶³−1".
Choice: `0` is canonical; `+`, `-`, spaces, or leading zero refused (`checkpoint`).

**C40 — §6 Merkle tree.**
Choice: RFC 6962 §2.1 MTH (split at the largest power of two below n), empty tree `SHA-256("")`; inclusion and consistency verification per RFC 9162 §2.1.3.2 / §2.1.4.2 (exact proof length required).

## §7 Notes and receipts

**C41 — §7 control characters in notes.**
Words: "MUST NOT contain an ASCII control character below U+0020 other than the line feeds that end lines".
Choice: bytes 0x00–0x1F other than LF refuse the note (`note`), anywhere; DEL (0x7F) is allowed in a note (it is not below U+0020). (The policy grammar forbids 0x7F separately.)
Why: literal.

**C42 — §7 signature line framing.**
Words: "`— ` (em dash U+2014, then one space), the key name, one space, then base64 … the line splits at its **first** space"; name "one or more characters, none of them `+` and none a Unicode white-space character — [list]".
Choice: line must begin with bytes E2 80 94 20; the name runs to the next 0x20; the payload is everything after it and must be canonical padded standard base64 decoding to ≥ 4 bytes. Name non-empty, no `+`, none of the listed code points.
Why: literal.

**C43 — §7 note structure.**
Words: "the **first** blank line ends the text … a note whose first line is blank has an empty first text line and is `note`"; "Every signature line, including the last, ends in one `0x0A`—exactly one"; "A note carries **at least one signature line**".
Choice: if the note starts with LF → `note`; text = bytes through the LF that precedes the first empty line; no empty line → `note`; the remainder must be non-empty, end in LF, and every line in it must frame (an empty line among them is a non-framing line → `note`).

**C44 — §7 key matching and length.**
Words: "**Framing is every line's; length is the matched key's.**" "What follows the key id is judged by the trusted key whose name and key id the line matches."
Choice: a line matches a trusted key when its name bytes equal the key's name and its first 4 payload bytes equal the key id. Log keys (0x01) require exactly 68 bytes, witness keys (0x04) exactly 76; any other length under a matched key is that key's failure.

**C45 — §7 cosignature timestamp bound and message.**
Words: "a listed witness's line whose timestamp is above it fails that witness's check, `cosignature`, before its signature is verified"; message "`cosignature/v1\n` ‖ `time ` ‖ <timestamp as decimal, no leading zeroes> ‖ `\n` ‖ <note text>".
Choice: as written; timestamp 0 renders `0`.

**C46 — §7 receipts: which keys, which text.**
Words: "the log keys the verifier trusts for the anchored origin (§9.4: the trust file's, plus every `log_key` of a state it has accepted)"; steps 1–8.
Choice: steps exactly in the given order; step 3 counts the signed-text lines (before the first blank line) and requires 4 and the header; deadline canonical decimal ≤ 2⁶³−1; `expired` when a non-zero checking time is ≥ deadline.

## §8 Bundles and freshness

**C47 — §8.1 bundle `device` field and binding.**
Words: "`device` | text | the `device_id` this bundle proves"; "confirm that **`device` is the `device_id` the `entry` names** — for an `enroll`, the id inside the embedded request; for the other device types, the `device_id` in the body".
Choice: `device` is any text (no grammar check at step 1). Binding decodes the entry under the §4.0 profile (strict), reads `t` and `body`; `enroll` → decode the embedded request (strict profile) and take its `device_id`; `rotate`/`revoke` → body `device_id`; any other type, or an entry/request that does not decode, or a missing/non-text id → `binding`. No signature or replay check in binding.
Why: §8.1 says the bundle steps never replay.

**C48 — §8.1 bundle schema.**
Choice: closed map of exactly the six keys, `v` uint 1, `device` text, `index` uint, `entry` bytes, `proof` array of 32-byte byte strings, `checkpoint` text; any fault → `bundle`; length > 81919 → `bundle` before decoding.

**C49 — §8.1 inclusion.**
Words: "the index is outside the tree, or the inclusion proof does not chain the entry's leaf hash to the signed root".
Choice: `index ≥ size` → `inclusion`; RFC 9162 verification with exact proof length.

**C50 — §8.1 freshness ladder.**
Choice: first matching row of unknown / hard_stale (`S_hard ≠ 0 && elapsed > S_hard`) / fresh (`elapsed ≤ S`) / degraded.

## §9 Trust file and policy grammar

**C51 — §9.1 verifier key parsing.**
Words: "Split it on `+` **at most twice**"; "key id is lowercase"; "A key name is one or more ASCII bytes from `0x21` to `0x7E`, `+` excluded"; "`alg ‖ pk` is 33 bytes, and 33 bytes encode to 44 base64 characters"; "a reader MUST **recompute**".
Choice: name/id/data split on the first two `+`; id exactly 8 lowercase hex characters; data canonical standard base64 (44 characters, re-encodes identically) of 33 bytes; recomputed id must match; algorithm byte must be the one the context requires; public key must be a §3.1 valid point.

**C52 — §9.1 / §3.1 point check inside every policy parse.**
Words: §9.1 grammar: "Every `<vkey>` MUST be parsed as a C2SP verifier key … 32-byte Ed25519 public key"; §3.1 item 2: "every verifier key a `policy` entry's text carries … a trust file's `log_key` and `witnesses`".
Choice: my policy parser checks every vkey's public key is a valid point in every context (trust file policy, `policy` entry, `policies/` texts, the informational policy inside fork evidence).
Why: one parser, one rule ("every key that enters a verifier's state is a valid point"). The alternative (point check only where §3.1 item 2 lists) differs only on a crafted evidence `policy` field or a grammar vector with a small-order key; flagged for the sweep.

**C53 — §9.1 policy line splitting and trailing whitespace.**
Words: "ASCII space (`0x20`) and tab (`0x09`) separate fields, in runs"; "a line that is empty, or holds only spaces and tabs, is **ignored**"; "spaces and tabs before the keyword are not part of it".
Choice: fields are the maximal non-empty runs of non-space/tab bytes; trailing whitespace adds no field.

**C54 — §9.1 bytes ≥ 0x80 in a policy.**
Words: "Bytes `0x80–0xFF` are content, not separators … Norn's CBOR text must still be valid UTF-8 (§4.0)."
Choice: the grammar parser does not itself validate UTF-8; the CBOR layer does wherever the policy arrives inside CBOR. A `.txt` policy vector is parsed as bytes.
Why: the sentence assigns UTF-8 validity to §4.0, not to the grammar.

**C55 — §9.1 unknown directive keyword.**
Choice: a non-comment, non-blank line whose first field is not exactly `log`, `witness`, `group` or `quorum` is an error.
Why: "the four directives … are **lowercase**. Nothing here is case-folded."

**C56 — §9.1 group threshold token.**
Choice: `all` → n, `any` → 1, otherwise canonical decimal (no leading zero, no sign) with `1 ≤ k ≤ n`; anything else an error. `n` counts the members on the line.

**C57 — §9.1 names.**
Choice: witness and group names: 1–64 bytes of 0x21–0x7E without `+`; one shared namespace; defined once; `none` cannot be defined (witness or group); `none` cannot be a member; `all`/`any` allowed as names.

**C58 — §9.1 trust-file correspondence.**
Words: "MUST name **exactly** the witnesses `witnesses` lists, with the same keys … compared as canonical text"; "A `log` line … **it MUST be `norn.trust.log_key`** … compared the same way, as verifier-key text."
Choice: the set of policy witness names equals the set of `witnesses[].name`; for each name the vkey text is byte-equal; every `log` line's vkey text equals `log_key`.

**C59 — §9.1 trust `anchor`.**
Choice: closed map of exactly `type` (text, any value), `max_lag` (uint), `mode` (text, must be `advisory`).

**C60 — §9.1 other trust members.**
Choice: `version` uint 1; `net` 16 bytes; `origin` text equal (bytes) to the derived origin; `name` text 1–64 bytes (any UTF-8); `genesis_hash` 32 bytes; `log_key` alg 0x01, name equal to `origin`, valid point; `log_urls` array (≥ 1) of non-empty text; `witnesses` array (≥ 1) of closed maps `{name, key, url?}` with `name` 1–64 bytes of the policy name grammar and unique, `key` an alg-0x04 vkey with a valid point, `url` text (may be empty); no witness public key equal to the log key's; size ≤ 65536.

**C61 — §9.4 learned log keys and informed readers.**
Words: "A learned key is the verifier key `<origin>+<id>+base64(0x01 ‖ pk)`"; "A node keeps the trust file's key **alongside**"; policy "replaces".
Choice: an informed reader trusts the trust key plus every `log_keys[].pk` of the replayed state (named the origin, id computed with alg 0x01), and verifies under the state's `policy` when non-empty, else the trust policy. Policy `log` lines never add trusted keys.

## §10–§11 Verifier, fork evidence

**C62 — §10.1 listed witnesses.**
Words: "a cosignature line whose name **and** key id match a listed witness does not verify".
Choice: "listed" = the `witness` directives of the policy in force (for a fresh reader the trust policy, whose witnesses equal the trust file's list).

**C63 — §10 fork comparison inputs.**
Choice: `at = min(cp.size, stored.size)`; served root at `at` recomputed from served entries; mine = stored root when `at == stored.size`, else computed from the node's own branch entries if the node holds them; when it does not, no comparison is possible and a shorter head is `rollback`; at `at = 0` both roots are the empty-tree hash.

**C64 — §10.1 step 11 `genesis`.**
Choice: size 0 with no stored checkpoint → `genesis`; otherwise replay entry 0 alone and an abort → `genesis`. Checked after step 10 and before tiles (step 12).

**C65 — §11.1 evidence `split` 0.**
Words: "A `split` that is 0 carries an all-zero `split_root` and two empty proofs."
Choice: version 2 with `split` 0 and a non-zero `split_root` or a non-empty split proof → `proof`.

**C66 — §11.1 evidence checkpoint verification.**
Choice: `held`/`conflicting` checked with §10.1 steps 2–7 under the reader's own trust (trust file's log key, trust policy); no entries fetched.

**C67 — §11.1 `version` before `schema`.**
Choice: `version` absent, non-uint or not 1/2 → `version`; then the exact key set for that version and member types (`held`, `conflicting`, `policy` text; `size`, `split` uint; `held_root`, `split_root` exactly 32 bytes; proofs arrays of exactly-32-byte strings) → `schema`.

## §14 Canonical JSON, §15, §16

**C68 — §12/§14 entry mirrors.**
Words: "`entries/NN-<type>.json` | mirror: `{entry, entry_hash, leaf_hash, preimage_sha256, size}` … The `entry` object mirrors the **CBOR**".
Choice: render the decoded CBOR as canonical JSON per §14 (maps as objects with bytewise-sorted keys, byte strings lowercase hex, text strings escaped per §14.2, uints decimal, booleans), and compare whole mirror files byte for byte.

**C69 — §15 age.**
Words: "The node's estimate of now is **the largest of the lower bounds** it holds"; "The **age** of a held checkpoint is this estimate minus that checkpoint's quorum time".
Choice: estimate = max over recorded pairs of `q + (now_mono − m)`; age = estimate − `q_held`.

**C70 — §16.1 standalone request check order and network.**
Words: "A consumer MUST validate structure **and** verify `sig` before showing a request … MUST also refuse a request whose `net` is not the network it serves".
Choice: text layer (bech32m) → CBOR profile → schema and field rules (incl. point check, `expires > ts`) → `net` equals the served network → signature, mirroring `enroll`'s order (net before signature).

**C71 — §16.2 bech32m.**
Choice: BIP-350 decode with constant 0x2bc830a3; all-lowercase or all-uppercase only; HRP must be `norn`; separator is the last `1`; checksum 6 characters; characters 33–126; no 90-character limit; padding < 5 bits and zero; decoded payload ≤ 65535 bytes.

**C72 — §14.2 escaping.**
Choice: escape exactly `"`, `\`, `\b`, `\t`, `\n`, `\f`, `\r` and other U+0000–U+001F as `\u00xx` lowercase; everything else verbatim.

**C73 — §6 anchor digest.**
Choice: SHA-256 of the checkpoint bytes through the LF that terminates the blank separator line (body + blank line, four LFs).
