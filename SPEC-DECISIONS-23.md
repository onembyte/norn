# Cold gate run 23 — decisions log

Written after reading SPEC.md in full and before opening `testdata/vectors/README.md`,
any manifest or any vector. Each item: section, the exact words, the reading chosen, why.
This file is not edited after the vectors are opened; later doubts go in the report.

## Encoding profile (§4.0, §4.1)

C01. §4.0 Integers: "major type 0 only; shortest form; ≤ 2⁶³−1."
  Chosen: the bare decoder refuses any major-type-0 value above 2⁶³−1 in every Norn CBOR
  artifact (entries, requests, trust files, bundles, evidence), as a profile fault, not a
  schema fault. Why: the row is in the profile table, which applies to all CBOR structures.

C02. §4.0 "Shortest form means every argument, not only integers ... the length header of a
  byte string, text string, array or map."
  Chosen: the decoder refuses any head whose argument is not in preferred (shortest) form, for
  all major types 0, 2, 3, 4, 5. Additional-info values 28–30 are not well-formed and refused.

C03. §4.0 "every map key is a text string of 1–23 bytes" / §4.1 "keys strictly increasing in
  §4.1's order".
  Chosen: decoder-level rule for every map in every artifact (including `labels` inside a
  request and every map in trust files, bundles, evidence). Non-text key, empty key or key
  longer than 23 bytes → profile refusal. Order = bytewise over the encoded key (header+bytes),
  i.e. shorter first then bytewise; equal key = refusal (no separate duplicate rule needed).

C04. §4.0 allow-list: "the two simple values false (20) and true (21) of major type 7, as the
  single bytes 0xf4 and 0xf5 — and nothing else".
  Chosen: 0xe0–0xf3, 0xf6, 0xf7, 0xf8 xx (any xx), 0xf9/0xfa/0xfb floats, 0xfc–0xfe, 0xff all
  refused by the decoder. Tags (major 6), negative integers (major 1) and any indefinite length
  refused by the decoder.

C05. §4.0 "Text strings | definite length; valid UTF-8".
  Chosen: strict UTF-8 (no surrogate code points, no overlong forms, nothing above U+10FFFF) —
  Go's utf8.Valid. Applied to every text string (keys and values) at the decoder.

C06. §4.0 "Nesting depth is at most 8, counted in containers ... A scalar does not add depth".
  Chosen: the decoder refuses a map/array that would sit at depth 9 or deeper; applied to every
  Norn CBOR artifact; an embedded request is decoded by a separate call with depth restarting
  at 1. Why: "A decoder MUST bound its own resource use. Two limits, both normative."

C07. §4.0 "MAX_ENTRY_BYTES is 65535 ... as is an enrollment request"; §8.1 "MAX_BUNDLE_BYTES is
  81919"; §9.1 "MAX_TRUST_BYTES is 65536"; §11.1 "MAX_EVIDENCE_BYTES is 65536".
  Chosen: each limit is checked on the raw input length before decoding (`len > limit` refuses;
  exactly the limit is accepted). For a request in text form, the limit applies to the decoded
  payload. A byte/text/array/map head declaring more than the remaining input is refused before
  any allocation (for an artifact, that is a decode/`cbor` fault, not an oversize one).

C08. §4.0 "A decoder MUST consume the whole input: bytes after the item are a violation of the
  profile". Chosen: trailing bytes → decoder refusal (`decode` for an entry).

C09. §4.0 "Booleans | valid CBOR items; schemas MUST reject them outside
  params.rotate_needs_signer". Chosen: true/false decode; every schema that expects uint, text,
  bytes, map or array refuses a boolean there (`decode`, `bundle`, `schema`, invalid trust).

## Envelope, signatures, replay order (§4.1–§5.2)

C10. §5.1 step 3 "exactly the permitted keys, every member of the type §4.1 gives it (t text,
  ts, after and prev uint, body a map), v = 1, net = anchor.net, well-formed sigs".
  Chosen: envelope keys exactly {v,t,net,ts,body,sigs} plus optional {after,prev}; v uint == 1;
  t text; net bytes of length 16 and equal to anchor.net; ts uint; after/prev uint if present;
  body map; sigs array. Any failure → `decode`.

C11. §4.0 "Well-formed sigs ... means precisely: that closedness, kid matching its field
  constraint, role within the enum, sig exactly 64 bytes, and the array sorted by kid with no
  repeats." Chosen: each element a map of exactly {kid, role, sig}; kid text matching
  ^[0-9a-f]{16}$ (exactly 16 bytes); role text in {root, signer, device}; sig bytes len 64;
  kids strictly increasing bytewise. Failure → `decode` (bad-genesis at entry 0).

C12. §4.0 "signature preimage | the 14-byte prefix norn/entry/v1\n ... then the envelope encoded
  without the sigs key"; content_hash = SHA-256 of that preimage.
  Chosen: re-encode the decoded envelope canonically without `sigs` (identical to the received
  bytes minus the sigs pair, because only canonical input is admitted).

C13. §5.1 step 1 "An entry whose entry_hash is in the first set, or that decodes and whose
  content_hash is in the second → reject (dup-entry) ... the hash is the one of an entry steps 2
  and 3 accept". Chosen order: (1) entry_hash already seen → dup-entry; else record it. (2)
  decode; (3) envelope; failures are `decode`. (1b) only for an entry passing 2 and 3: content
  hash already in the applied set → dup-entry. Then step 4 onwards. The content hash joins the
  applied set only when step 8 applies the entry. Entry 0's entry_hash joins the byte set, and
  its content hash the applied set when genesis applies.

C14. §5.1 step 7 "Count valid signatures per role ... For the governance types ... fewer than
  root_thr valid root signatures → threshold. For note: no valid signer or root signature".
  Chosen: a signature is valid for role R iff its declared role is R, its kid names a key that
  the state before this entry holds in role R (roots map / signers map), and Ed25519 under
  NORN-ED25519-v1 verifies over the preimage. Invalid elements are ignored. enroll, rotate and
  revoke have no step-7 check; their signature checks are inside step 8.

C15. §4.3 "a key counts only for the role it currently holds; a device key counts only for its
  own device_id". Chosen: a device-role signature is valid only if its kid equals
  kid(device_pk) of the key the rule names (current device_pk; for rotate also the incoming
  device_pk; for enroll the request's device_pk — not needed since enroll's consent is the
  request signature). A device key signing with role signer resolves to nothing.

C16. §5.1 enroll row order: body closed & request present (decode) · request decodes under
  §16.1 and its net equals the entry's (decode) · request signature (no-device-sig) · signer
  count ≥ signer_thr (threshold) · prev (stale-state) · dup-id · dup-wg.
  Chosen exactly that order. "Decodes under §16.1" includes the request size cap, profile,
  closed schema, v == 1, every field type, device_id grammar, labels rules, expires > ts when
  present, and device_pk a valid point (§3.1 item 2). The envelope's own device-role signatures
  are ignored for enroll.

C17. §4.4 "present and equal where the object exists, absent where it does not — which is only
  an enroll of a device_id that no accepted entry has ever named". Chosen: for enroll, if a
  device record exists (any status) prev must equal record.version, else prev must be absent;
  for every other state-changing type prev must be present and equal to the object's version;
  genesis versions are 0 so the first governance change needs prev 0.

C18. §5.1 rotate row: body (decode, incl. incoming device_pk a valid point) · unknown-device ·
  not-active · current-key device signature (no-device-sig) · signer threshold if
  rotate_needs_signer (threshold) · prev (stale-state) · new wg_pk not active for another device
  (dup-wg) · incoming-key signature when the body carries a device_pk that differs from the
  current one (no-device-sig). Chosen exactly. Body keys: device_id (text, §2 grammar), wg_pk
  (bytes 32), device_pk (bytes 32, optional). wg_pk is not point-checked (X25519, never signs).
  Effect: wg_pk replaced, device_pk replaced if present, version = index, since_index unchanged.

C19. §5.1 revoke row: body (decode) · unknown-device · not-active · authorised by signers,
  roots or the device (threshold) · prev (stale-state). Chosen: authorised iff valid signer
  count ≥ signer_thr, or valid root count ≥ root_thr, or one valid device-role signature by the
  device's current device_pk; counts are never pooled. reason optional text 0–256 bytes; it is
  not stored. Effect: status revoked, since_index = version = index, removed from active_wg.

C20. §5.1 signer_add/root_add: body (pk bytes 32, a valid point — §3.1 item 2 lists both) ·
  prev · kid(pk) not already a root or signer (dup-key). Chosen: dup-key compares kid(pk)
  against the kids of both maps; a key equal to a log or witness key is not refused here (no
  rule says so).

C21. §5.1 signer_remove/root_remove: body (kid ^[0-9a-f]{16}$) · prev · kid in that role
  (unknown-key) · root_remove only: len(roots)−1 ≥ root_thr (root-invariant). signer_remove has
  no invariant (D-028), so signer_thr may exceed len(signers) afterwards.

C22. §5.1 signer_thr/root_thr: body (thr uint, not bool) · prev · 1 ≤ thr ≤ len(set) (bad-thr).

C23. §5.1 log_key row: body · pk 32 bytes (and a valid point, §3.1 item 2 lists the log_key
  entry), overlap uint (decode) · prev · pk not a witness key of the policy in force — state
  policy when non-empty, else anchor.policy — compared as public-key bytes (dup-key) · pk not
  the anchor log key's pk nor any pk in log_keys (dup-key). Only `witness` lines of the policy
  in force count as witnesses. Effect: append {pk, overlap, since_index = index}.

C24. §5.1 policy row: body · text ≤ 4096 bytes (decode) · parses under §9.1's grammar with
  every key a valid point (decode) · prev · no `witness` line's pk equals an active log key pk
  (anchor or learned) (dup-key). `log` lines in a policy entry are unconstrained beyond the
  grammar (may name active or not-yet-published keys; more than one allowed). Effect: state
  policy = verbatim text.

C25. §5.1 params row: body is a non-empty map of §4.5 keys with §4.5 types (decode) · prev.
  Types: checkpoint_interval, staleness, mmd uint (zero allowed — §4.5 states no floor);
  rotate_needs_signer bool only (a uint 1 is refused); routes text, exactly "granted" or
  "advisory". Merge (overwrite per key). The same three rules at genesis give bad-genesis.

C26. §5.1 note row: body closed {text} · text ≤ 4096 bytes · prev absent (decode). Empty text
  is valid; absent text is decode.

C27. §5.1 step 6 "after present and > index → reject (after)". Chosen: after ≤ index passes;
  at index 0 after must be 0 (bad-genesis otherwise).

C28. §5.1 entry 0: every failure is bad-genesis; abort → rejected [{0,bad-genesis}], size 0,
  every state field at its zero value, net from the anchor, params at defaults, versions 0.
  Body checks: name text 1–64 bytes; roots/signers non-empty arrays of 32-byte valid points,
  distinct, disjoint, no shared kid within or across; root_thr/signer_thr uint (not bool) with
  1 ≤ thr ≤ len; params optional and, if present, non-empty with §4.5 keys and types; no other
  body key. Bootstrap counts root-role signatures whose kid resolves in the body's roots.

C29. §5.1 "Replay of an empty list of entries yields the zero state of §5.3 with size 0 and
  rejected empty". Chosen: as stated (not bad-genesis).

C30. §4.3 enroll "≥ signer_thr signers"; §4.3 revoke "≥ signer_thr signers, or the device
  itself, or ≥ root_thr roots". Chosen: roots never authorise an enroll; signers never
  authorise governance.

C31. §5.2 dup-wg for enroll "active for any device". Chosen as stated (unobservable vs "another
  device" because dup-id fires first).

C32. No uniqueness of device_pk across devices is checked anywhere (no rule states one).

## State and canonical JSON (§5.3, §14)

C33. §5.3 "Every field below is always present". Chosen: top-level keys name, net, size,
  root_thr, signer_thr, roots, signers, params (all five §4.5 keys), policy, log_keys, devices,
  active_wg, versions (signers, roots, params, policy, log_key), rejected. Device record keys
  device_pk, wg_pk, status, since_index, version, labels ({} when none), expires (0 when none).
  Byte strings lowercase hex; maps keyed by kid / device_id / hex wg_pk.

C34. §14.1 "object keys sorted ascending, bytewise over the UTF-8 encoding of the bare key
  string"; §14.2 escapes exactly " \ \b \t \n \f \r and other C0 as \u00xx lowercase; nothing
  else escaped; output followed by exactly one 0x0A. Chosen exactly; I write my own encoder.

C35. §5.3 "T is the quorum time ... the newest instant such that the witnesses whose
  cosignature timestamp is at or after it satisfy the policy". Chosen: per listed witness take
  its newest verifying cosignature timestamp; T = the largest candidate timestamp c such that
  the set {w : ts_w ≥ c} satisfies the policy (nested groups evaluated as one member each);
  none satisfies → no clock; `quorum none` → no clock.

C36. §5.3 "A device is expired exactly when expires != 0 && expires <= T"; no clock → expiry not
  judged. Proven set = active devices not expired, with replay's current wg_pk.

C37. §5.3 held head: "a reader that holds that tree head keeps the policy and the T it accepted
  it under ... The copy's own lines are still checked ... The copy's quorum is not judged
  again". Chosen: when a checkpoint's (origin, size, root) equals the stored head, cosignature
  lines are checked under the stored head's accepting policy, the quorum step is skipped, and
  the stored note, cosignatures, policy and T stand. This relaxation does not apply to a
  checkpoint inside a bundle or evidence.

## Grants (§4.0)

C38. §4.0 "the label split on commas, each part trimmed ... leading and trailing U+0020s are
  removed and nothing else is". Chosen: split on ',' only; strip only 0x20 at both ends; an
  empty part (e.g. "a,,b", a trailing comma, or an empty label value) makes the whole label no
  grant.

C39. §4.0 "a dotted quad — four decimal octets 0–255, none with a leading zero — or an IPv6
  address as RFC 4291 §2.2 writes it: groups of one to four hexadecimal digits in either case,
  at most one ::, a dotted quad allowed in place of the last 32 bits, and no zone".
  Chosen: "0" is an octet, "00"/"01" are not. IPv6: without :: exactly 8 groups (or 6 + dotted
  quad); with :: at most 7 groups' worth (dotted quad counts 2), because RFC 4291 says "::"
  indicates one or more groups of zeros; a group may carry leading zeros ("0001"); a lone
  leading or trailing ':' (not part of ::) is malformed; the embedded dotted quad uses the same
  octet rules.

C40. §4.0 "The length is decimal without a leading zero, at most 32 for a dotted quad and 128
  for IPv6". Chosen: digits only, "0" allowed, "00"/"08" refused, no sign.

C41. §4.0 "An IPv4-mapped IPv6 prefix is no grant either ... its address before masking lies in
  ::ffff:0:0/96". Chosen: such a part makes the WHOLE label no grant (consistent with "the parts
  that did parse count for nothing"). IPv4-compatible (::a.b.c.d) addresses are ordinary IPv6.

C42. §4.0 "masked to its prefix, duplicates removed, sorted as text ... RFC 5952 form with every
  group in lowercase hexadecimal (an embedded dotted quad is written as two groups)".
  Chosen: mask host bits to zero (no refusal for host bits set); IPv6 canonical text per RFC
  5952: no leading zeros in a group, the longest run of two or more zero groups compressed to
  ::, the first such run on a tie, a single zero group not compressed, never dotted output;
  dedupe and sort bytewise over the canonical strings (IPv4 and IPv6 mixed). Absent label → no
  grant, rendered as an empty list.

## Signed notes, checkpoints, receipts (§6, §7, §10)

C43. §7 "the first blank line ends the text, and every line after it belongs to the signature
  block. The text is at least one line". Chosen: split the note at the first "\n\n"; the text
  is everything through the first of those LFs; a note starting with LF, or with no blank line,
  or with no signature line after it, or with any empty line in the signature block, or not
  ending in exactly one LF, is `note`.

C44. §7 "The signed text and every signature line MUST be valid UTF-8, and MUST NOT contain an
  ASCII control character below U+0020 other than the line feeds". Chosen: whole-note check
  before anything else; DEL (0x7F) and C1 controls are permitted by this rule.

C45. §7 signature line: "— " then the key name up to the first space, then the payload;
  name "one or more characters, none of them + and none a Unicode white-space character —
  [explicit list]". Chosen: exactly that list (U+0009–U+000D, U+0020, U+0085, U+00A0, U+1680,
  U+2000–U+200A, U+2028, U+2029, U+202F, U+205F, U+3000); a line without a space after the
  name, or not starting with the em-dash prefix, does not frame → `note`.

C46. §7 "standard base64 with padding ... canonical RFC 4648 §3.5 ... decodes to at least the
  4-byte key_id". Chosen: payload must be padded std base64 whose decode→re-encode reproduces
  the text exactly and which decodes to ≥ 4 bytes, else `note`. Length beyond that is judged
  only by a matched key.

C47. §7 "key_id = SHA-256(name ‖ 0x0A ‖ alg ‖ pk)[0:4]"; §9.4 a learned key is
  "<origin>+<id>+base64(0x01 ‖ pk)". Chosen: a line matches a trusted key iff its name bytes
  equal the key's name bytes and its first 4 payload bytes equal the key's id (no case folding).
  Trusted log keys: the trust file's log_key plus, for an informed reader, one per state
  log_keys row, named the origin with alg 0x01.

C48. §10.1 step 3 "no line whose name and key id match a trusted log key verifies, or any line
  that matches does not". Chosen: every matching line must be 68 bytes and verify over the text
  under NORN-ED25519-v1, and at least one must match; otherwise `log-signature`.

C49. §6 / §10.1 step 4: exactly three text lines; size canonical decimal ("0" allowed, no
  leading zeros, digits only, ≤ 2⁶³−1); root canonical padded std base64 of exactly 32 bytes.
  Else `checkpoint`. Then step 5: origin line byte-equal to the trust origin, else `origin`.

C50. §10.1 step 6: every line whose name and key id match a witness listed by the applicable
  policy (its `witness` lines' verifier keys) must carry a 76-byte payload, a timestamp ≤ 2⁶³−1
  (checked before the signature) and a valid signature over "cosignature/v1\ntime <decimal>\n"
  ‖ text; else `cosignature` — under `quorum none` too. Lines matching no listed witness are
  ignored, including a witness the trust file lists but the replayed policy dropped.

C51. §10.1 step 7: the set of listed witnesses with at least one verifying line must satisfy the
  quorum expression (witness: present; group: ≥ k satisfied members; none: always). Else
  `quorum`.

C52. §7 receipts, steps in order note · log-signature · receipt (exactly 4 text lines, first
  "norn/receipt/v1") · origin (byte equality) · leaf-hash (canonical padded std base64, exactly
  32 bytes) · deadline (canonical decimal, ≤ 2⁶³−1, "0" allowed) · entry (when a submitted leaf
  is supplied, bytes equal) · expired (now ≠ 0 and now ≥ deadline). Trusted keys as C47.

C53. §6 anchors: digest = SHA-256 of the checkpoint note's bytes from the start through the LF
  ending the blank separator line (body + blank line).

## Served logs (§6, §10)

C54. §6 paths: index N in three-digit groups, non-final groups prefixed x; hash tile
  tile/<L>/<N>[.p/<W>], entry bundle tile/entries/<N>[.p/<W>].

C55. §6 "A partial bundle holds exactly the number of entries its path declares"; fall back to
  the full path only when the partial is not served; a full stand-in must be exactly 256 frames
  / 8192 bytes, of which the first W are used. A present partial is used even if a full one
  also exists (no fallback from a malformed partial).

C56. §10 order: checkpoint fetch (unserved) · note · log-signature · checkpoint · origin ·
  cosignature · quorum · entries (unserved for a missing bundle; entries for bad framing or
  count) · head · fork/rollback if a head is stored · genesis · tiles (unserved for a missing
  tile; tiles for any byte or length difference) · accept.

C57. §10 / §6 tiles to check: for every level L with floor(size/256^L) ≥ 1, every tile
  (full and partial) at that level, each hash being the RFC 6962 hash of the complete subtree of
  256^L leaves at that position.

C58. §10 fork block: at = min(cp.size, stored.size); served root at `at` recomputed from served
  entries; mine = stored root when at == stored.size, the node's own branch root at `at` when it
  holds its entries, the empty-tree hash when at == 0; when mine is unknown no comparison is
  made. served ≠ mine → `fork`; else cp.size < stored.size → `rollback`.

C59. §10.1 step 11 "replaying it alone aborts with bad-genesis". Chosen: genesis check = entry 0
  exists and replaying it alone under the anchor does not abort.

## Bundles (§8.1, §10.1)

C60. §10.1 bundle step 1: oversize (> 81919), any profile fault, not a map, not exactly the six
  keys, v not uint 1, device not text in the §2 grammar, index not uint, entry not bytes or
  longer than 65535, proof not an array of exactly-32-byte strings, checkpoint not text →
  `bundle`.

C61. §8.1 checkpoint check is §10 steps 2–7 under the reader's current keys and policy (no held
  relaxation); then `inclusion` (index < size and RFC 9162 §2.1.3.2 with exact consumption);
  then `binding`.

C62. §8.1 binding: the entry must decode under the profile and pass the structural envelope
  (closed key set, v == 1, t text, net 16 bytes (not compared with the anchor), ts uint, body
  map, after/prev uint when present, well-formed sigs). Device named: enroll → body["request"]
  as bytes decoded under §16.1 structure and field rules including point admission and
  expires > ts, but not its signature or network; extra body keys allowed. rotate/revoke →
  body["device_id"] when it is text. Any other t → no device. Label must equal the named id
  byte for byte.

C63. §8.1 condition 3: the installed key is the wg_pk replay to the node's stored checkpoint
  gives for an active device; nothing for a revoked or unknown one.

## Trust files (§9)

C64. §9.1: closed map {version, net, origin, name, genesis_hash, log_key, log_urls, witnesses,
  policy, anchor?}; version uint 1; net bytes 16; origin text exactly derived; name text 1–64
  bytes (any UTF-8); genesis_hash bytes 32; log_key a vkey with alg 0x01, correct recomputed id,
  name == origin, valid point; log_urls array of ≥ 1 non-empty texts; witnesses array of ≥ 1
  closed maps {name, key, url?} with name in the policy-name grammar (1–64 bytes), unique; key a
  vkey with alg 0x04, correct id, valid point; url text when present; no witness pk equal to the
  log_key pk; anchor (optional) closed map with all of type (text, any value), max_lag (uint),
  mode (text, exactly "advisory"). Policy: parses; its witness lines' short names equal the
  witnesses names as a set, each with byte-identical vkey text; every log line's vkey text
  equals log_key's text. Size > 65536 refused first.

C65. §9.1 verifier key: "Split it on + at most twice"; name ASCII 0x21–0x7E without '+', no
  length limit; id 8 lowercase hex; data canonical base64 of exactly 33 bytes (alg ‖ pk); id
  recomputed must equal. In any policy the pk must also be a valid point (§3.1 item 2: "a policy
  parses one way everywhere").

C66. §9.3 fingerprint: first 10 bytes of SHA-256(trust CBOR), Crockford base32 MSB first, 16
  chars as 4 groups of 4 joined by '-', file = that string + LF.

## Policy grammar (§9.1)

C67. §9.1 grammar rules chosen exactly as tabled: LF-terminated lines (missing final LF is an
  error; empty text has no quorum line and is refused); only TAB and LF among controls (0x00–0x08,
  0x0B–0x1F, 0x7F errors anywhere); fields split on runs of space/tab; blank and comment lines
  ignored; '#' elsewhere ordinary; keywords lowercase; field counts exact (log 1–2, witness 2–3,
  group ≥ 3, quorum 1); names ASCII 0x21–0x7E without '+', ≤ 64 bytes, one namespace, defined
  once, `none` predefined and not definable or a member; members previously defined and
  distinct; threshold all/any/canonical decimal 1 ≤ k ≤ n; exactly one quorum naming a
  previously-defined witness or group or `none`; any directive order, names resolved in order;
  every vkey's pk appears once across log and witness lines; log vkeys alg 0x01, witness alg
  0x04; URL tokens opaque.

## Fork evidence (§11.1)

C68. §11.1 steps: oversize (> 65536) · cbor (profile fault or not a map) · version (absent, not
  uint, or not 1/2) · schema (exact key set per version; held/conflicting/policy text; size and
  split uint; held_root and split_root bytes 32; every proof array element bytes 32) · policy
  (grammar + point admission only) · held · conflicting (§10 steps 2–7 under the reader's own
  keys and policy) · size (size > held.size, or conflicting.size ≠ size) · proof · consistent.

C69. §11.1 proof step: size 0 → proof; size == held.size → proof must be empty and held_root ==
  held root; else RFC 9162 §2.1.4.2 consistency (size, held_root) → (held.size, held.root) with
  exact consumption. Version 2: split > size → proof; split 0 → split_root all zero and both
  split proofs empty; else for each head, split == head.size → empty proof and split_root ==
  head root, otherwise consistency proof (split, split_root) → head. Then held_root ==
  conflicting.root → consistent; else the fork is proved.

## Requests (§16)

C70. §16.2: bech32m per BIP-350; HRP "norn"; separator = last '1'; all-lowercase or
  all-uppercase accepted, mixed refused; checksum constant 0x2bc830a3 only; no 90-char limit;
  5→8 regrouping with padding < 5 bits and zero; decoded payload ≤ 65535. §16.1 closed schema
  {v, ts, net, sig, wg_pk, labels?, expires?, device_id, device_pk}; v uint 1; ts uint required;
  net bytes 16; sig bytes 64; wg_pk bytes 32; labels per §4.0 (≥ 1 pair, ≤ 32, keys 1–23 bytes,
  values text ≤ 256 bytes); expires uint > ts when present (so expires 0 is refused);
  device_id §2 grammar; device_pk bytes 32 and a valid point; signature over
  "norn/enroll-request/v1\n" ‖ CBOR(request without sig). A consumer also refuses another net.

## Ed25519 (§3.1)

C71. §3.1 NORN-ED25519-v1: valid point = canonical encoding (y < p, x = 0 ⇒ sign 0), on curve,
  [L]P = O and P ≠ O; S < L; cofactorless [S]B = R + [k]A with k = SHA-512(R‖A‖M) mod L. I
  implement edwards25519 field and group arithmetic myself (standard library only) and use
  crypto/ed25519 only to sign constructed inputs; the predicate is checked against the CCTV set.

## Freshness (§8.1, §15)

C72. §8.1 ladder: unknown (no quorum time) · hard_stale (S_hard > 0 and elapsed > S_hard) ·
  fresh (elapsed ≤ S) · degraded. §15: the estimate of now is the largest of the lower bounds
  q_i + (m_now − m_i); age = estimate − q_held, never negative; S from the state replayed through
  the held checkpoint.

## Things I treat as outside the static suite

C73. §13 reconciliation (grant bound, overlaps, modes), §15 gossip and CLOCK_SKEW, §16.3 key
  handling: not implemented beyond what the vectors need; noted in the report.
