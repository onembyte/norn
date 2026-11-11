# Cold gate run 21 — reading decisions

Written after reading `SPEC.md` in full and before opening
`testdata/vectors/README.md`, any manifest or any vector. Not edited afterwards;
later doubts go in the report.

Each entry: section · the exact words · what I chose · why.

## Cryptography (§3.1)

**C01** §3.1 item 1 — "32 bytes that are the canonical encoding (RFC 8032 §5.1.3) of a point of order exactly `L`". Choice: decode strictly (y < p; reject x = 0 with sign bit 1; on-curve via square root), then compute [L]P with my own edwards25519 arithmetic and require [L]P = O and P ≠ O. All three clauses are checked even though the canonical ones are said to be implied. Why: the spec says both the order clause and the canonical clauses; checking all costs nothing.

**C02** §3.1 item 3 — "`S`, read as a little-endian integer, MUST be less than `L` … `[S]B = R + [k]A` … the cofactorless one … is the definition." Choice: A and R must both pass C01; S < L; then the cofactorless equation. I use Go's `crypto/ed25519.Verify` for the equation (it rejects S ≥ L, recomputes `[S]B − [k]A`, encodes it canonically and compares with R's bytes; with R canonical this is exactly the cofactorless equation), plus my own point checks on A and R. Why: standard library only; stdlib Verify alone accepts small-order A/R.

**C03** §3.1 item 2 — "A key that is not is refused as `decode` at its entry type's body step". Choice: point admission is part of each body's field validation (the `decode` check of step 8, or of step 6 at genesis → `bad-genesis`), so for governance types it runs after the step-7 root quorum. For `rotate` the incoming `device_pk` is checked in the body step, before `unknown-device`.

## CBOR profile (§4.0)

**C04** §4.0 — "The profile is an allow-list … unsigned integer … byte string … text string … array … map … `false` … `true` … and nothing else." Choice: one decoder for every Norn CBOR artifact (entries, requests, trust files, bundles, evidence, bare hostile inputs) that refuses major type 1, 6, any major-7 item but 0xf4/0xf5 (so 0xf6, 0xf7, 0xf8 xx, floats, 0xe0–0xf3, 0xff), additional info 28–31 (reserved and indefinite), non-shortest heads for integers and for every length header, integers > 2⁶³−1, invalid UTF-8 (Go `utf8.Valid`, which rejects surrogates and overlongs), map keys that are not text or not 1–23 bytes, map keys not strictly increasing by encoded form, and trailing bytes.

**C05** §4.0 — "Nesting depth is at most 8, counted in containers. The top-level map is depth 1". Choice: a container whose depth would be 9 is refused; scalars add nothing. The same limit applies to every Norn CBOR artifact, and a nested request restarts at 1 (decoded by a separate call).

**C06** §4.0 — "`MAX_ENTRY_BYTES` is 65535 … as is an enrollment request". Choice: length checked on the raw input before decoding: entry and request ≤ 65535; bundle ≤ 81919; trust ≤ 65536; evidence ≤ 65536. In replay an over-long entry is `decode`. A declared length that runs past the end of the input is a decode error raised before any allocation.

**C07** §4.0 / §4.1 — "keys **strictly increasing** in §4.1's order". Choice: compare the encoded key items bytewise (equivalently: shorter first, then bytewise); equal keys fail the same comparison.

**C08** §4.0 — "Booleans | valid CBOR items; schemas MUST reject them outside `params.rotate_needs_signer`". Choice: the decoder yields bool values; every schema field typed uint/text/bytes refuses a bool as a type error (`decode` / `bad-genesis` / `bundle` / `schema` / trust invalid).

## Entries (§4.1–§4.5, §5)

**C09** §4.0 — "`v`, `t`, `net`, `ts`, `body` and `sigs` are all **mandatory**; `after` and `prev` are the only optional keys". Choice: the envelope must have exactly these keys with types v uint = 1, t text, net bytes(16) equal to anchor.net, ts uint, after uint, prev uint, body map, sigs array. Any failure is step 3 `decode`.

**C10** §4.0 — "'Well-formed `sigs`' … closedness, `kid` matching its field constraint, `role` within the enum, `sig` exactly 64 bytes, and the array sorted by `kid` with no repeats." Choice: each element a map of exactly {kid, role, sig}; kid text `^[0-9a-f]{16}$`; role ∈ {root, signer, device}; sig bytes(64); kids strictly increasing as byte strings. Part of step 3.

**C11** §5.1 step 1 — "An entry that replay **applies** adds its `content_hash` to the second … the hash is the one of an entry steps 2 and 3 accept". Choice: order inside step 1: (a) entry_hash in byte set → `dup-entry`; add entry_hash; (b) decode (step 2) and envelope-check (step 3) — on failure `decode`; (c) content_hash in applied set → `dup-entry`. So the content check is only reached by entries that pass steps 2 and 3, and it precedes step 4. An accepted `note` counts as applied (it is accepted; "applies" is read as "accepted").

**C12** §4.0 — "`content_hash` | `SHA-256` of the signature preimage". Choice: SHA-256("norn/entry/v1\n" ‖ canonical CBOR of the envelope minus `sigs`). Since the decoder admits only canonical CBOR, re-encoding the decoded map without `sigs` reproduces the signed bytes.

**C13** §5.1 entry 0 — "Its `entry_hash` joins §5.1 step 1's first seen set, and when step 8 applies it, its `content_hash` joins the second". Choice: as written; an aborted genesis still leaves nothing to compare since replay stops.

**C14** §5.1 entry 0 step 6 — "`params`, if present, is **non-empty**, has only §4.5 keys, and each value has the §4.5 type". Choice: also apply the `routes` closed value set at entry 0 (§4.5 says "a genesis that gives it any text but `granted` or `advisory` … is refused (`decode`, or `bad-genesis` at entry 0)"). Genesis body is closed: {name, roots, root_thr, signers, signer_thr, params?}. `name` UTF-8 1–64 bytes; every root and signer a valid point; no duplicate keys, disjoint sets, no kid collision within or across; thresholds within 1..len.

**C15** §5.1 entry 0 step 7 — "genesis signatures are counted against the `roots` and `root_thr` *in its own body*". Choice: count sigs whose role is `root`, whose kid is kid(pk) of a key in body.roots, and which verify over the preimage. Signer keys never count.

**C16** §5.1 step 3 — "a numeric `t` is `decode`, not `unknown-type`". Choice: type check of `t` in step 3; membership in §4.3 in step 4.

**C17** §5.1 step 7 / §5.2 — "a signature `{kid, role, sig}` is *valid* iff `kid` names a key this entry may be signed by **in that role**". Choice: per role, resolve kid against the pre-entry state's map (roots / signers); device role resolves only to the device key(s) the entry names (enroll: request's device_pk; rotate: current and incoming device_pk; revoke: current device_pk); a kid resolving to nothing, or a failing signature, is ignored. A key counts once (kids are unique anyway).

**C18** §4.3 `note` — "any 1 signer or root". Choice: step 7 refuses a `note` with zero valid signer and zero valid root signatures; device signatures never count for a note.

**C19** §5.1 table, `enroll` — "body closed and `request` present · the request decodes under §16.1 and its `net` equals the entry's (`decode`) · … signature … (`no-device-sig`) · valid `signer` count ≥ `signer_thr` (`threshold`) · `prev` … · `dup-id` · `dup-wg`". Choice: exactly that order; body must be exactly {request} with request a byte string; request decode includes §16.1 field rules and point admission of device_pk; envelope device-role signatures on an enroll count for nothing.

**C20** §5.1 `rotate` — "body well-formed and closed, its `device_pk` when present a valid point (`decode`) · `device_id` known · currently `active` · valid `device` signature by the device's **current** `device_pk` · if `params.rotate_needs_signer`, signer count · `prev` · new `wg_pk` not active for another device · if the body carries `device_pk`, a valid `device` signature by that key as well". Choice: as written; body {device_id, wg_pk, device_pk?}, device_id grammar, wg_pk bytes(32), device_pk bytes(32) + valid point. "Known" = a device record exists (active or revoked).

**C21** §5.1 `revoke` — "authorised by signers, roots **or** the device itself (`threshold`)". Choice: valid signers ≥ signer_thr, or valid roots ≥ root_thr, or one valid device-role signature by the record's current device_pk. Counts never pool. Body {device_id, reason?}; reason UTF-8 0–256 bytes.

**C22** §5.1 `signer_add`, `root_add` — "`kid(pk)` not already a root or signer (`dup-key`)". Choice: compare kids, as written, across both roles. pk bytes(32) and a valid point (decode).

**C23** §5.1 `root_remove` — "removing it leaves ≥ `root_thr` roots and ≥ 1 root (`root-invariant`)". Choice: after `unknown-key`; signer_remove has no invariant.

**C24** §5.1 `signer_thr`, `root_thr` — "`1 ≤ thr ≤ len(set)` (`bad-thr`)". Choice: set = the role's current key set; thr bool → decode.

**C25** §5.1 `log_key` — "`pk` is not the public key of any witness the policy in force names — `policy` when it is non-empty, else `anchor.policy`". Choice: only `witness` directives count (a `log` line names no witness); compare raw 32-byte public keys; then compare against the anchor log key's pk and every `log_keys[].pk`. pk must be a valid point (decode, in the body step before prev).

**C26** §5.1 `policy` — "`text` MUST parse as `c2sp.org/tlog-policy`, every verifier key it carries a valid point". Choice: every key on both `log` and `witness` lines must be a valid point (decode); text ≤ 4096 bytes; then prev; then dup-key: any `witness` line whose pk equals the anchor log key pk or a learned log key pk. `log` lines in a policy entry are not compared with log keys.

**C27** §5.1 `params` — "non-empty, only §4.5 keys, each of the right type". Choice: uint for checkpoint_interval, staleness, mmd (zero allowed); bool for rotate_needs_signer; text ∈ {granted, advisory} for routes; merge into state.

**C28** §4.4 — "`prev` … **present and equal** where the object exists, **absent** where it does not — which is only an `enroll` of a `device_id` that no accepted entry has ever named". Choice: governance objects always exist (version 0 after genesis), so a governance entry without `prev` is `stale-state`. A device record exists from its first accepted enroll and is never deleted.

**C29** §4.4 — "`note` changes nothing and carries no `prev`; a `note` with one is `decode`". Choice: checked in step 8 after the text cap, per the table order.

**C30** §5.3 — device `since_index` "index of the entry that last changed `status`"; `version` "index of the last accepted entry naming this `device_id`". Choice: enroll sets both; rotate sets version only; revoke sets both. Re-enroll replaces the record wholesale (labels `{}` and expires 0 when absent).

## Canonical state and JSON (§5.3, §14)

**C31** §5.3 — "every field present". Choice: name, net (hex), size, root_thr, signer_thr, roots {kid: hex}, signers {kid: hex}, params (all five keys), policy, log_keys [{overlap, pk, since_index}], devices {id: {device_pk, wg_pk, status, since_index, version, labels, expires}}, active_wg {hex(wg_pk): id}, versions {signers, roots, params, policy, log_key}, rejected [{index, reason}]. Abort: zero state with params at defaults and rejected [{0, bad-genesis}]. Empty log: zero state, rejected [].

**C32** §14 — "sorted **ascending, bytewise over the UTF-8 encoding of the bare key string**", escaping table, one final 0x0A. Choice: implement exactly; no escaping beyond the table (U+007F, U+0085, U+2028 verbatim).

## Grants (§4.0)

**C33** §4.0 — "the label split on commas, each part trimmed and parsed … masked … duplicates removed, sorted as text … a label that is absent or does not parse **as a whole** is **no grant**". Choice: trim only U+0020 at both ends; an empty part is a failure; dotted quad octets 0–255 with no leading zero; IPv6 per RFC 4291 text with 1–4 hex digits per group, at most one `::` which must stand for ≥1 group, optional trailing dotted quad (counts 2 groups), no zone; length decimal without leading zero (so `0` allowed), ≤32/≤128. IPv4-mapped (unmasked address within ::ffff:0:0/96) makes the whole label no grant. Output: masked address in canonical text (IPv4 dotted; IPv6 RFC 5952: lowercase, no leading zeros, the longest run of ≥2 zero groups compressed, first on tie, never an embedded dotted quad), `/len`; dedupe; sort bytewise. "No grant" is represented as no list (distinct from an empty list only if a vector distinguishes them).

## Signed notes (§7)

**C34** §7 — "**the first blank line ends the text**". Choice: split the note at the first "\n\n"; text = bytes through the first LF of that pair; the rest are signature lines. A note beginning with LF → `note`. A signature block with zero lines → `note`. Every signature line ends in exactly one LF; an empty line inside or after the block → `note`.

**C35** §7 — UTF-8 and "MUST NOT contain an ASCII control character below U+0020 other than the line feeds". Choice: checked over the whole note (text and every signature line) before parsing lines; DEL 0x7F is allowed.

**C36** §7 — "A signature line is `— ` … the key name, one space, then base64 … split at its **first** space". Choice: prefix E2 80 94 20; name = bytes up to the first 0x20; name non-empty, valid UTF-8, no `+`, no character of the listed white-space set; payload = rest, canonical padded std base64 (re-encode must equal the text), decoded length ≥ 4.

**C37** §7 — "Framing is every line's; length is the matched key's." Choice: a line selects a trusted key when name equal and key id (first 4 bytes) equal; then length must be 68 (alg 0x01) or 76 (alg 0x04) or the selected key's check fails. Unmatched lines are ignored at any length.

**C38** §7 cosignature — "timestamp is an unsigned 64-bit **big-endian** … at most 2⁶³−1 … signature … over `cosignature/v1\n` ‖ `time ` ‖ decimal ‖ `\n` ‖ note text". Choice: as written; timestamp > 2⁶³−1 fails the line before the Ed25519 call.

**C39** §7 — "A verifier key string is `<name>+<key_id as 8 lowercase hex digits>+<base64(alg ‖ pk)>`. Split it on `+` at most twice". Choice: name 1+ bytes in 0x21–0x7E without `+`; id exactly 8 lowercase hex and equal to the recomputed SHA-256(name ‖ 0x0A ‖ alg ‖ pk)[0:4]; data exactly 44 base64 chars decoding to 33 bytes, canonical (re-encode equals text); alg byte returned to the caller, which decides which alg is permitted; pk must be a valid point wherever a key is admitted (trust file, policies).

## Checkpoints and the verifier loop (§6, §10)

**C40** §6 — size "in decimal with **no leading zeroes** and at most 2⁶³−1"; root "standard base64 with padding, 32 bytes … canonical". Choice: exactly three text lines; `0` is a valid size; the origin line is compared at step 5 only.

**C41** §10.1 step 3 — "no line whose name and key id match a trusted log key … verifies, or any line that matches does not". Choice: trusted log keys = the trust file's `log_key` plus, for an informed reader, every learned `log_keys[].pk` as verifier key named the origin with alg 0x01. Every matching line must be 68 bytes and verify; at least one must match.

**C42** §10.1 step 6 — "a cosignature line whose name **and** key id match a listed witness does not verify". Choice: listed = `witness` directives of the policy in force (trust policy, or the replayed state's policy when non-empty); a line matches by the witness verifier key's own name (e.g. `norn-witness/pi`) and id. Every matching line must verify; step 7 counts witnesses (by directive name) having ≥ 1 verifying line.

**C43** §9.1 quorum evaluation — "a `group` may name a `group`. It counts as **one** member". Choice: recursive evaluation; `none` is always satisfied.

**C44** §5.3 `T` — "the newest instant such that the witnesses whose cosignature timestamp is at or after it satisfy the policy". Choice: each listed witness contributes its newest verifying timestamp; try candidate instants from newest to oldest; the first that satisfies the policy is T; `quorum none` → no clock; nothing satisfies → no clock.

**C45** §5.3 / §10 — the held head: "every line is checked as above, under the policy that accepted it, but the quorum is not judged again, and the stored note, cosignatures and `T` stand". Choice: when the parsed tree head (origin, size, root) equals the stored head, steps 2–6 run under the held policy, step 7 is skipped and T stays the stored one.

**C46** §10 outline / §10.1 order — "1 unserved, 2 note, 3 log-signature, 4 checkpoint, 5 origin, 6 cosignature, 7 quorum, 8 entries, 9 head, 10 fork/rollback, 11 genesis, 12 tiles". Choice: implement in that order; a missing entry bundle is `unserved` at step 8; a missing hash tile `unserved` at step 12.

**C47** §10 — "mine := stored_cp.root if at == stored_cp.size; the root THIS NODE's branch had at `at`, otherwise". Choice: the reader holds its own entries when it verified the stored head; without them and at < stored size, no fork can be decided and a shorter head is `rollback`; a longer head can still be compared because at = stored size.

**C48** §10.1 — "An empty log served to a node that holds a head is `rollback`; served to one that does not, `genesis`". Choice: as written; the empty tree root is SHA-256("").

**C49** §6 — "a verifier that cannot fetch `tile/<L>/<N>.p/<W>` MUST fetch `tile/<L>/<N>` before it answers `unserved` … the file it fetches must itself be a well-formed full tile or bundle". Choice: fall back only when the partial path is absent; a present but malformed partial is judged as is; a stand-in full tile must be exactly 8192 bytes (else `tiles`), a stand-in full bundle exactly 256 frames (else `entries`).

**C50** §10 — "require every served hash tile == the rebuilt tree's". Choice: every tile at every level L with N >> 8L ≥ 1 is fetched and compared byte for byte with the rebuilt level-8L node hashes.

**C51** §6 — paths "three-digit groups, most significant first, joined by `/` … every group but the last prefixed `x`". Choice: as written.

**C52** §10.1 step 11 — "its entry 0 is not the genesis the anchor pins: replaying it alone aborts with `bad-genesis`". Choice: genesis check = replay([entry0]) does not abort; size 0 → `genesis`.

## Receipts (§7)

**C53** §7 receipt steps 1–8. Choice: as written; step 3 needs exactly four text lines with line 1 `norn/receipt/v1`; step 5 canonical padded base64 of exactly 32 bytes; step 6 canonical decimal ≤ 2⁶³−1; step 7 only when a submitted leaf is supplied; step 8 only when the checking time is nonzero, refusing when time ≥ deadline.

## Bundles (§8.1)

**C54** §8.1 / §10.1 bundle step 1 — "does not decode as §8.1's closed map, carries an unknown key, an unsupported version, or a `device` outside §2's grammar; or a `proof` element that is not exactly 32 bytes … or an `entry` longer than `MAX_ENTRY_BYTES`". Choice: length > 81919 → `bundle` before decode; decode/type errors (v uint = 1, device text grammar, index uint, entry bytes ≤ 65535, proof array of bytes(32), checkpoint text) → `bundle`.

**C55** §8.1 inclusion — "verified per RFC 9162 §2.1.3.2: exactly the hashes that procedure consumes". Choice: index ≥ size → `inclusion`; RFC 9162 algorithm, and a proof with surplus or missing hashes → `inclusion`.

**C56** §8.1 binding — "Binding is structural". Choice: the entry must pass the §4.0 profile and the §4.1 envelope shape (exact members, types, v = 1, 16-byte net, well-formed sigs) without the anchor net comparison; t = enroll → body.request (bytes) decoded under §16.1 structure and field rules including point admission and `expires > ts`, without signature or net comparison, body otherwise open; t = rotate/revoke → body.device_id as text; any other t, or a failure → names no device → `binding`. Label must equal the named id.

## Fork evidence (§11.1)

**C57** §11.1 codes 0–9. Choice: 0 file length > 65536 → `oversize`; 1 profile decode or not a map → `cbor`; 2 version absent/non-uint/not 1 or 2 → `version`; 3 key set exactly 7 (v1) / 11 (v2) and types (held/conflicting/policy text, size/split uint, held_root/split_root bytes(32), proof arrays of bytes(32)) → `schema`; 4 carried policy parse + valid points → `policy`; 5/6 held, conflicting under the reader's own keys and policy (§10 steps 2–7) → `held`/`conflicting`; 7 size > held.size or conflicting.size ≠ size → `size`; 8 proofs (size 0; same-size empty proof and held_root equality; RFC 9162 consistency with exact consumption; v2 split ≤ size, zero-split rules, split proofs with the same empty-proof rule) → `proof`; 9 roots equal → `consistent`.

**C58** §11.1 step 4 — "when `split` is not 0, that `split_proof_held` chains (`split`, `split_root`) to `held`'s signed head". Choice: same rule as step 3 per head: split equal to that head's size requires an empty proof and split_root equal to that head's root; otherwise RFC 9162 consistency from (split, split_root) to (head size, head root).

## Trust files (§9)

**C59** §9.1. Choice: length ≤ 65536; closed map {version, net, origin, name, genesis_hash, log_key, log_urls, witnesses, policy, anchor?}; version = 1; net bytes(16); origin = derived exactly; name UTF-8 text 1–64 bytes; genesis_hash bytes(32); log_key vkey alg 0x01, name == origin, valid point; log_urls array ≥ 1 of non-empty text; witnesses array ≥ 1 of closed {name, key, url?}, name 1–64 bytes in the ASCII key-name grammar, unique, key vkey alg 0x04 valid point, url text; no witness pk equals the log_key pk; policy parses, its witness directive names equal the witnesses' names as a set and each vkey text is identical; a `log` line, if any, has text equal to `log_key`; anchor, if present, exactly {type text, max_lag uint, mode text = "advisory"}, any type.

**C60** §9.3 — "first **10 bytes** of `SHA-256(CBOR(trust))` … Crockford base32 … four groups of four joined by `-` … followed by one `0x0A`". Choice: as written.

## Policy grammar (§9.1)

**C61** §9.1 — "Every directive line, including the final line, ends in ASCII line feed … so does every other line". Choice: text must end in LF (empty text has no lines and fails "exactly one quorum"); lines split on LF.

**C62** §9.1 — controls: "The only allowed ASCII control bytes are tab and line feed; all other bytes `0x00–0x08`, `0x0B–0x1F` and `0x7F` are an error anywhere". Choice: byte scan before line parsing; bytes ≥ 0x80 are content. The parser itself does not require UTF-8 (the CBOR layer does).

**C63** §9.1 — comments "first character other than ASCII space or tab is `#`"; blank lines; fields split on runs of space/tab; trailing whitespace adds no field. Choice: as written.

**C64** §9.1 field count — "`quorum` one, `witness` two or three, `log` one or two, `group` a name, a threshold and one or more members". Choice: as written; URLs are not validated.

**C65** §9.1 names — "one or more bytes `0x21`–`0x7E`, `+` excluded — and is at most 64 bytes"; one namespace; defined once; `none` predefined and not definable, not a group member; references only to earlier definitions. Choice: as written; unknown keywords (including uppercase) are errors.

**C66** §9.1 group thresholds — "`all` is `n`, `any` is 1, and a count is **canonical decimal** with `1 ≤ k ≤ n`". Choice: as written; members distinct by name.

**C67** §9.1 keys — "a verifier key appears **once** in a policy … compared by their parsed underlying public key". Choice: raw 32-byte pk compared across log and witness lines. Algorithm: log → 0x01, witness → 0x04. Declared id recomputed. Point validity is enforced by the policy parser (used everywhere a policy is parsed: trust, policy entry, evidence, `policies/`).

## Requests (§16)

**C68** §16.1 — closed map {v, ts, net, sig, wg_pk, labels?, expires?, device_id, device_pk}. Choice: v = 1; net bytes(16); sig bytes(64); wg_pk bytes(32) (no X25519 validation); labels map text→text, ≥ 1 pair, ≤ 32 pairs, values ≤ 256 bytes; expires uint > ts; device_id §2 grammar; device_pk bytes(32) and a valid point. Signature over "norn/enroll-request/v1\n" ‖ CBOR(request minus sig), checked under NORN-ED25519-v1. A consumer refuses another network.

**C69** §16.2 — bech32m per BIP-350, HRP `norn`, constant 0x2bc830a3, lowercase or all-uppercase, mixed refused; separator = last `1`; characters 33–126; no 90-character limit; padding < 5 bits and zero; decoded payload ≤ 65535.

## Freshness and proven set (§8.1, §5.3, §15)

**C70** §8.1 — ladder "unknown → hard_stale (S_hard configured and elapsed > S_hard) → fresh (elapsed ≤ S) → degraded". Choice: S_hard 0 = not configured.

**C71** §15 — "The node's estimate of now is **the largest of the lower bounds** it holds". Choice: estimate = max over recorded (q, m) of q + (now_mono − m); age = estimate − held q.

**C72** §5.3 — "A device is expired exactly when `expires != 0 && expires <= T`"; no clock → no expiry judged. Choice: as written.

**C73** §6 anchors — "the three body lines **plus the blank line**, four `0x0A` in all". Choice: SHA-256 over the note bytes from the start through the LF ending the blank separator line.
