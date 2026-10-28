# Cold gate run 20 — decisions log

Written after reading `SPEC.md` in full and before opening `testdata/vectors/README.md`,
any manifest or any vector. Each entry: section, the exact words, what I chose, why.
Not edited after the first vector was opened; later doubts go in the report.

## §3.1 NORN-ED25519-v1

**C01** §3.1 item 1 — "the canonical encoding (RFC 8032 §5.1.3) of a point of order exactly `L` ... `[L]P = O` and `P ≠ O`".
Choice: own big-integer edwards25519 decoder: reject `y ≥ p`, reject no square root, reject `x = 0` with sign bit 1, reject the identity, then compute `[L]P` and require the identity. Why: the text names the predicate; Go's stdlib edwards25519 is internal and its decoder is lenient, so I check the point myself.

**C02** §3.1 item 3 — "`S` ... MUST be less than `L` ... `[S]B = R + [k]A` ... the cofactorless one ... is the definition".
Choice: valid-point(A) ∧ valid-point(R) ∧ S < L, then `crypto/ed25519.Verify`, which computes `[S]B − [k]A` and compares its canonical encoding with `R` (cofactorless). Why: once R is canonical, byte equality of the encoding is the cofactorless equation; stdlib also refuses S ≥ L.

**C03** §3.1 item 2 — "A key that is not is refused as `decode` at its entry type's body step".
Choice: point admission is part of the body schema check of genesis (→ bad-genesis), `signer_add`, `root_add`, `log_key`, `rotate` incoming `device_pk`, every key in a `policy` entry's text (log and witness lines), the embedded request's `device_pk`; at trust load (invalid file); in fork evidence's carried policy (`policy`); in request decoding. Why: the item lists these points exactly.

## §4.0 encoding profile

**C04** §4.0 "The profile is an allow-list ... and nothing else" / "`0xf8` followed by any byte below 32".
Choice: decoder accepts major 0, 2, 3, 4, 5 and only `0xf4`/`0xf5` in major 7; every other major-7 byte (including `0xf8 xx` for every `xx`, 0xf9–0xfb floats, 0xff break), tags, negative ints, indefinite lengths refused. Why: literal allow-list.

**C05** §4.0 "Shortest form means every argument, not only integers".
Choice: every head argument (uint value, byte/text/array/map length) must be in preferred serialization: values < 24 inline, < 2^8 one byte, etc. Why: stated.

**C06** §4.0 Integers "≤ 2⁶³−1".
Choice: any major-0 value above 2^63−1 is a profile violation (decoder), wherever it appears (entries, requests, bundles, trust, evidence). Lengths above that cannot occur in bounded input and are refused as truncated/oversize anyway.

**C07** §4.0 "every **map key** is a text string of 1–23 bytes".
Choice: applies to every map in every Norn CBOR structure (envelope, body, sigs elements, labels, request, trust, witness elements, anchor, bundle, evidence). A non-text or empty or 24+ byte key is a decoder refusal. Why: "All Norn CBOR structures ... use ... with these restrictions".

**C08** §4.1 "bytewise lexicographic order of their encoded form ... strictly increasing".
Choice: compare the encoded key items (header + bytes); each key strictly greater than the previous. Duplicate keys and unsorted keys are the same refusal.

**C09** §4.0 "valid UTF-8".
Choice: Go `utf8.Valid` (RFC 3629: no surrogates, no overlongs, ≤ U+10FFFF), for every text string including map keys.

**C10** §4.0 "A decoder MUST consume the **whole** input".
Choice: trailing bytes after the top-level item are a profile violation (`decode`).

**C11** §4.0 "Nesting depth is at most 8, counted in containers. The top-level map is depth 1".
Choice: depth counter incremented on entering an array or map; entering a container at depth 9 is refused. Embedded request decoded by a separate call with depth restarting at 1.

**C12** §4.0 "`MAX_ENTRY_BYTES` is 65535 ... an entry is at most that many bytes — as is an enrollment request".
Choice: input longer than the artifact's cap refused before decoding; also any declared string/array/map length larger than the remaining input is refused (truncated) without allocation, and a declared length larger than the cap is refused as size. Caps: entry and request 65535, bundle 81919, trust 65536, evidence 65536.

**C13** §4.0 field table: `device_id` "matches `^[a-z0-9][a-z0-9.-]{0,63}$` as a whole".
Choice: byte-wise check, 1–64 bytes, first byte `[a-z0-9]`, rest `[a-z0-9.-]`; nothing else (no newline).

**C14** §4.0 `name`, `reason`: "UTF-8, 1–64 / 0–256 bytes"; `text` "≤ 4096 bytes".
Choice: byte lengths, inclusive bounds.

**C15** §4.0 `labels`: "≤ 32 entries; keys 1–23 bytes ...; values ≤ 256 bytes, the empty value included; ... `labels: {}` is refused".
Choice: 1–32 pairs, text→text, value ≤ 256 bytes (empty allowed). Present-but-empty refused.

**C16** §4.0 `roots`, `signers` at genesis: "arrays of 32-byte `pk`, no duplicates, no key in both".
Choice: duplicates compared on the 32 key bytes. Two distinct keys with an equal `kid` are not refused by any stated rule; I do not add a kid-collision rule (literal reading). Noted as a possible gap.

**C17** §4.0 `kid` "exactly 16 characters matching `^[0-9a-f]{16}$`".
Choice: byte check, lowercase hex only, exactly 16 bytes; applies in `sigs` and in `signer_remove`/`root_remove` bodies.

**C18** §4.0 "sorted by `kid` bytewise, with no repeated `kid`".
Choice: compare kid text bytes, strictly increasing; part of envelope check (step 3, `decode`).

**C19** §4.0 "Booleans ... schemas MUST reject them outside `params.rotate_needs_signer`".
Choice: a boolean where a uint/text/bytes is expected is a schema fault (`decode`/`bad-genesis`/`schema`/`bundle`/invalid trust).

## §4.0 grants

**C20** §4.0 "the label split on commas, each part trimmed and parsed ... a label that is absent or does not parse as a whole is no grant".
Choice: split on every `,`; strip leading and trailing U+0020 only; an empty part (e.g. trailing comma, empty label) does not parse → no grant.

**C21** §4.0 "An IPv4-mapped IPv6 prefix is no grant either" with §12.1 "IPv4-mapped addresses before masking".
Choice: an IPv6 part whose written address (before masking) lies in `::ffff:0:0/96` makes the whole label no grant. IPv4-compatible (`::a.b.c.d`) is not mapped and is allowed.

**C22** §4.0 "groups of one to four hexadecimal digits in either case, at most one `::`, a dotted quad allowed in place of the last 32 bits, and no zone".
Choice: hand parser. `::` must stand for at least one zero group (so with `::` at most 7 explicit groups, the quad counting as 2); without `::` exactly 8 groups. Dotted quad only as the final component. Empty groups other than the `::` refused.

**C23** §4.0 "The length is decimal without a leading zero, at most 32 ... 128".
Choice: `0` allowed; `00`, `01` refused; digits only.

**C24** §4.0 "IPv6 address in RFC 5952 form with every group in lowercase hexadecimal (an embedded dotted quad is written as two groups)".
Choice: mask, then render: lowercase, no leading zeros in a group, the longest run of ≥ 2 zero groups compressed to `::` (first run on a tie), a single zero group not compressed; never a dotted quad.

**C25** §4.0 "masked to its prefix, duplicates removed, sorted as text".
Choice: bytewise sort of the canonical strings after masking and dedup; IPv6 and IPv4 interleave by text.

## §4.1–§4.5, §5 replay

**C26** §5.1 step 3 "exactly the permitted keys, every member of the type §4.1 gives it (`t` text, `ts`, `after` and `prev` uint, `body` a map), `v` = 1, `net` = `anchor.net`, well-formed `sigs`".
Choice: `v` must be uint 1, `net` a 16-byte string equal to anchor.net, `sigs` an array of closed `{kid, role, sig}` maps with kid format, role ∈ {root, signer, device}, sig 64 bytes, sorted/unique. All `decode`.

**C27** §5.1 step 1 "An entry whose `entry_hash` is in the first set, or that decodes and whose `content_hash` is in the second → reject (`dup-entry`)" and "the hash is the one of an entry steps 2 and 3 accept".
Choice: step 1 checks the byte set; then, only if decode and the envelope check both pass, checks the content set. Every entry adds its entry_hash. Content hash is added only when the entry is applied (genesis included).

**C28** §4.0 `content_hash` "SHA-256 of the signature preimage".
Choice: `SHA-256("norn/entry/v1\n" ‖ canonical CBOR of the envelope without sigs)`; since input is canonical, I re-encode the decoded map minus `sigs`.

**C29** §5.2 "a signature `{kid, role, sig}` is valid iff `kid` names a key this entry may be signed by in that role, and Ed25519 verification ... succeeds".
Choice: role `root` resolves kid in pre-entry roots; `signer` in pre-entry signers; `device` only for enroll (request's device_pk), rotate (current and incoming device_pk), revoke (device's current device_pk); for every other type a device-role signature resolves to nothing. Distinct keys counted per role; invalid signatures ignored.

**C30** §4.3 / §5.1 `revoke` "≥ `signer_thr` signers, or the device itself, or ≥ `root_thr` roots".
Choice: three independent tests, no pooling; device = the named device's current device_pk from state.

**C31** §5.1 step 7 "For `note`: no valid `signer` or `root` signature → reject (`threshold`)".
Choice: note needs ≥ 1 valid signer-or-root signature; checked at step 7, before its body (so a note with `prev` and no valid signature is `threshold`).

**C32** §5.1 enroll row "the request decodes under §16.1 and its `net` equals the entry's (`decode`)".
Choice: request decoding = §4.0 profile (fresh depth, cap 65535) + §16.1 closed schema + field rules (v = 1, device_id grammar, device_pk 32 bytes and valid point, wg_pk 32, net 16, sig 64, labels rules, expires > ts when present). Then net equality. All `decode`. Then signature (`no-device-sig`).

**C33** §16.1 `expires` "MUST be > `ts`".
Choice: strictly greater; `expires` 0 with any `ts` ≥ 0 is refused (0 > ts never holds). Absent means none (state 0).

**C34** §5.1 enroll/rotate: no rule on `wg_pk` beyond 32 bytes.
Choice: any 32 bytes accepted as a WireGuard key (no X25519 validation, all-zero allowed).

**C35** §5.1 rotate row order: "body ... (`decode`) · `device_id` known · currently `active` · valid `device` signature by the device's current `device_pk` · if `params.rotate_needs_signer`, signer count · `prev` · new `wg_pk` not active for another device (`dup-wg`) · if the body carries `device_pk`, a valid `device` signature by that key as well".
Choice: exactly this order. A rotate presenting its own current wg_pk is allowed.

**C36** §5.1 `enroll` `prev` "is the `device_id`'s record `version`, or absent when no accepted entry has ever named the id".
Choice: if a device record exists (active or revoked) prev must be present and equal; else prev must be absent.

**C37** §4.4 governance `prev`.
Choice: required and equal to `versions.<object>` (0 after genesis) for every governance type; note with prev → `decode` at step 8; genesis with prev → bad-genesis.

**C38** §5.1 `signer_add`/`root_add` "`kid(pk)` not already a root or signer (`dup-key`)".
Choice: compare kid of the new pk against kids of both role sets (kid, as written). pk must be bytes32 and a valid point (`decode`).

**C39** §5.1 `log_key` "`pk` is not the public key of any witness the policy in force names — `policy` when it is non-empty, else `anchor.policy`".
Choice: witness lines only (not `log` lines) of the parsed policy in force; compare 32-byte pk. Then active log keys: anchor.log_key pk and every `log_keys` pk.

**C40** §5.1 `policy` "no witness the text names has the public key of an active log key".
Choice: witness lines only; `log` lines of the new policy are not compared (a log line may name any key).

**C41** §5.1 `params` "non-empty, only §4.5 keys, each of the right type"; §4.5 routes closed set.
Choice: three uints (zero allowed), `rotate_needs_signer` bool, `routes` text ∈ {granted, advisory}. Merge into state; same rule for genesis params.

**C42** §5.1 `signer_thr`/`root_thr` "`1 ≤ thr ≤ len(set)` (`bad-thr`)".
Choice: len of the current set before the entry.

**C43** §5.1 `root_remove` "removing it leaves ≥ `root_thr` roots and ≥ 1 root".
Choice: `len(roots) − 1 ≥ root_thr`.

**C44** §5.1 entry 0 step 6/7 bootstrap.
Choice: genesis signatures with role `root` whose kid resolves among body.roots; distinct valid count ≥ root_thr. Genesis body field checks also include point admission (C03), name 1–64 bytes, params rules (C41). Order as written (unobservable).

**C45** §5.3 state.
Choice: params always holds all five keys; log_keys `{overlap, pk, since_index}`; versions five keys; devices with labels `{}`/expires 0 defaults; aborted state: name "", net from anchor, everything zero, params defaults, rejected `[{index:0, reason:"bad-genesis"}]`. Empty log: zero state, rejected `[]`, size 0.

**C46** §14 canonical JSON.
Choice: keys sorted bytewise over UTF-8; escapes exactly the listed set (`\"`, `\\`, `\b`, `\t`, `\n`, `\f`, `\r`, other C0 as lowercase `\u00xx`); everything else verbatim; bytes lowercase hex; trailing `0x0A`.

## §6, §7 notes, checkpoints, receipts

**C47** §7 "the first blank line ends the text"; "Every signature line, including the last, ends in one 0x0A—exactly one"; "at least one signature line".
Choice: parse: whole note valid UTF-8 and no byte < 0x20 except LF; split into lines on LF; require final LF; first line non-empty; text = lines before the first empty line; at least one line after it; every later line non-empty and frames.

**C48** §7 signature line "`— ` ... the key name, one space, then base64 ... splits at its first space"; name rule.
Choice: prefix exactly `E2 80 94 20`; name = up to the first U+0020; name non-empty, no `+`, none of the listed whitespace code points; payload = remainder, standard padded base64, canonical (re-encode equals), decoded length ≥ 4. DEL (0x7F) is allowed (it is not below U+0020).

**C49** §7 "Framing is every line's; length is the matched key's".
Choice: a line matches a key iff name bytes equal the key's name and the 4-byte id equals the key's id. A matched log key (alg 0x01) requires exactly 68 bytes, a matched witness key (alg 0x04) exactly 76. Unmatched lines ignored whatever the length.

**C50** §7 cosignature timestamp "at most 2⁶³−1 ... fails that witness's check, `cosignature`, before its signature is verified"; message `"cosignature/v1\n" ‖ "time " ‖ <decimal> ‖ "\n" ‖ <note text>`.
Choice: as written.

**C51** §6 checkpoint body "exactly three lines ... size in decimal with no leading zeroes and at most 2⁶³−1 ... root as standard base64 with padding, 32 bytes once decoded ... canonical".
Choice: size `0` allowed (canonical decimal of zero); root re-encodes exactly. Failure → `checkpoint`.

**C52** §10 log signature "Every signature line whose name and key id match a trusted log key MUST verify, and at least one such line MUST be present".
Choice: trusted log keys = trust `log_key` + every learned `log_keys` pk as verifier key named origin, alg 0x01, id recomputed; all learned keys usable regardless of the checkpoint's size.

**C53** §10.1 step 6 "a cosignature line whose name and key id match a listed witness does not verify — listed meaning named by the policy in force".
Choice: witnesses = `witness` lines of the policy in force (replayed state policy if non-empty, else trust policy); matching uses the vkey's note name (e.g. `norn-witness/pi`), not the policy short name.

**C54** §9.1 group semantics; §10.1 step 7.
Choice: a witness is satisfied iff it has ≥ 1 verifying line; group satisfied iff satisfied members ≥ k; nested group counts as one member; `none` always satisfied.

**C55** §5.3 "T is the quorum time ... the newest instant such that the witnesses whose cosignature timestamp is at or after it satisfy the policy"; "A witness counts once ... its newest".
Choice: per witness take the newest verifying timestamp; T = max t over those timestamps such that {w : ts_w ≥ t} satisfies the quorum. `quorum none` → no clock. No satisfying instant → no clock.

**C56** §7 receipt steps 1–8.
Choice: in order: note framing → log signature (same matching rule as C49/C52; ≥ 1 matched, all matched verify, exact length) → exactly four text lines and first `norn/receipt/v1` (`receipt`) → origin equality → leaf hash canonical std-padded base64 of 32 bytes → deadline canonical decimal ≤ 2^63−1 (`0` allowed) → entry binding when a leaf is supplied → `now ≠ 0 ∧ now ≥ deadline` → `expired`.

## §6 tiles, §10 loop

**C57** §6 paths: three-digit groups, `x` prefix on non-final groups, `.p/<W>` for partial.
Choice: as written; level-L hash count = floor(size / 256^L) at tree height 8L; tiles at each level with ≥ 1 hash.

**C58** §6 "a verifier that cannot fetch `tile/<L>/<N>.p/<W>` MUST fetch `tile/<L>/<N>` before it answers `unserved`; ... the file it fetches must itself be a well-formed full tile or bundle".
Choice: fall back only on absence of the partial (not on a malformed partial); a full stand-in must be exactly 8192 bytes / exactly 256 frames; compare only the first W.

**C59** §10.1 order.
Choice: 1 unserved(checkpoint) → 2 note → 3 log-signature → 4 checkpoint → 5 origin → 6 cosignature → 7 quorum → 8 entries (unserved if a bundle is missing) → 9 head → 10 fork/rollback (if a stored head is held) → 11 genesis (size 0, or entry 0 aborts replay alone) → 12 tiles (unserved if a tile is missing) → replay.

**C60** §10.1 step 8 "A zero-length frame frames".
Choice: length-0 frames are entries; the empty entry is a replay `decode`.

**C61** §10 fork block: `at := min(cp.size, stored.size)`; served root at `at` from served entries; mine = stored root if `at == stored.size`, else my branch's root at `at` (only if I hold my branch's entries); otherwise no accusation.
Choice: as written; size rule after.

## §8.1 bundles

**C62** §10.1 bundle step 1 and §8.1 table.
Choice: length > 81919 → `bundle`; decode under the profile with that cap; closed six keys; `v` = 1; `device` text in §2 grammar; `index` uint; `entry` bytes ≤ 65535; `proof` array of exactly-32-byte strings; `checkpoint` text. All `bundle`.

**C63** §10.1 bundle step 3 "the index is outside the tree, or the inclusion proof does not chain ... or the proof carries more or fewer hashes".
Choice: RFC 9162 §2.1.3.2 with exact consumption; index ≥ size → `inclusion`.

**C64** §8.1 binding "The entry itself must decode under §4.0's profile and §4.1's envelope — its closed set of members, each of its type: `v` 1, a text `t`, a 16-byte `net`, a uint `ts`, a map `body`, well-formed `sigs`".
Choice: binding checks the envelope structurally (key set, types incl. optional after/prev uint, v = 1, sigs well-formed), not net against anchor. `enroll`: body must hold `request` as bytes (body not closed); request decoded with §16.1 structure + field rules + point admission, not signature or net; its device_id. `rotate`/`revoke`: body `device_id` must be a text string; compared bytewise with the label. Any other `t` names no device → `binding`.

## §9 trust file and policy grammar

**C65** §9.1 trust fields.
Choice: cap 65536 first; profile decode; closed map; version 1; net 16 bytes; origin exactly derived; name 1–64 bytes text; genesis_hash 32 bytes; log_key vkey alg 0x01, name == origin, id recomputed, valid point; log_urls array ≥ 1 of non-empty text; witnesses array ≥ 1 of closed `{name, key, url?}`, name 1–64 bytes of the key-name grammar, unique, key vkey alg 0x04 with recomputed id and valid point, url text; no witness pk equal to log_key pk; policy parses, witness names as a set equal the file's names, each witness vkey text equal to the file's key text, each `log` line vkey text equal to log_key; anchor optional closed `{type, max_lag, mode}`, type any text, max_lag uint, mode `advisory`.

**C66** §9.1 policy grammar.
Choice: whole text: every line ends in LF (non-empty text must end in LF); bytes 0x00–0x08, 0x0B–0x1F, 0x7F refused anywhere; lines split on LF; fields split on runs of space/tab; blank lines and lines whose first non-blank char is `#` ignored; keywords exact lowercase, unknown keyword refused; field counts exact; names key-name grammar ≤ 64 bytes, one namespace, `none` undefinable, unique; group thr `all`/`any`/canonical decimal 1..n; members previously defined, not `none`, no repeats; exactly one quorum naming an earlier definition or `none`; vkeys parsed (C67), log alg 0x01, witness alg 0x04, point admission, public keys unique across all lines; URLs opaque.

**C67** §7/§9.1 verifier key "`<name>+<key_id as 8 lowercase hex digits>+<base64(alg ‖ pk)>`. Split it on `+` at most twice".
Choice: name = before first `+`, id = between first and second `+` (exactly 8 lowercase hex), data = rest; data std base64, canonical, exactly 33 bytes; alg ∈ {0x01, 0x04} as the role requires; declared id must equal recomputed `SHA-256(name ‖ 0x0A ‖ alg ‖ pk)[0:4]`.

**C68** §9.3 fingerprint.
Choice: first 10 bytes of SHA-256(file bytes), Crockford base32 MSB first, 16 chars in 4 groups joined by `-`; file content = string + LF.

## §11.1 fork evidence

**C69** §11.1 codes in order: oversize → cbor → version → schema → policy → held → conflicting → size → proof → consistent.
Choice: as written. `cbor` includes "not a map". `version` absent / not uint / not 1 or 2. `schema`: exact key set for the version and types (held/conflicting/policy text, size/split uint, held_root/split_root bytes of exactly 32, proofs arrays of exactly-32-byte strings).

**C70** §11.1 step 3/8 proof.
Choice: size 0 → `proof`; size == held.size → proof must be empty and held_root == held root; else RFC 9162 §2.1.4.2 with exact consumption. v2: split ≤ size; split 0 → zero root and both split proofs empty; split > 0 → each split proof chains to its head, empty exactly when split equals that head's size (then split_root must equal that head's root).

**C71** §11.1 held/conflicting checked "per §10 — this network's origin, the log keys the reader trusts ..., and a satisfied witness quorum under the reader's own policy".
Choice: checkpoint steps 2–7 with the reader's trusted keys and its policy in force.

## §8.1 freshness, §5.3 evaluation

**C72** §8.1 ladder "unknown / hard_stale / fresh / degraded", first row that holds.
Choice: unknown if no quorum time; hard_stale if hard > 0 and elapsed > hard; fresh if elapsed ≤ S; else degraded.

**C73** §5.3 "A device is expired exactly when `expires != 0 && expires <= T`"; no clock → not judged.
Choice: as written.

**C74** §15 age estimate "the largest of the lower bounds".
Choice: estimate(now) = max over recorded pairs (q + (mono_now − m)); age = estimate − held quorum time.

## §16 requests

**C75** §16.2 bech32m.
Choice: BIP-350 decoding: characters 33–126, all-lower or all-upper (mixed refused), separator = last `1`, HRP `norn` (case-folded only when the whole string is uppercase), data charset, checksum constant 0x2bc830a3 (bech32's 1 refused), no length limit; 5→8 regrouping with padding < 5 bits and zero; decoded payload ≤ 65535.

**C76** §16.1 "A consumer MUST validate structure and verify `sig` ... MUST also refuse a request whose `net` is not the network it serves".
Choice: order: text layer → CBOR profile → schema/field rules (incl. point admission) → signature → consumer network.

## §6 anchors

**C77** §6 anchors "SHA-256 of the note's leading bytes through the newline that terminates the blank separator line".
Choice: digest of checkpoint bytes up to and including the first `\n\n`'s second LF.

## Harness

**C78** §12 "`says` is a semantic hint ... What a reader compares is the `codes` map wherever a manifest has one".
Choice: compare closed codes exactly wherever given; where only `says`/accept is given, compare accept/refuse and report my own reason beside it.
