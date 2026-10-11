# Cold gate run 14 — interpretation decisions

Written after reading `SPEC.md` in full and **before** opening
`testdata/vectors/README.md`, any manifest or any vector. Not edited afterwards;
later doubts go in `SPEC-DEFECTS-14.md`.

Format: `Cnn` — section — exact words — choice — why.

## Signatures (§3.1)

**C01** — §3.1 item 1 — "the encoded `y` is below `p`, the sign bit is 0 when `x` is 0, the bytes decode to a point on the curve, and that point is not the identity and has no component of order 2, 4 or 8 — `[L]P = O` and `P ≠ O`".
Choice: implement RFC 8032 §5.1.3 decoding myself (math/big): reject `y ≥ p`; recover `x`; reject if no square root; reject `x = 0` with sign bit 1; then compute `[L]P` and require the identity, and `P ≠ O`. Why: Go's stdlib `crypto/ed25519` accepts non-canonical `A` and small-order points, so the predicate cannot be delegated to it.

**C02** — §3.1 item 3 — "`S`, read as a little-endian integer, MUST be less than `L` … and with `k = SHA-512(R ‖ A ‖ M)` read little-endian and reduced mod `L`, `[S]B = R + [k]A`" … "the cofactorless one, RFC 8032 §5.1.7's second form, is the definition".
Choice: verify = (A valid point) ∧ (R valid point) ∧ (S < L) ∧ cofactorless equation, computed in my own point arithmetic. A signature of wrong length (≠ 64) or key of wrong length (≠ 32) never verifies. Why: stated.

**C03** — §3.1 item 2 — "A key that is not is refused as `decode` at its entry type's body step … for a governance entry that step follows the root quorum".
Choice: the valid-point test on admitted keys runs inside step 8's body check for governance entries (after the root-quorum `threshold` check), and inside the `rotate` body check (first check of step 8). In genesis it is part of entry-0 step 6 (`bad-genesis`). Why: stated.

**C04** — §3.1 item 2 — "every verifier key a `policy` entry's text carries".
Choice: in a `policy` entry, both `log` and `witness` vkeys must be valid points; failure → `decode`. In any policy parse (trust file, evidence, policy files) I apply the same point check, since §9.1's grammar paragraph says every `<vkey>` "MUST be parsed as a C2SP verifier key" and §3.1 makes trust-file witness keys valid points. Why: one parser, strictest reading consistent with every sentence.

## Encoding profile (§4.0)

**C05** — §4.0 — "A Norn CBOR item is an unsigned integer (major type 0), a byte string (2), a text string (3), an array (4), a map (5), or one of the two simple values `false` (20) and `true` (21) of major type 7 — and nothing else."
Choice: decoder refuses major 1, major 6, major 7 with ai ∉ {20,21} (including ai 24 two-byte simple even for 20/21, ai 25–27 floats, 22, 23, 28–31), and ai 31 (indefinite) on any major; ai 28–30 is malformed. Why: allow-list, stated.

**C06** — §4.0 — "Integers | major type 0 only; shortest form; ≤ 2⁶³−1."
Choice: the 2⁶³−1 bound is a decoder (profile) rule applied to every major-0 item, not a schema rule. Why: it sits in the profile table and §4.0 construction 2 lists "an integer above 2⁶³−1" as a profile patch.

**C07** — §4.0 — "Shortest form means every argument, not only integers … the length header of a byte string, text string, array or map".
Choice: every head argument (value or length) must use the shortest encoding. Why: stated.

**C08** — §4.0 — "every map key is a text string of 1–23 bytes".
Choice: a decoder rule for every map in every Norn CBOR artifact (entries, requests incl. `labels`, trust files, bundles, evidence). A non-text key, an empty key or a key over 23 bytes is a decoder failure. Why: in the profile table; §12.1 says `oversize-label-key` "is refused by the decoder before the `labels` field rule".

**C09** — §4.0/§4.1 — "keys strictly increasing in §4.1's order".
Choice: compare encoded key bytes (header included); since keys are 1–23 bytes this is length-then-bytewise. Equal or decreasing → decoder failure. Why: stated.

**C10** — §4.0 — "Text strings | definite length; valid UTF-8".
Choice: RFC 3629 UTF-8 (Go `utf8.Valid`: no surrogates, no overlongs, ≤ U+10FFFF). Why: the standard meaning.

**C11** — §4.0 — "Nesting depth is at most 8, counted in containers. The top-level map is depth 1".
Choice: a container whose depth would be 9 is refused; scalars add nothing; an embedded request is decoded by a fresh call starting at 1. Applied to every CBOR artifact. Why: stated.

**C12** — §4.0 — "`MAX_ENTRY_BYTES` is 65535, and an entry is at most that many bytes — as is an enrollment request".
Choice: input length > 65535 refused before parsing for entries and requests (request text form: decoded payload). Bundles 81919, trust files 65536, evidence 65536, each refused on length before parsing. Why: stated.

**C13** — §4.0 — "A decoder MUST consume the whole input".
Choice: trailing bytes after the top-level item → decoder failure. Why: stated.

**C14** — §4.0 — "Booleans | valid CBOR items; schemas MUST reject them outside `params.rotate_needs_signer`".
Choice: the decoder admits `true`/`false`; every schema type check for uint/text/bytes refuses a boolean. Why: stated.

**C15** — §4.0 — "A negative for one of those rules must fail for that rule and nothing else".
Choice: my decoder returns a distinct internal reason per profile rule (null, undefined, float, simple, negative, tag, indefinite, non-text key, key length, key order, utf8, non-shortest, int-too-large, depth, size, trailing, truncated) so the harness can check "refused for its own rule". Why: `entries-hostile/` is announced as asking which rule refuses.

## Entries (§4.0–§4.5)

**C16** — §4.0 derived values — "`content_hash` | `SHA-256` of the signature preimage below".
Choice: preimage = `"norn/entry/v1\n"` ‖ canonical re-encoding of the decoded envelope minus `sigs`. Because the profile is canonical and whole-input, re-encoding equals the received bytes minus the `sigs` pair. Why: §4.2.

**C17** — §4.0 — "`entry_hash` | `SHA-256` of the entry as received, byte for byte".
Choice: hash of raw bytes. Why: stated.

**C18** — §4.0 field constraints — "`kid` … exactly 16 characters matching `^[0-9a-f]{16}$`".
Choice: lowercase hex only, in `sigs` and in `signer_remove`/`root_remove` bodies; uppercase → `decode`. Why: stated.

**C19** — §4.0 — "Each element of `sigs` is itself a closed map of exactly `{kid, role, sig}`".
Choice: all three required; `role` ∈ {root, signer, device} else `decode`; `sig` must be bytes of length 64 else `decode`; array strictly increasing by `kid` (bytewise on the hex text, which equals bytewise on the decoded bytes) else `decode`. Why: stated.

**C20** — §4.0 — "`device_id` | matches `^[a-z0-9][a-z0-9.-]{0,63}$`".
Choice: ASCII-only regex, 1–64 bytes. Why: stated.

**C21** — §4.0 — "`name`, `reason` | UTF-8, 1–64 / 0–256 bytes"; "`text` (`note`, `policy`) | UTF-8, ≤ 4096 bytes".
Choice: byte counts, not characters. `reason` optional, absent ≡ `""`. Why: stated.

**C22** — §4.0 — "`labels` | map text→text; ≤ 32 entries; keys 1–23 bytes …; values ≤ 256 bytes; … `labels: {}` is refused as a schema fault".
Choice: values may be empty (0 bytes); at most 32 pairs; empty map → schema fault. Why: stated bounds only.

**C23** — §4.0 — "The `ip` label is the device's grant … the label split on commas, each part trimmed and parsed as an IPv4 or IPv6 prefix, masked to its prefix, duplicates removed, sorted as text".
Choice: "trimmed" = ASCII whitespace (space, tab, CR, LF, VT, FF) at both ends; "prefix" requires an explicit `/len` (Go `netip.ParsePrefix`, which refuses leading zeros, zones and bare addresses); IPv4-mapped IPv6 (`::ffff:a.b.c.d/n`) → no grant; any empty or unparseable part → no grant; render with Go's canonical `Prefix.String()` (RFC 5952 for IPv6); sort bytewise. Why: "parsed as a prefix" names a prefix, not an address; the trim set is not stated, so I take ASCII whitespace.

**C24** — §4.1 — "`v`, `t`, `net`, `ts`, `body` and `sigs` are all mandatory; only `after` is optional".
Choice: `v` uint equal to 1, `t` text, `net` bytes of length 16 equal to `anchor.net`, `ts` uint, `after` uint, `body` map, `sigs` array — every failure `decode` at step 3. Why: §5.1 step 3.

**C25** — §4.3 — "`enroll` | `request` (bytes — a §16 enrollment request, verbatim)".
Choice: body is a closed map with exactly `request` (bytes). The request is decoded by a separate call under §16.1 (own size cap, own depth). Every request failure — profile, schema, field rule, `expires > ts`, `device_pk` point, `net` mismatch — is `decode`; only the request signature is `no-device-sig`. Why: §5.1 enroll row.

**C26** — §4.3 — "`rotate` | `device_id`, `wg_pk` (new), `device_pk` (new, OPTIONAL)".
Choice: closed body; `wg_pk` and `device_pk` bytes32; `device_pk` a valid point. If the incoming `device_pk` equals the current one, one signature satisfies both device checks. Why: the spec states nothing against it; D-032's "re-presenting the device's own key" is read symmetrically.

**C27** — §4.3 — "`revoke` | `device_id`, `reason` (string, OPTIONAL — absent is equivalent to `""`)".
Choice: closed body. Authorisation is the OR of three un-pooled tests: valid signer count ≥ `signer_thr`; valid root count ≥ `root_thr`; ≥ 1 valid `device` signature by the named device's current `device_pk`. Why: §4.3, §12.1 `bad-revoke-neither-quorum`.

**C28** — §4.3 — "Signature counting: a key contributes at most once; a key counts only for the role it currently holds".
Choice: count distinct `kid`s whose element declares role R, whose `kid` is in state's R map, and whose signature verifies under §3.1 over the preimage. Why: stated (§5.2).

**C29** — §5.2 — "For `device` it is the `device_pk` of the device this entry names".
Choice: a `device`-role element counts only if its `kid` equals `kid(device_pk)` of the relevant key (current, or incoming for `rotate`); a device-role element in an `enroll` envelope is ignored (the request's own `sig` is the device check). Why: stated.

**C30** — §4.3 — "`signer_add` | `pk`"; "`root_add` | `pk`"; "`log_key` | `pk` (bytes32), `overlap` (uint s)".
Choice: closed bodies; `pk` bytes32 valid point; `overlap` uint (boolean → `decode`). Why: stated.

**C31** — §4.3/§5.1 — "`thr` is a plain uint here … Its range — `1 … len(set)` — is a replay decision".
Choice: schema checks only uint-ness (bool → `decode`); range → `bad-thr` against the current set size. Why: stated.

**C32** — §4.5 — "`routes` is the one text-valued parameter and its value set is closed".
Choice: `checkpoint_interval`, `staleness`, `mmd` any uint (0 allowed); `rotate_needs_signer` boolean only; `routes` text ∈ {granted, advisory}. Why: table.

## Replay (§5)

**C33** — §5.1 entry 0 — "The duplicate key of §5.1 step 1 is recorded as seen."
Choice: entry 0's key = `content_hash` if it decodes and its envelope passes (net included), else `entry_hash`. Why: same definition as step 1.

**C34** — §5.1 entry-0 step 7 — "genesis signatures are counted against the `roots` and `root_thr` in its own body".
Choice: count elements with role `root` whose `kid` is `kid(pk)` of a key in the body's `roots`; signer-role elements and kids of body `signers` count for nothing. Why: §12.1 `18-…`, `19-…` rows confirm the role and set both matter.

**C35** — §5.1 entry 0 — "Any failure → abort (`bad-genesis`)".
Choice: on abort, state = zero state (name "", size 0, thresholds 0, empty maps, params defaults, policy "", log_keys [], rejected [{0,bad-genesis}]), and nothing after entry 0 is read. Why: stated.

**C36** — §5.1 step 1 — "its `content_hash` if steps 2 and 3 would accept it … and its `entry_hash` otherwise".
Choice: one seen set holding both kinds of 32-byte keys. Why: stated; collisions between the two hash domains are negligible.

**C37** — §5.1 step 3 — "well-formed `sigs`".
Choice: per C19, inside step 3, so a malformed sigs array is `decode` before `unknown-type`. Why: stated.

**C38** — §5.1 steps 4–6 — "`t` not in §4.3 → reject (`unknown-type`)" · "`t` = `genesis` → `dup-genesis`" · "`after` present and > index".
Choice: in that order; `after == index` passes. Why: stated.

**C39** — §5.1 step 7 — "For `note`: no valid `signer` or `root` signature → reject (`threshold`)."
Choice: note needs ≥1 valid signer **or** root signature, checked before its body. For `enroll`, `rotate`, `revoke` step 7 rejects nothing. Why: stated.

**C40** — §5.1 enroll row — "body closed and `request` present · the request decodes under §16.1 and its `net` equals the entry's (`decode`) · the request's signature verifies … (`no-device-sig`) · valid `signer` count ≥ `signer_thr` (`threshold`) · `device_id` not currently `active` (`dup-id`) · `wg_pk` not in `active_wg` (`dup-wg`)".
Choice: exactly that order; the request's §16.1 field rules (incl. `expires > ts`) are part of "decodes under §16.1"; `net` checked after the request's own schema. Why: stated.

**C41** — §5.1 rotate row — order "body … (`decode`) · `device_id` known (`unknown-device`) · currently `active` (`not-active`) · valid `device` signature by the device's current `device_pk` (`no-device-sig`) · if `params.rotate_needs_signer`, signer count ≥ `signer_thr` (`threshold`) · new `wg_pk` not active for another device (`dup-wg`) · if the body carries `device_pk`, a valid `device` signature by that key as well (`no-device-sig`)".
Choice: exactly that order. Why: stated.

**C42** — §5.1 — "`since_index` records the index of the entry that last changed the device's status: `enroll` sets it, `revoke` sets it, `rotate` leaves it alone."
Choice: as stated. Re-enroll replaces the whole record (§5.3).

**C43** — §5.1 `params` row — "non-empty, only §4.5 keys, each of the right type (`decode`) · **merge**".
Choice: validate the whole map before applying any key (no partial write). Why: "A rejected entry … changes nothing else".

**C44** — §5.1 `root_remove` — "removing it leaves ≥ `root_thr` roots and ≥ 1 root (`root-invariant`)".
Choice: `len(roots) − 1 ≥ root_thr` (with `root_thr ≥ 1` implying ≥ 1). Why: stated.

**C45** — §5.1 `signer_add`, `root_add` — "`kid(pk)` not already a root or signer (`dup-key`)".
Choice: compare by `kid`, across both roles. Why: stated.

**C46** — §5.1 `policy` row — "`text` MUST parse as `c2sp.org/tlog-policy`, every verifier key it carries a valid point".
Choice: parse with the §9.1 grammar (C70–C83); no correspondence with the trust file; more than one `log` line allowed. Why: §9.1 `log` lines row.

**C47** — §5.3 — "`params` | map | §4.5 defaults, overlaid by `genesis.body.params`, then by each `params` entry".
Choice: state `params` always carries all five §4.5 keys including `routes`. Why: §4.5 lists a default for each.

**C48** — §5.3 — "`log_keys` | array of `{overlap, pk, since_index}`".
Choice: as stated, `pk` lowercase hex in JSON. `roots`/`signers` map kid → hex pk. `net` hex. Why: §14.1 byte strings.

**C49** — §5.3 — "`labels` | map string → string | `{}` when the enrolment carried none"; "`expires` | uint | `0` when the enrolment carried none".
Choice: as stated.

## Evaluation time and freshness (§5.3, §8.1, §15)

**C50** — §5.3 — "`T` is the quorum time … the newest instant such that the witnesses whose cosignature timestamp is at or after it satisfy the policy".
Choice: per listed witness take its newest verifying timestamp; candidate instants are those timestamps, tried newest first; `T` is the first candidate `t` for which the set {w : ts_w ≥ t} satisfies the policy. `quorum none` → no `T`. Why: the satisfying set only changes at a timestamp, so the maximum is attained at one.

**C51** — §5.3 — "The policy is the one under which this checkpoint was accepted: the trust policy for a first read, or the most recently replayed policy for a reader that already has one".
Choice: `T` uses the accepting policy, never the policy replayed from the same checkpoint. Why: stated.

**C52** — §5.3 — "A device is expired exactly when `expires != 0 && expires <= T`".
Choice: as stated; no `T` → no expiry judged.

**C53** — §8.1 — ladder "`unknown` … `hard_stale` … `fresh` … `degraded`", "the first row, read top to bottom".
Choice: unknown if no quorum time; hard_stale if `S_hard > 0 ∧ elapsed > S_hard`; fresh if `elapsed ≤ S`; else degraded. Why: stated.

**C54** — §15 — "The node's estimate of now is the largest of the lower bounds it holds … The age of a held checkpoint is this estimate minus that checkpoint's quorum time."
Choice: estimate = max over recorded pairs of `q + (now_mono − m)`; seeded value counts as a pair at monotonic 0. Why: stated.

## Notes, checkpoints, receipts (§6, §7, §10)

**C55** — §7 — "The signed text is everything up to and including the newline that ends the last text line … the first blank line ends the text".
Choice: split the note at the first `"\n\n"`; text = bytes through the first `\n` of that pair; the text must be non-empty. Why: stated.

**C56** — §7 — "Every signature line, including the last, ends in one `0x0A`—exactly one".
Choice: after the blank line, the remainder must be ≥ 1 lines, each non-empty and LF-terminated; an empty line there (extra LF) or a missing final LF is `note`. Why: stated.

**C57** — §7 — "A signature line is `— ` …, the key name, one space, then base64 of a payload … the line splits at its first space".
Choice: after the `"— "` prefix, split at the first space; the name must be non-empty; the payload must be non-empty, canonical padded standard base64 (decode then re-encode equals the text), ≥ 4 bytes. A payload containing a space is not base64 → `note`. Why: stated; "a name" read as non-empty.

**C58** — §7 — "The signed text and every signature line MUST be valid UTF-8."
Choice: the whole note must be valid UTF-8 (the separator line is ASCII), checked as framing → `note`. Why: stated.

**C59** — §7 — "Framing is every line's; length is the matched key's."
Choice: a line matches a trusted key when its name equals the key's name **and** its 4-byte key id equals the key's id. Log key (0x01): payload exactly 68, Ed25519 over the text. Witness (0x04): exactly 76, Ed25519 over `"cosignature/v1\ntime " ‖ decimal(ts) ‖ "\n" ‖ text`. Unmatched lines ignored. Why: stated.

**C60** — §7 — cosignature timestamp "an unsigned 64-bit big-endian count of seconds".
Choice: any uint64 accepted; the decimal is Go's `strconv.FormatUint`. Why: D-076's bound is stated for decimal *lines*, and the timestamp is binary.

**C61** — §6 — "the tree size in decimal with no leading zeroes and at most 2⁶³−1".
Choice: `0` is canonical; any other value must start with 1–9; digits only; ≤ 2⁶³−1. Root: padded standard base64, canonical, decodes to exactly 32 bytes. Exactly three text lines. Why: stated.

**C62** — §10/§10.1 — order `note` → `log-signature` → `checkpoint` → `origin` → `cosignature` → `quorum`.
Choice: as stated; `log-signature` requires ≥ 1 matching line and every matching line valid; `cosignature` requires every line matching a listed witness to verify. Why: stated.

**C63** — §9.4 — "A learned key is the verifier key `<origin>+<id>+base64(0x01 ‖ pk)`".
Choice: trusted log keys = trust `log_key` plus, for an informed reader, every `log_keys` pk of its accepted state, each named the origin with id recomputed under 0x01. Why: stated.

**C64** — §9.4 — "A `policy` entry supersedes `norn.trust.policy` for every checkpoint a node accepts after replaying it".
Choice: informed reader verifies with the state's `policy` text when non-empty, else the trust policy. Why: stated.

**C65** — §7 receipt steps 1–8.
Choice: exactly that order; step 2 identical to the checkpoint log-signature rule (every matching line must verify); step 3: exactly four text lines and line 1 = `norn/receipt/v1`; step 6 canonical decimal ≤ 2⁶³−1; step 8 `check_time ≠ 0 ∧ check_time ≥ deadline` → `expired`. Why: stated.

**C66** — §6 — the OTS digest "the three body lines plus the blank line, four `0x0A` in all".
Choice: SHA-256 of the checkpoint bytes through the first `"\n\n"` inclusive. Why: stated.

## Tiles (§6)

**C67** — §6 — "Tile height 8 (width 256) … level `L` covers 256^(L+1) leaves".
Choice: level-L hash i = Merkle root of leaves `[i·256^L, (i+1)·256^L)`; for size N, level L holds `N >> 8L` hashes split into full tiles of 256 and one partial tile of the remainder (if non-zero); levels continue while `N >> 8L > 0`. Entry bundles: `N/256` full and one partial of `N mod 256`. Every implied tile must be fetched and checked. Why: tlog-tiles as restated.

**C68** — §6 — "`<N>` is the tile's index written in three-digit groups … with every group but the last prefixed `x`".
Choice: as stated; partial suffix `.p/<W>`. Why: stated.

**C69** — §6 — "A partial bundle holds exactly the number of entries its path declares."
Choice: a bundle must parse into exactly W (256 for full) frames with no trailing bytes; otherwise `entries`. A zero-length frame is framed (replay decides). Why: stated.

## Policy grammar (§9.1)

**C70** — §9.1 — "fields are separated by ASCII spaces and tabs only".
Choice: split each line on runs of 0x20/0x09; bytes 0x80–0xFF are content; the grammar does not itself require UTF-8 (the CBOR layer does). Why: "Bytes 0x80–0xFF are content".

**C71** — §9.1 — "a line whose first character other than ASCII space or tab is `#` is ignored in its entirety".
Choice: as stated; control-byte rule applies to comments too.

**C72** — §9.1 — "A missing final line feed is an error whatever the last line holds".
Choice: empty text (zero lines) is not refused by this rule, but by "exactly one quorum line". Why: no line, no missing delimiter.

**C73** — §9.1 — "The only allowed ASCII control bytes are tab and line feed".
Choice: any byte in 0x00–0x08, 0x0B–0x1F, 0x7F anywhere → error.

**C74** — §9.1 — "each directive takes exactly the fields its production above allows".
Choice: `log` 1–2 args, `witness` 2–3, `group` ≥ 3 (name, threshold, ≥1 member), `quorum` exactly 1; unknown keyword → error. Why: stated.

**C75** — §9.1 — "Witness and group names share one namespace; each name is defined once … `none` is predefined, cannot be defined, and is invalid as a group member."
Choice: witness/group names are any field bytes (no extra charset rule); defining `none` → error; `all`/`any` may be names. Why: stated.

**C76** — §9.1 — "a `group` or `quorum` line names only what an earlier line defined".
Choice: resolve names sequentially; a later redefinition is an error (namespace rule). Why: stated.

**C77** — §9.1 — "Keys are compared by their parsed underlying public key … This applies across `log` and `witness` lines."
Choice: compare the 32-byte pk, regardless of algorithm byte. Why: stated.

**C78** — §9.1 — "`all` is `n`, `any` is 1, and a count is canonical decimal with `1 ≤ k ≤ n`".
Choice: canonical = no leading zero, digits only; n = number of members. Why: stated.

**C79** — §9.1 — "a `group` may name a `group`. It counts as one member".
Choice: recursive evaluation; a witness is met when it is in the cosigner set.

**C80** — §9.1 verifier key — "Split it on `+` at most twice … The key id is lowercase … A key name is one or more ASCII bytes from `0x21` to `0x7E`, `+` excluded … `alg ‖ pk` is 33 bytes, and 33 bytes encode to 44 base64 characters".
Choice: exactly 8 lowercase hex chars; data exactly 44 chars canonical standard base64 decoding to 33 bytes; alg ∈ {0x01, 0x04} (role-specific where used); recomputed id must match; pk a valid point. Why: stated.

**C81** — §9.1 — "`log` lines | not required, and more than one is allowed".
Choice: as stated.

**C82** — §9.1 — "`quorum` | exactly one line".
Choice: zero or two quorum lines → error.

**C83** — §9.1 — "`witness <name> <vkey> [<url>]`" … "Optional policy URLs … Norn does not validate their URI syntax".
Choice: URL field accepted as any field.

## Trust file (§9)

**C84** — §9.1 table.
Choice: closed map with `version`(=1), `net`(16B), `origin`, `name`(1–64B), `genesis_hash`(32B), `log_key`, `log_urls`(≥1, each non-empty text), `witnesses`(≥1 closed maps `{name,key,url?}`), `policy`, optional `anchor`. Unknown key → invalid.

**C85** — §9.1 — "`origin` | MUST equal `norn/` + lowercase unpadded RFC 4648 base32 of `net`".
Choice: byte equality with my derivation.

**C86** — §9.1 — "`log_key` … MUST parse as one, MUST NOT be a cosignature key, and its note name MUST equal `origin`".
Choice: alg 0x01, name == origin (exact), id recomputed, valid point.

**C87** — §9.1 — "a witness `name` is 1–64 bytes and unique within the file".
Choice: byte length; uniqueness by exact bytes; witness `key` alg 0x04, id recomputed, valid point; `url` text if present (empty allowed).

**C88** — §9.1 `policy` — "MUST name exactly the witnesses `witnesses` lists, with the same keys … compared as canonical text".
Choice: the set of policy witness names equals the set of `witnesses[].name`; for each name, policy vkey text == file key text; any `log` line text == `log_key` text (so at most one log line). Why: stated.

**C89** — §9.1 — "`anchor` | `{type, max_lag, mode}`, OPTIONAL … an unknown `type` is ignored … `mode` MUST be `"advisory"`".
Choice: closed map, all three required, `type` text (any), `max_lag` uint, `mode` == "advisory".

**C90** — §9.1 — "A file with no witnesses MUST be rejected".
Choice: `witnesses` must be present with ≥ 1 element.

**C91** — §9 — no rule makes a witness key distinct from the log key except the policy's `keys` row.
Choice: enforce distinctness only through the policy parse (which sees a log line only when present). Why: no other text states it.

**C92** — §9.3 — "The first 10 bytes of `SHA-256(CBOR(trust))` … Crockford base32 … four groups of four".
Choice: as stated; the fingerprint file is that string plus one LF.

## Bundles (§8.1)

**C93** — §8.1/§10.1 — bundle steps `bundle` → checkpoint codes → `inclusion` → `binding`.
Choice: `bundle` = oversize (> 81919), profile failure, not a closed six-key map, wrong types (`proof` elements exactly 32 bytes), `v` ≠ 1. Checkpoint verified per §10 steps 2–7 under the reader's keys and policy. `inclusion`: `index < size` and RFC 9162 §2.1.3.2 verification. `binding`: entry decodes as an entry and the named device_id equals `device` (enroll → request's device_id; rotate/revoke → body `device_id`; any other type, or undecodable → `binding`).

**C94** — §8.1 — "confirm `SHA-256(0x00 ‖ entry)` and `proof` reach that checkpoint's root at `index` for that size".
Choice: RFC 9162 inclusion verifier, which rejects surplus or missing path elements. Why: the RFC algorithm.

## Fork handling (§10, §11)

**C95** — §10 — "at := min(cp.size, stored_cp.size) … if served ≠ mine → FORK … if cp.size < stored_cp.size → refuse".
Choice: after `head` passes; `mine` = stored root when `at == stored.size`, else the root of the node's own branch at `at` if the node holds it; if it does not hold it, no fork judgment and the result is `rollback` (when shrinking). `at == 0` compares empty roots (equal). Why: stated.

**C96** — §10.1 — "`genesis` … reached only by a log that passes that comparison".
Choice: genesis check = replay entry 0 alone (or no entry 0) after the fork/rollback step and before `tiles`.

**C97** — §10.1 step 1 — "The same code for any file a later step needs and cannot fetch — an entry bundle (step 8), a hash tile (step 11) — reported at that step".
Choice: a missing hash tile is `unserved` at the **tiles** step (table step 12), i.e. after `genesis`. The parenthetical says "step 11", which the table assigns to `genesis`; I read it as the tiles step.

**C98** — §11.1 reader steps and codes 0–9.
Choice: `oversize` (> 65536) → `cbor` (profile or not a map) → `version` (absent/not uint/not 1 or 2) → `schema` (exact key set per version, types, 32-byte hashes) → `policy` (carried text parses) → `held` → `conflicting` (each per §10 steps 2–7 under the reader's own keys and policy) → `size` → `proof` → `consistent`.

**C99** — §11.1 step 3 — "`size` 0 never passes this step".
Choice: `size == 0` → `proof`. `size == held.size`: proof must be empty and `held_root == held.root`. Otherwise RFC 9162 §2.1.4.2 consistency verification of (size, held_root) → (held.size, held.root).

**C100** — §11.1 step 4 — "A `split` that is 0 carries an all-zero `split_root` and two empty proofs."
Choice: version 2: `split > size` → `proof`; split 0 with non-zero `split_root` or a non-empty proof → `proof`; split > 0 → each split proof checked as step 3 (empty and root-equality at a head's own size). All before `consistent`.

**C101** — §11.1 `held` row — "When the branch the accuser stored is the shorter one … that head is `held`".
Choice: a reader does not need to know which branch was stored; it checks the file as written.

## Requests (§16)

**C102** — §16.1 table.
Choice: closed map; required v(=1), ts, net(16), sig(64), wg_pk(32), device_id, device_pk(32, valid point); optional labels (non-empty), expires (uint > ts). Signature: NORN-ED25519 over `"norn/enroll-request/v1\n"` ‖ canonical CBOR of the map without `sig`.

**C103** — §16.2 — "A decoder MUST reject a payload whose padding is 5 bits or more, or whose padding bits are not zero."
Choice: convert 5→8 bits; leftover bits ≥ 5 or non-zero → refuse.

**C104** — §16.2 — "the separator being the last `1` … the printable-ASCII range".
Choice: BIP-350: chars 33–126; all-lower or all-upper; HRP exactly `norn` (case-folded only within an all-uppercase string); data part ≥ 6 chars; checksum constant 0x2bc830a3; no 90-char limit; decoded payload ≤ 65535.

**C105** — §16.2 text in `.txt` files.
Choice: the harness strips trailing ASCII whitespace from a `.txt` file before decoding (a file's final newline is file framing, not part of the bech32m string). Why: the spec does not define a file form.

## Canonical JSON (§14)

**C106** — §14.2 — "Exactly these characters are escaped, and no others".
Choice: `"`, `\`, `\b`, `\t`, `\n`, `\f`, `\r`, other C0 as `\u00xx` lowercase; everything else verbatim. Keys sorted bytewise over UTF-8.

## Grants and routes (§13.1)

**C107** — §13.1 — "kept only where it lies within a prefix of the peer's grant".
Choice: a provider prefix p is kept when some grant prefix g has the same family, `p.bits ≥ g.bits`, and p's masked address lies in g. Not vectored by any static artifact I expect; implemented for completeness.
