# Cold gate run 19 — decisions log

Written after reading `SPEC.md` in full and before opening
`testdata/vectors/README.md`, any manifest or any vector. Not edited afterwards;
later doubts go in `SPEC-DEFECTS-19.md`.

Each entry: section · the exact words · what I chose · why.

---

## Encoding profile (§4.0, §4.1)

**C01** · §4.0 Text strings row · "every **map key** is a text string of 1–23 bytes" ·
I apply the 1–23-byte text-key rule in the decoder to **every** map of **every** Norn
CBOR artifact (entries, requests and their `labels`, trust files, bundles, evidence),
not only to envelope/body keys. · The row is in the profile table, which §4.0 says
governs all Norn CBOR structures; §4.0's `labels` row also says "keys 1–23 bytes (the
map-key cap above — a longer key is unencodable)", which only makes sense if the cap
is profile-wide.

**C02** · §4.0 "The profile is an allow-list … Every other item is refused by the
decoder, before any schema looks at it" · My decoder refuses, in a single
left-to-right pass, at the **first** offending byte: major type 1, 6, any major-7
item other than `0xf4`/`0xf5`, additional-info 28–30 (not well-formed), 31
(indefinite), a non-shortest argument, an integer above 2⁶³−1, a declared length
longer than the remaining input, invalid UTF-8 in a text string, a non-text map key,
a map key outside 1–23 bytes, a map key not strictly greater (encoded form) than its
predecessor, a container beyond depth 8, and trailing bytes. · The spec says the
profile refuses all of these before any schema; where several apply to one input, it
does not order them, so I report the first one reached reading forward (header before
content, key type before key length before key order).

**C03** · §4.0 "Shortest form means every argument, not only integers" · Every head
argument (integer value, string/array/map length) must use the preferred
serialization: values 0–23 inline, 24–255 one byte, 256–65535 two, up to 2³²−1 four,
otherwise eight. · Stated explicitly.

**C04** · §4.0 "Integers | major type 0 only; shortest form; ≤ 2⁶³−1" · The 2⁶³−1
cap is applied to integer *values* (major type 0). A length argument above 2⁶³−1 can
never be satisfied by the input and is refused as truncation. · The row is about
integers; lengths are bounded by the input and the artifact caps anyway.

**C05** · §4.0 "Nesting depth is at most 8, counted in containers. The top-level map
is depth 1 … A scalar does not add depth" · A container (map or array, empty or not)
at depth 9 is refused; depth 8 is accepted. Scalars never count. The depth is checked
when the container's head is read, after the head's own well-formedness and
shortest-form checks. · Literal reading; "at most 8" makes 8 legal.

**C06** · §4.0 "`MAX_ENTRY_BYTES` is 65535 … refused on length, before anything it
declares is allocated" (and §8.1/§9.1/§11.1's own caps) · Each artifact's cap is
checked against the **input length** before decoding starts (entry/request 65535,
bundle 81919, trust 65536, evidence 65536). A header that declares more bytes than
remain in a short input is a truncation (well-formedness) fault, not a size fault. ·
§11.1 says so explicitly for evidence ("a short file whose CBOR declares more than it
holds is `cbor`, not `oversize`"); I apply the same reading to every artifact. For
entries both are `decode` anyway.

**C07** · §4.0 "Text strings | definite length; valid UTF-8" · Validity is RFC 3629
UTF-8: no overlong forms, no surrogate code points (U+D800–U+DFFF), nothing above
U+10FFFF (Go `utf8.Valid`). · Standard meaning of "valid UTF-8".

**C08** · §4.0 "the single bytes `0xf4` and `0xf5` … `0xf8` followed by any byte
below 32 … which RFC 8949 §3.3 makes not well-formed" · Every `0xf8 xx` is refused
(below 32 not well-formed, 32–255 forbidden simple values). `0xf6`, `0xf7`,
`0xe0`–`0xf3`, `0xf9`–`0xfb`, `0xfc`–`0xfe`, `0xff` are refused. · Allow-list.

**C09** · §4.1 "Map keys MUST be sorted … bytewise lexicographic order of their
encoded form" and "Keys are **strictly increasing**" · One comparison of encoded key
bytes, strictly greater than the previous key, refuses both disorder and duplicates,
in every map. · Stated.

**C10** · §4.0 "Booleans | valid CBOR items; schemas MUST reject them outside
`params.rotate_needs_signer`" · Booleans pass the decoder everywhere; every schema
field typed uint/text/bytes/map/array refuses a boolean, in entries, requests, trust
files, bundles and evidence. · Stated.

## Entry schema (§4.0 field table, §4.1, §4.3)

**C11** · §4.0 "`v`, `t`, `net`, `ts`, `body` and `sigs` are all **mandatory**;
`after` and `prev` are the only optional keys" and §5.1 step 3 "every member of the
type §4.1 gives it (`t` text, `ts`, `after` and `prev` uint, `body` a map), `v` = 1,
`net` = `anchor.net`, well-formed `sigs`" · Envelope check: exactly those keys; `v`
uint equal to 1; `t` text (any text — membership is step 4); `net` a 16-byte byte
string equal to `anchor.net`; `ts`, `after`, `prev` uint; `body` map; `sigs` array of
closed `{kid, role, sig}` maps, `kid` `^[0-9a-f]{16}$`, `role` ∈ {root, signer,
device}, `sig` exactly 64 bytes, strictly increasing by `kid` string. All → `decode`.
· Stated.

**C12** · §4.0 "`sigs` is an array of maps `{"kid","role","sig"}` sorted by `kid`
bytewise, with no repeated `kid`" · Sorting compares the `kid` text strings bytewise
(equivalently the hex strings lexicographically), strictly increasing. · "bytewise".

**C13** · §4.3 body table and §4.0 "Bodies are closed schemas too" · Body schemas:
`genesis` {name, roots, root_thr, signers, signer_thr, params?}; `enroll` {request:
bytes}; `rotate` {device_id, wg_pk, device_pk?}; `revoke` {device_id, reason?};
`signer_add`/`root_add` {pk}; `signer_remove`/`root_remove` {kid}; `signer_thr`/
`root_thr` {thr}; `params` = the §4.5 keys themselves (the body *is* the partial
params map); `note` {text}; `log_key` {pk, overlap}; `policy` {text}. Every `pk`,
`device_pk`, `wg_pk` is a 32-byte byte string. · Table plus "`params` is the one type
whose permitted keys are the §4.5 parameter names".

**C14** · §4.0 "Byte strings | fixed sizes where stated (`net` 16, `pk` 32, `sig` 64)"
· `wg_pk` (X25519) must be exactly 32 bytes and is otherwise unchecked (no point or
low-order check). · §3 says the WireGuard key never signs; no rule constrains its
value beyond being a 32-byte key.

**C15** · §3.1 item 2 "A key that is not is refused as `decode` at its entry type's
body step" · Point admission (§3.1 item 1) is part of the body step for `signer_add`,
`root_add` and `log_key` `pk`, a `rotate`'s incoming `device_pk`, every verifier key
in a `policy` entry's text (log and witness lines), and the request's `device_pk`
inside `enroll` (as part of "the request decodes under §16.1"); at entry 0, of every
`roots`/`signers` key (`bad-genesis`). · Stated.

**C16** · §4.0 field table "`name`, `reason` | UTF-8, 1–64 / 0–256 bytes" and
"`text` … ≤ 4096 bytes" · Byte lengths of the UTF-8 encoding, not characters; no
character-class restriction on these free texts (controls allowed; §14 escapes them).
· "bytes".

**C17** · §4.0 `labels` row · `labels` (only inside a request): a map of text→text,
1–32 pairs, keys 1–23 bytes, values 0–256 bytes; `{}` refused. · Stated.

**C18** · §4.0 "`device_id` | matches `^[a-z0-9][a-z0-9.-]{0,63}$` **as a whole**" ·
Implemented as a byte loop over the whole string (length 1–64, first byte
`[a-z0-9]`, rest `[a-z0-9.-]`), no regex engine. · Removes the `$`-before-newline
trap the spec describes.

## Replay (§5)

**C19** · §5.1 step 1 and the `content_hash` row · Two seen sets. `entry_hash` =
SHA-256(raw bytes) is checked and recorded first for every entry at index ≥ 1. The
`content_hash` comparison is made only for an entry that decodes (step 2) **and**
passes the envelope check (step 3); I place it immediately after step 3 and before
step 4, still reported as `dup-entry`. `content_hash` = SHA-256 of the preimage,
built by canonically re-encoding the decoded envelope without `sigs`. It is
recorded only when an entry is accepted (every accepted type, `note` included); entry
0's is recorded when genesis applies. · "the hash is the one of an entry steps 2 and
3 accept"; an entry whose envelope fails cannot be "decodable" in the sense needed to
have a content key, and a duplicate must precede `dup-genesis` (entry-0 content
copies) — the earliest point where the hash exists is right after step 3.

**C20** · §5.1 entry 0 steps 1–8 · Entry 0 is checked in the written order; any
failure aborts with `{index 0, bad-genesis}`, `size` 0 and the zero state (`net` from
the anchor, §4.5 default params). Step 6 checks `name` 1–64 bytes, `roots`/`signers`
non-empty arrays of distinct 32-byte valid-point keys, disjoint, thresholds
1…len, `params` (if present) non-empty with only §4.5 keys of the right type and a
closed `routes` value; step 7 counts signatures with `role` "root" whose `kid`
resolves to a key in the body's `roots`, verified under NORN-ED25519-v1. · Stated;
order unobservable (§12.1).

**C21** · §5.1 steps 4–7 and the per-type table · Order for index ≥ 1: byte-dup →
decode → envelope → content-dup → unknown-type → dup-genesis → after → step 7 (root
quorum for the nine governance types; ≥ 1 valid signer-or-root signature for `note`)
→ the type's own list in written order. `enroll`, `rotate`, `revoke` have no step-7
check. · Stated as normative order.

**C22** · §5.2 "Signature counting, precisely" · A `sigs` element is valid iff its
declared `role` and `kid` resolve to a key in that role in the state before the entry
(root → `roots[kid]`, signer → `signers[kid]`, device → the named device's
key(s) — see C23/C24) and the signature verifies over the preimage under
NORN-ED25519-v1. Invalid or unresolvable elements are ignored. Counts are per role and
never pooled. · Stated.

**C23** · §4.3 / §5.2 device signature resolution · `rotate`: a device element is
valid for the current key iff `kid` = kid(current `device_pk`) and it verifies under
it; for the incoming key iff `kid` = kid(incoming) and it verifies under it; one
element serves both when the keys are equal. `revoke`: kid(current `device_pk`) of
the named device. `enroll`: a device element on the envelope counts for nothing —
consent is the request's own `sig`. Governance and `note`: device elements count for
nothing. · Stated in §4.3/§5.2.

**C24** · §4.3 `revoke` "≥ `signer_thr` signers, **or** the device itself, **or** ≥
`root_thr` roots" · Authorised iff valid signer count ≥ `signer_thr`, or valid root
count ≥ `root_thr`, or ≥ 1 valid device signature by the named device's current key;
else `threshold`. · Stated; counts not pooled.

**C25** · §4.4 / §5.1 `prev` · Device objects: a record exists iff the `device_id`
is a key of `devices` (created by an accepted `enroll`, kept on revoke); `enroll`
requires `prev` absent when no record exists, else present and equal to the record's
`version`; `rotate`/`revoke` require it present and equal. Governance types require
`prev` present and equal to the relevant `versions` member (0 after genesis). `note`
with `prev` → `decode` at its third check; genesis with `prev` → `bad-genesis`. ·
Stated.

**C26** · §5.1 `rotate` "new `wg_pk` not active **for another device** (`dup-wg`)" ·
`dup-wg` iff `active_wg[wg_pk]` exists and is not this `device_id`. Effect: remove
the old `wg_pk` from `active_wg`, add the new one, replace `device_pk` if present,
`version` = index, `since_index` unchanged. · Stated.

**C27** · §5.1 `enroll` "`wg_pk` not in `active_wg` (`dup-wg`)" · Any active device,
including the same id (unreachable because `dup-id` precedes). Effect: the record is
replaced wholesale (`labels` `{}` and `expires` 0 when absent from the request),
`status` active, `since_index` = `version` = index. · Stated.

**C28** · §5.1 `root_remove` "removing it leaves ≥ `root_thr` roots and ≥ 1 root" ·
`root-invariant` iff `len(roots) − 1 < root_thr` (or < 1). · Stated.

**C29** · §5.1 `signer_thr`, `root_thr` "`1 ≤ thr ≤ len(set)`" · `len(set)` is the
current size of the signer set (for `signer_thr`) or root set (for `root_thr`) in the
state before the entry. · Natural reading.

**C30** · §5.1 `log_key` "`pk` is not the public key of any witness the policy in
force names — `policy` when it is non-empty, else `anchor.policy`" · "Policy in
force" = `state.policy` if it is a non-empty string, else `anchor.policy`; parse it
and compare `pk` with the public keys of its **witness** lines only (not `log`
lines). If `anchor.policy` cannot be parsed (never for a valid trust file), its
witness set is taken as empty. · "witness the policy … names"; §9.1's invariant is
log-vs-witness disjointness.

**C31** · §5.1 `log_key` "`pk` is not an active log key — `anchor.log_key` or any
`pk` in `log_keys`" · `anchor.log_key` is parsed as a verifier key and its 32-byte
public key compared; `log_keys` pks compared bytewise. · Stated "compared as
public-key bytes".

**C32** · §5.1 `policy` · Checks: `text` ≤ 4096 bytes; parses under the §9.1 grammar
with every key a valid point (log and witness lines); `prev`; no **witness** line's
public key equals an active log key (anchor's or learned). The trust-file-only rules
(log line must equal `norn.trust.log_key`, correspondence with `witnesses`) do **not**
apply to a `policy` entry; several `log` lines are allowed. · §9.1 `log` lines row:
"That limit is the trust file's, not the grammar's".

**C33** · §5.1 `params` "non-empty, only §4.5 keys, each of the right type" ·
`checkpoint_interval`, `staleness`, `mmd` uint (any value, 0 included);
`rotate_needs_signer` boolean; `routes` text ∈ {"granted","advisory"}. Merge
overwrites only the keys present. · No ranges are stated.

**C34** · §5.1 `note` · Accepted `note` changes nothing but its `content_hash` is
recorded (it is "applied" in the D-078 sense). · §12.1 log-republish row says the
signed note "applies".

**C35** · §5.3 canonical state · JSON field set exactly as the table; `roots`/
`signers` map kid→hex pk; `active_wg` map **hex(wg_pk)** → device_id; `log_keys`
array of `{overlap, pk (hex), since_index}` in log order; `params` all five keys;
`versions` five keys; device record seven keys. Empty log → zero state with `size` 0
and `rejected` []. · §14.1 "byte strings | lowercase hex", applied to map keys that
are byte strings as well.

## Ed25519 (§3.1)

**C36** · §3.1 item 1 "A valid point" · Implemented from RFC 8032 §5.1.3: y < p,
x recovered, x=0 with sign 1 refused, on-curve, then `[L]P = O` and `P ≠ O` computed
with my own extended-coordinate arithmetic. · Stated; libraries differ.

**C37** · §3.1 item 3 · A signature verifies iff `A` and `R` are valid points, `S` <
L (not reduced), and `[S]B = R + [k]A` with k = SHA-512(R‖A‖M) mod L
(cofactorless). · Stated as the definition.

**C38** · §3.1 item 2 list of admission points · Point admission is applied to: genesis
roots/signers, `root_add`/`signer_add`/`log_key` pk, rotate's incoming `device_pk`,
every verifier key in policy text (policy entries, trust policy, evidence's carried
policy, `policies/*.txt`), a request's `device_pk`, the trust file's `log_key` and
witness keys. · Stated ("a policy parses one way everywhere").

## Grants (§4.0)

**C39** · §4.0 "once U+0020 is removed from both of its ends and nothing else is" ·
Each comma-separated part has **all** leading and trailing U+0020 stripped (runs, not
one). No other character is trimmed. · "removed from both of its ends".

**C40** · §4.0 "a label that is absent or does not parse **as a whole** is **no
grant**" · An empty label value, an empty part (",," or a trailing comma), or any
unparseable part makes the whole label no grant. · Whole-label rule.

**C41** · §4.0 "An IPv4-mapped IPv6 prefix is no grant either" and §12.1 "IPv4-mapped
addresses before masking" · A part whose IPv6 address (as written, before masking)
has 80 zero bits followed by 16 one bits is no grant, whatever its prefix length and
whether written with a dotted quad or hex. IPv4-compatible (`::a.b.c.d`) is not
mapped and is rendered in hex. · The §12.1 table phrase.

**C42** · §4.0 "four decimal octets 0–255, none with a leading zero" · Each octet
1–3 digits, value ≤ 255, no leading zero (except "0" itself); the same rule inside an
embedded dotted quad. · Stated.

**C43** · §4.0 "groups of one to four hexadecimal digits in either case, at most one
`::`, a dotted quad allowed in place of the last 32 bits, and no zone" · `::` must
stand for at least one zero group (seven explicit groups + `::` is fine, eight is
not); without `::` exactly eight groups (or six + dotted quad); a lone leading or
trailing `:` is invalid. · RFC 4291 §2.2 and §12.1's "compression consumes at least
one group".

**C44** · §4.0 "the IPv6 address in RFC 5952 form" · Lowercase, leading zeros
suppressed, the longest run of ≥ 2 zero groups compressed to `::`, first run on a
tie, a single zero group not compressed, never a dotted quad. Masked to the prefix
length before rendering; parts deduplicated on the canonical text; sorted bytewise
as text across families. · RFC 5952 §4.2.

## Signed notes (§7), checkpoints (§6)

**C45** · §7 "the **first** blank line ends the text" · The note is split at the
first occurrence of "\n\n": text = bytes up to and including the first of those LFs;
the signature block follows the second. A note beginning with "\n" has an empty first
text line → `note`. No "\n\n" anywhere → `note`. · Stated.

**C46** · §7 "Every signature line, including the last, ends in one `0x0A`—exactly
one" · The block must be non-empty, end in LF, and contain no empty line. · Stated.

**C47** · §7 UTF-8/control rule · Before any key is looked at, the **whole note**
must be valid UTF-8 and contain no byte < 0x20 other than LF (CR included). DEL
(0x7F) is allowed in notes. · "below U+0020"; DEL is not below.

**C48** · §7 signature line grammar · Prefix exactly U+2014 U+0020; the name runs to
the first U+0020; it must be non-empty, contain no `+` and none of the listed
white-space code points; everything after that space is the payload, which must be
canonical padded standard base64 (length a multiple of 4, re-encoding reproduces it)
decoding to ≥ 4 bytes. A line with no space after the prefix does not frame. · Stated.

**C49** · §7 "Framing is every line's; length is the matched key's" · A line matches
a trusted key iff its name equals the key's name byte-for-byte and its first 4
payload bytes equal the key's id. Unmatched lines are ignored whatever their length.
A matched log line must be exactly 68 bytes and verify over the text; a matched
witness line exactly 76 bytes, timestamp ≤ 2⁶³−1 (checked before the signature), and
verify over "cosignature/v1\ntime <decimal>\n" ‖ text. · Stated.

**C50** · §10.1 step 3 · `log-signature` iff no line matches a trusted log key, or
any matching line fails (length or signature). Trusted log keys = trust `log_key`
plus, for an informed reader, every `log_keys` pk as `<origin>+<id>+b64(0x01‖pk)`,
id computed under the origin name. · Stated (§9.4).

**C51** · §6 checkpoint body · Exactly three text lines: origin (any non-empty
text, compared at step 5), size (ASCII digits, no leading zero unless exactly "0",
≤ 2⁶³−1), root (canonical padded base64 of exactly 32 bytes: 44 characters). Size 0
is legal; its root is SHA-256 of the empty string (RFC 6962 MTH of no leaves). · §6;
`detect/empty` described as a cosigned head over no entries.

**C52** · §10.1 steps 6–7 · Listed witnesses = the **witness lines of the policy in
force** (trust policy for a fresh reader; replayed `state.policy` when non-empty for
an informed reader), matched by the vkey's own name and id. Every matching line must
verify; quorum is evaluated over the short names of witnesses with ≥ 1 verifying
line. `quorum none` is satisfied by the empty set. · Stated.

**C53** · §5.3 `T` · T = the largest timestamp t among listed witnesses' newest
verifying lines such that {w : ts_w ≥ t} satisfies the policy; none → no clock;
`quorum none` → no clock. Expired iff `expires != 0 && expires <= T`. · Stated.

**C54** · §5.3 "a reader that holds that tree head keeps the policy and the `T` it
accepted it under, and reading it again … changes neither (D-082 (1))" · When a
candidate's (origin, size, root) equals the held head, I verify the candidate's note
under the policy (and keys) the held head was accepted under and report the held T;
a larger or different head faces the current (replayed) policy. · Literal reading.

## Tiles, the verifier loop (§6, §10)

**C55** · §6 tiles · A level-L tile N holds the hashes of tree nodes at height 8L
covering leaves [N·256^(L+1), …); for size n there are ⌊n/256^(L+1)⌋ full level-L
tiles and a partial of width ⌊n/256^L⌋ mod 256 when non-zero, for every L with
⌊n/256^L⌋ ≥ 1. "Every served hash tile" = every tile that tree size implies, all
levels; each is fetched (partial path first, full path as fallback) and compared byte
for byte. · tlog-tiles, restated in §6.

**C56** · §6 / §10.1 fallback · Only a **missing** partial falls back to the full
path. A served partial that is malformed is judged as served (`tiles` / `entries`).
A full file standing in must be exactly 8192 bytes / exactly 256 frames, else `tiles`
/ `entries`; then its first W hashes/entries are used. Missing both → `unserved`. ·
§6 "a verifier that cannot fetch … MUST fetch"; §12.1 run 18 L9 row.

**C57** · §10.1 step 8 · Every bundle the size implies is fetched (missing →
`unserved`) and framed; any truncated frame, extra bytes, or frame count ≠ declared
width → `entries`. A zero-length frame frames. · Stated.

**C58** · §10.1 step 10 · With a stored head: at = min(sizes); served root at `at`
recomputed from the served entries; mine = stored root if at = stored size, else the
root of the node's own branch at `at` from its own entries. If the node lacks its own
entries at `at`, no comparison is made (no accusation) and the size rule applies.
Differ → `fork`; else candidate smaller → `rollback`; equal size and root, or larger
and agreeing → continue. · Stated.

**C59** · §10.1 step 11 · `genesis` iff the served log has size 0 or replaying entry 0
alone under the anchor aborts (`bad-genesis`). · Stated.

**C60** · §10 replay and proven set · After step 12, state = replay(anchor,
entries[0:size]); proven = active devices not expired at T (no clock → none expire).
· Stated.

## Receipts (§7)

**C61** · §7 "Checking a receipt" · Steps in the given order with the given codes.
Step 3: exactly four text lines and line 1 = `norn/receipt/v1` → else `receipt`.
Step 5: canonical padded base64, 32 bytes. Step 6: canonical decimal (digits, no
leading zero except "0", no sign) ≤ 2⁶³−1. Step 8: refuse iff now ≠ 0 and now ≥
deadline. · Stated.

## Bundles (§8.1, §10.1)

**C62** · §8.1 / §10.1 bundle steps · Order: input length > 81919 → `bundle`; profile
decode (limit 81919) → `bundle`; closed six-key map, `v` = 1, `device` text in §2
grammar, `index` uint, `entry` bytes ≤ 65535, `proof` array of 32-byte strings,
`checkpoint` text → `bundle`; checkpoint loop steps 2–7; inclusion (index < size,
RFC 9162 §2.1.3.2 with exact consumption) → `inclusion`; binding → `binding`. ·
Stated.

**C63** · §8.1 binding "Binding is structural" · The entry must decode under the
profile (limit 65535) and pass the envelope's closed key set and member types (`v`
= 1, text `t`, 16-byte `net`, uint `ts`, uint `after`/`prev` when present, map
`body`, well-formed `sigs`) — `net` is **not** compared with the anchor. Then:
`enroll` → `body.request` must be a byte string that decodes under §16.1's structure
and field rules including point admission (not its signature, not its `net`), and its
`device_id` is the named id; other body keys are ignored. `rotate`/`revoke` →
`body.device_id` must be text, and is the named id; other body keys ignored. Any
other `t` names no device. Named id ≠ label → `binding`. · Stated with the D-082 (4)
positives.

## Trust file (§9)

**C64** · §9.1 · Valid iff: length ≤ 65536; profile decode; closed map {version,
net, origin, name, genesis_hash, log_key, log_urls, witnesses, policy, anchor?};
version = 1; net 16 bytes; origin text equal to the derived origin exactly; name
text 1–64 bytes (no grammar); genesis_hash 32 bytes; log_key text parsing as a
verifier key with alg 0x01, valid point, declared id = recomputed id, name = origin;
log_urls array, ≥ 1, each non-empty text; witnesses array ≥ 1 of closed maps {name,
key, url?}, name 1–64 bytes of the key-name grammar, unique, key a 0x04 verifier key
(valid point, id recomputed), url text (may be empty); no witness pk equal to log_key
pk; policy parses (general grammar, point admission) and its witness-line name set
equals the witnesses name set, each vkey text equal to that witness's key text, and
every log line's vkey text equal to log_key's text; anchor, if present, a closed map
{type text (any value), max_lag uint, mode text = "advisory"}. · Stated.

**C65** · §9.3 fingerprint · First 10 bytes of SHA-256(file bytes) in Crockford
base32 MSB-first, 16 characters in groups of four joined by "-", file = that + LF. ·
Stated.

## Policy grammar (§9.1)

**C66** · §9.1 rule table · Parse: whole text must end in LF; every byte in
0x00–0x08, 0x0B–0x1F, 0x7F is an error anywhere; lines split at LF; a line of only
spaces/tabs is ignored; a line whose first non-space/tab character is `#` is ignored;
fields are maximal runs of non-space/tab bytes. Keywords exactly `log`, `witness`,
`group`, `quorum`; any other first field is an error. · Stated; an unknown directive
is not one of the four and the grammar is closed.

**C67** · §9.1 field counts and names · `log` 1–2 fields, `witness` 2–3, `group` ≥ 3,
`quorum` exactly 1. Witness/group names: 1–64 bytes of 0x21–0x7E without `+`; one
namespace; defined once; `none` not definable. URLs: any field, unvalidated. ·
Stated.

**C68** · §9.1 vkeys · `<name>+<8 lowercase hex>+<44-char canonical base64 of 33
bytes>`, split on the first two `+`; name of 0x21–0x7E without `+` (no length cap
beyond ≥ 1); alg 0x01 on `log` lines, 0x04 on `witness` lines; pk a valid point;
declared id = SHA-256(name‖0x0A‖alg‖pk)[0:4]. Duplicate public keys across all lines
are an error. · Stated.

**C69** · §9.1 groups · Threshold `all` = n, `any` = 1, else canonical decimal (no
leading zero, ASCII digits) with 1 ≤ k ≤ n; members previously defined, no
duplicates, not `none`. Quorum: exactly one line naming a previously defined witness
or group, or `none`. Evaluation is recursive; a nested group counts as one member. ·
Stated.

## Evidence (§11.1)

**C70** · §11.1 reader steps · oversize (> 65536) → cbor (profile decode, top level
must be a map) → version (`version` absent, not uint, or ∉ {1, 2}) → schema (exact
key set for the version; types; 32-byte roots and proof hashes) → policy (general
grammar with point admission; trust-file-only rules not applied; no 4096 cap) → held
(§10 steps 2–7 under the reader's keys and policy) → conflicting → size (size >
held.size, or conflicting.size ≠ size) → proof → consistent → fork proven. · Stated.

**C71** · §11.1 `proof` step · size 0 → `proof`. size = held.size → proof must be
empty and held_root = held.root. Else RFC 9162 §2.1.4.2 from (size, held_root) to
(held.size, held.root), exact consumption. v2: split > size → `proof`; split 0 →
split_root all zero and both split proofs empty; else for each head h ∈ {held,
conflicting}: split = h.size → that split proof empty and split_root = h.root;
otherwise the RFC 9162 consistency proof from (split, split_root) to h. All before
`consistent`. · Stated, with "the same empty-proof rule at a head's own size".

## Requests (§16)

**C72** · §16.1 · Profile decode (limit 65535, depth restarts); closed map; required
v (=1), ts, net (16), sig (64), wg_pk (32), device_id (§2), device_pk (32, valid
point); optional labels (C17), expires (uint > ts). Signature over
"norn/enroll-request/v1\n" ‖ CBOR(request without sig) under NORN-ED25519-v1. A
consumer additionally refuses another network's request. · Stated.

**C73** · §16.2 bech32m · Separator is the last `1`; HRP non-empty and equal to
`norn` after case folding; every character 33–126; all lowercase or all uppercase
(mixed refused); data characters in the BIP-173 charset; ≥ 6 data characters;
checksum constant 0x2bc830a3 (bech32's 1 refused); 5→8 regrouping with < 5 padding
bits, all zero; no 90-character limit; decoded payload ≤ 65535 bytes. · BIP-350 plus
§16.2's narrowings.

## Freshness (§8.1, §15)

**C74** · §8.1 ladder · First row that holds: `unknown` (no quorum time) →
`hard_stale` (S_hard > 0 and elapsed > S_hard) → `fresh` (elapsed ≤ S) →
`degraded`. S_hard = 0 means unconfigured. · Stated.

**C75** · §15 age · Estimate of now = max over recorded pairs (q_i + (m_now − m_i));
age of a held checkpoint = estimate − its quorum time (never negative). · Stated.

## Canonical JSON (§14)

**C76** · §14 · No whitespace; object keys sorted bytewise on UTF-8; byte strings
lowercase hex; integers plain decimal; exactly the §14.2 escapes with `\u00xx`
lowercase; everything else verbatim (no `/`, HTML or non-ASCII escaping); one final
LF. · Stated.

## Merkle (§6, RFC 6962/9162)

**C77** · §6 / RFC 6962 §2.1 · Leaf H(0x00‖d), node H(0x01‖l‖r), split at the largest
power of two below n; empty tree SHA-256(""). Inclusion and consistency verified with
RFC 9162 §2.1.3.2 / §2.1.4.2 verbatim, refusing any surplus or missing hash. ·
Referenced standards.
