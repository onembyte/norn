# Cold gate run 22 — decisions log

Written after reading SPEC.md in full and before opening `testdata/vectors/README.md`,
any manifest or any vector. Not edited afterwards; later doubts go in the report.

Each entry: section, the exact words, what I chose, why.

## Cryptography (§1, §3.1)

C01 §3.1 item 1 — "32 bytes that are the canonical encoding (RFC 8032 §5.1.3) of a point of
order exactly `L` ... `[L]P = O` and `P ≠ O`". Chose: decode strictly (y < p, x recovered
by RFC 8032 §5.1.3, reject x = 0 with sign bit 1, reject non-square), then compute `[L]P`
and require the identity, and require `P ≠ O`. Both canonical clauses and the order clause
are implemented separately even though the text says the canonical clauses are implied.
Why: the text names all three; implementing all three can only refuse what the predicate
refuses.

C02 §3.1 item 3 — "`S` ... MUST be less than `L` — below `L`, not merely with its top bits
clear, and not reduced by the verifier". Chose: refuse any S ≥ L before any group
arithmetic. Why: literal.

C03 §3.1 item 3 — "the cofactorless one, RFC 8032 §5.1.7's second form, is the definition".
Chose: with A and R valid points (C01), check `[S]B = R + [k]A` cofactorless, k =
SHA-512(R ‖ A ‖ M) mod L, where R and A are the 32 bytes as received. Implementation: my own
validity check on A and R, then the standard library's `crypto/ed25519.Verify` (which
rejects S ≥ L and compares the canonical encoding of `[S]B − [k]A` with R). Because R is
canonical, byte equality is point equality. Why: the spec says "a verifier may compute
either" equation once A and R have order L.

C04 §3.1 item 2 — "every key that enters a verifier's state is a valid point where it
enters". Chose: point admission at genesis roots/signers, root_add, signer_add, log_key,
rotate incoming device_pk, every verifier key a policy (entry, trust file, evidence) carries
— log and witness lines alike — a request's device_pk, a trust file's log_key and witness
keys. Not applied to `wg_pk` (X25519, §3). Why: the list in item 2; wg_pk is never a
signing key.

C05 §1 — "Key ID `kid(pk)` = first 8 bytes of `H(pk)`, lowercase hex". §7 — "`key_id` =
`SHA-256(name ‖ 0x0A ‖ alg ‖ pk)[0:4]`". Chose exactly those two, independent.

## CBOR profile (§4.0)

C06 §4.0 — "The profile is an allow-list". Chose: decoder accepts only major types 0, 2, 3,
4, 5 and the single bytes 0xf4/0xf5; everything else (major 1, 6, 0xf4/0xf5 excepted major
7, any additional-info 31 indefinite, reserved additional info 28–30) is refused by the
decoder before any schema. 0xf8 xx is refused whatever xx is.

C07 §4.0 — "Shortest form means every argument, not only integers". Chose: every head
(integer value, byte/text/array/map length) must use the shortest encoding: values < 24 in
the initial byte, 0x18 only for 24–255, 0x19 only for 256–65535, 0x1a only for up to
2³²−1, 0x1b only above that.

C08 §4.0 — "Integers ... ≤ 2⁶³−1". Chose: any major-0 value above 2⁶³−1 is refused by the
decoder (not only by schemas).

C09 §4.0 — "Text strings | ... valid UTF-8". Chose: Go's `utf8.Valid` (rejects surrogate
encodings ED A0..ED BF, overlongs, > U+10FFFF). Applies to every text string, keys and
values.

C10 §4.0 — "every **map key** is a text string of 1–23 bytes". Chose: applies to every map
in every Norn CBOR artifact (entries, bodies, labels, requests, trust files, bundles,
evidence). A non-text key, an empty key or a key over 23 bytes is a decoder refusal.

C11 §4.0/§4.1 — "keys **strictly increasing** in §4.1's order". Chose: compare encoded
key items (header + bytes) bytewise; each must be strictly greater than the previous. Since
all keys are ≤ 23 bytes this is length-first, then bytewise.

C12 §4.0 — "A decoder MUST consume the **whole** input". Chose: trailing bytes after the
top-level item are a decoder refusal.

C13 §4.0 — "Nesting depth is at most 8, counted in containers. The top-level map is depth
1". Chose: entering a map/array at depth 9 is refused; scalars do not add depth; an embedded
request (byte string) is decoded by a separate call restarting at depth 1.

C14 §4.0 — "`MAX_ENTRY_BYTES` is 65535 ... A bundle larger than [81919] MUST be refused on
length ... `MAX_TRUST_BYTES` is 65536 ... `MAX_EVIDENCE_BYTES` is 65536". Chose: the decoder
takes the artifact's own cap and refuses an input whose length exceeds it before parsing.
Inclusive caps (= cap accepted). Request cap = 65535 (applied to the decoded request bytes).
In addition, any declared string/array/map length that exceeds the bytes remaining is refused
before allocation (a truncation, not an "oversize").

C15 §4.0 — "Booleans | valid CBOR items; schemas MUST reject them outside
`params.rotate_needs_signer`". Chose: decoder admits booleans; every schema that expects a
uint/text/bytes refuses a boolean as a type fault (entries: `decode`; evidence: `version` or
`schema` per §11.1; bundle: `bundle`; trust: invalid).

## Entries, envelope, bodies (§4.0–§4.5)

C16 §4.0 — "`entry_hash` | SHA-256 of the entry **as received**". "`content_hash` | SHA-256
of the signature preimage". "signature preimage | the 14-byte prefix `norn/entry/v1\n` ...
then the envelope encoded **without** the `sigs` key". Chose: preimage = prefix ‖ canonical
re-encoding of the decoded envelope map minus `sigs` (identical to slicing, since only
canonical input is admitted).

C17 §4.1 — envelope keys `v, t, net, ts, after, prev, body, sigs`; "`v`, `t`, `net`, `ts`,
`body` and `sigs` are all mandatory; `after` and `prev` are the only optional keys". Chose:
closed set; types v uint (=1), t text, net bytes of length 16 (and = anchor.net), ts uint,
after uint, prev uint, body map, sigs array. Any failure is `decode` (step 3).

C18 §4.0 — "Well-formed `sigs`" = "closedness, `kid` matching its field constraint, `role`
within the enum, `sig` exactly 64 bytes, and the array sorted by `kid` with no repeats".
Chose: each element a map with exactly kid (text, `^[0-9a-f]{16}$`), role (text ∈ {root,
signer, device}), sig (bytes, 64); kids strictly increasing as byte strings.

C19 §4.0 field table — `device_id` "matches `^[a-z0-9][a-z0-9.-]{0,63}$` as a whole".
Chose: hand-written byte check over the whole string (no regex engine), 1–64 bytes.

C20 §4.0 — "`name`, `reason` | UTF-8, 1–64 / 0–256 bytes"; "`text` ... ≤ 4096 bytes".
Chose: byte lengths, never characters. `reason` optional, absent = "". `text` required
(present, possibly empty).

C21 §4.0 — `labels`: "≤ 32 entries; keys 1–23 bytes; values ≤ 256 bytes, the empty value
included; ... `labels: {}` is refused". Chose exactly that; values must be text.

C22 §4.0 reserved labels `ip`, `endpoint` — "opaque text: their hint syntax MUST NOT be
validated". Chose: replay and request checking never parse them; only the grant function
(C61) parses `ip`.

C23 §4.3 bodies, closed: genesis {name, roots, root_thr, signers, signer_thr, params?};
enroll {request: bytes}; rotate {device_id, wg_pk: bytes32, device_pk?: bytes32};
revoke {device_id, reason?}; signer_add/root_add {pk: bytes32}; signer_remove/root_remove
{kid}; signer_thr/root_thr {thr: uint}; params = the partial §4.5 map itself (the body *is*
the map, not wrapped); note {text}; log_key {pk: bytes32, overlap: uint}; policy {text}.
Chose these readings; `wg_pk` is any 32 bytes (no curve check).

C24 §4.5 — params keys and types: checkpoint_interval/staleness/mmd uint (zero allowed, no
floor stated), rotate_needs_signer bool, routes text ∈ {"granted","advisory"}. Chose:
a params map must be non-empty, only those keys, each of its type; wrong value set for
routes is `decode` (`bad-genesis` at entry 0).

C25 §4.3 — "Signature counting: a key contributes at most once; a key counts only for the
role it currently holds". §5.2 — "a signature `{kid, role, sig}` is *valid* iff `kid` names
a key this entry may be signed by **in that role**". Chose: for role root/signer, look up
`kid` in that role's map of the state before the entry; for role device, the kid must equal
`kid(pk)` of the device key(s) this entry may carry (enroll: none in the envelope — envelope
device signatures never count; rotate: current and incoming; revoke: current); then verify
under NORN-ED25519-v1; count distinct keys.

C26 §4.3 `revoke` — "≥ `signer_thr` signers, **or** the device itself, **or** ≥ `root_thr`
roots". Chose: three independent tests, never pooled.

C27 §4.3 `rotate` — "one valid signature for each *distinct* key among the two". Chose: if
incoming device_pk equals the current key, the current-key check satisfies the incoming
check.

C28 §4.3 `note` — "any 1 signer or root". Chose: at least one valid signer-role or root-role
signature (step 7).

## Replay (§4.4, §5)

C29 §5.1 entry 0 — steps 1–8, all `bad-genesis`. Chose that order: decode → envelope
(including net = anchor.net, v = 1, well-formed sigs) → t = genesis → leaf hash pin → after
0/prev absent → body (name 1–64, roots/signers distinct valid 32-byte points, disjoint, no
kid collisions, thresholds in range, params rules) → bootstrap quorum counted against the
body's roots only (role root) → initialise. Entry 0's entry_hash joins the byte set; on
success its content_hash joins the content set.

C30 §5.1 step 1 — "An entry whose `entry_hash` is in the first set, or that decodes and
whose `content_hash` is in the second → reject (`dup-entry`)" and "the hash is the one of an
entry steps 2 and 3 accept". Chose: (a) byte set test before decoding; add entry_hash to the
byte set unconditionally; (b) after steps 2 and 3 pass, test content_hash against the
applied-content set and answer `dup-entry` there, before step 4; (c) add content_hash only
when step 8 applies the entry.

C31 §5.1 step 3 — "The types are this step's". Chose: envelope type faults are `decode` even
for under-signed governance entries.

C32 §5.1 steps 4–7 order: unknown-type, dup-genesis, after (after > index), then step 7's
governance root quorum / note signer-or-root rule; enroll/rotate/revoke signature checks live
in step 8 after their own body checks.

C33 §5.1 type table — I implement every rule's checks in the order written, with codes as
written, including: enroll body → request decode + request net = entry net (`decode`) →
request signature (`no-device-sig`) → signer count (`threshold`) → prev (`stale-state`) →
dup-id → dup-wg; rotate body (+ incoming point) → unknown-device → not-active → current
device sig → signer threshold if rotate_needs_signer → prev → dup-wg (another device) →
incoming-key sig; revoke body → unknown-device → not-active → authorisation → prev;
signer_add/root_add body (+ point) → prev → dup-key (kid in either role); signer_remove body
→ prev → unknown-key; root_remove body → prev → unknown-key → root-invariant;
thresholds body → prev → bad-thr; log_key body (+ point) → prev → witness-key dup-key →
active-log-key dup-key; policy body → ≤ 4096 → parses with valid points → prev → dup-key;
params body → non-empty/known keys/types → prev; note body → ≤ 4096 → prev absent.

C34 §4.4 — "`prev` ... **present and equal** where the object exists, **absent** where it
does not — which is only an `enroll` of a `device_id` that no accepted entry has ever
named". Chose: the object "exists" for an enroll iff `state.devices` has a record for the id
(only accepted entries create records); every other state-changing type always has an object
(versions start at 0 after genesis), so prev must be present and equal.

C35 §5.1 log_key — "`pk` is not the public key of any witness the policy in force names —
`policy` when it is non-empty, else `anchor.policy`". Chose: parse that policy text and
compare only `witness`-line public keys (not `log` lines) with pk bytes; then compare pk with
anchor.log_key's public key and every `log_keys[].pk`.

C36 §5.1 policy — "no witness the text names has the public key of an active log key".
Chose: only witness lines of the new text are compared with active log keys; its `log` lines
are not (pre-announcement and an old witness key on a log line stay legal).

C37 §5.1 params — "**merge** into `params`". Chose: overwrite the given keys only; a rejected
entry writes nothing (validate fully, then apply).

C38 §5.1 — "`since_index` records the index of the entry that last changed the device's
status: enroll sets it, revoke sets it, rotate leaves it alone"; `version` = last accepted
entry naming the device. Re-enrol replaces the record wholesale.

C39 §5.1 — "Abort means replay stops immediately: `rejected` holds exactly `{index: 0,
reason: "bad-genesis"}` and `size` is 0", with the full zero state (net from anchor, params
defaults). Empty input: zero state, size 0, rejected empty.

C40 §5.2/§5.3 — dup-wg for enroll: `wg_pk` ∈ active_wg (any device); for rotate: active for
a different device_id.

## Canonical state and JSON (§5.3, §14)

C41 §5.3 — state members name, net, size, root_thr, signer_thr, roots (kid → pk),
signers, params (all five keys), policy, log_keys [{overlap, pk, since_index}], devices
{id → {device_pk, wg_pk, status, since_index, version, labels, expires}}, active_wg
{hex wg_pk → id}, versions {signers, roots, params, policy, log_key}, rejected [{index,
reason}]. All always emitted.

C42 §14 — no whitespace; keys sorted bytewise over UTF-8; bytes as lowercase hex; integers
plain decimal; escape exactly `"` `\` \b \t \n \f \r and other C0 as `\u00xx` lowercase;
everything else verbatim (/, <, >, &, DEL, U+2028/2029, non-ASCII); one trailing 0x0A.

## Notes, checkpoints, receipts (§6, §7, §10)

C43 §7 — "the **first** blank line ends the text"; "a note whose first line is blank ...
is `note`"; "Every signature line, including the last, ends in one 0x0A—exactly one"; "A
note carries at least one signature line". Chose: split on 0x0A; the note must end in 0x0A;
the text is the lines before the first empty line (≥ 1 line); every line after the blank
line is a signature line; an empty one (second blank line, extra final newline) is `note`.

C44 §7 — "MUST be valid UTF-8, and MUST NOT contain an ASCII control character below
U+0020 other than the line feeds". Chose: whole-note UTF-8 check and a byte scan for
0x00–0x1F except 0x0A, both `note`, before any key lookup. DEL (0x7F) is not a control under
this rule (it says "below U+0020").

C45 §7 — signature line: "`— ` ..., the key name, one space, then base64"; "splits at
its **first** space"; name "one or more characters, none of them `+` and none a Unicode
white-space character" (the listed set). Chose: prefix must be exactly E2 80 94 20; name =
bytes up to the first 0x20; name non-empty, no '+', no listed white space (decoded as UTF-8
runes); payload = rest; payload must be canonical padded standard base64 (decode and
re-encode reproduces it exactly, which also rejects embedded CR/LF and unpadded forms) of at
least 4 bytes. All failures `note`.

C46 §7 — "Framing is every line's; length is the matched key's". Chose: a line "matches" a
key when name bytes equal the key's name and the first 4 payload bytes equal its key id.
Unmatched lines are ignored whatever their length.

C47 §7 alg 0x01 — 68 bytes exactly, signature over the note text (through its final LF).
Alg 0x04 — 76 bytes exactly; timestamp big-endian uint64, > 2⁶³−1 fails before the signature;
message `cosignature/v1\ntime <decimal>\n` ‖ text.

C48 §10.1 step 3 — "no line whose name and key id match a trusted log key ... verifies, or
any line that matches does not". Chose: at least one matched log line; every matched log line
must be 68 bytes and verify. Trusted log keys = trust file `log_key` plus, for a reader that
has accepted a state, every `log_keys[].pk` published as `<origin>+<id>+base64(0x01‖pk)`
(§9.4).

C49 §6 / §10.1 step 4 — exactly three text lines; size canonical decimal ("0" allowed, no
leading zeros, digits only, ≤ 2⁶³−1); root canonical padded standard base64 of exactly 32
bytes. All `checkpoint`. Step 5: origin byte-equal to trust origin.

C50 §10.1 step 6 — "a cosignature line whose name **and** key id match a listed witness
does not verify — listed meaning named by the policy that applies". Chose: listed = every
`witness` directive of the applicable policy (reachable from the quorum or not); match on the
witness vkey's note name and its 0x04 key id. Step 7: the set of witnesses with ≥ 1 verifying
line must satisfy the policy's quorum; `quorum none` is always satisfied.

C51 §5.3 — quorum time T: "the newest instant such that the witnesses whose cosignature
timestamp is at or after it satisfy the policy"; "A witness counts once ... its newest".
Chose: per listed witness, the newest verifying timestamp; T = the largest timestamp t among
those such that {w : ts_w ≥ t} satisfies the quorum; none → no clock; `quorum none` → no
clock.

C52 §5.3/§10 held head — "**This checkpoint** is its tree head — origin, size and root
... reading it again ... changes neither (D-082 (1)). The copy's own lines are still checked
as §10 checks every checkpoint ... The copy's quorum is not judged again". Chose: if the
candidate's (origin, size, root) equals the stored head's, run steps 2–6 with the stored
accepting policy, skip step 7, keep stored note/T/policy; the log-signature step still
requires a verifying matched log line. Bundles and evidence never get this treatment.

C53 §10 — policy in force: "the trust file's, or the most recently replayed". Chose: the
replayed state's `policy` when non-empty, else the trust policy.

C54 §10 outline + §10.1 step order — 1 unserved (checkpoint), 2 note, 3 log-signature, 4
checkpoint, 5 origin, 6 cosignature, 7 quorum, 8 entries (unserved if a bundle is missing),
9 head, 10 fork / rollback (only with a stored head), 11 genesis (replay of entry 0 alone
aborts, or size 0), 12 tiles (unserved if a tile is missing). Chose exactly this order.

C55 §10 fork block — `at = min(sizes)`; served root at `at` recomputed from served entries;
mine = stored root if at = stored size, else my own branch's root at `at` when I hold it.
Chose: unequal → `fork`; else if cp.size < stored size → `rollback`; if I do not hold my own
branch and at < stored size → skip the comparison and answer `rollback`.

C56 §6 tiles — tlog-tiles: height 8; level-L tile N holds the level-8L node hashes N·256 …;
implied tiles are every level with ⌊n/256^L⌋ ≥ 1; the last tile of a level is partial
`.p/W` when its count is not a multiple of 256. Entry bundles: big-endian uint16 frames; a
bundle must hold exactly its declared count with no trailing bytes (`entries`); zero-length
frames frame. A missing partial falls back to the full path, which must be exactly 8192 bytes
(`tiles`) or exactly 256 frames (`entries`), first W used; a present malformed partial does
not fall back. Paths: three-digit groups, all but the last prefixed `x`.

C57 §7 receipts — steps note → log-signature → receipt (exactly 4 text lines, first
`norn/receipt/v1`) → origin (exact) → leaf-hash (canonical padded base64, exactly 32 bytes)
→ deadline (canonical decimal ≤ 2⁶³−1, "0" allowed) → entry (when a submitted leaf is given)
→ expired (now ≠ 0 and now ≥ deadline).

## Bundles (§8.1)

C58 §8.1/§10.1 bundle steps — length > 81919 → `bundle`; decode (profile, cap 81919); closed
map of exactly v (uint = 1), device (text, §2 grammar), index (uint), entry (bytes ≤ 65535),
proof (array of 32-byte strings), checkpoint (text) — any fault `bundle`; then checkpoint
steps 2–7 under current keys and current policy (no held-head exemption); then `inclusion`
(index < size, RFC 9162 §2.1.3.2 with exact consumption); then `binding`.

C59 §8.1 binding — "Binding is structural". Chose: the entry must decode under the §4.0
profile and have the complete closed envelope with types (v = 1, t text, net 16 bytes — not
compared with the anchor, ts uint, body map, well-formed sigs, after/prev uint when present);
for `enroll`, body must carry a `request` byte string (other body keys tolerated) that decodes
under §16.1 structure and field rules including point admission and expires > ts, without
signature or network checks, and its device_id must equal the label; for `rotate`/`revoke`,
the body's `device_id` text must equal the label (body otherwise unchecked); any other type
names no device → `binding`.

C60 §8.1 condition 3 — install the replayed state's `wg_pk` of an active device, never the
bundle entry's.

## Grants (§4.0 D-077, §13.1)

C61 §4.0 grant — split the `ip` label on ',', trim leading/trailing U+0020 only, parse
`<address>/<length>`; IPv4 dotted quad of four decimal octets 0–255 without leading zeros
("0" allowed); IPv6 per RFC 4291 §2.2 (1–4 hex digits per group, either case, at most one
`::` consuming ≥ 1 group, optional trailing dotted quad as the last 32 bits, no zone);
length decimal without leading zero, ≤ 32 / ≤ 128; mask; refuse the whole label if any part
fails, if any part is empty, or if any IPv6 address before masking lies in ::ffff:0:0/96;
render IPv4 dotted, IPv6 RFC 5952 (lowercase, longest run of ≥ 2 zero groups compressed,
first on a tie, no embedded dotted quad); deduplicate; sort bytewise as text. "No grant" =
the empty list.

## Trust files and policies (§9)

C62 §9.1 — trust file: length ≤ 65536; decode; closed map {version (uint = 1), net (bytes
16), origin (text = "norn/" + lowercase unpadded RFC 4648 base32 of net), name (text 1–64
bytes, any UTF-8), genesis_hash (bytes 32), log_key (text vkey, alg 0x01, id recomputed,
name = origin, valid point), log_urls (array ≥ 1 of non-empty text), witnesses (array ≥ 1 of
closed maps {name, key, url?}: name 1–64 bytes of the policy name grammar, unique; key a
0x04 vkey, id recomputed, valid point; url text, may be empty), policy (text, parses),
anchor? (closed {type text, max_lag uint, mode = "advisory"})}; no witness pk equals the log
pk; policy witness short names = witnesses names as a set, and per name the policy vkey text
equals the array's key text exactly; every policy `log` line's vkey text equals `log_key`.

C63 §9.1 policy grammar — chose: the text must end in LF (empty text has no quorum line →
invalid); bytes 0x00–0x08, 0x0B–0x1F, 0x7F anywhere → error; split on LF; a line that is
blank (spaces/tabs only) or whose first non-space/tab char is `#` is ignored; fields split on
runs of space/tab; keywords exact lowercase; field counts log 1–2, witness 2–3, group ≥ 3,
quorum exactly 1; names 1–64 bytes 0x21–0x7E without '+', one shared namespace, defined once,
`none` cannot be defined; group thresholds `all`/`any`/canonical decimal 1 ≤ k ≤ n; members
previously defined, no repeats, not `none`; exactly one quorum line naming an earlier
definition or `none`; vkeys parsed by C64 with alg 0x01 for log and 0x04 for witness and a
valid point; each public key appears once across log and witness lines; URLs opaque. I do not
require UTF-8 inside the policy grammar itself (bytes 0x80–0xFF are "content"); the CBOR text
layer requires it.

C64 §7/§9.1 verifier key — `<name>+<8 lowercase hex>+<base64>`, split on '+' at most twice;
name ASCII 0x21–0x7E without '+' (no length cap stated for a vkey name); base64 canonical
(44 chars, decode → 33 bytes, re-encode identical); first byte alg; declared id must equal
the recomputed id.

C65 §9.3 — fingerprint: first 10 bytes of SHA-256(trust bytes), Crockford base32 MSB first,
16 chars, groups of four joined by '-', file = that string + LF.

C66 §9.4 — learned keys accumulate and are never retired; the trust file's key is kept
alongside; a `policy` entry replaces the policy for the next checkpoint, not the one that
carried it.

## Evidence (§11.1)

C67 §11.1 — steps: 0 oversize (file length > 65536); 1 cbor (profile with cap 65536, must be
a map); 2 version (absent, non-uint incl. boolean, or ∉ {1,2}); 3 schema (exact key set per
version, types; hashes exactly 32 bytes); 4 policy (carried text parses with valid points);
5 held (§10 steps 2–7 under the reader's keys and own policy); 6 conflicting (same);
7 size (size > held size, or conflicting size ≠ size); 8 proof (size 0; main proof /
same-size root rule / surplus proof; v2: split > size, split 0 with non-zero root or
non-empty proofs, each split proof per its head with the own-size rule); 9 consistent
(held_root = conflicting root). Fork proved otherwise.

C68 §11.1 consistency proofs — RFC 9162 §2.1.4.2 verification with exact consumption,
requiring 0 < m ≤ n; m = n with a non-empty proof is a failure.

## Freshness (§8.1, §15)

C69 §8.1 ladder — unknown (no quorum time) → hard_stale (S_hard > 0 and elapsed > S_hard)
→ fresh (elapsed ≤ S) → degraded. Comparisons on exact durations.

C70 §15 — estimate of witness-time now = max over held (q, m) pairs of q + (now_mono − m);
age = estimate − the held checkpoint's quorum time.

## Requests (§16)

C71 §16.1 — closed map: v (uint = 1), ts (uint, required), net (bytes 16), sig (bytes 64),
wg_pk (bytes 32), labels? (C21), expires? (uint > ts), device_id (§2 grammar), device_pk
(bytes 32, valid point). Signature preimage `norn/enroll-request/v1\n` ‖ CBOR(request
without sig), verified under NORN-ED25519-v1 by device_pk. A consumer additionally refuses a
request for another network.

C72 §16.2 — bech32m per BIP-350: HRP `norn`, separator the last '1', charset, checksum
constant 0x2bc830a3 (bech32's 1 rejected), all-lowercase or all-uppercase (mixed refused),
characters 33–126, no 90-char limit; 5→8 regrouping with padding < 5 bits and all zero;
decoded payload ≤ 65535.

## Harness

C73 §12 — "`says` is a semantic hint ... What a reader compares is the `codes` map wherever
a manifest has one". Chose: the harness compares my closed code with every code a manifest
gives, and compares accept/refuse where it gives none; it never string-matches `says`.
