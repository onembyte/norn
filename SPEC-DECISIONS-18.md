# Decisions log — cold gate run 18

Written after reading `SPEC.md` in full and before opening `testdata/vectors/README.md`,
any manifest or any vector. Each entry: section, the exact words, the reading chosen, why.
Not edited afterwards; later doubts go in the report.

## Ed25519 (§3.1)

**C01 — §3.1 item 1.** "32 bytes that are the canonical encoding (RFC 8032 §5.1.3) of a point of order exactly `L` ... the encoded `y` is below `p`, the sign bit is 0 when `x` is 0, the bytes decode to a point on the curve, and that point is not the identity and has no component of order 2, 4 or 8".
Chosen: implement every clause separately (reject y >= p, reject x = 0 with sign bit 1, reject off-curve, compute [L]P and require O, require P != O). Why: the spec says the canonical clauses are implied by the order clause, but checking them costs nothing and the order clause alone is what decides; both give the same answers.

**C02 — §3.1 item 3.** "`S`, read as a little-endian integer, MUST be less than `L` ... and with `k = SHA-512(R ‖ A ‖ M)` read little-endian and reduced mod `L`, `[S]B = R + [k]A`. ... the cofactorless one, RFC 8032 §5.1.7's second form, is the definition."
Chosen: verify = len 64; R a valid point (C01); S < L (full 256-bit compare, no reduction); A a valid point (re-checked at verification even though every admitted key was checked at admission); cofactorless equation compared as points. Implemented from RFC 8032 with math/big extended-coordinate arithmetic; the standard library's crypto/ed25519 is used only to *sign* test inputs.

**C03 — §3.1 item 2.** "MUST be a valid point wherever a key is admitted ... every verifier key a `policy` entry's text carries".
Chosen: every policy parse, wherever it happens (trust file, policy entry, evidence, `policies/*.txt`), checks every vkey's public key is a valid point; a trust file's `log_key` and witness keys likewise; genesis roots and signers; `signer_add`/`root_add`/`log_key` pk; `rotate` incoming `device_pk`; a request's `device_pk`. `wg_pk` (X25519) gets only its 32-byte length check.

## CBOR profile (§4.0)

**C04 — §4.0 allow-list.** "A Norn CBOR item is an unsigned integer (major type 0), a byte string (2), a text string (3), an array (4), a map (5), or one of the two simple values `false` (20) and `true` (21) ... and nothing else."
Chosen: one strict decoder used for every Norn CBOR artifact (entries, requests, trust files, bundles, evidence). It refuses major type 1, 6, every 7 other than 0xf4/0xf5, every indefinite length (additional info 31), reserved additional info 28–30, non-shortest heads for every head (ints and lengths), uints above 2^63−1, invalid UTF-8 text, map keys that are not text or are outside 1–23 bytes, map keys not strictly increasing in encoded-form order, trailing bytes, declared lengths beyond the remaining input, nesting depth above 8.

**C05 — §4.0 map keys.** "every **map key** is a text string of 1–23 bytes".
Chosen: enforced at the decoder for every map in every artifact (labels, trust file, witness elements, anchor, bundle, evidence), not only entries. Why: the sentence is in the profile table, which governs all Norn CBOR.

**C06 — §4.0 depth.** "Nesting depth is at most 8, counted in containers. The top-level map is depth 1 ... A scalar does not add depth".
Chosen: a container at depth 8 is accepted (empty or not); a container at depth 9 is refused. The top-level item, if a container, is depth 1, whatever its kind. Embedded request restarts at 1.

**C07 — §4.0 size caps.** "`MAX_ENTRY_BYTES` is 65535 ... as is an enrollment request"; "`MAX_BUNDLE_BYTES` is 81919"; "`MAX_TRUST_BYTES` is 65536"; "`MAX_EVIDENCE_BYTES` is 65536".
Chosen: the decoder takes the cap as a parameter and checks the *input length* against it before parsing (input longer than the cap is refused); a declared length longer than the remaining input is a truncation error (decode / `cbor`), never a size error. For evidence, the length check is the `oversize` code; for bundles, `bundle`; for entries, `decode`.

**C08 — §4.0 UTF-8.** "Text strings | definite length; valid UTF-8".
Chosen: Go `utf8.Valid` (rejects overlongs, surrogate code points, > U+10FFFF).

**C09 — §4.0 shortest form.** "Shortest form means every argument, not only integers."
Chosen: every head (uint value, byte/text/array/map length) must use the shortest argument form (value < 24 inline, < 256 one byte, etc.).

**C10 — §4.0 booleans.** "Booleans | valid CBOR items; schemas MUST reject them outside `params.rotate_needs_signer`".
Chosen: the decoder accepts 0xf4/0xf5 anywhere; every typed field rejects a boolean except `rotate_needs_signer`, which accepts only a boolean.

## Entries, envelope, schema (§4.0–§4.5)

**C11 — §4.0 derived values.** "`entry_hash` | `SHA-256` of the entry **as received**"; "`content_hash` | `SHA-256` of the signature preimage"; "signature preimage | the 14-byte prefix `norn/entry/v1\n` ... then the envelope encoded **without** the `sigs` key".
Chosen: content preimage = prefix ‖ canonical re-encoding of the decoded envelope map with `sigs` removed (the decoder is strict, so re-encoding the rest reproduces the received bytes of those members).

**C12 — §5.1 step 1 vs steps 2–3.** "An entry whose `entry_hash` is in the first set, or that decodes and whose `content_hash` is in the second → reject (`dup-entry`)" and "the hash is the one of an entry steps 2 and 3 accept".
Chosen: step 1 checks the byte key first (dup-entry), then records it; the content-key comparison is made only for an entry that has passed steps 2 and 3 (decode and envelope, `net` included), immediately after step 3 and before step 4. An entry that fails step 2 or 3 is `decode` even if its content equals an applied entry's.

**C13 — §5.1 step 1.** "Every entry that reaches this step adds its `entry_hash` to the first, **whether or not it is later rejected**".
Chosen: check membership, then add (an entry is never a duplicate of itself). Entry 0's byte key is added too; its content key is added only when genesis applies.

**C14 — §5.1 step 3.** "exactly the permitted keys, **every member of the type §4.1 gives it** (`t` text, `ts`, `after` and `prev` uint, `body` a map), `v` = 1, `net` = `anchor.net`, well-formed `sigs`".
Chosen: envelope keys exactly {v,t,net,ts,body,sigs} plus optional {after,prev}; `v` uint equal 1; `t` text (any text, the type is judged at step 4); `net` 16-byte bytes equal to anchor; `ts` uint; `after`/`prev` uint; `body` map; `sigs` array of closed {kid,role,sig} maps, kid `^[0-9a-f]{16}$` text, role text in {root,signer,device}, sig 64 bytes, strictly increasing kid (bytewise on the text). All `decode`.

**C15 — §4.2 / §5.2 signature validity.** "a signature `{kid, role, sig}` is *valid* iff `kid` names a key this entry may be signed by **in that role**, and Ed25519 verification of `sig` over the preimage succeeds."
Chosen: role `root` resolves against state-before roots by kid; `signer` against state-before signers; `device` against the device key(s) of the device the entry names (enroll: no envelope device key counts — the request signature is checked instead; rotate: current device_pk and, if present, the incoming device_pk; revoke: current device_pk). An unresolved or failing signature is ignored. Each key counts at most once.

**C16 — §4.3 note.** "any 1 signer or root".
Chosen: at least one valid `signer`-role or `root`-role signature; device-role signatures do not count.

**C17 — §4.3 revoke.** "≥ `signer_thr` signers, **or** the device itself, **or** ≥ `root_thr` roots".
Chosen: three independent tests, never pooled; "the device itself" = one valid device-role signature by the named device's current `device_pk`. Another device's signature does not count.

**C18 — §4.3 rotate signatures.** "one valid signature for each *distinct* key among the two, so an incoming key that is the current key needs its one signature and no other".
Chosen: check (a) a valid device signature under the current key (kid = kid(current)), later (b) if body has `device_pk` different from current, a valid device signature under kid(new) verified with the new key. If equal, (b) is satisfied by (a).

**C19 — §4.3 enroll.** "≥ `signer_thr` signers. The device's consent is the **embedded request**".
Chosen: only `signer`-role valid signatures count toward the enroll threshold; roots do not.

**C20 — §4.4 prev.** "**present and equal** where the object exists, **absent** where it does not — which is only an `enroll` of a `device_id` that no accepted entry has ever named."
Chosen: every governance object always exists after genesis (version 0), so every governance entry needs `prev` equal to the current version (0 included). A device object exists iff a device record exists (any accepted enroll ever).

**C21 — §5.1 table, enroll's first check.** "body closed and `request` present · the request decodes under §16.1 and its `net` equals the entry's (`decode`)".
Chosen: body exactly {request} with a byte-string value; request decoded with its own call (depth restarts, 65535 cap), full §16.1 structure and field rules incl. point admission and `expires > ts`; then request `net` == entry `net`. All `decode`.

**C22 — §5.1 rotate body.** "body well-formed and closed, its `device_pk` when present a valid point (§3.1) (`decode`)".
Chosen: keys {device_id, wg_pk} required, {device_pk} optional; device_id §2 grammar; wg_pk 32 bytes; device_pk 32 bytes and valid point.

**C23 — §5.1 revoke body.** "body well-formed and closed (`decode`)"; §4.3 "`reason` (string, **OPTIONAL** — absent is equivalent to `""`)".
Chosen: {device_id} required, {reason} optional text 0–256 bytes UTF-8.

**C24 — §5.1 signer_add/root_add.** "`kid(pk)` not already a root or signer (`dup-key`)".
Chosen: body {pk} 32 bytes, valid point (decode); prev; then dup-key by kid in either role.

**C25 — §5.1 root_remove.** "removing it leaves ≥ `root_thr` roots and ≥ 1 root (`root-invariant`)".
Chosen: `len(roots) − 1 >= root_thr` (and ≥ 1, implied).

**C26 — §5.1 thresholds.** "`1 ≤ thr ≤ len(set)` (`bad-thr`)".
Chosen: compared with the current size of the set before the entry; `thr` must be a uint (a boolean is `decode`).

**C27 — §5.1 log_key.** "`pk` is not the public key of any witness the policy in force names — `policy` when it is non-empty, else `anchor.policy` — compared as public-key bytes (`dup-key`) · `pk` is not an active log key — `anchor.log_key` or any `pk` in `log_keys`".
Chosen: body {pk, overlap}; pk 32 bytes and a valid point; overlap uint; prev; dup-key against witness-line keys (not `log` lines) of the policy in force; dup-key against the anchor log key's pk and every learned pk.

**C28 — §5.1 policy.** "`text` MUST parse as `c2sp.org/tlog-policy`, every verifier key it carries a valid point (§3.1) (`decode`) · `prev` ... · no witness the text names has the public key of an active log key".
Chosen: body {text}; ≤ 4096 bytes; parse with the §9.1 grammar (no trust-file correspondence rules); prev; dup-key if any *witness* line key equals an active log key's pk. A `log` line may name any key (pre-announcement).

**C29 — §5.1 params / genesis params.** "non-empty, only §4.5 keys, each of the right type".
Chosen: uint for checkpoint_interval, staleness, mmd; bool for rotate_needs_signer; text in {granted, advisory} for routes. No numeric range rules. Merge on apply; genesis params overlay the defaults.

**C30 — §5.1 note.** "`text` ≤ 4096 bytes (`decode`) · `prev` absent (`decode`)".
Chosen: body {text} UTF-8 ≤ 4096 bytes (0 allowed); `prev` present → `decode` at step 8 (after step 7's threshold).

**C31 — §5.1 entry 0.** "every failure here is `bad-genesis`".
Chosen: decode + envelope (same as steps 2–3, net vs anchor), t = genesis, leaf hash = anchor.genesis_hash, after 0 if present, prev absent, body checks (name UTF-8 1–64 bytes; roots/signers non-empty arrays of 32-byte valid points, distinct by bytes, disjoint; 1 ≤ thr ≤ len; params optional non-empty typed; closed body), then root-role signatures resolved against body roots by kid, ≥ root_thr. Any failure aborts with `{index 0, bad-genesis}`, size 0, zero state with anchor net and default params.

**C32 — §5.3 state serialisation.** "`active_wg` | map `wg_pk` → `device_id`"; §14.1 "byte strings | **lowercase hex**".
Chosen: byte-string map keys (roots/signers are already kid text; `active_wg` keys) rendered as lowercase hex; `net`, pk values hex; `params` emits all five keys; `versions` five keys; device record seven fields.

## Grants (§4.0)

**C33 — §4.0 grant derivation.** "the label split on commas, each part trimmed and parsed as an IPv4 or IPv6 prefix, masked to its prefix, duplicates removed, sorted as text"; "once U+0020 is removed from both of its ends and nothing else is".
Chosen: split on `,`; strip only 0x20 from both ends of each part; empty part → no grant; parse strictly per D-077; mask; render canonical; dedupe; sort bytewise. Absent label or any failing part → no grant (empty list).

**C34 — §4.0 IPv6 text.** "groups of one to four hexadecimal digits in either case, at most one `::`, a dotted quad allowed in place of the last 32 bits, and no zone".
Chosen: `::` must stand for at least one zero group (eight explicit groups with `::` is invalid); `::` alone is valid; the embedded dotted quad counts as two groups and must be last; rendering per RFC 5952 (lowercase, no leading zeros, longest run of ≥ 2 zero groups compressed, first on a tie, no IPv4 notation).

**C35 — §4.0 IPv4-mapped.** "An IPv4-mapped IPv6 prefix is no grant either".
Chosen: the *unmasked* address is tested: bytes 0–9 zero and bytes 10–11 0xff → the whole label is no grant (an IPv4-mapped address written with a short prefix is refused too).

## Notes, checkpoints, receipts (§6, §7)

**C36 — §7 text end.** "the **first** blank line ends the text ... The text is at least one line: a note whose first line is blank ... is `note`".
Chosen: split at the first "\n\n"; the text is everything up to and including the first LF of that pair; text must be non-empty with a non-empty first line.

**C37 — §7 framing.** "Every signature line, including the last, ends in one `0x0A`—exactly one"; "A note carries **at least one signature line**"; control-byte and UTF-8 rules.
Chosen: whole note must be valid UTF-8 with no byte < 0x20 except LF (DEL allowed); after the blank line, ≥ 1 lines, each terminated by exactly one LF, none empty; each starts "— " (U+2014 U+0020); name = up to the first space; name non-empty, no `+`, none of the listed white-space code points; payload = remainder, canonical padded standard base64 (re-encode equals text), decoding to ≥ 4 bytes.

**C38 — §7 matching and length.** "What follows the key id is judged by the trusted key whose name and key id the line matches. A line that matches no trusted key is ignored whatever its length".
Chosen: a line matches a trusted key iff its name equals the vkey name byte for byte and its first four payload bytes equal the key id. Matched log-key line: payload exactly 68 bytes and verifies over the text, else `log-signature`. Matched listed-witness line: exactly 76 bytes, timestamp ≤ 2^63−1, verifies over the cosignature message, else `cosignature`.

**C39 — §10 log signature.** "Every signature line whose name and key id match a trusted log key MUST verify, and at least one such line MUST be present."
Chosen: as stated, across the trust key plus learned keys (named origin, id over 0x01 ‖ pk).

**C40 — §6 checkpoint body.** "exactly three lines ... size in decimal with **no leading zeroes** and at most 2⁶³−1 ... root as standard base64 with padding, 32 bytes once decoded ... canonical".
Chosen: size matches `0|[1-9][0-9]*` and ≤ 2^63−1; root base64 decodes to 32 bytes and re-encodes to the same text; any non-empty origin line is accepted at step 4 and compared for exact equality at step 5.

**C41 — §5.3 quorum time.** "the newest instant such that the witnesses whose cosignature timestamp is at or after it satisfy the policy"; "A witness counts once. Two verifying lines ... are its newest".
Chosen: per listed witness take its newest verifying timestamp; T = the largest t among those timestamps such that {w : ts_w ≥ t} satisfies the quorum; `quorum none` → no clock; no satisfying t → no clock. Computed under the policy that accepted the checkpoint (trust policy for a fresh reader, replayed policy for an informed one).

**C42 — §7 receipt order.** Steps 1–8 as numbered.
Chosen: exactly that order; step 3 checks line count == 4 and first line == `norn/receipt/v1`; step 6 deadline `0|[1-9][0-9]*` ≤ 2^63−1; step 8 refuses when the checking time is nonzero and ≥ deadline.

## Policies (§9.1)

**C43 — §9.1 grammar, UTF-8.** "Bytes `0x80–0xFF` are content, not separators ... Norn's CBOR text must still be valid UTF-8 (§4.0)."
Chosen: the policy parser also refuses invalid UTF-8 (every policy in Norn is CBOR text, so no well-formed artifact can carry one; for raw `.txt` files this keeps one reading everywhere).

**C44 — §9.1 grammar, lines.** "Every directive line, including the final line, ends in ASCII line feed ... and so does every other line".
Chosen: non-empty text must end in LF; the empty text has no lines (and then fails "exactly one quorum").

**C45 — §9.1 names.** "one or more bytes `0x21`–`0x7E`, `+` excluded — and is at most 64 bytes"; "`none` is predefined, cannot be defined"; "`all` and `any` are ordinary names outside the threshold position".
Chosen: as stated; witness and group names share one namespace; `none` refused as a definition and as a member.

**C46 — §9.1 field counts and URLs.** "`quorum` one, `witness` two or three, `log` one or two, `group` a name, a threshold and one or more members".
Chosen: URL field is any non-separator token, not validated.

**C47 — §9.1 keys.** "a verifier key appears **once** in a policy, on whatever line. Keys are compared by their parsed underlying public key".
Chosen: duplicate 32-byte pk across all log and witness lines → error.

**C48 — §9.1 thresholds.** "a count is **canonical decimal** with `1 ≤ k ≤ n`".
Chosen: `[1-9][0-9]*` and ≤ n; `all`/`any` lowercase keywords in the threshold position.

**C49 — §9.1 quorum semantics.** "a `group` may name a `group`. It counts as **one** member".
Chosen: recursive evaluation; a witness is satisfied iff it has a verifying line.

**C50 — §7 verifier key.** "`<name>+<key_id as 8 lowercase hex digits>+<base64(alg ‖ pk)>`. Split it on `+` **at most twice**".
Chosen: name ASCII 0x21–0x7E no `+` (no length cap at the vkey level); id exactly 8 lowercase hex; data canonical base64 decoding to 33 bytes; declared id must equal SHA-256(name ‖ 0x0A ‖ alg ‖ pk)[0:4]; algorithm checked by context; pk a valid point.

## Trust file (§9)

**C51 — §9.1 trust file.** Table rows.
Chosen: size ≤ 65536 first; strict CBOR; closed map {version, net, origin, name, genesis_hash, log_key, log_urls, witnesses, policy} + optional anchor; version 1; net 16; origin == derived exactly; name UTF-8 1–64 bytes; genesis_hash 32; log_key vkey alg 0x01, name == origin, id recomputed, valid point; log_urls ≥ 1 non-empty text; witnesses ≥ 1 closed {name, key, url?}, name policy-grammar 1–64 bytes, unique, key vkey alg 0x04 recomputed valid point, url text; no witness pk == log_key pk; policy parses; set of policy witness names == set of array names and per name vkey text equal; every policy `log` line text == log_key text; anchor closed {type text (any), max_lag uint, mode == "advisory"}.

**C52 — §9.3 fingerprint.** "first **10 bytes** ... Crockford base32 ... 16 characters in four groups of four joined by `-`"; "`trust.fingerprint` file holds exactly that string followed by one `0x0A`".

**C53 — §9.4 learned keys.** "A learned key is the verifier key `<origin>+<id>+base64(0x01 ‖ pk)`".
Chosen: an informed reader trusts the trust key plus every learned key, each named origin; no activation index; policy for an informed reader = replayed state's policy when non-empty, else the trust policy.

## Tiles and Merkle (§6, §10)

**C54 — §6 tiles.** "Tile height 8 (width 256), as torchwood requires"; "level `L` covers 256^(L+1) leaves".
Chosen: level-L tile N holds, for i < W, the hash of the complete subtree of 256^L leaves starting at leaf (N·256 + i)·256^L; for tree size n, level L has floor(n/256^(L+1)) full tiles and, if w = floor(n/256^L) mod 256 > 0, one partial tile of width w; every such tile is fetched and compared byte for byte (length 32·W).

**C55 — §6 fallback.** "a verifier that cannot fetch `tile/<L>/<N>.p/<W>` MUST fetch `tile/<L>/<N>` before it answers `unserved` ... exactly 32 × 256 bytes, or exactly 256 frames".
Chosen: as stated; wrong-length full tile → `tiles`; wrong frame count → `entries`.

**C56 — §10.1 order.** Steps 1–12 as numbered; checkpoint unserved at 1; bundle unserved at 8; hash tile unserved at 12; genesis (replay of entry 0 alone aborting, or no entry 0) at 11 after fork/rollback.

**C57 — §10 fork/rollback.** "at := min(cp.size, stored_cp.size) ... mine := stored_cp.root if at == stored_cp.size, the root THIS NODE's branch had at `at`, otherwise ... a node that does not hold `at` cannot tell a fork from a rollback; it refuses below and MUST NOT accuse".
Chosen: when the node lacks its own entries at `at` < stored size, skip the comparison; a smaller served size is then `rollback`. The root at size 0 is SHA-256 of the empty string on both sides.

**C58 — RFC 9162 proofs.** "A list with more or fewer hashes than the procedure consumes is not the proof".
Chosen: inclusion: index < size and exact consumption; consistency: 0 < m < n, exact consumption; m == n handled by the callers' own empty-proof rules.

## Bundles (§8.1, §10.1)

**C59 — §8.1 binding.** "The entry itself must decode under §4.0's profile and §4.1's envelope — version 1, a text `t`, a map `body` — or it names no device".
Chosen: binding decodes the entry with the strict decoder and checks the §4.1 envelope shape (closed key set, mandatory keys, member types, v == 1, well-formed sigs) but NOT `net` against the anchor (the spec says a bundle proves inclusion, not acceptance; the network is replay's judgement). enroll → request decoded under §16.1 structure and field rules incl. point admission, without signature or network; rotate/revoke → the body's `device_id` text; every other type names no device.

**C60 — §8.1 rotate/revoke body.** "for the other device types, the `device_id` in the body".
Chosen: only the `device_id` member is read (must be text); the rest of the body is not validated for binding.

**C61 — §10.1 bundle step 1.** "does not decode as §8.1's closed map, carries an unknown key, an unsupported version, or a `device` outside §2's grammar; or a `proof` element that is not exactly 32 bytes ... or an `entry` longer than `MAX_ENTRY_BYTES`".
Chosen: length ≤ 81919 first, then strict decode, then closed schema with types, then those field rules — all `bundle`.

**C62 — §8.1 condition 3.** "the key the node installs for it is **the `wg_pk` replay gives**".

## Fork evidence (§11.1)

**C63 — §11.1 codes.** Steps 0–9 as numbered.
Chosen: exactly that order. `cbor` covers decode failures and "not a map"; `version` absent/non-uint/other; `schema` exact key set per version with types (32-byte hashes); `policy` §9.1 grammar + valid points (no trust correspondence); `held`/`conflicting` per §10 steps 2–7 under the reader's keys and policy; `size`; `proof`; `consistent`.

**C64 — §11.1 step 8, split.** "`split` is 0 with a `split_root` that is not all zero ... a split proof does not chain `split_root` at `split` to its head, or a split proof is carried where none is required".
Chosen: split ≤ size; split 0 → root all zero and both proofs empty; else held proof chains (split, split_root) to held head (empty iff split == held size, then split_root must equal held root), conflicting proof chains to conflicting head (empty iff split == conflicting size, then must equal its root).

## Requests (§16)

**C65 — §16.1.** Table.
Chosen: closed map {v, ts, net, sig, wg_pk, device_id, device_pk} + optional {labels, expires}; v == 1; net 16; sig 64; wg_pk 32; device_pk 32 valid point; device_id §2; labels non-empty ≤ 32 pairs, text values ≤ 256 bytes; expires uint > ts; signature over "norn/enroll-request/v1\n" ‖ canonical CBOR without sig. Structure before signature.

**C66 — §16.2 bech32m.** "A decoder MUST reject a payload whose padding is 5 bits or more, or whose padding bits are not zero"; uppercase accepted, mixed refused, bech32 refused.
Chosen: BIP-350 decoding (last `1` separator, chars 33–126, HRP compared lowercased == "norn", checksum constant 0x2bc830a3, data ≥ 6 checksum characters, no 90-char limit), then 5→8 regrouping with the padding rule, payload ≤ 65535.

## Freshness and expiry (§5.3, §8.1, §15)

**C67 — §8.1 ladder.** "the **first row, read top to bottom, whose condition holds**": unknown → hard_stale (S_hard configured and elapsed > S_hard) → fresh (elapsed ≤ S) → degraded. S_hard 0 = not configured.

**C68 — §15 estimate.** "The node's estimate of now is **the largest of the lower bounds** it holds"; age = estimate − quorum time of the held checkpoint.

**C69 — §5.3 expiry.** "A device is expired exactly when `expires != 0 && expires <= T`"; no clock → expiry not judged.

## JSON (§14)

**C70 — §14.** Canonical JSON exactly as tabled: no whitespace, keys bytewise over UTF-8, hex bytes, escapes only `"` `\` and C0 (named short forms for \b \t \n \f \r, else \u00xx lowercase), trailing LF.

## Anchors (§6)

**C71 — §6 OTS digest.** "`SHA-256` of the note's leading bytes **through the newline that terminates the blank separator line**".
