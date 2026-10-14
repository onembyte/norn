# Decisions log — cold gate run 15

Written after reading `SPEC.md` in full and before opening `testdata/vectors/README.md`,
any manifest or any vector. Each entry: section, the exact words, what I chose, why.
Not edited afterwards; later doubts go in the report.

## Ed25519 (§3.1)

**C01 — §3.1 item 1.** "A valid point is 32 bytes that are the canonical encoding (RFC 8032 §5.1.3) of a point of order exactly `L`" … "A verifier may check it … by decoding, re-encoding and comparing the bytes, then computing `[L]P`."
Chose: decode per RFC 8032 §5.1.3 with explicit refusal of `y ≥ p` and of `x = 0` with sign bit 1, then require `P ≠ O` and `[L]P = O`, computed with my own extended-coordinate arithmetic (math/big). Why: it is the stated method; the canonical clauses are cheap and are named even though implied.

**C02 — §3.1 item 3.** "`R ‖ S` (64 bytes) verifies under a key `A` over a message `M` only if `R` is a valid point; `S` … MUST be less than `L` … `[S]B = R + [k]A`."
Chose: predicate = validPoint(A) ∧ validPoint(R) ∧ S < L ∧ cofactorless equation. Equation and `S < L` via Go's `crypto/ed25519.Verify` (which refuses `S ≥ L` and compares `encode([S]B − [k]A)` with the bytes of `R`; with `R` canonical that is point equality). Why: item 3 names only `R`, but item 4 says the predicate rejects `low_order_A` / `non_canonical_A` vectors, so `A`'s validity is part of the predicate itself, not only of admission.

**C03 — §3.1 item 2.** "A key that is not is refused as `decode` at its entry type's body step … it makes a trust file invalid."
Chose: genesis roots/signers → `bad-genesis`; `root_add`/`signer_add`/`log_key` `pk`, `rotate` incoming `device_pk`, an `enroll` request's `device_pk`, every vkey of a `policy` entry's text (log lines included) → `decode` at the body step; trust `log_key`/witness keys → trust invalid; a standalone request → refused. The policy parser checks the point for every vkey wherever it is used (trust policy, evidence policy, policy entry, `policies/`).

## CBOR profile (§4.0, §4.1)

**C04 — §4.0.** "The profile is an allow-list … unsigned integer (0), byte string (2), text string (3), array (4), map (5), or one of the two simple values `false` (20) and `true` (21) … and nothing else."
Chose: decoder accepts only those heads; major 1, 6, 7 with any other additional info (including 24 one-byte simple values, 25–27 floats, 31 break) and additional info 28–31 anywhere are refused.

**C05 — §4.0 Integers row.** "major type 0 only; shortest form; ≤ 2⁶³−1."
Chose: the bound applies to every uint in every Norn CBOR structure (entries, requests, trust files, bundles, evidence) and is enforced by the decoder.

**C06 — §4.0.** "Shortest form means every argument, not only integers."
Chose: preferred serialization refused-otherwise for uint values and for byte/text/array/map length heads.

**C07 — §4.0 Text strings row.** "every **map key** is a text string of 1–23 bytes".
Chose: enforced in the decoder on every map of every Norn CBOR structure (labels included); a non-text key, an empty key or a 24+-byte key is a profile violation.

**C08 — §4.1.** "Keys are **strictly increasing** … each key's encoded form greater than the one before it".
Chose: compare (length, bytes) of each key (equivalent to encoded-form order because every key header is one byte); equal or smaller → refused.

**C09 — §4.0.** "Nesting depth is at most 8, counted in containers. The top-level map is depth 1 … A scalar does not add depth".
Chose: a container at depth 9 is refused; an embedded request is decoded by a separate call whose depth restarts at 1.

**C10 — §4.0.** "`MAX_ENTRY_BYTES` is 65535 … as is an enrollment request".
Chose: input longer than the artifact's cap is refused before decoding (entries/requests 65535, bundles 81919, trust 65536, evidence 65536); a declared length larger than the remaining input is refused before allocation.

**C11 — §4.0.** "A decoder MUST consume the **whole** input".
Chose: trailing bytes are a profile violation.

**C12 — §4.0.** "Text strings | definite length; valid UTF-8".
Chose: RFC 3629 validity as Go's `utf8.Valid` (no surrogates, no overlongs, ≤ U+10FFFF), keys and values alike.

**C13 — §4.0 field table.** "`labels` | map text→text; ≤ 32 entries; keys 1–23 bytes …; values ≤ 256 bytes; a `labels` map, when present, MUST carry at least one pair".
Chose: values may be empty (0–256 bytes; no floor is stated); keys 1–23; 1–32 pairs; values must be text.

**C14 — §4.0.** "`device_id` matches `^[a-z0-9][a-z0-9.-]{0,63}$` **as a whole**".
Chose: a byte loop over the whole string (no regex engine), 1–64 bytes.

**C15 — §4.0.** "`kid` … exactly 16 characters matching `^[0-9a-f]{16}$`" in `sigs` and in `signer_remove`/`root_remove` bodies.
Chose: as written; malformed → `decode`.

**C16 — §4.0.** "`sigs` is an array of maps … sorted by `kid` bytewise, with no repeated `kid`".
Chose: strictly increasing bytewise comparison of the kid strings; closed `{kid, role, sig}`; role ∈ {root, signer, device}; sig exactly 64 bytes.

**C17 — §4.0.** "Booleans | valid CBOR items; schemas MUST reject them outside `params.rotate_needs_signer`".
Chose: a boolean anywhere a uint, text or bytes is expected is a schema fault (`decode`, `bad-genesis` at 0, `schema` in evidence, `bundle`, invalid trust).

**C18 — §4.1 / §5.1 step 3.** "exactly the permitted keys, **every member of the type §4.1 gives it** …, `v` = 1, `net` = `anchor.net`, well-formed `sigs`".
Chose: keys ⊆ {v,t,net,ts,after,prev,body,sigs}; mandatory v,t,net,ts,body,sigs; `v` a uint equal to 1; `t` text (any value); `net` a byte string equal to anchor.net; `ts`/`after`/`prev` uint; `body` a map; `sigs` per C16.

**C19 — §5.1 step 1.** "The entry's duplicate key is its `content_hash` if steps 2 and 3 would accept it … and its `entry_hash` otherwise. A key already seen → reject (`dup-entry`)."
Chose: one seen set holding both kinds of key (the text says "a key already seen", one set); content_hash computed only when C18 passes; the key is recorded before any later check; entry 0's key is recorded the same way (entry-0 step 1).

**C20 — §4.0 derived values.** "signature preimage | the 14-byte prefix `norn/entry/v1\n` … then the envelope encoded **without** the `sigs` key".
Chose: canonical re-encoding of the decoded envelope minus `sigs` (identical to what the canonical input implies).

## Replay (§4.3–§5.3)

**C21 — §5.2 counting.** "a signature `{kid, role, sig}` is *valid* iff `kid` names a key this entry may be signed by **in that role**, and Ed25519 verification … succeeds."
Chose: role string must equal the role counted; kid resolved in that role's map of the pre-entry state; NORN-ED25519-v1 over the preimage; counted per distinct kid. Invalid signatures ignored.

**C22 — §5.1 entry 0.** Steps 1–8, "every failure here is `bad-genesis`".
Chose: listed order. Body closed {name, roots, root_thr, signers, signer_thr, params?}; name text 1–64 bytes; roots/signers non-empty arrays of 32-byte valid points, distinct, disjoint; thresholds uint with 1 ≤ thr ≤ len; params (if present) non-empty, §4.5 keys, §4.5 types, `routes` ∈ {granted, advisory}; `after` 0 if present; `prev` absent. Bootstrap counts `role: "root"` signatures whose kid is kid(pk) of a body root. Abort state per §5.1.

**C23 — §5.1 `enroll` row.** "body closed and `request` present · the request decodes under §16.1 and its `net` equals the entry's (`decode`) · … (`no-device-sig`) · … (`threshold`) · `prev` … (`stale-state`) · … (`dup-id`) · … (`dup-wg`)".
Chose: body exactly {request: bytes}; request per C50 including device_pk validity, `expires > ts`, depth restart; net equal; request signature; signer count ≥ signer_thr; prev; dup-id; dup-wg against every active device. Effect: record replaced wholesale (labels `{}` and expires 0 when absent), status active, since_index = version = index.

**C24 — §5.1 `rotate` row.** Order as listed.
Chose: body closed {device_id, wg_pk, device_pk?}, device_id pattern, wg_pk 32 bytes, device_pk 32-byte valid point → `decode`; no record → `unknown-device`; revoked → `not-active`; a valid `role: "device"` signature with kid(current device_pk) → else `no-device-sig`; rotate_needs_signer → signer count; prev; wg_pk active for a different id → `dup-wg`; device_pk present and different from current → a valid `role: "device"` signature with kid(new pk) → else `no-device-sig`. Effect: replace wg_pk (and device_pk); version = index; since_index, labels, expires unchanged.

**C25 — §5.1 `revoke` row.** "authorised by signers, roots **or** the device itself (`threshold`)".
Chose: body closed {device_id, reason?}, reason text 0–256 bytes; unknown-device; not-active; authorised iff signers ≥ signer_thr or roots ≥ root_thr or one valid device signature by the current device_pk (counts are never pooled); prev. Effect: status revoked, out of active_wg, since_index = version = index.

**C26 — §5.1 `signer_add`, `root_add`.** "`kid(pk)` not already a root or signer (`dup-key`)".
Chose: compared by kid, across both roles, as written.

**C27 — §5.1 `signer_remove`/`root_remove`.** "`kid` is a signer (`unknown-key`)" / "removing it leaves ≥ `root_thr` roots and ≥ 1 root (`root-invariant`)".
Chose: kid must be in that role's map (a kid in the other role is `unknown-key`); root_remove needs len(roots) − 1 ≥ root_thr. signer_remove has no invariant.

**C28 — §5.1 `signer_thr`/`root_thr`.** "`1 ≤ thr ≤ len(set)` (`bad-thr`)".
Chose: len of the current set at that entry.

**C29 — §5.1 `log_key`.** "`pk` is not the public key of any witness the policy in force names — `policy` when it is non-empty, else `anchor.policy`".
Chose: compare against `witness` lines only (log lines of that policy are not witnesses); a `pk` equal to the anchor log key or to an already learned key is not refused (nothing says so); append {pk, overlap, since_index}.

**C30 — §5.1 `policy`.** "`text` MUST parse as `c2sp.org/tlog-policy`, every verifier key it carries a valid point (`decode`) · `prev` … · no witness the text names has the public key of an active log key — `anchor.log_key` or any `pk` in `log_keys`".
Chose: parse per C58–C67; dup-key compares only `witness` lines; every learned key counts as active ("never retired", §9.4); state.policy = text verbatim.

**C31 — §4.3 `params`.** "`params` | partial §4.5 map".
Chose: the body itself is the partial parameter map (non-empty, §4.5 keys, §4.5 types, closed `routes`); merged key by key.

**C32 — §5.1 `note`.** "body well-formed and closed (`decode`) · `text` ≤ 4096 bytes (`decode`) · `prev` absent (`decode`)"; step 7: "no valid `signer` or `root` signature → reject (`threshold`)".
Chose: `text` required; empty text allowed; threshold before the body; no version changes.

**C33 — §4.4.** "**present and equal** where the object exists, **absent** where it does not — which is only an `enroll` of a `device_id` that no accepted entry has ever named."
Chose: the five governance objects always exist after genesis (version 0); a device record exists iff an accepted entry created it (a rejected enroll creates nothing).

**C34 — §5.1.** "A rejected entry … changes nothing else."
Chose: all checks complete before any mutation.

**C35 — §5.3 / §14.** State schema.
Chose: bytes as lowercase hex; roots/signers kid→hex pk; log_keys [{overlap, pk, since_index}]; device records with all seven fields; active_wg hex(wg_pk)→id; versions five keys; rejected [{index, reason}]; params all five keys; one trailing LF.

**C36 — §14.2.** "Exactly these characters are escaped, and no others".
Chose: `\"` `\\` `\b` `\t` `\n` `\f` `\r`, other C0 `\u00xx` lowercase; DEL, U+2028/9 and non-ASCII verbatim.

**C37 — §14.1.** "sorted **ascending, bytewise over the UTF-8 encoding of the bare key string**".
Chose: Go string comparison of the UTF-8 bytes.

## Notes, checkpoints, receipts (§6, §7, §10)

**C38 — §7.** "the **first** blank line ends the text".
Chose: signed text = bytes up to the first "\n\n" plus one "\n"; no "\n\n", or a note starting with "\n" (empty text), → `note`. After the separator: one or more lines, each ending in exactly one LF, none empty; else `note`.

**C39 — §7.** "MUST NOT contain an ASCII control character below U+0020 other than the line feeds".
Chose: whole note valid UTF-8, no byte < 0x20 except LF; DEL (0x7F) is not refused (only "below U+0020" is named).

**C40 — §7.** "the line splits at its **first** space and everything after it is the payload".
Chose: prefix U+2014 U+0020; name up to the first 0x20, non-empty, no `+`, no character of the listed white-space set; payload = rest of line (a second space makes it non-base64 → `note`); payload canonical padded std base64 (re-encode equals text), decoded ≥ 4 bytes.

**C41 — §7 / §10.** "What follows the key id is judged by the trusted key whose name and key id the line matches."
Chose: match = name bytes equal and first 4 payload bytes equal the key's id; matched payload exactly 68 (alg 0x01) or 76 (alg 0x04); unmatched lines ignored whatever their length.

**C42 — §10 / §10.1 step 3.** "Every signature line whose name and key id match a trusted log key MUST verify, and at least one such line MUST be present."
Chose: as written; trusted keys = trust `log_key` plus every learned `pk` as `<origin>+id+base64(0x01‖pk)` with the id recomputed for the origin name (§9.4).

**C43 — §10.1 steps 6–7.** "a cosignature line whose name **and** key id match a listed witness does not verify".
Chose: witnesses of the policy in force matched by their vkey note name and id; 76 bytes, timestamp ≤ 2⁶³−1 checked before the signature, signature over `cosignature/v1\ntime <ts>\n` ‖ text; quorum evaluated over policy short names of witnesses with ≥ 1 verifying line.

**C44 — §5.3.** "`T` is the **quorum time** … the newest instant such that the witnesses whose cosignature timestamp is at or after it satisfy the policy".
Chose: per witness its newest verifying timestamp; T = the largest candidate timestamp t with {w : ts_w ≥ t} satisfying; `quorum none` or nothing satisfying → no clock.

**C45 — §6 checkpoint body.** "exactly three lines … no leading zeroes … at most 2⁶³−1 … standard base64 with padding, 32 bytes once decoded … canonical".
Chose: `0` and `[1-9][0-9]*` ≤ 2⁶³−1; root 44-char canonical padded base64 → 32 bytes; all `checkpoint`; origin equality is step 5.

**C46 — §6 / §10.1 step 8.** "A partial bundle holds **exactly** the number of entries its path declares."
Chose: bundles for N entries: full groups of 256 then `.p/<N mod 256>`; each must frame exactly its count; a zero-length frame frames; extra bytes → `entries`; a missing bundle → `unserved`.

**C47 — §6 paths.** Three-digit groups, `x` prefix on all but the last, `.p/<W>` for partial.
Chose: as written.

**C48 — §6 / §10.1 step 12.** "The served `tile/<L>/…` hashes MUST also agree with the tree it rebuilt."
Chose: every level L with ⌊N/256^L⌋ ≥ 1 has its full tiles and a partial tile of width ⌊N/256^L⌋ mod 256 (when non-zero); each must be served (else `unserved`) and equal the rebuilt 32·W bytes exactly (else `tiles`).

**C49 — §10 / §10.1 step 10.** "at := min(cp.size, stored_cp.size) … if served ≠ mine → FORK … if cp.size < stored_cp.size → refuse without raising a fork".
Chose: served root recomputed from served entries; mine = stored root when at == stored size, else the node's own branch root computed from its own entries; a node without its branch refuses a shorter head as `rollback` without accusing. Loop order: unserved, note, log-signature, checkpoint, origin, cosignature, quorum, entries, head, fork/rollback, genesis, tiles.

**C50 — §16.1.** Request table.
Chose: closed map; required v (uint 1), ts, net (16 bytes), sig (64), wg_pk (32), device_id (pattern), device_pk (32, valid point); optional labels (C13) and expires (uint, > ts); signature NORN-ED25519 over `norn/enroll-request/v1\n` ‖ CBOR(request minus sig). A standalone request is not compared with any net.

**C51 — §16.2.** bech32m, HRP `norn`.
Chose: BIP-350 decoding (chars 33–126, no mixed case, lowercase an all-upper string, separator = last `1`, HRP exactly `norn`, ≥ 6 data chars, charset, polymod constant 0x2bc830a3), then 5→8 regrouping with padding < 5 bits and zero; no 90-char limit; text failures before CBOR.

**C52 — §7 receipts.** Steps 1–8 and their codes.
Chose: step 2 uses C41/C42 (every matched line verifies, ≥ 1); exactly four text lines; header exact; origin exact; leaf hash canonical padded base64 of 32 bytes; deadline `0|[1-9][0-9]*` ≤ 2⁶³−1; entry binding when given; expired iff time ≠ 0 and time ≥ deadline.

**C53 — §8.1 / §10.1 bundle table.** `bundle`, checkpoint steps, `inclusion`, `binding`.
Chose: length > 81919 → `bundle` before decoding; closed map of exactly six keys, `v` == 1, `device` text, `index` uint, `entry` bytes, `proof` array of 32-byte strings, `checkpoint` text; checkpoint steps 2–7 (no entries); inclusion: index < size and RFC 9162 §2.1.3.2 with the whole proof consumed; binding: entry decoded under the profile; `enroll` → the request's `device_id`; `rotate`/`revoke` → body `device_id`; anything else or any decode failure → `binding`.

## Trust file (§9)

**C54 — §9.1.** Field table.
Chose: length > 65536 → invalid before decoding; closed map; all keys but `anchor` required; `version` uint 1; `net` 16 bytes; `origin` equals the derived lowercase unpadded RFC 4648 base32 exactly; `name` 1–64 bytes; `genesis_hash` 32 bytes; `log_key` vkey alg 0x01 named `origin`, recomputed id, valid point; `log_urls` ≥ 1 non-empty texts; `witnesses` ≥ 1 closed {name 1–64 bytes, key vkey alg 0x04 recomputed id valid point, url? text}, names unique bytewise; no witness pk equals the log pk; `policy` parses, its witness-name set equals the trust's, each policy witness vkey text equals that witness's `key` text, every `log` line text equals `log_key`; `anchor` closed {type text (any), max_lag uint, mode text == "advisory"}.

**C55 — §9.3.** Fingerprint.
Chose: first 10 bytes of SHA-256(trust bytes), Crockford base32 MSB-first (16 chars), groups of 4 joined by `-`, file content plus one LF.

**C56 — §9.2.** "Building the CBOR from this rendering must reproduce `trust.cbor` byte for byte".
Chose: a minimal TOML reader for the shown shapes (hex bytes fields, inline `anchor` table, `[[witness]]` → `witnesses` in order, absent `url` omitted).

**C57 — §9.4.** "signed by `norn.trust.log_key`, or by a `pk` in `log_keys` of a state this node has already accepted" / "A `policy` entry supersedes `norn.trust.policy`".
Chose: a fresh reader trusts the trust key and policy; an informed reader adds every learned key and uses the replayed policy when non-empty; the policy in force for a checkpoint is the one held before that checkpoint is accepted.

## Policy grammar (§9.1)

**C58 — line endings.** "A missing final line feed is an error whatever the last line holds".
Chose: text must end in LF; empty text has no quorum → error.

**C59 — controls.** "all other bytes `0x00–0x08`, `0x0B–0x1F` and `0x7F` are an error anywhere … Bytes `0x80–0xFF` are content".
Chose: as written; the policy parser does not itself check UTF-8 (the CBOR layer does where the text comes from CBOR).

**C60 — blank lines/comments.** "a line whose **first character other than ASCII space or tab** is `#` is ignored".
Chose: as written; `#` elsewhere ordinary.

**C61 — fields.** "ASCII space (`0x20`) and tab (`0x09`) separate fields, in runs".
Chose: split on runs; leading and trailing runs produce no field.

**C62 — field count.** "`quorum` one, `witness` two or three, `log` one or two, `group` a name, a threshold and one or more members".
Chose: as written; unknown keyword → error.

**C63 — names.** "Witness and group names share one namespace; each name is defined **once** … `none` is predefined, cannot be defined, and is invalid as a group member".
Chose: any non-empty field is a name (no character class stated); members and quorum resolve only to earlier definitions; no member twice; exactly one quorum.

**C64 — thresholds.** "a count is **canonical decimal** with `1 ≤ k ≤ n`".
Chose: `all` = n, `any` = 1, else `[1-9][0-9]*` with 1 ≤ k ≤ n.

**C65 — keys.** "a verifier key appears **once** in a policy … compared by their parsed underlying public key".
Chose: log vkeys alg 0x01, witness vkeys alg 0x04, recomputed id, valid point, all pks distinct across log and witness lines.

**C66 — §7 verifier key.** "Split it on `+` **at most twice** … key name is one or more ASCII bytes from `0x21` to `0x7E`, `+` excluded … `alg ‖ pk` is 33 bytes … 44 base64 characters".
Chose: name grammar; id exactly 8 lowercase hex; data exactly 44 chars, canonical base64 (re-encode equals), 33 bytes.

**C67 — evaluation.** "a `group` may name a `group`. It counts as **one** member".
Chose: witness satisfied iff in the cosigner set; group satisfied iff ≥ k satisfied members; `none` always satisfied.

## Evidence, freshness, grants, misc

**C68 — §11.1.** Steps 0–9.
Chose: > 65536 → `oversize`; profile decode failure or non-map → `cbor`; `version` absent/non-uint/not 1|2 → `version`; key set and types (32-byte hashes) → `schema`; carried policy parse → `policy`; held then conflicting checkpoint steps 2–7 under the reader's own trust/policy → `held`/`conflicting`; `size` > held size or ≠ conflicting size → `size`; then `proof` (size 0; at held size: empty proof and held_root == held root; else RFC 9162 §2.1.4.2 consistency (size, held_root) → held; v2: split ≤ size; split 0 needs all-zero split_root and empty proofs; else each split proof as step 3 against its head, empty where split equals that head's size with split_root equal to that root); then `consistent` if held_root == conflicting root.

**C69 — §5.3.** "A device is expired exactly when `expires != 0 && expires <= T`".
Chose: as written; no clock → no expiry judged.

**C70 — §8.1 ladder.** "the **first row, read top to bottom, whose condition holds**".
Chose: unknown (no quorum time) → hard_stale (hard > 0 ∧ elapsed > hard) → fresh (elapsed ≤ S) → degraded.

**C71 — §15.** "The node's estimate of now is **the largest of the lower bounds** … The **age** of a held checkpoint is this estimate minus that checkpoint's quorum time."
Chose: estimate = max over pairs (q + now_mono − m) (seed counts as a pair observed at monotonic 0); age = estimate − held q.

**C72 — §15.** "`abs((wall - quorum_time) - age) > Δclock` … equality does not alarm".
Chose: as written, default Δclock 300 s.

**C73 — §4.0 grant (D-077).** "the label split on commas, each part trimmed … masked … duplicates removed, sorted as text … does not parse **as a whole** is **no grant**" / "An IPv4-mapped IPv6 prefix is no grant".
Chose: split on `,`; trim only U+0020 at both ends; `<addr>/<len>`; IPv4 four decimal octets 0–255 without leading zeros; IPv6 per RFC 4291 §2.2 (1–4 hex digits either case, ≤ one `::`, trailing dotted quad allowed, no zone); length decimal no leading zero ≤ 32/128; IPv4-mapped judged on the address value before masking (in `::ffff:0:0/96`); canonical text dotted quad or RFC 5952 lowercase (longest ≥ 2 zero-group run compressed, first on tie, embedded quad written as hex groups); dedupe after masking; sort bytewise; any failing or empty part → no grant; absent label → no grant.

**C74 — §6 anchors.** "through the newline that terminates the blank separator line".
Chose: SHA-256 of the note bytes up to and including the first "\n\n".

**C75 — §4.4 / §5.1 step 6.** "`after` present and > index → reject (`after`)".
Chose: index = position in the log (manifest order).

**C76 — §10.1 step 11.** "its entry 0 is not the genesis the anchor pins: replaying it alone aborts with `bad-genesis`".
Chose: run my entry-0 procedure on the served entry 0; size 0 → no entry 0 → `genesis` (or `rollback` under a held head, decided at step 10).

**C77 — §7 cosignature message.** "`<timestamp as decimal, no leading zeroes>`".
Chose: Go `strconv.FormatUint`.

**C78 — §9.1 witness `url`.** "`url`, when present, is text; empty text is allowed".
Chose: any text, not URI-validated; `anchor.type` any text, ignored.
