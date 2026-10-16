# Decisions log — cold gate run 17

Written after reading `SPEC.md` in full and before opening `testdata/vectors/README.md`,
any manifest or any vector. Each entry: section, the exact words, what I chose, why.
Not edited afterwards; later doubts go in the report.

---

**C01 — Preamble, precedence of external specifications.**
Words: "Norn reuses these specifications verbatim; where they conflict with this document, they win, with one exception. §7 and §10 are Norn's profile ... and govern where they are stricter".
Choice: SPEC.md decides everything it states; an external specification only supplies what SPEC.md leaves to it (RFC 8032 arithmetic, RFC 9162 proof procedures, BIP-350 bech32m, RFC 6962 hashing, RFC 5952 text). Why: the task instruction says so, and read literally the sentence would let `tlog-checkpoint` extension lines override §6's "no extension lines" (a §6 rule, not §7/§10); §10.1 step 4 restates three lines with a code, so I follow SPEC.md.

**C02 — §3.1 item 1, valid point.**
Words: "32 bytes that are the canonical encoding (RFC 8032 §5.1.3) of a point of order exactly `L` ... `[L]P = O` and `P ≠ O`".
Choice: decode strictly per RFC 8032 §5.1.3 (y < p, reject x = 0 with sign bit 1, reject if no square root), then require P ≠ O and [L]P = O. Implemented from RFC 8032 in `math/big`, not via `crypto/ed25519` (which accepts small-order points). Why: the predicate is stated exactly; libraries differ, so I own the arithmetic.

**C03 — §3.1 item 3, signature verification.**
Words: "verifies under a key `A` ... only if `R` is a valid point; `S` ... MUST be less than `L` ... `[S]B = R + [k]A` ... the cofactorless one ... is the definition."
Choice: reject unless len = 64, R valid point, S < L (no reduction); k = SHA-512(R‖A‖M) mod L; compute [S]B − [k]A and compare its canonical encoding with R's 32 bytes (equal to point equality since R is canonical). A is also checked as a valid point at verify time (unobservable: item 2 admits no other key).

**C04 — §3.1 item 2, where key validity is enforced.**
Words: "MUST be a valid point wherever a key is admitted: a genesis, `root_add`, `signer_add`, `log_key` or `enroll` entry, a `rotate`'s incoming `device_pk`, and every verifier key a `policy` entry's text carries (§5), an enrollment request (§16), and a trust file's `log_key` and `witnesses` (§9). The policy that fork evidence carries (§11.1) is parsed the same way".
Choice: checked at exactly those points: genesis roots and signers (`bad-genesis`), root_add/signer_add/log_key `pk` and rotate incoming `device_pk` (`decode` in step 8's body check), every key on every line (log and witness) of any policy text parsed by the shared grammar (policy entry, trust file, evidence, anchor policy), request `device_pk` at request decode. Not checked: `wg_pk` (X25519, never signs).

**C05 — §3.1 item 2, step of the point check for governance entries.**
Words: "for a governance entry that step follows the root quorum, so an under-signed one is `threshold` first".
Choice: the point check is part of the first "body well-formed and closed (`decode`)" check of step 8, so step 7's quorum decides first.

**C06 — §4.0 allow-list.**
Words: "A Norn CBOR item is an unsigned integer (major type 0), a byte string (2), a text string (3), an array (4), a map (5), or one of the two simple values `false` (20) and `true` (21) ... as the single bytes `0xf4` and `0xf5` — and nothing else."
Choice: decoder refuses major 1, major 6, every major-7 byte except 0xf4/0xf5 (so 0xe0–0xf3, 0xf6, 0xf7, all of 0xf8–0xff), and additional info 28–31 for majors 0–5 (reserved or indefinite).

**C07 — §4.0 integer cap.**
Words: "Integers | major type 0 only; shortest form; ≤ 2⁶³−1."
Choice: every major-0 value in every Norn CBOR artifact above 2⁶³−1 is a decoder (profile) error. Length arguments are bounded separately (C12).

**C08 — §4.0 shortest form.**
Words: "Shortest form means every argument, not only integers."
Choice: every head argument (integer values and string/array/map lengths) must use the minimal encoding: < 24 inline, else the smallest of 1/2/4/8 bytes that holds it.

**C09 — §4.0 map-key cap.**
Words: "every **map key** is a text string of 1–23 bytes".
Choice: enforced inside the decoder for every map of every Norn CBOR artifact (entries, requests and their labels, trust files, bundles, evidence). A non-text key, an empty key, or a key over 23 bytes is a profile error. Why: §12.1 says the cap "is vectored at the decoder" and `requests-bad/oversize-label-key` is "refused by the decoder before the `labels` field rule".

**C10 — §4.0/§4.1 key order.**
Words: "keys **strictly increasing** in §4.1's order — the same comparison is what forbids a duplicate key"; "bytewise lexicographic order of their encoded form".
Choice: compare each key's full encoded bytes (header + content) with the previous key's; the new key must be strictly greater. Equal or smaller is one error.

**C11 — §4.0 nesting depth.**
Words: "Nesting depth is at most 8, counted in containers. The top-level map is depth 1 ... A scalar does not add depth ... its own nesting restarts at 1".
Choice: a container at depth d holds containers at depth d+1; a container at depth 9 is refused; scalars never count; a byte string's content is not parsed by the outer call; the embedded request is decoded by its own call starting at depth 1.

**C12 — §4.0 MAX_ENTRY_BYTES and per-artifact caps.**
Words: "an entry is at most that many bytes — as is an enrollment request"; bundles, trust files and evidence "each states its own bound".
Choice: the decoder takes the artifact's cap: entries and requests 65535 (also the generic decoder used for `entries-hostile/`), bundle 81919, trust 65536, evidence 65536. Input longer than the cap is refused before parsing. A string/array/map header declaring more bytes (or more items) than remain in the input, or more than the cap, is refused before anything is allocated; a declared length above the cap is classed as a size violation, one merely above the remaining input as truncation.

**C13 — §4.0 whole input.**
Words: "A decoder MUST consume the **whole** input".
Choice: bytes after the top-level item are a profile error (`decode` for an entry).

**C14 — §4.0 UTF-8.**
Words: "Text strings | definite length; valid UTF-8".
Choice: RFC 3629 validity (Go `utf8.Valid`: no overlongs, no surrogates, nothing above U+10FFFF), applied to every text string including map keys.

**C15 — §4.0 decoder error precedence.**
Words: (none — the spec gives no order among profile violations).
Choice: size cap first, then one left-to-right pass reporting the first violation in byte order; for a map pair the key is decoded and checked (type, 1–23 bytes, UTF-8) before it is compared with the previous key, then the value is decoded.

**C16 — §4.0 booleans.**
Words: "Booleans | valid CBOR items; schemas MUST reject them outside `params.rotate_needs_signer`".
Choice: a boolean anywhere else is a schema fault of that artifact (`decode`, `bad-genesis`, `bundle`, `schema`, invalid trust file).

**C17 — §4.0 derived hashes.**
Words: "`entry_hash` | `SHA-256` of the entry **as received**"; "`content_hash` | `SHA-256` of the signature preimage"; "signature preimage | the 14-byte prefix `norn/entry/v1\n` ..., then the envelope encoded **without** the `sigs` key".
Choice: entry_hash over the raw bytes; content_hash over the prefix plus the canonical re-encoding of the decoded envelope with `sigs` removed (identical to the received bytes minus that pair, since the received bytes are canonical).

**C18 — §4.0 `sigs` well-formedness.**
Words: "closedness, `kid` matching its field constraint, `role` within the enum, `sig` exactly 64 bytes, and the array sorted by `kid` with no repeats."
Choice: each element is a map with exactly `kid` (text, `^[0-9a-f]{16}$`), `role` (text, one of `root`/`signer`/`device`), `sig` (bytes, 64); the array is strictly increasing by kid text bytes. All three keys required. Any failure: `decode` at step 3.

**C19 — §4.0 `device_id`.**
Words: "matches `^[a-z0-9][a-z0-9.-]{0,63}$` **as a whole**".
Choice: byte-level check, no regex engine: first byte in [a-z0-9], the rest in [a-z0-9.-], total 1–64 bytes.

**C20 — §4.0 `labels`.**
Words: "map text→text; ≤ 32 entries; keys 1–23 bytes ...; values ≤ 256 bytes, the empty value included; a `labels` map, when present, MUST carry at least one pair".
Choice: present ⇒ 1–32 pairs, values text of 0–256 bytes; a non-text value is a schema fault.

**C21 — §4.0 genesis key arrays.**
Words: "arrays of 32-byte `pk`, no duplicates, no key in both".
Choice: duplicates and overlap compared by public-key bytes; each element must be a 32-byte byte string and a valid point (C04); arrays non-empty.

**C22 — §4.0 reserved labels.**
Words: "their hint syntax MUST NOT be validated".
Choice: `ip` and `endpoint` values get only the generic label rules during request checking and replay; the grant is derived separately (C23) and never refuses an entry.

**C23 — §4.0 grant derivation (D-077).**
Words: "the label split on commas, each part trimmed and parsed as an IPv4 or IPv6 prefix, masked to its prefix, duplicates removed, sorted as text"; "once U+0020 is removed from both of its ends and nothing else is"; "groups of one to four hexadecimal digits in either case, at most one `::`, a dotted quad allowed in place of the last 32 bits, and no zone"; "An IPv4-mapped IPv6 prefix is no grant either".
Choice: split on `,`; strip only U+0020 from both ends; part = address `/` length, exactly one `/`; dotted quad = four decimal octets 0–255 without leading zero ("0" allowed); length decimal without leading zero ("0" allowed), ≤ 32 / ≤ 128. IPv6: `::` at most once and standing for at least one zero group; without `::` exactly 8 groups (an embedded quad counts as 2 and must be last); with `::` at most 7 explicit groups; the embedded quad uses the same octet grammar; empty groups otherwise invalid. IPv4-mapped is tested on the address **as written, before masking** (first 80 bits 0, next 16 bits 1). Masked, rendered RFC 5952 (lowercase, no leading zeros, compress the longest run of two or more zero groups, the first on a tie, a single zero group not compressed, embedded quads rendered as two hex groups); deduplicated; sorted bytewise as strings. Any failing part (including an empty part) ⇒ no grant, represented as an empty list. Absent label ⇒ no grant.

**C24 — §4.1 envelope.**
Words: "`v`, `t`, `net`, `ts`, `body` and `sigs` are all **mandatory**; `after` and `prev` are the only optional keys"; §5.1 step 3 "(`t` text, `ts`, `after` and `prev` uint, `body` a map), `v` = 1, `net` = `anchor.net`, well-formed `sigs`".
Choice: `net` must be a byte string of exactly 16 bytes equal to the anchor's; `v` a uint equal to 1; any other key is `decode`.

**C25 — §4.3 body schemas.**
Words: the §4.3 table; "Bodies are closed schemas too".
Choice: genesis {name, roots, root_thr, signers, signer_thr, params?}; enroll {request: bytes}; rotate {device_id, wg_pk: bytes32, device_pk?: bytes32}; revoke {device_id, reason?: text 0–256}; signer_add/root_add {pk: bytes32}; signer_remove/root_remove {kid: hex16 text}; signer_thr/root_thr {thr: uint}; params {subset of §4.5}; note {text: text ≤ 4096}; log_key {pk: bytes32, overlap: uint}; policy {text: text ≤ 4096}. Missing required, unknown key or wrong type ⇒ `decode`.

**C26 — §4.3/§5.2 rotate signatures.**
Words: "one valid signature for each *distinct* key among the two, so an incoming key that is the current key needs its one signature and no other".
Choice: current-key check = a `device`-role signature whose kid is kid(current device_pk) and which verifies; incoming-key check = a `device`-role signature whose kid is kid(incoming device_pk) and which verifies (the same one when the keys are equal).

**C27 — §4.3 revoke authorisation.**
Words: "≥ `signer_thr` signers, **or** the device itself, **or** ≥ `root_thr` roots".
Choice: three independent tests, never pooled; "the device itself" = a verifying `device`-role signature by the named device's current `device_pk` only (another device's key does not count).

**C28 — §4.3 note.**
Words: "any 1 signer or root".
Choice: at least one verifying signature by a current signer (role `signer`) or current root (role `root`).

**C29 — §4.3/§5.2 signature counting.**
Words: "a key counts only for the role it currently holds"; "`kid` names a key this entry may be signed by **in that role**".
Choice: a `root`-role signature counts only if its kid is in the pre-entry `roots`; `signer` only if in `signers`; counts are of distinct kids; failures are ignored. Enroll and rotate (with `rotate_needs_signer`) count only signers.

**C30 — §4.4 `prev` presence.**
Words: "**present and equal** where the object exists, **absent** where it does not — which is only an `enroll` of a `device_id` that no accepted entry has ever named".
Choice: a device object exists iff a device record exists (records persist after revoke and are replaced by re-enrolment). Governance objects exist from genesis (version 0), so `prev` is always required for them.

**C31 — §4.4 objects.**
Words: the object table.
Choice: signer_add/signer_remove/signer_thr → `versions.signers`; root_add/root_remove/root_thr → `versions.roots`; params → `versions.params`; policy → `versions.policy`; log_key → `versions.log_key`; enroll/rotate/revoke → the record's `version`.

**C32 — §4.5 params.**
Words: types in the table; "`routes` is the one text-valued parameter and its value set is closed".
Choice: `checkpoint_interval`, `staleness`, `mmd` uint; `rotate_needs_signer` boolean only (a uint 1 is refused); `routes` text in {`granted`, `advisory`}.

**C33 — §5 anchor's `log_key` and `policy`.**
Words: "The last two are read by one rule only — the log/witness key invariant".
Choice: `anchor.log_key` is parsed as a verifier key to get its public key; `anchor.policy` is parsed by the shared grammar to get witness-line keys. If either fails to parse it contributes no key (the spec is silent; a trust file that passed §9 always parses).

**C34 — §5.1 entry 0.**
Words: steps 1–8 and "Abort ... `rejected` holds exactly `{index: 0, reason: "bad-genesis"}` and `size` is 0 ... `params` at the §4.5 defaults".
Choice: steps in the written order; abort state: name "", net from anchor, size 0, thresholds 0, empty maps/arrays, params defaults, policy "", versions all 0, rejected [{0, bad-genesis}]. Genesis signatures: `root`-role signatures whose kid is kid of a body root, verified against that root, counted distinct.

**C35 — §5.1 empty log.**
Words: "Replay of an **empty** list of entries yields the zero state of §5.3 with `size` 0 and `rejected` empty".
Choice: the abort state with `rejected` = [] (params at defaults, net from anchor).

**C36 — §5.1 step 1 ordering.**
Words: "An entry whose `entry_hash` is in the first set, or that decodes and whose `content_hash` is in the second → reject (`dup-entry`)"; "the hash is the one of an entry steps 2 and 3 accept".
Choice: (1) entry_hash seen ⇒ `dup-entry`, else record it; (2) decode ⇒ `decode`; (3) envelope ⇒ `decode`; then content_hash seen ⇒ `dup-entry`; then steps 4…8. content_hash recorded only when the entry is applied (including entry 0).

**C37 — §5.1 step 3 scope.**
Words: "exactly the permitted keys, every member of the type §4.1 gives it ..., `v` = 1, `net` = `anchor.net`, well-formed `sigs`".
Choice: body closedness and body field rules belong to step 8, not step 3.

**C38 — §5.1 step 7.**
Words: "For the governance types (...): fewer than `root_thr` valid `root` signatures → reject (`threshold`). For `note`: no valid `signer` or `root` signature".
Choice: as written; genesis never reaches it (step 5); enroll, rotate, revoke check signatures inside step 8.

**C39 — §5.1 step 8 orders.**
Words: the type table "checks, in order".
Choice: exactly as tabled. enroll: body/request present → request decode and net (`decode`) → request signature (`no-device-sig`) → signers (`threshold`) → prev → dup-id → dup-wg. rotate: body incl. incoming point (`decode`) → unknown-device → not-active → current key sig → signers if required → prev → dup-wg (another device) → incoming key sig. revoke: body → unknown-device → not-active → authorisation → prev. signer_add/root_add: body (32 bytes, valid point) → prev → dup-key (kid in either role). signer_remove: body → prev → unknown-key. root_remove: body → prev → unknown-key → root-invariant (remaining ≥ root_thr and ≥ 1). thresholds: body → prev → bad-thr (1 ≤ thr ≤ len(set)). log_key: body/pk/overlap/point → prev → witness dup-key → active-log-key dup-key. policy: body → ≤ 4096 → parse incl. points → prev → dup-key. params: body/keys/types/non-empty → prev. note: body → ≤ 4096 → prev absent.

**C40 — §5.1 log_key vs the policy in force.**
Words: "`pk` is not the public key of any witness the policy in force names — `policy` when it is non-empty, else `anchor.policy`".
Choice: only `witness` lines count (a `log` line names no witness); compared as public-key bytes.

**C41 — §5.1 policy entry.**
Words: "`text` MUST parse as `c2sp.org/tlog-policy`"; §9.1 "That limit is the trust file's, not the grammar's: a `policy` entry (§5.1) has no such correspondence."
Choice: the shared grammar only (several `log` lines allowed, no correspondence with any trust file); dup-key compares `witness`-line public keys with the active log keys (anchor key and every `log_keys` pk); `log` lines are not compared.

**C42 — §5.1 params entry.**
Words: "non-empty, only §4.5 keys, each of the right type (`decode`)".
Choice: as written; the effect merges key by key into the current params.

**C43 — §5.1 expiry.**
Words: "Entries whose `expires` has passed are treated as `revoked` at **evaluation time** (§5.3), not at replay".
Choice: replay never looks at `expires`; status stays `active` in the state.

**C44 — §5.2 `unknown-device` vs `not-active`.**
Words: "names a `device_id` never enrolled" / "a device that is already `revoked`".
Choice: known = a record exists; revoked record ⇒ `not-active`.

**C45 — §5.3/§14 state JSON.**
Words: field tables; "byte strings | **lowercase hex**".
Choice: `net`, keys, `wg_pk`, `device_pk` as lowercase hex; `active_wg` keyed by hex of `wg_pk`; `params` always carries all five keys (bool for `rotate_needs_signer`, string for `routes`); `labels` {} when none; `expires` 0 when none; all members always present.

**C46 — §5.3 evaluation time T.**
Words: "the newest instant such that the witnesses whose cosignature timestamp is at or after it satisfy the policy"; "A witness counts once. Two verifying lines from the same witness with different timestamps are its newest"; "Under `quorum none` there is no clock."
Choice: for each witness named by the policy that accepted the checkpoint, take the newest timestamp among its verifying lines; candidate instants are those timestamps; T = the largest candidate t such that {w : ts_w ≥ t} satisfies the quorum; none satisfies ⇒ no clock; `quorum none` ⇒ no clock. A `policy` entry inside the replayed range does not change this checkpoint's T.

**C47 — §5.3 expiry.**
Words: "A device is expired exactly when `expires != 0 && expires <= T`".
Choice: as written; with no clock, expiry is not judged and the device keeps its replayed status.

**C48 — §6 tile geometry.**
Words: "Tile height 8 (width 256) ... level `L` covers 256^(L+1) leaves".
Choice: hash k of tile (L, N) is the RFC 6962 node at height 8L with index 256N + k (a complete subtree of 256^L leaves). For size n, level L has m = ⌊n / 256^L⌋ such nodes; tiles N = 0 … ⌈m/256⌉−1, the last partial with width m mod 256 when that is non-zero; levels continue while m ≥ 1.

**C49 — §6 paths.**
Words: "three-digit groups, most significant first, joined by `/` ... every group but the last prefixed `x`"; "`.p/<W>`".
Choice: as written; `tile/entries/<N>` for bundles.

**C50 — §6 D-079 fallback.**
Words: "a verifier that cannot fetch `tile/<L>/<N>.p/<W>` MAY fetch `tile/<L>/<N>` and use its first `W` hashes, and likewise the full entry bundle ...; what it uses is compared with the tree it rebuilt exactly as the partial path would have been".
Choice: for a missing partial hash tile, the full tile must hold at least 32·W bytes and only its first W hashes are compared; bytes after them are not judged. For a missing partial bundle, the first W frames of the full bundle are read and the remainder is not judged. Only when both paths are absent is it `unserved`.

**C51 — §6 checkpoint body.**
Words: "the tree size in decimal with **no leading zeroes** and at most 2⁶³−1"; "standard base64 with padding, 32 bytes once decoded ... canonical".
Choice: size: ASCII digits only, "0" allowed, no leading zero otherwise, ≤ 2⁶³−1; root: canonical padded standard base64 of exactly 32 bytes. Exactly three text lines.

**C52 — §6 anchor digest.**
Words: "the three body lines **plus the blank line**, four `0x0A` in all".
Choice: SHA-256 over the note's bytes from the start through the LF ending the blank separator line.

**C53 — §7 note splitting.**
Words: "the **first** blank line ends the text"; "a note whose first line is blank ... is `note`"; "Every signature line, including the last, ends in one `0x0A`—exactly one"; "A note carries **at least one signature line**".
Choice: the note must end in LF; lines are split on LF; the first empty line ends the text; first line empty ⇒ `note`; no empty line ⇒ `note`; zero signature lines ⇒ `note`; any empty line after the separator ⇒ `note`.

**C54 — §7 whole-note characters.**
Words: "The signed text and every signature line MUST be valid UTF-8, and MUST NOT contain an ASCII control character below U+0020 other than the line feeds".
Choice: checked over the entire note before any line is parsed; DEL (0x7F) is allowed.

**C55 — §7 signature line grammar.**
Words: "`— ` (em dash U+2014, then one space), the key name, one space, then base64 of a payload"; "the line splits at its **first** space"; name "one or more characters, none of them `+` and none a Unicode white-space character" (the list).
Choice: prefix bytes E2 80 94 20; name = bytes up to the first U+0020; payload = the rest; no space after the name ⇒ `note`; name empty, holding `+` or a listed white-space character ⇒ `note`; payload must be canonical padded standard base64 (length a multiple of 4, re-encoding reproduces it) decoding to ≥ 4 bytes, else `note`.

**C56 — §7 matching and length.**
Words: "What follows the key id is judged by the trusted key whose name and key id the line matches. A line that matches no trusted key is ignored whatever its length".
Choice: a line matches a key iff name equals the key's name and payload[0:4] equals its id. Alg 0x01 ⇒ exactly 68 bytes; alg 0x04 ⇒ exactly 76. Wrong length under a matched key is that key's failure (`log-signature` / `cosignature`).

**C57 — §7 cosignature.**
Words: "at most 2⁶³−1 ... fails that witness's check, `cosignature`, before its signature is verified"; message "`cosignature/v1\n` ‖ `time ` ‖ <decimal> ‖ `\n` ‖ <note text>".
Choice: as written; note text = the signed text through its final LF.

**C58 — §7 verifier keys.**
Words: "`<name>+<key_id as 8 lowercase hex digits>+<base64(alg ‖ pk)>`. Split it on `+` **at most twice**"; name "one or more ASCII bytes from `0x21` to `0x7E`, `+` excluded"; "33 bytes encode to 44 base64 characters without padding ... Decoding and re-encoding MUST reproduce the exact data text".
Choice: as written; recomputed id must equal the declared one; the data must decode to exactly 33 bytes; the public key must be a valid point; the algorithm required (0x01 or 0x04) is checked by the context.

**C59 — §7 receipts.**
Words: the eight-step list.
Choice: in order; step 2 uses every trusted log key (trust file's plus learned), and any matching line that fails (signature or length) is `log-signature`, as for checkpoints; step 3 exactly four lines and first line `norn/receipt/v1`; deadline "0" is canonical; checking time 0 skips step 8.

**C60 — §8.1 bundle schema.**
Words: "a closed map of exactly these six keys"; "`MAX_BUNDLE_BYTES` is 81919 ... refused on length".
Choice: cap first, then the profile decoder (cap 81919), closed map {v=1, device (§2 grammar), index uint, entry bytes, proof array of exactly-32-byte strings, checkpoint text}; every failure `bundle`. A proof hash of another length is `bundle`, not `inclusion`.

**C61 — §8.1 bundle checkpoint.**
Words: "verify its checkpoint per §10 — this network's origin, a log signature and a satisfied witness quorum".
Choice: loop steps 2–7 only, with the reader's trusted log keys and policy in force.

**C62 — §8.1 inclusion.**
Words: "verified per RFC 9162 §2.1.3.2: exactly the hashes that procedure consumes".
Choice: RFC 9162 §2.1.3.2 with the final `sn == 0` check; index ≥ size ⇒ `inclusion`.

**C63 — §8.1 binding.**
Words: "confirm that **`device` is the `device_id` the `entry` names** — for an `enroll`, the id inside the embedded request; for the other device types, the `device_id` in the body"; "an entry whose request does not decode, or whose body names no `device_id`, names no device".
Choice: decode the entry under §4.0 (profile only, entry cap); it must be a map with text `t` and map `body`; `enroll` ⇒ `body.request` bytes decoded under §16.1 (structure, fields and point; no signature and no net comparison) gives the id; `rotate`/`revoke` ⇒ `body.device_id` text; any other type or failure ⇒ no device ⇒ `binding`. No other envelope rule is applied.

**C64 — §8.1 entry size in a bundle.**
Words: "`MAX_ENTRY_BYTES` does not apply to a bundle".
Choice: no separate cap on the embedded entry beyond the bundle cap.

**C65 — §8.1 freshness.**
Words: the ladder; "`elapsed > params.staleness` makes it stale"; "zero means not configured".
Choice: first row that holds of: unknown (no quorum time) → hard_stale (S_hard > 0 and elapsed > S_hard) → fresh (elapsed ≤ S) → degraded.

**C66 — §9.1 trust file.**
Words: the field table and "Unknown keys MUST cause rejection"; "`MAX_TRUST_BYTES` is 65536".
Choice: cap, profile decoder (cap 65536), closed map with version=1, net 16 bytes, origin = derived (exact case), name 1–64 bytes, genesis_hash 32 bytes, log_key (vkey, alg 0x01, name = origin, valid point), log_urls ≥ 1 non-empty texts, witnesses ≥ 1 closed maps {name, key, url?} with name 1–64 bytes of the policy name grammar and unique, key alg 0x04 with recomputed id and valid point, url text (empty allowed); no witness public key equal to the log key's; policy parses and corresponds; anchor optional closed {type text, max_lag uint, mode = "advisory"}, unknown type ignored.

**C67 — §9.1 correspondence.**
Words: "MUST name **exactly** the witnesses `witnesses` lists, with the same keys ... compared as canonical text"; "A `log` line ... MUST be `norn.trust.log_key`"; "The correspondence is on the **set** of names".
Choice: the set of policy `witness` names equals the set of `witnesses[].name`; for each name the vkey text is byte-equal; at most one `log` line, and it must be byte-equal to `log_key`; URLs not compared.

**C68 — §9.1 trust policy size.**
Words: "`text` (`note`, `policy`) | UTF-8, ≤ 4096 bytes" is a field constraint of entries.
Choice: the 4096-byte cap does not apply to a trust file's policy (bounded only by the file cap).

**C69 — §9.1 anchor.**
Words: "**an unknown `type` is ignored** ... **`mode` MUST be `"advisory"`**".
Choice: as written; `max_lag` any uint.

**C70 — §9.1 policy grammar.**
Words: the rule table.
Choice: text must end in LF; split into lines on LF; bytes 0x00–0x08, 0x0B–0x1F, 0x7F anywhere ⇒ error; lines of only space/tab ignored; lines whose first non-space/tab byte is `#` ignored; fields = runs of non-space/tab (trailing whitespace adds no field); keyword exact lowercase `log`/`witness`/`group`/`quorum`, otherwise error; field counts as stated; witness/group names: ASCII 0x21–0x7E without `+`, ≤ 64 bytes, one shared namespace, defined once, `none` reserved; members previously defined, no duplicate, not `none`; exactly one `quorum` naming a previously defined name or `none`; every vkey parsed per C58 with `log` 0x01 and `witness` 0x04, valid points, and no public key twice across all lines; URL fields are opaque tokens. Text must be valid UTF-8 where it comes from CBOR.

**C71 — §9.1 group threshold.**
Words: "`all` is `n`, `any` is 1, and a count is **canonical decimal** with `1 ≤ k ≤ n`".
Choice: digits only, no leading zero, 1 ≤ k ≤ n.

**C72 — §9.1 evaluation.**
Words: "a `group` may name a `group`. It counts as **one** member of the outer group".
Choice: a witness is satisfied iff it is among the verifying cosigners; a group iff at least k of its members are satisfied; `none` is always satisfied.

**C73 — §9.3 fingerprint.**
Words: "The first **10 bytes** of `SHA-256(CBOR(trust))` ... Crockford base32 ... four groups of four joined by `-`"; "followed by one `0x0A`".
Choice: as written, over the exact file bytes.

**C74 — §9.4 trusted log keys.**
Words: "A learned key is the verifier key `<origin>+<id>+base64(0x01 ‖ pk)`"; "no separate activation index"; "a learned key is **never retired**"; "Norn takes the log key it verifies with from `log_key`, never from here" (§9.1 log lines).
Choice: trusted = the trust file's `log_key` plus one key per `log_keys` row named the origin with id computed from (origin, 0x01, pk), usable for every checkpoint whatever its size; policy `log` lines are never trusted for verification.

**C75 — §9.4 policy in force.**
Words: "A `policy` entry supersedes `norn.trust.policy` for every checkpoint a node accepts after replaying it".
Choice: the replayed state's `policy` when non-empty, else the trust file's.

**C76 — §10/§10.1 loop order.**
Words: the outline and §10.1 table.
Choice: unserved(checkpoint) → note → log-signature → checkpoint → origin → cosignature → quorum → entries (fetch; `unserved` if a bundle is absent) → head → fork/rollback (only with a stored head) → genesis → tiles (`unserved` if a tile is absent).

**C77 — §10 stored head comparison.**
Words: "at := min(cp.size, stored_cp.size) ... a node that does not hold `at` cannot tell a fork from a rollback; it refuses below and MUST NOT accuse".
Choice: served root at `at` computed from the served entries; mine = stored root when at = stored size, else the root of the node's own branch at `at` from its own mirror; differ ⇒ `fork`; then cp.size < stored size ⇒ `rollback`. A node without its own branch at `at` (only possible when at < stored size) skips the comparison and answers `rollback`.

**C78 — §10.1 step 11.**
Words: "the served log has no entry 0, or its entry 0 is not the genesis the anchor pins: replaying it alone aborts with `bad-genesis`".
Choice: run the entry-0 procedure on the served entry 0 against the anchor; abort or absence ⇒ `genesis`.

**C79 — §10.1 step 12.**
Words: "a tile of width `W` is exactly 32 × `W` bytes"; "The served `tile/<L>/…` hashes MUST also agree".
Choice: every tile the size implies at every level; partial ⇒ exactly 32·W bytes; full ⇒ exactly 8192 bytes; fallback per C50.

**C80 — §11.1 evidence steps.**
Words: the step table and the reader list.
Choice: oversize (> 65536) → cbor (profile with cap 65536, or not a map) → version (absent / not uint / not 1|2) → schema (exact key set for the version; held/conflicting/policy text; size/split uint; held_root/split_root exactly 32 bytes; proof arrays of exactly-32-byte strings) → policy (shared grammar with points) → held (§10 steps 2–7 under the reader's keys and policy) → conflicting → size (size > held size, or conflicting size ≠ size) → proof → consistent.

**C81 — §11.1 proof step details.**
Words: "`size` 0 never passes"; "Empty when `size` equals `held`'s size"; "A `split` that is 0 carries an all-zero `split_root` and two empty proofs".
Choice: size 0 ⇒ `proof`; size = held size ⇒ proof must be empty and held_root = held root; else RFC 9162 §2.1.4.2 from (size, held_root) to (held size, held root) with exact consumption. v2: split > size ⇒ `proof`; split = 0 ⇒ split_root all zero and both split proofs empty, else `proof`; split > 0 ⇒ each split proof checked like the main one against its head (empty and root-equal at that head's own size). All before `consistent`.

**C82 — §14 canonical JSON.**
Words: §14.1 and §14.2 tables.
Choice: as written; keys sorted by UTF-8 bytes; only the listed escapes, other C0 as `\u00xx` lowercase; final LF.

**C83 — §16.1 request.**
Words: the field table; "`expires` ... MUST be > `ts`".
Choice: closed map, required v (=1), ts, net (16), sig (64), wg_pk (32), device_id (§2), device_pk (32, valid point); optional labels (C20) and expires (> ts). Preimage "norn/enroll-request/v1\n" ‖ canonical encoding without `sig`.

**C84 — §16.1 consumer order.**
Words: "MUST validate structure **and** verify `sig` before showing ... MUST also refuse a request whose `net` is not the network it serves".
Choice: text layer → CBOR profile → schema and fields → signature → network.

**C85 — §16.2 text form.**
Words: "bech32m (BIP-350), HRP `norn`"; "Mixed case MUST be rejected"; "padding is 5 bits or more, or whose padding bits are not zero"; "BIP-173's 90-character limit does not apply".
Choice: whole string all-lowercase or all-uppercase; characters 33–126; separator = last `1`; HRP must be `norn` after lowercasing; ≥ 6 data characters; checksum constant 0x2bc830a3 (constant 1 rejected); 5→8 regroup without padding acceptance beyond < 5 zero bits; no length limit other than the decoded payload's 65535. A `.txt` file's single trailing LF, if present, is file framing and is removed; any other whitespace is an invalid character.

**C86 — §12 `says`.**
Words: "`says` is a **semantic hint** ... What a reader compares is the `codes` map wherever a manifest has one".
Choice: the harness compares closed codes; where only `says` exists, the harness checks the outcome (accept/refuse) and maps the rule by hand.

**C87 — §8.1 condition 3 installs.**
Words: "the key the node installs for it is **the `wg_pk` replay gives**".
Choice: installs = the replayed `wg_pk` of each device active (and, with a clock, unexpired) at the bundle's checkpoint; a revoked device installs nothing.

**C88 — §15 age.**
Words: "The node's estimate of now is **the largest of the lower bounds** it holds"; "The **age** of a held checkpoint is this estimate minus that checkpoint's quorum time".
Choice: estimate = max over recorded pairs (q, m) of q + (now_m − m); age = estimate − q_held.

**C89 — §5.1 enroll request decode inside an entry.**
Words: "the request decodes under §16.1 and its `net` equals the entry's (`decode`)".
Choice: full §16.1 decode (profile with its own depth/size, closed schema, fields, point, expires > ts), then net equality; both `decode`; signature after.

**C90 — §5.2 enroll `dup-wg`.**
Words: "For `enroll` that means active for **any** device".
Choice: `wg_pk` present in `active_wg` at all.
