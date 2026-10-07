# decisions.md — readings chosen from SPEC.md alone

Written after reading SPEC.md (all 1982 lines) top to bottom and **before**
opening `testdata/vectors/README.md`, any `cases.json`/`manifest.json`, or
running any vector. Not edited after the first vector run.

Numbering: C01, C02, … Each item: the place, the reading chosen (**chosen**),
the readings rejected (**rejected**). Where the prose is unambiguous but a
format detail is delegated to an external spec that I must fill from memory
(no web), that is logged too, marked *[external]*.

## A. CBOR encoding profile (§4.0, §4.1)

- **C01 — Profile is enforced in the decoder, not in the schema.** §4.0 lists
  null/undefined/float/tag/indefinite/negative/non-shortest/unsorted/dup-key/
  invalid UTF-8/oversized key as profile rules and §12.1 says `entries-hostile/`
  is "at the decoder". **chosen**: a generic decoder that accepts any top-level
  item (scalar or container) and refuses every profile violation with its own
  error kind. **rejected**: typed decoding that only rejects what the schema
  cannot hold.
- **C02 — Simple values other than `false`/`true`.** §4.0 names booleans,
  `null`, `undefined` and floats; it is silent on the other simple values
  (0xe0–0xf3, 0xf8 xx). **chosen**: refuse them in the decoder. **rejected**:
  accept as opaque items and let the schema refuse.
- **C03 — "shortest form" covers every head argument** (integers *and* lengths)
  — the prose settles it; logged because it is the classic trap.
- **C04 — Integer cap.** ≤ 2⁶³−1; a uint64 above is refused **in the decoder**.
  **rejected**: accept up to 2⁶⁴−1 and refuse only in fields.
- **C05 — Map-key cap.** Every map key, at every depth (incl. `labels`), must be
  a text string of 1–23 **bytes**; an empty key is refused; a non-text key is
  refused. Checked in the decoder. **rejected**: characters; schema-only check.
- **C06 — Map key order.** Strictly increasing in bytewise order of the
  **encoded** key (header included) ⇒ shorter first, then bytewise. One
  comparison refuses both unsorted and duplicate keys.
- **C07 — Depth.** Containers only; top-level container = 1; scalars add 0;
  depth 8 accepted, 9 refused; checked on entering a container, before reading
  its contents. An embedded request restarts at 1. **rejected**: counting
  scalars; counting the top level as 0.
- **C08 — Size caps.** Input length > cap ⇒ refused before parsing; = cap
  accepted. Entry and request: 65535. Bundle: 81919. Trust: 65536. Evidence:
  65536. **rejected**: `≥ cap` refused.
- **C09 — Whole input consumed.** Trailing bytes after the top item ⇒ refused
  (decoder). Truncated input ⇒ refused.
- **C10 — UTF-8 validity** is checked for every text string (keys and values) in
  the decoder using Go's `utf8.Valid` (refuses surrogates and overlongs).
- **C11 — Decoder error precedence** inside one item: length cap first; then a
  single left-to-right streaming parse, so the first violation in byte order
  decides; depth is tested when a container header is read.
- **C12 — Byte-string fixed sizes** (`net` 16, `pk` 32, `sig` 64) are
  **schema** rules applied where the field is checked, not decoder rules:
  `net` and `sig` at §5.1 step 3, body `pk`/`wg_pk`/`device_pk` at step 8.
  Required by §5.1's "under-signed governance entry with a malformed body is
  `threshold`". **rejected**: size checks in the decoder.

## B. Entry envelope and schema (§4.0–§4.3, §5.1 steps 2–3)

- **C13 — Signature preimage** is rebuilt by canonically re-encoding the decoded
  envelope minus `sigs` (`norn/entry/v1\n` prefix + map of n−1 pairs in §4.1
  order). With a strict decoder this equals the received bytes with the `sigs`
  pair cut out. **rejected**: slicing raw bytes (equivalent here).
- **C14 — Step 3 contents.** Envelope keys exactly `{v,t,net,ts,body,sigs}` plus
  optional `after`; `v` uint and = 1; `t` text; `net` bytes of length 16 equal
  to `anchor.net`; `ts` uint; `after` uint; `body` map; `sigs` array of closed
  `{kid,role,sig}` maps with `kid` `^[0-9a-f]{16}$`, `role` ∈
  {root,signer,device}, `sig` exactly 64 bytes, sorted strictly by `kid`
  (bytewise on the 16-char text, which equals sort on the 8 raw bytes).
- **C15 — `t` that is text but unknown** passes step 3 and is `unknown-type` at
  step 4; a body that is a map but malformed for its type is judged at step 8.
- **C16 — Body closedness** for every type, including `rotate`/`revoke` where
  the §5.1 table says only "well-formed". **chosen**: closed (§4.0 "Bodies are
  closed schemas too").
- **C17 — `device_id` regex** `^[a-z0-9][a-z0-9.-]{0,63}$` matched against the
  whole string (Go `regexp` `$` is end-of-text). Byte length 1–64 follows.
- **C18 — `name`** (genesis) UTF-8 1–64 **bytes**; `reason` 0–256 bytes,
  optional, absent ≡ ""; `text` 0–4096 bytes (empty accepted for `note`).
- **C19 — `labels`** map text→text, ≤ 32 pairs, keys 1–23 bytes, values 0–256
  bytes. **An empty `labels` map that is present is accepted** (the spec bounds
  the count above only). **rejected**: refusing a present-but-empty map by
  analogy with `params`.
- **C20 — Reserved label hints `ip`/`endpoint`** never validated.
- **C21 — `params` value types**: `checkpoint_interval`, `staleness`, `mmd` are
  any uint (0 allowed, no upper bound beyond 2⁶³−1); `rotate_needs_signer` is a
  CBOR boolean only (uint 1 refused). **rejected**: range limits on the uints.

## C. Replay (§5.1, §5.2)

- **C22 — `entry_hash`** is SHA-256 of the raw bytes, recorded before decode,
  for every entry that reaches step 1 (entry 0 included). Entry 0's hash is in
  the seen set even when entry 0 aborts (moot: replay stops).
- **C23 — Index** used by `after` and `since_index` is the 0-based log position.
- **C24 — Step 7 counting** happens once per entry against the state before the
  entry; enroll/rotate/revoke thresholds are evaluated inside step 8 in the
  table's order.
- **C25 — A signature is valid** iff (role=`root` and `kid` ∈ state.roots) or
  (role=`signer` and `kid` ∈ state.signers) or (role=`device` and `kid` =
  kid(the device key this entry may be signed by)), **and** Ed25519 verifies
  over the preimage under the key that `kid` resolves to. Counting is by
  distinct kid per role. A `device` signature on a governance entry or `note`
  counts for nothing (well-formed, ignored).
- **C26 — `note` authorisation**: ≥ 1 valid `signer` **or** `root` signature;
  at step 7, before its body check.
- **C27 — `enroll`** order: body closed + `request` is a byte string present →
  request decodes under §16.1 (profile with its own depth restart, closed
  schema, field rules, `v`=1, `expires` > `ts` when present) **and**
  request.net = entry.net (`decode`) → request sig under its own `device_pk`
  (`no-device-sig`) → valid signers ≥ `signer_thr` (`threshold`) → `dup-id` →
  `dup-wg` (any active device).
- **C28 — `enroll` effect**: replaces the record wholesale; `status` active;
  `since_index` = index; `labels` {} if absent; `expires` 0 if absent; add
  `active_wg[wg_pk]`.
- **C29 — `rotate`** order exactly as the §5.1 row. "Known" = present in
  `devices` in any status. Device signature validity: `kid` = kid(current
  `device_pk`) for the first device check; `kid` = kid(new `device_pk`) for the
  proof of possession. **If the body's `device_pk` equals the current one**, the
  single device signature satisfies both checks (sigs cannot repeat a kid).
- **C30 — `rotate` effect**: delete `active_wg[old wg]`, set
  `active_wg[new wg]`, replace `wg_pk` (and `device_pk` if carried);
  `since_index` unchanged.
- **C31 — No `device_pk` uniqueness rule** at enroll or rotate (the document
  states none). **rejected**: inventing a `dup-key`/`dup-id`-style check.
- **C32 — `revoke`** authorisation is three independent tests, never pooled:
  signers ≥ `signer_thr`, **or** a valid `device` sig by the device's current
  key, **or** roots ≥ `root_thr`. Effect: status `revoked`, `since_index` =
  index, remove its `wg_pk` from `active_wg`; key fields, labels, expiry kept.
- **C33 — `signer_add`/`root_add`**: body `pk` must be 32 bytes (`decode`);
  `dup-key` compares `kid(pk)` against both roles.
- **C34 — `signer_remove`/`root_remove`**: `kid` format checked first
  (`decode`); `unknown-key` if not in that role; `root_remove` requires
  `len(roots)−1 ≥ root_thr` (`root-invariant`). Thresholds are not adjusted by
  removals.
- **C35 — `signer_thr`/`root_thr`**: `1 ≤ thr ≤ len(current set)`, else `bad-thr`.
- **C36 — `log_key`**: `pk` 32 bytes, `overlap` uint; appended even if the same
  pk was already appended or equals the trust key.
- **C37 — `policy` entry**: `text` ≤ 4096 bytes and must parse under §9.1's
  **grammar** rules only (no trust-file correspondence, no limit on `log`
  lines). Effect: `state.policy` = text.
- **C38 — `params` entry / genesis params**: non-empty, only §4.5 keys, right
  types; merge (overlay) key by key.
- **C39 — Genesis (entry 0)**: steps in the written order; all failures
  `bad-genesis`; body closed with `params` optional; `roots`/`signers`
  non-empty arrays of 32-byte keys, distinct **by key bytes**, disjoint;
  thresholds in range; bootstrap counts `root`-role signatures whose `kid` is
  the kid of a key in `body.roots` and that verify; `signer`/`device` sigs are
  ignored.
- **C40 — Aborted state** and **empty-log state** exactly as §5.1 says
  (`rejected` = `[{0,bad-genesis}]` vs `[]`, size 0, params defaults).

## D. Canonical state JSON (§5.3, §14)

- **C41 — Byte-valued map keys** (`active_wg` keys) are rendered as lowercase
  hex strings, like every byte string. **rejected**: base64.
- **C42 — `params`** always emits all four §4.5 keys.
- **C43 — `policy`** is "" until a `policy` entry; the trust file's policy is
  **not** copied into the state.
- **C44 — Key sort** is bytewise over UTF-8 of the bare key (not UTF-16).
- **C45 — Escapes** exactly §14.2; U+007F, U+2028/2029, `/`, `<>&` verbatim;
  C0 others `\u00xx` lowercase.
- **C46 — Entry mirror JSON** renders the decoded CBOR value with the same
  rules (bytes hex, booleans `true/false`), absent optional members absent.
- **C47 — `preimage_sha256`** (entry and request mirrors) is SHA-256 of the
  preimage **including** its domain prefix. **rejected**: CBOR part only.

## E. Signed notes (§7)

- **C48 — Text/signature split** at the **first** `\n\n`; the text is through
  the first `\n` of that pair. A note with no blank line, or with empty text
  (starts with `\n`), is malformed (`note`).
- **C49 — Signature block**: one or more lines, each `— <name> <b64>\n`; exactly
  one `0x0A` after the last; any blank line inside or after ⇒ `note`. Name is
  everything between the em-dash-space and the **first** following space; an
  empty name ⇒ `note`. Payload: standard padded canonical base64 (re-encode
  must match), decoded length exactly 68 or 76, for **every** line including
  strangers' lines ⇒ otherwise `note`.
- **C50 — No UTF-8 / control-character / size / signature-count limits on
  notes** beyond what §7 states (the document gives none; `\r` is content).
  **rejected**: importing `x/mod/sumdb/note`'s extra rules from memory.
- **C51 — Matching** a line to a key = name equal **and** 4-byte key id equal.
  After matching, the payload length must be the key's algorithm length (68 for
  `0x01`, 76 for `0x04`), else the matched-key failure code (`log-signature` /
  `cosignature`).
- **C52 — Log signature rule**: ≥ 1 line matches a trusted log key and every
  matching line verifies. Applied identically to receipts.
- **C53 — Cosignature message**: `cosignature/v1\ntime <decimal ts>\n` + note
  text; timestamp = payload bytes 4..12 big-endian.

## F. Checkpoints and the served log (§6, §10)

- **C54 — Checkpoint body**: exactly three text lines; size canonical decimal
  uint64 ("0" allowed, leading zero refused, sign refused); root canonical
  padded base64 of exactly 32 bytes. Failure ⇒ `checkpoint`. Origin compared by
  byte equality at step 5.
- **C55 — Verifier step order** exactly §10.1's table: unserved → note →
  log-signature → checkpoint → origin → cosignature → quorum → entries → head →
  fork/rollback → tiles. Missing entry bundle ⇒ `unserved` at step 8's place;
  missing hash tile ⇒ `unserved` at step 11's place.
- **C56 — Hash tile contents** *[external, tlog-tiles from memory]*: a level-L
  tile holds consecutive 32-byte hashes of complete subtrees of height 8L (L=0:
  leaf hashes). For tree size N, level L has ⌊N/256^(L+1)⌋ full tiles and one
  partial tile of width ⌊N/256^L⌋ mod 256 when that is non-zero; levels exist
  while ⌊N/256^L⌋ > 0. **Every** implied tile at every level is fetched and
  compared. **rejected**: checking level 0 only.
- **C57 — Entry bundles**: a full bundle has exactly 256 entries, a partial
  exactly W; leftover bytes or a short read ⇒ `entries`.
- **C58 — Learned log keys' note name** (§9.4): a `log_key` entry carries a raw
  `pk` only; I give it name = `origin` and algorithm `0x01` (from §2: "the log
  key's signed-note name MUST equal [origin]"), key id =
  SHA-256(origin‖0x0A‖0x01‖pk)[0:4]. **rejected**: matching learned keys by
  public key alone, ignoring name/id. *This is a format detail the document
  does not give directly.*
- **C59 — Trusted log keys** = trust `log_key` ∪ every `log_keys[].pk` of a
  state already accepted (never retired). A fresh reader has only the trust key.
- **C60 — Policy for acceptance and for `T`**: the trust file's for a first
  read; the last replayed `state.policy` (if non-empty) for later checkpoints.
- **C61 — Quorum time `T`** = max t over the distinct verifying-witness
  timestamps such that {w : newest_ts(w) ≥ t} satisfies the policy; each
  witness counts at its **newest** verifying line; `quorum none` ⇒ no clock;
  never satisfied ⇒ no clock.
- **C62 — Fork/rollback** (§10): at = min(cp.size, stored.size); served root at
  `at` recomputed from served entries; mine = stored.root if at = stored.size,
  else this node's branch root at `at` if it holds those entries; if it does
  not hold them and the candidate is shorter ⇒ `rollback` (no accusation).
  served ≠ mine ⇒ `fork`; else cp.size < stored.size ⇒ `rollback`; same size,
  same root ⇒ accepted (no change).

## G. Policy grammar (§9.1)

- **C63 — Line splitting**: on `0x0A`; a non-empty remainder after the last LF
  ⇒ error; control bytes checked over the **whole** text first (incl.
  comments). Comment = first non-space/tab char is `#`. Blank = only
  spaces/tabs.
- **C64 — Lines after the `quorum` line** are permitted (e.g. a witness defined
  after `quorum`), provided the quorum's referent was defined before it.
  **rejected**: `quorum` must be the last directive. *Not stated either way.*
- **C65 — Name charset**: any non-empty run of non-separator bytes; `none`
  cannot be defined; `all`/`any` allowed as names.
- **C66 — "Unicode space"** in key names = Go `unicode.IsSpace` (White_Space
  property: incl. U+0085, U+00A0, U+1680, U+2000–200A, U+2028/9, U+202F, U+205F,
  U+3000). **rejected**: category Zs only; ASCII only.
- **C67 — Verifier key parse**: split on `+` at most twice; name non-empty,
  no `+`, no Unicode space; id exactly 8 lowercase hex digits (**uppercase hex
  refused** — not stated; chosen strict); data canonical padded base64 of 33
  bytes; alg ∈ {0x01, 0x04} as the role requires; recomputed id must equal.
- **C68 — Duplicate keys** compared by the 32-byte public key across all `log`
  and `witness` lines.
- **C69 — Threshold**: `all`→n, `any`→1, else canonical decimal with 1 ≤ k ≤ n;
  n counts members (a nested group is one member).
- **C70 — Unknown directive keyword** ⇒ error.

## H. Trust file (§9)

- **C71 — Closed map**; `version`=1; `origin` = derived string exactly; `name`
  1–64 bytes; `genesis_hash` 32 bytes; `log_urls` array, ≥ 1, each non-empty
  text, duplicates allowed; `witnesses` ≥ 1 closed `{name,key,url?}`; `anchor`
  optional closed `{type(text), max_lag(uint), mode("advisory")}`.
- **C72 — Witness ↔ policy correspondence** is a set equality on names, and for
  each name the **full verifier key** (name, algorithm, public key — equivalent
  to the canonical text) must be equal. **rejected**: comparing public keys
  only.
- **C73 — The policy's `log` line** (if any) must equal `log_key` as a full
  verifier key. **rejected**: public key only. At most one `log` line in a trust
  policy (a second one cannot equal the first without being a duplicate key).
- **C74 — `log_key` note name = origin**, compared by byte equality.
- **C75 — Fingerprint** over the file bytes as received (canonical by
  construction); Crockford base32 of 10 bytes, MSB first, 4×4 with `-`.
- **C76 — Trust check order** is unobservable (one outcome: reject); I check
  size → CBOR → schema/fields → keys → policy → correspondence.
- **C77 — TOML rendering**: I parse only the shape §9.2 shows (`key = value`
  scalars, hex byte strings for `net`/`genesis_hash`, arrays of strings, inline
  table `anchor`, `[[witness]]` tables, `#` comments) and map back to CBOR.

## I. Receipts (§7)

- **C78 — Receipt key** is the trust file's `log_key` only ("the anchored log
  key"). **rejected**: also accepting learned `log_keys`.
- **C79 — Deadline** canonical decimal uint64. **rejected**: cap at 2⁶³−1.
- **C80 — Step 3** refuses both a wrong line count and a wrong header as
  `receipt`; the origin/leaf/deadline steps never run on a wrong-count note.

## J. Bundles (§8.1, §10.1)

- **C81 — Bundle length cap** refusal code = `bundle` (§10.1 gives no separate
  code). A proof element that is not 32 bytes, a wrong-typed member, or a
  missing/unknown key ⇒ `bundle` (closed typed map). **rejected**: `inclusion`
  for a malformed proof element.
- **C82 — Bundle checkpoint** is verified under the trust file's key and policy
  only (the bundle is "checkable by someone holding only `norn.trust`").
- **C83 — `device` member** may be any text; only the binding step judges it.
- **C84 — Binding**: decode the entry (profile + envelope shape); `enroll` ⇒
  embedded request's `device_id`; `rotate`/`revoke` ⇒ body `device_id`; any
  other type or an undecodable entry ⇒ `binding`. Signatures are not re-checked
  at this step.
- **C85 — Inclusion**: index ≥ size ⇒ `inclusion`; RFC 6962 path verification
  with the RFC 9162 §2.1.3.2 algorithm (*[external]*: §1 cites 6962 §2.1.1,
  which defines the path, not a verifier).

## K. Fork evidence (§11.1)

- **C86 — Steps and codes** exactly as tabulated (oversize → cbor → version →
  schema → policy → held → conflicting → size → proof → consistent). `version`
  absent / non-uint / ≠1 ⇒ `version` even when other keys are wrong.
- **C87 — Reader's policy and keys**: trust file's (the vectors' reader holds
  only `trust.cbor`).
- **C88 — Consistency proof** verified with the RFC 9162 §2.1.4.2 algorithm
  (*[external]*, compatible with RFC 6962 §2.1.2 ordering); `size` 0 ⇒ `proof`;
  `size` = held.size ⇒ proof must be empty and `held_root` = held root.

## L. Expiry, freshness (§5.3, §8.1, §15)

- **C89 — Expiry clock** is the checkpoint's quorum time `T`, not `T` plus
  monotonic elapsed. §5.3 and §13 say "the checkpoint's witness time"; §8.1's
  "a node's estimate of now … and under §5.3 judges no expiry at all" invites
  the other reading. **rejected**: judging expiry at the running estimate.
- **C90 — `elapsed`** is §8.1's (monotonic now − monotonic at learning this
  checkpoint's `T`). §15 defines age differently (newest seen `T` + monotonic
  since − this checkpoint's `T`); they differ when a newer `T` has been seen.
  **chosen** §8.1. **rejected** §15's estimate-based age.
- **C91 — Freshness ladder** in table order; `S_hard` = 0 means unconfigured.

## M. Enrollment request text form (§16.2)

- **C92 — bech32m** *[external, BIP-350 from memory]*: charset
  `qpzry9x8gf2tvdw0s3jn54khce6mua7l`, polymod generator
  {0x3b6a57b2,0x26508e6d,0x1ea119fa,0x3d4233dd,0x2a1462b3}, HRP expansion,
  constant 0x2bc830a3, separator = last `1`, ≥ 6 data chars, characters
  33–126 only, all-lower or all-upper, HRP must equal `norn` case-folded under
  the whole-string case rule, no 90-char limit.
- **C93 — Padding**: refused if the leftover bit count ≥ 5 or any leftover bit
  is 1.
- **C94 — Text files**: a single trailing `\n` (or `\r\n`) on a `.txt` is file
  framing, stripped before decoding. **rejected**: treating it as part of the
  string.
- **C95 — Standalone request check** = text layer → CBOR profile (cap 65535)
  → closed schema / field rules (incl. `expires > ts`) → signature. The
  request's `net` is compared against a network only at the entry layer.
  **rejected**: signature before field rules.
