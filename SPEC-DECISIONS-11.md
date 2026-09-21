# Running log: decisions SPEC.md did not make for me

Recorded *as I hit them*, before consulting any vector. Each entry: what I had to
decide, what the document says (or fails to say), what I chose, and how I could
tell if I chose wrong.

(Numbered D-n in order encountered; the report renumbers them.)

## D-1 — the CBOR error vocabulary is not specified, but `cases.json` keys off it
`entries-hostile/cases.json` gives each negative a `says` string the refusal
"must be about" (e.g. `simple value`, `deeper than`, `map key must be 1-23 bytes`).
SPEC.md never states any error strings. I matched my messages to those phrases.
A second implementer writing from SPEC.md alone would produce different strings
and could not self-check against `cases.json`. Not an interop defect (the strings
never cross the wire) but a suite-usability one.

## D-2 — `null` is "forbidden" but the vector wants "simple value"
§4.0 bans `null` by name and `undefined` by name. CBOR major type 7 also has
`true`/`false` (allowed), the 0..19 simple values, and simple value 24. SPEC.md
never says what happens to simple value 0..19 or 24 other than null/undefined
(i.e. an unassigned simple like `0xf0`). I decided: every mt7 argument other
than 20 (false) and 21 (true) is refused. The document does not say this;
it enumerates three of the values and leaves the rest to inference.

## D-3 — what "≤ 2^63−1" applies to
§4.0's Integers row caps integers at 2^63−1. It does not say whether a
*length header* (bstr/tstr/array/map count) above 2^63−1 is the same violation
or a different one, nor whether an 8-byte length header must also be ≤ 2^63−1.
I applied the cap to every mt-0 integer *value* and, separately, refused any
length header that exceeds the remaining input.

## D-4 — depth counting for the top-level scalar
§4.0 says "the top-level map is depth 1" and "a scalar does not add depth".
For `entries-hostile/bare-float` the top-level item *is* a scalar. Depth of a
bare scalar is therefore 0, which is fine. Unstated but harmless.

## D-5 — where MAX_ENTRY_BYTES is enforced
§4.0 says an entry is at most 65535 bytes and `entries-hostile/oversize-entry`
is "a header promising 65536 bytes, refused on length before anything is
allocated". SPEC.md does not say whether the 65535 cap is (a) a check on the
input buffer length before decoding, or (b) a check on declared lengths during
decoding. The vector needs (b) as well as (a) — a 5-byte file whose header
promises 65536 must be refused "on length". I implemented both.

## D-6 — the `sigs` sort comparison
§4.0: "`sigs` … sorted by `kid` bytewise". `kid` is a 16-char lowercase hex
*text string*. "bytewise" on the text is the same as on the decoded hex here, so
the ambiguity is harmless — but the document never says which. Chose: bytewise
over the UTF-8 of the `kid` text.

## D-7 — whether field constraints are checked on fields a type does not use
§4.0's field-constraint table is keyed by field *name* (`device_id`, `name`,
`reason`, `text`, `labels`, `kid`). §4.3's body table says which keys each type
carries. I applied each constraint wherever that field name appears in a body.

## D-8 — `log_key`'s `pk`/`overlap` and `params` values' integer range
§5.1 says `log_key`'s `pk` is 32 bytes and `overlap` "a uint". No upper bound is
given for `overlap`, `ts`, `after`, `expires`, `thr` beyond §4.0's 2^63−1.
Chose: no further bound.

## D-9 — state.json numeric/byte rendering of `net`
§5.3 says `net` is "16 bytes"; §14.1 says byte strings render as lowercase hex.
Unambiguous. But §5.3 does not say whether `log_keys[].pk` and the `roots`/
`signers` map *values* are byte strings (hex) — I read them as bytes → hex.

## D-10 — `params` in state when genesis aborts
§5.1 says the aborted state has "`params` at the §4.5 defaults". Clear.

## D-11 — the order of `rejected` when replay aborts
§5.1: `rejected` holds exactly `{index:0, reason:"bad-genesis"}`. Clear.

## D-12 — `note` has "no state effect" but can still be rejected
§5.1 step 7 gives `note` a threshold check, step 8 gives it body checks.
An accepted `note` changes nothing. Clear.

## D-13 — does `size` advance for an aborted genesis?
§5.3: "`0` if replay aborted at entry 0". Clear.

## D-14 — evaluation of `expires` uses `<=` — but against what when `T` is unknown
§5.3 is explicit: no clock → expiry not judged. `proven/cases.json` encodes
`t: 0` as "no clock". SPEC.md does not say that `T = 0` *means* no clock; that
is the vector's convention. I treat "no clock" as a separate boolean.

## D-15 — §10's `mine` when `at < stored_cp.size`
§10 says `mine` is "the root THIS NODE's branch had at `at`". SPEC.md does not
say where the node gets that root: it must recompute it from the entries it
holds. Chose: recompute from its own stored branch's entries. The `detect/`
cases supply `../served` as the held branch implicitly (`stored` is a checkpoint
over `served`'s entries) — but **SPEC.md never states that the node keeps the
entries of its stored branch**, only its checkpoint. See report.

## D-16 — the four freshness states: which wins when both `hard_stale` and `degraded` apply
§8.1's table is ordered and `hard_stale` precedes `degraded` ("otherwise").
Clear. But `fresh` precedes `hard_stale`: an `elapsed ≤ S` with `S_hard < S`
configured is `fresh` by the table's order. Unstated whether that is intended.

## D-17 — trust file: which checks run in which order
§9.1 lists the fields in a table and the rules in prose. No ordering is given
and `trust-bad/cases.json` only demands refusal, not a reason. Chose: schema,
then per-field, then cross-field. Unobservable.

## D-18 — `MAX_TRUST_BYTES` / `MAX_EVIDENCE_BYTES` / `MAX_BUNDLE_BYTES` are on the
**encoded file**, not the decoded structure. SPEC.md says "a file larger than
this MUST be refused on length", so file length. Clear.

## D-19 — the tlog-tiles partial-tile path
§6 defers tile and bundle *paths* to `c2sp.org/tlog-tiles` and does not restate
them. The suite ships `tile/entries/000.p/126` and `tile/0/000.p/126`. A reader
with no copy of tlog-tiles cannot derive `NNN.p/W`. I implemented from memory of
the C2SP document (`tile/<L>/<index path>[.p/<width>]`, `tile/entries/...` for
entry bundles, 3-digit zero-padded path segments with `xNNN/` prefixes above
1000). **This is a real hole for a fresh implementer**: SPEC.md names the
document but the document is not in the sealed directory.

## D-20 — whether the verifier must fetch full tiles or may use only entry bundles
§6 says the rebuild is from entry bundles and the served `tile/<L>/…` hashes
"MUST also agree". It does not say *which* levels must be checked, or that a
verifier must fetch every level. Chose: check every served level-0 tile (and any
other level present) against the rebuilt tree. `served/` only ships level 0.

## D-21 — `origin` base32: whether padding-stripping happens before or after
lowercasing is immaterial. Chose: encode, strip `=`, lowercase.

## D-22 — Crockford base32 "most-significant bit first" for 10 bytes = 80 bits =
exactly 16 symbols, no padding. Clear.

## D-23 — bech32m: SPEC.md explicitly refuses to restate BIP-350. I implemented
from knowledge. A fresh implementer without BIP-350 cannot proceed; the document
says so, which is honest, but it means the sealed directory is not sufficient.

## D-24 — the receipt note's `deadline` line format
§7 shows `<uint deadline unix seconds>` as the fourth line. It does not say the
line is canonical decimal with no leading zeroes (as §6 does for the checkpoint
size line). Chose: parse as decimal, no leading-zero rule enforced (nothing
tests it).

## D-25 — `key_id` for a verifier key string is "8 hex digits" (§7). SPEC.md does
not say lowercase. Chose: case-insensitive parse, lowercase compare. Unobservable
in the suite.

## D-26 — §10: what "the node's trust policy" means for a bundle checked offline
§8.1 says "verify its checkpoint per §10", and §10 uses `norn.trust.policy` or a
replayed one. For a standalone bundle check there is no replayed state, so the
trust file's policy applies. Chose that.

## D-27 — `detect/` outcome vocabulary (`accept`/`refuse`/`fork`) is the vector's,
not SPEC.md's. §10 produces "FORK" and "refuse"; "accept" is implied.

## D-28 — whether a `policy` entry's text must be non-empty
§5.1: `text` ≤ 4096 bytes and MUST parse as tlog-policy. An empty policy has no
`quorum` line so it fails parsing anyway. No decision needed.

## D-29 — whether `state.policy` is the policy used for §5.3's `T` on the very
checkpoint being verified. §9.4 says a `policy` entry supersedes "for every
checkpoint a node accepts **after replaying it**". Circular for the head you are
replaying from. Chose: verify the head under what you had *before* replaying it
(trust file, or previously-replayed state), which is what §9.4's bootstrap
argument requires. `served-superseded/` confirms both answers are "correct"
depending on what the reader has done.

## D-30 — §11.1 step 1 "verify both checkpoints per §10": under which log key?
The reader's trust-file log key, or one from a replayed state? Chose: trust file
only (the reader has "the network's trust file and nothing else").
