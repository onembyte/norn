# SPEC defects — cold gate run 15

Reader: an independent implementer working from `SPEC.md` and `testdata/vectors/` only.
Implementation: Go, standard library only, `work/impl/` (package `norn`, harness
`cmd/harness`, demonstrations `cmd/demos`). Decisions taken before opening any vector:
`work/decisions.md` (C01–C78, unedited since).

## 1 Tally

**Digests.** `testdata/vectors/SHA256SUMS`: 920 of 920 digests verify (with `shasum -a 256 -c`
before implementing, and again inside the harness, group `sha256sums`). The only file in the
tree not listed is `SHA256SUMS` itself.

**First full run: 3029 checks, 3029 pass, 0 fail.** No first-run failure. Groups: keys 61,
ed25519-cctv 914, entries 64, entries-hostile 17, replay 441 (log, log-edges, log-cas,
log-admission, log-empty, 26 genesis and 2 genesis-good fixtures: every per-entry reason, every
`.reason` file, every `codes` map, every `state.json` byte for byte), trust 66, policies 72,
requests 76, served 6, checkpoints-bad 45 (44 codes plus the recomputed
`signature_blind_accepts` set), served-variants 33, served-large 42, detect 41 (pairs and
staleness ladder), proofs 53, receipts 27, proven 96 (four evaluation times, grants, bundle key
joins, 36 grant labels), fork 50, anchors 3, setup 2, sha256sums 920.

**Checks added after the first run:** group `rules` (355): for every `rules` map in every
manifest, the cited phrase occurs in the cited SPEC section (all do); and for every
`requests-bad` case marked `signature: valid` whose text layer decodes, the device signature
verifies over that request. The first version of that metadata check failed two cases, both
harness errors, not implementation errors: `unsorted-keys` is signed over the canonical
preimage, not the received order, and `corrupt-character` damages the payload itself, so no
signature can be expected to verify; text-layer cases are now excluded.

**Final run: 3384 checks, 3384 pass, 0 fail.** Every closed code a manifest names is compared
exactly (§5.2 replay reasons, §7 receipt codes, §10.1 loop and bundle codes, §11.1 evidence
codes, the `entries-hostile` refusal categories).

## 2 The sweep

Every variant is one switch at one decision point of the base implementation (`on("…")` in
`work/impl/*.go`); the final list is `work/sweep/variants-final.txt`, and the per-variant result
with the checks that catch each one is `work/sweep/single-final.tsv` (`single.tsv` and
`single-extra.tsv` are the first pass).

**Counts.** 404 single variants, each run against the whole suite (3384 checks): **358 caught,
46 survive.** Of the caught, 121 are caught by exactly one check, 137 by two or three, 100 by more
(the most fragile pins are listed per decision in §5). The list grew during the run: three
switches with capital letters in their names were missed by the first enumeration and run
separately (`ed-skip-A-check` 26 checks, `ed-skip-R-check` 1 — `cctv/304` alone, `ed-S-reduce` 2),
and four switches were added after the first pass (`pol-logline-no-point`, `qn-requires-cosig`,
`state-net-from-genesis` for §12.1's list, and `cp-cosig-reachable-only`, a late doubt not in the
decisions log). Three switches that first survived because they were no-ops or too weak in my code
(`cp-origin-before-logsig`, `ev-size-before-checkpoints`, `grant-mapped-after-mask`) were
rewritten and are caught. `fix-dup-accepted-content` is the fix proposed in H2, not a variant, and
is not counted. Final per-variant results: `work/sweep/single-final.tsv`.

**Survivors, classified (46).**

*Equivalent — no input separates them from the base (15).* `ed-cofactored` (with both points of
order L the two equations agree, §3.1 item 3); `ed-y-noncanonical-accept`, `ed-xzero-sign-accept`
(§12.1, confirmed by computation, §4); `sig-count-repeats`, `enr-dupwg-other-only`,
`req-pk-len-any`, `pol-none-member-ok`, `state-net-from-genesis` (§12.1-declared);
`b32-first-separator` (the HRP `norn` and the bech32 charset hold no `1`, so first and last `1`
coincide); `note-split-last-space` (D-077's name rule refuses either split — L5);
`merkle-incl-no-sn-check` (a short path cannot reach the root without a collision);
`cbor-request-depth-inherit` (a request is at most two deep; any deeper one fails its closed
schema with the same code); `pol-utf8-check` (policy text always arrives as CBOR text, already
UTF-8); `cbor-nontext-keys` and `pol-two-quorums-last` (no-ops in my code: a second check refuses
the same input, or the switch acts only beside another).

*Genuine — a concrete input on which base and variant disagree (31),* every one built and run by
`work/demos` (files in `work/demos-out/`, signed where needed with `keys.json` seeds):

| kind | variants (demo) |
|---|---|
| spec ambiguity or defect (§3) | `dup-two-sets` (G01, H1); `pol-names-ascii` (G10, M1); `cp-cosig-reachable-only` (G29, M2); `lk-refuse-known-key`, `lk-dupkey-include-log-lines` (G05/G06, M3); `note-last-blank` (G09, L1); `note-empty-text-ok` (G08, L2); `bnd-device-format` (G14, L3); `fld-label-value-floor` (G02, L4); `grant-sort-numeric` (G04, L6); `req-net-must-match` (G13, L7); `ord-threshold-before-after` (G21, L8) |
| spec explicit, no vector holds it (§5) | `rot-newkey-sig-suffices` (G17); `bnd-enroll-only` (G15); `ev-split-zero-root-any` (G16); `rcpt-unsigned-is-logsig` (G12); `note-del-refused` (G07); `grant-compress-single-zero` (G03); order pairs `enr-stale-before-threshold` (G18), `ord-enroll-dup-before-stale` (G19), `ord-revoke-stale-before-auth` (G20), `par-stale-before-body` (G22), `pol-dupkey-before-stale` (G23), `pol-stale-before-parse` (G24), `rm-unknown-before-stale` (G25), `rot-stale-before-threshold` (G26), `thr-badthr-before-stale` (G27), `lk-dupkey-before-stale` (G28) |
| declared in §12.1, now constructed (§4) | `qt-none-unbounded` (G11), `qn-requires-cosig` (D2), `pol-logline-no-point` (D1) |

**Composites.** Survivor × survivor: all 1035 pairs of the 46 run; **1034 survive**, one is caught
— `note-last-blank` × `rcpt-unsigned-is-logsig`, by `receipt-bad/extra-final-newline`: the
last-blank split leaves that receipt with no signature line, which the second switch then codes
`log-signature` instead of `note`. Survivor × caught: every survivor against every variant caught
by exactly one check (the ones a survivor could mask), 5566 pairs; **1 survives** —
`req-net-must-match` × `req-net-len-any`: comparing a request's `net` with the reader's own also
refuses the short `net` of `requests-bad/short-net`, so the masked length rule changes nothing
beyond G13. No composite produced a behaviour that its single survivors did not already show.
Files: `work/sweep/composite-ss.tsv`, `composite-sw1.tsv`, `composite-late.tsv`.

## 3 Defects

Ratings: **H** a conforming reader can be turned against the network, or two conforming
readers decide differently on input a network can see; **M** two readings change what a node
does, reachable only through operator/root configuration or malformed input; **L** wording,
over- or under-claim, nothing a node does differently. Every constructed input is in
`work/demos-out/` and is re-run by `work/demos` (output `work/demos-run.txt`).

### H1 — the two duplicate keys share one namespace, and one is the other's preimage (§5.1 step 1, §4.0)

**Words.** §5.1 step 1: "The entry's duplicate key is its `content_hash` if steps 2 and 3 would
accept it … and its `entry_hash` otherwise. A key already seen → reject (`dup-entry`). Every entry
that reaches this step adds its key to the seen set". §4.0: "`content_hash` | `SHA-256` of the
signature preimage", "`entry_hash` | `SHA-256` of the entry **as received**".

**What a second implementer cannot know.** Both keys are bare SHA-256 values, and the bytes a
`content_hash` is taken over (`norn/entry/v1\n` ‖ CBOR(envelope − sigs)) are themselves a byte
string anyone can append to a log. Appended as an entry they never decode — 0x6E (`n`) opens a
14-byte text string that swallows the envelope's map header and leaves bytes over — so that
entry's key is SHA-256 of those bytes: exactly the `content_hash` of the genuine entry. The literal reading ("the seen set", one set)
then refuses the genuine entry, appended later, as `dup-entry`; a reader that keeps the two kinds
of key apart (separate maps, or typed keys — an ordinary way to write it) applies it. The
document never says whether the two kinds may collide.

**Proof.** Surviving variant `dup-two-sets`. Input `G01-preimage-as-entry.bin` then
`G01-entry-X.cbor` (a `note` signed by `signer1`), appended to the 162-entry `log/` fixture: base
`dup-entry`, variant accepted. The preimage needs no key: it is derived from the entry itself.

**Smallest change.** Key the seen set by (kind, hash): "an `entry_hash` and a `content_hash`
never match each other". The fix proposed in H2 does this too.

### H2 — an under-signed copy, appended first, cancels the genuine entry while its receipt is honoured (§5.1 step 1 with D-031; §4.4; §7)

**Words.** §5.1 step 1: "Every entry that reaches this step adds its key to the seen set,
**whether or not it is later rejected** (D-031): the first appearance of a signed content is the
only one replay will ever apply". §4.4: "Inserting it *later* is delay, which receipts (§7) and
staleness (part 6) catch". §7: "A receipt whose leaf is absent from every checkpoint cosigned
after `deadline` is non-repudiable proof of log misbehaviour". §6: "Log operator validation is
optional and non-binding".

**What goes wrong.** `sigs` is outside the content key, so the same content with `sigs: []` (or
with fewer signatures than the threshold) has the same key. A log that receives a signed entry
appends that stripped copy first: it is rejected (`threshold`) but its key is recorded, and the
genuine entry — appended on time, so the receipt is honoured and no receipt-based proof of
misbehaviour exists — replays as `dup-entry`. Every conforming reader agrees, and every one of
them is turned against the network: they faithfully keep a revoked device. The submitter can
re-sign with a new `ts`; the log can repeat the trick each time. The same power belongs to anyone
holding a partially signed entry during §16.3's append-only threshold signing (one co-signer or
whoever relays the draft), since an unfinished entry is exactly the under-signed copy. The
document's claim that late insertion is caught by receipts does not hold for this path, and
nothing in §5–§7 or §11 names the pattern as misbehaviour.

**Proof.** Not a variant (both readings agree); demonstrated as S1 in `work/demos-run.txt`:
`S1-stripped-revoke.cbor` (printer's revoke, signers' signatures removed) then `S1-revoke.cbor`
(the same revoke signed by `signer1` and `signer3`, correct `prev`), appended to `log/`: copy
`threshold`, genuine revoke `dup-entry`, printer stays `active`.

**Smallest change.** Record an `entry_hash` for every entry, and a `content_hash` only for an
**accepted** entry; refuse an entry as `dup-entry` if its `entry_hash` was seen or its
`content_hash` belongs to an accepted entry. I ran this as switch `fix-dup-accepted-content`: all
3384 checks still pass (the six D-070 copy vectors are copies of accepted entries;
`bad-repeat-of-rejected`, `-undecodable` and `-genesis` are byte repeats), the revoke in S1
applies (printer `revoked`), and G01's X is accepted.

### M1 — a policy's `<name>` has no stated character set or length (§9.1 grammar)

**Words.** "`witness <name> <vkey> [<url>]`", "Witness and group names share one namespace; each
name is defined **once**", "Key names follow §7's ASCII grammar"; the trust-file table: "**a
witness `name` is 1–64 bytes** and unique within the file".

**What a second implementer cannot know.** The restated grammar — offered as complete ("a
restatement that leaves it out is not enough to write an agreeing verifier") — never says which
bytes a witness or group name may hold or how long it may be. The 1–64 bound is the trust file's;
"Key names follow §7's ASCII grammar" is about vkey names, but sits in the same paragraph and is
easily applied to the short names too. A `policy` entry (no trust-file correspondence) or a trust
file whose witness is named outside ASCII, or longer than 64 bytes, is accepted by one reader
and refused by another — and a refused `policy` entry leaves the two readers with different
policies, quorums and `versions.policy`.

**Proof.** Variant `pol-names-ascii` survives. `G10-policy-nonascii-witness-name.cbor` (the
current policy with `pi` renamed `zürich`, root-signed by root1–3, correct `prev`): base
accepted, variant `decode`. Reachable only through the roots or the trust-file author: M.

**Smallest change.** Define `<name>` in the grammar (for example "one or more bytes other than
space, tab, line feed and the forbidden controls, at most 64", or "§7's key-name grammar") and
say that it holds in every policy, not only a trust file's.

### M2 — "a witness the policy names" vs "a witness that counts" (§10 outline, §10.1 step 6)

**Words.** §10: "every cosignature LINE naming a witness the policy names must verify"; §10.1
step 6: "a cosignature line whose name **and** key id match a listed witness does not verify";
§9.1: "`policy` is where it learns whether that witness counts".

**What a second implementer cannot know.** A policy may define a witness its quorum never
reaches (`policies/directive-after-quorum` is accepted with one; a trust file may list one). One
reader checks every defined witness's lines and refuses a head carrying a bad line from a witness
that does not count; another checks only witnesses the quorum reaches and accepts it. Both read
the words literally ("names" vs "counts").

**Proof.** Variant `cp-cosig-reachable-only` survives (a late doubt, not in the decisions log).
`G29-trust-friend-outside-quorum.cbor` (the shipped trust file with policy `group two all pi vps`
/ `quorum two`, `friend` still listed) and `G29-friend-bad-cosignature.checkpoint` (served head,
one bit of friend's signature flipped, canonical base64): base `cosignature`, variant accepted.
Needs that operator configuration: M.

**Smallest change.** "Every line matching any witness the policy defines must verify, whether or
not its quorum reaches that witness" (or the opposite, stated).

### M3 — re-publishing an active log key is neither allowed nor refused (§5.1 `log_key`, §5.2 `dup-key`)

**Words.** §5.1: "`pk` is not the public key of any witness the policy in force names … (`dup-key`,
§9.1's invariant)"; §5.2 `dup-key`: "a `log_key` whose `pk` an active witness holds … a key entering
a role whose set must stay disjoint from another".

**What a second implementer cannot know.** Nothing says what a `log_key` whose `pk` is already an
active log key (the anchor's, or one learned earlier) does. The base appends a second row to
`log_keys`. A reader reasoning from `signer_add`/`root_add` ("`kid(pk)` not already a root or
signer") refuses it as `dup-key`; a reader that compares against the policy's `log` lines as well
as its witnesses refuses the anchor key too. Either way the two states differ in `log_keys`,
`versions.log_key`, and therefore in every later `log_key` entry's `prev`.

**Proof.** Variants `lk-refuse-known-key` and `lk-dupkey-include-log-lines` survive.
`G05-log_key-republish-anchor.cbor` (pk = `logkey`, root-signed, correct `prev`): base accepted,
both variants `dup-key`; the same with `logkey2` (learned at index 27): base accepted,
`lk-refuse-known-key` `dup-key`. Roots only: M.

**Smallest change.** One sentence in the `log_key` row: re-publishing an active log key is
accepted and appends a row (or: is `dup-key`).

### L1 — first blank line vs last: distinguishable after all, and the reference library splits at the last (§7, §12.1)

**Words.** §7: "the **first** blank line ends the text … the two readings are told apart by no Norn
artifact only because every note text here has a fixed line count"; "These rules are **verified
against `golang.org/x/mod/sumdb/note`**"; §12.1: "a text carrying a blank line has the wrong line
count under **both** readings and is refused either way".

**What goes wrong.** A blank line placed between two *signature* lines separates the readings by
code: the first-blank reader sees an empty signature line (`note`); a last-blank reader moves the
log's line into the text, finds no trusted line or a wrong signature (`log-signature`). Codes are
the contract (§10.1: "an implementation reports one of these codes and no other"; §11.1: "MUST
refuse it for the same reason"), so §12.1's "refused either way" is true and insufficient. To my
recollection `x/mod/sumdb/note` locates the separator with the *last* `\n\n`; I could not check
that offline, but if so, a reader built on the library the document cites answers
`log-signature`, and "verified against" over-claims for this rule.

**Proof.** Variant `note-last-blank` survives. `G09-blank-between-signatures.checkpoint` (served
head with one LF inserted after its first signature line; no signing needed): base `note`, variant
`log-signature`. Both refuse: L.

**Smallest change.** Ship that file in `checkpoints-bad/` coded `note`; correct §12.1; drop or
qualify the "verified against" sentence for the separator rule.

### L2 — a note whose first line is blank (§7)

**Words.** "A note's text lines are non-empty, so the **first** blank line ends the text".

**What a second implementer cannot know.** Whether an empty text (the note starts with LF) is
malformed framing or an empty text that fails later. `G08-leading-blank-line.checkpoint`: base
`note`, variant `note-empty-text-ok` `log-signature`. Both refuse: L. **Change:** "the text is at
least one line; a note whose first line is blank is `note`".

### L3 — a bundle proves inclusion, not acceptance (§8, §8.1)

**Words.** §8: "The bundle is self-contained, so it can be checked by someone holding only
`norn.trust` — which is what makes it useful in an alarm, an audit trail, or a bug report"; §8.1:
"It proves that this device was enrolled — or rotated, or whatever its type is — at that index".

**What goes wrong.** §10.1's four bundle steps never consult replay, so a bundle around an entry
that replay *rejected* passes. `G14b-bundle-of-rejected-enroll.bundle` wraps `log/6-bad-no-device-sig`
(an `enroll` whose embedded request does not verify under its own `device_pk`, rejected by replay
as `no-device-sig`) with an inclusion proof into
`served/checkpoint`: accepted, labelled `printer`. `G14-bundle-of-rejected-entry.bundle` does the
same for `log/79` (device id `Probe`, refused `decode`), and also separates readers on whether
`device` must be a §2 `device_id` (variant `bnd-device-format`: `bundle`). The node's own condition
3 replays, so enforcement is unaffected; the audience the section addresses — someone holding only
`norn.trust` — is misled. L (over-claim). **Change:** "proves that the entry is in the log at that
index; whether replay accepted it needs the log through `index`".

### L4 — label values: "≤ 256 bytes" without the floor `reason` states (§4.0)

**Words.** "`labels` | … values ≤ 256 bytes" beside "`name`, `reason` | UTF-8, 1–64 / 0–256 bytes".
§12.1 itself notes that a floor is shown only by a positive ("a reader that requires one byte
rejects entries this document accepts, which only a positive can show"), and ships none for label
values. `G02-enroll-empty-label-value.cbor` (labels `{note: ""}`, device-signed, signer-signed):
base accepted, variant `fld-label-value-floor` `decode` — a device present in one state and not the
other. The words favour the base, so L; **change:** "values 0–256 bytes" and a positive vector.

### L5 — the first-space argument is stale (§7)

**Words.** "split at the *last* one instead and a line carrying two spaces parses as a signature
from a name nobody lists, which §10 ignores rather than refuses". Since D-077 a name holding a
space does not frame, so the last-space split refuses that line as `note` too (variant
`note-split-last-space` is equivalent). Nothing behaves differently; the justification is wrong.

### L6 — grant text: "sorted as text" and RFC 5952's single zero group are unvectored (§4.0)

`G03/G04` in `demos-run.txt`: `2001:db8:0:1:1:1:1:1/128` — base (RFC 5952: one zero group is not
compressed) vs `grant-compress-single-zero` `2001:db8::1:1:1:1:1/128`; `9.0.0.0/8, 10.0.0.0/8` —
base `10.0.0.0/8,9.0.0.0/8` vs `grant-sort-numeric`. The bound a node installs is compared by
containment, so only `proven.json`'s `grant` text and `proven/cases.json` would differ. **Change:**
"sorted bytewise" and two `grant-labels.json` rows.

### L7 — a standalone request's `net` (§16.1, §16.3)

"A consumer MUST validate structure **and** verify `sig` before showing a request to a human" —
nothing says whether the consumer compares `net` with its own network. `G13-request-other-net.cbor`
(net `another-net-0001`, signed by its device key): base accepted, `req-net-must-match` refused. The
`enroll` that carries it is refused `decode` either way, so L. **Change:** say which.

### L8 — `log/101` is named for step 6 before step 7 but is a `note` (§5.1)

§5.1 names "`log/101-bad-precedence-after-before-threshold` (step 6 before step 7)". It is a
`note`; no governance entry holds the pair, and a reader that swaps 6 and 7 for governance types
only passes (`ord-threshold-before-after`; `G21-signer_add-after-and-unsigned.cbor`: base `after`,
variant `threshold`). §5.1 already admits untested orders exist, so L.

## 4 Declared survivors (§12.1 "What is not vectored"), each checked

| §12.1 item | checked how | result |
|---|---|---|
| §3.1 point check on a policy `log` line | switch `pol-logline-no-point` survives; `D1-policy-log-line-identity-key.cbor` (identity point on a `log` line, root-signed): base `decode`, variant accepted | confirmed unvectored |
| source-neutral acquisition | not static | agreed |
| §13 reconciliation, allowed-ips ∩ grant | not implemented here; no vector | agreed |
| §16.3 key handling | not static | agreed |
| `none` as a group member | `pol-none-member-ok` survives: refused as undefined either way | confirmed equivalent |
| CR inside a policy verifier key | control-byte rule refuses first; `vk-b64-lax` is caught only through `trust-bad/44`'s `log_key` | confirmed |
| OpenTimestamps attestations | harness checks the §6 digest and that each stated digest occurs in its `.ots` file; nothing more | agreed |
| `quorum none` accepting an uncosigned head | `qn-requires-cosig` survives; `D2-uncosigned-head.checkpoint` under a constructed quorum-none trust file (trust files are unsigned, so the "second anchor" is constructible): base accepted, variant `quorum`. Related: `qt-none-unbounded` survives (G11: contractor kept vs dropped) | confirmed unvectored — and constructible |
| "a key contributes at most once" | `sig-count-repeats` survives; `log/134` holds the sorted-unique rule | confirmed |
| "must not count it … in the moment before that refusal" | no artifact can see it | agreed |
| order of entry 0's steps | one code, `bad-genesis` | agreed |
| §3.1 canonical clauses | `ed-y-noncanonical-accept` and `ed-xzero-sign-accept` survive; `TestNonCanonicalYNeverPrimeOrder`: of the 38 encodings with y in [p, p+19), 24 lie on the curve and none has prime order; x = 0 only at y = ±1 | confirmed by computation |
| blank line inside a note's text | inside the text, refused either way — but a blank line in the signature block separates the readings by code (L1, G09) | **inaccurate** |
| "never from a supplied proof" | no served log carries a proof | agreed |
| §16.1 32-byte `device_pk` | `req-pk-len-any` survives (point check needs 32 bytes) | confirmed |
| `state.net` from the anchor | `state-net-from-genesis` survives | confirmed |
| `entry_hash` as received | no re-canonical form exists for an undecodable entry | agreed |
| `MAX_ENTRY_BYTES` on the embedded request | entry cap fires first | agreed |
| witness key a cosignature key at verification | trust file refuses first | agreed |
| `dup-wg` for `enroll`: any vs another | `enr-dupwg-other-only` survives | confirmed |

## 5 Decisions the vectors pinned, and decisions they did not

Each decision C01–C78 (`work/decisions.md`), with the switches that flip it and how many checks
catch each. "Pinned" means every switch at that decision is caught.

**Pinned by the suite.**

- C01–C02 (NORN-ED25519-v1): order check 164, small-order-only 48, identity 6; A check 26,
  R check 1 (`cctv/304` alone), S reduction 2. The cofactored equation and the two canonical
  clauses are equivalent (§2, §4).
- C03 key admission: `root_add`/`signer_add`/`log_key` 5, genesis 4, `rotate` incoming key 2,
  request 3, verifier keys 4 — every point but a policy `log` line (§4, D1).
- C04–C12 the CBOR profile: each banned item, shortest form (5; lengths-only 3), integer cap 3,
  key cap 24 / empty key (2 / 1), key order 4, duplicate keys 3, bare-string order 281, depth ±1,
  every size cap ±1 for entries, bundles, trust files and evidence, trailing bytes 3, UTF-8 4.
  Most of these are held by a single file each — `entries-hostile/*`, `proofs/at-the-cap`,
  `trust-good/at-the-cap`, `fork/bad-one-past-the-cap`.
- C14–C18, C20–C22 field rules, `sigs`, envelope, signature counting (role 5, no-verify 3,
  keys-after-entry 3, device kid 4, device role 3), genesis (2–4 each).
- C26, C33–C37 additions, `prev` presence (3–23), no partial writes (2), state shape (3–6),
  canonical JSON (2–6).
- C40–C49 note lines, matched lengths, log keys, cosignatures, T (oldest line 1, median 2,
  newest 4, oldest 3, retroactive policy 3), checkpoint body, bundles framing, `x` prefixes (20),
  tiles (level-0-only 1, prefix compare 1, missing tile 1), fork/rollback order (2–4), genesis
  placement (2–4).
- C51 bech32m (1–18 each), C54 trust file (26 of its 27 switches are held by exactly one
  `trust-bad`/`trust-good` file each; correspondence-skip by 5), C55 fingerprint 2, C56 TOML reproduction (checked,
  not varied), C57 informed reader (2–4), C58–C67 policy grammar (1–4 each), C69–C71 expiry,
  ladder, age (1–2 each), C74 anchor range (1 each), C75 `after` (5 / 213), C76–C78.

**Partly pinned — the suite holds some switches at the decision and not others.**

| decision | not held | demo | why it matters |
|---|---|---|---|
| C24 `rotate` | the current-key signature against a signature by the **incoming** key alone (`rot-newkey-sig-suffices`); stale before the signer threshold (`rot-stale-before-threshold`) | G17, G26 | G17: a reader that accepts the incoming key's own signature hands any device's identity to whoever holds a fresh key — and passes all 3384 checks. No shipped `rotate` carries a signature by its incoming key without one by the current key (`log/46` has the current key's only, `log/141` and `log-cas/28` neither), so none can catch it |
| C23 `enroll` | threshold before stale; stale before dup-id | G18, G19 | order only |
| C25 `revoke` | authorisation before stale | G20 | order only |
| C27, C28 | stale before unknown-key; stale before bad-thr | G25, G27 | order only |
| C29 `log_key` | stale before dup-key; an already active log key (M3) | G28, G05/G06 | M3 changes state |
| C30 `policy` | parse before stale; stale before dup-key | G24, G23 | order only |
| C31 `params` | body before stale | G22 | order only |
| §5.1 steps 6/7 for governance types | `log/101` is a `note` (L8) | G21 | order only |
| C13 labels | value floor (L4) | G02 | acceptance differs |
| C19 duplicate key | shared namespace (H1) | G01 | acceptance differs |
| C38 note split | first vs last blank line (L1); leading blank line (L2) | G09, G08 | codes differ |
| C39 controls | DEL in a signature line's name | G07 | a reader refusing DEL lets any stranger veto heads on a shared log, the attack §10 argues against for names |
| C43 cosignatures | witnesses outside the quorum (M2) | G29 | acceptance differs |
| C44 T | `quorum none` has no clock (declared) | G11 | expiry differs |
| C50 requests | a standalone request's `net` (L7) | G13 | display only |
| C52 receipts | an unsigned receipt is `note`, not `log-signature` | G12 | code differs |
| C53 bundles | a positive bundle proving a `rotate` or `revoke` (only negatives ship); `device` as a §2 id (L3) | G15, G14 | a reader binding only enrolments refuses every rotate bundle |
| C63 policy names | character set and length (M1) | G10 | acceptance differs |
| C68 evidence | split 0 with a non-zero `split_root` | G16 | acceptance of evidence differs |
| C73 grants | RFC 5952's single zero group; "sorted as text" (L6) | G03, G04 | published grant text differs |

**Not pinned at all.** C72 (`CLOCK_SKEW`): no vector and no artifact exercises it; it is
advisory and changes no state, so I implemented nothing for it. C20 (preimage by re-encoding) and
C09's depth restart for a request are equivalent by construction.

## 6 Verdict

Two H defects. H1 is a genuine split between two plausible readings of §5.1's duplicate key on
input any log can carry; H2 is a consequence of the document's own duplicate rule that defeats the
guarantee §4.4 and §7 claim for receipts, and turns every conforming reader into the instrument
that keeps a revoked device on the network. One change to §5.1 (H2's) closes both and keeps all
3384 checks green. M1–M3 are gaps reachable through root or operator configuration. Beyond the
defects, the sweep found ten ordering pairs and six rules that `SPEC.md` states plainly and no
vector holds — the most consequential being a `rotate` signed only by its incoming key (§5,
`rot-newkey-sig-suffices`), a misreading that hands a device's identity to whoever holds a fresh key
and passes the whole suite.

SPEC INSUFFICIENT

## 7 Closing self-check

**Files I wrote — all under `/Users/francomichetti/dev/security/norn-lanes/sealed-run15/work/`:**

- `decisions.md` (written before any vector was opened; not edited since).
- `SPEC-DEFECTS-15.md` (this report).
- Implementation: `impl/go.mod`, `impl/cbor.go`, `impl/cjson.go`, `impl/ed25519x.go`,
  `impl/entry.go`, `impl/evidence.go`, `impl/grant.go`, `impl/merkle.go`, `impl/note.go`,
  `impl/policy.go`, `impl/replay.go`, `impl/request.go`, `impl/trust.go`, `impl/variants.go`,
  `impl/verifier.go`, `impl/ycheck_test.go`, `impl/cmd/harness/main.go`, `impl/cmd/demos/main.go`.
- Binaries and run logs: `harness`, `demos`, `run-first.txt`, `run-2.txt`, `run-final.txt`,
  `demos-run.txt`.
- Sweep: `sweep/run1.sh`, `sweep/variants.txt`, `sweep/variants-final.txt`, `sweep/single.tsv`,
  `sweep/single-extra.tsv`, `sweep/single-final.tsv`, `sweep/survivors.txt`,
  `sweep/survivors-final.txt`, `sweep/weak.txt`, `sweep/weak1.txt`, `sweep/weak1-final.txt`,
  `sweep/weak1-new.txt`, `sweep/pairs-ss.txt`, `sweep/pairs-sw.txt`, `sweep/pairs-sw1.txt`,
  `sweep/pairs-late.txt`, `sweep/composite-ss.tsv`, `sweep/composite-sw1.tsv`,
  `sweep/composite-late.tsv`.
- Constructed inputs: the 33 files in `demos-out/` (D1, D2, G01–G29, S1).
- Tool state, by way of `HOME`, `GOCACHE`, `GOPATH` and `TMPDIR` pointed into `work/`:
  `gocache/` (Go build cache), `home/Library/Application Support/go/telemetry/local/` (Go's local
  telemetry counters), `gopath/` and `tmp/` (empty). `GOPROXY=off`, `GOTOOLCHAIN=local`: nothing
  was fetched.

**Nothing outside `work/` was written by my commands.** `find` for anything newer than `SPEC.md`
outside `work/` finds only the sealed directory itself, whose timestamp (2026-10-12 11:16) predates
this run; `SHA256SUMS` still verifies 920 of 920 and the tree still holds 921 files. No command
read, listed or searched any other copy of the project, and nothing used the network.

Two things outside `work/` that my commands did not write but a reviewer should know: (1) when I
backgrounded two commands, the Claude Code runtime itself kept their stdout in its own task-output
files under `/private/tmp/claude-501/…/tasks/` (one holds the line `finished` and a count, the
other was stopped with no output); (2) the user's shell profile initialises zoxide in every Bash
call, which may record visited directory paths in zoxide's own database under the real home
directory. I did not check either, because checking would mean reading outside the sealed
directory.
