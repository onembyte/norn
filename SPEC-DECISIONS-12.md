# Decisions recorded from SPEC.md alone, BEFORE opening any file under vectors/

Each item: what the prose leaves open, and the reading I chose for the build.
(Later annotations, added after running the vectors, are marked [POST].)

## Encoding profile (§4.0)

P1. Simple values other than true/false/null/undefined (major type 7, simple 0..19,
    24..31, 32..255, and the 0xf8 one-byte-simple form). §4.0's table names floats,
    undefined, null, booleans; it never mentions other simple values. Choice: reject
    (no field type accepts them). The table does not say so.
P2. "Booleans allowed (params.rotate_needs_signer only)". Is a boolean anywhere else
    a *profile* error or a *schema* error? Indistinguishable for entries (both
    `decode`), but for trust/bundle/evidence the code differs: evidence `cbor` vs
    `schema`. Choice: profile allows booleans everywhere; schema refuses them.
P3. Depth "at most 8": depth 8 accepted, 9 refused. Clear.
P4. `MAX_ENTRY_BYTES`: is the check on the input length, or on a declared length
    (a header promising 65536)? `entries-hostile/oversize-entry` is described as
    "a header promising 65536 bytes, refused on length before anything is
    allocated" -- which "length"? Choice: refuse if input length > 65535, AND the
    decoder refuses any declared string/array/map length exceeding the bytes that
    remain (truncation). A declared length that cannot fit is then "truncated", not
    "oversize", unless the file itself is long. Not decided by the text.
P5. Map key "1–23 bytes" applies to every map key at decoder level (incl. labels).
P6. Is a non-text map key a profile error? Yes, "every map key is a text string".
P7. 0x7f/0x5f/0x9f/0xbf indefinite → refuse; reserved additional info 28..30 → refuse
    (not mentioned; RFC 8949 well-formedness).

## Envelope (§4.1, §5.1 step 3)

E1. Step 3 lists "exactly the permitted keys, v = 1, net = anchor.net, well-formed
    sigs". It does NOT list the *types* of `t`, `ts`, `after`, `body`. Choice: all
    envelope member types are checked at step 3 (→ `decode`): `t` text, `ts` uint,
    `after` uint, `body` map. Alternative reading: `body` being a map is a step-8
    "body well-formed" check -- then an under-signed governance entry whose body is
    not a map is `threshold`, not `decode`. Not decided by the text.
E2. `t` that is a text string not in §4.3 → `unknown-type`; `t` not a text → `decode`.
E3. Body contents for governance and `note` checked only at step 8 (after step 7).

## Types, signatures (§4.3, §5.1, §5.2)

T1. `rotate` whose body `device_pk` equals the current `device_pk`: both
    signature requirements resolve to the same kid, and `sigs` cannot repeat a kid.
    Choice: one valid device signature by that key satisfies both. Not stated.
T2. `revoke` by "the device itself": requires role `device` and the kid of the
    device's current `device_pk`. Not pooled across roles.
T3. `note` threshold: at least one valid `signer` or `root` (role-matched) sig.
T4. `policy` entry text "MUST parse as c2sp.org/tlog-policy": does parsing include
    validating each `<vkey>` (name+8hex+base64 alg‖pk, recomputed id, algorithm
    byte)? §9.1 restates the grammar but never says whether a malformed vkey is a
    parse error. Choice: a vkey must have the form name+8hex+base64, decode to
    1+32 bytes, and its declared id must be recomputed and match; the algorithm
    byte is NOT constrained by the grammar (trust file constrains it separately).
    Not decided by the text.
T5. Policy names: is `none` (or `all`, `any`) a legal witness/group name? Choice:
    defining a witness or group named `none` is an error (reserved). Not stated.
T6. Witness and group names share one namespace. "each witness and group name is
    defined once" -- choice: a group may not reuse a witness's name.
T7. `quorum` must name something defined *before* it? The `group` row says
    "previously defined"; the `quorum` row does not. Choice: quorum may come
    anywhere and refer to any defined name (resolved after all lines are read).
    Not decided by the text.
T8. `group` threshold `k`: canonical decimal, 1 ≤ k ≤ n. A `k` that overflows
    uint64 → error.
T9. Policy URL tokens: any non-empty token; not validated as URLs.

## State, JSON (§5.3, §14)

S1. `params` always has all four keys. `log_keys` elements {overlap, pk, since_index}.
S2. Entry `.json` mirrors: §14 applies; byte strings (incl. the embedded `request`)
    rendered as lowercase hex. "The entry object mirrors the CBOR" -- the
    embedded request rendered as bytes (hex), not decoded. Not stated explicitly.
S3. Abort state: params at defaults; every other member empty/zero.

## Evaluation time T (§5.3, §9.4)

Q1. Which policy computes T for the checkpoint the state was replayed from: the
    policy in force when that checkpoint was *accepted* (trust policy, or the
    previously replayed one), or the policy in the state *replayed from it*
    (which may contain a `policy` entry inside that very range)? §5.3 says "the
    policy (§9)"; §9.4 says a policy entry supersedes the trust policy "for every
    checkpoint a node accepts after replaying it, and for §5.3's T". The fixture
    log contains `policy-rotated` (2-of-3 → 3-of-3), so the two readings give
    different T on served/checkpoint. Decision: the policy the checkpoint was
    accepted under (the trust file's, for a node that has replayed nothing).
    A policy in the checkpoint's own replay range applies to the next
    checkpoint, not retroactively to this one's T. §5.3 and §9.4 now say this;
    the vector records 1760003607 under the acceptance policy and 1760003600
    under the replayed policy to keep the distinction observable.
Q2. Expired iff expires != 0 && expires <= T; no clock → no expiry. Clear.

## Notes and checkpoints (§6, §7, §10)

N1. Signature line payload length for a line whose key IS known but whose length
    is the other algorithm's (e.g. 76 bytes under the log key's name+id): §7 says
    68 or 76 is framing, "exactly that length" per algorithm. Choice: framing
    accepts 68 or 76 for any line; a known-key line of the wrong length for its
    algorithm fails verification (log-signature / cosignature), not `note`.
    Not decided by the text.
N2. Key names: §7 says a name contains no space. signed-note also forbids `+` and
    other whitespace. Choice: framing requires a non-empty name with no space;
    `+` not checked at framing.
N3. A note whose first line is blank (empty text): `note` refusal.
N4. Root line base64: strict (canonical padding bits) decoding. "base64 the line's
    own length does not account for" read as trailing garbage; non-zero pad bits
    are not addressed. Choice: strict.
N5. Size line: canonical decimal, fits uint64.
N6. Checkpoint signature verification for log key: only lines whose name+id match
    a trusted key count; all such lines must verify.
N7. Hash tile files: a tile whose byte length is not 32×width → `tiles`.

## Trust (§9.1)

R1. Witness `url`: any text, empty allowed? Only `log_urls` is said to be
    non-empty. Choice: witness url any text (empty accepted). Not decided.
R2. Policy URLs need not equal the `witnesses[].url`. Not stated either way.
R3. `anchor` is a closed map (unknown member → reject) by §4.0's general rule.
R4. `log` line in the trust policy compared to `log_key` as vkey text.
R5. trust.toml: the rendering is sketched, not specified (quoting, inline table,
    order); I will not build CBOR from TOML beyond spot checks.

## Bundles (§8.1)

B1. A bundle whose `entry` does not decode, or decodes to a type with no device:
    `binding`. A `rotate`/`revoke` entry binds by body `device_id`.
B2. `index` ≥ checkpoint size → `inclusion`.
B3. Bundle checkpoint verified under trust log key and trust policy (plus nothing
    replayed) unless a case says otherwise.

## Evidence (§11.1)

V1. `size` == 0: consistency from the empty tree. Undefined; treat as proof failure
    unless proof empty and held size 0. Edge, not likely vectored.
V2. Step 2 "verify both checkpoints per §10": steps 2–7 of §10.1.

## Requests (§16)

Q-R1. `.txt` files: whether a trailing newline is part of the text form is not
    specified. Choice: strip one trailing "\n" when reading a file.
Q-R2. Reserved label keys `ip`/`endpoint` not validated.
Q-R3. bech32m: whole string all-lower or all-upper; HRP compared case-insensitively
    after the case rule; no length limit except payload ≤ 65535.

## Meta

M1. The `cases.json` schemas of every vector directory are not specified in
    SPEC.md; a runner has to reverse-engineer them. (Harness, not interop.)
M2. Outside §5.2/§10.1/§11.1 there is no closed refusal vocabulary (trust files,
    requests, entries-hostile, policies, receipts): "refused for its own reason"
    can only be judged by mapping `says` by hand.

## Selections made after the gate (2026-10-02, D-066)

The choices below supersede the pre-vector readings above where they differ.
They follow the C2SP `tlog-policy` document named by §9.1; a review of the
repository found that the implementations did not establish a common reading.

- **T4:** every policy `vkey` is parsed and its key ID recomputed; `log` keys
  use algorithm `0x01`, `witness` keys use `0x04`. Canonical base64 pad bits
  remain governed by D-062 and checkpoint 6.5l-vii-d-xi.
- **T5:** `none` is predefined and cannot be defined as a witness or group or
  appear as a group member. `all` and `any` are special only in a threshold
  position and remain legal names elsewhere.
- **T6:** witness and group names share one namespace, as both parsers already
  implemented.
- **T7:** the `quorum` line MUST name a witness or group defined on an earlier
  line; `none` is the predefined exception. The Python reference already
  enforced ordering; Go is aligned to it.
- **Additional C2SP details recorded by D-066:** duplicate vkeys are compared
  by underlying public key, every directive line ends in line feed, and ASCII
  controls other than tab and line feed (including DEL) are rejected. These
  details were absent from the local restatement. Names `all` and `any` are
  ordinary names outside the threshold position.

## Selections made for trust-file rules (2026-10-02, D-067)

- Trust URL values are opaque text; Norn does not URI-validate them.
- `log_urls` remains required and non-empty. A witness `url` is optional, and
  present empty text is allowed.
- Optional `log` and `witness` URLs in the C2SP policy are application-specific
  and need not equal the trust file's endpoint fields. Only the existing key
  and name correspondence requirements bind those sections.
