# Norn — Decisions

Format: what · why · rejected. Newest at the bottom. Never delete; supersede.

## D-001 · Name: Norn (2026-09-18)
The Norns carve the record of what has happened; nothing carved is uncarved — an
append-only log of fate. GitHub search: no security/networking project uses it
(`nornir` is a network-automation framework, `norns` a monome instrument; neither
collides). Go module path TBD (`github.com/onembyte/norn`).

## D-002 · Go (2026-09-18)
torchwood, tessera, witness, formats, wgctrl, sigsum-go are all Go and all live.
Rejected: Rust (would mean reimplementing tlog client + witness client; tailscale-rs
shows how slow that is) · Python (no kernel wg control story worth shipping).

## D-003 · Reuse C2SP transparency formats verbatim (2026-09-18)
tlog-tiles / checkpoint / cosignature / witness / policy. Existing witnesses and
monitors must work unchanged — that is the whole point of being an ecosystem
member rather than a new island. Rejected: custom AUM-style hash chain (Tailnet
Lock) — no witnesses, no tooling, no monitors.

## D-004 · Full replication + replay, no prefix tree (2026-09-18)
Target networks are 10¹–10⁶ entries; every node holds the whole log and replays
it. There is no lookup to equivocate on. Rejected: KEYTRANS-style prefix+log tree
— built for billions of users, brings VRFs, privacy-preserving lookups and a
server-side query path we don't need.

## D-005 · Observe mode is mandatory before enforce (2026-09-18)
Fail-closed enforcement on unaudited crypto can take a network down. Every
deployment starts in observe mode; enforce is an explicit promotion. Source:
tailscale-rs TKA rollout note.

## D-006 · No chain by default — decision deferred to LEDGER-OPTIONS.md (2026-09-18)
Provisional: a witnessed transparency log provides non-equivocation without
consensus. Part 3 evaluates permissioned BFT chains, public-chain anchoring and
hybrids against the same criteria and either confirms or overturns this. Until
then nothing in SPEC.md may assume either.

## D-007 · Two signer roles: root (cold) and signer (warm) (2026-09-18, part 2)
Threat A3: a stolen warm signer key must not be able to remove the other signers
and lock admins out. So `Enroll`/`Revoke`/`Rotate`-approval are *signer* entries;
`SignerAdd`/`SignerRemove`/`ThresholdChange`/`RootAdd`/`RootRemove` are *root*
entries, root keys are cold. Rejected: TKA-style weighted single-tier keys with
"prefer RemoveKey" fork rules — needs history rewriting for recovery, which an
append-only log cannot do.

## D-008 · Devices have an Ed25519 identity key separate from the X25519 WG key (2026-09-18, part 2)
Threat A7 (key substitution) needs proof of possession, and self-service `Rotate`
needs something the device can sign with. X25519 keys must not be reused for
signing. So an enrollment binds `(device_id, device_pubkey_ed25519, wg_pubkey_x25519)`,
signed by the device key and by a signer. Rejected: XEdDSA-style signing with the
WG key — cross-protocol key reuse, no hardware support, nobody audits it.

## D-009 · Hybrid ledger: witnessed log core + optional public-chain anchoring (2026-09-18, part 3)
Supersedes the "provisional" in D-006. Core is a single C2SP transparency log with
k-of-N witnesses, peer gossip and CT-style submission receipts (O1). Checkpoint
hashes may additionally be anchored via OpenTimestamps as an *advisory* witness
type (O4) — it defeats backdating under full log+witness collusion and nothing
else, costs nothing, and never touches the handshake path. Multi-log validity (O2)
is the documented upgrade for multi-tenant deployments. Rejected: permissioned
BFT chain (O3) — validators are witnesses that also order, with an always-on
liveness assumption a homelab can't meet, solving untrusted-writer ordering that
Norn doesn't have; on-chain registry (O5) — a node can't verify contract state
without trusting an RPC, which reintroduces the single trusted party Norn removes,
plus gas, wallets, permanent public device names and no LAN-only operation.
Full scoring in LEDGER-OPTIONS.md.

## D-010 · Entries carry an optional `after` (observed log size) (2026-09-18, part 4)
Guards against a log operator inserting a validly-signed entry earlier than the
signer intended (reordering a `revoke` before a later `enroll`). Rejected: a
`prev`-hash chain inside entries — forces signers to serialise on the head and
breaks concurrent signing; CT does not chain entries either.

## D-011 · Reuse tlog-proof@v1 bundles and signed-note receipts (2026-09-18, part 4)
Per-peer evidence is a C2SP "spicy signature" bundle (torchwood `VerifyProof`);
submission receipts are signed notes, CT-SCT-style. Rejected: custom proof and
receipt encodings — no tooling, no vectors.

## D-012 · Replay is a pure function with fixed rejection reason codes (2026-09-18, part 4)
Two implementations must produce byte-identical canonical state JSON, including
the `rejected[]` list. This is what makes the cold-model gate and a second
implementation meaningful. Rejected: "best effort" replay that skips invalid
entries silently.

## D-013 · Enforce at the cryptokey routing table via wgctrl; poll, don't patch (2026-09-18, part 5)
The peer table is the one place a key can be refused independently of any control
plane, on every WireGuard implementation wgctrl reaches (kernel netlink, UAPI,
WireGuardNT, FreeBSD). Mainline Linux has no peer-change netlink event (2021 and
2023 patches unmerged), so watchdog/observe poll at T_poll = 200 ms. Rejected:
eBPF/nftables as the primary mechanism — blind to the key-swap attack; patching
WireGuard — the whole point is zero protocol changes.

## D-014 · Tailscale/Headscale get observe mode only, event-driven via LocalAPI (2026-09-18, part 5)
tailscaled exposes no UAPI socket; its peer table is reachable only through
LocalAPI (`WatchIPNBus` with peer-state notifications, `status --json`). Norn
detects unproven peers there but cannot evict them without patching tailscaled —
which is what Tailnet Lock already is. Rejected: forking tailscaled.

## D-015 · Watchdog fight policy: alarm by default, quarantine opt-in (2026-09-18, part 5)
A control-plane daemon that re-adds an evicted key produces a flap. Norn detects
it (N evictions in W) and either keeps alarming or takes the interface down. Fail-
closed is a deliberate operator choice, never a default (D-005 spirit). The real
fix for NetBird is an upstream peer-admission hook (Phase 7).

## D-016 · Nodes gossip checkpoints and tiles to each other over the tunnel (2026-09-18, part 6)
Peers serve their adopted checkpoint and tiles on the WireGuard address. Buys
liveness under a log freeze and split-view detection even when witnesses collude:
witnesses guard against the log, gossip guards against the witnesses. Rejected:
control-plane-only distribution (Tailnet Lock's freeze weakness); a separate
gossip transport (the tunnel already authenticates peers and needs no new ports).

## D-017 · Witness cosignature time is the node's clock for freshness (2026-09-18, part 6)
`quorum_time` = k-th newest cosignature timestamp; age is tracked on the monotonic
clock from adoption. Wall clock only raises CLOCK_SKEW. Rejected: trusting the
node's wall clock (A11); Roughtime now (v2 option).

## D-018 · Policy text is verbatim tlog-policy; the anchor lives in norn.trust (2026-09-18, part 6)
No Norn dialect of the policy language, so any tlog-policy tool parses it.
The OpenTimestamps anchor is a separate trust-file table evaluated off the
handshake path. Rejected: extending the grammar with an `anchor` line.

## D-019 · The ssh-agent protocol is the only signer interface (2026-09-18, part 7)
TKey, YubiKey-OpenPGP (via gpg-agent), password-manager agents and software keys
all present Ed25519 keys through it and return raw Ed25519 signatures. Norn stores
no private keys of its own. Rejected: Secure Enclave and TPM (P-256 only, no
Ed25519); a Norn-specific keystore; FIDO2 `ed25519-sk` in v0 (its signature is a
FIDO assertion, needs a second signature kind — Phase 7).

## D-020 · Log key and witness policy rotate via root-signed log entries with an overlap window (2026-09-18, part 7)
`log_key` and `policy` entries evolve trust inside the log; the trust file holds
only initial keys + genesis hash. The log signs with old and new keys for
`overlap` so stale trust files still bootstrap. Rejected: re-issuing trust files
to every device on every rotation.

## D-021 · Loss of the root quorum is recovered by re-genesis, made cheap by `norn migrate` (2026-09-18, part 7)
Append-only logs cannot un-steal a root. `norn migrate` produces a new genesis
and batch re-enrollments from persistent device keys, so the only per-device step
is importing one new trust file. Rejected: any "root override" backdoor — it would
be the thing an attacker steals.

## D-022 · Demos are one attack against three stacks, run twice (2026-09-18, part 8)
Plain WireGuard (owner: prevented), NetBird (watchdog: evicted + fight), Headscale
(observe: detected, honestly not prevented). Showing the honest limitation next to
the wins is what makes the wins believable. Rejected: a single "look, blocked" demo.

## D-023 · The monitor is an enrolled peer; alerts go to ntfy and Home Assistant (2026-09-18, part 8)
Being a peer gives it every node's evidence and metrics over the tunnel with no
new ports, and keeps it off the enforcement path. Phone push + a light turning red
are the demo outputs; Alertmanager/email for real deployments. Rejected: a
separate monitoring network; the monitor as a log-side component (it must be
independent of the log operator).

## D-024 · Recordings are generated by vhs tapes gated on assertion scripts (2026-09-18, part 8)
`run.sh` asserts the outcome and only then renders the tape, so every video in the
README is reproducible from `make demos`. Rejected: hand-recorded screencasts.

## D-025 · Apache-2.0 (2026-09-18, part 9)
Patent grant matters for a security protocol meant to be reimplemented; matches
Tessera/witness (Apache-2.0) and is compatible with torchwood/wgctrl (BSD-3).
Rejected: MIT (no patent grant); AGPL (blocks the NetBird/Headscale integrations).

## D-026 · `labels.ip` and `labels.endpoint` are reserved advisory hints (2026-09-19, 0.2)
Owner mode needs allowed-ips and endpoints from somewhere; signed labels are the
simplest signed source for static labs and homelabs. They are hints: a control
plane may override endpoints, never keys. Rejected: first-class `allowed_ips`
field in `enroll` (would make the log the routing authority, which it is not).

## D-027 · Encoding profile: no null, no negatives, no floats, map keys < 24 bytes (2026-09-19, 0.2)
Restricting CBOR to this subset makes RFC 8949 §4.2.1 and the older RFC 7049
key ordering coincide, removes every encoder-specific ambiguity found in CBOR
libraries, and keeps a decoder small enough to fuzz to the ground. Rejected:
"whatever cbor2/fxamacker emit by default".

## D-028 · `signer_remove` has no quorum invariant (2026-09-19, 0.4)
Found while building the rejection vectors: a symmetric "don't drop below
threshold" check on `signer_remove` would make the *last* signer key
unremovable — exactly the key you must be able to remove when it is stolen
(threat A3). Roots can always `signer_add` afterwards, so the degraded state is
recoverable. `root_remove`/`root_thr` keep their invariant, because losing the
root quorum is not recoverable in-log (R5 re-genesis). Rejected: symmetry for
its own sake.

## D-029 · Trust fingerprint is 80 bits of Crockford base32, not 4 words (2026-09-19, 0.5)
SPEC §9 originally said "first 8 bytes … rendered as 4 words from a 256-word
list" — internally inconsistent (4 words from 256 words is 32 bits, not 64) and,
at 32 bits, **grindable**: threat A10 is an attacker who substitutes the trust
file, and a second preimage that is also a valid trust file pointing at their log
is ~2³² work — minutes on a GPU. Now 10 bytes = 80 bits, Crockford base32
(omits I/L/O/U, the confusable characters), 4 groups of 4. Also avoids freezing
an English wordlist, which is a poor comparison aid for non-English speakers.
Rejected: BIP-39/PGP wordlists (provenance and licensing); more words from a
small list (harder to read aloud than 16 characters, no security gain).

## D-030 · Fixture policy text uses real verifier keys (2026-09-19, 0.5)
The `policy` entry and the trust file now carry actual tlog-policy text built
from the fixture's log and witness keys, so Go's policy parser is exercised by
the vectors rather than a placeholder string. Changed `entries/13-policy` and
`log/28-policy` bytes; no other entry moved.

## D-031 · An exact entry is usable at most once, accepted or rejected (2026-09-19, 0.7a)
*Key superseded by D-070 (2026-10-07): "exact" is the signed content for an entry that decodes, the bytes otherwise. The intent stands.*

Raised by the cold-model gate as an undecided question (D15). Entry hashes enter
the `dup-entry` seen-set **before** validation, so a rejected entry cannot be
re-inserted at a later index to take effect against a changed state. Concretely:
without this, a log operator could re-insert the original `enroll` of a revoked
device to resurrect it — `after` bounds reordering (`after ≤ index`) but not
re-insertion further along the log. Rejected: only remembering accepted entries
(simpler, but leaves that replay window open).

## D-032 · A `rotate` that installs a new identity key must prove possession of it (2026-09-19, 0.7c)
Was open question D20. When `rotate.body.device_pk` is present the entry MUST
carry a valid `device` signature from **both** the current and the incoming key.
Only the device can rotate (the current key must sign), so installing a key it
does not hold harms only itself — but irrecoverably: it could never rotate again
without a signer-assisted re-enrolment. The device holds both keys at that
moment, so the second signature costs nothing, and it matches D-008's
proof-of-possession rule for `enroll`. Rejected: accepting the new key on the
current key's word alone (one typo bricks the device).

## D-033 · `bad-thr` is about the value, `root-invariant` about the resulting set (2026-09-19, 0.7c)
Was open question D11: `root_thr` with `thr > len(roots)` satisfied both
definitions. `bad-thr` now covers any `signer_thr`/`root_thr` value outside
`1 … len(set)`; `root-invariant` is reserved for `root_remove` shrinking the set
below the threshold. Vectors 42 and 25 pin both sides.

## D-034 · The witness policy has exactly two homes, never three (2026-09-19, 0.7d)
Was loose end D29. `params.witness_policy` is removed. The policy lives in
`norn.trust.policy` (what a node is provisioned with) and in the `policy` entry
type (what supersedes it in-log, D-020). A third, "informational" copy in
`params` is how two verifiers come to disagree about the witness quorum — the
very thing guarding the log against a lying operator. Rejected: keeping it
documented as advisory; advisory copies get read.

## D-035 · SPEC.md structure is verified by the build (2026-09-19, 0.9a)
Two normative sections were deleted by my own regex splices and neither the
test suite nor a full conformance run noticed: §14 (0.2, an over-greedy
three-line substitution ate the heading after the bullet it targeted) and the
canonical-JSON rules (0.7d, a §12 rewrite spliced between two anchors that
bracketed more than intended). Vectors cannot catch this — a section with no
vectors can vanish silently. `internal/specdoc` now parses SPEC.md on every
`make ci` and fails on a numbering gap, a duplicate number, a dangling `§N`
reference, an empty section, or the absence of any section named in a required
manifest. Rejected: "be more careful with sed".

## D-036 · `kid` is a constrained field: 16 lowercase hex, else `decode` (2026-09-19, 0.9b-1)
Was open question E6. A malformed `kid` is a schema violation, not a key that
merely fails to resolve — the two produce different reason codes, so leaving it
unstated lets two implementations disagree about the same entry. The `sigs`
array's sorted-and-unique requirement is enforced the same way: accepting an
unsorted array would give one signature set two canonical forms, which defeats
the point of a deterministic encoding.

## D-037 · `revoke.reason` and `genesis.params` are OPTIONAL (2026-09-19, 0.9b-1)
Was E8, where §4.3 and §5.1 disagreed. Absent `reason` is equivalent to `""`;
absent `genesis.params` means the §4.5 defaults. Both match the reference
implementation, which is what the vectors already encode.

## D-038 · Entry bodies are closed schemas, like the envelope (2026-09-19, 0.11a)
Run 3 shipped a variant that left bodies open to unknown keys and passed the
whole suite — and so did this implementation at the time, by accident rather
than by rule. Two implementations agreeing without a rule is not agreement; the
next one closes them and diverges. Bodies are now closed: §4.3's table is the
complete key list per type, an unknown or missing key is `decode`, and a
per-type `BODY_KEYS` registry enforces it in one place rather than in fourteen
handlers. `params` is the exception, its keys being the §4.5 parameter names.

## D-039 · `thr: 0` is `bad-thr`, never `decode` (2026-09-19, 0.11a)
§4.0's field table listed `thr ≥ 1` among constraints whose violation is
`decode`, while deferring it "to replay"; §5.2 called a zero threshold
`bad-thr`. The value is a well-formed uint, so nothing about it is a schema
violation — the `thr` row is removed from §4.0 and `bad-thr` owns it. Both
halves of the clause are now vectored: 0 (61) and above-the-set-size (19).

## D-040 · Encoding negatives must isolate the rule, and ship with a control (2026-09-19, 0.11b)
Run 3 observed that the encoding-profile negatives were over-determined: a
`null` in a typed field is rejected for the type, so the vector never exercises
the profile rule and an implementation skipping profile checks still passes.
Two consequences. First, the *type* bans (floats, negative integers,
`undefined`) are untestable by construction — no Norn field would accept such a
value — and the spec now says so rather than pretending a vector covers them.
Second, the *encoding* bans are testable precisely because a lenient decoder
turns them into a **valid entry**: tag-wrapped values unwrap, indefinite strings
concatenate, duplicate keys resolve last-wins. Those four are vectored, each
proven isolating by a deliberately permissive decoder in the fixture, and the
unpatched control they are patches of ships beside them — without a control, a
negative can be rejected for a fault its author did not intend.

## D-041 · Vector names derive from their index; nothing is addressed by number (2026-09-19, 0.11c)
Entry names drifted twice: inserting a vector shifts every later index while a
hard-coded name stays put, so `72-after-below-index` ended up at index 76. Worse,
one vector fetched the entry to duplicate as `b.items[67]` — a stale number there
would silently point at an *accepted* entry and quietly turn a `dup-entry` vector
into something else. Names are now `f"{b.index}-…"`, the duplicate source is
looked up by the property it needs (`_first_rejected`), and two tests fail the
build if any name and index disagree. Same lesson as D-040 and the derived file
counts: assert the property, never the magic number.

## D-042 · The build verifies the vectors, not just the code (2026-09-19, 0.12)
Nothing checked that the *committed* vectors still match what the reference
implementation produces, which is how seven orphan files from a renumbering
survived three conformance runs — the suite tested the code against the vectors
and never the vectors against their source. Now: `make vectors-check`
regenerates into a scratch tree and diffs, `make ref-test` runs the reference's
own tests, both in CI; and `internal/specdoc` gained Go-side checks that need no
Python — no orphan files, every manifest entry has its `.cbor` and a matching
`.reason`, names agree with indices, and the anchor's `genesis_hash` really is
the leaf hash of entry 0.

## D-043 · Signature verification must be provably load-bearing (2026-09-19, 0.13a)
Gate run 4 stubbed Ed25519 verification to return `true` and reproduced the
entire manifest. Every "bad signature" negative in the suite was detectable
without cryptography — a *missing* signature, too *few*, one by the *wrong*
device, a *mislabelled* role. The one thing none of them did was **fail to
verify**. Two vectors now carry signatures that are syntactically perfect and
cryptographically wrong, and a test fails the build if stubbing verification
ever stops changing the outcome. A conformance suite that a signature-blind
implementation passes is not a conformance suite.

## D-044 · A negative must fail for its own rule, by one of two constructions (2026-09-19, 0.13a)
Patching a byte inside the signature preimage breaks the signature, so the
vector is rejected for that instead of the rule it names. Either the patch
**canonicalises away** (a stripped tag, a joined indefinite string, a resolved
duplicate key, reordered signatures) and the original signatures still verify,
or it **cannot** (invalid UTF-8, an oversized integer or map key) and the entry
must be **re-signed over the patched preimage**. A test asserts one of the two
holds for every encoding negative, and that no entry's `after` exceeds its own
index. Three vectors violated this and one had *three* independent faults.

## D-045 · The spec cites vectors by name, never by index (2026-09-19, 0.13a)
§12.1's coverage table drifted twice, most recently with two different offsets
in the same table, because inserting a vector renumbers every later one. Names
are stable under insertion; indices are not. `internal/specdoc` now fails the
build if a citation stops resolving against the manifest, so the table cannot
quietly become fiction again.

## D-046 · The body check runs *after* the authorisation check (2026-09-19, 0.13b)
§5.1 says step 7 (quorum) precedes step 8 (the type rule, which begins with the
body check), and spells out the consequence: an under-signed governance entry
with a malformed body is `threshold`, not `decode`. My reference implementation
did the opposite — it validated the body first. Gate run 4 predicted exactly
this divergence as an unpinned variant, and it turned out I was on the wrong
side of my own spec. Implementation corrected to follow the spec, and vectored.

## D-047 · Resource limits are specified and enforced (2026-09-19, 0.13b)
Run 4 noted the profile bounds key lengths and integer magnitude but says
nothing about nesting depth or total size, so a conforming decoder is a trivial
stack-exhaustion target — and it had to invent a depth cap with no basis in the
text. §4.0 now fixes depth at 8 (the deepest a valid entry can reach is
`body.labels`) and entry size at 65536 bytes, and the reference enforces both
with tests, including a truncated length header that must fail without
allocating.

## D-048 · `sigs` ordering is a schema rule, not an encoding rule (2026-09-19, 1.1)
Surfaced immediately by the Go implementation: `bad-unsorted-sigs` decodes
cleanly at the CBOR layer, because CBOR canonicalises *map* key order and says
nothing about *array* order. The sorted-and-unique requirement on `sigs` is
therefore enforced during envelope validation (§5.1 step 3), not by the codec.
§4.0 now says so and §12.1 files the vector under schemas rather than the
encoding profile. Exactly the kind of gap a second implementation finds by
existing — the first payoff from starting Phase 1.

## D-049 · The log writes its own POSIX tiles; Tessera is the documented upgrade (2026-09-19, 2.3)
`PLAN.md` named Tessera for the write path and D-002 cited it as a reason to
choose Go. Measured before committing to it: `github.com/transparency-dev/tessera`
pulls **135 modules**, including Google Cloud Spanner, Storage, IAM, monitoring
and trace, because it ships every driver alongside POSIX. Norn's module graph
is currently **3**.

Weighed honestly:

- Tessera's value is at scale — batching, durability across replicas, cloud
  backends. A Norn log is 10¹–10⁶ entries, fully replicated to every node, and
  serves from a directory.
- The dependency would land in `norn-log` only, not in `nornd`, so a verifier's
  supply-chain surface stays small either way. That is the strongest argument
  for taking it, and it is why this is a close call rather than an obvious one.
- But `go.sum` and CI are per-module: every contributor and every build fetches
  all 135 to compile a program that writes a few hundred files.

Decision: `internal/tlogstore` writes the tlog-tiles layout directly, using
`x/mod/sumdb/tlog` (already a dependency) for the Merkle mathematics, with
write-then-rename for atomicity. **This does not weaken ground rule 3**, which
is about the *formats* being interoperable — and that is tested directly in 2.6,
where an unmodified `transparency-dev/witness` must cosign a Norn checkpoint.
Who writes the bytes does not matter; whether the bytes are right does.

Upgrade trigger, recorded so this is falsifiable: adopt Tessera when the log
outgrows a single directory, needs more than one writer, or needs a cloud
backend — i.e. when its actual value is being used rather than paid for.

## D-050 · bech32m for the request text form, minus two BIP rules (2026-09-19, 2.9a)
HRP `norn`, checksum constant `0x2bc830a3`. **Dropped:** BIP-173's 90-character
limit, which is sized for addresses while a request is ~250 characters — and the
deviation is asserted narrowly in both implementations, so every *other* invalid
vector still fails. **Refused:** plain bech32, whose only difference is the
checksum constant; accepting both would accept the mutation the constant exists
to catch, and the negative vector proves it with the same payload under the
other constant. Uppercase is accepted because QR alphanumeric mode has no
lowercase; mixed case is not. Rejected: base64url (not QR-alphanumeric, no
checksum) · raw hex (twice the characters) · a Bitcoin bech32 library (a
dependency for 120 lines, checked against the BIP's own vectors instead).

## D-051 · One module owns the §2/§4.0 field rules (2026-09-19, 2.9a)
`nornref/fields.py` and `internal/fields`. Entry bodies (§4.3) and enrollment
requests (§16.1) share `device_id`, `labels`, key-length and uint rules; the
second copy was about to be written. **Extracting them found a live divergence:**
the reference accepted a CBOR `true` wherever a uint was required, because
`isinstance(True, int)` is true in Python, while Go's type switch refused it —
so the two implementations disagreed about whether `{"expires": true}` is a
valid `enroll` body. No vector covered it, so nothing failed. Now both refuse,
and `requests-bad/bool-expires` binds a third implementation to the same answer.

## D-052 · Each vector generator prunes only what it owns (2026-09-19, 2.9a)
`gen_vectors.py` declares `OWNED` and `FOREIGN` and prunes inside `OWNED` only;
a path in neither stops the run. Until this checkpoint every `make vectors`
silently deleted `served/` and `proofs/` — eleven files — because prune removed
whatever that run had not written, and the two-provenance split of 2.7 had
reached `vectors-check` without reaching the generator. The Go generator already
owned its two directories by rebuilding them wholesale. Rejected: a denylist of
foreign paths (a new foreign directory would be deleted again) · dropping prune
(it exists because seven orphans from a renumbering survived three conformance
runs).

## D-053 · Norn writes the ssh-agent client, and tests it against a real agent (2026-09-19, 2.9b-i)
`internal/sshagent` implements the four messages Norn needs — request
identities, sign — rather than importing `golang.org/x/crypto/ssh/agent`.
**Measured:** that package brings **five modules** (crypto, net, sys, term,
text) and the whole SSH transport for a protocol Norn uses four messages of;
Norn's graph is 7 and its pitch is a NAS and a Pi. Same trade as D-049.

The real objection to hand-writing a wire protocol is that the author can only
test it against their own fake, which proves nothing — the self-agreement trap
this project keeps refusing. So the tests drive **OpenSSH's own `ssh-agent`**:
generate an Ed25519 key with `ssh-keygen`, load it with `ssh-add`, list it,
sign an entry through it, and verify the result as an ordinary §4.2 signature.
`NORN_REQUIRE_SSH_AGENT=1` in CI turns "not installed" into a failure so the
real-agent tests cannot quietly stop running. The fake agent stays for what a
real one will not do on request: sign with the wrong key, announce a gigabyte,
answer with the wrong message, claim another algorithm.

**A signature from an agent is verified before it is used.** An agent is a
separate process, sometimes another vendor's, sometimes hardware; a signature
that does not verify must fail in the CLI rather than in somebody else's
replay. Rejected: trusting the agent's answer (a broken agent would then
publish an invalid entry under the operator's name) · a Norn key store (the
thing the agent abstraction exists to avoid).

## D-054 · `entry.Sign` takes a `crypto.Signer` (2026-09-19, 2.9b-i)
Not a new Norn interface: `ed25519.PrivateKey` already satisfies the stdlib
one, so every existing call site compiled unchanged, and an agent-held key —
TKey, YubiKey, 1Password — is the same thing to an entry as a key in memory.
Ed25519 is enforced at the seam: a P-256 signer (Secure Enclave, TPM 2.0, which
`ENROLLMENT.md` part 1 says are unsupported) is refused with an error rather
than a panic, and a signer returning the wrong number of bytes leaves the
envelope untouched instead of writing a malformed `sigs` entry.

## D-055 · Tier 0 is an OpenSSH private key file, unencrypted, and Norn refuses the encrypted kind (2026-09-19, 2.9b-ii)
`ENROLLMENT.md` promised an "age-style scrypt" file. Three things were wrong
with it, and the checkpoint that implemented it is where they surfaced.

**The dependency measurement inverts the obvious answer.** `x/crypto/scrypt`
alone pulls the **same five modules** as all of `x/crypto/ssh` (crypto, net,
sys, term, text), because the cost is x/crypto's own `go.mod`, not the package
imported. So "a small KDF" was never cheaper than "the whole OpenSSH key
format" — it was the same price for less.

**The promise it breaks.** `ENROLLMENT.md` part 1 says Norn has "no key format
to invent". An age-style envelope around an Ed25519 seed is a key format, and
Norn would own it forever. The OpenSSH private-key format already exists, and
using it means `ssh-keygen` can make a Norn key and `ssh-add` can load one:
**tier 0 becomes tier 1 with no conversion**, which the tests check by loading a
Norn-written key into a real agent.

**The threat model it does not fit.** The file exists because `nornd` signs
`rotate` and self-`revoke` at boot with nobody at the keyboard. A passphrase
would have to live beside the key, which protects nothing. So encrypted keys are
**refused**, with an error that names the remedy (`ssh-add`), and a human's
signer key belongs in an agent — where a passphrase-protected key ends up
anyway, after one prompt.

Parsing is hand-written against `internal/sshwire`, under the rule D-053 set:
**hand-write wire formats, never crypto primitives.** Unencrypted
openssh-key-v1 is pure framing; the encrypted kind needs bcrypt-pbkdf, which is
exactly the primitive not to hand-roll — and refusing it is what keeps the rule
intact. Both directions are tested against the real tools, and the three copies
of the public key inside the file must agree, so a damaged or crafted file
cannot make Norn sign under an unexpected identity. Rejected: PBKDF2 from the
standard library (0 modules, but invents a format and picks a GPU-friendly KDF
for key material, which D-029 already refused for a fingerprint) · importing
`x/crypto/ssh` to read the encrypted kind (five modules for a case whose
passphrase would sit next to the key).

## D-056 · `rsc.io/qr` for the QR, and the uppercase request form (2026-09-19, 2.9c)
`ENROLLMENT.md` part 7 rule 4 is binding — any flow needing a second device
works with a phone camera — and a request is ~250 characters, which nobody
retypes correctly. **Measured: one module, no transitive dependencies, three
packages.** The graph goes 7 → 8. Hand-writing a QR encoder would mean
Reed-Solomon over GF(256), version selection and mask scoring, none of it
Norn's subject, and — unlike the ssh-agent protocol — there is **no reference
implementation on this machine to test it against**, so it would be exactly the
self-agreement this project refuses.

What Norn does own is the part a library cannot check: the quiet zone and the
light/dark mapping. A code with no quiet zone, or with its modules inverted, is
a valid QR that no scanner reads. So `Matrix` is built separately from the
drawing and checked module-for-module against the library's own map, the quiet
zone is asserted on all four sides, and the terminal colours are written
explicitly rather than relying on half-blocks, which would invert on a
light-background terminal.

**The QR carries the uppercase request.** §16.2 allows the uppercase form
precisely because QR alphanumeric mode has no lowercase letters, and the test
measures the saving rather than assuming it: the same payload is a strictly
smaller code in uppercase. The lowercase form is what goes to stdout.

**Honest limit:** no QR *decoder* was available here, so nothing in CI proves a
phone can read it. That proof is a `PLAN.md` Phase 2 gate line — end-to-end
enrolment with a phone camera, timed — and it stays open until the lab runs it.

## D-057 · An `enroll` entry carries the device's request verbatim (2026-09-19, 2.9d-i)
Was: §4.3 required a `device` signature on the `enroll` envelope. That envelope
is built by a **signer**, who picks `ts` and `after`, and the device is headless
and one-way — it prints one QR and is never heard from again. **The device could
not produce the signature the spec demanded.** Four cold-model gate runs and 208
tests missed it because the fixture holds every private key and signed one
envelope as the device and again as a signer: consent no real participant could
give, and indistinguishable from the real thing. Answered by the user: option C.

The body is now `request` — the §16 request, byte for byte. §5.1's device check
becomes "the embedded request decodes, its signature verifies under its **own**
`device_pk`, and its `net` matches the entry's". No new reason codes: a
malformed or foreign-network request is `decode`, a request whose signature does
not verify is `no-device-sig`.

**This is stronger than what it replaces, not a workaround.** A device signature
over an envelope proves the device saw *some* envelope. An embedded request
proves it consented to exactly this `device_id`, `device_pk`, `wg_pk`, labels and
expiry — and a signer cannot alter any of them without destroying the proof,
where before it could have restated them freely. `ts` and `after` stay with the
signer, the only party that knows the log. Each side keeps one job.

Consequences taken rather than hidden: the log fixture lost an entry rather
than gaining one, because §4.0's 23-byte map-key cap had to move to
`requests-bad/` — after this
change **no entry body has a free-form map left**, and putting the oversize key
anywhere else would let a closed-schema check fire first and hide a missing cap.
The field negatives (`bad-device_id-uppercase`, `bad-pk-length`, …) now sit
*inside* the request, in entries that are otherwise well formed and properly
signed, so an implementation treating `request` as opaque bytes accepts all
three. Rejected: a round trip to the device (no return channel to a headless
Pi; kills the under-3-minute gate) · the device building the whole entry (an
`enroll` could then never carry `after`, losing the ordering guard on exactly
the entry type that creates an identity).

## D-058 · The checkpoint file *is* the signed note, and the verifier checks it (2026-09-19, 2.9e-i)
Found while building the submission path: `logclient.Verify` had never used
`norn.trust.log_key`. It fetched an unsigned `checkpoint` file, rebuilt the tree
from the served entries, and required them to hash to the head **in that same
file** — internally consistent, signed by nobody. §10 step 2 says "verify log
signature", and `tlog.Verify` had existed since 2.6a, unwired.

The tamper tests of 2.5 all passed because they tampered in ways tree
recomputation catches. What they could not catch: a mirror, a peer serving by
gossip, or anyone on the transport handing over a log whose head no operator
ever signed. Without the check, `log_key` was decoration, §11's fork evidence
had nothing to point at — two conflicting **signed** checkpoints is what makes a
fork non-repudiable — and G6 held only by accident of the genesis pin.

So: `tlogstore.Open` now takes the log's signing key and writes the **signed
note** at `checkpoint`. There is no unsigned sibling. A file a verifier is not
allowed to believe should not exist where somebody might read it by mistake,
and `checkpoint.signed` was exactly that. `logclient.Anchor` carries the
verifier keys (plural, for a `log_key` rotation's overlap window), and a Verify
with no key at all is refused rather than silently skipping the step.

**Still owed, and now written down in §10 itself:** the witness-policy check.
That needs a cosignature, which needs a running witness — Phase 4, the same
item as 2.6b. Until then Norn verifies *who wrote* the head, not that the head
was shown to anybody else.

## D-059 · wgctrl, paid for once and fenced in (2026-09-19, 3.5b)
**Measured: the graph goes 8 → 24.** wgctrl's own requirement list is 18 modules,
but five of them (x/crypto, x/net, x/sys, x/term, x/text) were already there, so
the net cost is **16 new modules** — mdlayher's netlink stack, gvisor, wintun,
and wireguard-go itself. By far the largest jump in the project, and it lands in
the component that runs on a Pi.

Taken anyway, because the alternative is worse in the way that matters.
`wgctrl` is what `PLAN.md` and `ENFORCEMENT.md` part 2 already chose, and its
backend table *is* wgctrl's capability matrix. Writing it ourselves would mean
hand-rolling **generic netlink** for kernel WireGuard — family resolution,
nested attributes, dumps — on a machine with no netlink to test against. That
is the neighbour of D-053's rule: hand-write wire formats, never crypto
primitives, and **never a kernel protocol you cannot test**. A mis-parsed peer
list is a security failure, not a formatting bug.

What makes it affordable is that it is **fenced in**, and the fence is tested.
`internal/wgdev` is the only package that imports it, and `internal/depgraph`
asserts that `cmd/norn`, `cmd/norn-log`, `internal/reconcile`, `internal/agent`,
`internal/peertable` and `internal/endpoint` do not — so the CLI stays light,
the log server stays small, and every enforcement decision including the A1
swap attack remains a unit test against `peertable.Device` rather than a lab
run. Rejected: a hand-rolled netlink client (untestable here, and the failure
mode is silent) · UAPI-only support (would drop kernel WireGuard, which is the
platform the gate measures) · shelling out to `wg` (parsing a human-readable
format as an authority, with no way to distinguish absent from empty).

## D-060 · `hard_stale` is tested before `fresh` (2026-09-24)
§8.1's four freshness states are evaluated in the order listed, first match
wins, and `hard_stale` comes before `fresh`.

**Why.** The two predicates overlap: both hold whenever `S_hard < elapsed ≤ S`.
`S` is `params.staleness`, which a **root quorum can raise**; `S_hard` is the
node's own opt-in floor and is deliberately not a `params` key, for the reason
D-034 gives about the witness policy — things that decide whether to trust stay
local so the network cannot lower them. Testing `fresh` first makes `S_hard`
unreachable whenever `S` is at or above it, so the roots could lift every
node's local hard stop without touching a single node's configuration. A limit
the network can raise is not a local limit.

The fixture builds the trap without anyone arranging it: genesis sets
`staleness: 600`, `log/29-params` raises it to 900, and `cmd/nornd` accepts any
`S_hard` at or above 600 — so `S_hard = 700`, a sensible choice while `S` was
600, lands in the overlap permanently and silently.

**Rejected.** *Keep `fresh` first and require `S_hard > S`* — preserves the
ladder as originally drawn (fresh → degraded → hard_stale, ordered by elapsed),
but leaves the overlap quietly meaning "no hard limit", and the config guard
compares against §4.5's *default* rather than the live `staleness`, so it does
not prevent the inversion it was written for. *Keep `fresh` first and alarm on
the inversion* — most in keeping with "no silent divergence", and the honest
runner-up; rejected as the larger change for the same outcome, since under
D-060 there is no inversion to alarm about. The cost of D-060 is that a node in
the overlap goes straight from `fresh` to `hard_stale` with no `degraded` band,
which is what asking for a tight hard limit means.

Consequence: `cmd/nornd`'s floor on `hard_stale` stays, but only as a typo
guard. It is no longer a claim that `S_hard` must exceed the network's
`staleness`; that configuration is legitimate and is the point.

## D-061 · Closed reason codes for §10 and §11.1 (2026-09-30)
The verifier's refusals (§10) and the fork-evidence checker's refusals (§11.1)
each get a closed, normative vocabulary in §5.2's style, and the suite's
`cases.json` names those codes where it now names `says` substrings.

**Why.** An ordering between two refusals is observable only if the two are
distinguishable. §5.2 makes them so for replay, and that is the only reason
§5.1's step order can be vectored at all. Outside replay every refusal was the
same event to a black-box run, so three rules the document states — §10's
signature-decides-before-origin, and §11.1's two step orderings — were pinned
only by a phrase in a JSON file (cold gate run 11, D10). The deeper argument is
the operator's: two nodes that refuse the same checkpoint for different reasons
have no shared word to say so, and §11 rule 4 makes one class of refusal
permanent until a human installs a new trust file. §5.2 exists because that
argument was accepted once, for replay; nothing about it is weaker one layer up.

**Rejected.** *§11.1 only* — half the surface, but leaves §10's ordering
unvectored and the verifier's alarms without a shared vocabulary. *Leave it as
recorded* — honest, but three stated rules that nothing can check, in a suite
whose claim is that a rule stated is a rule reachable.

**Cost, accepted.** New normative surface on a frozen v1, which every second
implementation must now emit. The codes are part of the contract from here on;
`says` stays, as a semantic hint, for the suite's own discipline.

## D-062 · Canonical base64 wherever the protocol carries it (2026-10-02)
Every base64 field a note, a key or a receipt carries — a checkpoint's root
line, a signature payload, a verifier key's data — MUST be canonical: standard
alphabet, padded, and **pad bits zero** (RFC 4648 §3.5). A non-canonical
spelling is refused by the step that reads the field.

**Why.** §6 and §7 already argue that two spellings of one head are an attack
surface — gossip, caches and de-duplication keyed on bytes an attacker chooses
— and closed that hole for the size line and payload lengths. Non-zero pad
bits are a second spelling of the same root or signature, and both
implementations accepted them, because Go's `encoding/base64` and Python's
decoder are lax about pad bits by default (cold gate run 12, D14a).

**Rejected.** *Specify the lax behaviour as it is* — documents the hole §6 and
§7 argue against.

**Cost, accepted.** Inputs that verify today are refused; every implementation
must use a strict decoder or check the pad bits itself.

## D-063 · Closed refusal codes for receipts (2026-10-02)
Checking a submission receipt becomes a stated procedure with a closed list of
refusal codes, in §10.1's style.

**Why.** §7 calls receipts "non-repudiable proof of log misbehaviour" — an
artifact a stranger checks, exactly like a proof bundle or fork evidence, and
D-061 gave those two closed codes for the reason that applies here unchanged:
two readers that refuse the same receipt must refuse it for the same reason,
or a vector can only ask "refused?" (cold gate run 12, D11).

**Cost, accepted.** A third closed vocabulary that every implementation must
emit.

## D-064 · `SPEC.md` absorbs what is normative in the companion documents (2026-10-02)
What `SPEC.md` cites as normative from `GOSSIP.md`, `ENFORCEMENT.md` and
`ENROLLMENT.md` — the parts a verifier or a node needs to interoperate, such as
the checkpoint acquisition order and the witness-time clock — moves into
`SPEC.md`. The companion documents stay, and are called informative.

**Why.** A reader holding the spec and the vectors, which is the reader the
cold-model gate models, has none of the companion documents, so "every
cross-reference resolves" was false for exactly that reader (cold gate run 12,
D22).

**Rejected.** *Ship them beside `SPEC.md`* — three more documents a second
implementer must read and keep consistent, most of which is operational
guidance rather than protocol.

## D-065 · No closed codes for trust files, requests and policies in v1 (2026-10-02)
Those layers keep `says` hints matched by hand; closed vocabularies for them
are recorded for v1.1.

**Why.** A code list per layer is a large normative addition, and the
remaining gate is close. The layers that strangers check against each other —
the verifier, evidence, receipts — have codes (D-061, D-063); these are read
by the node that loads them (cold gate run 12, §5 M2).

## D-066 · Match the policy parser to C2SP `tlog-policy` (2026-10-02)
Norn's policy grammar follows the current [C2SP `tlog-policy`](https://c2sp.org/tlog-policy) format for line endings, definition order, reserved names, verifier keys, duplicate keys, and allowed control bytes. Every directive line, including the last, MUST end in line feed. A `quorum` MUST refer to a witness or group defined earlier, except for the predefined `none`; `none` cannot be defined as a witness or group and cannot be a group member. Witness and group names share one namespace. Names `all` and `any` remain legal in name positions; they are special only in the threshold position. Every verifier key MUST parse with its key ID recomputed, and its algorithm MUST match its directive (`0x01` for `log`, `0x04` for `witness`). Repeated keys are detected by the underlying public key, even when vkey names or IDs differ. The only allowed ASCII control bytes are tab and line feed; other ASCII controls, including DEL and carriage return, are refused.

**Why.** The implementation review found that Go accepted forward quorum references while Python refused them; both accepted definitions shadowing `none`; neither parser validated vkeys or algorithm roles; and both compared duplicate keys as text. The current C2SP document settles those points explicitly. It also defines duplicate vkeys by underlying public key, requires a final line feed, and closes the byte-level control set. Those requirements and the policy's opaque-byte rule were not all captured by the local wording. This aligns the format with the source Norn already claims to use (cold gate run 12, D7–D8).

**Rejected.** *Preserve the earlier `SPEC-DECISIONS-12.md` readings where they conflict with C2SP* — a policy that is accepted by Norn but refused by another `tlog-policy` reader is not interoperable. *Require canonical base64 here* — D-062 assigns that cross-format change to 6.5l-vii-d-xi; this decision requires successful key decoding and a matching key ID, while canonical pad bits remain that later checkpoint's work.

**Cost, accepted.** Go tightens forward-reference and key validation; both implementations refuse previously accepted policy text that violates C2SP. The policy grammar remains a verifier input with no closed refusal-code vocabulary (D-065).

## D-067 · Trust-file URLs are opaque application data (2026-10-02)
Trust-file URL fields are text and are not checked for URI syntax. `log_urls`
must still be a non-empty array of non-empty strings. A witness `url` is
optional text; if present, an empty string is permitted. Optional URLs on
C2SP `log` and `witness` policy lines are application-specific and do not have
to equal `log_urls` or `witnesses[].url`. Key and witness-name correspondence
rules remain unchanged.

**Why.** C2SP `tlog-policy` makes the meaning of a policy URL
application-specific and says offline verification does not require URLs. The
trust parser already treats URL values as text rather than applying URI
validation. Only `log_urls` has an explicit non-empty constraint in §9.1; an
optional witness URL is a distinct case. Preserving a present empty URL also
requires Go to retain field presence, since absence and empty text serialize
differently in canonical CBOR.

**Rejected.** *URI-validate every URL or require policy URLs to match the trust
file's URL fields* — endpoint syntax and use belong to the application, and a
policy URL is not part of the key or witness correspondence rule.

**Cost, accepted.** A trust file can carry text that a network client cannot
use as an endpoint; the trust parser does not reinterpret or rewrite it.

## D-068 · The cold-model gate converges on behaviour, not on a verdict string (2026-10-07)
`PLAN.md` Phase 6's line "Cold-model gate repeated on frozen spec" passes on
**two consecutive sealed runs with zero behaviour-changing defects** — a
defect the run's own report rates high or medium — with every low-severity
finding of both runs recorded in `SPEC.md` §12.1's not-vectored list. Each run
keeps the existing protocol: a fresh agent, a new sealed copy made with `git
archive` from the pushed head, run 11's prompt, and a transcript audit showing
no access to this repository and no web access.

**Why.** Thirteen runs have shown that a stochastic reader always finds
something to say about a large document: runs 11–13 passed every check
(622/622, 1,212/1,212, then 1,353/1,353) and still could not return
`SPEC SUFFICIENT`, because the verdict also rates prose a second implementer
would never diverge on. A gate that no run can pass is not a gate. What the line exists to
prove is that two implementers given only `SPEC.md` and the vectors build the
same thing; a high or medium finding is exactly a place where they would not.
Two runs in a row guards against one lucky reader.

**Rejected.** *Keep requiring the exact string `SPEC SUFFICIENT`* — it never
terminates, and each round adds normative text that is itself new surface for
the next reader. *One clean run* — a single reader can miss what the next one
finds; each of runs 11–13 raised defects the run before it had not. *Drop the gate* — it
is the only check in the project that no session author can game.

**Cost, accepted.** A low-severity ambiguity can ship in v1, recorded and
visible in §12.1 rather than fixed. The severity rating is the reader's own,
so the transcript audit also checks that no finding is rated low while its
text describes two implementations disagreeing on an outcome.

## D-069 · What a node held outlives a restart and a reboot (2026-10-07)
A node keeps three things on disk, in a state directory that survives a
reboot (`nornd`: `state_dir`, default `/var/lib/norn`; `proven.json` stays in
`/run/norn`):

- the stored checkpoint §10 compares against, as the mirror of the log it
  verified;
- what it learned from that state: the log keys and witness policy it
  published (§9.4);
- the evidence of a fork it proved, whose presence is the freeze (§11).

At start the node verifies its mirror again under the trust file. If the trust
file's keys or policy refuse it — the only refusals what a node learned can
change — it is verified once more under what the mirror's own entries publish,
which is the authority it was accepted under: a root quorum, replayed from the
pinned genesis. What verifies is held as the stored checkpoint. It is compared
against and is **not enforced** until a checkpoint verifies in the new
process. A mirror that does not verify is reported (`MIRROR_UNUSABLE`) and
ignored. Evidence is written durably and never over another file.

**Why.** §10's comparison protects only a node that remembers what it held.
A restarted node held nothing until its first verification, so it accepted an
older, correctly cosigned head of its own log and undid every revocation since
(review F1, audit SEC-004). The freeze and the head lived under `/run`, a tmpfs
cleared at boot (SEC-006). And a node restarted after an in-log key rotation
could verify neither its mirror nor its log again. §11's "forever" has to
outlive the machine, and a restart or a reboot is something an attacker can
cause.

**Rejected.** *Enforce the restored head at once* — it verified at a witness
time this process cannot place, and installing it during an outage would let a
restart reopen peers an `S_hard` drop had closed. *Refuse to start when the
state directory is on a tmpfs or cannot be written* — a node that cannot keep
its freeze still enforces, and refusing would leave the network with no node;
`nornd` warns instead. *Persist only the checkpoint* — the learned keys and
policy come from replaying the entries, and the mirror already holds them to
serve peers. *Name evidence by content hash* — §11 names
`fork/<unix>.evidence`.

**Cost, accepted.** One full verification of the mirror at start. The mirror
does not yet survive a power cut, because it syncs nothing; its head can then
name a file the disk never received, and the node reports it unusable and holds
nothing. That is `HARDENING-PLAN.md` H4-f. The freeze does survive one.

## D-070 · Two entries are the same entry when their signed content is the same (2026-10-07)
`dup-entry` (§5.1 step 1) is keyed on SHA-256 of the entry's **signature
preimage** — the envelope encoded without `sigs` (§4.2) — for every entry that
decodes, and on the raw bytes for one that does not. Accepted or rejected, as
D-031 already says: the first appearance of a signed content is the only one
replay will ever apply. `norn-log` refuses a submission whose preimage it
already holds. Supersedes D-031's key, not its intent.

**Why.** D-031 was written to stop a revoked device's original `enroll` from
being re-inserted later. It keyed "exact entry" on the bytes as received, and
`sigs` is outside every signature's preimage while an unresolvable signature is
ignored (§5.2). So any past entry plus one junk signature — or minus a surplus
one, or with a role label changed — was a new entry whose original signatures
still counted. On the shipped log, `spare` (revoked at 39) came back and the
3-of-3 quorum fell to 2-of-3; no key was needed (audit SEC-001, confirmed
2026-10-07 in Go, in the reference and in the vectors, where `log/70` and
`log/89` share a preimage and were both required accepted).

**Rejected.** *Refuse any signature that does not resolve* — closes one
variant; a dropped surplus signature still replays. *Remember accepted content
only* — reopens D-031's window for a rejected entry re-tried against a changed
state; it is a strict subset of this rule. *Document and defer* — leaves G3
false. *A validity window per entry* — replays inside it still work, and
honest entries expire behind a slow log.

**Recorded for v1.1, not rejected.** *Per-device sequence numbers* — each
`enroll`, `rotate` and `revoke` carries the device's next counter and replay
requires exactly it. Structurally stronger, and the owner wants it; it is a new
field, a device-side signing change and a full regeneration, so it is a v1.1
design beside D-065's closed codes, not a v1 fix.

**Cost, accepted.** An under-signed entry that reaches the log burns its
content: the signers re-issue with a new `ts`. That was already true of an
exact repeat under D-031, so the rule becomes simpler, not stricter in kind.
`log/89-two-sig-base` becomes `dup-entry`.

## D-071 · A node that lost its state corroborates before it trusts, and a node that kept it remembers how old its view was (2026-10-07)
Prompted by the IETF KEYTRANS architecture draft -10 (2026-10-07), whose §7.2
"State Loss" says what this threat model borrowed its structure from without
yet saying: a client that loses its local state loses its ability to detect a
fork, and the mitigations are parameters — the interval between out-of-band
checks and the auditor's maximum lag both far below the time between
state-loss events — and, for clients whose state is ephemeral, a third party
or a policy of not consuming what was inserted too recently. Norn's state is
the stored checkpoint (§10) and the witness clock (§15); its out-of-band check
is peer gossip every `T_g` (KT §3.3's third mechanism); its auditor is the
witness quorum, with maximum lag `S`. `T_g` = 30 s and `S` = 10 min are both
far below the interval between reinstalls, so the parameter rule holds. Three
things did not, found by reading the agent against §7.2 (audit SEC-004's open
remainder is two of them):

**(a) The witness clock did not survive a restart.** The node's estimate of
now was seeded by the first head to verify in the process, at age zero. A node
that had called its view `degraded` for two hours — or had dropped every peer
past `S_hard` — restarted into `fresh` on the very same head when the log
served it again; a restart is something whoever keeps a log stale can also
cause, so `S_hard` was a limit a restart lifted. **Decision:** the node writes
its estimate of witness-time now — the newest quorum time it has seen, carried
forward by monotonic time — to `<state_dir>/clock`, durably, whenever that
estimate has advanced a minute since the last write, whatever the log is doing.
At start the clock is seeded from the file, as a quorum time observed at
monotonic zero. The seed is a lower bound on now — the estimate was true when
written and time has not run backwards — so a head's age after a restart is at
least the age it had at the last write, and nothing is called fresher than it
was. A file that does not parse is ignored and reported; a missing one is a
first start and silent. Seeding the clock from the restored head was rejected
in H1 and stays rejected: a head's quorum time says when witnesses signed it,
not how long this node has held it.

**(b) A restarted node asked no peers until something verified**, because the
peer list was read from the head verified in this process; a node rebooted
while its log was down could not use the gossip that exists for exactly that.
**Decision:** the peer list is read from the head the node holds — the restored
one until something verifies. Those peers verified under the anchor as proven
when the node last ran. The restored head is still never enforced (D-069).

**(c) A node with no held head** — first start, state directory lost, mirror
unusable — has nothing to compare its first head against, so §10 cannot catch
a fork or a rollback for it: the first head verifies at any size, is enforced
at once, and is not checked against a peer until `T_g` later. If that head is
a branch cosigned by 2k−N colluding witnesses (A9), the node enforces the
attacker's branch for a round and then freezes on it — the outcome §11 exists
to prevent, and one a node with history would never reach, because it would
have refused the branch. This is KT §7.2's "not consuming what was inserted
too recently", for a node whose whole view was inserted recently.
**Decision:** a node holding no previous head treats its first verified head
as **uncorroborated**. It asks its proven peers in the same cycle, before
enforcing, and in every following cycle until one answers; a peer whose head
verifies under the anchor with the first head as the stored checkpoint
corroborates it (equal or extending it, and then adopted as today). While
uncorroborated the head **is** enforced when no peer answers — a node alone,
or one whose peers are reachable only through the tunnel it has yet to
configure (owner mode on a fresh interface), must be able to start — and the
node says so once (`FIRST_HEAD_UNCORROBORATED`). A fork proven against a head
this node enforced without corroboration leaves it no branch it can stand
behind: the desired set is emptied, as past `S_hard`, and the node freezes.
A node with no peers configured corroborates with nobody; its protection
after state loss is the witness quorum alone, which the operator chose when
leaving gossip off.

**Rejected.** *Hold the first head until a peer answers* — an owner-mode node
on a fresh interface can reach no peer until it enforces, and the first node
of a network never could. *Freeze on the uncorroborated branch as §11 does
for a held one* — continuity is §11's argument, and a node that enforced the
branch a cycle ago has none. *Ask the witnesses* — `tlog-witness` has no read
endpoint, and witnesses would then sit on the enforcement path. *Partition or
mirror other networks' logs* (KT §5.3) — one log per network, replicated to
every node, is the design; directories are a non-goal.

**Cost, accepted.** One small durable write a minute; up to `r` peer requests
per cycle while a head is uncorroborated, which ends with the first answer; a
fresh node whose peers are reachable adopts `T_g` sooner than today. No wire
format and no vector changes. `SPEC.md` §13.2 and §15 carry the node-contract
sentences; `THREAT-MODEL.md` gains A13.

## D-073 · A peer's allowed-ips are bounded by its enrollment's grant (2026-10-08)
`labels.ip` stops being advisory: under `params.routes = "granted"` (the default) a
node installs for a peer only allowed-ips within the masked prefixes its `enroll`
carried; a provider may narrow, never widen; a device enrolled without a grant gets
its key and no routes; `endpoint` stays overridable. Why: G1 proved the key and
nothing proved the routes, and in WireGuard a peer's AllowedIPs is its authority to
source those addresses — the one thing a compromised coordinator could still do was
hand a legitimate peer `0.0.0.0/0`. Supersedes the "hint" half of D-026 and keeps its
reason: the log bounds what a peer may claim; it does not route. Rejected: a
first-class `routes` entry type (more protocol than the hole needs; v1.1 if
re-enrolment proves too heavy) · leaving routes advisory (the hole).
**Recorded for v1.1, not rejected.** *Proof-carrying admission* — a peer presents a
fresh witnessed inclusion proof before the handshake and is installed just in time
within its grant; the coordinator becomes an address book. *Devices as witnesses* —
nodes cosign the heads they verified, and a policy may name k of a network's own
devices. Each is a wire protocol with its own freshness and denial-of-service
questions. `HARDENING-PLAN.md` H18, D-073's block in `BUILD-LOG.md`.

## D-072 · Five audit questions: a fork shrinks the enforced set to what both branches agree on; one Ed25519 predicate; v1 keeps log-key retirement and `quorum none` behind explicit settings (2026-10-09)
The owner's answers of 2026-10-09 to the audit's five questions (`BUILD-LOG.md`'s
6.5m-sec-dec block), after reviewing the recommendations; (a) and (c) are the
owner's own, sharpened in review.
**(a) A proven fork freezes authorization at the last state both branches agree
on, and keeps enforcing it — the enforced set may shrink and never grow** (the
owner's option D; superseding the recommendation to change nothing on the
interface). Once equivocation is proven a node consumes no new authorization
state from either branch. The safe state is the common prefix: the largest size
at which both branches have the same tree. The node keeps on its interface only
peers that are both enforced now and authorized at that prefix, so whatever
either branch added after the split — the rogue a split view exists to install —
is removed, and anything revoked after it stays out. The detecting node computes
the split from its own entries and the conflicting tree it just verified; a node
that only receives evidence needs the evidence to carry the split (its size, the
root there, and a consistency proof to each branch) — a change to §11.1's
evidence format. With no split point established, a node **fails closed** by
default (empty desired set): a fork is cryptographic proof that the log and a
witness quorum misbehaved, unlike staleness, which is why `S_hard` stays opt-in
while this does not. The `FORK` alarm is critical and repeats until a new trust
file. Accepted costs, stated: legitimate devices enrolled after the split, on the
honest branch too, lose their peers until recovery; an attacker who holds the log
key and 2k−N witnesses gains a way to cut a network off. Rejected: changing
nothing on the interface (leaves a split view's rogue connected after detection);
evicting against the node's own branch (keeps the rogue, which is on that branch).
**(b) A `labels` map, when present, carries at least one pair**; `labels: {}` is a
decode fault. One encoding of "no labels": absence.
**(c) §3 defines one implementation-independent predicate, NORN-ED25519-v1**,
covering canonical encodings of `A` and `R`, `S < L`, small-order and torsion
points, subgroup membership and the verification equation; admitting keys and
verifying signatures both follow it. The C2SP CCTV Ed25519 vectors (fetched with
the owner's leave, vendored with their provenance) and Norn's own edge vectors
decide it: Go, the Python reference and the cold-built verifier must give the
same answer on every one. A disagreement by `contrib/verify-py`, which is kept
byte for byte, is a finding answered by a new cold run, not a patch. A Mythos
review precedes the merge. A Rust implementation is not required.
Rejected: "as Go's `crypto/ed25519` verifies" (not a rule a second implementer
can read); leaving §3 as it is (two verifiers can disagree about a state).
**(c), design (2026-10-09, row 023r-a).** *The predicate.* A key and a signature's
`R` are accepted only as the canonical RFC 8032 §5.1.3 encoding of a point of
order exactly `L` — not the identity, no component of order 2, 4 or 8 — `S < L`,
and the cofactorless equation; under those conditions the cofactored equation
gives the same answer, because `[S]B − R − [k]A` then lies in the prime-order
subgroup, where only `O` is killed by 8. *Why order exactly `L` and not merely
"not small order"* (libsodium's and ed25519-dalek `verify_strict`'s line): a
point with a small-order component and a prime-order one is where the two
equations part — the CCTV set's `low_order_component` and `low_order_residue`
vectors — and a signer who holds such a key can make a signature one library
accepts and another refuses; an honest key `[s]B` and an honest `R = [r]B` never
have such a component, so excluding it costs nothing honest and removes every
formula-dependent case. *The CCTV set* (`C2SP/CCTV` `ed25519/`, 914 vectors,
commit `50a8ecf2`, 2026-09-25): 913 carry a flag and are rejected, one carries
none and is accepted; no vector has `S ≥ L`, so Norn's own vectors cover that
edge. *Libraries:* Go's `crypto/ed25519` is cofactorless and refuses `S ≥ L` and
non-canonical `R` but accepts small-order and mixed-order keys (the CCTV README's
"ref10" behaviour), so the Go predicate is implemented explicitly with
`filippo.io/edwards25519` (canonical = decodes and re-encodes to the same bytes;
order `L` = `[L]P = O` and `P ≠ O`) and every verification site goes through it;
the reference uses libsodium's `crypto_core_ed25519_is_valid_point` for `A` and
`R` and checks `S < L` itself. *The cold verifier* is cofactored and checks none
of this; the Norn edge vectors (023r-e) will fail under it, the second finding
of the same kind as 021r-b's, answered by the same new cold run.
**(d) v1: a `log_key` entry is for planned rotation;** a compromised log key is
contained by the witness quorum and remedied by a new trust file (R7, A2).
Verifier-side retirement is recorded for v1.1.
**(e) `nornd` refuses `owner` and `watchdog` under an effective `quorum none`**
unless `allow_no_quorum` is set; `observe` always runs; a policy lowered to none
while running alarms on the degraded cadence until restart.
**(a), design (2026-10-09, row 021r-a).** *The frozen set is the devices proven
at the split and at the node's own held head*, not "what was on the interface":
the second is what the node enforced per its branch, and it is recomputable from
the mirror after a reboot, which an interface snapshot is not. Routes come from
the split state's grant. *The evidence carries the split* (`split`, `split_root`,
a consistency proof to each head; version 2, eleven keys) because a node that
only receives the file holds one branch and cannot find the split itself; a
version-1 file still proves the fork and claims no split, so a reader fails
closed on it. *An accuser can understate the split and never overstate it*: both
proofs hold at every size up to the true split, so no maximality proof is
carried — understating is dominated by the fork itself, since whoever can sign
a fork can fork at entry 1. *The cold verifier* (`contrib/verify-py`, sealed at
`89b5b99`) refuses version 2 as `version`; when the version-2 vectors land
(021r-b) `make verify-py` fails on them, which is the finding H14's rule
anticipates, answered by a new cold run and never by editing the verifier.
**(e), design (2026-10-10, row 033r-a).** *Effective* is the policy the node
would verify under: a published policy it restored (§9.4) replaces the trust
file's, so a network whose roots raised a `quorum none` trust file's policy in
the log starts, and one whose roots lowered theirs to none does not. *The
running alarm is for the nodes a restart would stop* — `owner` and `watchdog`
without `allow_no_quorum` — and says so, so the refusal it predicts is not a
surprise; a node configured with the setting said in advance that this is what
it means, and `observe` never stops. *It keeps enforcing meanwhile*: the roots
lowering the bar is a governance act in the log, visible to every monitor, not
evidence that any peer stopped being proven.
Rows: 6.5m-sec-021r (a), 022r (b), 023r (c), 014r (d), 033r (e).

## D-074 · Cold gate run 13's eight questions: keys after rotation, one age, the signed-note profile, exact vkey comparison, sequential names, an ASCII key-name grammar, a `genesis` code, an allow-listed CBOR profile (2026-10-09)
The owner's answers of 2026-10-09 to run 13's eight questions (`BUILD-LOG.md`'s
6.5l-ix-b block), with the owner's refinements.
**(a)** Bundles and receipts verify under every log key the verifier trusts for
the origin and the policy of that state; a signature line's key name and key id
select the candidate key — no trial of every key — and unknown lines are
ignored. Retirement stays a trust-policy change.
**(b)** One normative age: §15's, the node's estimate of now from witness-signed
time (a lower bound that never moves backwards) minus the checkpoint's quorum
time. A Mythos review precedes the merge and states the exact boundaries (`>` or
`≥` at `S` and `S_hard`) and that clock skew never changes freshness.
**(b), reviewed (2026-10-09, row H5-f-b).** §15's definition stands, and the
review found the clock behind it wrong in the same direction §8.1's reading was.
*The estimate* is the largest lower bound the node holds — for every quorum
time `q` verified at monotonic `m`, `q + (now − m)` — not "the newest quorum
time plus monotonic time since": the code kept the newest quorum time, so a head
cosigned at a newer instant but learned long after an older one replaced a
larger bound with a smaller one and moved the estimate backwards, and the held
view looked younger than the node had already proven the world to be
(`detect/staleness.json` `newer-quorum-time-keeps-the-larger-bound`: 600 s and
`fresh` under the old clock, 1000 s and `degraded` under §15). *Boundaries:*
`>` at `S` and at `S_hard`, compared as durations; an age exactly on either is on
the fresh side, as the table already vectored. *Skew:* `CLOCK_SKEW` changes no
state (§15 already said so; T5 holds it; §8.1 now says it too). *The bound's
gap, stated rather than hidden:* monotonic time does not count a suspend, and
the clock file does not count the time between its last write and the next
start, so an age is a lower bound and the states err toward `fresh` by at most
that gap until the next verified checkpoint; a node SHOULD read a monotonic
source that counts suspended time where the platform has one (row
6.5l-ix-f-b-ii). Rejected again: wall time in either direction — letting a
forward wall jump age a view would let a wrong clock drop every peer, the
outcome A11 forbids.
**(c)** §7 and §10 are Norn's profile of the reused signed-note specifications:
lines whose name and key id match no trusted key are ignored; known lines follow
the witness policy; the signed text and every line MUST be valid UTF-8.
**(d)** "The same keys" means the same verifier key compared as canonical text —
name, algorithm and public key — for `witness` against `witnesses` and `log`
against `log_key`.
**(e)** Lines may follow `quorum`; names resolve in order — a `quorum` or `group`
line names only what an earlier line defined — and nothing defined later changes
an earlier line.
**(f)** Key ids are 8 **lowercase** hex digits. Key names in trust files and
policies follow an explicit **ASCII** grammar instead of a Unicode whitespace
predicate (whose tables differ between Go and Python); Norn's own log key names
are origins and already ASCII. A stranger's cosignature line with any other name
is still ignored, not refused (c).
**(g)** A served log whose entry 0 is not the anchored genesis — or that has no
entry 0 — is refused with a new `genesis` code by the shared verifier, so the
node, `norn verify`, the monitor and evidence checking agree. High priority.
**(g), amended by the owner 2026-10-10** (raised implementing 6.5l-ix-f-g: the
recommendation placed `genesis` between `head` and `fork`, which would have
stopped a node that holds an honest head from accusing a different-genesis
branch signed by the same log — today it does, as `fork`). Genesis validation
is a trust-domain check, but it MUST NOT suppress fork or rollback detection
against an already trusted head: a verifier that holds one first decides
`rollback` or `fork` against it, records the evidence and freezes; only with
no prior trusted head, or a log that passes that comparison, does a missing or
unexpected genesis refuse the history as `genesis` (the owner's
`ERR_GENESIS_MISMATCH`). §10.1: `head`, then `fork`/`rollback`, then `genesis`,
then `tiles` — `head` stays before `fork`, because the comparison needs a tree
rebuilt from entries that hash to the signed head.
**(h)** §4.0 states its CBOR profile as an allow-list: unsigned integers, byte and
text strings, arrays, maps, `false` and `true`; every other type, simple value
included, is refused; the existing rules (shortest form, definite lengths,
strictly increasing keys, the whole input) stand, with vectors for each.
Rows: 6.5l-ix-f's sub-rows (H5-f-a … h).
