# Norn — Decisions

Format: what · why · rejected. Newest at the bottom. Never delete; supersede.

D-060 to D-077 were written on 2026-09-30, from `BUILD-LOG.md`: after D-059
(3.5b) the choices were recorded only in the journal, and the first audit
(`docs/audit/ROADMAP.md`, documentation integrity pass) asked for them here.
Each names the checkpoint that made the choice and the `SPEC.md` section that
states it; where the day of a Phase 4 checkpoint is not recorded anywhere, the
heading gives the checkpoint and the day it was written down. D-077 is a
correction, not a choice, and says so. Superseded or
amended in part: D-011 by D-066, D-017 by D-062, D-018 by D-069, D-026 by D-060,
D-027 by D-070, D-055 by D-077, D-058's open item by D-061. D-020 is confirmed
and applied by D-067. Decisions that are still the maintainer's — D-a to D-l in
`docs/audit/ROADMAP.md` — are not recorded here until they are made.

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

## D-060 · Label hints are the device's own words and cannot name a key; the reserved name is open (2026-09-19, 3.3; recorded 2026-09-30)
Amends D-026. What stands: labels are advisory hints for owner mode, and a
control plane may override an endpoint, never a key (SPEC §4.0). What changed:
since D-057 the labels travel inside the device's own request, signed by the
device, so a signer cannot alter them without destroying that signature
(SPEC §4.3, §16.1). And 3.3 made "never keys" structural rather than checked:
`endpoint.Hints` has no key field, so a provider decorates devices the log
proves and cannot name a peer at all (`internal/endpoint`). A malformed label
is reported and evicts nothing; the device keeps the routes that did parse
(`TestAMalformedLabelIsReportedNotFatal`). A proven device no provider places
is still installed, and reported as unrouted.

**Not settled, and not settled here.** SPEC §4.0 and D-026 reserve `ip`;
`nornd` reads `allowed_ips`, `endpoint` and `keepalive`
(`internal/endpoint/endpoint.go`). A device enrolled with only the reserved
`ip` label is therefore installed with no allowed-ips and reported unrouted —
fail closed, but not what the spec says (SEC-018). Which name is reserved, and
the canonical CIDR form, is D-f in `docs/audit/ROADMAP.md`. Rejected: picking
the name inside a documentation pass.

## D-061 · Witness keys are cosignature keys, and the trust file's two witness lists must agree (4.1a–4.1c; recorded 2026-09-30)
A witness key is a `c2sp.org/tlog-cosignature` v1 verifier key, algorithm
`0x04`; the log key is a signed-note key, `0x01`, and MUST NOT be a
cosignature key (SPEC §7, §9.1). The algorithm byte is part of the key id, so
one public key under both algorithms is two verifiers. `witnesses` and
`policy` in `norn.trust` MUST name exactly the same witnesses with the same
keys (SPEC §9.1; `trust-bad/17`, `18`). A checkpoint is accepted only when
every line from a witness the policy names verifies and the quorum is met
(SPEC §10) — the witness-policy check D-058 recorded as still owed. Since
6.5m-i the key rule reaches a `policy` entry too: every `witness` line's key
MUST parse as a cosignature key, else `decode` (SPEC §5.1;
`log/129-bad-policy-witness-key-not-a-cosigner`).

Why: 4.1a found Norn encoding witness keys as `0x01`, so a trust file naming a
real witness was refused and a cosigned checkpoint did not parse. 4.4 then had
an unmodified `transparency-dev/witness` cosign a Norn checkpoint
(`internal/interop`; the test skips unless `make witness` has built the
witness, and CI does not build it). The two lists are not redundant:
`witnesses` says where a witness is, `policy` says whether it counts, and a
file where they differ configures a quorum its operator did not mean.
Rejected: one key type for both roles · treating the two lists as independent.

## D-062 · `quorum_time` is the newest instant the policy is satisfied, not the k-th newest timestamp (4.2a, 4.2c; recorded 2026-09-30)
Supersedes D-017's definition and keeps its principle. `T` is the newest
instant such that the witnesses whose cosignature timestamp is at or after it
satisfy the policy (SPEC §5.3; `freshness.QuorumTime`). For a flat
`group home k …` that is the k-th newest timestamp; for nested groups it is
the only definition there is. Only a verifying line from a witness the policy
names contributes, and a witness counts once. Under `quorum none` there is no
`T`, and freshness is `unknown`, not fresh (SPEC §5.3, §8.1). The wall clock
still decides nothing: `CLOCK_SKEW` compares `wall − quorum_time` with the
monotonic age the node has measured since adoption, on a direct-from-log
fetch only, and raises an alarm and nothing else (`GOSSIP.md` §5). That is
the rule. Today `agent.Once` runs `checkClock` on whatever head it adopted, a
peer's included, and the alarm is a log line (SEC-033, open).

Why: in 4.2a, with `group inner 2 pi vps`, `group top 1 inner friend` and
signatures at pi=500, vps=400, friend=100, "the 1st newest" says 500 and the
policy is first satisfied at 400 — a node reading it naively believes a head
is a hundred seconds fresher than any quorum vouched for. In 4.2c,
`|wall − quorum_time|` reported a clock fault on a correct machine whenever
the log went quiet. Rejected: "k-th newest" as the rule · a `quorum none`
clock that is always fresh · the skew test `GOSSIP.md` first gave. Open: which
policy computes `T` for the first head after a `policy` entry is D-l.

## D-063 · `staleness` is the network's, `S_hard` is the node's, and the freshness table is read top to bottom (4.2b, 4.2d, 6.5l-ii; recorded 2026-09-30)
A view's age is monotonic time since the node learned its quorum time (A11).
`S` is `params.staleness` from the replayed log, so a network agrees on when a
view is too old. `S_hard` is node-local and opt-in: zero means off, and
`nornd -hard-stale` refuses a value below §4.5's default of 600 s
(`MinHardStale` in `cmd/nornd/config.go`). The state is the first row of
SPEC §8.1's table, read top to bottom, whose condition holds — `unknown`,
`fresh` (`elapsed ≤ S`), `hard_stale` (`S_hard` set and `elapsed > S_hard`),
`degraded` — so a node never drops its peers while the network calls its view
fresh. `hard_stale` is enforced as an empty desired set, through the same
reconciler: owner mode replaces the table with nothing, watchdog evicts every
peer, observe writes nothing (4.2d).

Why: crossing `S_hard` drops every peer, so it is a local choice for the same
reason the witness policy is not a `params` key (D-034). 6.5l-ii found
`fresh` and `hard_stale` both true when `S_hard < elapsed ≤ S`, a region the
fixture's own `29-params` puts a node with `S_hard = 700` in; both
implementations already tested `fresh` first, and §8.1 now says so. Rejected:
`S_hard` as a `params` key · a default `S_hard` · `hard_stale` winning the
overlap.

## D-064 · §10 compares with the stored head from the node's own tree, where both branches reach, before the size rule (4.5c, 4.6b, 6.5i-i; recorded 2026-09-30)
A node holding a checkpoint recomputes the served branch's root at
`min(cp.size, stored.size)` from the entries it fetched, and compares it with
its own branch's root at that size — never with a consistency proof somebody
supplied — and does so before it refuses a smaller head. A mismatch is a fork
(§11); a smaller head that agrees is refused without an accusation (SPEC §10;
`logclient.Verify`; `detect/`). It rests on full replication (D-004): a node
holds every entry and tile it verified (4.5a). It holds them within one
process only: the stored head is not durable, so a restarted node has nothing
to compare with (SEC-004, `docs/audit/ROADMAP.md` task 2).

Why: 4.5c found nothing compared a fetched checkpoint with the one held, so
serving a node its own log as it stood earlier — correctly signed, cosigned
and replayable — made a device revoked since active again; once peers are a
source, anyone in the mesh can do that. 4.6b found a fork onto a shorter
branch filed as a rollback, with no evidence, and 6.5i-i (cold gate run 8, D1)
found §10's prose could not reach FORK there while `detect/` demanded it.
Rejected: a supplied proof from the party being checked · the size rule first.

## D-065 · Expiry is judged at the checkpoint's time `T`, and not at all without one (4.8, 6.5m-v; recorded 2026-09-30)
A device is expired exactly when `expires != 0 && expires <= T`, with `T` the
quorum time of the checkpoint the state was replayed from — never the node's
wall clock. With no `T` (no quorum time yet, or `quorum none`) expiry is not
judged: the devices replay gives stay admitted, and the view reports
`unknown`, never `fresh` (SPEC §5.3, §8.1 condition 4; `proven.IsProven`,
`proven.EvaluationTime`).

Why: 4.8 found `proven.FromResult` and `Agent.desired` judging expiry on the
wall clock, so a fast clock evicted a device early and a slow one kept an
expired one, silently — the failure A11 exists to prevent. Falling back to the
wall clock where there is no `T` would be the one place A11 leaked. 6.5m-v
(cold gate run 12, D11) wrote the no-clock case into §8.1. Rejected: the wall
clock as a fallback · dropping every peer the moment the roots publish
`quorum none`. Open: whether `nornd` may enforce under `quorum none` (D-j) and
which policy computes `T` (D-l).

## D-066 · Proof bundles are Norn's own format; receipts stay signed notes (2026-09-20, 6.5e-iii; recorded 2026-09-30)
Supersedes D-011 for bundles. A bundle is SPEC §8.1's closed six-key map in
deterministic CBOR (`v`, `device`, `index`, `entry`, `proof`, `checkpoint`),
unsigned — its authority is the checkpoint inside it — bounded by
`MAX_BUNDLE_BYTES`, and checked by §10 plus an RFC 6962 inclusion proof. It is
not `c2sp.org/tlog-proof@v1`, and v1 claims no byte compatibility with it;
the reference list at the head of `SPEC.md` names that document for
comparison only. torchwood is not a dependency: `internal/proof` checks
inclusion with `golang.org/x/mod/sumdb/tlog`.
Receipts are still signed notes, as D-011 decided (SPEC §7); D-074 says how
one is read.

Why: 2.7 gave §8 its first concrete bytes and said compatibility had not been
checked. 6.5e-iii found §8.1 still saying "Reconcile before freezing v1" in a
spec marked frozen, and decided rather than deferred: naming a specification
the bytes were never checked against is the unverified claim this project
refuses. A later version may adopt `tlog-proof` outright. Rejected: claiming
compatibility untested · an open reconciliation item in a frozen spec.

## D-067 · D-020 stands, applied: keys accumulate, a policy replaces, and `overlap` binds the log (2026-09-20, 6.5g-ii-a, 6.5g-ii-b)
Asked of the maintainer at 6.5g-ii — does v1 apply in-log rotation or only
record it — and answered on 2026-09-20: apply it. A checkpoint MUST be signed
by `norn.trust.log_key` or by a `pk` in `log_keys` of a state the node has
already accepted, and the node keeps the trust file's key alongside what it
learned. A `policy` entry replaces `norn.trust.policy` for every checkpoint
accepted after replaying it. `overlap` is an obligation on the log to keep
signing with the superseded key, not a rule for a verifier. The roots may
lower the policy, to `quorum none` included (SPEC §9.4). `served-rotated/`
and `served-superseded/` each have two correct answers, decided by what the
reader has replayed; `TestTheAgentFollowsALogKeyRotation` is where the node
follows one.

Why: rotation is not circular — reaching a state that names a key needs a
checkpoint accepted under a key held before, and a `log_key` entry needs the
root quorum, so a stolen log key cannot name its own successor. A raised
quorum must bind the nodes already watching, or it protects only those that
were not. Rejected: (b), recording rotation without acting on it, which
reversed D-020 and left §4.5's "supersedes" false. Open: learned log keys
accumulate and §9.4 gives none a retirement — that, and ENROLLMENT R7, is D-d;
which policy computes `T` on the first head after a `policy` entry is D-l.

## D-068 · Fork evidence is checked under the reader's own policy, and its roles swap on the longer branch (2026-09-21, 6.5h-vi-c; 2026-09-30, 6.5m-iv)
Evidence is SPEC §11.1's closed seven-key map, checkable offline by somebody
holding the trust file. A reader verifies both checkpoints under **its own**
policy — the trust file's, or one it has replayed — and never under the
`policy` the file carries, which is informational and MUST parse (6.5h-vi-c;
`forkevidence.Check` takes `readerPolicy`). `held` is the branch whose entries
the accuser holds; when the served branch is the longer one the roles swap:
the served head is `held`, the stored head is `conflicting`, and `size` is the
stored size (6.5m-iv; SPEC §11 rule 1, §11.1). `agent.writeEvidence` builds it
that way (`internal/agent/fork.go`), and
`TestAForkOnTheLongerBranchStillLeavesEvidence` and
`detect/fork-on-a-longer-branch` hold it. That fixed SEC-005 (a).

Why: an accuser who chooses the quorum rule can write `quorum none` and have
two uncosigned heads accepted as proof, and under §11 rule 4 that freezes a
network until an operator acts. Written to the letter, a node meeting a fork
on the longer branch — the natural shape of a growing log — wrote no evidence,
froze in memory only, and a restart unfroze it. Rejected: verifying under the
carried policy · writing nothing when the accuser's branch is the shorter one.
Open: which of the two policies a replayed node uses (D-e); `Check` with the
learned log keys and the current policy (SEC-005 (b), (c)); a freeze that
survives a reboot (SEC-006).

## D-069 · The restated policy grammar is closed, tolerates comments, and reserves `none` (2026-09-21, 6.5i-vi-a, 6.5k-iii; 2026-09-30, 6.5l-iii, 6.5m-i)
Amends D-018. The rules are SPEC §9.1's table. Fields are separated by ASCII
space and tab only; `0x0B`, `0x0C` and `0x0D` are an error anywhere in a line,
and a comment or blank line is tested for them before it is ignored; every
other character, other Unicode whitespace included, is content. A `#` starts a
comment only as a line's first character other than space or tab. Each
directive takes exactly its fields. `witness` and `group` names share one
namespace, are defined once and used only after they are defined, on the
`quorum` line too; `none` is reserved. A verifier key appears once in a
policy, on whatever line. A trailing run of separators is not a field. For a
`policy` entry, §5.1 adds that every `witness` key MUST parse as a
cosignature key (D-061).

Why: a `policy` entry's text is replayed, so a line one parser accepts and
another refuses is a `decode` on one node and a new quorum on the other. The
two parsers here disagreed on 23 whitespace characters and on the key rule
across directives (6.5l-iii) and on where the `quorum` line is resolved
(6.5m-i), and both let a witness be named `none` and then read `quorum none`
as no quorum. What amends D-018: comments went the tolerant way at 6.5i-vi-a,
on consequence rather than on knowledge of upstream, and §9.1 states the cost —
if `c2sp.org/tlog-policy` has no comments, a Norn policy carrying one is text
other tooling refuses. Since 6.5l-v-b the fixture's live policy begins with a
comment (D-075). Rejected: leaving these readings to an upstream document a
reader holding only `SPEC.md` does not have.

## D-070 · Shortest form means every argument, and map keys are strictly increasing (2026-09-21, 6.5k-ii)
Refines D-027. RFC 8949 §4.2.1's preferred serialization applies to every head
argument — an integer's value and the length header of a byte string, text
string, array or map — and a map's keys are strictly increasing in §4.1's
order, one comparison that also forbids a duplicate key (SPEC §4.0;
`log/75-bad-cbor-nonshortest-length`, `log/74-bad-duplicate-map-key`).

Why: `entry_hash` is over the bytes as received, so a second legal encoding of
one governance entry is a second leaf that also replays — a way around
`dup-entry` by the route §4.1's consume-the-whole-input rule closes. A reader
holding the rule for integers only, or "sorted" as non-decreasing plus
last-key-wins, passed the suite before this. Rejected: shortest form for
integers alone · two separate rules for order and duplicates. Not closed by
this: an old entry with one junk signature appended is a different byte
string whose original signatures still count (SEC-001), and entry identity is
D-a.

## D-071 · A signature line counts by name and key id, a key id is recomputed in lowercase, and a line has one spelling (2026-09-21, 6.5h-vi-c, 6.5k-iv-c; 2026-09-30, 6.5l-iv-a, 6.5l-iv-b, 6.5m-ii)
A log or cosignature line counts for a listed key only when both its key name
and its key id match that key (SPEC §10). A line under a listed name with
another id, or under an unlisted name with a listed id, is a stranger's line:
ignored, neither counted nor refused (`served-name-collision/`,
`served-witness-id-collision/`, `served-log-id-collision/` MUST be accepted).
Refusal is per line: a witness with one verifying line and one that does not
verify is refused, not counted. The policy names a witness when it carries a
`witness` directive for it, whether or not a `group` or the `quorum` uses it
(`served-unused-witness/`). A reader MUST recompute a verifier key's id from
its name, algorithm byte and key, and compare it as lowercase text (SPEC §7;
`trust-bad/37`, `39`, `40`). A signature line is exactly its payload's
encoding: padded standard base64 with zero padding bits
(`checkpoints-bad/24`).

Why: matching on the name alone gives anyone a veto over a head; matching on
the id alone lets four bytes the line's writer chose speak for a witness.
`golang.org/x/mod/sumdb/note` accepts an upper-case id and non-zero padding
bits; Norn does not, so one key and one line each have one spelling and one
cosignature cannot count twice. Rejected: the canonical implementation's
leniency on either point.

## D-072 · Every comparison with an origin is byte for byte (2026-09-30, 6.5l-iv-c)
A string that extends an origin, one it extends, and one that differs from it
only in case are all other origins (SPEC §2). That holds on the checkpoint
(§10; `checkpoints-bad/21`–`23`), on the log key's note name and on the
derivation from `net`, which is compared as text by encoding `net`, never by
decoding `origin` (§9.1; `trust-bad/41`–`45`), and on the receipt (§7;
`receipts-bad/origin-*`). Why: a prefix match, a case-folded match and a
decode-and-compare each let a different origin through, and standard base32
decoders fold case and ignore the two padding bits a 26-character string
carries. Rejected: any comparison but `==`. `trust.NetFromOrigin` stays lax,
because it parses what an operator types into `norn enroll` and is not on the
verification path. §12.1 admits that §8.1's and §11.1's own origin checks are
pinned only by an unrelated origin.

## D-073 · A key an entry adds counts for nothing on the entry that adds it (2026-09-30, 6.5l-iv-d)
Signatures resolve against the state before the entry (SPEC §4.2). A
`root_add` cannot count the root it admits towards its own quorum, and a
`rotate` carrying a new `device_pk` needs the device's current key, the
incoming one counting in addition and never instead
(`log/126-bad-root_add-signed-by-the-added-key`,
`log/127-bad-rotate-signed-by-the-incoming-key-only`). Why: resolving against
the state after the entry admits a root quorum that bootstrapped itself, and
on `rotate` lets whoever holds a fresh key take a device over —
`rotate_needs_signer` defaults to `false` (§4.5). Rejected: the after-state
reading.

## D-074 · A receipt is read by rule (2026-09-30, 6.5l-v-a)
Whoever holds a receipt and relies on it MUST refuse it unless its text is
exactly four lines: `norn/receipt/v1`; `norn.trust.origin` byte for byte; the
padded, zero-padding-bit `b64` of exactly 32 bytes; and the deadline in
canonical decimal — no leading zero, no sign — that fits in 64 bits. The note
verifies by §10's rule for a log signature: every line whose name and key id
match a trusted log key verifies, and at least one is present (SPEC §7;
`receipts-bad/`, fourteen files). None of it needs the entry or a clock.

Why: §7 gave the receipt's shape and nothing a holder must refuse. Go
accepted a leading zero, a non-zero padding bit and a carriage return; Python
accepted a leading zero, a plus sign and a non-zero padding bit, and returned
on the first line that verified. A promise with three spellings cannot be compared or held against
the log (A2). Rejected: the canonical `x/mod` `Open`, which verifies one line
per name and opens `receipts-bad/two-log-signatures`.

## D-075 · A length in bytes counts UTF-8 as encoded, with no normalisation (2026-09-30, 6.5l-v-b)
Every byte cap on text — map keys, `name`, `reason`, `text`, label values,
`device_id`, §9.1's two names — counts the UTF-8 encoding as received, never
code points, UTF-16 units or grapheme clusters, and no Unicode normalisation
comes first (SPEC §4.0). Seven caps ship as pairs: a value at exactly the cap
in characters of every UTF-8 width, and the same value one byte over with the
same character count.

Why: every over-long vector was ASCII, so a reader counting characters passed
the suite, and a 300-byte Cyrillic `reason` is `decode` on one node and a
revocation on the other. The policy pair is padded with a §9.1 comment, so the
live `state.policy` now begins with one; BUILD-LOG 6.5l-v-b records that as a
choice the maintainer can reverse. Rejected: counting characters ·
normalising first · padding the policy inside a witness URL. Admitted in
§12.1: no `log/` entry carries a label at or past 256 bytes, so a separate
entry-path label check is pinned by nothing.

## D-076 · A refusal's reason is not normative outside §5.2, and `about` is a hint (2026-09-30, 6.5l-vi)
In a `cases.json`, `says` is a placement contract — a phrase that appears
verbatim in the named section — and `about` is what a refusal is about in the
reference implementation's words, a hint and not text a conforming reader has
to produce. Only §5.2's reason codes are normative (D-012). The suite binds
accept or refuse, and the rule each file is named for; the order a reader
checks in decides only which refusal it reports (SPEC §10, §11.1, §12;
`TestSaysIsAPlacementKeyAndAboutIsAHint`).

Why: run 11 rebuilt an error vocabulary from `cases.json` to pass, and found
three catches resting on a string match and on nothing in the document. This
is the current choice, not the closing of the question: closed reason-code
lists for §7, §8.1, §9.1, §11.1 and §16 would make check order observable and
let two nodes triage a freeze in the same words, and that is D-k, the
maintainer's.

## D-077 · D-055's boot-time signer is not built; only `genesis` and `enroll` can be made (recorded 2026-09-30)
A correction to D-055's premise, not a new decision. D-055 chose an
unencrypted OpenSSH key file because `nornd` signs `rotate` and self-`revoke`
at boot. No such code exists: `nornd` signs nothing; `norn init` builds
`genesis`; `norn enroll` and `norn sign` build and sign `enroll` only
(`cmd/norn/sign.go` refuses any other type); there is no `norn revoke`,
`rotate`, `migrate` or governance builder (SEC-008, `docs/audit/ROADMAP.md`
task 5). The format D-055 chose stands: `norn init` and `norn enroll` write
it, and they and `norn sign` read it. What is missing is its consumer at boot, and a
builder for every entry type but those two.
