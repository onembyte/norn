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

