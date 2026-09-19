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
