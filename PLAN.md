# Norn — Plan

> The Norns carve into the Tree the record of what has happened. Nothing carved is uncarved.
> **Thesis: no peer without proof.**

A key-transparency layer for WireGuard. Every device enrollment, key rotation and
revocation is an entry in an append-only, witnessed, fully-replicated log. A node
completes a handshake with a peer **only** if it holds a proof that the peer's key is
in the log and not revoked. That is owner mode's guarantee: watchdog mode evicts an
unproven key within a window, and observe mode — the default, D-005 — only reports.
The coordination server (Headscale, NetBird, Tailscale,
innernet, or a human with `wg-quick`) keeps doing what it does — Norn just makes it
**unable to lie silently**.

Started **2026-09-18**. Author: Franco Michetti (`onembyte`). Language: Go.

The first audit (2026-09-30) is in `docs/audit/`: `SECURITY_AUDIT.md` (SEC-001…SEC-036),
`PROJECT_STATUS.md`, and `ROADMAP.md`, which orders the next work and lists the
decisions that are the maintainer's (D-a…D-l). Every ticked gate line below was
re-checked against the repository after it, and five ticks that were not true of it were removed,
each with its reason; the open lines' notes on software halves were corrected where `LAB.md` §3
and the audit contradicted them.

## Files

| File | Part | What |
|---|---|---|
| `PRIOR-ART.md` | 1 | why this doesn't exist yet; the gap, precisely |
| `THREAT-MODEL.md` | 2 | 12 adversaries, 6 guarantees, windows, parameters |
| `LEDGER-OPTIONS.md` | 3 | six ledger architectures scored; D-009 |
| `SPEC.md` | 4 (+5–7) | entries, replay, log, receipts, proofs, trust file |
| `ENFORCEMENT.md` | 5 | modes, reconciler, integration matrix, measurements |
| `GOSSIP.md` | 6 | witnesses, freshness, gossip, T1–T8 |
| `ENROLLMENT.md` | 7 | key tiers, ceremony, QR flow, runbooks R1–R10 |
| `LAB.md` | 8 | topology, demos D1–D4, monitor |
| `PUBLICATION.md` | 9 | audiences, review, launch, talks |
| `DECISIONS.md` | all | D-001…D-077. D-060–D-077 were recorded on 2026-09-30 from `BUILD-LOG.md`; the decisions still open (D-a…D-l) are in `docs/audit/ROADMAP.md` |
| `README.md` | 9 | public-facing summary, status line and quick start |
| `BUILD-LOG.md` | — | every checkpoint since Phase 0: what was done, what was found, what was decided |
| `SECURITY.md` | — | how to report a vulnerability; the known open findings |
| `CONTRIBUTING.md` | — | how to build and test, and the rules every change follows |
| `SPEC-DEFECTS*.md`, `SPEC-DECISIONS-11.md` | — | cold-model gate reports: runs 1, 2 and 4–13 (run 3 passed and left none); run 11's reading log |
| `COWORKER.md` | — | persistent context for agents working on Norn and related WireGuard work; revised 2026-09-30, first version in `docs/COWORKER-v1.md` |
| `docs/audit/` | — | the first audit, 2026-09-30: security findings, status, roadmap |

---

## Why this exists

WireGuard authenticates peers by raw public key and, by design, has no key
distribution. Every mesh product fills that hole with a coordination server that
every node trusts completely. If that server is compromised — or its operator is
compelled — it can hand your laptop an attacker's key labelled `truenas-155` and
the tunnel will be cryptographically perfect and completely wrong.

| Camp | Examples | What it gives you | What it never gives you |
|---|---|---|---|
| Coordination servers | Headscale, NetBird, ZeroTier, innernet | key distribution, NAT traversal | any way to detect that they lied |
| Offline PKI | Nebula | CA-signed certs | a record of what the CA signed; revocation with proof of delivery |
| Tailnet Lock | Tailscale only | control plane can't add nodes | a *log* of node keys, witnesses, gossip, non-TOFU bootstrap, portability |

Certificate Transparency fixed the identical problem for the web PKI in 2013:
don't stop CAs from issuing, make every issuance public and let anyone check.
Norn is CT for the peer table.

Three things make it not-a-clone (see `PRIOR-ART.md §The gap`):

1. **It is a log, not an authority chain.** Tailnet Lock records changes to *who may
   sign*; Norn records *every key that was ever signed*. A stolen signing key still
   leaves a permanent, monitorable trail.
2. **The log travels over the tunnel.** Nodes serve checkpoints and tiles to each
   other, so a control plane that withholds updates (Tailscale's own acknowledged
   freeze attack) is detected and routed around.
3. **It is implementation-independent.** Norn reconciles the kernel's WireGuard peer
   table against the proven set. It needs no patch to Headscale, NetBird or `wg`.

## Non-goals

- Not a VPN, not NAT traversal, not a coordination server. Norn never carries traffic.
- Not a blockchain and not a token. Non-equivocation comes from witnesses; the
  question "is a chain ever warranted?" is answered formally in `LEDGER-OPTIONS.md`.
- Not KEYTRANS-compatible and not internet-scale. Target: closed networks,
  10¹ – 10⁶ entries, full replication on every node.
- Not availability protection against the log operator or control plane. Norn
  **detects** withholding and bounds its duration; it does not prevent it.
- Not protection against a node whose WireGuard private key is stolen. That is
  what `Revoke` is for; the window is bounded by checkpoint interval + staleness policy.
- Not anonymity. To whoever can read the log, entries reveal every device's id,
  WireGuard key, identity key, labels (including the reserved `ip` and `endpoint`
  hints, D-026), requested expiry, the time of each enrolment, rotation and
  revocation, a revocation's reason, `note` text, and the key id and role of every
  signature (SPEC §4.1, §4.3, §16.1).

---

## Ground rules (every phase)

1. **Threat model first.** No mechanism enters `SPEC.md` until `THREAT-MODEL.md`
   names the adversary it defeats and the one it does not.
2. **Spec first.** No code for a message type until it is in `SPEC.md` with test
   vectors in `testdata/vectors/`.
3. **Reuse the transparency ecosystem, don't fork it.** C2SP formats verbatim
   (`tlog-tiles`, `tlog-checkpoint`, `tlog-cosignature`, `tlog-witness`,
   `tlog-policy`). If a Sigsum or transparency-dev witness can't cosign a Norn
   checkpoint unchanged, the design is wrong.
4. **Observe before enforce.** Every deployment — including the lab — runs in
   observe mode (log only, never touch the interface) before enforce mode is allowed.
5. **The lab is the truth.** `make lab-test` on a clean 3-node lab = green (planned: `lab/` and
   that target do not exist yet). A
   security property without a lab test does not exist.
6. **Time-box.** Phase over 2× estimate: stop, cut scope, write why in `DECISIONS.md`.
7. **Every decision gets a `DECISIONS.md` entry:** what, why, what was rejected.
8. **A gate is PASS only when every line of its PASS list is true.** No partial credit.

---

## Fixed decisions (do not re-litigate until Phase 6 is done)

| Decision | Choice | Why |
|---|---|---|
| Language | **Go** | The whole transparency stack is Go. Chosen 2026-09-18 for `filippo.io/torchwood`, `transparency-dev/tessera`, `transparency-dev/witness` and `wgctrl`; as built, neither torchwood nor Tessera is a dependency. The log writes its own tiles over `x/mod/sumdb/tlog` (D-049); the signed-note, cosignature, tlog-policy and tlog-witness client code is Norn's own; notes, checkpoints and cosignatures are cross-checked in tests against `x/mod/sumdb/note` and `transparency-dev/formats`, and the witness protocol against the unmodified witness, which is built outside the module (`make witness`); `wgctrl` is fenced into `nornd` and `internal/wgdev` (D-059). D-066 records that proof bundles are Norn's own format rather than torchwood's; no entry records the choice to write the note, cosignature and policy code instead of taking torchwood. |
| Signatures | **Ed25519** | tlog note/cosignature format is Ed25519; hardware signers (TKey, YubiKey) support it. |
| Hash / tree | **SHA-256, RFC 6962 Merkle** | tlog-tiles compatibility; existing witnesses and monitors verify unchanged. |
| Entry encoding | **Deterministic CBOR (RFC 8949 §4.2)** | TKA precedent; cheap canonicalization; test vectors are byte-exact. |
| Log format | **C2SP tlog-tiles + tlog-checkpoint** | Static files. Serve from nginx, S3, or a directory on the NAS. |
| State model | **Full replication + replay on every node** | No prefix trees, no lookups — nothing to equivocate on except the checkpoint, and witnesses cover that. |
| Log operator | **Untrusted for validity.** Inclusion ≠ validity. | Verifiers re-check every entry signature against signer state at replay. The log is a bulletin board, not a judge. |
| Enforcement target | **Kernel WireGuard (Linux) via wgctrl, first** | The only place enforcement is possible without patching someone's daemon. Userspace/Tailscale get observe mode (Tailscale observe is not implemented: Phase 3). |
| Rollout | **Observe mode is mandatory before enforce** | tailscale-rs lesson: verify-and-log before fail-closed. |
| Trust bootstrap | **Pre-provisioned `norn.trust` file, out of band. No TOFU.** | Closes Tailnet Lock's stated bootstrap weakness. |
| Consensus | **Witnessed transparency log + optional OpenTimestamps anchoring of checkpoints (D-009)** | Decided in `LEDGER-OPTIONS.md`: witnesses give non-equivocation; anchoring defeats backdating under full collusion; BFT chains and on-chain registries rejected with reasons. |

## Repo layout

As built on 2026-09-30. `lab/` and `demo/` are planned and do not exist yet.

```
norn/
  PLAN.md  PRIOR-ART.md  THREAT-MODEL.md  LEDGER-OPTIONS.md  SPEC.md  ENFORCEMENT.md  GOSSIP.md
  ENROLLMENT.md  LAB.md  PUBLICATION.md  DECISIONS.md  BUILD-LOG.md  COWORKER.md  SPEC-DEFECTS*.md
  cmd/norn/          # CLI: init | enroll | sign | submit | verify | status | audit | stamp | verify-evidence | monitor
                     #   `sign` signs `enroll` entries only: no revoke, rotate or governance builder yet (SEC-008)
  cmd/nornd/         # node agent: observe (default) | watchdog | owner; serves its checkpoint, tiles and fork evidence to peers
  cmd/norn-log/      # log server over internal/tlogstore (not Tessera, D-049) + witness submitter
  cmd/norn-witness/  # empty stub; internal/interop runs the real witness that `make witness` builds
  cmd/norn-genlog/   # writes the Go-generated vector directories (Makefile GO_VECTOR_DIRS)
  internal/cbor/ fields/ cjson/ entry/ replay/ state/                # §4–§5: encoding, entries, replay, state
  internal/tlog/ tlogstore/ logserver/ logclient/ mirror/            # tiles and proofs, write side, verifier, a node's mirror
  internal/note/ cosign/ policy/ witness/ receipt/ proof/            # signed notes, cosignatures, tlog-policy, tlog-witness, receipts, bundles
  internal/trust/ genesis/ enrollreq/ bech32m/ qrterm/               # trust file, ceremony, enrollment requests
  internal/keyfile/ sshagent/ sshwire/ wgkey/                        # signer keys (file, ssh-agent) and WireGuard keys
  internal/agent/ reconcile/ peertable/ wgdev/ endpoint/ fight/ proven/ freshness/   # one nornd cycle, from verify to the interface
  internal/gossip/ forkevidence/                                     # peer exchange over the tunnel, fork evidence
  internal/monitor/ plainlog/ ots/                                   # `norn monitor`, entries in words, OpenTimestamps
  internal/docclaims/ specdoc/                                       # the build's checks on the prose and on SPEC.md's structure
  internal/interop/ depgraph/                                        # tests only: the unmodified witness; import fences
  internal/wg/       # empty package, a doc comment only; the reconciler is internal/reconcile + internal/agent
  testdata/vectors/  # JSON/CBOR test vectors — the cross-implementation contract
  contrib/norn-ref/  # Python reference implementation from SPEC.md alone; generates every vector outside GO_VECTOR_DIRS and anchors/
  contrib/ots-vector/  # python-opentimestamps generator for testdata/vectors/anchors/
  docs/              # COWORKER-v1.md, HANDOFF.md; audit/, upstream/
  lab/               # planned: 3-node lab: kernel wg + headscale + log + witness (containers/VMs on TrueNAS)
  demo/              # planned: attack demos: malicious-headscale, stolen-signer, withheld-checkpoint
```

---

## Phases

Estimates assume one person, part-time. Total ≈ 14–16 weeks.

### Phase 0 — Threat model, ledger decision, spec skeleton (1 week)
Deliverables: `THREAT-MODEL.md`, `LEDGER-OPTIONS.md` with a decision,
`SPEC.md` v0 with entry formats + verifier rules + first test vectors,
repo initialised, CI running `go test` + `go vet` + `staticcheck`.
**PASS when:**
- [x] Threat model names ≥ 6 adversaries, and for each: what Norn guarantees, what it explicitly does not.
- [x] `LEDGER-OPTIONS.md` compares ≥ 4 architectures on the same criteria and records one decision in `DECISIONS.md`.
- [x] `SPEC.md` has byte-exact test vectors for every entry type and for one full replay.
- [x] Cold-model gate: a fresh model given only `SPEC.md` + vectors implements an entry verifier that passes all vectors. **Run 3 passed: `SPEC SUFFICIENT WITH GAPS`, 396/396.** Runs 1 and 2 returned SPEC INSUFFICIENT (`SPEC-DEFECTS.md`, `SPEC-DEFECTS-2.md`, both closed and their defects fixed). Passing the checks was never the bar — the bar is that a second implementer could not reasonably have got it wrong.

### Phase 1 — Core library (2 weeks)
`internal/entry`, `internal/state`: encoding, signing, replay, validity rules.
**PASS when:**
- [x] Replay of the fixture log yields the expected state, byte-exact. **Go reproduces `state.json` byte for byte** from the 130-entry fixture (88 of its entries are refused, each for its recorded reason), and all 19 `genesis/` cases abort with their recorded state.
- [x] Rejected: wrong signer, below threshold, signer revoked in an earlier entry, duplicate device id, rotate signed by neither old key nor signers, entry referencing unknown device. **All six vectored** — checking this found two with no vector at all, including the removed-signer case, which is the whole point of `signer_remove`. A test now fails the build if any of the six stops being exercised.
- [ ] `go test -fuzz` on decoder + replay: 1 h, zero panics. **Unticked 2026-09-30 (SEC-015): at HEAD no fuzz input reaches a replay handler.** `FuzzReplayAfterAValidGenesis` opens `testdata/vectors/log/00-genesis.cbor`, which is now `0-genesis.cbor`, so it skips on every run; `FuzzReplayNeverPanics` feeds one entry under an all-zero anchor that no entry 0 can pass. The 1.6 run was real — 83,791,152 executions, zero failures: canonical round-trip 54.6M, replay on arbitrary bytes 26.8M, replay after a valid genesis 2.4M — and the decoder target still asserts canonical round-trip, not merely absence of panics.
- [x] Cross-implementation check: all 16 entries in `testdata/vectors/entries/` **rebuilt in Go from their semantic values** and signed independently produce bytes identical to the shipped vectors. Stronger than re-exporting, and without duplicating the fixture — see the 1.7 note in `BUILD-LOG.md`.

### Phase 2 — The log + CLI (2 weeks)
`norn-log` on its own POSIX tlog-tiles writer (`internal/tlogstore`; the plan named Tessera, D-049 says why not); `norn init|enroll|sign|submit|verify|status`.
**PASS when:**
- [ ] Log directory served by plain nginx; `norn verify` fetches tiles + checkpoint and reproduces state. **Half true (audited 2.10):** the verifier fetches the checkpoint, the entry bundles **and every hash tile**, and reproduces `state.json` byte for byte — tested over HTTP against a stock static file server with no server-side logic, which is the property this line is really about. **nginx itself has never run**, so the line stays open until the lab does it.
- [x] Tamper test: flip one byte in a tile → inclusion proof fails, verifier refuses. **Closed by 2.10.** Until then the verifier never fetched a hash tile, so this was false and looked true: it rebuilt the tree from entry bundles, which is stronger, but left a log free to serve corrupt tiles to every monitor and witness while the one program guaranteed to be looking said nothing. Now a flipped byte and a missing tile are each refused, and a tampered leaf's inclusion proof stops verifying under upstream's checker (2.2).
- [ ] Log restarts without losing or reordering entries; checkpoint size monotonic. **Unticked 2026-09-30: true of a clean restart only — a crash inside `tlogstore.writeFile` after it removes a partial bundle's older width and before the new one is renamed in can leave that bundle's directory empty, so `recover` stops short and `Open` publishes a smaller checkpoint (SEC-011).** Reopening an untouched log leaves the checkpoint and the replayed state byte-identical; size increases strictly across appends; and after a clean restart the log **keeps counting** — the next entry lands at the index the old checkpoint ended on, and entry 0 is still entry 0.
- [ ] An unmodified `transparency-dev/witness` cosigns a Norn checkpoint (ground rule 3). **Unticked 2026-09-30: the one test of it skips unless `make witness` has been run, CI runs neither `make witness` nor `NORN_REQUIRE_WITNESS=1` (SEC-036), and `BUILD-LOG.md` records no run since 4.4, while `internal/note` has changed since (6.5m-ii, 6.5m-v).** What 4.4 established: `internal/interop` drives the real `transparency-dev/witness` at a pinned commit — its own binary, its own key from its own `generate_keys`, no Norn code in it and none of its code in Norn's `go.mod` — and the checkpoint `norn-log` serves carries that witness's cosignature. `norn verify` accepts it with the quorum enforced, and refuses the same checkpoint with that one line removed, so the cosignature is demonstrably *why* it passed. Build the witness with `make witness`; the test skips without it, and `NORN_REQUIRE_WITNESS=1` makes the skip a failure. The line closes again when CI builds the witness and sets that variable.
- [x] Go `note` / torchwood accept `testdata/vectors/receipt.note` and the trust file's verifier keys unchanged (cross-checks the 0.5 encodings, which are otherwise only self-consistent). Done in 2.1 with `golang.org/x/mod/sumdb/note`, in both directions: it opens what we sign, we verify what it signs, and its key-id derivation matches ours across 32 name/key combinations. torchwood was never used and is not a dependency.
- [ ] End-to-end enrollment with a phone camera: device QR → `norn sign` on the laptop with a hardware key (touch) → submit → device imports trust file by QR → active. Timed; target < 3 min. **Software-only half done:** `norn enroll | sign | submit | verify` runs end to end against a real `norn-log`, and a network can be bootstrapped from nothing and a device enrolled into it (2.9f-ii). What is untested is everything physical — a phone reading the QR, a hardware key's touch, and the clock.
- [ ] Runbooks R1–R3, R6, R7 executed in the lab and their downtime column verified. **Not executable yet:** no shipped tool builds the entries R1–R3 and R7 need — `norn sign` signs `enroll` entries only, and there is no builder for `signer_*`, `root_*`, `revoke` or `log_key` (SEC-008) — and `norn-log restore` (R6) does not exist.

### Phase 3 — Enforcement agent (2–3 weeks)
`nornd` observe + enforce on kernel WireGuard; owner mode and watchdog mode — normative in `ENFORCEMENT.md`.
**PASS when:**
- [ ] Lab, enforce/watchdog: rogue key added with `wg set` is evicted with p99 < 1 s over 1 000 runs at T_poll = 200 ms; packets that crossed the window are counted and reported. **Software half done (audited 3.8):** an injected key is gone after **exactly one cycle**, so the window is one cycle rather than some multiple of it. **A cycle is not `T_poll` yet:** `agent.Once` fetches and replays the whole log, and may ask peers, before it reconciles, so the window is `T_poll` plus that I/O — bounded, at 30 s per exchange with the log and, since the SEC-003 fix, 10 s per peer read, but not removed (SEC-013; SEC-003's structural half). The distribution, and the packets that crossed the window, are measurements — nothing here counts a packet.
- [ ] Lab, enforce/owner: the peer table equals the proven set at all times (continuous diff, 24 h soak, zero divergence). **Software half done against `peertable.Fake` only:** the first cycle installs the proven set and **fifty further cycles write nothing** — a daemon that rewrote the table every poll could never pass a continuous diff, so that is the property the soak would really be checking. The audit found it holds only against the fake, which stores any key: a real interface ignores a peer whose key is its own, and nothing in `internal/agent` takes the node's own key out of the desired set, so against real WireGuard owner mode would rewrite the table every cycle (SEC-012, open; D-g). The soak itself needs a day and an interface.
- [ ] A `Revoke` entry drops the device within one checkpoint interval. **Software half done, and it was untested until this audit:** every enforcement test started from a fixed proven set, so nothing showed the peer table *following the log when the log changed underneath it*. Now a real `revoke` is appended to a real log between two cycles, in owner and watchdog mode, and the device loses its place. The timing against a checkpoint interval is the lab's.
- [ ] Observe mode: 24 h soak, zero writes to the interface (verified by diffing `wg showconf` every second). **Software half done:** twenty-five cycles with a different intruder appearing before each one, zero writes, an alarm every time. One quiet cycle proving nothing was the weaker test this replaces.
- [ ] Zero false removals in the 24 h soak. **Software half done:** across fifty unchanged cycles no proven peer is ever removed, and `internal/reconcile` refuses to plan a removal for a key the log proves. The soak adds real time, a real interface and real churn.
- [ ] Fight test against a real NetBird management server: `CONTROL_PLANE_FIGHT` fires and `quarantine` isolates the host. **Software half done (3.6):** three evictions of one key inside the window declare a fight exactly once, evictions continue, and `quarantine` runs a configured command once and only when chosen. What needs NetBird is whether a real control plane behaves the way the detector assumes.
- [ ] Tailscale observe: an unproven peer key in the netmap raises `UNPROVEN_PEER` within 1 s of the LocalAPI event. **Not started.** There is no LocalAPI watcher: `tailscaled` exposes no UAPI socket, so this is a different source of truth feeding the same reconciler, not a backend behind `peertable.Device`. `ENFORCEMENT.md` part 6 places it in the integration work, and it stays unwritten rather than half-written.

### Phase 4 — Witnesses, gossip, freshness (3 weeks)
`tlog-witness` submission + `tlog-policy` quorum; self-hosted witnesses on the Pi
(.153) and a VPS; peer-served checkpoints over the tunnel; staleness policy — normative in `GOSSIP.md`, lab scenarios T1–T8.
**PASS when:**
- [ ] Split-view lab: two log instances presenting divergent checkpoints to two nodes → detected via gossip within 2 checkpoint intervals, alarm raised, no peer changes applied from the losing view. **Software half not closed.** The 4.8 audit found a peer serving a second history filed as one broken neighbour; since then a forked peer, *once asked*, raises `FORK`, writes evidence and freezes exactly as a forked log does. But `agent.Once` asks peers for a checkpoint only when its own verification fails or its view is stale, so two nodes each kept fresh on a different branch never compare heads and the split is not detected via gossip at all (SEC-007; with one colluding witness under the shipped 2-of-3 policy, SEC-002). Gossiping every T_g as GOSSIP §2/§6 says, or superseding D-016, is decision D-c. The timing (2·T_g) and two real log instances are the lab's.
- [ ] Witness quorum lost → node refuses the new checkpoint, keeps last good, alarms. **Software half done (4.1c, tested at the node in 4.8):** a checkpoint short of the quorum is refused, the stored head does not move, the peer table is untouched and it alarms. Taking two of three witnesses *down* is the lab's.
- [ ] Log server killed → nodes still converge on the newest witnessed checkpoint via peers. **Software half done (4.5d):** a node with an unreachable log adopts a peer's checkpoint and says so. Killing a real log server and watching real nodes converge is the lab's.
- [ ] Replayed old checkpoint → rejected (size monotonic + consistency proof). **Unticked 2026-09-30: true within one process only — the stored head, the witness clock and the keys and policy learned by replay live in memory, so a restarted node accepts a rolled-back, quorum-cosigned checkpoint as `fresh` (SEC-004, open).** Within a process (4.5c) both mechanisms exist and are tested at three levels: in the verifier (an older head and a rewritten history are each refused, by name), at the node (its own log truncated is refused, reported, and the peer table untouched), and through gossip (a peer cannot roll a node back). T4's `REPLAY` counter is a monitor metric and belongs to Phase 5.
- [ ] T1b evidence propagation: a node that never saw the second branch freezes via peer evidence ≤ 3·T_g. **Software half closed by 4.9:** `GET /norn/evidence` serves a node's proof, and a node with a **healthy** log polls its peers for one on `T_g` — which is the whole point, since node3 in T1b has no other reason to ask anybody anything. It freezes only on evidence it has checked itself against its own trust file, so a peer serving junk cannot take a network down; it keeps a copy so it can pass the proof on in turn. It holds while the log key and policy are the trust file's: evidence is checked with the trust file's log key alone and adopted under its policy (SEC-005 (b) and (c), open), and the copy lives in the run directory, `/run/norn` by default, which a reboot clears (SEC-006). The `≤ 3·T_g` timing across three real nodes is the lab's.
- [ ] T5 clock skew: a node with wall clock +2 h raises CLOCK_SKEW and does **not** go degraded. **Software half done (4.2c) — and the audit found the other half was false.** T5 also requires the *proven set* to be unchanged, and it was not: expiry was judged against the node's wall clock, so a fast machine evicted a device early and a slow one kept an expired one, silently. SPEC §5.3 says plainly that expiry is judged against **the checkpoint time**; it now is. A real machine with a two-hour offset is still the lab's.
- [ ] T7 revoke propagation latency measured and ≤ T_c + T_g + T_poll. A measurement across three real nodes; nothing here counts milliseconds. The *behaviour* — a `revoke` entry evicting a device within one cycle — was closed in 3.8.
- [ ] Checkpoint N has a verifiable OpenTimestamps proof in `anchors/`; `norn verify --anchored` checks it (advisory witness, D-009). **Software done (4.7a–c):** `norn stamp` obtains a proof from a calendar and writes `anchors/<size>.ots`; `norn verify --anchored` walks it against the checkpoint body, reports the block it commits into without claiming to have checked a chain, and says "different document" when a checkpoint was edited after stamping. What is untested is what T8 actually asks for — a **real** calendar round trip and the upgrade from a calendar's promise to a Bitcoin block attestation, which takes hours on the public internet.

### Phase 5 — Attack demos + monitor (2 weeks)
Reproducible demos — normative in `LAB.md` §2: D1a/b/c (one attack × plain WG / NetBird / Headscale), D2 stolen signer, D3 freeze + fork, D4 lifecycle. `norn monitor` per `LAB.md` §3.
**PASS when:**
- [ ] `make demos` from a clean `make lab-up`: all six `run.sh` assert green and render their tapes. **Nothing exists and nothing here can:** `lab/` and `demo/` do not exist in the repository, and their contents are containers, a patched Headscale and NetBird, and rendered tapes. This is the lab's whole job.
- [ ] D1a: rogue key never appears in `wg show` on node1. D1b: evicted with measured window, `CONTROL_PLANE_FIGHT` fires, `quarantine` isolates. D1c: `UNPROVEN_PEER` + phone push ≤ 1 s. **Software halves:** D1a and D1b are tested against `peertable.Fake` (3.x): owner mode never installs an unproven key, an injected key is gone after exactly one cycle, `CONTROL_PLANE_FIGHT` fires on a key that keeps coming back, `quarantine` takes the interface out of service. D1c has none: the `tailscaled` observer is not written (Phase 3), and `nornd` only logs `UNPROVEN_PEER`; `monitor.Rules.Node` maps such an event to a critical alert, but nothing carries a node's events to `norn monitor` (`LAB.md` §3). The *measured window*, the three control planes and a phone receiving a push are the lab's.
- [ ] D2: rogue enrollment visible, phone alert, `norn audit --by`, R2 executed, eviction time on screen. `norn audit --by <kid> --since <t>` exists since 5.8 — the 5.7 audit had found it missing although `ENROLLMENT.md` R2 and `LAB.md` D2 both name it. R2 cannot be executed yet: its other steps are `signer_remove` and `revoke`, and no shipped tool builds either (SEC-008). The rest of the line is software that exists: a valid-looking enrolment is reported at info like any other entry, which is D2's point — *transparency beats authority*.
- [ ] D3: nodes stay fresh through a log freeze via gossip; fork evidence on both nodes; `norn verify-evidence` passes offline. **Unticked 2026-09-30: no demo exists, and the software half fails after a log-key or policy rotation — evidence is built and checked under the trust file's log key and policy alone (SEC-005 (b) and (c), open) — and across a reboot, which clears the freeze from `/run/norn` (SEC-006).** Done in software (4.5d, 4.6, 4.9, 6.5m-iv): a node with an unreachable log adopts a peer's checkpoint; a fork produces evidence on the node that caught it — on the longer branch too since 6.5m-iv (SEC-005 (a)) — and on every node it tells; and `norn verify-evidence` checks that evidence offline against a trust file alone, and refuses a file that proves no fork or belongs to another network.
- [ ] Monitor: one notification received per rule in `LAB.md` §3 during the run; status page reachable over the tunnel. **Software in part (5.1–5.6):** every rule in §3's table is implemented and tested in `internal/monitor`, and one round over the shipped fixture fires four of them, but `norn monitor` does not call all of them: the receipt inbox, `WitnessQuorum`, `AnchorLag` and a node's own events have no caller (`LAB.md` §3). The status page serves on a configured address and escapes what a device's own labels put on it, and is never handed a verified result, so it shows no devices. "Received" — on a phone, during a run, one per rule — needs the run.

### Phase 6 — Spec v1 + publication (2 weeks)
Freeze `SPEC.md`, publish vectors, README with threat model and comparison table,
blog post, WireGuard mailing list + r/WireGuard + HN, request review from a
transparency-dev / Sigsum person — sequence and review targets in `PUBLICATION.md`.
**Status (2026-09-30):** `SPEC.md` was frozen as v1 on 2026-09-20 and has been amended since by the cold-model checkpoints (6.5e onward); 6.5n will amend it again. `PUBLICATION.md` Gate A
(a verifier from the spec alone) waits on the cold-model gate line below: 6.5n and decision
D-l. Gate B (the Phase 3–5 numbers) also waits on the audit: `docs/audit/ROADMAP.md` asks
for its tasks 1 (the structural half), 2 and 5, a decision on D-a and the documentation pass
first. Task 1's minimal half has landed (SEC-003: every peer read and submission has a
deadline); tasks 2 (SEC-004, SEC-006) and 5 (SEC-008) have not.
**PASS when:**
- [ ] Cold-model gate repeated on frozen spec: independent verifier passes all vectors. Runs 5–13 each passed every check and none has returned `SPEC SUFFICIENT` outright. Run 12 (2026-09-30): `SPEC INSUFFICIENT`, 553/553, 33 of 128 variants survive, 14 defects (`SPEC-DEFECTS-12.md`); thirteen closed in 6.5m-i, -ii, -iv and -v, and D3 — which policy computes a checkpoint's `T` — is the maintainer's decision D-l, so 6.5m-iii stays open. Run 13 (2026-09-30): `SPEC SUFFICIENT WITH GAPS`, 886/886, 25 of 185 variants survive, 0 of 12,720 composites pass, 8 defects and none High (`SPEC-DEFECTS-13.md`); D1 is D-l again, the other seven are planned as 6.5n-i to -iii, and run 14 is 6.5n-iv. The line stays open.
- [ ] One person outside this homelab runs the lab and files an issue.
- [ ] Comparison table (Tailnet Lock / Nebula / NetBird / Norn) reviewed by someone who has run at least two of them.

### Phase 7 — Stretch (backlog, not scheduled)
FIDO2 `ed25519-sk` signature kind (YubiKey without OpenPGP) · dual-key rotate grace · Tailscale observe integration via LocalAPI ·
NetBird upstream PR · macOS/Windows agent (wireguard-go) · public witness network
onboarding · **multi-log validity (O2)** for multi-tenant deployments · **policy transparency** (log the ACL too, so a control plane can't
silently change who may talk to whom) · Internet-Draft.

---

## Part log

- **2026-09-18 part 1** — foundation: this file, `DECISIONS.md` D-001…D-006. Name and libraries verified.
- **2026-09-18 part 2** — `THREAT-MODEL.md`: 12 adversaries, 6 guarantees, enforcement-mode windows, provisional parameters. Forced D-007 (root/signer roles) and D-008 (device identity key).
- **2026-09-18 part 3** — `LEDGER-OPTIONS.md`: six architectures scored against the threat model; D-009 = witnessed log + optional OpenTimestamps anchoring; BFT chain and on-chain registry rejected with reasons; falsifiable "when a chain would be right" table.
- **2026-09-18 part 4** — `SPEC.md` v0: envelope + domain-separated signatures, 12 entry types, pure replay state machine with reason codes, tlog-tiles layout, receipts, tlog-proof bundles, trust file, fork rule, vector list. D-010…D-012.
- **2026-09-18 part 5** — `ENFORCEMENT.md`: backends wgctrl reaches, observe/owner/watchdog modes, reconciler pseudocode, endpoint providers, honest integration matrix (Tailscale = observe only; NetBird needs an upstream hook), failure semantics, Phase 3 measurement plan. D-013…D-015.
- **2026-09-18 part 6** — `GOSSIP.md`: three-signal model, checkpoint acquisition, witness deployment + independence table, verbatim tlog-policy, witness-time freshness state machine, peer gossip endpoints, fork evidence, 8 lab scenarios T1–T8 with expected latencies, metrics. D-016…D-018.
- **2026-09-18 part 7** — `ENROLLMENT.md`: key tiers (ssh-agent as the one signer interface; Secure Enclave/TPM unsupported), 10-minute root ceremony, QR enrollment flow, rotate/revoke/expiry, 10 recovery runbooks, `log_key` + `policy` governance entries, binding UX principles. D-019…D-021.
- **2026-09-18 part 8** — `LAB.md`: container topology on TrueNAS (real Pi + VPS as witnesses), six demos (D1a/b/c same attack × three stacks, D2 stolen signer, D3 freeze+fork, D4 lifecycle) as assertion-gated vhs tapes, monitor rules/outputs/status page, chaos container. D-022…D-024.
- **2026-09-18 part 9** — `PUBLICATION.md` (positioning, audiences, review targets, launch sequence, Transparency.dev 2027 / FOSDEM 2027, reviewer checklist, risks), `README.md` skeleton, D-025 Apache-2.0. Consolidation: part-N markers removed, file index added. **Plan complete — next action is Phase 0.**
