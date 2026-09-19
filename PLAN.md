# Norn — Plan

> The Norns carve into the Tree the record of what has happened. Nothing carved is uncarved.
> **Thesis: no peer without proof.**

A key-transparency layer for WireGuard. Every device enrollment, key rotation and
revocation is an entry in an append-only, witnessed, fully-replicated log. A node
completes a handshake with a peer **only** if it holds a proof that the peer's key is
in the log and not revoked. The coordination server (Headscale, NetBird, Tailscale,
innernet, or a human with `wg-quick`) keeps doing what it does — Norn just makes it
**unable to lie silently**.

Started **2026-09-18**. Author: Franco Michetti (`onembyte`). Language: Go.

## Files

| File | Part | What |
|---|---|---|
| `PRIOR-ART.md` | 1 | why this doesn.t exist yet; the gap, precisely |
| `THREAT-MODEL.md` | 2 | 12 adversaries, 6 guarantees, windows, parameters |
| `LEDGER-OPTIONS.md` | 3 | six ledger architectures scored; D-009 |
| `SPEC.md` | 4 (+5–7) | entries, replay, log, receipts, proofs, trust file |
| `ENFORCEMENT.md` | 5 | modes, reconciler, integration matrix, measurements |
| `GOSSIP.md` | 6 | witnesses, freshness, gossip, T1–T8 |
| `ENROLLMENT.md` | 7 | key tiers, ceremony, QR flow, runbooks R1–R10 |
| `LAB.md` | 8 | topology, demos D1–D4, monitor |
| `PUBLICATION.md` | 9 | audiences, review, launch, talks |
| `DECISIONS.md` | all | D-001…D-025 |
| `README.md` | 9 | public-facing skeleton |

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
- Not anonymity. Log entries reveal device names and enrollment times to whoever can read the log.

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
5. **The lab is the truth.** `make lab-test` on a clean 3-node lab = green. A
   security property without a lab test does not exist.
6. **Time-box.** Phase over 2× estimate: stop, cut scope, write why in `DECISIONS.md`.
7. **Every decision gets a `DECISIONS.md` entry:** what, why, what was rejected.
8. **A gate is PASS only when every line of its PASS list is true.** No partial credit.

---

## Fixed decisions (do not re-litigate until Phase 6 is done)

| Decision | Choice | Why |
|---|---|---|
| Language | **Go** | The whole transparency stack is Go: `filippo.io/torchwood` v0.9 (client: tiles, checkpoints, witness policy), `transparency-dev/tessera` v1.0 (log write path, POSIX driver), `transparency-dev/witness`, `wgctrl`. All verified on proxy.golang.org 2026-09-18. |
| Signatures | **Ed25519** | tlog note/cosignature format is Ed25519; hardware signers (TKey, YubiKey) support it. |
| Hash / tree | **SHA-256, RFC 6962 Merkle** | tlog-tiles compatibility; existing witnesses and monitors verify unchanged. |
| Entry encoding | **Deterministic CBOR (RFC 8949 §4.2)** | TKA precedent; cheap canonicalization; test vectors are byte-exact. |
| Log format | **C2SP tlog-tiles + tlog-checkpoint** | Static files. Serve from nginx, S3, or a directory on the NAS. |
| State model | **Full replication + replay on every node** | No prefix trees, no lookups — nothing to equivocate on except the checkpoint, and witnesses cover that. |
| Log operator | **Untrusted for validity.** Inclusion ≠ validity. | Verifiers re-check every entry signature against signer state at replay. The log is a bulletin board, not a judge. |
| Enforcement target | **Kernel WireGuard (Linux) via wgctrl, first** | The only place enforcement is possible without patching someone's daemon. Userspace/Tailscale get observe mode. |
| Rollout | **Observe mode is mandatory before enforce** | tailscale-rs lesson: verify-and-log before fail-closed. |
| Trust bootstrap | **Pre-provisioned `norn.trust` file, out of band. No TOFU.** | Closes Tailnet Lock's stated bootstrap weakness. |
| Consensus | **Witnessed transparency log + optional OpenTimestamps anchoring of checkpoints (D-009)** | Decided in `LEDGER-OPTIONS.md`: witnesses give non-equivocation; anchoring defeats backdating under full collusion; BFT chains and on-chain registries rejected with reasons. |

## Repo layout

```
norn/
  PLAN.md  PRIOR-ART.md  THREAT-MODEL.md  LEDGER-OPTIONS.md  SPEC.md  DECISIONS.md
  cmd/norn/          # CLI: init | enroll | sign | submit | verify | status | revoke | monitor
  cmd/nornd/         # node agent: observe | enforce; serves checkpoints+tiles to peers
  cmd/norn-log/      # log server (Tessera POSIX) + witness submitter
  cmd/norn-witness/  # thin wrapper around transparency-dev/witness for self-hosting
  internal/entry/    # canonical encoding, signing, per-entry validation
  internal/state/    # replay → {devices, keys, status, signers, threshold}
  internal/tlog/     # checkpoint / tile / proof plumbing (torchwood)
  internal/wg/       # wgctrl reconciler: owner mode + watchdog mode
  internal/gossip/   # peer checkpoint exchange over the tunnel
  internal/trust/    # norn.trust parsing + pinning
  testdata/vectors/  # JSON/CBOR test vectors — the cross-implementation contract
  lab/               # 3-node lab: kernel wg + headscale + log + witness (containers/VMs on TrueNAS)
  demo/              # attack demos: malicious-headscale, stolen-signer, withheld-checkpoint
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
- [x] Replay of the fixture log yields the expected state, byte-exact. **Go reproduces `state.json` byte for byte**, and all 12 `genesis/` aborts.
- [x] Rejected: wrong signer, below threshold, signer revoked in an earlier entry, duplicate device id, rotate signed by neither old key nor signers, entry referencing unknown device. **All six vectored** — checking this found two with no vector at all, including the removed-signer case, which is the whole point of `signer_remove`. A test now fails the build if any of the six stops being exercised.
- [x] `go test -fuzz` on decoder + replay: 1 h, zero panics. **83,791,152 executions across three targets, all PASS.** The decoder target asserts canonical round-trip, not merely absence of panics.
- [x] Cross-implementation check: all 16 entries **rebuilt in Go from their semantic values** and signed independently produce bytes identical to the shipped vectors. Stronger than re-exporting, and without duplicating the fixture — see the 1.7 note in `BUILD-LOG.md`.

### Phase 2 — The log + CLI (2 weeks)
`norn-log` on Tessera POSIX; `norn init|enroll|sign|submit|verify|status`.
**PASS when:**
- [ ] Log directory served by plain nginx; `norn verify` fetches tiles + checkpoint and reproduces state. **Half true (audited 2.10):** the verifier fetches the checkpoint, the entry bundles **and every hash tile**, and reproduces `state.json` byte for byte — tested over HTTP against a stock static file server with no server-side logic, which is the property this line is really about. **nginx itself has never run**, so the line stays open until the lab does it.
- [x] Tamper test: flip one byte in a tile → inclusion proof fails, verifier refuses. **Closed by 2.10.** Until then the verifier never fetched a hash tile, so this was false and looked true: it rebuilt the tree from entry bundles, which is stronger, but left a log free to serve corrupt tiles to every monitor and witness while the one program guaranteed to be looking said nothing. Now a flipped byte and a missing tile are each refused, and a tampered leaf's inclusion proof stops verifying under upstream's checker (2.2).
- [x] Log restarts without losing or reordering entries; checkpoint size monotonic. Reopening an untouched log leaves the checkpoint and the replayed state byte-identical; size increases strictly across appends; and after a restart the log **keeps counting** — the next entry lands at the index the old checkpoint ended on, and entry 0 is still entry 0.
- [ ] An unmodified `transparency-dev/witness` cosigns a Norn checkpoint (ground rule 3 proven). **Half done (2.6a):** `transparency-dev/formats`, the package witnesses use to parse and verify checkpoints, accepts a Norn checkpoint unchanged and rejects a wrong key and an origin mismatch. The cosignature round trip needs a running witness and is a lab item.
- [x] Go `note` / torchwood accept `testdata/vectors/receipt.note` and the trust file's verifier keys unchanged (cross-checks the 0.5 encodings, which are otherwise only self-consistent). Done in 2.1 with `golang.org/x/mod/sumdb/note`, in both directions: it opens what we sign, we verify what it signs, and its key-id derivation matches ours across 32 name/key combinations.
- [ ] End-to-end enrollment with a phone camera: device QR → `norn sign` on the laptop with a hardware key (touch) → submit → device imports trust file by QR → active. Timed; target < 3 min. **Software-only half done:** `norn enroll | sign | submit | verify` runs end to end against a real `norn-log`, and a network can be bootstrapped from nothing and a device enrolled into it (2.9f-ii). What is untested is everything physical — a phone reading the QR, a hardware key's touch, and the clock.
- [ ] Runbooks R1–R3, R6, R7 executed in the lab and their downtime column verified.

### Phase 3 — Enforcement agent (2–3 weeks)
`nornd` observe + enforce on kernel WireGuard; owner mode and watchdog mode — normative in `ENFORCEMENT.md`.
**PASS when:**
- [ ] Lab, enforce/watchdog: rogue key added with `wg set` is evicted with p99 < 1 s over 1 000 runs at T_poll = 200 ms; packets that crossed the window are counted and reported. **Software half done (audited 3.8):** an injected key is gone after **exactly one cycle**, which is what makes the window equal to `T_poll` rather than some multiple of it. The distribution, and the packets that crossed the window, are measurements — nothing here counts a packet.
- [ ] Lab, enforce/owner: the peer table equals the proven set at all times (continuous diff, 24 h soak, zero divergence). **Software half done:** the first cycle installs the proven set and **fifty further cycles write nothing** — a daemon that rewrote the table every poll could never pass a continuous diff, so that is the property the soak would really be checking. The soak itself needs a day and an interface.
- [ ] A `Revoke` entry drops the device within one checkpoint interval. **Software half done, and it was untested until this audit:** every enforcement test started from a fixed proven set, so nothing showed the peer table *following the log when the log changed underneath it*. Now a real `revoke` is appended to a real log between two cycles, in owner and watchdog mode, and the device loses its place. The timing against a checkpoint interval is the lab's.
- [ ] Observe mode: 24 h soak, zero writes to the interface (verified by diffing `wg showconf` every second). **Software half done:** twenty-five cycles with a different intruder appearing before each one, zero writes, an alarm every time. One quiet cycle proving nothing was the weaker test this replaces.
- [ ] Zero false removals in the 24 h soak. **Software half done:** across fifty unchanged cycles no proven peer is ever removed, and `internal/reconcile` refuses to plan a removal for a key the log proves. The soak adds real time, a real interface and real churn.
- [ ] Fight test against a real NetBird management server: `CONTROL_PLANE_FIGHT` fires and `quarantine` isolates the host. **Software half done (3.6):** three evictions of one key inside the window declare a fight exactly once, evictions continue, and `quarantine` runs a configured command once and only when chosen. What needs NetBird is whether a real control plane behaves the way the detector assumes.
- [ ] Tailscale observe: an unproven peer key in the netmap raises `UNPROVEN_PEER` within 1 s of the LocalAPI event. **Not started.** There is no LocalAPI watcher: `tailscaled` exposes no UAPI socket, so this is a different source of truth feeding the same reconciler, not a backend behind `peertable.Device`. `ENFORCEMENT.md` part 6 places it in the integration work, and it stays unwritten rather than half-written.

### Phase 4 — Witnesses, gossip, freshness (3 weeks)
`tlog-witness` submission + `tlog-policy` quorum; self-hosted witnesses on the Pi
(.153) and a VPS; peer-served checkpoints over the tunnel; staleness policy — normative in `GOSSIP.md`, lab scenarios T1–T8.
**PASS when:**
- [ ] Split-view lab: two log instances presenting divergent checkpoints to two nodes → detected via gossip within 2 checkpoint intervals, alarm raised, no peer changes applied from the losing view.
- [ ] Witness quorum lost → node refuses the new checkpoint, keeps last good, alarms.
- [ ] Log server killed → nodes still converge on the newest witnessed checkpoint via peers.
- [ ] Replayed old checkpoint → rejected (size monotonic + consistency proof).
- [ ] T1b evidence propagation: a node that never saw the second branch freezes via peer evidence ≤ 3·T_g.
- [ ] T5 clock skew: a node with wall clock +2 h raises CLOCK_SKEW and does **not** go degraded.
- [ ] T7 revoke propagation latency measured and ≤ T_c + T_g + T_poll.
- [ ] Checkpoint N has a verifiable OpenTimestamps proof in `anchors/`; `norn verify --anchored` checks it (advisory witness, D-009).

### Phase 5 — Attack demos + monitor (2 weeks)
Reproducible demos — normative in `LAB.md` §2: D1a/b/c (one attack × plain WG / NetBird / Headscale), D2 stolen signer, D3 freeze + fork, D4 lifecycle. `norn monitor` per `LAB.md` §3.
**PASS when:**
- [ ] `make demos` from a clean `make lab-up`: all six `run.sh` assert green and render their tapes.
- [ ] D1a: rogue key never appears in `wg show` on node1. D1b: evicted with measured window, `CONTROL_PLANE_FIGHT` fires, `quarantine` isolates. D1c: `UNPROVEN_PEER` + phone push ≤ 1 s.
- [ ] D2: rogue enrollment visible, phone alert, `norn audit --by`, R2 executed, eviction time on screen.
- [ ] D3: nodes stay fresh through a log freeze via gossip; fork evidence on both nodes; `norn verify-evidence` passes offline.
- [ ] Monitor: one notification received per rule in `LAB.md` §3 during the run; status page reachable over the tunnel.

### Phase 6 — Spec v1 + publication (2 weeks)
Freeze `SPEC.md`, publish vectors, README with threat model and comparison table,
blog post, WireGuard mailing list + r/WireGuard + HN, request review from a
transparency-dev / Sigsum person — sequence and review targets in `PUBLICATION.md`.
**PASS when:**
- [ ] Cold-model gate repeated on frozen spec: independent verifier passes all vectors.
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
