# Norn — Threat Model

Written **2026-09-18** (plan part 2). Everything in `SPEC.md` must trace back to
an adversary here. Structure borrowed from Sigsum's design doc and the KEYTRANS
architecture draft; content is Norn's.

The one-sentence version, in Sigsum's style:

> **Norn is secure if a monitor can discover every peer key that an honest node
> would accept — and no honest node accepts a key the log has not published.**

---

## 1. Parties

| Party | Holds | Trusted for |
|---|---|---|
| **Root signer(s)** | cold Ed25519 key(s), offline | governance: add/remove signers, change threshold, emergency revoke |
| **Signer(s)** | warm Ed25519 key(s), on admin devices | device lifecycle: `Enroll`, `Revoke`, approve `Rotate` |
| **Device** | X25519 WireGuard key + Ed25519 device identity key | proving possession of its own keys; self-service `Rotate` |
| **Log operator** | log signing key, storage, HTTP endpoint | **nothing except liveness.** Inclusion ≠ validity. |
| **Witnesses** (N, policy k-of-N) | witness Ed25519 keys | cosigning only checkpoints consistent with all they have seen |
| **Node / verifier** (`nornd`) | `norn.trust` file, local log replica, WG interface | correct replay + enforcement on its own host |
| **Monitor** | read access to the log | alerting humans; never in the enforcement path |
| **Control plane** (Headscale / NetBird / Tailscale / a human) | node configs, endpoints, ACLs | **nothing.** Norn exists so that it need not be trusted for the peer set. |

Norn deliberately has **no party that is trusted for both liveness and correctness.**

## 2. Assets

1. **The proven peer set** on each node: `{device_id → wg_pubkey, status}` derived by replay.
2. **Signer state**: `{root keys, signer keys, threshold}` — compromise of this is compromise of everything after it.
3. **Log integrity**: append-only, single history.
4. **Trust anchors**: `norn.trust` (log key, witness keys + policy, genesis hash, network id).
5. **Availability** of tunnels — an asset Norn *protects only by detection*, never by prevention.

## 3. Adversaries

For each: capabilities · goal · what Norn guarantees · what it does not · detection window.
Windows use the parameters in §6.

### A1 — Compromised control plane
*Headscale / NetBird management / Tailscale control / whoever writes node configs.*
Capabilities: full control of every config a node receives (peers, endpoints, allowed-IPs, ACLs, DNS). Cannot sign log entries.

| Goal | Norn |
|---|---|
| Inject a rogue peer | **Prevented** in enforce mode (G1). **Detected** in observe mode ≤ T_poll. |
| Swap a legit peer's key (MITM) | **Prevented** in enforce mode: the swapped key has no inclusion proof (G1). |
| Withhold new entries / checkpoints (freeze) | **Detected**: nodes fetch checkpoints from peers over the tunnel (G4). Not prevented if *all* paths are cut. |
| Remove a legit peer / poison endpoints (DoS) | **Not prevented.** Owner mode keeps the peer *listed*, but endpoints and NAT traversal still come from the control plane. Availability is a non-goal. |
| Change ACLs so rogue-but-listed peers can reach more | Out of scope until *policy transparency* (v2 backlog). |

This is the adversary Tailnet Lock defends against; Norn adds gossip (freeze) and no-TOFU (A1 at bootstrap, see A10).

### A2 — Compromised log operator
Capabilities: withhold entries, stop signing, present different histories to different clients (split view), append garbage. Cannot forge valid entries (no signer keys).

| Goal | Norn |
|---|---|
| Split view | **Detected** unless ≥ k witnesses collude (G2). Non-repudiable proof: two cosigned checkpoints of the same size with different roots, or a failed consistency proof. |
| Append invalid entries to grant access | **Harmless**: verifiers ignore entries that fail signer-state validation at replay (G3). **Except, until fixed — open defect SEC-001:** a past valid entry re-appended with one junk signature is not a duplicate and applies again (a revoked device returns, a raised quorum falls). Needs no key. Fix awaiting a decision (`BUILD-LOG.md`, 6.5m-sec-001b). |
| Withhold / freeze | **Detected** via staleness (G4). DoS only. |
| Rewrite history | **Detected**: consistency proof fails against any earlier checkpoint held by any node or witness. |

### A3 — Stolen signer key (warm key, device-ops role)
Capabilities: create *valid* `Enroll`/`Revoke` entries. Cannot touch signer set (role separation, D-007).

| Goal | Norn |
|---|---|
| Enroll a rogue device | **Not prevented — but published.** The entry is in the log, attributable to that signer key, within T_c (G5). Monitor alerts. This is CT's property: misissuance is loud. |
| Revoke legit devices (DoS) | Same: published, attributable, reversible by re-enrollment after `SignerRemove`. |
| Remove other signers / lock admins out | **Prevented**: signer role cannot emit governance entries. Only root can. |

Recovery: root publishes `SignerRemove(stolen)` + `Revoke(rogue devices)`. No history rewrite (contrast TKA, which "rewrites the changelog"; Norn is append-only and supersedes instead).

### A4 — Stolen root key
Capabilities: everything, including `SignerAdd`, `ThresholdChange`, `RootRemove` if root quorum is 1.

| Norn |
|---|
| **Published** (G5) — root-level entries are the loudest monitor alert. **Not prevented** if root quorum = 1. Mitigation is procedural: root quorum ≥ 2 for anything beyond a homelab; root keys cold (hardware, offline). A network whose entire root quorum is stolen must be re-genesised: new `norn.trust` to every node out of band. Norn cannot save a network from total governance compromise, and says so. |

### A5 — Network attacker (on-path or off-path)
Capabilities: block, delay, reorder, replay, inject packets between any parties.

| Goal | Norn |
|---|---|
| Replay an old checkpoint | **Rejected**: checkpoint size must be ≥ last seen, consistency proof required (G2). |
| Serve stale proofs to keep a revoked peer alive | **Bounded** by freshness: proofs must reference a checkpoint cosigned within S (G4). |
| Block access to the log server | **Routed around** via peer gossip over the tunnel. |
| Read log traffic | Log contents are not secret (§7). Fetches happen over the tunnel or HTTPS anyway. |
| Tamper with WireGuard data | WireGuard's job, not Norn's. |

### A6 — Compromised member node
Capabilities: a valid WG key + device key, a copy of the log, position inside the tunnel.

| Goal | Norn |
|---|---|
| Forge gossip | **Impossible**: gossiped checkpoints carry log + witness signatures. |
| Withhold gossip / lie about what it saw | Can only *withhold*; peers have other peers. DoS at most. |
| Enroll another device | **Impossible** without a signer key. |
| Attack other nodes through the tunnel | Out of scope — segmentation/ACL is the control plane's job (see A1, v2). |
| Stay connected after compromise is noticed | **Bounded**: `Revoke` takes effect within T_c + T_g + T_poll (G4). |

### A7 — Malicious enrollee
Capabilities: submits an enrollment request.

| Goal | Norn |
|---|---|
| Enroll a WG pubkey it does not control (key-substitution) | **Prevented**: enrollment request is signed by the device identity key, and the WG pubkey is bound to it (D-008). |
| Enroll a pubkey already active for another device | **Rejected at replay**: uniqueness rule — one active device per WG pubkey. |
| Socially engineer a signer | Procedural. Norn makes the result visible (G5); it cannot make admins careful. |

### A8 — Malicious insider with a legitimate signer key
Not prevented — they are authorized. **Every action is attributable to their key and permanent** (G5). Threshold > 1 on root operations forces collusion; monitors alert on every entry. This is accountability, not prevention, and the doc says so.

### A9 — Witness faults
| Case | Norn |
|---|---|
| < k witnesses faulty or malicious | No effect on correctness; policy tolerates. |
| ≥ k witnesses refuse to cosign (liveness) | Log cannot advance under the node's policy → nodes hold last good checkpoint, alarm (G4). DoS. |
| ≥ k witnesses **collude with the log** | **Split view becomes possible. Out of scope**, exactly as for CT and Sigsum. Mitigation: witnesses in independent trust domains (Pi, VPS, a friend, public witness network). |

### A10 — Attacker at bootstrap
Capabilities: controls the channel that provisions a new node.

| Norn |
|---|
| If the attacker controls the `norn.trust` delivery, the node joins the attacker's network. **Norn removes TOFU (G6) but cannot secure the out-of-band channel itself.** The trust file is small (~1 KB); QR / USB / typed fingerprint are all acceptable. `nornd` refuses to start without one — there is no "accept whatever the server sends" path. |

### A11 — Wrong clocks
A node's clock is wrong or manipulated.

| Norn |
|---|
| Freshness is judged against **witness cosignature timestamps**, not the node's wall clock; the node needs only *monotonic* local time plus a tolerance. A node whose clock is off by more than the tolerance alarms rather than silently accepting stale proofs. Roughtime is a v2 option. |

### A12 — Bugs in Norn itself
A fail-open bug admits rogue peers; a fail-closed bug takes the network down.

| Norn |
|---|
| Observe mode mandatory before enforce (D-005). Fuzzed decoder and replay (Phase 1 gate). Owner mode has no race window; watchdog mode has one (§5). Cold-model reimplementation from spec + vectors as an independence check. |

## 4. Guarantees

| # | Guarantee | Rests on |
|---|---|---|
| **G1 Peer authenticity** | In enforce mode, every peer in the node's WG table has an inclusion proof, under a checkpoint the node accepted, and its replayed status is `active`. | correct verifier; intact `norn.trust`; < k faulty witnesses |
| **G2 Non-equivocation** | Two honest nodes never accept incompatible histories. A fork yields a non-repudiable proof and is held forever (KEYTRANS rule: once forked, reject everything inconsistent with the held view). | < k witnesses colluding with the log; Ed25519 + SHA-256 sound |
| **G3 Validity independent of the log** | Replay admits only entries valid under the signer state at that point. The log can publish garbage; it cannot grant access. **Open defect SEC-001** breaks this today (see A2). | signer keys not compromised beyond A3/A4 |
| **G4 Bounded staleness** | A node acting on a checkpoint older than S is `degraded` and alarms. A `Revoke` is effective on every honest, connected node within T_c + T_g + T_poll or that node alarms. | at least one honest path to a fresh checkpoint (log or peer) |
| **G5 Transparency / accountability** | Every accepted key traces to a log entry signed by an identifiable signer. Monitors see every entry within T_c + monitor lag. | monitor exists and runs (procedural) |
| **G6 No TOFU** | A node never trusts a log, witness set or genesis it was not provisioned with. | out-of-band channel (A10) |

## 5. Enforcement modes and the watchdog window

| Mode | Who writes the WG peer table | Window for a rogue peer |
|---|---|---|
| **observe** | not Norn; Norn only reads | ∞ — alerts only |
| **enforce / owner** | Norn, from the proven set; control plane supplies endpoints only | **none** — the peer is never added |
| **enforce / watchdog** | control plane adds; Norn reconciles | ≤ T_poll (Linux WireGuard has no peer-change event; `nornd` polls via wgctrl). A handshake and a few packets can slip through in that window. |

Owner mode is the design intent. Watchdog mode exists so Norn can sit beside an unmodified NetBird/innernet; its window is documented, measured in the Phase 3 gate, and defaults to T_poll = 200 ms.

## 6. Parameters (provisional; revisited in part 6)

| Symbol | Meaning | Default |
|---|---|---|
| T_c | max interval between checkpoints (log issues one on every append and at least every T_c) | 60 s |
| T_g | peer gossip interval | 30 s |
| T_poll | watchdog poll interval | 200 ms |
| S | staleness before `degraded` | 10 min |
| S_hard | staleness before enforce mode drops *all* peers (opt-in; default keeps last-known-good) | off |
| k-of-N | witness policy | lab: 1-of-1 · homelab: 2-of-3 · org: 3-of-5 |
| Δclock | tolerance on witness timestamps vs local monotonic clock | 5 min |

## 7. Explicit non-goals (repeated from PLAN.md so this file stands alone)

Availability under A1/A2/A9 · stolen WG private key before revocation · colluding log + witness quorum · security of the `norn.trust` delivery channel · privacy of log contents (device names, enrollment times, key fingerprints are visible to anyone who can read the log) · traffic policy between authorized peers · internet-scale directories.

## 8. Residual risks → feed later parts

- **Root quorum = 1 in homelabs** is the realistic weak point (A4). Part 7 must make a 2-of-3 root with one key on paper/hardware *easy*, or nobody will do it.
- **Freeze with all paths cut** (A1 + A5 together) is undetectable until a path returns; the degraded-state UX must make "I haven't seen a fresh checkpoint in 40 min" impossible to miss. Part 6.
- **Watchdog window** (§5) — measure it; if > 1 s in practice, owner mode becomes the only enforce mode.
- **Whether witnesses alone are enough**, or a consensus layer buys anything against A2/A9 — this is exactly the question `LEDGER-OPTIONS.md` (part 3) must answer with these adversaries as the scoring criteria.
