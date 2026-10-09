# Norn — Threat Model

Written **2026-09-18** (plan part 2). Everything in `SPEC.md` must trace back to
an adversary here. Structure borrowed from Sigsum's design doc and the KEYTRANS
architecture draft (-08 then; A13 reads -10, 2026-10-07); content is Norn's.

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
| Widen a legit peer's routes (hand it `0.0.0.0/0`) | **Prevented** in enforce mode under `routes = granted` (G7); the attempt is reported. |
| Withhold new entries / checkpoints (freeze) | **Detected**: nodes fetch checkpoints from peers over the tunnel (G4). Not prevented if *all* paths are cut. |
| Remove a legit peer / poison endpoints (DoS) | **Not prevented.** Owner mode keeps the peer *listed*, but endpoints and NAT traversal still come from the control plane. Availability is a non-goal. |
| Change ACLs so rogue-but-listed peers can reach more | Out of scope until *policy transparency* (v2 backlog). |

This is the adversary Tailnet Lock defends against; Norn adds gossip (freeze) and no-TOFU (A1 at bootstrap, see A10).

### A2 — Compromised log operator
Capabilities: withhold entries, stop signing, present different histories to different clients (split view), append garbage. Cannot forge valid entries (no signer keys). A stolen log key alone signs no checkpoint a node accepts unless 2k−N witnesses collude too (A9); the witness quorum contains it, the remedy is a new trust file, and verifier-side retirement is recorded for v1.1 (D-072 (d)).

| Goal | Norn |
|---|---|
| Split view | **Detected** unless ≥ k witnesses collude (G2). Non-repudiable proof: two cosigned checkpoints of the same size with different roots, or a failed consistency proof. |
| Append invalid entries to grant access | **Harmless**: verifiers ignore entries that fail signer-state validation at replay (G3). A past valid entry re-appended under a different signature list is the same entry and is refused as a duplicate (D-070; audit SEC-001, 2026-10-07). |
| Withhold / freeze | **Detected** via staleness (G4). DoS only. |
| Rewrite history | **Detected**: consistency proof fails against any earlier checkpoint held by any node or witness. |

### A3 — Stolen signer key (warm key, device-ops role)
Capabilities: create *valid* `Enroll`/`Revoke` entries. Cannot touch signer set (role separation, D-007).

| Goal | Norn |
|---|---|
| Enroll a rogue device | **Not prevented — but published.** The entry is in the log, attributable to that signer key, within T_c (G5). Monitor alerts. This is CT's property: misissuance is loud. |
| Revoke legit devices (DoS) | Same: published, attributable, reversible by re-enrollment after `SignerRemove`. |
| Remove other signers / lock admins out | **Prevented**: signer role cannot emit governance entries. Only root can. |
| Grow the log / flood submissions | Only a holder of an authorized signer or root key can grow this log: its courtesy check refuses malformed garbage before replay and unauthorized entries before append (§6; verifiers must still check). Each candidate applies one entry to a copy of the held replay; a per-source token bucket refuses a flood with §7's `429` and `Retry-After` before reading its body or replaying. Sources are remote IPv4 addresses or IPv6 /64s; proxy headers are ignored, so clients behind a reverse proxy safely share one bucket. Idle buckets are evicted and the source map is bounded. A trusted-proxy option is deferred to a later row. |

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
Only a signer-key holder (or authorized root-key holder) can grow this log; the courtesy check refuses garbage, without replacing a verifier's checks (§6). A legitimate signer can still grow the history with valid entries, but floods are refused per remote host with §7's `429` before any body read or replay. Proxy headers do not grant another bucket: behind a reverse proxy all clients share one, the safe default until a later trusted-proxy option. Idle eviction and a fixed source-map bound keep rotating sources from growing the limiter's memory without bound. An IPv6 source is its /64; a rotating attacker with many prefixes can still fill the map, and new sources then wait with `429` for an idle one, ten minutes at least; memory stays bounded and refused requests never reach the log.

### A9 — Witness faults
Two k-of-N quorums share at least 2k−N witnesses, so the number that must collude with the log to get two histories cosigned is max(0, 2k−N) — one under the shipped 2-of-3 policy, not k.

| Case | Norn |
|---|---|
| fewer than max(0, 2k−N) witnesses colluding with the log | No split view under the quorum alone; correctness holds. |
| ≥ k witnesses refuse to cosign (liveness) | Log cannot advance under the node's policy → nodes hold the last good checkpoint and alarm (G4). DoS. A 3-of-3 policy makes the bound k at the cost of exactly this: any one witness down stalls cosigning. |
| max(0, 2k−N) or more witnesses collude with the log — with 2k ≤ N, that is none | A split view is possible: the quorum alone proves nothing about a fork, and detection rests on gossip between nodes every `T_g` (T1). `norn init` warns when 2k ≤ N. Mitigation as for CT and Sigsum: witnesses in independent trust domains (Pi, VPS, a friend, public witness network). |

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

### A13 — State loss
A node loses what it held: a reinstall, a wiped or failed disk, a mirror that no longer verifies, or a first start. KEYTRANS architecture -10 §7.2 (2026-10-07): a client that loses its state loses its ability to detect a fork; the mitigations are an out-of-band check interval and an auditor lag both far below the time between state-loss events, and not consuming what was inserted too recently.

| Case | Norn (D-071) |
|---|---|
| Restart or reboot with the state directory intact | §10's comparison still protects: the stored checkpoint, the learned keys and policy, and any fork evidence are read back (D-069). The witness clock is read back too, so a view that was `degraded` or `hard_stale` is so again; a restart lifts no staleness limit. The peers the held head proves are asked even before anything verifies here. |
| No held head: first start, state lost, mirror unusable | The first verified head is **uncorroborated**: proven peers are asked in the same cycle and every cycle after until one answers; a peer holding another branch is a fork proven before anything was enforced. With no peer answering the head is enforced — a node must be able to start — and said so; a fork proven afterwards empties the peer set rather than freezing on the attacker's branch. Rollback exposure in that window is bounded by `S` (an older head is `degraded` past it) and ends at the first peer answer, at most `T_g` once the tunnel is up. |
| No peers configured | Nobody to corroborate with: the witness quorum alone, and `S`. The operator chose that by leaving gossip off. |
| Parameters | `T_g` = 30 s and `S` = 10 min against reinstalls measured in months: KT's "much less than" holds by three orders of magnitude. |

## 4. Guarantees

| # | Guarantee | Rests on |
|---|---|---|
| **G1 Peer authenticity** | In enforce mode, every peer in the node's WG table has an inclusion proof, under a checkpoint the node accepted, and its replayed status is `active`. | correct verifier; intact `norn.trust`; < k faulty witnesses |
| **G2 Non-equivocation** | Two honest nodes never accept incompatible histories. A fork yields a non-repudiable proof and is held forever (KEYTRANS rule: once forked, reject everything inconsistent with the held view). | fewer than max(0, 2k−N) witnesses colluding with the log — one, under 2-of-3 (A9); Ed25519 + SHA-256 sound; with 2k ≤ N the quorum alone proves nothing about a fork and detection rests on gossip; 3-of-3 makes the bound k, but any one witness down stalls cosigning |
| **G3 Validity independent of the log** | Replay admits only entries valid under the signer state at that point. The log can publish garbage; it cannot grant access. | signer keys not compromised beyond A3/A4 |
| **G4 Bounded staleness** | A node acting on a checkpoint older than S is `degraded` and alarms. A `Revoke` is effective on every honest, connected node within T_c + T_g + T_poll or that node alarms. | at least one honest path to a fresh checkpoint (log or peer) |
| **G5 Transparency / accountability** | Every accepted key traces to a log entry signed by an identifiable signer. Monitors see every entry within T_c + monitor lag. | monitor exists and runs (procedural) |
| **G6 No TOFU** | A node never trusts a log, witness set or genesis it was not provisioned with. | out-of-band channel (A10) |
| **G7 Route authenticity** | In enforce mode under `params.routes = "granted"`, every allowed-ip a node installs for a peer lies within that peer's grant, the prefixes its enrollment carried. | G1's assumptions; the signers granted what they meant to |

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

### 6.1 Full replication and the scale ceiling

`PLAN.md` targets 10¹–10⁶ entries in closed networks; that is a design target,
not a tested capacity or a configured log-size ceiling.

Every node replicates the whole log (`internal/mirror.Write`) and replays from
genesis on each start with a usable mirror (`internal/agent.restoreHead` →
`verify` → `internal/logclient.Verify`); without a usable mirror its first
successful fetch does the same. There is no snapshot or compaction path.
In-process updates can resume the held replay (`internal/logclient.VerifyFrom`);
that does not survive a process restart.

A typical entry is taken to be 420 bytes. That is an assumption, not a
measurement of a production log: the replay fixture in `testdata/vectors/log`,
the only log there is, has a mean entry within a quarter of it, rejected and
malformed entries included, and a guard keeps it there. `MAX_ENTRY_BYTES` = 65535 (`internal/cbor.MaxEntryBytes`,
`SPEC.md` §4.0); the serving cap `internal/tlog.MaxBundleEntryBytes` = 65535.
Entry bundles add 2 bytes per entry (`internal/tlog.EncodeBundle`'s uint16
framing, `SPEC.md` §6). Hash tiles have height 8, width 256
(`internal/tlog.TileHeight`, `TileWidth`), and 32-byte hashes (`crypto/sha256.Size`,
`SPEC.md` §6). `MAX_BUNDLE_BYTES` = 81919 (`internal/proof.MaxBundleBytes`,
`SPEC.md` §8.1) caps a portable proof bundle, not the replicated log or an entry
bundle; it is not multiplied by the entry count here.

For E entries, current-head hash payload is
`H(E) = sha256.Size × Σ floor(E / TileWidth^L)`, starting at L = 0 and stopping
at zero; current-head payload is `E × (entry_bytes + framing_bytes) + H(E)`.

The first table counts only files needed by the current head. The second
estimates mirrors before 6.5m-xii-m that observed every append and retained
earlier partial bundle and tile paths; a mirror now holds the current head
plus one previous generation of partials. It
assumes every entry has the typical size or the entry cap respectively;
neither table is a filesystem capacity guarantee.

| Entries | Typical estimate per node (bytes, including hashes) | Entry-cap worst case per node (bytes, including hashes) | Hash tile overhead (bytes) |
|---|---|---|---|
| 1000 | 454096 | 65569096 | 32096 |
| 10000 | 4541248 | 655691248 | 321248 |
| 100000 | 45412512 | 6556912512 | 3212512 |
| 1000000 | 454125472 | 65569125472 | 32125472 |

For retained partials, define
`R(x) = floor(x / w) × w(w+1)/2 + r(r+1)/2`, where `w = TileWidth` and
`r = x mod w`; substitute `R(E)` for E in entry storage and
`sha256.Size × Σ R(floor(E / w^L))` for H(E).

| Entries | Typical estimate with all partials per node (bytes, including hashes) | Entry-cap worst case with all partials per node (bytes, including hashes) | Retained hash tile overhead (bytes) |
|---|---|---|---|
| 1000 | 57075256 | 8243072596 | 4023104 |
| 10000 | 582543280 | 84130297480 | 41083520 |
| 100000 | 5831755424 | 842059422224 | 412296384 |
| 1000000 | 58352075296 | 8425229508736 | 4127668064 |

N nodes hold N times the per-node payload in either table; these are estimates
of file-content bytes, excluding checkpoints, filesystem metadata and allocation rounding, proof
bundles, temporary writes and other caches. Full replication puts storage and
startup work on the smallest node; a larger network multiplies storage without
reducing that node's work.

Raspberry Pi replay time is **unmeasured**. There is no replay benchmark in the
tree; the lab must measure startup replay on the actual Pi, with its log,
storage and witness policy, before treating the design target as usable capacity.

## 7. Explicit non-goals (repeated from PLAN.md so this file stands alone)

Availability under A1/A2/A9 · stolen WG private key before revocation · colluding log + witness quorum · security of the `norn.trust` delivery channel · privacy of log contents (device names, enrollment times, key fingerprints are visible to anyone who can read the log) · traffic policy between authorized peers · internet-scale directories.

## 8. Residual risks → feed later parts

- **Root quorum = 1 in homelabs** is the realistic weak point (A4). Part 7 must make a 2-of-3 root with one key on paper/hardware *easy*, or nobody will do it.
- **Freeze with all paths cut** (A1 + A5 together) is undetectable until a path returns; the degraded-state UX must make "I haven't seen a fresh checkpoint in 40 min" impossible to miss. Part 6.
- **Watchdog window** (§5) — measure it; if > 1 s in practice, owner mode becomes the only enforce mode.
- **State loss and gossip** (A13): a node that lost its state is protected after its first head only by its peers; a mesh whose nodes cannot reach each other over the tunnel (strict allowed-ips, no node-to-node routes) has no gossip and so no corroboration. H8's deployment kit must check that peers are reachable on the gossip port, and `norn status` should say when none has ever answered.
- **Whether witnesses alone are enough**, or a consensus layer buys anything against A2/A9 — this is exactly the question `LEDGER-OPTIONS.md` (part 3) must answer with these adversaries as the scoring criteria.
