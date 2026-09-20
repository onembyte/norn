# Norn — Distribution, Freshness, Witnesses, Gossip

Written **2026-09-18** (plan part 6). How a node gets a checkpoint it can trust,
how it knows the checkpoint is recent, and how two nodes discover they were lied to.

## 1. Three signals, three jobs

| Signal | Guards against | Fails how |
|---|---|---|
| **Log** (`log_urls`) | nothing — it is the source | can stall or lie |
| **Witnesses** (k-of-N) | the log lying (split view, rewrite) | can stall (liveness) or, ≥ k colluding, lie with the log |
| **Peers** (gossip over the tunnel) | the log *and* the witnesses stalling; the log *and* the witnesses lying **to different nodes** | can only withhold; every byte they relay is signed |

The sentence to remember: **witnesses guard against the log; gossip guards against
the witnesses.** Neither alone is enough; together, the only undetectable attack is
a log + witness quorum that shows *every* node the *same* false history — which is
no longer a split view, it is a forgery of signed entries, which needs signer keys.

## 2. Acquiring a checkpoint

```
every T_g (30 s), and on demand:
  candidates := fetch(log_urls…) ∪ fetch(r random proven peers, r = 3) ∪ {stored}
  for cp in candidates sorted by size desc:
      if !VerifyCheckpoint(cp, log key): continue
      if !policy.Satisfied(cp cosignatures): continue           # §4
      if stored && cp.size < stored.size: continue               # never go backwards
      if stored && !Consistent(stored → cp): FORK(stored, cp)    # §6
      adopt cp; fetch tiles; replay; hand proven set to enforcer
      break
```

Order of sources matters only for speed; **trust is identical** — a checkpoint from
a peer is as good as one from the log because the signatures are the same.

## 3. Witness deployment

- The **log** pushes every new checkpoint to each witness (`tlog-witness`
  `add-checkpoint`, with the consistency proof from the witness's last size); the
  cosignatures are appended to the served `checkpoint`. The log makes only
  *outbound* connections, so a log on a home NAS behind NAT needs nothing opened.
- A **witness** that must accept inbound (from the log) but sits behind NAT itself
  (the Pi) either lives on the same LAN as the log or exposes itself through an
  `https-bastion` on the VPS (reverse TLS connection, ALPN `bastion/0`, addressed by
  key hash). Both configurations are in the lab.
- Implementation: `transparency-dev/witness` (OmniWitness, sqlite, one binary) or
  `sigsum-witness`. `cmd/norn-witness` is a thin wrapper that takes a `norn.trust`
  and produces the witness config — so "run a witness for my network" is one command.
- **Freshness rule for witnesses** (borrowed from Sigsum): a witness SHOULD refuse to
  cosign a checkpoint whose log signature is older than 5 min, so cosignature
  timestamps are meaningful.

### Independence — say it plainly in the docs

| Witness placement | Independent from… | Not independent from… |
|---|---|---|
| same host as the log | nothing | anything |
| Pi on the same LAN (.153) | NAS compromise | the admin, the house, the ISP |
| VPS at another provider | the house, the LAN | the admin |
| a friend's box | the admin | a colluding friend |
| public witness network (ArmoredWitness etc.) | everyone above | — |

Homelab default `2 of [pi, vps, friend]`: no single physical location and no single
person can forge a quorum. A 1-of-1 self-witness is allowed only in observe mode.

`norn-log -self-witness <policy name>=<keyfile>` is that first row, and it is how a
network gets through its first minutes: a log with no witness publishes heads that
every verifier refuses (§10 step 3), so something has to cosign before the network
works at all. The log says so on every start, because a witness sharing the log's
host cannot detect the one thing witnesses exist to detect — that log serving two
different views. Moving those keys onto a second machine is the whole improvement;
the key is refused at startup if the policy does not name it, or names it under a
different key, since either produces cosignatures nothing counts.

## 4. Policy

`norn.trust.policy` is **verbatim `c2sp.org/tlog-policy`** — no Norn dialect.
Homelab example:

```
log     <log vkey>       http://10.0.0.155:8099/norn
witness pi     <vkey>    http://10.0.0.153:8100
witness vps    <vkey>    https://w.example.net
witness friend <vkey>    https://bastion.example.net/<keyhash>
group   home 2 pi vps friend
quorum  home
```

The optional OpenTimestamps anchor (D-009) is **not** in the policy file: it is a
separate `anchor` table in `norn.trust`, evaluated only by `norn verify --anchored`
and the monitor, never by `nornd` on the handshake path.

## 5. Freshness — witness time is the clock

A node's wall clock is untrusted (A11). Define for an adopted checkpoint:

- `quorum_time(cp)` = the latest instant T such that the witnesses whose cosignature
  is at least T **satisfy the policy** — the newest time the network as a whole
  vouches for. For a flat `group home k …` this is the *k-th newest* cosignature
  timestamp, which is how it reads at first; that phrasing has no meaning once
  groups nest, because `group top 1 inner friend` has no single k. Evaluating the
  policy at each candidate instant gives the same answer for the flat case and a
  defined one for the rest.
- A policy of `quorum none` has **no** `quorum_time`: a network that asked for no
  corroboration has nobody vouching for the time either, so its freshness is
  `unknown`, not perfect.
- On every adoption the node records `(mono_now, quorum_time)`.
- `age()` = `quorum_time_at_adoption` + (monotonic elapsed since) — compared against
  the *newest* `quorum_time` it has seen. Wall clock is used only to raise
  `CLOCK_SKEW` when `|wall − quorum_time| > Δclock` at the moment of a direct-from-log
  fetch (when cosignatures are seconds old).

State machine:

```
fresh      age ≤ S (10 min)            normal
degraded   S < age ≤ S_hard, or S_hard off   keep proven set; alarm every 5 min; poll all sources every 10 s
hard-stale age > S_hard (opt-in)       enforcer drops all peers (owner: ReplacePeers []; watchdog: evict all)
```

`degraded` is loud by design: `norn status` prints the age in red, the monitor
pages, Home Assistant gets an event. The A1+A5 "all paths cut" residual is
undetectable only if nobody looks; this makes not-looking hard.

## 6. Peer gossip

Each `nornd` serves, **on its WireGuard interface address only** (unreachable
outside the tunnel), plain HTTP:

| Endpoint | Returns |
|---|---|
| `GET /norn/checkpoint` | its currently adopted cosigned checkpoint |
| `GET /norn/tile/…`, `GET /norn/tile/entries/…` | tlog-tiles it holds (it holds all of them — full replication) |
| `GET /norn/evidence` | any fork evidence it holds (§7) |
| `POST /norn/hint` | "I have size N" — optional nudge; receiver pulls, never trusts the body |

Every `T_g` a node pulls `/norn/checkpoint` from `r = 3` random proven peers and
runs §2 on the result. Consistency proofs are computed locally from tiles (the node
has them), so a peer serves data, never claims.

Properties this buys, each with a lab test (§8):
- **Liveness under log freeze** — one node that got the new checkpoint suffices for
  the whole connected mesh (T2).
- **Split-view detection with colluding witnesses** — two nodes fed different
  quorum-valid checkpoints detect it on their next exchange (T1).
- **Evidence propagation** — a node that detects a fork pushes `/norn/hint`; peers
  pull `/norn/evidence`, verify it independently, and freeze too (T1b).

Gossip carries only signed material, so a rogue peer inside the watchdog window
can withhold but not deceive; unproven peers are not polled.

## 7. Fork evidence

`fork/<unix>.evidence` = both cosigned checkpoints + the failing consistency proof
(or the equal-size/different-root pair), plus the policy text. Anyone with
`norn.trust` can re-verify it offline: `norn verify-evidence <file>`. This is the
artifact that goes to the witness operators, the log operator's boss, or a blog post.

## 8. Split-view and freshness test design (Phase 4 gate)

Lab (`lab/`): 3 nodes (kernel WG), 1 log, 3 witnesses (2 honest + 1 configurable),
1 monitor, all on TrueNAS as containers/VMs; a `chaos` container that can rewrite
routes so the log serves *different content per client IP*.

| # | Scenario | Setup | Expected within |
|---|---|---|---|
| **T1** | Split view, colluding witnesses | log serves branch A (size N, entry E_a) to node1 and branch B (size N, entry E_b) to node2; all 3 witnesses cosign both | both nodes write evidence, freeze, alarm ≤ 2·T_g; monitor receives evidence ≤ 3·T_g; proven set unchanged on both |
| **T1b** | Evidence propagation | as T1 but node3 sees only branch A | node3 freezes via peer evidence ≤ 3·T_g |
| **T2** | Log freeze | log stops serving; node1 already has size N+1 | node2, node3 adopt N+1 via gossip ≤ 2·T_g; nobody goes `degraded` |
| **T3** | Honest witnesses, lying log | log tries branch B to node2; witnesses cosigned A already | witnesses refuse B; node2 never adopts B; node2 stays on A (from peers), no alarm except `LOG_MISBEHAVIOUR` from the receipt check |
| **T4** | Replay | chaos replays a cosigned checkpoint of size N−5 | rejected; no state change; `REPLAY` counter increments |
| **T5** | Clock skew | node2 wall clock +2 h | `CLOCK_SKEW` alarm; **not** `degraded`; proven set unchanged |
| **T6** | Witness quorum loss | 2 of 3 witnesses down | log cannot reach quorum; nodes hold last good; `degraded` after S; recovers when witnesses return |
| **T7** | Revoke propagation | signer revokes node3 | node1, node2 evict node3 ≤ T_c + T_g + T_poll; measured |
| **T8** | Anchoring | monitor OTS-stamps checkpoint N | `norn verify --anchored` passes after the Bitcoin proof upgrades; fails on a tampered checkpoint |

Each scenario is a script under `lab/tests/` that exits 0 on PASS and prints the
measured latency. `make lab-test` runs all of them.

## 9. Metrics (`nornd` exposes Prometheus on the tunnel address)

`norn_checkpoint_size`, `norn_checkpoint_age_seconds`, `norn_state{fresh|degraded|hard_stale|fork}`,
`norn_gossip_peers_polled_total`, `norn_gossip_adopted_from{log|peer}`,
`norn_fork_evidence_total`, `norn_replay_rejected_total`, `norn_clock_skew_seconds`,
`norn_reconcile_seconds` (histogram), `norn_evicted_peers_total`, `norn_unproven_peers`.
