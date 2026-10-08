# Norn — Distribution, Freshness, Witnesses, Gossip

Written **2026-09-18** (plan part 6). This document is **informative**: the
distribution story — how a node gets a checkpoint it can trust, how it knows
the checkpoint is recent, and how two nodes discover they were lied to — and no
rule an interoperable node needs lives here; `SPEC.md` owns those. Where it
disagrees with `SPEC.md`, the SPEC and the implemented node win.

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

`SPEC.md` §§10 and 15 define acceptance. A checkpoint from a proven peer has
the same trust requirements as one from a `log_urls` endpoint. The node checks
the signature, origin and witness policy, fetches the candidate's entries and
tiles, and verifies their tree before using the candidate. It compares the
candidate and stored branches at their common size **before** applying the
rollback rule: a shorter divergent branch is a fork, while a shorter
consistent branch is refused without an accusation. Only a fully verified,
replayed checkpoint can replace the stored one or change the proven set.

Source order affects how soon the node hears about a head; it does not change
what the node can accept. Peer selection and the polling schedule are described
in §6 below.

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

A log asks its witnesses over `c2sp.org/tlog-witness` at the `url` its own
`norn.trust` gives them — the network already says where they are, so a log is not
configured twice. An unreachable witness never stops the log: T6 below is explicit
that a witness outage leaves the log publishing and the *nodes* degrading, so the
head goes out with whatever corroboration was available. A log that refused to write
instead would turn a witness outage into a log outage.

An **idle** log still republishes every `checkpoint_interval`, because witness time
is what freshness is measured against: a log that stopped asking would make its own
network go `degraded` with nothing wrong, the quietest networks first.

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

`SPEC.md` §§5.3, 8.1 and 15 define the clock and state machine. This section
explains the operating consequences.

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
- On each verified checkpoint with quorum time the node can record
  `(mono_now, quorum_time)`; only the newest time advances its estimate.
- The node estimates now from the newest quorum time it has seen plus monotonic
  elapsed time since seeing it. A held checkpoint's age is that estimate minus
  its own quorum time; an older peer head cannot move the estimate backwards.
- The wall clock is used for one thing only: raising `CLOCK_SKEW`. The test is
  `|(wall − quorum_time) − age| > Δclock` on a **direct-from-log** fetch — never on a
  checkpoint pulled from a peer, which may legitimately be older.

  `|wall − quorum_time| > Δclock` is the same test only when `age` is zero, and is
  wrong away from it: a log that has not been cosigned for two hours produces two
  hours on a node whose clock is perfect. Subtracting the age this node has been
  measuring all along separates the two, and T5 below depends on the difference —
  a skewed node alarms and does *not* go degraded, and a stale log degrades and
  does *not* alarm. Δclock defaults to **5 minutes**: at a direct fetch the newest
  cosignature is already one checkpoint interval plus a witness round trip old, so
  a tighter bound would alarm on a healthy network.

State machine:

```
hard-stale age > S_hard (opt-in)       enforcer drops all peers (owner: ReplacePeers []; watchdog: evict all)
fresh      age ≤ S (10 min)            normal
degraded   otherwise                   keep proven set; alarm every 5 min; poll all sources every 10 s
unknown    no quorum time (quorum none) keep proven set; alarm every 5 min (FRESHNESS_UNKNOWN)
```

**Tested top to bottom, first match wins** — `hard-stale` before `fresh`, per
§8.1 and D-060. That matters only when **S_hard is tighter than S**, and then it
decides everything: `degraded` is empty and the node goes from fresh straight to
hard-stale at its own limit. The alternative — `fresh` first — would mean a root
quorum could raise `params.staleness` past a node's S_hard and lift that node's
hard stop out of reach without touching its configuration, which is the opposite
of a local limit.

In the ordinary configuration, where S_hard sits above S, the three read as the
ladder they look like: fresh, then degraded, then hard-stale.

`hard-stale` is a deliberate outage, so it is **opt-in twice**: `nornd` leaves S_hard
unset unless `-hard-stale` or `hard_stale` says otherwise, and a very small value is
refused as a typo guard — a limit shorter than the interval a log issues checkpoints
at would hard-stale the node almost always. That floor is **not** a rule that S_hard
must exceed the network's `staleness`; that configuration is legitimate and is the
point of having a local floor at all.

The `degraded` alarm repeats on its cadence rather than once, because a degraded node
that simply went quiet is indistinguishable from one that recovered; recovering resets
it, so the next degradation is announced immediately rather than up to five minutes
later.

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
| `GET /norn/evidence` | the newest fork evidence it holds, or 404 (§7) |

An implementation may offer `POST /norn/hint` as an optional nudge to pull;
the receiver never trusts its body. The current server rejects writes, including
this optional endpoint.

Every `T_g` (30 seconds by default) a node pulls `/norn/checkpoint` from up
to `r = 3` random proven peers, including when its direct log answers. An
unusable or stale log triggers an immediate peer round. The node runs §15's
source-neutral verification on each answer. Consistency proofs are computed
locally from tiles, so a peer serves data, never claims.
A peer is addressed through its allowed-ips, so under `routes = "granted"` only
devices with a grant can be asked.

Every one of these reads is bounded, and the bounds are **implementation
defaults, not protocol** (`HARDENING-PLAN.md` H2): `nornd` gives one read from a
peer 5 s (`peer_timeout`), one round of asking peers 5 s in all
(`round_budget`), and one verification of the log — a request per bundle and
tile — 60 s (`verify_budget`). A peer the round's budget did not reach was not
asked (`PEER_ROUND_CUT`); a verification the budget cut short fails like any
other and the node holds its last verified state. A silent neighbour therefore
costs a cycle one budget, never the cycle.

The address is **derived from the interface, never configured**: `nornd` takes a
gossip *port* and gets the host from the WireGuard device itself, so there is no
setting that could point it at `0.0.0.0`. The required endpoints are read-only —
`GET` and `HEAD` are accepted and writes are refused, because a peer answers
questions and takes no instructions —
and they expose the node's mirror directory and nothing beside it.

Properties this buys, each with a lab test (§8):
- **Liveness under log freeze** — one node that got the new checkpoint suffices for
  the whole connected mesh (T2).
- **Split-view detection with colluding witnesses** — two nodes fed different
  quorum-valid checkpoints detect it on their next exchange (T1).
- **Evidence propagation** — peers independently pull `/norn/evidence`, verify
  it, and freeze too (T1b). An optional hint can shorten discovery latency.

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

## 9. Metrics (**planned**: `nornd` will expose Prometheus on the tunnel address)

None of these exist yet: the node publishes `/run/norn/proven.json`
(`SPEC.md` §13.3) and no metrics at all. The list is the shape the exporter
should take, kept here so the names are argued about before the exporter is
written rather than after.

`norn_checkpoint_size`, `norn_checkpoint_age_seconds`, `norn_state{fresh|degraded|hard_stale|fork}`,
`norn_gossip_peers_polled_total`, `norn_gossip_adopted_from{log|peer}`,
`norn_fork_evidence_total`, `norn_replay_rejected_total`, `norn_clock_skew_seconds`,
`norn_reconcile_seconds` (histogram), `norn_evicted_peers_total`, `norn_unproven_peers`.
