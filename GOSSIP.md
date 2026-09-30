# Norn — Distribution, Freshness, Witnesses, Gossip

Written **2026-09-18** (plan part 6). How a node gets a checkpoint it can trust,
how it knows the checkpoint is recent, and how two nodes discover they were lied to.

**Status, 2026-09-30.** This is the design. Where the code does something else,
or nothing yet, the section says so and names the audit finding
(`docs/audit/SECURITY_AUDIT.md`) or the open decision (`docs/audit/ROADMAP.md`).
The largest difference is cadence: a node asks its peers for a checkpoint only
when the log fails or its view is stale, not every T_g (§2, §6; SEC-007), and
whether to implement the design or change it is decision **D-c**, not yet made.
Nothing in §8's lab exists, `cmd/norn-witness` is an empty stub (§3), and none
of §9's metrics is implemented.

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

**Not true of the code today (SEC-002, SEC-007, open).** Gossip guards against
the witnesses only if nodes compare heads, and a node whose view is fresh does
not ask its peers (§2). So a split view that stays freshly cosigned on both
branches goes unnoticed: the log plus enough witnesses to cosign both branches
can keep chosen nodes on a branch that omits a revocation. "Enough" is
**2k−N**, not k, because two quorums of a flat k-of-N policy are guaranteed to
share only 2k−N witnesses — one under the homelab 2-of-3 (§3). Decisions D-b
(the bound and the default policy) and D-c (the cadence) are open.

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

**What `nornd` does instead (pending D-c).** Every `T_poll` (200 ms), not every
T_g, `agent.Once` fetches the head from one log location — `-log`, or the trust
file's first `log_urls` entry; the others are not used — and verifies it with
`logclient.Verify` against the stored head, tiles and replay included. It asks
up to r = 3 random proven peers (`gossip.Choose`) **only when that failed or the
head it got is stale** (older than S); a peer's head replaces the log's only if
the log failed or the peer's is larger. While the view is fresh no peer is asked
for a checkpoint at all (`TestPeersAreNotAskedWhenTheLogAnswers` pins this). The
trust rule is as above: a peer's answer goes through the same `logclient.Verify`
under the same anchor. BUILD-LOG 4.5d records the choice as a bandwidth
decision and 4.5e adds the stale case; SEC-007 is its consequence. Whether to
restore the design — fetch only `/norn/checkpoint` from r peers every T_g,
tiles only on a larger head or a different root — or to supersede D-016 is
decision D-c.

## 3. Witness deployment

- The **log** pushes every new checkpoint to each witness (`tlog-witness`
  `add-checkpoint`, with the consistency proof from the witness's last size); the
  cosignatures are appended to the served `checkpoint`. The log makes only
  *outbound* connections, so a log on a home NAS behind NAT needs nothing opened.
- A **witness** that must accept inbound (from the log) but sits behind NAT itself
  (the Pi) either lives on the same LAN as the log or exposes itself through an
  `https-bastion` on the VPS (reverse TLS connection, ALPN `bastion/0`, addressed by
  key hash). Both configurations are planned for the lab (§8), which does not
  exist yet.
- Implementation: `transparency-dev/witness` (OmniWitness, sqlite, one binary) or
  `sigsum-witness`. Only the first is tested against Norn: `internal/interop`
  runs the pinned build `make witness` produces, and skips when it is absent,
  which it is in CI. `cmd/norn-witness` is meant to be a thin wrapper that takes a
  `norn.trust` and produces the witness config — so "run a witness for my
  network" is one command. **Not implemented:** today `cmd/norn-witness` is
  `func main() {}`, and a witness is configured by hand.
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

Two corrections, both open. First, "cannot forge a quorum" is not "cannot split
the view": the log pushes to each witness separately, so it can show `pi` only
branch A and `vps` only branch B, and a colluding `friend` cosigns both. Two
2-of-3 quorums need share only one witness (2k−N), so one colluding witness is
enough (SEC-002). Whether Norn refuses or warns on a policy whose quorums need
not intersect, and which default it ships, is decision D-b. Second, nothing
enforces "only in observe mode": `nornd` starts in owner or watchdog mode under
a 1-of-1 or `quorum none` policy with no warning (SEC-033); whether it should
refuse, require an override, or document it is decision D-j.

A log asks its witnesses over `c2sp.org/tlog-witness` at the `url` its own
`norn.trust` gives them — the network already says where they are, so a log is not
configured twice. An unreachable witness never stops the log: T6 below is explicit
that a witness outage leaves the log publishing and the *nodes* degrading, so the
head goes out with whatever corroboration was available. A log that refused to write
instead would turn a witness outage into a log outage.

An **idle** log still republishes every `checkpoint_interval`, because witness time
is what freshness is measured against: a log that stopped asking would make its own
network go `degraded` with nothing wrong, the quietest networks first. `norn-log`
does this only when the trust file gives at least one witness a `url`
(`witnessClients`, `refresh`): a log cosigned by `-self-witness` alone does not
republish while idle (SEC-034, open).

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
  `unknown`, not perfect. One exception in the code (SEC-028, open): a node that
  already has a witness clock and then accepts a `quorum none` head computes its
  age from the zero time, so it reports `degraded`, or `hard_stale` with S_hard
  set, rather than `unknown`.
- On every adoption the node records `(mono_now, quorum_time)`.
- `age()` = `quorum_time_at_adoption` + (monotonic elapsed since) — compared against
  the *newest* `quorum_time` it has seen.
- The wall clock is used for one thing only: raising `CLOCK_SKEW`. The test is
  `|(wall − quorum_time) − age| > Δclock` on a **direct-from-log** fetch — never on a
  checkpoint pulled from a peer, which may legitimately be older. The code does not
  keep that restriction yet: `agent.Once` runs `checkClock` on whatever head it
  adopted, a peer's included (SEC-033, open).

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
fresh      age ≤ S (10 min)            normal
degraded   S < age ≤ S_hard, or S_hard off   keep proven set; alarm every 5 min; poll all sources every 10 s
hard-stale age > S_hard (opt-in)       enforcer drops all peers (owner: ReplacePeers []; watchdog: evict all)
```

`hard-stale` is a deliberate outage, so it is **opt-in twice**: `nornd` leaves S_hard
unset unless `-hard-stale` or `hard_stale` says otherwise, and a value below §4.5's
`staleness` default is refused — it would drop every peer before the network had even
called the view degraded.

That floor only covers the default. `S` is a `params` key and can be raised above an
`S_hard` a node chose earlier (this project's own fixture goes from 600 to 900). So the
rows above are read **top to bottom, first match wins** (`SPEC.md` §8.1): such a node
stays `fresh` up to `S` and then goes straight to `hard-stale`. It never drops peers
while the network calls its view fresh.

The `degraded` alarm repeats on its cadence rather than once, because a degraded node
that simply went quiet is indistinguishable from one that recovered; recovering resets
it, so the next degradation is announced immediately rather than up to five minutes
later.

`degraded` is loud by design: `norn status` prints the age in red, the monitor
pages, Home Assistant gets an event. The A1+A5 "all paths cut" residual is
undetectable only if nobody looks; this makes not-looking hard.

**Quieter than that today.** `nornd` repeats its `DEGRADED` event every 5 min,
but logs it at INFO (SEC-033). `norn status` is a one-shot command that fetches
the log itself: it prints the quorum time and an age measured by the local
clock, labelled as such, with no colour, and says that the fresh/degraded state
is tracked by a running `nornd` — it does not compute the state. `norn monitor`
raises `checkpoint-age` for the log and for each node it watches, a warning past
S and critical at 3·S, and sends it to whichever outputs `monitor.toml`
configures, a Home Assistant webhook among them (`LAB.md` §3).

## 6. Peer gossip

Each `nornd` serves, **on its WireGuard interface address only** (unreachable
outside the tunnel), plain HTTP:

| Endpoint | Returns |
|---|---|
| `GET /norn/checkpoint` | its currently adopted cosigned checkpoint |
| `GET /norn/tile/…`, `GET /norn/tile/entries/…` | tlog-tiles it holds (it holds all of them — full replication) |
| `GET /norn/evidence` | any fork evidence it holds (§7) |
| `POST /norn/hint` | "I have size N" — optional nudge; receiver pulls, never trusts the body. **Not implemented** |

`internal/gossip.Handler` serves the first three and nothing else. There is no
`POST /norn/hint`: the server refuses every method but `GET` and `HEAD` (`readOnly`),
and nothing sends a hint.

Every `T_g` a node pulls `/norn/checkpoint` from `r = 3` random proven peers and
runs §2 on the result. Consistency proofs are computed locally from tiles (the node
has them), so a peer serves data, never claims.

**Not what the code does (SEC-007; pending D-c).** A node asks r random proven
peers for their head — and fetches their tiles and replays, through the same
`logclient.Verify` — only when the log failed or its own view is stale (§2).
Every T_g, whatever the log is doing, it asks r random proven peers for
`/norn/evidence` instead (`pollEvidence`), which finds a fork only after some
other node has proved it.

The address is **derived from the interface, never configured**: `nornd` takes a
gossip *port* and gets the host from the WireGuard device itself, so there is no
setting that could point it at `0.0.0.0`. The endpoints are read-only — anything
but `GET` is refused, because a peer answers questions and takes no instructions —
and they expose the node's mirror directory and nothing beside it. "Unreachable
outside the tunnel" holds only as far as routing does: under Linux's weak host
model a packet for the tunnel address that arrives on another interface is
accepted, so a host on the same LAN that routes the tunnel address to the node
can reach the port unless a firewall rule stops it (SEC-034, open).

Properties this buys, each with a lab test (§8):
- **Liveness under log freeze** — one node that got the new checkpoint suffices for
  the whole connected mesh (T2).
- **Split-view detection with colluding witnesses** — two nodes fed different
  quorum-valid checkpoints detect it on their next exchange (T1).
- **Evidence propagation** — a node that detects a fork pushes `/norn/hint`; peers
  pull `/norn/evidence`, verify it independently, and freeze too (T1b).

As implemented: T2 holds in software once the log fails or the view goes stale
(`TestAPeerCarriesTheNodeWhenTheLogIsGone`,
`TestADegradedNodeAsksItsPeersEvenWhenTheLogAnswers`). T1 does not, while both
nodes are fresh: they never compare heads (SEC-002, SEC-007), and
`TestAForkedPeerIsAForkNotABrokenNeighbour` reaches detection only after its log
goes quiet. T1b holds by polling rather than by a pushed hint: peers find the
evidence on a later `pollEvidence` round (every T_g, r random proven peers),
check it with `forkevidence.Check` against their own trust file, and freeze
(`TestANodeFreezesOnEvidenceFromAPeer`) — within the limits of §7. No lab test
exists for any of them (§8).

Gossip carries only signed material, so a rogue peer inside the watchdog window
can withhold but not deceive; unproven peers are not polled.

## 7. Fork evidence

`fork/<unix>.evidence` = both cosigned checkpoints + the failing consistency proof
(or the equal-size/different-root pair), plus the policy text. Anyone with
`norn.trust` can re-verify it offline: `norn verify-evidence <file>`. This is the
artifact that goes to the witness operators, the log operator's boss, or a blog post.

Two limits in the code, both open. `forkevidence.Check` takes one log key and one
policy, and the node, `pollEvidence` and `norn verify-evidence` all pass the trust
file's. After the roots rotate the log key, a genuine fork signed by the new key
fails the check: the node writes no evidence file, freezes in memory only, and
has nothing for its peers to fetch (SEC-005 (b)). After the roots raise the
policy, evidence whose heads meet only the trust file's weaker policy still
passes, and freezes nodes that would themselves have refused those heads
(SEC-005 (c)). Since `bdb3086` evidence is written when the served branch is the
longer one too (SEC-005 (a), fixed).

## 8. Split-view and freshness test design (Phase 4 gate)

**Planned; none of it exists.** There is no `lab/` directory, no script under
`lab/tests/` and no `make lab-test` target, so no scenario below has run. Some
behaviours have software tests against `peertable.Fake` and in-process logs and
peers (§6); the latencies in the last column are unmeasured. Two alarms named
below do not exist in the code: no `LOG_MISBEHAVIOUR` alarm (T3) and no `REPLAY`
counter (T4, and §9).

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

**Not implemented.** `nornd` exposes no metrics endpoint and records none of the
metrics below; the only thing it serves on the tunnel address is §6. Its events
go to its own log (`report` in `cmd/nornd/main.go`), where nothing else reads
them.

`norn_checkpoint_size`, `norn_checkpoint_age_seconds`, `norn_state{fresh|degraded|hard_stale|fork}`,
`norn_gossip_peers_polled_total`, `norn_gossip_adopted_from{log|peer}`,
`norn_fork_evidence_total`, `norn_replay_rejected_total`, `norn_clock_skew_seconds`,
`norn_reconcile_seconds` (histogram), `norn_evicted_peers_total`, `norn_unproven_peers`.
