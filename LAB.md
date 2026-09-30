# Norn — Lab, Attack Demos, Monitor

Written **2026-09-18** (plan part 8). Where the security properties get proven,
recorded, and paged to a phone.

**Status, 2026-09-30: the lab and the demos do not exist.** There is no `lab/`
directory, no `demo/` directory, no `lab/compose.yaml`, no chaos container, no
patches under `demo/patches/`, and no `make lab-up`, `make lab-test` or
`make demos` target (`Makefile`). Everything in §1, §2, §4 and §5 is planned,
and no result in them has been produced. §3 is the exception: `norn monitor`
exists (`cmd/norn/monitor.go`, `internal/monitor`), with the gaps §3 lists.

## 1. Lab topology (TrueNAS .155, Docker, `lab/compose.yaml`)

Planned; none of this exists yet.

Containers run with `NET_ADMIN` and get their **own network namespace**, so each
node has a private kernel WireGuard interface (the host's `wg0` is reserved by
TrueNAS; inside a netns the name doesn't matter). `/dev/net/tun` is passed to the
Tailscale and NetBird clients. VMs are the fallback only if a client refuses containers.

```
bridge  norn-lab 10.99.0.0/24            ("the internet")
------------------------------------------------------------
log          norn-log (Tessera POSIX) + nginx static tiles      10.99.0.10
w-lab        witness, *configurable malicious*                  10.99.0.11
w-pi         real Pi .153 (LAN)      — independent location    via LAN
w-vps        real VPS                — independent provider    via internet
monitor      norn monitor + ntfy + status page + OTS job        10.99.0.12  (also an enrolled peer)
node1..3     kernel WG + nornd  (overlay 10.9.0.0/24)           10.99.0.21-23
headscale    control plane + ts1, ts2 (tailscaled)              10.99.0.30-32
netbird      combined server + nb1, nb2                         10.99.0.40-42
evil         chaos: per-client routing (nft), patched control planes, replayer   10.99.0.66
```

Budget: ~12 containers, < 2 GB RAM, no GPU. `make lab-up` · `make lab-test`
(T1–T8 from `GOSSIP.md` §8 + Phase 3 measurements from `ENFORCEMENT.md` §10) ·
`make demos` — none of these targets exists yet. GitHub Actions runs unit tests
and vectors (`.github/workflows/ci.yml`); the lab is to run on the NAS
(self-hosted runner later, `make` first).

## 2. Attack demos — the same attack against three stacks

Planned; no demo exists yet.

The narrative that makes Norn legible: **one attack, three coordination servers,
three honest outcomes.** Each demo runs twice — *without* Norn (attack succeeds)
and *with* it.

| Demo | Stack | Norn mode | Without Norn | With Norn | What the viewer learns |
|---|---|---|---|---|---|
| **D1a** | plain WireGuard, admin script as "control plane" | owner | `evil` runs `wg set wg0 peer <rogue>` on node1; rogue pings node1 | rogue key never appears in `wg show`; rogue's handshakes time out; `EVICTED_PEER` if it was ever there | prevention, zero window |
| **D1b** | NetBird, patched management server injects a peer | watchdog | rogue reaches nb1 | evicted in ~T_poll; NetBird re-adds; `CONTROL_PLANE_FIGHT` fires; with `quarantine` nb1 isolates itself | prevention with a measured window + fight detection |
| **D1c** | Headscale, patched to inject a node into the netmap | observe | rogue reaches ts1, **nobody knows** | `UNPROVEN_PEER` alarm + phone push ≤ 1 s; tunnel still up (honest: Norn cannot evict here) | this is Headscale #1432, live; detection where prevention is impossible without patching tailscaled |
| **D2** | stolen signer key | any | — | attacker enrolls `rogue-laptop` *validly*; monitor pushes "signer-1 enrolled rogue-laptop" to the phone; `norn audit --by signer-1` lists it; root runs R2; eviction time on screen | **transparency beats authority**: a valid-looking enrollment is still loud |
| **D3** | freeze, then split view | any | log cut → nothing new ever arrives; fork → two nodes silently disagree | nodes stay fresh via gossip; fork evidence written on both, `norn verify-evidence` re-checks it offline, all nodes freeze | witnesses guard the log, gossip guards the witnesses |
| **D4** | lifecycle | — | — | `norn init` ceremony (paper words) → QR enroll from a phone → status page shows the device, in < 3 min | it is usable |

Each demo = `demo/<name>/run.sh` (brings up the scenario, **asserts** the outcome,
exits non-zero on failure) + `demo/<name>/demo.tape` (vhs; rendered to `.mp4` + `.gif`
only after `run.sh` passed). Recordings are therefore reproducible artifacts, not
screen captures. Phase 5 gate = all six `run.sh` green from a clean `make lab-up`.

What the code would support today, if the lab existed:

- **D1a** — owner mode exists but has not run on a real interface, and on one it
  rewrites the table every cycle until SEC-012 is fixed (`ENFORCEMENT.md` §3).
  Owner mode's eviction raises `UNPROVEN_PEER`; `EVICTED_PEER` is watchdog mode's.
- **D1b** — watchdog mode, fight detection and the `quarantine` policy exist.
- **D1c** — cannot run: the Tailscale/Headscale observer is not implemented
  (`ENFORCEMENT.md` §6), and no node reports `UNPROVEN_PEER` to the monitor (§3).
- **D2** — the monitor reports every entry, so the rogue enrolment is announced;
  `norn audit -by` takes a key id, not a signer's name; R2 cannot be executed,
  because no shipped tool builds `signer_remove` or `revoke` (`ENROLLMENT.md` §5,
  SEC-008).
- **D3** — a node whose log is cut asks its peers and stays fresh. The fork half
  does not happen as described while both nodes are fresh: they never compare
  heads (`GOSSIP.md` §6; SEC-002, SEC-007).
- **D4** — `norn init` has no paper words (`ENROLLMENT.md` §2), nothing reads a
  QR, and the monitor's status page never shows devices (§3).

## 3. Monitor — `norn monitor`

The monitor is **an enrolled peer**: it sees the log, the witnesses and every node's
metrics/evidence through the tunnel, with no extra ports. It never sits on the
enforcement path.

### Inputs
log tiles + checkpoint · each witness's latest cosignature · each node's
`/norn/checkpoint`, `/norn/evidence`, Prometheus endpoint · the receipt inbox
(submitters can forward receipts to it) · optional OpenTimestamps job (D-009).

What `norn monitor` reads today (`monitor.Watcher.Round`): the log, verified under
the trust file and any key or policy it has replayed, and, for each `[[node]]` in
`monitor.toml`, that node's `/norn/evidence` and its mirror through the gossip
endpoints, verified the same way. It does not poll witnesses, nodes have no
Prometheus endpoint (`GOSSIP.md` §9), the receipt inbox (`monitor.Inbox`) is not
wired in, and it runs no OpenTimestamps job (`norn stamp` is a separate command).

### Rules (defaults; `monitor.toml`)

| Event | Level | Notes | In `norn monitor` today |
|---|---|---|---|
| any new entry | info | "2 h ago: signer-1 enrolled pi-cam" — every entry, always; a homelab has few | yes (`new-entry`) |
| root-level entry (`signer_*`, `root_*`, `log_key`, `policy`, `params`) | **critical** | governance changes are the loudest thing in the system | yes (`governance-entry`) |
| entry rejected at replay (log published garbage) | warning | log operator misbehaving or buggy | yes (`rejected-entry`) |
| receipt deadline passed without inclusion | **critical** | non-repudiable proof of A2 | no: `monitor.Inbox` exists and is tested, but nothing feeds it |
| fork evidence from any node | **critical** | includes the evidence file | yes (`fork-evidence`), when a node serves any bytes at `/norn/evidence`; the alert gives their length, not the file, and the monitor does not check them |
| witness quorum unreachable > 2·T_c | warning | liveness | no: `Rules.WitnessQuorum` exists, nothing calls it |
| checkpoint age > S on any node | warning → critical at 3·S | freeze | yes (`checkpoint-age`), for the log and each node |
| node heartbeat missing > 5 min | warning | nornd down = window becomes ∞ in watchdog | yes (`heartbeat`): a node whose mirror has not verified for that long |
| `UNPROVEN_PEER` / `EVICTED_PEER` / `CONTROL_PLANE_FIGHT` from a node | **critical** | A1 in progress | no: `Rules.Node` maps them, but `nornd` only logs its events and nothing carries them to the monitor |
| `CLOCK_SKEW` | warning | | no, for the same reason |
| anchor lag > `max_lag` | info | advisory by design | no: `Rules.AnchorLag` exists, nothing calls it |

The monitor also raises `log-unreadable` when the log cannot be read or does not
verify.

### Outputs
`ntfy` (push to phone, the demo channel) · **Home Assistant** webhook → `norn_alert`
event (automation: FORK turns the office light red — a demo, not built yet) ·
Prometheus Alertmanager · stdout JSON · email. All optional; stdout always. All
five are implemented (`internal/monitor/sink.go`, wired in `sinksFor`).

### Status page
Read-only HTML on the tunnel address: checkpoint size/age, witness cosignature
times, anchor status, device table with proof links, last 20 entries in plain
words, open alerts. The Norn equivalent of a CT log's public page — and the thing
you screenshot for the README.

As implemented, `monitor.Status` renders all of that except anchor status, and
`norn monitor` serves it read-only at whatever address `status_listen` names —
nothing restricts it to the tunnel. But `norn monitor` never hands the page a
verified result: it sets only the latest round's alerts, so the page shows the
network's name, its fingerprint, "nothing verified yet" and those alerts. The
full page exists only in `internal/monitor`'s tests. Its proof links lead back
to the page itself: the handler answers every path with the same HTML.

## 4. Chaos container (`evil`)

Planned; none of this exists yet.

- `nft` rules that route the log's HTTP per client IP → serve branch A to node1, B to node2 (T1, D3).
- Patched Headscale (one function: append a node to every netmap) and patched NetBird management (one gRPC handler: include a rogue peer) — kept as small diffs in `demo/patches/` so reviewers can read exactly what "compromised control plane" means.
- Replayer: re-serves a stored older checkpoint (T4).
- Clock: `date -s` inside node2 (T5).
- Kill switches: stop log, stop 2 of 3 witnesses (T2, T6).

## 5. What "done" looks like on the NAS
Not reached: none of the three targets exists yet (§1).

`make lab-up && make lab-test && make demos` on a clean checkout: green, six recordings in `demo/out/`, status page reachable from the laptop over the tunnel, one phone notification per alert type received during the run.
