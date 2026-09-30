# Norn — Enforcement Layer

Written **2026-09-18** (plan part 5). How `nornd` turns the proven set into a
refused handshake. Implements `THREAT-MODEL.md` §5; feeds `SPEC.md` §14.

**Status, 2026-09-30.** This is the design. Where `nornd` does something else,
or nothing yet, the section says so and names the audit finding
(`docs/audit/SECURITY_AUDIT.md`). All three modes are implemented in
`internal/reconcile` and `internal/agent` and write through `wgctrl`
(`internal/wgdev`), but every enforcement test runs against
`peertable.Fake`: no test writes to a real WireGuard interface, and the one
that touches a kernel (`TestAgainstARealInterfaceIfOneExists`) only reads an
interface if one exists. None of the §10 measurements has run.

## 1. Principle

WireGuard decides whom to talk to in exactly one place: the **cryptokey routing
table** — the interface's list of `(peer public key, allowed-ips, endpoint)`. A key
not in that table gets no handshake response at all (WireGuard's silence property).
Norn enforces there, and only there. Nothing in the packet path, nothing in the
handshake, no protocol changes: **a rogue key is simply never installed, or is
removed.**

Everything below is about who writes that table, and how fast Norn can win when
someone else writes it too.

## 2. Backends (what `wgctrl` v0.0.0-2024-12 can drive)

| Platform / implementation | Transport | Read | Write | Norn modes possible |
|---|---|---|---|---|
| Linux kernel WireGuard | generic netlink | ✓ | ✓ | observe · owner · watchdog |
| wireguard-go (Linux, macOS, Windows, BSD) | UAPI unix socket / named pipe | ✓ | ✓ | observe · owner · watchdog |
| Windows WireGuardNT kernel driver | ioctl | ✓ | ✓ | observe · owner · watchdog (verify in Phase 3) |
| FreeBSD kernel | ioctl | ✓ | ✓ | observe · owner · watchdog |
| OpenBSD kernel | ioctl | ✓ | read-only | observe |
| tailscaled (embedded wireguard-go, **no UAPI socket**) | LocalAPI only | ✓ (events) | ✗ | **observe** |

Write primitives used: `ConfigureDevice(iface, Config{ReplacePeers: true, Peers: …})`
for owner mode; `PeerConfig{PublicKey: k, Remove: true}` for watchdog removals;
`UpdateOnly` to refresh endpoints without adding keys. `nornd` never touches the
interface's private key, listen port or fwmark. It does drop peers' preshared
keys: `peertable.Peer` has no preshared-key field, so an owner-mode
`ReplacePeers` rewrite re-adds every peer without one (SEC-035).

**No peer-change events on Linux.** Two patches adding a netlink multicast group
for peer changes (2021, 2023) were never merged; NetBird's own interface monitor
polls. So watchdog and observe modes **poll** `Device()` every `T_poll`. A netlink
dump of a 1 000-peer interface is well under a millisecond; 200 ms polling is free.

## 3. Modes

### observe
Reads only. Every `T_poll`: `actual := Device(iface).Peers`; diff against `proven`.
Any key in `actual` not in `proven` → `UNPROVEN_PEER` alarm with the key, the
allowed-ips it was given, and the endpoint. Any proven key missing from `actual` →
`MISSING_PEER` (informational; the control plane may legitimately not have
connected it yet). Never writes. Mandatory first mode everywhere (D-005).

### enforce / owner
`nornd` is the **sole writer** of the peer table.

- Desired table = `proven` × endpoint data from an **endpoint provider** (§5).
- On every proven-set change and every `T_poll`: if `actual ≠ desired` →
  `ConfigureDevice(ReplacePeers: true, Peers: desired)`. This both installs the
  proven set and evicts anything an external writer slipped in, and **the
  eviction raises `UNPROVEN_PEER` as observe mode would**: correcting an attack
  silently would leave the attempt invisible, and the attempt is the thing worth
  knowing about.
- **A rewrite keeps an endpoint the interface has learned** where the provider
  supplies none. WireGuard learns a peer's endpoint from its handshakes, and for
  a roaming peer it exists nowhere else; rewriting the table with a zero
  endpoint would discard it and take that peer offline until it happened to
  handshake again — an outage caused by enforcement, on a peer nobody doubted.
- A difference in **endpoints alone** is refreshed with `UpdateOnly`, never by
  rewriting the table: `actual ≠ desired` above means the keys or their
  allowed-ips differ. A peer that roams is not a security event.
- The endpoint provider may supply endpoints / allowed-ips **only for keys in
  `proven`**; keys it mentions that are not proven are logged and dropped. A control
  plane thus degrades to an *endpoint directory* — the role it should have had.
- Window for a rogue key: **none**. It is never written.
- **Not yet convergent on a real interface (SEC-012, open).** The desired set
  holds every proven device, the node's own included, and WireGuard ignores a
  peer whose key is the interface's own. So on a real interface `actual`
  never equals `desired` and owner mode rewrites the table every `T_poll`;
  `peertable.Fake` stores any key, which is why the tests do not show it.
  Whether a node excludes its own key is decision D-g (`docs/audit/ROADMAP.md`).

### enforce / watchdog
Someone else (NetBird, innernet, a human) owns the table; `nornd` polices it.

- Every `T_poll`: for each `actual` key ∉ `proven` → `PeerConfig{Remove: true}`,
  alarm `EVICTED_PEER`. A proven device the table does **not** carry raises
  `MISSING_PEER` and nothing else: installing it is the table owner's job, not
  Norn's (G4 non-goal), and the difference between "reported" and "installed"
  is the whole distinction between watchdog and owner mode.
- Window: ≤ `T_poll` + reconfigure latency, plus the I/O each cycle does
  before it reconciles. Today that is the whole log fetched and replayed
  every cycle, with nothing cached and each request allowed 30 s
  (`logclient.Timeout`; SEC-013), and bounded peer reads: 10 s for each
  silent peer asked, with up to r asked for fork evidence (at most once per
  T_g) and, when the log failed or the view is stale, up to r for a
  checkpoint; a peer that answers each read just inside the deadline costs
  10 s per file fetched from it (§8 (c); `gossip.FetchTimeout`; SEC-003). A handshake
  and a few packets can complete inside it. To be measured in the Phase 3
  gate (§10), which has not run.
- **Fight detection.** If the same key is evicted `N` times within `W` (default 3
  in 60 s) the control-plane daemon is re-adding it: alarm `CONTROL_PLANE_FIGHT`
  and apply the configured fight policy:
  - `alarm` (default) — keep evicting, keep alarming;
  - `quarantine` — bring the interface down (`ip link set … down`) until an
    operator intervenes. Fail-closed by choice, never by default.

## 4. Reconciler (normative pseudocode)

```
every T_poll, and immediately on proven-set change:
  actual  := wg.Device(iface).Peers            # keyed by public key
  desired := for d in proven: (d.wg_pk, allowed_ips(d), endpoint(d), keepalive(d))
  case mode:
    observe:  report(actual − desired.keys, desired.keys − actual)
    owner:    if keys(actual) ≠ keys(desired) or any allowed_ips differ:
                wg.ConfigureDevice(iface, {ReplacePeers: true, Peers: desired})
              else if endpoints changed: ConfigureDevice({Peers: changed, UpdateOnly: true})
    watchdog: for k in keys(actual) − keys(desired): ConfigureDevice({Peers: [{k, Remove: true}]})
              fight-detect(k)
  write /run/norn/proven.json and /run/norn/reconcile.json (for other tools / the monitor)
```

Idempotent; safe to run twice; reconcile latency is to be logged as a histogram
(`norn_reconcile_seconds`, not implemented) so the watchdog window is a measured
number, not a claim.

**Implemented, and what is not.** The `case mode` block is `reconcile.Decide`, a
pure function, and `reconcile.Apply`, which does the writes; fight detection is
`agent.noteEvictions`. The last line is half done:
`nornd` writes `proven.json` (§9), its proof bundles and a mirror under its
run directory (default `/run/norn`), but **`reconcile.json` is not
implemented**, and neither is `norn_reconcile_seconds` or any other metric
(`GOSSIP.md` §9): `nornd` exposes no metrics endpoint. The watchdog window is
therefore not measured. The cycle is not the loop above either: `nornd` runs
`agent.Once` every `T_poll`, and each cycle fetches and replays the log, asks
peers if the log failed or the view is stale, polls peers for fork evidence
at most once per T_g, and only then reconciles (SEC-003, SEC-013). There is no
separate trigger on a proven-set change, and no alarm when a cycle overruns
`T_poll`.

Swap attack check (A1): the control plane installs the attacker's key with the
legit device's allowed-ips and removes the legit key. Owner mode: desired still
contains the legit key → `ReplacePeers` evicts the attacker and restores the legit
peer with its last known endpoint. Watchdog mode: attacker evicted within the
watchdog window (§3);
legit peer stays absent until the control plane restores it (availability is the
control plane's, not Norn's — G4 non-goal).

## 5. Endpoint providers (owner mode only)

Keys come from the log. Endpoints, allowed-ips and keepalives come from a provider,
which is deliberately *untrusted for keys*:

| Provider | Source | Notes |
|---|---|---|
| `static` | `[[peer]]` blocks in `nornd.toml` keyed by `device_id` | homelab default; a `wg-quick` file with only `[Interface]` plus Norn is a complete setup. Implemented (`Config.Static`) |
| `labels` | `labels.allowed_ips`, `labels.endpoint`, `labels.keepalive` in the `enroll` entry | advisory hints signed by a signer; good enough for static-IP labs. Implemented (`endpoint.Labels`) |
| `file` | a JSON file some other daemon writes | escape hatch for any control plane. Implemented (`hints_file`, `endpoint.LoadFile`) |
| `netbird` / `headscale` | adapter reading the control plane's view (Phase 7) | control plane becomes an endpoint directory. **Not implemented** |

`nornd` asks them in that order of precedence: `static`, then `file`, then
`labels` (`providerFor`). The `labels` provider reads `allowed_ips`, while
`SPEC.md` §4.0, D-026, the fixture, the `cmd/norn` tests and `ENROLLMENT.md`
§3 use the label `ip`; a device enrolled with `ip` alone is installed with no
allowed-ips and reported unrouted (SEC-018). Which name is canonical is
decision D-f (`docs/audit/ROADMAP.md`).

## 6. Integration matrix (honest)

"Norn today" is what the code does on 2026-09-30. Every mode in it reaches the
interface through `wgctrl`, and none has yet run against the system in its row
(see the status note at the top).

| System | Data plane | Who writes peers | Norn today | Path to real enforcement |
|---|---|---|---|---|
| Plain WireGuard / `wg-quick` | kernel | static config | **owner** designed for it; observe, owner and watchdog implemented, not yet run on a real interface | the Phase 3 lab gates, after SEC-012 (own key) and SEC-018/019 (label name, CIDR form) — Norn is then the peer config |
| innernet | kernel | innernet daemon | observe; watchdog expected to flap (untested) | Phase 3: check if innernet can run with peer management off; else upstream hook |
| NetBird — Linux | kernel (preferred) | NetBird engine, re-syncs on updates | observe; watchdog expected to flap (untested) | **Phase 7: upstream PR — a peer-admission hook in the engine** (`AdmitPeer(pubkey) bool`). NetBird is Go and open; this is a credible, high-visibility contribution |
| NetBird — macOS / Windows | wireguard-go via UAPI | same | observe / watchdog via the UAPI socket (untested) | same PR |
| Tailscale / Headscale | wireguard-go inside tailscaled, no UAPI | tailscaled | **nothing: not implemented.** Planned, observe only and event-driven: `client/local` `WatchIPNBus(NotifyPeerWireGuardState)` + `status --json` peer keys diffed against `proven` (D-014; `PLAN.md` Phase 3, "Tailscale observe", not started). It would be a second source of truth, not a `wgctrl` backend: `tailscaled` has no UAPI socket (§2) | none without patching tailscaled — which is exactly what Tailnet Lock is. Norn's value here would be *independent detection* of a control plane the operator doesn't trust (Headscale #1432) |
| Windows WireGuardNT | kernel | whoever | owner / watchdog (untested) | verify ioctl write path in Phase 3 |
| Nebula, ZeroTier, OpenZiti | not WireGuard | — | out of scope | — |

## 7. Defence in depth on Linux (optional, never sufficient alone)

**Planned, not implemented:** no code in the repository touches nftables.

`nornd` could maintain an nftables set `norn_proven_src` of the allowed-ips of proven
peers and a rule `iifname wg0 ip saddr != @norn_proven_src drop`. It would cut the
watchdog window for *new* rogue IPs to zero, but is **blind to the swap attack**
(same IP, different key) — so it is an add-on, and the README must say so when it
ships.

## 8. Failure semantics

Rows without a letter are the design. The code does what they say, except the
design's fork row: row (a) is what a frozen node actually does. Rows with a
letter are what the code does on 2026-09-30 where the design is wrong or
silent; the notes below the table explain each one and name the finding.

| Event | Owner | Watchdog | Observe |
|---|---|---|---|
| `nornd` crashes | table keeps last written proven set; no new peers appear until restart | control plane keeps adding; window becomes ∞ → the monitor alarms on missing heartbeat | alarms stop → monitor alarms |
| checkpoint stale > S (`degraded`) | keep last proven set; alarm | same | alarm |
| stale > S_hard (opt-in) | `ReplacePeers` with empty set — fail closed | evict all | — |
| fork detected (design) | freeze at last proven set; alarm; refuse new state | same | alarm |
| trust file missing/invalid | refuse to start | refuse to start | refuse to start |
| fork detected (code) (a) | table left exactly as it is: nothing an external writer adds is removed | **stops evicting** — not "same" | `FORK` once, then `FROZEN_BY_FORK` every cycle; no `UNPROVEN_PEER` |
| `nornd` restarts while the log is unreachable (b) | table left as it is until a state verifies | nothing evicted until then | no `UNPROVEN_PEER` until then |
| a proven peer accepts connections and never answers (c) | the rewrite waits on the peer reads | the eviction window grows by the peer reads | alarms wait on the peer reads |

**(a) A frozen node stops enforcing (SEC-021, open).** While frozen, every cycle
stops before it verifies or reconciles (`Agent.Once`), in every mode. The freeze
is the evidence file under `<run dir>/fork/`, so it is lost at reboot with the
default `/run/norn` (SEC-006, open); and when no evidence file can be built or
checked — a head signed only by a log key rotated in after the trust file
(SEC-005 (b), open) — the node is frozen in memory only and a restart
unfreezes it.

**(b) A restart forgets what the node verified (SEC-004, open).** The stored
checkpoint, held tree, witness clock and replayed keys and policy live in memory
only. While the log stays unreachable, every cycle ends `NO_STATE_YET` before it
reconciles, and peers cannot carry the node, because `Agent.PeerAddresses` is
empty until a state has verified. When a head is served again, the first
correctly signed, quorum-cosigned one is accepted however old, with no rollback
check, and its quorum time becomes the node's "now", so it reads `fresh`; owner
mode then reinstalls a device revoked since. The only signal is `CLOCK_SKEW`, if
that head is more than Δclock behind the wall clock. A fork freeze is reloaded
only if the run directory survived: a process restart keeps it, a host reboot
clears the default `/run/norn` (SEC-006). The fix is `docs/audit/ROADMAP.md`
task 2.

**(c) A silent peer is bounded, not avoided (SEC-003, bounded).** Every read
from a peer gives up after 10 s (`gossip.FetchTimeout`, since `4f7732d`). A
cycle asks up to r peers for fork evidence, at most once per T_g, and, when the
log failed or the view is stale, up to r for a checkpoint — all before it
reconciles. So a cycle can run up to r × 10 s longer for each of those two
rounds, and a peer that answers each read just inside the deadline costs 10 s
per file fetched from it. No alarm reports the overrun; a silent peer asked for
evidence is not reported at all, and one asked for a checkpoint is reported as
`PEER_REFUSED`. Reconciling before peer I/O, and a cycle-overrun alarm, are open
(`docs/audit/ROADMAP.md` task 1).

The alarms in these rows are log lines. `FORK`, `FROZEN_BY_FORK`, `DEGRADED`,
`HARD_STALE`, `CLOCK_SKEW` and `NO_STATE_YET` are logged at INFO; the warnings
are `UNPROVEN_PEER`, `EVICTED_PEER`, `VERIFY_FAILED`,
`ENFORCING_ON_STALE_STATE`, `INTERFACE_UNAVAILABLE` and the fight and quarantine
events (`report` in `cmd/nornd/main.go`; SEC-021, SEC-033).

## 9. Interface between verifier and enforcer (→ SPEC §14)

In-process (nornd embeds the verifier). Also serialised to `/run/norn/proven.json`,
which is how everything *else* finds out — the monitor, Home Assistant, a support
bundle, an operator with `jq`:

```
{ "version": 1,
  "checkpoint": {"origin": …, "size": N, "root": "<hex>", "cosigned_at": null},
  "freshness": "fresh" | "degraded" | "hard_stale" | "unknown",
  "age_seconds": null,
  "devices": [ {"device_id": "…", "wg_pk": "<b64>", "labels": {…}, "expires": 0,
                "proof": "proofs/<device_id>.bundle", "since_index": N} … ],
  "written_at_local_clock": T }
```

This is what `internal/proven` writes (`proven.Set`); `age_seconds` is the
view's age in witness time, `null` when there is no witness clock. Nothing in
the repository reads the file yet: `norn monitor` reads a node through its
gossip endpoints (`GOSSIP.md` §6), which serve the mirror and fork evidence and
not `proven.json`.

Three things this schema is careful about, each of them a number somebody would
otherwise act on:

- **`freshness` is a state, not a boolean.** Witness time is the clock (part 5 of
  `GOSSIP.md`), so with no cosignature there is no clock: the state is `unknown`
  and a consumer must handle it. A `"degraded": false` would assert that all is
  well, which is not something a node without witness time can know.
- **`cosigned_at` is `null` until a witness cosigns**, and `written_at_local_clock`
  is named for what it is. The local clock is good for noticing a stopped daemon
  and for nothing else (A11).
- **Every `proof` names a bundle that is actually written**, beside the file, and
  each one is checkable by someone holding only `norn.trust` (§8) — until the
  roots rotate the log key: a bundle whose checkpoint the new key signed is one
  a reader holding only the trust file must refuse
  (`testdata/vectors/served-rotated/cases.json`). A `proof` field
  pointing at nothing would be worse than no field: an alarm would cite evidence
  that does not exist.

The file is replaced atomically, because it is rewritten while something else is
reading it. It is rewritten only after a cycle whose verification succeeded: a
cycle that holds the interface to its last good state because the log and the
peers failed, and every cycle of a frozen node, leave the previous file in
place, `freshness` included (SEC-033). A consumer that sees `"fresh"` should
also check `written_at_local_clock`.

## 10. Phase 3 measurement plan

Planned. None of these has run, and the lab they need does not exist yet
(`LAB.md`; there is no `lab/` directory and no `make` target for it).

1. Watchdog window: script adds a rogue key with `wg set`, starts a handshake from
   it, records time-to-eviction and whether any data packet crossed. 1 000 runs,
   report p50/p99. Gate: p99 < 1 s at `T_poll` = 200 ms.
2. Owner-mode divergence: 24 h soak with a chaos script writing random peers every
   5–30 s; continuous diff must show zero divergence lasting > `T_poll`.
3. Flap test against a real NetBird management server (lab): measure fight
   detection and confirm `quarantine` actually isolates.
4. Poll cost: CPU of `nornd` at 200 ms polling with 1, 100, 1 000 peers.
