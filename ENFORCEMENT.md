# Norn — Enforcement Layer

Written **2026-09-18** (plan part 5). This document is **informative**: how
`nornd` turns the proven set into a refused handshake, as deployment and
measurement context. `SPEC.md` §§8.1 and 13 own the node's enforcement contract;
where this document disagrees with `SPEC.md`, the SPEC and the implemented node
win.

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
interface's private key, listen port or fwmark.

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
  Owner rewrites carry through each kept peer's existing preshared key, which
  the log does not manage.
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
- Two proven devices whose provider-supplied allowed-ips overlap get neither
  overlapping prefix, and the pair is reported (`PROVIDER_CLAIM`): WireGuard routes
  to the most specific prefix, so an overlap would hand one device's addresses to
  another, and nothing in the log decided that. Each device keeps its other routes.
- Norn never deliberately writes a rogue key. An external writer's change is
  corrected on the next cycle; the window depends on polling and reconfiguration.

### enforce / watchdog
Someone else (NetBird, innernet, a human) owns the table; `nornd` polices it.

- Every `T_poll`: for each `actual` key ∉ `proven` → `PeerConfig{Remove: true}`,
  alarm `EVICTED_PEER`. A proven device the table does **not** carry raises
  `MISSING_PEER` and nothing else: installing it is the table owner's job, not
  Norn's (G4 non-goal), and the difference between "reported" and "installed"
  is the whole distinction between watchdog and owner mode.
- Window: ≤ `T_poll` + reconfigure latency. A handshake and a few packets can
  complete inside it. Measured in the Phase 3 gate; documented in every README.
- **Fight detection.** If the same key is evicted `N` times within `W` (default 3
  in 60 s) the control-plane daemon is re-adding it: alarm `CONTROL_PLANE_FIGHT`
  and apply the configured fight policy:
  - `alarm` (default) — keep evicting, keep alarming;
  - `quarantine` — bring the interface down (`ip link set … down`) until an
    operator intervenes. Fail-closed by choice, never by default.

## 4. Reconciler (pseudocode; the normative modes are `SPEC.md` §13.1)

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
  after a verified cycle, publish /run/norn/proven.json and its proof bundles
```

Idempotent; safe to run twice. Reconcile latency measurement remains in the
Phase 3 plan (§10); the current node does not publish a `reconcile.json` file
or the `norn_reconcile_seconds` histogram.

Swap attack check (A1): the control plane installs the attacker's key with the
legit device's allowed-ips and removes the legit key. Owner mode: desired still
contains the legit key → `ReplacePeers` evicts the attacker and restores the legit
peer with its last known endpoint. Watchdog mode: attacker evicted within `T_poll`;
legit peer stays absent until the control plane restores it (availability is the
control plane's, not Norn's — G4 non-goal).

## 5. Endpoint providers (owner mode only)

Keys come from the log. Endpoints, allowed-ips and keepalives come from a provider,
which is deliberately *untrusted for keys*:

| Provider | Source | Notes |
|---|---|---|
| `static` | `[[peer]]` blocks in `nornd.toml` keyed by `device_id` | homelab default; a `wg-quick` file with only `[Interface]` plus Norn is a complete setup |
| `labels` | `labels.ip`, `labels.endpoint` in the `enroll` entry | advisory hints signed by a signer; good enough for static-IP labs |
| `file` | a JSON file some other daemon writes | escape hatch for any control plane |
| `netbird` / `headscale` | adapter reading the control plane's view (Phase 7) | control plane becomes an endpoint directory |

## 6. Integration matrix (honest)

| System | Data plane | Who writes peers | Norn today | Path to real enforcement |
|---|---|---|---|---|
| Plain WireGuard / `wg-quick` | kernel | static config | **owner** | done — Norn *is* the peer config |
| innernet | kernel | innernet daemon | observe; watchdog flaps | Phase 3: check if innernet can run with peer management off; else upstream hook |
| NetBird — Linux | kernel (preferred) | NetBird engine, re-syncs on updates | observe; watchdog **will flap** | **Phase 7: upstream PR — a peer-admission hook in the engine** (`AdmitPeer(pubkey) bool`). NetBird is Go and open; this is a credible, high-visibility contribution |
| NetBird — macOS / Windows | wireguard-go via UAPI | same | observe / watchdog via UAPI socket | same PR |
| Tailscale / Headscale | wireguard-go inside tailscaled, no UAPI | tailscaled | **observe only**, event-driven: `client/local` `WatchIPNBus(NotifyPeerWireGuardState)` + `status --json` peer keys diffed against `proven` | none without patching tailscaled — which is exactly what Tailnet Lock is. Norn's value here is *independent detection* of a control plane the operator doesn't trust (Headscale #1432) |
| Windows WireGuardNT | kernel | whoever | owner / watchdog | verify ioctl write path in Phase 3 |
| Nebula, ZeroTier, OpenZiti | not WireGuard | — | out of scope | — |

## 7. Defence in depth on Linux (optional, never sufficient alone)

`nornd` can maintain an nftables set `norn_proven_src` of the allowed-ips of proven
peers and a rule `iifname wg0 ip saddr != @norn_proven_src drop`. It cuts the
watchdog window for *new* rogue IPs to zero, but is **blind to the swap attack**
(same IP, different key) — so it is an add-on, and the README says so.

## 8. Failure semantics

| Event | Owner | Watchdog | Observe |
|---|---|---|---|
| `nornd` crashes | table keeps last written proven set; no new peers appear until restart; the restarted node holds its stored head and any fork freeze again (D-069) | control plane keeps adding; window becomes ∞ → the monitor alarms on missing heartbeat | alarms stop → monitor alarms |
| host reboots | the stored head and any fork freeze are read back from `state_dir` (default `/var/lib/norn`, never `/run`, which a reboot clears — D-069); the restored head is compared against, not enforced, until a checkpoint verifies; `nornd` warns at start if `state_dir` is unwritable or on a tmpfs | same | same |
| checkpoint stale > S (`degraded`) | keep last proven set; alarm | same | alarm |
| stale > S_hard (opt-in) | `ReplacePeers` with empty set — fail closed | evict all | — |
| fork detected | freeze at last proven set; alarm; refuse new state | same | alarm |
| trust file missing/invalid | refuse to start | refuse to start | refuse to start |

## 9. Interface between verifier and enforcer (→ `SPEC.md` §13.3)

In-process (nornd embeds the verifier). Also serialised to `/run/norn/proven.json`,
which is how everything *else* finds out — the monitor, Home Assistant, a support
bundle, an operator with `jq`:

```
{ "version": 1,
  "checkpoint": {"origin": …, "size": N, "root": "<hex>", "cosigned_at": null},
  "freshness": "fresh" | "degraded" | "hard_stale" | "unknown",
  "age_seconds": 0 | null,
  "devices": [ {"device_id": "…", "wg_pk": "<b64>", "labels": {…}, "expires": 0,
                "proof": "proofs/<device_id>.bundle", "since_index": N} … ],
  "written_at_local_clock": T }
```

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
  each one is checkable by someone holding only `norn.trust` (§8). A `proof` field
  pointing at nothing would be worse than no field: an alarm would cite evidence
  that does not exist.

The file is replaced atomically after a verified cycle, because something else
may read it during a write. An empty device set and empty labels are JSON
arrays and objects, respectively, not `null`.

## 10. Phase 3 measurement plan

1. Watchdog window: script adds a rogue key with `wg set`, starts a handshake from
   it, records time-to-eviction and whether any data packet crossed. 1 000 runs,
   report p50/p99. Gate: p99 < 1 s at `T_poll` = 200 ms.
2. Owner-mode divergence: 24 h soak with a chaos script writing random peers every
   5–30 s; continuous diff must show zero divergence lasting > `T_poll`.
3. Flap test against a real NetBird management server (lab): measure fight
   detection and confirm `quarantine` actually isolates.
4. Poll cost: CPU of `nornd` at 200 ms polling with 1, 100, 1 000 peers.
