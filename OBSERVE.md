# Watch your WireGuard mesh with Norn for a week

Start with one node a day. Then watch all nodes for seven days (user row U1).
Observe reads the peer table and reports differences. It never writes that
table. Keep the coordination server and the VPN running.

## Install and start

Use Linux, Go matching `go.mod`, systemd and an existing WireGuard interface.
From this repository, build and install the CLI, daemon, example config and
unit. Installation and live-node commands are yours to run in U1.

<!-- run: U1 -->
```sh
go build -o norn ./cmd/norn
go build -o nornd ./cmd/nornd
sudo install -m 0755 norn nornd /usr/local/bin/
sudo install -d -m 0755 /etc/norn
sudo install -m 0644 contrib/nornd.toml.example /etc/norn/nornd.toml
sudo install -m 0644 contrib/systemd/nornd.service /etc/systemd/system/nornd.service
```

Get your site's `norn.trust` through a channel you trust. Save it here as
`norn.trust`. It pins the network, genesis, log key and witness policy.
Use your site's trust file for the mesh, not the vectors'. Set the interface
name and keep `mode = "observe"`. The unit's transient user gets only
`CAP_NET_ADMIN`, which reading netlink needs.

<!-- run: U1 -->
```sh
sudo install -m 0644 norn.trust /etc/norn/norn.trust
sudo vi /etc/norn/nornd.toml
sudo systemctl daemon-reload
sudo systemctl enable --now nornd.service
sudo journalctl -u nornd.service -f
```

Check startup says observe and compare the anchor fingerprint out of band.
Review alarms daily and route them to your ntfy in U1. Check the service
is running and fresh. State survives reboot in `/var/lib/norn`;
`/run/norn` holds the runtime publication.

For an offline check, these commands run in a test against the shipped vectors.

<!-- run: test -->
```sh
./norn verify -trust testdata/vectors/trust.cbor -log testdata/vectors/served
```

The second check should print `FORK PROVEN`.

<!-- run: test -->
```sh
./norn verify-evidence -trust testdata/vectors/trust.cbor testdata/vectors/fork/evidence.cbor
```

## Alarms

Events go to stderr; the unit puts them in the journal. Each carries `kind`
and a message; peer events include keys, routes and endpoints when known.
`MISSING_PEER` is INFO. Fork, hard-stale, no-quorum and quarantine events are
ERROR. The rest are WARN. This includes enforcement-only events. Observe
reports freshness and forks too, but leaves the table alone.

| Kind | What it means | What to do |
|---|---|---|
| `UNPROVEN_PEER` | A table key is outside the proven set. | Check enrollment, revocation and the control plane; investigate the key. |
| `MISSING_PEER` | A proven key is absent from the table. | Check connectivity with the control plane; this can be normal. |
| `EVICTED_PEER` | Watchdog successfully removed an unproven key. | Check why it was added; verify you intended watchdog mode. |
| `VERIFY_FAILED` | No usable head was obtained this cycle. | Read the reason; check the log, witnesses, trust file and reachability. |
| `NO_STATE_YET` | Nothing has verified since startup; the table is untouched. | Restore a verifiable log path before relying on Norn. |
| `ENFORCING_ON_STALE_STATE` | Verification failed; reconciliation uses the last verified set. | Restore the log or a proven peer path; check the view's age. |
| `CLOCK_SKEW` | Wall time differs too far from the direct-log witness estimate. | Fix the machine's clock; this alarm does not change freshness or peers. |
| `DEGRADED` | Witness-clock age exceeds the network's staleness limit. | Check cosigning and log or peer paths; it repeats every five minutes. |
| `FRESHNESS_UNKNOWN` | `quorum none` supplies no witness time. | Review the witness policy; age cannot be vouched for. |
| `NO_QUORUM` | An enforcing node's policy changed to no witnesses without local opt-in. | Restore a witnessed policy; a restart refuses enforcement without explicit opt-in. |
| `HARD_STALE` | Age crossed the optional local hard limit; enforcement drops all peers. | Restore freshness and review that limit; observe only reports it. |
| `MIRROR_FAILED` | The verified log copy could not be kept for peers or restart. | Check state-directory space and permissions. |
| `MIRROR_UNUSABLE` | The saved mirror failed verification at startup and was ignored. | Preserve it; check corruption and the trust file before restarting again. |
| `CLOCK_UNUSABLE` | The saved witness clock could not be read or written. | Fix state storage; a restart may underestimate age without that clock. |
| `FIRST_HEAD_UNCORROBORATED` | With no held head, no peer answered about the first verified head. | Restore a proven peer path; witness verification alone did not compare peer views. |
| `ADOPTED_FROM_PEER` | A verified peer head replaced an unusable or stale log view. | Check the direct log path; gossip supplied the view meanwhile. |
| `PEER_ROUND_CUT` | A gossip round used its budget before reaching every chosen peer. | Check slow peers and timeouts; do not remove the round's bound. |
| `PEER_REFUSED` | A peer's checkpoint or evidence could not be used. | Read the reason; inspect that peer's reachability and stored log. |
| `INTERFACE_UNAVAILABLE` | The interface key or peers could not be read. | Check the interface name, VPN and access permissions. |
| `INTERFACE_UNCONFIGURED` | The interface has no own public key yet. | Finish configuring the VPN; Norn treats all proven devices as peers meanwhile. |
| `PROVIDER_CLAIM` | Hints name unproven devices or give missing, overlapping or widened routes; a logged WireGuard key may also be unreadable. | Fix hints or investigate the device key; providers cannot grant authority. |
| `ROUTES_UNGRANTED` | A proven device has no enrollment route grant. | Ask a signer for the intended grant; hints cannot supply that authority. |
| `CONTROL_PLANE_FIGHT` | The same key returned after repeated successful watchdog evictions. | Fix the competing writer; review why it keeps adding that key. |
| `QUARANTINED` | The chosen fight policy took the interface out of service. | Resolve the fight, then restore the interface deliberately. |
| `QUARANTINE_FAILED` | The chosen quarantine action failed. | Check its command and permissions; do not assume the interface is down. |
| `FORK` | Locally checked evidence proves two signed histories. | Preserve `/var/lib/norn/fork`; contact log and witness operators and investigate. |
| `FROZEN_BY_FORK` | A previous fork freezes adoption; enforcement only shrinks the common proven set, or drops all if no prefix is established. | Preserve evidence; recovery needs an explicitly provisioned new trust file. |

Age uses witness time plus monotonic elapsed time, not the wall clock.
Gap 6.5l-ix-f-b-ii remains: off Linux, `nornd`'s monotonic reading does not count a suspend,
so a node that slept judges its view younger than it is. Linux counts suspend
with `CLOCK_BOOTTIME`.

## Metrics

`GET /metrics` serves Prometheus text on the tunnel's gossip listener (port
8100). `gossip_port = 0` disables both. Replace the example address with this
node's tunnel address; scrape it in U1.

<!-- run: U1 -->
```sh
curl --fail http://192.0.2.1:8100/metrics
```

Watch `norn_checkpoint_age_seconds`, `norn_state` and `norn_unproven_peers`.
Missing observations are `NaN`; unknown freshness has no state samples.
Counters reset on restart. [GOSSIP.md §9](GOSSIP.md#9-metrics) lists every family.

## Stop and remove

Stop, save the state and fork evidence, then remove the installation. These
commands assume Norn is used only for this trial. The VPN, peer table, backup
and original repository stay with you.

<!-- run: U1 -->
```sh
sudo systemctl disable --now nornd.service
sudo cp -aL /var/lib/norn "$HOME/norn-observe-state"
sudo rm -f /etc/systemd/system/nornd.service /usr/local/bin/norn /usr/local/bin/nornd
sudo rm -f /etc/norn/nornd.toml /etc/norn/norn.trust
sudo rmdir /etc/norn
sudo rm -rf /run/norn /var/lib/norn /var/lib/private/norn
sudo systemctl daemon-reload
rm -f ./norn ./nornd ./norn.trust
```
