# Try Norn from a clean checkout

Use Go matching `go.mod` and run these commands from the repository root.
The first three stages need no network, root or WireGuard interface.
Go's dependencies must already be cached to build offline; a fresh Go install
needs to download them first. The shipped trust file is for these fixtures,
not your mesh.

Every shell block marked `test` runs in an offline test. Blocks marked `U1`
need a real node and are yours to run.

## Build the binaries

Build the operator CLI and the node daemon. There is no `make build` target.

<!-- run: test -->
```sh
go build -o norn ./cmd/norn
go build -o nornd ./cmd/nornd
printf 'Built norn and nornd\n'
```

Expect: `Built norn and nornd`.

## Offline verification

Replay the served log from its pinned genesis and check its witnessed checkpoint.
The fixture deliberately includes rejected entries; they do not grant peers.

<!-- run: test -->
```sh
./norn verify -trust testdata/vectors/trust.cbor -log testdata/vectors/served
```

Expect: `network    norn-testnet`, `size       162 entries` and `13 device(s), 8 active:`.

Check the shipped proof bundles, including `testdata/vectors/proofs/nas.bundle`.
There is no CLI command for a standalone bundle; this existing vector test
checks the bundles against the trust file and joins them to the replayed keys.
The NAS bundle proves its enrollment; replay supplies its later rotated key.

<!-- run: test -->
```sh
go test -count=1 -v ./internal/proof -run '^TestTheInstalledKeyIsTheReplayedOneNotTheBundles$'
```

Expect: `--- PASS: TestTheInstalledKeyIsTheReplayedOneNotTheBundles` and `PASS`.

Now check an accusation against the trust file alone. The log signed two
different trees at the same size, and a witness quorum cosigned both.

<!-- run: test -->
```sh
./norn verify-evidence -trust testdata/vectors/trust.cbor testdata/vectors/fork/evidence.cbor
```

Expect: `FORK PROVEN`, `at size     41 entries` and `Witnesses that were meant to prevent it: [pi vps friend]`.

## The simulation

Run real agents with fake peer tables and an in-memory network through the
T1–T7 scenarios. No socket is bound. This took about 11 seconds on the lane's
Mac; it is run in the page's test too.

<!-- run: test -->
```sh
make lab-sim
```

Expect: `T1 nas evidence`, `T1b node3 evidence`, `T2 laptop adoption latency:`, `T3 node2 under-quorum B refusal latency:`, `T4 all-node replay refusal latency:`, `T5 node2 CLOCK_SKEW latency:`, `T6 all-node degraded latency:` and `T7 nas eviction latency:`.
Expect: `Simulated time proves code ordering and bounds; it does not replace the lab's wall-clock measurements.`

The latency lines go to stdout. Only T7 saves a result file:
`t7.json` in `LAB_SIM_RESULTS`, which defaults to `${TMPDIR:-/tmp}/norn-lab-sim`.
It records eviction latencies and their bound in nanoseconds, plus the
simulated-time caveat. Set `LAB_SIM_RESULTS` to a directory outside the
checkout to keep a separate run. These are not measurements of a real mesh.

## An observe-mode node

The daemon can read the served directory offline, but it has no fake-interface
backend: starting a node still needs a real WireGuard interface or tailscaled.
Stop here without one; [OBSERVE.md](OBSERVE.md) covers the real node and U1.

On a machine with an existing `wg0` and permission to read it, this runs one
observe cycle against the fixtures. This block is U1 because the offline test
has no real interface or permission to read its peer table. Replace `wg0`
with your interface name. It compares real peers with fixture keys, so reports
of unproven or missing peers are expected; this does not verify your mesh.

<!-- run: U1 -->
```sh
trial=$(mktemp -d)
./nornd -once -mode observe -iface wg0 -gossip-port 0 \
  -trust testdata/vectors/trust.cbor -log testdata/vectors/served \
  -run-dir "$trial/run" -state-dir "$trial/state"
```

Startup should say observe mode and that the node will write nothing to the
peer table. Gossip is disabled; publication and saved state stay under the
temporary directory. For your mesh, follow `OBSERVE.md` with your site's
out-of-band trust file, read the alarms and watch one node for a day before
the seven-day U1 trial. No real-node trial is claimed here.
