# Norn

**Certificate Transparency for your WireGuard peer table.**

> Every mesh VPN trusts a coordination server that can hand your laptop an
> attacker's key — and you would never know. Norn puts every device enrollment,
> rotation and revocation in an append-only, witnessed log, and refuses any peer
> that isn't in it. Works beside Headscale, NetBird or plain `wg-quick`. Changes
> nothing in WireGuard.

*Status (2026-09-20): 49 Go packages, 630 tests, a frozen `SPEC.md`, and a
vector suite a second implementer can use without this repository. **14 of 38
gate lines** in `PLAN.md` are ticked — every gate that needs a running lab, a
measurement or a second pair of eyes is still open. No Norn has ever guarded a
network anyone depends on.*

<!-- demo GIFs: D1a owner · D1b watchdog · D1c observe (see LAB.md §2) -->

## Try it

Offline, against the vectors in this repository. No network, no daemon, no
trust in whoever handed you the files.

```console
$ go build -o norn ./cmd/norn
$ ./norn verify -trust testdata/vectors/trust.cbor -log testdata/vectors/served
network    norn-testnet
anchor     YV05-H4J9-MA1G-P8V2
size       90 entries
...
9 device(s), 6 active:
```

That replayed a log from its genesis, checked a witness quorum cosigned its
checkpoint, and printed the only set of peers a node would install.

Now the interesting half — catching a log that signed two different histories:

```console
$ ./norn verify-evidence -trust testdata/vectors/trust.cbor testdata/vectors/fork/evidence.cbor
FORK PROVEN
...
at size     41 entries
...
Witnesses that were meant to prevent it: [pi vps friend]
```

Nothing in that check needed the network to be running, or the accuser to be
trusted. That is the whole point: **no peer without proof**, and no accusation
without proof either.

## What Norn is

An append-only log of every device key your network ever authorised, cosigned
by witnesses in places the log operator does not control, replayed from genesis
by every node, and reconciled against the kernel's WireGuard peer table.

1. A **signer** enrolls a device: a signed entry goes into a **transparency log**.
2. **Witnesses** (k-of-N, in independent places) cosign each log checkpoint.
3. Every **node** replays the whole log, verifies the witness quorum, and installs
   **only proven keys** in its WireGuard peer table.
4. Nodes **gossip checkpoints to each other over the tunnel**, so a control plane
   that lies or stalls is detected and routed around.

Certificate Transparency fixed the identical problem for the web PKI in 2013:
don't stop CAs from issuing — make every issuance public and let anyone check.

## Who this is not for

- **You want a VPN.** Norn is not one. It needs WireGuard, and something to do
  NAT traversal and endpoint discovery; keep your coordination server.
- **You need the network up more than you need it correct.** Norn's failure
  direction is to refuse peers it cannot prove. A log outage plus a strict
  policy is an outage.
- **You cannot provision trust out of band.** There is no trust-on-first-use.
  A node that was not handed `norn.trust` through a channel you trust gets
  nothing from Norn (G6).
- **Your membership list is a secret.** Device names, enrollment times and key
  fingerprints are visible to anyone who can read the log.
- **You run at internet scale.** The design target is tens to low thousands of
  devices, not a public directory.

## Threat model in one screen

The six guarantees, and what each one actually rests on. The long version, with
twelve adversaries, is `THREAT-MODEL.md`.

| | Guarantee | Rests on |
|---|---|---|
| **G1** | Every peer in the table has an inclusion proof under a checkpoint the node accepted, and replays to `active`. | correct verifier · intact `norn.trust` · fewer than k faulty witnesses |
| **G2** | Two honest nodes never accept incompatible histories; a fork yields non-repudiable proof and is held forever. | fewer than k witnesses colluding with the log · Ed25519 + SHA-256 |
| **G3** | The log can publish garbage; it cannot grant access. Replay admits only entries valid under the signer state at that point. | signer keys not compromised |
| **G4** | A node on a stale checkpoint goes `degraded` and alarms; a revocation lands within a bounded window or somebody is told. | one honest path to a fresh checkpoint — the log **or** a peer |
| **G5** | Every accepted key traces to an entry signed by an identifiable signer. | a monitor exists and runs |
| **G6** | A node never trusts a log, witness set or genesis it was not provisioned with. | an out-of-band channel |

**What Norn never defends:** availability under a hostile control plane, log or
witness set · a stolen WireGuard private key before it is revoked · a log and a
witness quorum colluding · the channel that delivers `norn.trust` · the privacy
of the log's contents · what authorised peers then do to each other.

Enforcement is staged, and the weakest mode is the default: **observe** (report
only) → **watchdog** (reconcile a control plane's table, window ≤ `T_poll`) →
**owner** (Norn writes the table; a rogue peer is never added). See
`ENFORCEMENT.md`.

## How Norn compares

| | Tailnet Lock | Nebula | NetBird | **Norn** |
|---|---|---|---|---|
| Can the control plane add a device you never approved? | no, while it is on | no — only the offline CA can | yes | no |
| Is there a record of **every key ever authorised**? | no — the chain records who may *sign*, not what was signed | no | no | yes, append-only |
| Can a third party check that record without being trusted? | — | — | — | yes — witnessed checkpoints, replayable by anyone |
| A signing key is stolen. Afterwards, can you enumerate what it signed? | no | no | no | yes — `norn audit --by` |
| Control plane goes silent or withholds updates | acknowledged freeze attack | certs keep working until they expire | undetected | nodes gossip checkpoints over the tunnel; staleness alarms |
| Revocation | via the control plane | `pki.blocklist`, shipped in config | via the control plane | a logged entry, with a bounded window and an alarm if it is missed |
| Runs beside your existing stack | Tailscale only | Nebula only | NetBird only | Headscale, NetBird, innernet or `wg-quick`, unpatched |
| Would I run it on something that matters today? | yes, it is GA | yes | yes | **no** — see the status line above |

Sources and the longer argument are in `PRIOR-ART.md`. This table has not yet
been reviewed by anyone who has run two of these in anger; that gate is open.

## Documents

| File | What |
|---|---|
| `PLAN.md` | phases, gates, fixed decisions |
| `PRIOR-ART.md` | why this doesn't exist yet |
| `THREAT-MODEL.md` | 12 adversaries, 6 guarantees, what Norn does *not* defend |
| `LEDGER-OPTIONS.md` | do we need a blockchain? (scored; answer: 32 bytes of one, optionally) |
| `SPEC.md` | entries, replay, log layout, receipts, proofs, trust file — frozen at v1 |
| `ENFORCEMENT.md` | observe / owner / watchdog modes; integration matrix |
| `GOSSIP.md` | witnesses, freshness, peer gossip, split-view tests |
| `ENROLLMENT.md` | keys, ceremony, QR enrollment, recovery runbooks |
| `LAB.md` | lab topology, attack demos, monitor |
| `PUBLICATION.md` | how this reaches other people |
| `DECISIONS.md` | every decision, with what was rejected |
| `BUILD-LOG.md` | what was built, in order, and what each step got wrong first |

Interoperability is not claimed on my say-so: `testdata/vectors/` carries three
provenances, including bytes produced by `transparency-dev/witness` and by
`python-opentimestamps`, and `make vectors-check` verifies them.

## Non-goals
Not a VPN · not a coordination server · not availability protection · not internet-scale · not a blockchain.

## License
Apache-2.0
