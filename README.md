# Norn

**Certificate Transparency for your WireGuard peer table.**

> Every mesh VPN trusts a coordination server that can hand your laptop an
> attacker's key — and you would never know. Norn puts every device enrollment,
> rotation and revocation in an append-only, witnessed log, reports any peer
> that isn't in it, and — once you switch enforcement on — removes it. Built to
> sit beside plain `wg-quick` or NetBird; Headscale is planned, observe-only.
> Changes nothing in WireGuard.

*Status (2026-09-30): 49 Go packages, 774 tests, a frozen `SPEC.md`, and a
vector suite a second implementer can use without this repository. **9 of 38
gate lines** in `PLAN.md` are ticked — every gate that needs a running lab, a
measurement or a second pair of eyes is still open. The latest cold-model run
on the spec (13) returned `SPEC SUFFICIENT WITH GAPS` (`SPEC-DEFECTS-13.md`).
A security audit (`docs/audit/`) found two CRITICAL and two HIGH issues, and
none is closed: one is bounded, one documented rather than fixed, two open. No
Norn has ever guarded a network anyone depends on.*

<!-- demo GIFs: D1a owner · D1b watchdog · D1c observe (see LAB.md §2) -->

## Try it

Offline, against the vectors in this repository. No network, no daemon, no
trust in whoever handed you the files.

```console
$ go build -o norn ./cmd/norn
$ ./norn verify -trust testdata/vectors/trust.cbor -log testdata/vectors/served
network    norn-testnet
anchor     Y2KM-WGEJ-5GCD-X3HA
size       130 entries
...
11 device(s), 6 active:
...
88 entr(ies) rejected:
```

That replayed a log from its genesis, checked that a witness quorum cosigned
its checkpoint, and printed each device's replay status — `*` marks the
`active` ones — and how many entries were refused, by reason. That is not
quite the set a node installs: `nornd` also drops an `active` device whose
expiry the checkpoint's witness time has passed (`internal/proven`), and here
the two agree only because the one device with an expiry, `contractor`, has not
reached it at this checkpoint's witness time. In the default observe mode a
node installs nothing; it reports.

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
3. Every **node** replays the whole log, verifies the witness quorum, and — in
   owner mode — installs **only proven keys** in its WireGuard peer table.
   Watchdog mode evicts anything else a control plane adds; observe mode, the
   default, reports it.
4. Nodes **serve checkpoints to each other over the tunnel**, and a node whose
   log fails or goes stale asks its peers, so a log that stalls is routed
   around — by a node that has verified a state since it started, since that
   state is where it learns its peers' addresses (SEC-004). Today a node asks only then: `GOSSIP.md`'s fixed cadence, which
   would let fresh nodes catch a split view that colluding witnesses cosigned,
   is not implemented (SEC-002; decision D-c).

Certificate Transparency fixed the identical problem for the web PKI in 2013:
don't stop CAs from issuing — make every issuance public and let anyone check.

## Who this is not for

- **You want a VPN.** Norn is not one. It needs WireGuard, and something to do
  NAT traversal and endpoint discovery; keep your coordination server.
- **You need the network up more than you need it correct.** Norn's failure
  direction is to refuse peers it cannot prove. A node that has no verified
  state, or whose view is older than the `S_hard` it opted into, admits
  nobody new until the log or a peer answers.
- **You need to revoke or rotate a key today.** Replay applies `revoke`,
  `rotate` and the governance entries, but the CLI builds only `genesis`
  (`norn init`) and `enroll`; the other builders are not written (SEC-008).
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
| **G1** | In owner mode, every peer in the table has an inclusion proof under a checkpoint the node accepted, and replays to `active`. Watchdog mode holds it once a cycle has evicted what a control plane added; observe mode, the default, only reports. | correct verifier · intact `norn.trust` · fewer than k faulty witnesses |
| **G2** | Two honest nodes never accept incompatible histories; a fork yields non-repudiable proof and is held forever. | fewer than 2k−N witnesses colluding with the log — two k-of-N quorums need share only 2k−N, one for a 2-of-3 (SEC-002; decision D-b) · Ed25519 + SHA-256 |
| **G3** | The log can publish garbage; it cannot grant access. Replay admits only entries valid under the signer state at that point. | signer keys not compromised |
| **G4** | A node on a stale checkpoint goes `degraded` and alarms; a revocation lands within a bounded window or somebody is told — unless 2k−N colluding witnesses cosign a split view that withholds it, which stays fresh and raises nothing (SEC-002). | one honest path to a fresh checkpoint — the log **or** a peer |
| **G5** | Every accepted key traces to an entry signed by an identifiable signer. | a monitor exists and runs |
| **G6** | A node never trusts a log, witness set or genesis it was not provisioned with. | an out-of-band channel |

**What Norn never defends:** availability under a hostile control plane, log or
witness set · a stolen WireGuard private key before it is revoked · a log and a
witness quorum colluding · the channel that delivers `norn.trust` · the privacy
of the log's contents · what authorised peers then do to each other.

**Where the code falls short of this table today**, from the 2026-09-30 audit
(`docs/audit/SECURITY_AUDIT.md`):

- **G3.** An entry already in the log, re-submitted with one junk signature
  added, is a new entry to replay and applies again: a revoked device can come
  back, a raised witness policy can roll back. The log's `/add` asks for no
  credentials, so this needs no key (SEC-001). Documented, not fixed; whether
  and how to fix it is decision D-a.
- **G2 and G4 end at a restart.** A node holds its checkpoint in memory only,
  so a restarted `nornd` accepts whatever genuinely cosigned head it is served
  first, however old, as `fresh` (SEC-004), and its fork freeze lives under
  `/run/norn` by default, which a reboot clears (SEC-006).

Enforcement is staged, and the weakest mode is the default: **observe** (report
only) → **watchdog** (evict what a control plane adds to its table, once per
`T_poll` cycle; each cycle first fetches and replays the log and may wait on
silent peers, so the window is longer than `T_poll` and not yet measured —
SEC-003, SEC-013) → **owner** (Norn is the table's only writer; endpoints come
from a provider that has no way to name a key, `internal/endpoint`). See
`ENFORCEMENT.md`.

## How Norn compares

| | Tailnet Lock | Nebula | NetBird | **Norn** |
|---|---|---|---|---|
| Can the control plane add a device you never approved? | no, while it is on | no — only the offline CA can | yes | owner mode: no · watchdog: yes, until the next cycle evicts it · observe, the default: yes, and Norn raises `UNPROVEN_PEER` |
| Is there a record of **every key ever authorised**? | no — the chain records who may *sign*, not what was signed | no | no | yes, append-only |
| Can a third party check that record without being trusted? | — | — | — | yes — witnessed checkpoints, replayable by anyone |
| A signing key is stolen. Afterwards, can you enumerate what it signed? | no | no | no | yes — `norn audit --by` |
| Control plane goes silent or withholds updates | acknowledged freeze attack | certs keep working until they expire | undetected | a node whose log fails or goes stale asks its peers over the tunnel; staleness alarms |
| Revocation | via the control plane | `pki.blocklist`, shipped in config | via the control plane | a logged entry, with a bounded window and an alarm if it is missed — replay applies it, but no shipped tool builds one yet (SEC-008) |
| Runs beside your existing stack | Tailscale only | Nebula only | NetBird only | any interface `wgctrl` drives, unpatched: `wg-quick` (owner), or NetBird's or innernet's kernel interface (observe; watchdog is expected to fight their re-sync, `ENFORCEMENT.md` §6) — none yet run against the real stack. Headscale's clients (`tailscaled`) have no UAPI socket: planned, observe-only, not written |
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
| `SPEC-DEFECTS*.md` | the cold-model gate's reports: a fresh model, given only `SPEC.md` and the vectors, implements a verifier and says where the prose failed it |
| `docs/audit/` | the 2026-09-30 security audit, where the documents and the code disagree, and the roadmap with the decisions that are the maintainer's |

Interoperability is not claimed on my say-so. `testdata/vectors/` carries
three provenances: the Python reference in `contrib/norn-ref/`, this
repository's Go (`cmd/norn-genlog`, whose checkpoints and proofs are checked
with `transparency-dev/formats` and `x/mod/sumdb/tlog`), and
`python-opentimestamps`, which wrote `anchors/`. `make vectors-check`
regenerates the first two and diffs them against what is committed. An
unmodified `transparency-dev/witness` cosigning a Norn checkpoint is a test,
not a vector: `make witness` builds it, `internal/interop` runs it, and
without that build — in CI, for one — the test skips.

## Non-goals
Not a VPN · not a coordination server · not availability protection · not internet-scale · not a blockchain.

## License
Apache-2.0
