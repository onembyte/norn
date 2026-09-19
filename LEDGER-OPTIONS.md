# Norn — Ledger Options: do we need a blockchain?

Written **2026-09-18** (plan part 3). Scores every architecture against the
adversaries in `THREAT-MODEL.md`. Ends with a decision (`DECISIONS.md` D-009).

## 0. The question, stated precisely

A blockchain is a machine for **ordering writes among parties who do not trust
each other**, at the cost of latency, liveness assumptions and operational weight.
Before choosing one, ask who Norn's writers are:

- **Signers** write entries. They are already trusted for *content* (a signer's
  signature is what makes an entry valid). They are few (1–10) and known.
- **The log operator** only orders and publishes. It is trusted for *nothing*.
- **Readers (nodes)** need one property from the ordering layer: that everyone
  sees the same history — **non-equivocation** — plus **liveness** (new entries
  actually reach them).

So the real question is: *what is the cheapest structure that gives non-equivocation
and liveness against A1 (control plane), A2 (log operator) and A9 (witness quorum),
for a network that must also work on a LAN with no internet?*

## 1. Candidates

| # | Architecture | Precedent |
|---|---|---|
| **O0** | Hash chain, gossip only, no witnesses | Tailscale Tailnet Lock |
| **O1** | One transparency log + k-of-N witnesses + peer gossip + submission receipts | CT (receipts = SCTs), Sigsum, Sunlight, Filippo's keyserver |
| **O2** | m-of-n **independent logs**; an entry counts when in ≥ m of them | Chrome CT policy (2 logs per cert) |
| **O3** | **Permissioned BFT chain** (CometBFT); validators = admin-run nodes; the chain *is* the log | Hyperledger, Cosmos app-chains |
| **O4** | O1 + **public-chain anchoring** of checkpoint hashes (OpenTimestamps → Bitcoin, or Stellar) | Keybase (Merkle root → Bitcoin 2014, → Stellar 2020), OpenTimestamps |
| **O5** | **On-chain registry**: entries live in a smart contract on a public L2 | ENS, Handshake, Namecoin (naming, not peers) |
| **O6** | **Hybrid**: O1 core, O4 as an optional *anchor witness*, documented upgrade path to O2 | — |

## 2. Scoring

Criteria come straight from the threat model. ✓ good · ~ partial · ✗ fails.
"Node verifies with" = what a node must run or trust to check a proof itself.

| Criterion | O0 | O1 | O2 | O3 | O4 | O5 | O6 |
|---|---|---|---|---|---|---|---|
| A2 split-view detected | ~ (fork rules only) | ✓ (< k witnesses) | ✓ | ✓ (< ⅓ validators) | ✓ | ✓ | ✓ |
| A2 withholding / freeze survivable | ✗ | ~ (detected; receipts prove it) | ✓ (another log) | ✓ (< ⅓ can't stall) | ~ | ✓ | ~/✓ |
| A1 freeze detected | ✗ | ✓ (gossip) | ✓ | ✓ | ✓ | ✓ | ✓ |
| A9 k witnesses + log collude | ✗ | ✗ (out of scope) | ~ (need all logs) | ✗ (= ⅓ validators) | **~ can't backdate history** | ✓ | ~ |
| Entry latency ≤ T_c (60 s) | ✓ | ✓ (ms) | ✓ | ✓ (s) | ✓ for validity; anchor lags hours | ~ (L2 ~2–10 s; L1 minutes) | ✓ |
| Works on LAN with no internet | ✓ | ✓ | ✓ | ✓ | ✓ (anchors just lag) | ✗ | ✓ |
| Node verifies with | chain replay | Ed25519 + SHA-256, no network | same | light client + a *trusted full node* for liveness | same as O1 (+ optional OTS verify) | **an RPC you trust, or a full/light node** | same as O1 |
| Ops for one admin | trivial | 1 log + 2–3 witness daemons | 2+ logs | 4+ always-on validators (liveness needs > ⅔) | O1 + a cron job | wallet, gas, RPC | O1 + cron |
| Dependency surface | none | none | none | CometBFT (large) | OTS calendars (optional) | chain + wallet + RPC | optional OTS |
| Privacy of entries | local | log readers | same | validators | **only 32-byte hashes leave** | ✗ public forever | same as O4 |
| Reuses existing witnesses/monitors | ✗ | ✓ | ✓ | ✗ | ✓ | ✗ | ✓ |
| Honest novelty vs. cargo cult | proven | proven, unglamorous | proven | "we used a blockchain" | proven (Keybase) | maximum blockchain, minimum sense | *knows exactly which 32 bytes belong on a chain* |

## 3. What each option actually buys, in one paragraph each

**O0 (gossip-only).** Cheapest. No external attestation ever; split-view resistance
is a fork-resolution rule, and recovery from a stolen key means rewriting history,
which is why Tailnet Lock does that. Rejected: it is exactly the gap Norn exists to close.

**O1 (witnessed log).** Non-equivocation from k-of-N witnesses in independent trust
domains. Withholding is a DoS, not a breach — and with **submission receipts** (the
log signs "entry X will be included by size N / time T" on submission, the way CT
issues SCTs) a signer holds non-repudiable proof if it isn't. Every piece exists and
is audited-in-anger by CT. Verification needs zero network. This is the floor.

**O2 (multi-log).** The CT answer to "one log operator can stall." Two logs run by
different people; an entry is valid when in both (strict) or either (lenient, with
receipts). Doubles ops. Worth it when the log operator and the control-plane operator
are the same entity you don't fully trust — i.e. when Norn is deployed *by a tenant
against a provider*. Not needed when the admin runs both.

**O3 (BFT chain).** Replaces the single orderer with a validator set; withholding
needs > ⅓ colluding. But: validators must be *always on* for liveness (> ⅔), which a
homelab or a small org cannot promise; a node still needs a trusted full node to be
live; and validators are just witnesses that also order — the non-equivocation is
the same k-of-N assumption in a heavier coat. It answers a question Norn doesn't ask
(untrusted writers). Rejected for the core; the multi-org case is served by O2.

**O4 (anchoring).** Adds one witness that nobody can collude with: a public chain's
timestamp. Only checkpoint hashes (32 bytes) leave the network; entries never do.
OpenTimestamps makes it free and needs no wallet — one cron job posts each
checkpoint hash to calendar servers, gets a pending proof in ~1 s and a Bitcoin
proof hours later. What it buys is precise: **history cannot be backdated even if
the log and all witnesses collude** (the A9 residual), and fork-recovery evidence
becomes undeniable to third parties. What it does *not* buy: freshness, liveness,
enforcement, or anything a node needs in the handshake path. Keybase ran exactly
this for six years; it is the only blockchain use in this space that survived contact
with reality.

**O5 (on-chain registry).** The "go wild" option, scored honestly. Every enrollment
is a transaction: gas, a wallet per signer, device names public and immutable
forever, no LAN-only operation, and the fatal one — a node cannot verify contract
state without either running a light client for that chain or trusting an RPC
endpoint. Trusting an RPC reintroduces the exact single trusted party Norn is built
to remove. Rejected.

**O6 (hybrid).** O1 as the core; O4 as an optional *anchor witness* type in the
witness policy (`anchor: opentimestamps, max_lag: 24h`, advisory by default); O2 as
a documented upgrade path for multi-tenant deployments. Everything on the handshake
path stays offline-verifiable in microseconds. The chain is present, bounded, and
justified by a named adversary.

## 4. When a chain *would* be right (so the decision is falsifiable)

| Situation | Upgrade to |
|---|---|
| Two or more organisations share one mesh and neither trusts the other to run the log | **O2** (each runs a log; entries need both) |
| Regulatory need to prove *to outsiders* when a device was enrolled or revoked | **O4** anchoring required, not advisory |
| Log operator == control-plane operator == a provider the tenant distrusts | **O2** + O4 |
| Writers themselves become mutually distrusting (an open federation enrolling strangers' devices) | **O3** — and at that point it is a different product |

If none of these appear by Phase 6, the decision stands.

## 5. Decision

**O6.** Recorded as D-009. Consequences for later parts:

- Part 4 (`SPEC.md`): entries, checkpoints, tiles per C2SP; add **submission
  receipts**; add an optional `anchors/` directory next to tiles holding `.ots` proofs
  per checkpoint.
- Part 6: witness policy grammar gets an optional `anchor` clause; anchoring is a
  monitor-side job, never on the node's path.
- Phase 4 gate gains: "checkpoint N has a verifiable OpenTimestamps proof; `norn verify --anchored` checks it."
- Phase 7 backlog: multi-log (O2) validity rule.

## Sources

- OpenTimestamps — https://opentimestamps.org/ · https://petertodd.org/2016/opentimestamps-announcement
- OpenTimestamps calendar server — https://github.com/opentimestamps/opentimestamps-server
- CometBFT light client spec — https://docs.cometbft.com/main/spec/light-client/
- CometBFT fork accountability — https://docs.cometbft.com/main/spec/light-client/accountability/
- Keybase Merkle root → Bitcoin — https://book.keybase.io/docs/server/merkle-root-in-bitcoin-blockchain
- Keybase → Stellar — https://book.keybase.io/docs/server/stellar
- Transparency logs as a verifiable transport layer — https://transparency.dev/articles/logs-a-verifiable-transport-layer/
- Think Global, Act Local: gossip and client audits in VDS — https://arxiv.org/pdf/2011.04551
- Certificate Transparency Using Blockchain (IACR 2018/1232) — https://eprint.iacr.org/2018/1232.pdf
- Chrome CT policy — https://googlechrome.github.io/CertificateTransparency/ct_policy.html
