# Norn v0.1

## What it is

Norn is a pre-release tool for making WireGuard peer keys traceable to an append-only, witnessed log. A stranger can build the CLI and verify the repository's example log offline. No supported version exists yet ([SECURITY.md](SECURITY.md)).

The repository contains the log and a verifier that checks signed checkpoints, witness cosignatures, inclusion proofs, and replayed state; `nornd` with observe, owner, and watchdog modes; and the `norn` CLI. Its commands are `audit`, `enroll`, `govern`, `init`, `monitor`, `revoke`, `rotate`, `sign`, `stamp`, `status`, `submit`, `verify`, and `verify-evidence` ([cmd/norn](cmd/norn)). `SPEC.md` is frozen. The vector suite has two implementation sources: the Python reference generates entries, state, trust files, and enrollment requests; Go generates served logs, proofs, and checkpoints ([CONTRIBUTING.md](CONTRIBUTING.md)).

## What it guarantees, conditionally

These are the seven guarantees in [THREAT-MODEL.md §4](THREAT-MODEL.md#4-guarantees). Each depends on its stated assumptions.

- **Peer authenticity:** In enforce mode, installed peer keys are active in replay and have inclusion proofs under an accepted checkpoint. This rests on a correct verifier, intact `norn.trust`, and fewer than the witness threshold being faulty.
- **Non-equivocation:** Honest nodes do not accept incompatible histories; a proven fork is held and produces evidence. This rests on the witness-collusion bound, sound Ed25519 and SHA-256, and gossip when witness quorums need not intersect.
- **Validity independent of the log:** The log cannot grant access with invalid entries; replay checks each entry against signer state. This rests on signer keys not being compromised beyond the threat model.
- **Bounded staleness:** A node alarms when its checkpoint is too old, and a connected honest node applies a revocation within the stated interval or alarms. This rests on at least one path to a fresh checkpoint.
- **Transparency and accountability:** Accepted keys trace to identifiable signer entries, and a running monitor sees entries within the stated interval. This rests on a monitor being installed and running.
- **No TOFU:** A node accepts only its provisioned log, witness set, and genesis. This rests on the out-of-band delivery of `norn.trust`.
- **Route authenticity:** In granted-routes mode, installed allowed IPs stay within the enrollment grant. This rests on peer authenticity and signers granting the intended routes.

These are conditional protocol and software guarantees, not field measurements. Observe mode only reports unexpected peers. Watchdog mode can allow a rogue peer for up to its polling interval before removal. See [THREAT-MODEL.md §7](THREAT-MODEL.md#7-explicit-non-goals-repeated-from-planmd-so-this-file-stands-alone) for explicit non-goals, including availability, stolen WireGuard private keys before revocation, colluding log and witness quorum, trust-file delivery security, log privacy, traffic policy, and internet-scale directories.

## What has not happened

Nothing has run on a real kernel or real network, and there has been no outside review. PLAN.md has 38 gate lines: 14 are ticked and 24 remain open. In particular, the lab, the observe soak, enforcement measurements, and outside review are the owner's open rows U1–U7 in [HARDENING-PLAN.md Stage G](HARDENING-PLAN.md#stage-g--yours-not-looped-user). The v0.1 tag is also the owner's row U8.

Before upgrading or enrolling anything, note this behavior from D-073: a device enrolled without an `ip` label is installed with its key and no routes. [ENFORCEMENT.md §5](ENFORCEMENT.md#5-endpoint-providers-owner-mode-only) describes grants and the operator options.

Two open decisions can change behavior, each a DECISION block in [BUILD-LOG.md](BUILD-LOG.md). D-072 ("five protocol questions the audit raised") records five unresolved security questions, including watchdog behavior during a freeze and enforcement with no witness quorum. D-074 ("eight protocol questions cold gate run 13 raised") records eight unresolved specification questions from cold-model run 13.

## How it was tested

The contributor gate is `make vectors`, `make vectors-log`, `make test`, then `make vectors-check ref-test lint fmt-check vet`; run `make vectors-sums` when a vector changes ([CONTRIBUTING.md](CONTRIBUTING.md#gate)). The vectors use both Go and the Python reference, with the split described above.

The cold-model gate has run 13 times. The latest run, recorded in [BUILD-LOG.md](BUILD-LOG.md) under "6.5l-viii — cold-model gate run 13", scored 1,353 of 1,353 checks, but found defects that change behavior; it did not pass D-068. The gate therefore remains open.
