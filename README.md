# Norn

**Certificate Transparency for your WireGuard peer table.**

> Every mesh VPN trusts a coordination server that can hand your laptop an
> attacker's key — and you would never know. Norn puts every device enrollment,
> rotation and revocation in an append-only, witnessed log, and refuses any peer
> that isn't in it. Works beside Headscale, NetBird or plain `wg-quick`. Changes
> nothing in WireGuard.

*Status: **planning complete, not yet code** (2026-09-18). See `PLAN.md`.*

<!-- demo GIFs: D1a owner · D1b watchdog · D1c observe (see LAB.md §2) -->

## How it works

<!-- diagram: signer → log ⇄ witnesses ⇄ nodes (gossip) → wg peer table -->

1. A **signer** enrolls a device: a signed entry goes into a **transparency log**.
2. **Witnesses** (k-of-N, in independent places) cosign each log checkpoint.
3. Every **node** replays the whole log, verifies the witness quorum, and installs
   **only proven keys** in its WireGuard peer table.
4. Nodes **gossip checkpoints to each other over the tunnel**, so a control plane
   that lies or stalls is detected and routed around.

## Documents

| File | What |
|---|---|
| `PLAN.md` | phases, gates, fixed decisions |
| `PRIOR-ART.md` | why this doesn't exist yet |
| `THREAT-MODEL.md` | 12 adversaries, 6 guarantees, what Norn does *not* defend |
| `LEDGER-OPTIONS.md` | do we need a blockchain? (scored; answer: 32 bytes of one, optionally) |
| `SPEC.md` | entries, replay, log layout, receipts, proofs, trust file |
| `ENFORCEMENT.md` | observe / owner / watchdog modes; integration matrix |
| `GOSSIP.md` | witnesses, freshness, peer gossip, split-view tests |
| `ENROLLMENT.md` | keys, ceremony, QR enrollment, recovery runbooks |
| `LAB.md` | lab topology, attack demos, monitor |
| `PUBLICATION.md` | how this reaches other people |
| `DECISIONS.md` | every decision, with what was rejected |

## Non-goals
Not a VPN · not a coordination server · not availability protection · not internet-scale · not a blockchain.

## License
Apache-2.0
