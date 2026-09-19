# Norn — Publication and Impact Plan

Written **2026-09-18** (plan part 9). A protocol is impressive when someone else
runs it. This file is the path from "works on my NAS" to that.

## 1. Positioning

**One line:** *Certificate Transparency for your WireGuard peer table.*

**Three sentences:** Every mesh VPN trusts a coordination server that can hand your
laptop an attacker's key and you would never know. Norn puts every device
enrollment, rotation and revocation in an append-only, witnessed log and refuses
any peer that isn't in it. It works beside Headscale, NetBird or plain `wg-quick`,
changes nothing in WireGuard, and needs no blockchain — except the 32 bytes per
checkpoint we chose to anchor, and we explain exactly why.

**Never in the tagline:** "blockchain". It appears once, in `LEDGER-OPTIONS.md`, with
the scoring that justifies it.

## 2. Audiences, in order of who will actually try it

| Audience | What they want | Lead with |
|---|---|---|
| Self-hosters on Headscale / NetBird (r/selfhosted, r/WireGuard) | "can my control plane betray me, and would I know?" | D1c (Headscale #1432, live) and D1a |
| Transparency community (transparency-dev, Sigsum, C2SP) | correct reuse of their formats; a new *application* of tlogs | verbatim C2SP formats, unmodified witness cosigning a Norn checkpoint, T1/T3 |
| Security researchers | threat model, measured windows, honest limitations | `THREAT-MODEL.md`, `ENFORCEMENT.md` §5 numbers, D2 |
| ZTNA / fintech infra teams | auditable device admission, evidence for SOC 2 / ISO device inventory | status page, proof bundles, monitor alerts |

## 3. Artifacts at Phase 6

1. Public repo `github.com/onembyte/norn`, **Apache-2.0** (D-025).
2. `SPEC.md` frozen v1 + `testdata/vectors/` + a cold-model second implementation of the verifier in `contrib/verify-py/` (proves the spec, not the code).
3. `README.md` (skeleton in this repo): one-liner, three demo GIFs, how-it-works diagram, comparison table (§4), quickstart, threat-model summary, non-goals.
4. Blog post: *"Certificate Transparency for your VPN"* — the argument from `PRIOR-ART.md` + `LEDGER-OPTIONS.md`, one demo embedded.
5. A public witness for the reference network, and the status page, both live.
6. The fork-evidence format and `norn verify-evidence` — the thing a third party can check.

## 4. Comparison table (README)

| | plain WireGuard | Headscale / NetBird | Nebula | Tailscale + Tailnet Lock | **Norn** (beside any of them) |
|---|---|---|---|---|---|
| Compromised control plane can add a peer | n/a | **yes, silently** | lighthouse no; CA yes, silently | no | **no** (owner) / evicted (watchdog) / **detected** (observe) |
| Log of every key ever admitted | no | no | no | no (authority chain only) | **yes, append-only, witnessed** |
| Works when the control plane withholds updates | n/a | no | n/a | no (acknowledged) | **yes** — peers gossip checkpoints |
| Split-view detection | n/a | n/a | n/a | fork rules only | **k-of-N witnesses + gossip + evidence files** |
| Bootstrap | manual | TOFU | CA cert | TOFU (acknowledged) | **pre-provisioned trust file, no TOFU** |
| Revocation with proof of delivery | no | no | blocklist in config (CVE-2026-61699) | control plane | **log entry; eviction time measured** |
| Requires patching the VPN | — | — | — | it *is* the patch | **no** |
| Runs on a NAS + a Pi | yes | yes | yes | no | **yes** |

## 5. Review before publishing (private, 2–3 weeks)

| Who | Why | Ask |
|---|---|---|
| transparency-dev community (Slack / list) | format reuse, witness protocol | "does an unmodified witness really cosign this?" — bring the lab log |
| Sigsum / Glasklar people | witness freshness rule, policy usage | review `GOSSIP.md` §3–5 |
| torchwood / transparent-keyserver author | client-side proofs, policy parsing | "is this the intended use of `ThresholdPolicy` and `VerifyProof`?" |
| tailscale-rs TKA author | the only other person who reimplemented an authority chain | compare `SPEC.md` §5 replay with TKA fork rules |
| Headscale maintainers | #1307 / #1432 are open | "Norn observe mode is a partial answer to #1432 today; interested?" |
| NetBird maintainers | peer-admission hook | open an issue before the PR |

## 6. Launch sequence

1. **Week 0** — private review (§5); fix what they find.
2. **Week 2** — repo public + blog + *Show HN* + r/selfhosted + r/WireGuard + Lobsters, same day. Lead with the D1c GIF.
3. **Week 3** — comment on Headscale #1432 with the observe-mode recipe; open the NetBird hook issue; announce (not patch) on the WireGuard mailing list.
4. **Month 2** — Phase 7 PR to NetBird; onboard the reference log to a public witness.
5. **Talks** — Transparency.dev Summit **2027** (the 2026 summit is Sept 29–Oct 1, Montreal — too soon); FOSDEM 2027 network/security devrooms (CFPs open ~Nov 2026); a local BSides with the three-stack demo.
6. **Later** — an Internet-Draft, *Key Transparency for WireGuard peer sets*, only after a second implementation exists; C2SP proposal for the entry format only if another project wants to reuse it.

## 7. What reviewers actually check (the "impressive" list)

- [ ] Spec + byte-exact vectors, and a second implementation that passes them
- [ ] A threat model that names what it does **not** defend (A4, A9, A10 are the honest ones)
- [ ] Measured numbers, not adjectives: watchdog window p99, revoke propagation, gossip convergence
- [ ] Reproducible demos from `make demos`, including the one where Norn *can't* prevent (D1c)
- [ ] Reuse of an existing ecosystem instead of a new island (unmodified witness cosigns)
- [ ] A running witness and status page you can visit
- [ ] Prior art you found *before* building, with the gap stated precisely
- [ ] The blockchain question answered with a scoring table, not a mood

## 8. The career angle (one paragraph, for Franco)

Fintech ZTNA teams have the exact problem Norn solves — auditable device admission
with evidence — and almost none of them can articulate it. A repo that ships a
threat model, measured enforcement, and CT-grade transparency for network access
is a portfolio piece that speaks directly to that hiring conversation, and it sits
on the same "no finding without proof" thesis as Gungnir.

## 9. Risks to impact

| Risk | Mitigation |
|---|---|
| "yet another mesh VPN thing" | Norn is *not* a VPN; the README's first image is an attack, not an architecture |
| the word "blockchain" attracts the wrong crowd and repels the right one | tagline never says it; anchoring is optional and explained |
| scope creep into a control plane | non-goals in `PLAN.md`; endpoint providers stay untrusted for keys |
| nobody runs a witness for you | run three yourself (Pi, VPS, friend); design works with self-run witnesses |
| Tailscale ships gossip + witnesses in Tailnet Lock | good — cite it; Norn still covers Headscale/NetBird/plain WG, which Tailscale never will |
