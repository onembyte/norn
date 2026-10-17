# Norn — Publication and Impact Plan

Written **2026-09-18** (plan part 9), rewritten **2026-09-20** when the things
it promised reviewers stopped matching the repository. A protocol is impressive
when someone else runs it. This file is the path from "works on my NAS" to that.

## 1. Positioning

**One line:** *Certificate Transparency for your WireGuard peer table.*

**Three sentences:** Every mesh VPN trusts a coordination server that can hand your
laptop an attacker's key and you would never know. Norn puts every device
enrollment, rotation and revocation in an append-only, witnessed log and refuses
any peer that isn't in it. It works beside NetBird, innernet or plain `wg-quick`
(Tailscale and Headscale are planned), changes nothing in WireGuard, and needs no
blockchain — except the 32 bytes per checkpoint we chose to anchor, and we explain
exactly why.

**Never in the tagline:** "blockchain". It is answered in §6 and scored in
`LEDGER-OPTIONS.md`.

**The comparison table lives in `README.md`**, and only there. It is the first
thing a reviewer reads and the first thing that goes stale; one copy can be
kept true, two cannot.

## 2. Audiences, in order of who will actually try it

| Audience | What they want | Lead with |
|---|---|---|
| Self-hosters on Headscale / NetBird (r/selfhosted, r/WireGuard) | "can my control plane betray me, and would I know?" | planned D1c (Headscale #1432) and D1a |
| Transparency community (transparency-dev, Sigsum, C2SP) | correct reuse of their formats; a new *application* of tlogs | verbatim C2SP formats, an unmodified witness cosigning a Norn checkpoint, T1/T3 |
| Security researchers | threat model, measured windows, honest limitations | `THREAT-MODEL.md`, `ENFORCEMENT.md` §5 numbers, D2 |
| ZTNA / fintech infra teams | auditable device admission, evidence for SOC 2 / ISO device inventory | status page, proof bundles, monitor alerts |

## 3. What a reviewer can touch today

Both marks are promises. ✅ says a reviewer will find it; ⬜ says they will not,
and saying so is the point — the previous version of this file sent people to a
directory that was never created.

| Artifact | Today | What it is |
|---|---|---|
| `SPEC.md` | ✅ | frozen at v1; entries, replay, log layout, receipts, proofs, trust file |
| `testdata/vectors/` | ✅ | byte-exact vectors, three provenances, checksummed, usable without this repo |
| `contrib/norn-ref/` | ✅ | Python reference implementation, written from the spec alone; it *generates* the vectors |
| `cmd/norn/` | ✅ | the CLI: `init`, `enroll`, `sign`, `submit`, `verify`, `verify-evidence`, `revoke`, `rotate`, `govern`, `audit`, `stamp`, `monitor`, `status` |
| `cmd/nornd/` | ✅ | the node daemon: replay, quorum, gossip, reconcile |
| `README.md` | ✅ | the pitch, the threat model in one screen, the comparison table, a runnable quickstart |
| `THREAT-MODEL.md` | ✅ | 12 adversaries, 7 guarantees, and what Norn does not defend |
| `PRIOR-ART.md` | ✅ | the gap, with sources, found before building |
| `LEDGER-OPTIONS.md` | ✅ | the blockchain question answered with a scoring table |
| `GOSSIP.md` | ✅ | witnesses, freshness, peer gossip, split-view tests |
| `ENROLLMENT.md` | ✅ | key ceremony, QR enrollment, recovery runbooks |
| `BUILD-LOG.md` | ✅ | every checkpoint, and what each one got wrong first |
| `make vectors-check` | ✅ | regenerates the vectors from both implementations and diffs them |
| `make ref-test` | ✅ | the Python reference implementation's own unit tests |
| `make witness` | ✅ | runs an unmodified `transparency-dev/witness` against a Norn checkpoint |
| `contrib/verify-py/` | ✅ | an independent *verifier*, Python standard library only, built cold by another model family from `SPEC.md` and the vectors alone and kept as written; its `PROVENANCE.md` says how — H14 |
| `make verify-py` | ✅ | runs that verifier over every vector, its own RFC 8032, RFC 6962 and BIP-350 self-tests first; part of `make ci` |
| `lab/` | ⬜ | containers, a patched Headscale, NetBird; the whole of Phase 3 |
| `demo/` | ⬜ | the six recorded attack demos |
| `make demos` | ⬜ | needs `lab/`; every measured number in this plan comes from it |

A public witness for the reference network, and a live status page, are
deployments rather than files. Neither is running.

## 4. Review before publishing (private)

Not a calendar — a list of people whose objection would change the design, and
the one question each is actually qualified to destroy.

| Who | Why them | The ask |
|---|---|---|
| transparency-dev community (Slack / list) | they wrote the formats | "does an unmodified witness really cosign this?" — bring the lab log, not the claim |
| Sigsum / Glasklar | witness freshness and policy are their life's work | review `GOSSIP.md` §3–5, especially the degraded/hard-stale ladder |
| torchwood / transparent-keyserver author | client-side proofs, policy parsing | "is this the intended use of `ThresholdPolicy` and `VerifyProof`?" |
| tailscale-rs TKA author | the only other person who has reimplemented an authority chain | compare `SPEC.md` §5 replay with TKA's fork rules |
| Headscale maintainers | #1307 / #1432 are open and unanswered | "Norn's planned observe integration is a partial answer to #1432; interested?" |
| NetBird maintainers | the peer-admission hook Phase 7 needs | open an issue before the PR, never after |
| Somebody who has run two of Tailnet Lock, Nebula and NetBird in anger | the comparison table is written by someone who has run none of them | "which row is unfair?" |

## 5. The sequence

Gated on what is true, not on which week it is. A date slips quietly; a
precondition does not.

**Gate A — the spec can be handed to a stranger.**
Frozen `SPEC.md` ✅ · vectors that stand alone ✅ · an honest `README.md` ✅ ·
a second implementation of the *verifier*, built from the spec alone, passing
every vector ⬜ (6.5). Until the last one, the claim "the spec is sufficient"
is untested and must not be made in public.

**Gate B — the numbers are measured, not estimated.**
Every gate line in Phases 3, 4 and 5 of `PLAN.md`. Watchdog window p99, revoke
propagation, gossip convergence, and the demos that record them. Publishing
adjectives where numbers were promised is the failure this project exists to
avoid.

**Then, in order:**

1. **Private review** (§4). Fix what they find. Expect the comparison table to be the most-corrected thing in the repository.
2. **Repo public + blog post** — *"Certificate Transparency for your VPN"* — the argument from `PRIOR-ART.md` and `LEDGER-OPTIONS.md`, with one demo embedded. Show HN, r/selfhosted, r/WireGuard and Lobsters on the same day. Lead with the attack, not the architecture.
3. **Upstream conversations** — comment on Headscale #1432 with the observe-mode recipe; open the NetBird hook issue; announce on the WireGuard list without proposing a patch to WireGuard, because there isn't one.
4. **Phase 7** — the NetBird PR; onboard the reference log to a public witness.
5. **Talks** — Transparency.dev Summit 2027 (2026's is Sept 29–Oct 1 in Montreal: too soon); FOSDEM 2027 network and security devrooms, CFPs around November 2026; a local BSides with the three-stack demo.
6. **Later, and only then** — an Internet-Draft, *Key Transparency for WireGuard peer sets*, once a second implementation exists; a C2SP proposal for the entry format only if another project wants to reuse it.

## 6. The obvious questions

The ones asked in the first five minutes. Answering them badly in a comment
thread is how a project gets remembered wrongly.

### Is this a blockchain?

No. It is a Merkle log with k-of-N witness cosignatures — the same construction
Certificate Transparency has used since 2013, in the same formats, with none of
the consensus, tokens or mining. The only blockchain in Norn is 32 bytes per
checkpoint, optionally anchored to Bitcoin via OpenTimestamps, and that is an
advisory timestamp a node never consults when deciding whether to admit a peer.
`LEDGER-OPTIONS.md` scores the alternatives and shows the work.

### Why not just use Tailscale's Tailnet Lock?

Use it, if you are on Tailscale. Tailnet Lock records changes to *who may sign*;
Norn records *every key that was ever signed*, which is the property that lets
you enumerate the damage after a signing key is stolen. Tailnet Lock also
distributes its authority updates through the control plane, and its own
whitepaper acknowledges the resulting freeze attack. Norn's nodes gossip
checkpoints to each other over the tunnel, and it works with a readable and
writable WireGuard interface, as with NetBird's kernel interface, innernet or
plain `wg-quick`. Tailscale and Headscale support is planned.

### Who do I have to trust?

Fewer parties than you trust today, and explicitly. You trust the signer keys
you provisioned, and you trust that fewer than k of your N witnesses are
colluding with the log. You do **not** have to trust the log operator, the
coordination server, the network, or whoever handed you the software — every
one of those can lie and be caught. You do have to trust the out-of-band
channel that delivered `norn.trust`, and there is no trust-on-first-use to
paper over it.

### What happens when the log goes down?

The network keeps running on the last checkpoint each node accepted, gets
noisier as it ages — `fresh`, then `degraded`, then `hard_stale` — and alarms
rather than silently pretending to be current. Nodes also serve checkpoints to
each other over the tunnel, so the log has to be unreachable *and* every peer
stale before anything is blind. What Norn will not do is admit a peer it cannot
prove, so a log outage plus a strict policy is an outage; that is stated in the
README under who this is not for.

### Isn't this just Certificate Transparency with extra steps?

It is Certificate Transparency applied to a problem that has the same shape and
none of the infrastructure. The extra steps are the ones the setting demands:
the log travels over the tunnel it secures, nodes are also monitors because
there is no browser vendor to be one, and enforcement is local, because there is
nobody to revoke a certificate to. The formats are C2SP's, unmodified, so an
existing witness cosigns a Norn checkpoint without knowing what Norn is.

### Why would anyone run a witness for my little network?

They would not, and they do not have to. The design assumes you run your own
witnesses in places with different failure modes — a Pi at home, a cheap VPS, a
friend's box — which is a 2-of-3 that a single compromise of your NAS does not
break. Shared or public witnesses make the guarantee stronger because they are
harder to coerce together, but they are an upgrade, not a prerequisite.

### How is this different from signing my configs and shipping them with Ansible?

A signature proves who wrote a config; it does not prove that everyone was shown
the same one. Split-view is the whole attack: a signer that shows you one peer
set and your colleague another is perfectly consistent under signatures and
impossible under an append-only log with witness cosignatures. Norn also gives
you the thing config management cannot — an enumerable history, so that after a
key is stolen you can list precisely what it signed.

### What does it cost me to run?

A log process and three witness processes, all small, plus a daemon on each
node; the reference network runs on a NAS and a Raspberry Pi. The per-checkpoint
work is a handful of Ed25519 verifications and a Merkle path, and the log grows
by one entry per key change, not per connection. Bitcoin anchoring, if you turn
it on, is one free OpenTimestamps call per checkpoint you choose to stamp.

### Has anyone attacked it?

No, and that is the honest state. There is a threat model with twelve
adversaries, a test suite that includes the attacks I know how to write, fork
evidence that is checkable offline by a third party, and 83 million fuzz
executions against the replay path. None of that is an adversary who wants it
broken, which is what a private review round and a public repository are for.

### Why should I believe your threat model?

Do not — check it. Every guarantee in `THREAT-MODEL.md` names what it rests on,
and the ones that rest on nothing more than my saying so are marked as
procedural. The vectors let you build a verifier that disagrees with mine, the
fork evidence is verifiable without trusting the accuser, and `BUILD-LOG.md`
lists what each checkpoint got wrong before it got it right, which is a better
guide to where the bugs are than any assurance I could write.

## 7. What reviewers actually check

- [ ] Spec + byte-exact vectors, and a second implementation that passes them
- [ ] A threat model that names what it does **not** defend (A4, A9, A10 are the honest ones)
- [ ] Measured numbers, not adjectives: watchdog window p99, revoke propagation, gossip convergence
- [ ] Reproducible demos, including the one where Norn *cannot* prevent the attack (D1c)
- [ ] Reuse of an existing ecosystem instead of a new island — an unmodified witness cosigns
- [ ] A running witness and status page a stranger can visit
- [ ] Prior art found *before* building, with the gap stated precisely
- [ ] The blockchain question answered with a scoring table, not a mood

Four of those eight are open, and the three that need the lab are the three that
carry numbers. That ratio is the argument for Gate B.

## 8. Risks to impact

| Risk | Mitigation |
|---|---|
| "yet another mesh VPN thing" | Norn is *not* a VPN; the README's first image is an attack, not an architecture |
| the word "blockchain" attracts the wrong crowd and repels the right one | never in the tagline; anchoring is optional, advisory, and explained |
| scope creep into a control plane | non-goals in `PLAN.md`; endpoint providers stay untrusted for keys |
| nobody runs a witness for you | run three yourself; the design works with self-run witnesses and improves with shared ones |
| Tailscale ships gossip and witnesses in Tailnet Lock | good — cite it; Norn still covers the stacks Tailscale never will |
| publishing before Gate B | the numbers are the differentiator; adjectives would waste the one first impression |
