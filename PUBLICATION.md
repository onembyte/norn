# Norn — Publication and Impact Plan

Written **2026-09-18** (plan part 9), rewritten **2026-09-20** when the things
it promised reviewers stopped matching the repository, and revised
**2026-09-30** for the security audit (`docs/audit/`) and cold-model gate runs
12 and 13. A protocol is impressive when someone else runs it. This file is the
path from "works on my NAS" to that.

## 1. Positioning

**One line:** *Certificate Transparency for your WireGuard peer table.*

**Three sentences:** Every mesh VPN trusts a coordination server that can hand your
laptop an attacker's key and you would never know. Norn puts every device
enrollment, rotation and revocation in an append-only, witnessed log, reports
any peer that isn't in it and, once enforcement is on, removes it. It is built
to sit beside plain `wg-quick` or NetBird — Headscale is planned, observe-only —
changes nothing in WireGuard, and needs no blockchain — except the 32 bytes per
checkpoint we chose to anchor, and we explain exactly why.

**Never in the tagline:** "blockchain". It is answered in §6 and scored in
`LEDGER-OPTIONS.md`.

**The comparison table lives in `README.md`**, and only there. It is the first
thing a reviewer reads and the first thing that goes stale; one copy can be
kept true, two cannot.

## 2. Audiences, in order of who will actually try it

| Audience | What they want | Lead with |
|---|---|---|
| Self-hosters on Headscale / NetBird (r/selfhosted, r/WireGuard) | "can my control plane betray me, and would I know?" | D1a, and D1c (Headscale #1432) once the `tailscaled` observer it needs is written |
| Transparency community (transparency-dev, Sigsum, C2SP) | correct reuse of their formats; a new *application* of tlogs | verbatim C2SP formats, an unmodified witness cosigning a Norn checkpoint (`internal/interop`), T3, and T1 once gossip runs on its cadence (SEC-002) |
| Security researchers | threat model, measured windows, honest limitations | `THREAT-MODEL.md`, the Phase 3 numbers `ENFORCEMENT.md` §10 plans once the lab measures them, D2 |
| ZTNA / fintech infra teams | auditable device admission, evidence for SOC 2 / ISO device inventory | status page, proof bundles, monitor alerts |

## 3. What a reviewer can touch today

Both marks are promises. ✅ says a reviewer will find it; ⬜ says they will not,
and saying so is the point — the previous version of this file sent people to a
directory that was never created.

| Artifact | Today | What it is |
|---|---|---|
| `SPEC.md` | ✅ | entries, replay, log layout, receipts, proofs, trust file; frozen at v1 on 2026-09-20, and amended since by the cold-model checkpoints that close each run's defects — 6.5n will amend it again |
| `testdata/vectors/` | ✅ | byte-exact vectors, three provenances, checksummed, usable without this repo |
| `contrib/norn-ref/` | ✅ | Python reference implementation, written from the spec alone; it *generates* the entry, state, trust, receipt and request vectors |
| `cmd/norn/` | ✅ | the CLI: `init`, `enroll`, `sign`, `submit`, `verify`, `verify-evidence`, `audit`, `stamp`, `monitor`, `status`. It builds `genesis` and `enroll` entries and no other kind: no `revoke`, `rotate` or governance builder exists (SEC-008) |
| `cmd/nornd/` | ✅ | the node daemon: replay, quorum, gossip, reconcile. Its enforcement is tested against `peertable.Fake`, never a real interface; its checkpoint does not survive a restart, nor its fork freeze a reboot (SEC-004, SEC-006) |
| `README.md` | ✅ | the pitch, the threat model in one screen, the comparison table, a runnable quickstart |
| `THREAT-MODEL.md` | ✅ | 12 adversaries, 6 guarantees, and what Norn does not defend |
| `PRIOR-ART.md` | ✅ | the gap, with sources, found before building |
| `LEDGER-OPTIONS.md` | ✅ | the blockchain question answered with a scoring table |
| `GOSSIP.md` | ✅ | witnesses, freshness, peer gossip, split-view tests; the fixed gossip cadence it describes is not implemented — nodes ask peers only when the log fails or is stale (SEC-007) |
| `ENROLLMENT.md` | ✅ | key ceremony, QR enrollment, recovery runbooks; the runbooks that revoke or rotate need builders that do not exist yet (SEC-008) |
| `BUILD-LOG.md` | ✅ | every checkpoint, and what each one got wrong first |
| `docs/audit/` | ✅ | the 2026-09-30 security audit (36 findings), where the documents and the code disagree, and the roadmap: five tasks, and the decisions D-a to D-l that are the maintainer's |
| `SPEC-DEFECTS-13.md` | ✅ | the latest cold-model gate report: `SPEC SUFFICIENT WITH GAPS`, 886/886 checks, eight defects, none High |
| `make vectors-check` | ✅ | regenerates the Python reference's vectors and the Go-generated ones, each from its own generator, and diffs them against what is committed; `anchors/` is somebody else's bytes and is not regenerated |
| `make ref-test` | ✅ | the Python reference implementation's own unit tests |
| `make witness` | ✅ | builds a pinned, unmodified `transparency-dev/witness`; `internal/interop` then has it cosign a checkpoint `norn-log` serves. CI does not build it, so there that test skips |
| `contrib/verify-py/` | ⬜ | a committed second *verifier* built from the frozen spec alone. Each cold-model run writes one in a sealed workspace — run 13's is standard-library Go and passed 886/886 — and none is kept in this repository |
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
| torchwood / transparent-keyserver author | client-side proofs, policy parsing | torchwood is not a dependency: Norn parses `tlog-policy` and checks proofs with its own code (`internal/policy`, `internal/tlog`). "Does this reading of the policy grammar agree with `ThresholdPolicy`?" |
| tailscale-rs TKA author | the only other person who has reimplemented an authority chain | compare `SPEC.md` §5 replay with TKA's fork rules |
| Headscale maintainers | #1307 / #1432 are open and unanswered | "observe mode against `tailscaled` would be a partial answer to #1432; it is designed (`ENFORCEMENT.md` §6) and not written — would you want it?" |
| NetBird maintainers | the peer-admission hook Phase 7 needs | open an issue before the PR, never after |
| Somebody who has run two of Tailnet Lock, Nebula and NetBird in anger | the comparison table is written by someone who has run none of them | "which row is unfair?" |

## 5. The sequence

Gated on what is true, not on which week it is. A date slips quietly; a
precondition does not.

**Gate A — the spec can be handed to a stranger.**
`SPEC.md` frozen at v1 ✅ · vectors that stand alone ✅ · a `README.md` that
claims no more than the code does ✅ — the audit found it claimed more
(SEC-020, G2's bound in SEC-002, `docs/audit/PROJECT_STATUS.md` §5), the
documentation pass corrected those claims, and `internal/docclaims` checks its
counts and runs its commands · a second implementation of the *verifier*,
built from the spec alone, that finds nothing in the prose it could reasonably
have got wrong ⬜. That last one is `PLAN.md`'s cold-model gate line, and
passing every vector was never the bar. Run 12 passed
553 of 553 checks and returned `SPEC INSUFFICIENT` (`SPEC-DEFECTS-12.md`);
6.5m closed thirteen of its fourteen defects; run 13 passed 886 of 886 and
returned `SPEC SUFFICIENT WITH GAPS`, eight defects, none High
(`SPEC-DEFECTS-13.md`). The line waits on 6.5n — -i to -iii for run 13's gaps,
-iv for run 14 — and on decision D-l, and on none of the audit's tasks. Until
it closes, "the spec is sufficient" has not been shown and must not be said in
public.

**Gate B — the numbers are measured, not estimated, and the audit's worst
findings are answered.**
Every gate line in Phases 3, 4 and 5 of `PLAN.md`. Watchdog window p99, revoke
propagation, gossip convergence, and the demos that record them. Publishing
adjectives where numbers were promised is the failure this project exists to
avoid. The audit adds preconditions of its own (`docs/audit/ROADMAP.md`):
task 1's structural half — reconcile before any peer I/O, and a cycle-overrun
alarm (SEC-003); task 2, node state that survives a restart (SEC-004,
SEC-006); task 5, builders for `revoke`, `rotate` and the governance entries
(SEC-008); a decision on D-a, the entry-identity question behind SEC-001,
which meanwhile is documented and not fixed; and the documentation pass. Task
1's minimal half landed in `4f7732d`, which gave every peer read and every
submission a deadline. Its structural half, tasks 2 and 5, and D-a remain.

**Then, in order:**

1. **Private review** (§4). Fix what they find. Expect the comparison table to be the most-corrected thing in the repository.
2. **Repo public + blog post** — *"Certificate Transparency for your VPN"* — the argument from `PRIOR-ART.md` and `LEDGER-OPTIONS.md`, with one demo embedded. Show HN, r/selfhosted, r/WireGuard and Lobsters on the same day. Lead with the attack, not the architecture.
3. **Upstream conversations** — once the `tailscaled` observer exists, comment on Headscale #1432 with the observe-mode recipe; open the NetBird hook issue; announce on the WireGuard list without proposing a patch to WireGuard, because there isn't one.
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
whitepaper acknowledges the resulting freeze attack. A Norn node whose log
goes quiet or stale asks its peers for checkpoints over the tunnel, and Norn is
built to run beside NetBird, innernet or plain `wg-quick`, which Tailnet Lock
never will. Beside Headscale it is planned as observe-only and not written:
`tailscaled` exposes no UAPI socket, so there it could only watch.

### Who do I have to trust?

Fewer parties than you trust today, and explicitly. You trust the signer keys
you provisioned, and you trust that fewer than 2k−N of your N witnesses are
colluding with the log: two k-of-N quorums are only guaranteed to share 2k−N
witnesses, which is one for a 2-of-3 (SEC-002). Which policies to refuse or
warn about, and what default to ship, is decision D-b. You do **not** have to
trust the log operator, the coordination server, the network, or whoever
handed you the software — every one of those can lie and be caught. One
exception today: an entry already in the log, re-submitted with a junk
signature added, applies again and can bring a revoked device back, and the
log's `/add` asks for no credentials; the repeat is logged and witnessed, but
no monitor rule flags it (SEC-001, documented and not fixed, decision D-a). You
do have to trust the out-of-band channel that delivered `norn.trust`, and there
is no trust-on-first-use to paper over it.

### What happens when the log goes down?

The network keeps running on the last checkpoint each node accepted, gets
noisier as it ages — `fresh`, then `degraded`, then `hard_stale` — and alarms
rather than silently pretending to be current. Nodes also serve checkpoints to
each other over the tunnel, so the log has to be unreachable *and* every peer
stale before anything is blind. One exception today: a node holds its
checkpoint in memory only, so a `nornd` restarted during the outage cannot ask
its peers either: it learns their addresses from a state it has verified, and
it has none. It leaves the interface untouched until the log answers (SEC-004;
`docs/audit/ROADMAP.md` task 2). What Norn
will not do is admit a peer it cannot prove: a node with no verified state, or
whose view is older than the `S_hard` it opted into, admits nobody new until the
log or a peer answers. That is stated in the README under who this is not for.

### Isn't this just Certificate Transparency with extra steps?

It is Certificate Transparency applied to a problem that has the same shape and
none of the infrastructure. The extra steps are the ones the setting demands:
the log travels over the tunnel it secures, nodes are also monitors because
there is no browser vendor to be one, and enforcement is local, because there is
nobody to revoke a certificate to. The formats are C2SP's, unmodified, so an
existing witness cosigned a Norn checkpoint without knowing what Norn is
(`internal/interop`, after `make witness`, at checkpoint 4.4; not re-run since,
and skipped in CI).

### Why would anyone run a witness for my little network?

They would not, and they do not have to. The design assumes you run your own
witnesses in places with different failure modes — a Pi at home, a cheap VPS, a
friend's box — a 2-of-3 that a compromise of your NAS alone does not break.
The NAS plus any one of them does, because two 2-of-3 quorums share only one
witness (SEC-002); 3-of-3 or 3-of-4 closes that, the first at the cost of
liveness when one witness is down, and which default to ship is decision D-b.
Shared or public witnesses make the guarantee stronger because they are
harder to coerce together, but they are an upgrade, not a prerequisite.

### How is this different from signing my configs and shipping them with Ansible?

A signature proves who wrote a config; it does not prove that everyone was shown
the same one. Split-view is the whole attack: a signer that shows you one peer
set and your colleague another is perfectly consistent under signatures and
impossible under an append-only log whose witness quorums always share an
honest witness. Norn also gives you the thing config management cannot — an
enumerable history, so that after a key is stolen you can list precisely what
it signed (`norn audit --by`).

### What does it cost me to run?

A log process (`norn-log`) and one process per witness — today an unmodified
`transparency-dev/witness`, since `cmd/norn-witness` is an empty stub — plus a
daemon on each node. The lab `LAB.md` plans puts them on a NAS and a Raspberry
Pi; it has not been built. The per-checkpoint work should be a handful of
Ed25519 verifications and a Merkle path; today every poll re-downloads and
replays the whole log instead (SEC-013). The log grows by one entry per key
change, not per connection. Bitcoin anchoring, if you turn it on, is one free
OpenTimestamps call per checkpoint you choose to stamp.

### Has anyone attacked it?

No, and that is the honest state. There is a threat model with twelve
adversaries, a test suite that includes the attacks I know how to write, fork
evidence that is checkable offline by a third party, and a security audit
(`docs/audit/`, 2026-09-30) with two CRITICAL and two HIGH findings, none of
them closed yet. Fuzzing is thinner than this file used to say: checkpoint 1.6
ran 83.8 million executions, most of them against the CBOR decoder, and the
target meant to reach replay's handlers has been skipping since a fixture was
renamed, so at most 2.4 million ever reached one and none do today (SEC-015).
None of that is an adversary who wants it broken, which is what a private
review round and a public repository are for.

### Why should I believe your threat model?

Do not — check it. Every guarantee in `THREAT-MODEL.md` names what it rests on,
and the ones that rest on nothing more than my saying so are marked as
procedural; `docs/audit/` lists where the code falls short of it. The vectors
let you build a verifier that disagrees with mine, the fork evidence is
verifiable without trusting the accuser, and `BUILD-LOG.md` lists what each
checkpoint got wrong before it got it right, which is a better guide to where
the bugs are than any assurance I could write.

## 7. What reviewers actually check

- [ ] Spec + byte-exact vectors, and a second implementation that passes them — written from the spec alone by someone who is not its author. `contrib/norn-ref` passes them but was written alongside the spec; the independent bar is the cold-model gate, whose run 13 passed every check and returned `SPEC SUFFICIENT WITH GAPS`
- [ ] A threat model that names what it does **not** defend (A4, A9, A10 are the honest ones)
- [ ] Measured numbers, not adjectives: watchdog window p99, revoke propagation, gossip convergence
- [ ] Reproducible demos, including the one where Norn *cannot* prevent the attack (D1c)
- [ ] Reuse of an existing ecosystem instead of a new island — an unmodified witness cosigns
- [ ] A running witness and status page a stranger can visit
- [ ] Prior art found *before* building, with the gap stated precisely
- [ ] The blockchain question answered with a scoring table, not a mood

Three of those eight are met today: the threat model, the prior art and the
scoring table. The witness line was met at checkpoint 4.4 on a developer's
machine: `internal/interop` runs an unmodified witness after `make witness`
and skips without it, CI included. It has not been re-run since
`internal/note` changed (6.5m-ii, 6.5m-v). The second implementation is Gate A's open line. The
numbers and the demos need the lab, and nothing runs for a stranger to visit.
That ratio is the argument for Gate B.

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
| the word "blockchain" attracts the wrong crowd and repels the right one | never in the tagline; anchoring is optional, advisory, and explained |
| scope creep into a control plane | non-goals in `PLAN.md`; endpoint providers stay untrusted for keys |
| nobody runs a witness for you | run three yourself; the design works with self-run witnesses and improves with shared ones |
| Tailscale ships gossip and witnesses in Tailnet Lock | good — cite it; Norn still covers the stacks Tailscale never will |
| publishing before Gate B | the numbers are the differentiator; adjectives would waste the one first impression |
