# Norn — Roadmap after the first audit

**Date:** 2026-09-30 · from `SECURITY_AUDIT.md` and `PROJECT_STATUS.md`.
**Updated:** 2026-09-30, for the commits after the audit (`37c253d..5b1f915`).
This replaces nothing in `PLAN.md`; it says what the audit changes about
the order of work, and which items are the maintainer's to decide.

## The five tasks to do next

Ordered by what the audit found, not by phase. Each closes at least one
HIGH or CRITICAL, or unblocks one. Each names the regression test that is
its first deliverable, in the project's own style: prove the failure,
then the fix.

### 1. Bound every network read on the node and monitor (SEC-003, SEC-013)

The one finding four auditors hit independently, and the cheapest to
make safe. First, the minimal change: a dedicated `http.Client` for
`gossip.Peer` and the monitor with `Timeout`, `ResponseHeaderTimeout`, a
byte budget and `CheckRedirect` returning an error, plus a timeout on
`logclient.Submit`. That turns "forever" into "bounded" and needs no
design decision. **Done 2026-09-30 in `4f7732d`:** every `gossip.Peer`
read, the monitor's included, goes through a client with a 10 s deadline
(`gossip.FetchTimeout`), the same `ResponseHeaderTimeout` and a
`CheckRedirect` that refuses; `logclient.Submit` shares `HTTP.Fetch`'s
30 s `logclient.Timeout` and sets no `CheckRedirect`, so it still
follows a redirect; the byte budgets (`maxFetch`,
`logclient.MaxFetchBytes`) predate the audit. Tests: a silent, a
trickling and a redirecting peer (`internal/gossip`), a silent log on
submission (`internal/logclient`), and a watchdog cycle with three
silent peers that returns and evicts (`internal/agent`). **Open:** the
structural change — reconcile against the last good state *before* any
peer or evidence I/O, or move verification and gossip onto their own
goroutine that publishes a verified result to a reconciler ticking on
T_poll; add a cycle-overrun alarm and the latency histogram ENFORCEMENT
§4 already promises. Until then every ask of a silent peer costs a cycle
up to 10 s before it reconciles (`askPeers` and `pollEvidence` each ask
up to r), and a peer that answers each read just inside the deadline
costs 10 s per file `logclient.Verify` fetches. Tests: a peer that
accepts and never answers, a slow-loris peer, a slow log — each
asserting an injected key is still evicted within the documented bound
and the monitor round completes; of these, only the silent peer is
asserted at the node today. `4f7732d` gave THREAT-MODEL A6 and
ENFORCEMENT's watchdog window the r × 10 s term; update A6 and G4 again
when the structural half lands.

### 2. Make node state durable (SEC-004, SEC-006)

Persist the adopted signed checkpoint, the held tree or mirror, the
newest quorum time and the fork freeze in a durable state directory
(`/var/lib/norn`, systemd `StateDirectory`), separate from `/run`. Load and
re-verify them in `agent.New`; pass them as `Stored`/`Held`; restore learned
keys and policy by replaying the mirror; seed the clock conservatively
(start stale until a head at least as new as the persisted one is seen);
let a restarted node use the persisted proven set for peers and, in owner
mode, enforce it at boot. Specify what a node MUST persist in SPEC
§10/§11. Tests: restart-rollback refused and not `fresh`; freeze survives
a wipe of `/run`; learned policy survives. Correct THREAT-MODEL A5 and
untick PLAN:186 until then.

### 3. Restore split-view detection and fix the witness bound (SEC-002, SEC-007)

Every T_g, fetch only `/norn/checkpoint` from r proven peers regardless of
freshness; verify signature and quorum; compare with the held head; fetch
tiles only on a larger head or a different root. Have the monitor compare
each node's head with the log's and its previous view. Correct G2/A9 to
the 2k−N quorum-intersection bound; have `trust.Validate` and genesis
refuse or warn on policies whose quorums need not intersect, stating the
liveness trade-off. Test: the one-colluding-witness probe from the audit,
both nodes fresh, detected within 2·T_g. If the maintainer instead keeps
peers-only-when-stale, supersede D-016 and correct GOSSIP §2/§6/T1 and
PLAN:183 — but the fix is cheap and the pollEvidence rate-limit already
exists to hang it on.

### 4. Make fork evidence always producible and checkable (SEC-005)

Swap roles when the conflicting head is longer — **done 2026-09-30 in
`bdb3086`** (6.5m-iv, SEC-005 (a)): `agent.writeEvidence` builds with the
served head as `held` and its stored head as `conflicting` at the stored
size, and `TestAForkOnTheLongerBranchStillLeavesEvidence` and
`detect/fork-on-a-longer-branch` hold it. **Open:** give
`forkevidence.Check` a key set (trust key plus learned keys) and the
node's current policy (SEC-005 (b) and (c)); persist a freeze marker even
when evidence cannot be built; run `Check` in `loadFreeze`; write evidence
atomically (both writers in `internal/agent/fork.go` use `os.WriteFile`).
Resolve SPEC §11.1's "the trust file's, or one it has replayed" for nodes
(D-e). Tests: rotated key, raised policy. In the same change, attribute
cosignatures by verifier key (SEC-009) and validate keys inside in-log
`policy` entries (SEC-032), since they touch the same code. Since
`f83018a` (6.5m-i) replay refuses, as `decode`, a `policy` entry whose
`witness` key is not a cosignature key
(`log/129-bad-policy-witness-key-not-a-cosigner`); its `log` line's key
is not checked.

### 5. Ship the entry builders, or say they do not exist (SEC-008)

`norn revoke` (signer, root, `--self`), `norn rotate` (with `after` set by
default) and a governance builder (signer/root add, remove, threshold;
`log_key`; `policy`; `params`; `note`), all through the existing sign/submit
flow with its summary, confirm, `after`-guard and self-verify discipline,
refusing `-yes` for root. End-to-end tests against `norn-log`. This is the
gap that turns HIGH the day Norn is declared deployable. The cheap first
step, doable today: state in README, ENROLLMENT §4–5, `cmd/norn/doc.go`
and D-055 that only `enroll` is supported, and add the builders to the
PLAN gates.

## Decisions that are the maintainer's

These change the protocol, a recorded decision, or a public claim. Under
`docs/COWORKER-v1.md` §34 and the project's own rule they are not made inside a
fix.

| # | Decision | Options on the table | Blocks |
|---|---|---|---|
| D-a | **SEC-001** entry identity for de-duplication | (i) key the seen set on the signature preimage — smallest change, regenerates `log/`, burns the preimage of an under-signed entry; (ii) bind entries to their position (`after` required, or a prev-hash) — bigger redesign, breaks the offline enrollment flow; (iii) document only (current choice, 2026-09-30) | the core invariant against A2; the SEC-001 row in THREAT-MODEL |
| D-b | Witness quorum bound and default policy | (G2/A9 now state the 2k−N bound) refuse or warn on non-intersecting quorums; homelab default 3-of-3 (loses liveness on one witness down) or 3-of-4 | task 3 |
| D-c | Gossip cadence | implement GOSSIP §2/§6 as written, or supersede D-016 and downgrade T1 | task 3 |
| D-d | Log-key retirement (SEC-014) | verifier-side expiry (since_index + overlap in witness time, plus a `log_key_revoke` entry), or state that rotation is not revocation and rewrite R7 | ENROLLMENT R7, SPEC §4.3/§16.3 |
| D-e | Which policy a replayed node uses for evidence (§11.1) | the replayed one (matches §9.4's rationale) | task 4 |
| D-f | Reserved label name and CIDR canonical form (SEC-018/019) | `ip` per SPEC/D-026, `allowed_ips` as a deprecated alias; reject unmasked and 4-in-6 prefixes | owner mode on real interfaces |
| D-g | Whether a node excludes its own key from the desired set (SEC-012) | yes, read it from the interface | owner mode on real interfaces |
| D-h | Ed25519 verification semantics and key validity (SEC-023); empty `labels` (SEC-022) | RFC 8032 cofactorless with canonical A/R, or ZIP-215; `labels: {}` is `decode` or preserved | Python/Go agreement; vectors |
| D-i | Privacy model vs COWORKER-v1 §13 | record the "public log, opaque origin, readable labels" choice and the alternatives rejected | DECISIONS |
| D-j | Whether `nornd` may enforce under `quorum none` / 1-of-1 (GOSSIP §3) | refuse, require an override flag, or document | SEC-033 |
| D-k | Closed reason codes for every refusing layer (cold gate run 11, D10) | (i) lists in §5.2's style for §7, §8.1, §9.1, §11.1 and §16, with `cases.json` naming codes — makes check order observable and lets two nodes triage a §11 rule-4 freeze together; (ii) `about` as a non-normative hint (current choice, 6.5l-vi) | cross-implementation triage of a permanent refusal |
| D-l | Which policy computes a checkpoint's `T` (cold gate runs 12 D3 and 13 D1; `BUILD-LOG.md` "Decision needed — 6.5m-iii") | (i) the policy the head was accepted under — what the suite pins and the code does, `T` depends on history for one poll after a policy change; (ii) the policy in force after replay — `T` a function of the head alone, changes `proofs/cases.json`, `proven/` and both verifiers | 6.5m-iii and the PLAN cold-model gate line; who is admitted at an expiry boundary after a policy change |

## Documentation integrity pass (no decision needed)

**Done 2026-09-30**, in the commit that adds `docs/HANDOFF.md`, except the
`SPEC.md` items (the §4.3 blank line, now `SPEC.md:309`; torchwood named in
§6 and §10; the title) and the builder gate lines task 5 asks for in PLAN.
The list is kept as the record of what was stale:

- THREAT-MODEL: A5 restart caveat; A6 gossip row; A7 key-substitution row;
  G1 "in enforce mode"; G2/A9 pending D-b.
- README: G1 qualifier; the comparison row by mode; Headscale as planned
  observe-only and unimplemented; `norn verify` prints replay status, not
  the proven set; the claim that vectors include transparency-dev/witness
  bytes.
- ENFORCEMENT:134 "Norn today" → planned; §8 rows for restart-during-outage,
  frozen-node eviction, unresponsive peer; §4/§9 metrics and
  `reconcile.json` marked not implemented.
- GOSSIP §3 (`norn-witness`), §6 (`POST /norn/hint`), §5 (`norn status`
  prints age), §2/§6 pending D-c.
- ENROLLMENT §4–5 and `cmd/norn/doc.go`: which commands exist.
- PLAN: untick :154, :163, :172, :183, :186, :198 or annotate; refresh the
  DECISIONS index, fixed decisions and layout.
- DECISIONS: superseding entries for D-011, D-026, and the Phase 4–6
  choices that live only in BUILD-LOG.
- SPEC: the blank line at :296; torchwood references; the "v0 (draft)"
  title.
- Add `SECURITY.md` and `CONTRIBUTING.md`.

## Known defects outside the audit

Found after the audit, recorded here so they are not lost; none changes who
is admitted.

- `norn monitor` never hands its status page a verified result
  (`cmd/norn/monitor.go` sets `status.Alerts` only), so the page never shows
  devices, and its proof links lead back to the page itself (`LAB.md` §3).
- `norn monitor` does not call four of the rules `internal/monitor`
  implements and tests: the receipt inbox, `WitnessQuorum`, `AnchorLag`, and
  a node's own events (`LAB.md` §3; PLAN's Monitor and D1 lines).
- `receipt.Check` compares `int64(deadline) <= now.Unix()`, so a deadline
  above 2^63 wraps negative and reads as expired; the monitor's late flag uses
  the same arithmetic (`BUILD-LOG.md` 6.5l-v-a).

## Where this leaves the existing plan

`PLAN.md`'s Phase 6 (the cold-model gate on `SPEC.md`) continued beside
the audit, and 6.5l and 6.5m have landed except 6.5m-iii. 6.5l-v-a, -v-b
and -vi (`87a5d32`, `a62ebf6`, `345806a`) closed run 11's D4, D6 and
D10. Run 12 (6.5l-vii, `4348001`) returned `SPEC INSUFFICIENT`: 553/553
checks, 14 defects, one High (`SPEC-DEFECTS-12.md`). 6.5m-i, -ii, -iv
and -v (`f83018a`, `dcdd6a4`, `bdb3086`, `afde20f`) closed thirteen of
them; 6.5m-iii, run 12's D3, waits on D-l. Run 13 (6.5m-vi, `be385d9`)
returned `SPEC SUFFICIENT WITH GAPS`: 886/886 checks, 8 defects, none
High (`SPEC-DEFECTS-13.md`). 6.5n is next and planned, not started: -i
to -iii for run 13's D2–D8, -iv for run 14 (`BUILD-LOG.md` checkpoint
table). The PLAN gate line stays open until a run returns `SPEC
SUFFICIENT`: 6.5n-i to -iii for run 13's D2–D8, run 14 as 6.5n-iv, and D-l
for run 13's D1. Nothing in this audit lowers the value of that work: the byte and
crypto layers it hardens are the layers the audit found sound. What the
audit adds is that **Phase 3's lab gates are where the next real
findings are**. Every enforcement-path defect above (SEC-003, SEC-004,
SEC-012, SEC-013, SEC-019) is invisible to `peertable.Fake` and would
have been found by one day against a real interface. A Linux CI job that
creates a WireGuard link in a netns and runs one owner and one watchdog
cycle is the single test that would have caught the most.

Publication (`PUBLICATION.md` Gate B) should wait for tasks 1 (its
structural half), 2 and 5 at minimum, a decision on D-a, and the
documentation pass. Gate A (a verifier from `SPEC.md` alone) waits on
6.5n and D-l, and on none of tasks 1–5.
