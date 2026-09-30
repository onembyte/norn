# Norn — Roadmap after the first audit

**Date:** 2026-09-30 · from `SECURITY_AUDIT.md` and `PROJECT_STATUS.md`.
This replaces nothing in `PLAN.md`; it says what the audit changes about
the order of work, and which items are the maintainer's to decide.

## The five tasks to do next

Ordered by what the audit found, not by phase. Each closes at least one
HIGH or CRITICAL, or unblocks one. Each names the regression test that is
its first deliverable, in the project's own style: prove the failure,
then the fix.

### 1. Bound every network read on the node and monitor (SEC-003, SEC-013)

The one finding four auditors hit independently, and the cheapest to make
safe. First, the minimal change: a dedicated `http.Client` for
`gossip.Peer` and the monitor with `Timeout`, `ResponseHeaderTimeout`, a
byte budget and `CheckRedirect` returning an error, plus a timeout on
`logclient.Submit`. That turns "forever" into "bounded" and needs no
design decision. Then the structural change: reconcile against the last
good state *before* any peer or evidence I/O, or move verification and
gossip onto their own goroutine that publishes a verified result to a
reconciler ticking on T_poll; add a cycle-overrun alarm and the latency
histogram ENFORCEMENT §4 already promises. Tests: a peer that accepts and
never answers, a slow-loris peer, a slow log — each asserting an injected
key is still evicted within the documented bound and the monitor round
completes. Update THREAT-MODEL A6 and G4 to match whichever half lands.

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

Swap roles when the conflicting head is longer; give `forkevidence.Check`
a key set (trust key plus learned keys) and the node's current policy;
persist a freeze marker even when evidence cannot be built; run `Check`
in `loadFreeze`; write evidence atomically. Resolve SPEC §11.1's "the
trust file's, or one it has replayed" for nodes. Tests: longer branch,
rotated key, raised policy. In the same change, attribute cosignatures by
verifier key (SEC-009) and validate keys inside in-log `policy` entries
(SEC-032), since they touch the same code.

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
`COWORKER.md` §34 and the project's own rule they are not made inside a
fix.

| # | Decision | Options on the table | Blocks |
|---|---|---|---|
| D-a | **SEC-001** entry identity for de-duplication | (i) key the seen set on the signature preimage — smallest change, regenerates `log/`, burns the preimage of an under-signed entry; (ii) bind entries to their position (`after` required, or a prev-hash) — bigger redesign, breaks the offline enrollment flow; (iii) document only (current choice, 2026-09-30) | the core invariant against A2; the SEC-001 row in THREAT-MODEL |
| D-b | Witness quorum bound and default policy | correct G2/A9 to 2k−N; refuse or warn on non-intersecting quorums; homelab default 3-of-3 (loses liveness on one witness down) or 3-of-4 | task 3 |
| D-c | Gossip cadence | implement GOSSIP §2/§6 as written, or supersede D-016 and downgrade T1 | task 3 |
| D-d | Log-key retirement (SEC-014) | verifier-side expiry (since_index + overlap in witness time, plus a `log_key_revoke` entry), or state that rotation is not revocation and rewrite R7 | ENROLLMENT R7, SPEC §4.3/§16.3 |
| D-e | Which policy a replayed node uses for evidence (§11.1) | the replayed one (matches §9.4's rationale) | task 4 |
| D-f | Reserved label name and CIDR canonical form (SEC-018/019) | `ip` per SPEC/D-026, `allowed_ips` as a deprecated alias; reject unmasked and 4-in-6 prefixes | owner mode on real interfaces |
| D-g | Whether a node excludes its own key from the desired set (SEC-012) | yes, read it from the interface | owner mode on real interfaces |
| D-h | Ed25519 verification semantics and key validity (SEC-023); empty `labels` (SEC-022) | RFC 8032 cofactorless with canonical A/R, or ZIP-215; `labels: {}` is `decode` or preserved | Python/Go agreement; vectors |
| D-i | Privacy model vs COWORKER §13 | record the "public log, opaque origin, readable labels" choice and the alternatives rejected | DECISIONS |
| D-j | Whether `nornd` may enforce under `quorum none` / 1-of-1 (GOSSIP §3) | refuse, require an override flag, or document | SEC-033 |
| D-k | Closed reason codes for every refusing layer (cold gate run 11, D10) | (i) lists in §5.2's style for §7, §8.1, §9.1, §11.1 and §16, with `cases.json` naming codes — makes check order observable and lets two nodes triage a §11 rule-4 freeze together; (ii) `about` as a non-normative hint (current choice, 6.5l-vi) | cross-implementation triage of a permanent refusal |

## Documentation integrity pass (no decision needed)

Doable now, in one change, and worth doing before any of the above so the
documents stop claiming what the code does not do:

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

## Where this leaves the existing plan

`PLAN.md`'s Phase 6 (the cold-model gate on `SPEC.md`) continues in
parallel — 6.5l-v and 6.5l-vi are in flight and run 12 follows. Nothing in
this audit lowers the value of that work: the byte and crypto layers it
hardens are the layers the audit found sound. What the audit adds is that
**Phase 3's lab gates are where the next real findings are**. Every
enforcement-path defect above (SEC-003, SEC-004, SEC-012, SEC-013, SEC-019)
is invisible to `peertable.Fake` and would have been found by one day
against a real interface. A Linux CI job that creates a WireGuard link in
a netns and runs one owner and one watchdog cycle is the single test that
would have caught the most.

Publication (`PUBLICATION.md` Gate B) should wait for tasks 1, 2 and 5 at
minimum, a decision on D-a, and the documentation pass. Gate A (a
verifier from `SPEC.md` alone) is close and is not blocked by any of this.
