# Current Handoff

**Written:** 2026-09-30, with the documentation integrity pass that follows
`5b1f915`. Replace this file at the end of the next session; do not append to
it (`COWORKER.md` §21).

## Current focus

Norn. Two lines of work run side by side:

- **Phase 6, the cold-model gate on `SPEC.md`.** Run 13 returned `SPEC
  SUFFICIENT WITH GAPS`: 886/886 checks, 8 defects, none High
  (`SPEC-DEFECTS-13.md`). The `PLAN.md` gate line stays open. 6.5n-i to -iv
  are planned in the `BUILD-LOG.md` Phase 6 table.
- **The 2026-09-30 security audit** (`docs/audit/`). Its five tasks and the
  maintainer's decisions D-a to D-l are in `docs/audit/ROADMAP.md`. This
  session did its "Documentation integrity pass", which needs no decision,
  except for the three `SPEC.md` items listed in ROADMAP.

## Completed

Commits `37c253d..5b1f915`, oldest first:

- `87a5d32` 6.5l-v-a: a receipt is read by rule. Fourteen `receipts-bad/`
  vectors; SPEC §7 says what a holder MUST refuse (run 11 D4).
- `a62ebf6` 6.5l-v-b: every text cap counts bytes of UTF-8. Seven caps ship
  as pairs a character counter cannot tell apart (run 11 D6).
- `345806a` 6.5l-vi: a case's hint is `about`, `says` is placement, and a
  refusal's reason is not normative outside SPEC §5.2 (run 11 D10). Closed
  reason codes became decision D-k.
- `4f7732d` SEC-003, minimal half: `gossip.Peer` reads have a 10 s deadline
  and follow no redirect (`gossip.FetchTimeout`); `logclient.Submit` has a
  30 s deadline and still follows a redirect. Regression test:
  `TestASilentPeerDoesNotStallEnforcement` (`internal/agent`).
- `4348001` 6.5l-vii: cold-model gate run 12, `SPEC INSUFFICIENT`, 553/553,
  14 defects, one High (`SPEC-DEFECTS-12.md`).
- `f83018a` 6.5m-i: the policy grammar (run 12 D1, D10, D14). The fixture
  log is 130 entries, 88 of them refused.
- `dcdd6a4` 6.5m-ii: "a witness the policy names" is defined, and a
  signature line is exactly its payload's encoding (run 12 D2, D8).
- `bdb3086` 6.5m-iv: fork evidence in both directions (run 12 D4, D5, D7,
  D12). Fixes SEC-005 (a): `agent.writeEvidence` swaps the roles when the
  served branch is the longer one (`TestAForkOnTheLongerBranchStillLeavesEvidence`,
  `detect/fork-on-a-longer-branch`).
- `afde20f` 6.5m-v: the tail of run 12 (D6, D9, D11, D13).
- `be385d9` 6.5m-vi: cold-model gate run 13, `SPEC SUFFICIENT WITH GAPS`.
  6.5n planned.
- `5b1f915` `COWORKER.md` replaced by the maintainer's revised plan,
  verbatim. The first version is `docs/COWORKER-v1.md`, and every citation
  of its section numbers was repointed there.
- **The documentation integrity pass** (the commit that carries this file).
  It corrects README, PLAN, THREAT-MODEL, ENFORCEMENT, GOSSIP, ENROLLMENT,
  LAB, PUBLICATION, DECISIONS and the audit status lines; unticks five PLAN
  gate lines (14 → 9 of 38); records D-060–D-077; fixes four false code
  comments; and adds `SECURITY.md`, `CONTRIBUTING.md`, this file and
  `docs/upstream/OFFICIAL_PROJECT_CHECKLIST.md`.

## In progress

None. 6.5n-i is designed and not started (next action 2): `130-bad-repeated-sig`
(a `revoke` of `pi-cam` by the two current signers with one `sigs` element
duplicated), `131-bad-enroll-by-roots` (`halfsigned`, three roots, no
signers), `132-bad-rotate-by-roots` (`printer` to the free `rogue` key under
`rotate_needs_signer`), and `fork/bad-size-mismatch` rebuilt from the honest
40-entry head with a correct proof at 41, so only the size equality refuses it.

## Important decisions

- **SEC-001 is documented, not fixed** (D-a, current choice (iii), taken by
  the maintainer). `THREAT-MODEL.md` A2 says G3 does not hold against a
  malicious log operator until it is fixed.
- **SEC-003's structural half is deferred** to ROADMAP task 1: reconcile
  before peer I/O, and a cycle-overrun alarm.
- **6.5m-iii is held for D-l**, which policy computes a checkpoint's `T`
  (`BUILD-LOG.md` "Decision needed — 6.5m-iii"). Run 13's D1 raised it again.
- **`COWORKER.md` is the maintainer's text and is not edited.** Where its plan
  differs from what this repository has recorded, the facts are below. Nothing
  was changed to follow either side.

**Where `COWORKER.md` differs from what is recorded:**

- §11 says "Evaluate Tessera as infrastructure". D-049 evaluated it at 2.3 and
  deferred it: Tessera pulled 135 modules against the project's 3. Instead,
  `internal/tlogstore` writes tlog-tiles itself using `x/mod/sumdb/tlog`. D-049
  records when to adopt Tessera: when the log outgrows one directory, needs
  more than one writer, or needs a cloud backend.
- §10 lists eight events. SPEC §4.3 has 14 entry types: `genesis`, `enroll`,
  `rotate`, `revoke`, `signer_add`, `signer_remove`, `signer_thr`, `root_add`,
  `root_remove`, `root_thr`, `params`, `note`, `log_key`, `policy`. Authority
  has two roles with thresholds (D-007). SPEC has no `WG_KEY_BIND` and no
  `WG_KEY_REVOKE`. `enroll` binds the WireGuard key inside the device's request
  (D-057), `rotate` replaces it, and it ends with the device's `revoke`.
  Ordering comes from the log index plus an optional `after` lower bound
  (§4.4). No entry names the state it replaces; the audit lists this as a
  protocol ambiguity.
- §13 proposes `max_checkpoint_age`, `offline_grace_period`, `fail_mode` and
  STRICT/BALANCED/OFFLINE profiles. SPEC §8.1 has none of these. It has `S`,
  which is `params.staleness` (the network's, set in the log, default 600 s),
  and `S_hard`, which is the node's own (`nornd -hard-stale` or `hard_stale`,
  off by default). The four states are `unknown`, `fresh`, `hard_stale` and
  `degraded`, read top to bottom. By default a stale node keeps its
  last-known-good peers and alarms. Failing closed is opt-in through
  `S_hard`.
- §22 puts ADRs in `docs/decisions/`. This repository keeps one
  `DECISIONS.md`: what, why and rejected, newest at the bottom, superseded and
  never deleted. Most of §22's example ADRs already have an entry: ADR-001 is
  D-013, ADR-002 D-008, ADR-003 D-003 and D-049, ADR-004 D-027, ADR-005 D-007
  and D-028, ADR-006 D-004 (full replication and replay, no authenticated
  map), ADR-007 D-018 (amended by D-069) and D-034, ADR-008 D-017 (superseded by
  D-062), and ADR-009 D-013 and D-059.
- §15 asks for `wgctrl-go` to be compared against `wg`, UAPI and netlink in an
  ADR. D-059 does this. `internal/wgdev` wraps `wgctrl`, and
  `internal/depgraph` asserts that the CLI, `norn-log` and the enforcement
  packages do not import either one. `internal/wgdev` has never run against a
  real interface.
- §7's invariant holds only in owner mode. Observe, the default (D-005),
  installs and removes nothing. Watchdog removes a peer after the fact
  (THREAT-MODEL G1 and §5).
- §8 says Norn does not protect against "compromise of sufficient witness
  quorum". For a split view the bound is 2k−N colluding witnesses, not k, so
  one witness is enough under 2-of-3 (SEC-002, D-b).
- §4, §5 and §20 name eleven `docs/upstream/` files. Only
  `OFFICIAL_PROJECT_CHECKLIST.md` exists, and it was added in this pass. The
  repository records no upstream research, so `CONTRIBUTION_TRACKER.md` and the
  per-track files were not created (§4: "do not create empty documentation
  for appearance").
- §23's first assignment: the first plan's §36 assignment produced
  `docs/audit/` (`37c253d`). The six output headings §23 asks for have not
  been written.
- §1 describes Norn as "a coordinator-independent trust and key-transparency
  layer". The README's tagline is "Certificate Transparency for your WireGuard
  peer table", and `internal/docclaims` checks that tagline against
  `PUBLICATION.md`.
- §9's identity model agrees with D-008, and §12's "locally replayed
  deterministic state" is what D-004 chose.

## Open security questions

- **CRITICAL.** SEC-001: deferred, D-a. SEC-002: open, D-b and D-c.
- **HIGH.** SEC-003: bounded by `4f7732d`, structural half open. SEC-004:
  open.
- **MEDIUM.** SEC-005 (b) and (c) are open: `forkevidence.Check` takes one log
  key and one policy. SEC-006 to SEC-015 are open.
- **LOW.** SEC-016 to SEC-036 are open. SEC-027 and SEC-032 are partly
  addressed by `dcdd6a4`, `87a5d32` and `f83018a` (`docs/audit/SECURITY_AUDIT.md`).
- **Decisions D-a to D-l**, all the maintainer's: SEC-001 identity (a),
  quorum bound and default policy (b), gossip cadence (c), log-key retirement
  (d), the evidence policy (e), label name and CIDR form (f), a node's own key
  (g), Ed25519 semantics and empty `labels` (h), privacy model (i),
  enforcing under `quorum none` (j), closed reason codes (k), and which policy
  computes `T` (l). See `docs/audit/ROADMAP.md`.

## Blockers

- D-l blocks 6.5m-iii and the PLAN cold-model gate line.
- D-b and D-c block ROADMAP task 3. D-e blocks part of task 4. D-f and D-g
  block owner mode on real interfaces.
- There is no lab: `lab/` and `demo/` do not exist (`LAB.md`). Every Phase 3–5
  lab gate is open, and every enforcement test runs against `peertable.Fake`.
- Two Phase 6 gates need people from outside this repository: an outside
  lab run, and a review of the comparison table.
- The ROADMAP says `PUBLICATION.md` Gate B should wait for task 1's
  structural half, tasks 2 and 5, D-a and this pass.

## Exact next actions

1. Confirm GitHub Actions is green on the documentation-pass commit.
2. 6.5n-i as designed above: vectors for run 13's D2, D3 and D4, each
   differing from a valid artifact in one way, with Go and Python mutation
   controls (Go `internal/entry/decode.go` `sig.Kid <= previous`, Python
   `replay.py` line 99; the `enroll` signer count at `internal/replay/handlers.go`
   and `replay.py` line 190). Then 6.5n-ii, 6.5n-iii, and run 14 (6.5n-iv).
3. The maintainer decides D-l. Then D-a, and D-b with D-c.
4. ROADMAP task 1's structural half (SEC-003, SEC-013), then task 2 (SEC-004,
   SEC-006) and task 5 (SEC-008), each starting with the regression test the
   ROADMAP names.
5. When the repository is made public, enable GitHub private vulnerability
   reporting. `SECURITY.md` depends on it.

## Files changed

- **Committed, `37c253d..5b1f915`** (210 files): `SPEC.md`, `BUILD-LOG.md`,
  `PLAN.md`, `README.md`, `THREAT-MODEL.md`, `ENFORCEMENT.md`, `Makefile`,
  `SPEC-DEFECTS-12.md`, `SPEC-DEFECTS-13.md`, `COWORKER.md`,
  `docs/COWORKER-v1.md`, and `docs/audit/`. Go changes are in
  `internal/{agent,gossip,logclient,note,policy,receipt,replay}` and in tests
  across 15 packages. Python changes are in
  `contrib/norn-ref/nornref/{fixture,note,policy,replay}.py`,
  `contrib/norn-ref/gen_vectors.py` and the reference's tests. Also changed:
  `cmd/norn-genlog`, `contrib/ots-vector/generate.py`, and
  `testdata/vectors/` (26 directories, plus `README.md`, `SHA256SUMS` and
  `state.json`).
- **The documentation integrity pass:** new files `docs/HANDOFF.md`,
  `docs/upstream/OFFICIAL_PROJECT_CHECKLIST.md`, `SECURITY.md` and
  `CONTRIBUTING.md`. The pass also changes `BUILD-LOG.md`,
  `DECISIONS.md`, `ENFORCEMENT.md`, `ENROLLMENT.md`, `GOSSIP.md`, `LAB.md`,
  `PLAN.md`, `PUBLICATION.md`, `README.md`, `THREAT-MODEL.md`,
  `Makefile` (a comment), `cmd/norn/doc.go`, `cmd/norn-witness/doc.go`,
  `internal/wg/doc.go` and `internal/agent/agent.go` (comments only) and
  `docs/audit/*.md`.

## Tests run

- **CI.** The GitHub Actions `ci` workflow (`.github/workflows/ci.yml`) runs
  `make ci` and `make lint` on ubuntu-latest and macos-latest, and
  `make ref-test` and `make vectors-check`. It reported success for every
  pushed commit from `37c253d` (run 12) to `5b1f915` (run 23), checked
  2026-09-30. That evidence is on GitHub. `BUILD-LOG.md` records the rule that
  a ✅ checkpoint had a green suite, but it does not record the CI runs.
- **This pass.** `make ci` (gofmt, vet, `go test -race ./...`) ran locally
  in a clean worktree of the commit before it was pushed; `internal/docclaims`
  and `internal/specdoc`, which read these documents, pass.

## Upstream workstreams affected

None. The repository records no upstream research, and no WireGuard project
was contacted. Every `COWORKER.md` §3 track is untouched.
