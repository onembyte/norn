# Norn — review, verdict and operating instructions for the next builder

*Written 2026-10-07 by a review pass over the whole repository (documents, Go
and Python code, vectors, gate reports, and the uncommitted working tree).
Audience: Opus 5.5 running the build loop. Every claim below names the file it
was checked in. Nothing here was taken from a document's own description of
itself when the code could be read instead.*

---

## 0. How to use this file

- This file does **not** replace `BUILD-LOG.md`, which stays the ledger. It
  adds findings, a ranked work queue and guardrails. When a row from §4 is
  started, copy it into the `BUILD-LOG.md` table, subdivide it there, and tick
  it there.
- Read §5 (guardrails) before touching anything. Each rule names the incident
  in this repository that made it a rule.
- §6 has the verification recipes. A fix without its recipe run is not done.

---

## 1. Verdict: is this worth real-life work?

**Yes — conditionally, and the conditions are specific.**

What is genuinely strong (verified, not asserted):

| Strength | Where it is verified |
|---|---|
| The gap is real. No open system gives WireGuard peers a witnessed key-transparency log, gossip over the tunnel, external witnesses and no-TOFU bootstrap together. Tailnet Lock is Tailscale-only and admits the freeze attack in its own whitepaper; Headscale #1432 is open; Nebula shipped CVE-2026-61699 on exactly the "silent revocation loss" failure Norn turns loud. | `PRIOR-ART.md`, sources at its foot |
| The failure direction is right everywhere it matters: a failure never widens and never empties the peer table; observe is the default; `hard_stale` is opt-in twice; a proven fork freezes the node and survives restart. | `internal/agent/agent.go` (package comment, `Once`), `internal/agent/fork_test.go:167` |
| Two independent implementations (Go, Python standard-library + pynacl) must produce byte-identical vectors and `state.json`; the build checks it (`make vectors-check`). | `Makefile`, `contrib/norn-ref/`, CI `reference` job |
| 880 Go tests, race-enabled, on Linux in CI and on macOS locally (the macOS runner was dropped on 2026-10-07 under the owner's Actions-budget rule); two fuzz targets; architecture tests that forbid the kernel driver outside `nornd`. | `.github/workflows/ci.yml`, `internal/depgraph/`, `internal/cbor/fuzz_test.go`, `internal/replay/fuzz_test.go` |
| C2SP formats verbatim, so an unmodified `transparency-dev/witness` can cosign (format half proven: `make witness`, 2.6a). | `PLAN.md` fixed decisions, `GOSSIP.md` §3 |
| Witness time is the node's clock; the wall clock can only raise `CLOCK_SKEW`. This is subtle and correct (A11). | `internal/agent/agent.go:705`, `internal/freshness/` |
| Four cold-model gate runs by fresh agents on sealed copies, each audited from its transcript, each finding real defects; the fixes are vectors with controls, not prose. | `SPEC-DEFECTS-10..13.md`, `BUILD-LOG.md` 6.5k–6.5l |
| Dependencies are tiny: `x/mod`, `x/crypto`, `wgctrl`, `transparency-dev/formats`, `BurntSushi/toml`, `rsc.io/qr`. | `go.mod` |

What stops it being deployable today (verified):

1. **No Norn has ever guarded a network.** 14 of 38 `PLAN.md` gate lines are
   ticked; every lab, measurement and second-person line is open; `lab/` and
   `demo/` are empty directories; there is no Dockerfile, no systemd unit, no
   package. The README says so honestly (status line) — keep it that way.
2. **Validation effort is lopsided.** Roughly nine tenths of the rigour went
   into the spec/vector/replay layer. The node-on-a-kernel half (`wgdev`,
   `nornd`'s loop, gossip in the field) has unit tests against fakes and one
   test that runs "if a real interface exists", which CI never has.
3. **Three production bugs found by reading `nornd`'s path** — §2, F1–F3.
   None is visible in the test suite because the suite drives `Once()` by
   hand, never the daemon loop against a slow or hung network.
4. **Run 13 returned `SPEC INSUFFICIENT`**, with two protocol-level holes
   (open `rotate`/`revoke` bodies re-key a device; no stated verification key
   for bundles and receipts after a log-key rotation). Both are small to fix;
   neither is fixed yet.
5. **174 files, +5,299/−990 lines are uncommitted** in the working tree as of
   this review (the d-v … d-xii-v rows and run 13). The Go suite passes on it;
   nothing of it is pushed. That is five days of work one `git checkout` from
   gone.

**The realistic path to "real life":** fix F1–F3, land the pile, then run
Norn in **observe mode** on the homelab's real WireGuard mesh for a week. That
first deployment needs no lab, no witness network and no enforcement — it is
exactly what D-005 prescribes — and it will produce the first measured numbers
this project has. Enforce mode comes after the lab exists.

---

## 2. Findings (F1–F12), each with evidence and the fix

Severity: **H** = can admit or drop a peer wrongly in the field; **M** = can
stop the node doing its job or will not scale; **L** = maintenance / honesty.

### F1 (H) — a restarted node has no rollback protection on its first cycle
- **Evidence.** `internal/agent/agent.go:207` `New()` calls only `loadFreeze()`
  (`fork.go:43`), which restores a proven fork and nothing else. `a.last` is
  nil until the first successful verify, so `Once()` builds the anchor with
  `Stored: nil, Held: nil` (`agent.go:279–308`). `logclient.Verify` applies
  §10's "`cp.size ≥ stored.size`, compare branches" only when `Stored != nil`
  (`internal/logclient/client.go`, `checkAgainstStored`).
- **Consequence.** A restarted node accepts **any** correctly signed and
  cosigned checkpoint, including one older than the one it enforced before
  the restart. An attacker who can serve an old legitimate head at that moment
  (A2 log operator, A5 on-path to the log, or a lying peer — all in the threat
  model) rolls the proven set back and un-revokes every device revoked since.
  The mirror the node wrote every cycle (`internal/mirror`, under `RunDir`)
  already holds the last verified checkpoint and entries; the daemon simply
  does not read it back.
- **Fix.** On start, if `RunDir/mirror/checkpoint` exists: verify it under the
  anchor (`logclient.Verify` over `logclient.Dir(mirror)`), and seed `a.last`
  from the result so `Stored`/`Held` are set before the first fetch. A mirror
  that fails to verify is reported and ignored (it is not the enforced state).
  `ENFORCEMENT.md` §8 / `SPEC.md` §13.2 should say the stored head survives a
  restart.
- **Acceptance.** A test in `internal/agent`: verify a 20-entry log, construct
  a new `Agent` over the same `RunDir`, serve a cosigned 10-entry head of the
  same log; the first `Once()` must refuse it as `rollback` and keep the
  20-entry proven set. Control: delete the seeding and watch that test fail.

### F2 (M) — peer gossip fetches have no timeout; a hung peer stalls enforcement
- **Evidence.** `internal/gossip/server.go:111` `Peer.Fetch` uses `http.Get`,
  i.e. `http.DefaultClient`, which has **no timeout**. `askPeers`
  (`agent.go:665`) runs inside `Once()`, which the daemon loop calls
  synchronously (`cmd/nornd/main.go:254`). A proven peer that accepts TCP and
  never answers (asleep laptop, dropped route, a half-open connection) blocks
  the cycle indefinitely; while it is blocked, a watchdog node evicts nothing.
  The log fetcher does have a 30 s timeout (`internal/logclient/http.go:37`),
  but `Verify` makes one request per bundle and per tile, so a slow log can
  still hold one cycle for minutes.
- **Fix.** A `gossip` client with `Timeout` (a few seconds — it is a tunnel
  neighbour) and a per-round budget; a per-`Verify` budget for the log
  fetcher (context with deadline threaded through `Fetcher`). Reconciliation
  must never wait on the network: if the round overruns, reconcile on `a.last`
  and report `PEER_REFUSED`/`VERIFY_FAILED`.
- **Acceptance.** A test with a `Fetcher`/peer that blocks forever on one
  path; `Once()` returns within the budget and the fake peer table was still
  reconciled.

### F3 (M) — every cycle re-downloads and replays the entire log, 5× per second
- **Evidence.** `cmd/nornd/config.go:236` `DefaultPoll = 200 ms`; the loop
  calls `cycle.Once()` every poll (`main.go:254`); `Once()` always calls
  `logclient.Verify` (`agent.go:321`), which fetches the checkpoint, **every**
  entry bundle, rebuilds the tree, replays every entry and fetches **every**
  hash tile (`client.go:169–219`). There is no "checkpoint bytes unchanged →
  skip" path (grep for `SignedCheckpoint ==`, cache, ETag: none). With 138
  entries this is invisible; at 10⁴ entries and 50 nodes it is a self-inflicted
  DoS on the log and on each node's CPU. `ENFORCEMENT.md` §4 separates
  "every `T_poll`: diff the table" from verification; the daemon does not.
- **Fix.** (a) Fast path: fetch only `checkpoint`; if the bytes equal
  `a.last.SignedCheckpoint`, skip fetch and replay, re-read freshness from the
  clock, reconcile. (b) Incremental path: when the head grew, fetch only the
  bundles and tiles the new size implies beyond the stored size, verify
  consistency with the held tree, replay only the new entries onto the held
  state (replay is a pure fold — `internal/replay`). (c) Separate cadences:
  reconcile on `T_poll`, re-verify the head on its own interval (default a few
  seconds) and on every gossip round.
- **Acceptance.** A counting `Fetcher`: 50 cycles over an unchanged log make
  50 checkpoint requests and 0 bundle or tile requests; one appended entry
  causes exactly the new bundle/tile fetches. A control that removes the
  short-circuit fails the counting test.

### F4 (H, process) — five days of work uncommitted
- **Evidence.** `git status`: 174 modified/untracked/deleted files; last
  commit `39daef3` (2026-10-02). `BUILD-LOG.md` rows d-v … d-xii-v are ticked
  "✅ — reviewed" and run 13 is recorded, all uncommitted. `PROGRESS.html`
  attributes the work to Codex.
- **Fix.** Land it in reviewed chunks, one per BUILD-LOG row, each with the
  full gate (`make ci vectors vectors-log vectors-check ref-test lint`), in row
  order, and push after each. Do not squash it into one commit: a reviewer
  needs the row boundaries. Anchors (`testdata/vectors/anchors/`) were
  regenerated by the documented `generate.py`; confirm `internal/ots` passes
  before the first chunk.

### F5 (M, process) — the cold-gate loop is not converging on a binary verdict
- **Evidence.** Run 10 `INSUFFICIENT` → 11 `WITH GAPS` (23/148 variants
  survive) → 12 `WITH GAPS` (59/276) → 13 `INSUFFICIENT` (19 defects, 1,353
  checks pass). Each fresh agent enumerates a *different* variant space, so
  each run finds new survivors regardless of the previous fixes. The number of
  **behaviour-changing** defects per run is the signal (5 → 5 → 5 → 5 by the
  reports' own ratings); the verdict word is noise.
- **Fix.** Replace the termination rule. `PLAN.md`'s gate line reads
  "independent verifier passes all vectors" — it has passed all vectors four
  times. Define the gate as: *two consecutive sealed runs with zero defects
  rated H or M (behaviour-changing) and every L defect recorded in §12.1's
  not-vectored list.* Write it as a DECISION (D-068) and ask the user; do not
  decide it alone.

### F6 (M) — no lab, no packaging, no deployment artifact of any kind
- **Evidence.** `lab/` and `demo/` empty; no `Dockerfile`, `*.service`,
  package recipe or container image anywhere; `Makefile` has no `lab-*` or
  `demos` targets. Docker CLI and `colima` are installed on this Mac but no
  daemon runs and the disk is nearly full (memory note).
- **Fix.** §4 rows 6.5m-v (simulation harness) and 6.5m-vi (observe-mode
  deployment kit). A systemd unit and a config example are an hour's work and
  are the difference between "can be run" and "will be run".

### F7 (H → fixed by F1–F3, else M) — `nornd` has never run against a slow or hostile network
- **Evidence.** Every agent test drives `Once()` directly with in-memory fakes
  (`internal/agent/*_test.go`); `cmd/nornd`'s loop (`loop`, `nextPoll`) has no
  test with a blocking fetcher; `TestAgainstARealInterfaceIfOneExists` skips in
  CI. F1–F3 are the kind of bug this leaves.
- **Fix.** The simulation harness (§4, 6.5m-v): N agents, in-process fake
  peer tables, a fake log that can stall, split, replay and lie per client,
  real HTTP gossip servers on loopback. T1–T8 from `GOSSIP.md` §8 run in CI
  without Docker. The agent is already interface-driven enough for this.

### F8 (M) — the log server replays the whole log on every submission
- **Evidence.** `internal/logserver/logserver.go:107–146`: `add` reads every
  entry (`s.entries()`) and replays the full log to run the courtesy check,
  then `deadline()` does it **again**. O(n) per submission, twice. No rate
  limiting (`cmd/norn-log/main.go:140` admits it), no auth on `POST /add`.
  The courtesy replay does stop unsigned garbage from being appended (an
  entry replay rejects is refused with 409), so only a holder of a signer key
  can bloat the log — acceptable under A3/A8, but say it in `THREAT-MODEL.md`.
- **Fix.** Keep the replayed state in memory and fold the candidate onto a
  copy; compute `mmd` from that state. Add a per-source token bucket for §7's
  429. Low priority until the log sees more than one submission a minute.

### F9 (L) — `cmd/norn-genlog/main.go` is 3,173 lines
- **Evidence.** `wc -l`. It writes every Go-owned vector set in one file;
  three steps this week edited it by regex because its literals shift under
  `gofmt`.
- **Fix.** Split by vector directory (`fork.go`, `detect.go`, `checkpoints.go`,
  `proofs.go`, `served.go`) under one package; `make vectors-check` is the
  proof the split changed nothing. Do it in one row, with no behaviour change.

### F10 (L) — documents still promise things that are not built
- **Evidence.** `ENROLLMENT.md` marks eleven flows "planned": `norn rotate`,
  `norn revoke`, `norn migrate`, `norn trust import`, the pending inbox,
  paper keys, `norn-log restore`. `GOSSIP.md` §9 metrics: "none of these
  exist yet". The README's comparison table is honest (`norn audit --by`
  exists: `cmd/norn/audit.go:26`), and its status line is guarded by
  `internal/docclaims`. Keep every "planned" word where it is until the
  thing exists; never remove the status line's "No Norn has ever guarded a
  network anyone depends on" without a deployment that makes it false.

### F11 (L) — `ENFORCEMENT.md` and `GOSSIP.md` metrics/reconcile claims lag the code
- **Evidence.** `ENFORCEMENT.md` §4 says the node "does not publish a
  `reconcile.json` file or the `norn_reconcile_seconds` histogram" — true;
  §9 says planned Prometheus — none. Fine as long as it stays labelled.
- **Fix.** Fold into the deployment kit row: a minimal `/metrics` on the
  tunnel address with the nine names `GOSSIP.md` §9 already argued about.

### F12 (L) — scale ceiling is unstated for full replication
- **Evidence.** `PLAN.md` targets 10¹–10⁶ entries, full replication on every
  node, no snapshot or compaction anywhere; a Pi camera replays everything
  from genesis at every start. Fine for the design target; write the number
  down (entries × bytes × nodes) in `THREAT-MODEL.md` §6 so nobody discovers
  it in production.

---

## 3. Improvement points — what would make Norn unique and powerful

Ranked by (value to a real operator) ÷ (effort), with the reason it is a
differentiator and not a feature.

1. **An in-process mesh simulation that runs T1–T8 in CI.** Today the Phase 4
   security properties exist on paper and in unit tests of one node. A
   harness with N real `Agent`s, real gossip HTTP on loopback, and a
   programmable log (stall, split by client, replay old heads, skew) turns
   "witnesses guard the log, gossip guards the witnesses" from a sentence into
   a green check on every push — before any container exists. Nothing else in
   this field has that. *(§4 row 6.5m-v.)*

2. **Observe-mode deployment kit, and a first real deployment.** A systemd
   unit, `nornd.toml` example, a one-page "watch your mesh for a week" guide,
   `/metrics`. Observe mode writes nothing, so it is safe on the homelab
   today, and it is the step the whole plan (D-005) insists on. The first
   `UNPROVEN_PEER` from a real control plane is worth more than any further
   vector. *(6.5m-vi.)*

3. **Headscale first, as the adoption wedge.** Headscale #1432 (compromised
   control plane) is open since 2023 and labelled a feature gap; its users are
   exactly the "I run Tailscale's protocol but not Tailscale's control plane"
   audience that cannot have Tailnet Lock. Norn in observe mode beside
   Headscale, event-driven via LocalAPI (D-014, not built), with a published
   "here is how we detected an injected node" write-up, is the highest
   visibility result available. The NetBird `AdmitPeer` hook PR
   (`ENFORCEMENT.md` §6) is the enforce-mode equivalent and a credible
   upstream contribution.

4. **A public-witness-network story.** Replace "Pi, VPS, friend" with "one of
   your witnesses is an ArmoredWitness / transparency-dev witness you do not
   run". The cosignature format already works (2.6a); 2.6b (a running
   unmodified witness) is the missing proof. Once a public witness cosigns a
   Norn log, the independence claim in `GOSSIP.md` §3 stops depending on the
   operator's own hardware.

5. **`norn audit` as the product.** The comparison table's strongest row is
   "a signing key is stolen — can you enumerate what it signed?" Nobody else
   can. Grow `audit` into an exportable, proof-carrying report (every device
   admission with its signer, index, checkpoint and bundle) — that is the
   compliance artifact a small company would pay for, and it costs nothing
   cryptographically: every proof already exists.

6. **Policy transparency (ACLs in the log).** Listed as v2 backlog in
   `PLAN.md` Phase 7 and `THREAT-MODEL.md` A1. It is the feature no mesh VPN
   has and the natural next entry type; it is also the point where the
   control plane finally cannot lie about *anything* that matters. Do not
   start it before the lab exists — it is a protocol change and D-xxx
   territory — but keep it as the stated destination.

7. **Incremental verification and a snapshot story.** F3's incremental fetch
   is the first half. The second is a root-signed snapshot entry (state hash
   at index N) so a new node can bootstrap from a snapshot plus the tail,
   without giving up "no peer without proof": the snapshot is itself a
   root-quorum statement in the log. Needed before "tens of thousands of
   entries"; not before.

8. **Gate convergence rule (F5).** Not a feature, but the thing that decides
   whether this project ever calls v1 frozen. A stochastic reader cannot
   deliver a binary verdict; a stable count of behaviour-changing defects can.

What **not** to pursue: a mobile app, a coordination server, NAT traversal,
multi-tenant logs, a prefix tree, any chain beyond the optional OTS anchor.
`PLAN.md` non-goals and D-006/D-009 already said so and were right.

---

## 4. The work queue, in order

Rows in `BUILD-LOG.md`'s format. Insert them after the open 6.5l rows; the
order is deliberate — nothing in 6.5l-ix changes `nornd`, so the node bugs do
not wait for the spec loop, and the pile must land before anything else
touches the tree.

| row | title | scope and acceptance | |
|---|---|---|---|
| 6.5m-0 | Land the pile | the 174-file working tree committed in BUILD-LOG row order, one commit per row, full gate before each, pushed after each. Acceptance: `git status` clean, `origin/master == master`, `make ci vectors-check ref-test lint` green on the pushed head | ⬜ |
| 6.5m-i | Stored head survives a restart (F1) | `agent.New` seeds `a.last` from the verified mirror in `RunDir`; `SPEC.md` §13.2 says so; the rollback-at-restart test and its control | ⬜ |
| 6.5m-ii | Network budgets (F2) | gossip client timeout and per-round budget; per-`Verify` deadline through `Fetcher`; reconciliation never waits on the network; the blocking-peer test and control | ⬜ |
| 6.5m-iii | Unchanged head is a reconcile-only cycle (F3a) | checkpoint bytes compared before any bundle fetch; the counting-fetcher test; control removes the short-circuit | ⬜ |
| 6.5m-iv | Incremental fetch and replay (F3b–c) | only new bundles/tiles beyond the stored size; consistency against the held tree; replay folds the new entries onto the held state; separate verify and reconcile cadences; counting tests for "one new entry" | ⬜ |
| 6.5l-ix / 6.5l-x | Run 13's findings, then run 14 | as already queued, but the termination rule is D-068 (F5) — raise it as a DECISION block first | ⬜ |
| 6.5m-v | Mesh simulation harness: T1–T8 in CI | N agents, loopback gossip, a programmable log (stall / split per client / replay / skew / kill witnesses); each T scenario a test asserting `GOSSIP.md` §8's expected outcome with measured latency; `make lab-sim`; CI runs it | ⬜ |
| 6.5m-vi | Observe-mode deployment kit | systemd unit, `nornd.toml` example with comments, `/metrics` with the nine `GOSSIP.md` §9 names, a one-page runbook; a container image for the log; nothing enforces | ⬜ |
| 6.5m-vii | First real deployment, observe only **[user]** | `nornd` in observe mode on the homelab mesh for seven days; alarms to ntfy; a report of every event with its cause. This is the first measured data the project has and the first line of the README's status that can change | ⬜ |
| 6.5m-viii | A running unmodified witness cosigns (2.6b) | `make witness` + `omniwitness` against `norn-log` locally; the cosignature verifies under the policy | ⬜ |
| 6.5m-ix | Headscale observe via LocalAPI (D-014) | the watcher against a fake LocalAPI; `UNPROVEN_PEER` from the event, not a poll | ⬜ |
| — | then `NEXT-CHECKPOINTS.md` §2–§5 (persistent verifier, lab, demos, the two human gate lines) | unchanged | |

Every row: subdivide in `BUILD-LOG.md` first; TDD; a control per new rule or
vector with a **verified** restore; full gates; commit; tick; push.

---

## 5. Guardrails — how to not go off the rails

Each rule is followed by the incident in this repository that produced it.
These are not style preferences.

1. **One builder per working tree, ever.** Before starting or re-arming a
   loop: `git status`, `ListAgents`, and look for another session's process in
   `~/norn`. If anything else is writing, stop and ask. *(2026-10-02: two
   sessions edited the same files minutes apart; a third ticked a gate that
   never ran.)*
2. **A checkpoint is ticked only by its artifact.** A cold gate is ticked by
   `SPEC-DEFECTS-N.md` from a sealed run whose transcript you audited (tool
   calls touching `~/norn`: 0; web: 0). A lab line is ticked by a result file.
   Local tests never stand in for either. *(Run 12 was ticked without
   running; `baacd29` reopened it.)*
3. **Never trust a ✅ you did not produce.** Check its artifact before
   building on it. *(Same incident.)*
4. **Check this implementation before fixing a finding.** A fresh agent
   measures *its* implementation's variants. Classify each finding as "gap in
   the suite/prose" or "bug here" first; the fix is different. *(6.5l-vii-d:
   five H findings were suite gaps; four real bugs were found in Go and Python
   the same week by this method.)*
5. **A control proves a test is load-bearing, and only if its baseline is the
   real code.** Mutate one thing, run, restore byte-for-byte, verify the
   restore, record which test failed. A control that does not compile, or
   that runs on an already-mutated tree, proves nothing. *(6.5l-vi-b-ii-e: an
   unsplit `$FILES` in zsh skipped every backup and the mutations accumulated;
   6.5l-vii-b-iii: a control removed an import's only use and never ran.)*
6. **The full gate before every commit, no exceptions:** `make test`
   (race, ~10 min), `vectors`, `vectors-log`, `vectors-check`, `ref-test`,
   `lint`, `fmt-check`, `vet`. The document guards (`internal/specdoc`,
   `internal/docclaims`) read `README.md`, `SPEC.md`, `BUILD-LOG.md` and the
   vectors README; they are part of the suite on purpose.
7. **Push `master` as a fast-forward after every step.** Never force, never
   rebase a pushed history. *(6.5l-ii/iii: a decision left unpushed produced
   a two-session divergence and a merge of contradictory text.)*
8. **Generated artifacts are regenerated, never hand-edited.** Vectors come
   from `make vectors` (Python) and `make vectors-log` (Go); `anchors/` only
   from `contrib/ots-vector/generate.py`; checksums from `make vectors-sums`.
   A manifest edited by hand is a bug. *(Every regeneration this week moved
   indices; hand edits would have silently diverged.)*
9. **Anything that changes the protocol, acts outside this machine, or
   contacts a public service is a DECISION block in `BUILD-LOG.md`: write it,
   push, stop.** Protocol = any normative sentence in `SPEC.md` or a
   vector's expected outcome. Outside = the NAS, the Pi, a VPS, OpenTimestamps
   calendars, any posting. *(D-060 … D-067 were all taken this way; none was
   guessed.)*
10. **The fixed decisions in `PLAN.md` are not re-litigated**: Go, Ed25519,
    SHA-256/RFC 6962, deterministic CBOR, C2SP formats verbatim, full
    replication, untrusted log operator, wgctrl, observe-before-enforce,
    no-TOFU, witnessed log + optional OTS. No new dependency without a
    DECISION; `internal/depgraph` forbids the kernel driver outside `nornd`
    and `wgdev` — keep it green.
11. **Never put "blockchain" in the tagline**, the README, or a commit
    message as a description of Norn. `LEDGER-OPTIONS.md` answered that
    question; the answer was "32 bytes of one, optionally".
12. **Keep the README honest by construction.** Its status line is guarded;
    "No Norn has ever guarded a network anyone depends on" leaves only when
    6.5m-vii makes it false. `PUBLICATION.md` never claims the spec is
    sufficient before a run says so.
13. **The sealed-copy prompt is reused verbatim** (`BUILD-LOG.md` 6.5l-vii-c
    records it) except the directory and the report number. The agent must
    never read `~/norn`; verify that from its transcript, not its word.
14. **One sub-checkpoint per firing; subdivide first.** A row that outgrows
    one sitting is split, not rushed. If a previous firing is mid-checkpoint,
    finish it; never start a second.
15. **When a script fails mid-way, inspect the tree before continuing.** A
    partial write is worse than none. `git diff --stat` and the file you were
    editing, every time.
16. **Do not rewrite, do not "clean up" unrelated code, do not add
    frameworks.** The codebase's density of explanatory comments is
    deliberate; match it. A refactor row (like F9) changes no behaviour and
    proves it with `make vectors-check`.
17. **Time-box.** A row at 2× its estimate stops; cut scope and write why in
    `DECISIONS.md` (`PLAN.md` ground rule 6).
18. **Stop conditions.** Stop and ask when: a gate needs a person; a decision
    changes the protocol; a tool call needs the NAS or the public internet;
    another writer appears in the tree; a control cannot be made to bite;
    `make test` is red for a reason you cannot explain in one sentence.

---

## 6. Verification recipes

```sh
# the whole gate (what every commit needs)
make ci && make vectors vectors-log vectors-check ref-test lint

# the suite alone, race, ~10 min on this Mac
make test

# a single package, fast, no cache
go test -count=1 ./internal/agent/

# a control: mutate, run, restore, verify the restore (pattern)
cp internal/agent/agent.go /tmp/x.bak
python3 - <<'EOF'   # one surgical edit
...
EOF
go test -count=1 ./internal/agent/ 2>&1 | grep -E -- '--- FAIL'
cp /tmp/x.bak internal/agent/agent.go && cmp internal/agent/agent.go /tmp/x.bak && echo RESTORED

# did the regeneration change only what it should?
make vectors-log && git status --short testdata/ && make vectors-sums

# anchors (only when the served head moved); needs the upstream clone
git clone --depth 1 https://github.com/opentimestamps/python-opentimestamps /tmp/ots
PYTHONPATH=/tmp/ots:$(pwd)/contrib/ots-vector/stub contrib/norn-ref/.venv/bin/python contrib/ots-vector/generate.py

# audit a sealed-run transcript: tool calls naming this repo must be 0
python3 - <<'EOF'
import json; f='<tasks/...output>'; n=0
for line in open(f):
    if '/Users/francomichetti/norn' in line or '~/norn' in line: n+=1
print('lines naming the repo:', n)
EOF
```

Expected timings on this machine: `go test ./internal/agent/` ≈ 70 s;
`cmd/norn` ≈ 20 s; full `make test` ≈ 10 min; `make vectors` ≈ 20 s;
`make vectors-log` ≈ 30 s; `ref-test` ≈ 20 s.

---

## 7. Relevant information to build on, inspect or review

### Where the truth lives
- **Ledger:** `BUILD-LOG.md` (2,878 lines). First `| ⬜ |` row = next step.
  Narrative entries below the table explain what each step got wrong first.
- **Decisions:** `DECISIONS.md` D-001…D-067. In force and recent: D-060
  (`hard_stale` before `fresh`), D-061 (closed codes §10/§11.1), D-062
  (canonical base64), D-063 (receipt codes), D-064 (SPEC absorbs companion
  normative text), D-065 (no codes for trust/requests/policies in v1), D-066
  (policy parser matches C2SP), D-067 (trust URLs opaque).
- **Spec:** `SPEC.md` (1,982 lines, 16 sections); §12.1 is the coverage
  table; §10.1 and §11.1 the closed refusal codes; §13 and §15 now hold the
  node contract (moved from the companion docs under D-064).
- **Gate reports:** `SPEC-DEFECTS-{2,4,5,6,7,8,9,10,11,12,13}.md`,
  `SPEC-DECISIONS-{11,12,13}.md`. Run 13: 1,353/1,353 checks, 19 defects,
  verdict `SPEC INSUFFICIENT`; its five behaviour-changing ones are D1
  (open `rotate`/`revoke` bodies), D2 (no verification key for bundles and
  receipts after log-key rotation), D3 (inclusive threshold bound unpinned),
  D4 (orderings the text licenses reversing), D5 (two definitions of age).
- **Plan beyond the current queue:** `NEXT-CHECKPOINTS.md` (persistent
  verifier, lab, demos, human gate lines).

### Code map (51 packages, 52k Go lines, 7.5k Python)
- Leaf formats: `internal/{cbor,cjson,entry,enrollreq,note,cosign,policy,
  trust,tlog,bech32m,fields}`; refusal vocabularies `refusal`, `evrefusal`.
- Replay and state: `internal/{replay,state,genesis}` — a pure fold with
  closed reason codes (D-012); fuzzed.
- Verifier: `internal/logclient` (§10 loop), `proof` (§8.1 bundles),
  `forkevidence` (§11.1), `receipt` (§7), `freshness` (witness-time clock).
- Node: `internal/{agent,reconcile,peertable,wgdev,endpoint,fight,gossip,
  mirror,proven}`; daemon `cmd/nornd`. `wgdev` is the only kernel contact.
- Log: `internal/{tlogstore,logserver}`, `cmd/norn-log`; witness wrapper
  `cmd/norn-witness`; generator `cmd/norn-genlog`.
- Operator: `cmd/norn` (`init, enroll, sign, submit, verify, verify-evidence,
  audit, stamp, monitor, status`); monitor `internal/monitor` (ntfy, Home
  Assistant, Alertmanager, email sinks; status page).
- Guards over documents: `internal/specdoc`, `internal/docclaims`,
  `internal/depgraph`.
- Reference implementation: `contrib/norn-ref` (Python, pynacl only);
  `gen_vectors.py` owns the Python-generated vector sets; `GO_VECTOR_DIRS` in
  the Makefile lists the Go-owned ones.

### External facts that matter
- C2SP: `tlog-tiles`, `tlog-checkpoint`, `tlog-cosignature`, `tlog-witness`,
  `tlog-policy` — reused verbatim. The policy parser now matches upstream
  (D-066); multiple `log` lines with distinct keys are allowed.
- `transparency-dev/witness` (`omniwitness`) builds via `make witness`
  (`WITNESS_VERSION` in the Makefile); 2.6b (a running witness cosigning) is
  open.
- `python-opentimestamps` at `3af4643` writes `anchors/`; it now imports
  `pycryptodomex`, stubbed in `contrib/ots-vector/stub/Cryptodome/`.
- Headscale #1432 and #1307; NetBird's engine as the enforce-mode PR target;
  Nebula CVE-2026-61699 as the motivating failure.
- Homelab (from memory, verify before use): TrueNAS `.155` (lab host), Pi
  `.153` (witness), a VPS (witness). From this Mac's sandbox only
  `/usr/bin/ssh`, `nc` and `curl` reach the LAN; the disk is nearly full;
  Docker/colima installed, no daemon running.

### Known process incidents (do not repeat)
- 2026-10-02: parallel session ticked gate run 12 without running it
  (`baacd29` reopened); two sessions wrote the same files minutes apart.
- 2026-10-02: a control script's unsplit `$FILES` skipped every backup;
  results discarded and rerun.
- 2026-10-05/06: a large pile completed and reviewed but never committed
  (still true at this review).
- Earlier: a private witness key reached history and was scrubbed before the
  first push — never re-commit anything under `cmd/norn/norn-witness/` keys.

### Things to inspect next that this review did not reach
- `internal/wgdev` against a real interface (needs Linux or a wireguard-go
  on macOS with a UAPI socket): `ReplacePeers` semantics for a peer with no
  allowed-ips, keepalive handling, and that `UpdateOnly` never adds a key.
- `cmd/norn-log`'s witness push loop under a witness that answers slowly.
- `internal/monitor` end to end against a live `nornd` (the sinks are
  tested; a round against real nodes is not).
- `LEDGER-OPTIONS.md` scoring — accepted here on the strength of D-009; a
  reviewer who disagrees with "no chain" should start there.
