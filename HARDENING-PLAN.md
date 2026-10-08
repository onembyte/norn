# Norn — the hardening plan, start to finish

*Written 2026-10-07. Sources: the review in `mythos_optimization_addition.md`
(findings F1–F12, guardrails §5), `NEXT-CHECKPOINTS.md` (folded in here; that
file now only points here), run 13's report `SPEC-DEFECTS-13.md`, and D-068.
Every code claim this plan rests on was re-checked against the source before
it was written; the line references are to the tree as of `39daef3` plus the
uncommitted pile.*

**This file is the order and the detail. `BUILD-LOG.md` is the ledger.** A
checkpoint is ticked in `BUILD-LOG.md` only — never here — so the two cannot
disagree about what is done. The loop takes the first checkpoint in §3's order
whose `BUILD-LOG.md` row is not ✅.

---

## 1. Rules for every checkpoint

These restate `mythos_optimization_addition.md` §5; each rule there names the
incident that produced it. Read that section before the first firing.

1. **Before anything:** `git status`, `git log -1`, `git fetch` and compare
   with `origin/master`, and `ListAgents` / `ps` for another writer whose
   working directory is `~/norn`. If anything else wrote since the last
   commit this loop made, or a previous firing is mid-checkpoint, **finish
   that or stop — never start a second**.
2. **Subdivide in `BUILD-LOG.md` first.** Each checkpoint below already lists
   its sub-steps; copy them into the table as `-a`, `-b`, … rows before the
   first line of code, and split further if one turns out bigger than a
   sitting.
3. **TDD.** The failing test is written and run red *before* the change. A
   test that is green before the change is not the test for the change.
4. **A control for every new rule, vector or behaviour.** Mutate one thing,
   run, restore byte for byte, verify the restore with `cmp`, record which
   test failed. A control that does not compile, or runs on an already
   mutated tree, proves nothing. Use an in-memory runner (Python script that
   holds the originals) — never a shell loop over an unquoted list.
5. **The full gate before every commit:** `make test` (race, ~10 min),
   `make vectors vectors-log vectors-check ref-test lint fmt-check vet`.
   **Never run `make vectors` or `make vectors-log` while `make test` is
   running:** they rewrite `testdata/` in place, and tests that read a file
   mid-rewrite fail for reasons that are not in the code (6.5m-i-a's first
   gate run). Regenerate first, then test; `vectors-check`, `ref-test`,
   `lint`, `fmt-check` and `vet` are safe alongside.
6. **Commit, tick in `BUILD-LOG.md`, push `master` as a fast-forward.** One
   sub-checkpoint per commit. Never force, never rebase pushed history. The
   owner's rules in `~/.claude/CLAUDE.md` apply: stage named paths, never
   `git add -A`; **no attribution trailer at all** — no `Co-Authored-By`, no
   `Claude-Session` (owner, 2026-10-08; a Codex lane's `Codex-Model` line
   stays, it is the lane's report); and until 2026-11-01
   the head commit of every push carries `[skip ci]` (the account's Actions
   minutes are nearly spent; the full gate runs here). CI is Linux-only for
   the same reason; macOS is covered by this Mac.
7. **Stop and write a DECISION block** (`BUILD-LOG.md`, then commit and
   push) for: a change to what a conforming implementation must accept or
   refuse that `SPEC.md` does not already state, beyond the decisions in §2
   (fixing one implementation to match a rule the spec and the other
   implementation already agree on is a bug fix, not a decision); anything
   that needs the NAS, the Pi, a VPS or the public internet beyond Go/Python
   module downloads; anything that needs a person. Rows marked **[user]** are
   not looped. **An open decision blocks only the rows that depend on it**
   (§3's *needs* lines): the loop records it and takes the next unblocked
   row, and stops only when no unblocked row remains.
8. **Generated artifacts are regenerated, never edited by hand**: `make
   vectors`, `make vectors-log`, `make vectors-sums`, and `anchors/` only via
   `contrib/ots-vector/generate.py` (recipe in the review's §6).
9. **Do not refactor what a checkpoint does not name.** Match the code's
   comment density and voice. No new dependency without a DECISION;
   `internal/depgraph` stays green.
10. **When a script fails mid-way, inspect the tree before continuing.**
11. **Rows tagged 🧠 run under Mythos** (owner's instruction, 2026-10-07).
    The model cannot switch itself; only the owner can, with `/model`. So:
    when the next row to do is tagged 🧠 and this firing is **not** running
    on Mythos, it does no work on that row: it sends a notification — "next
    row needs Mythos: <row> — switch with /model" — and stops. It does not
    skip ahead: the tagged rows are the ones placed first on purpose. When a
    firing running on Mythos finishes a tagged row and the next row is
    untagged, it notifies "Mythos row done: <row> — you can switch back to
    Opus 5.5". Tagged: every DECISION write-up, and the rows whose mistakes
    would be silent security failures — 6.5m-sec-001a/b, the SEC-005(a),
    SEC-010 and SEC-029 rows, SEC-011, H2 and H4.
12. **Codex lanes run beside the loop** (owner's instruction, 2026-10-07:
    "use a codex session with my own subscription to work in parallel …
    choose the model you see fit for each task").
    - A row marked `[codex: <model>/<effort>]` is built by `codex exec` in its
      own clone, `~/norn-lanes/<lane>` (a local `git clone` of this repository
      on branch `codex/<lane>`), under `-s workspace-write`, so it can write
      nothing outside that clone and one output directory
      (`--add-dir ~/norn-lanes/out/<lane>`, mounted as `/lane-out`), pushes
      nowhere, and reaches no network. The sandbox also keeps `.git`
      read-only, so **a lane cannot commit** (lane B found this first); a
      lane therefore does **one row**, leaves the work in its tree, and
      writes the commit message to its output directory; the integrator
      commits it onto `master` after review, keeping the message and its
      `Codex-Model:` line. Its brief (`~/norn-lanes/BRIEF-<lane>.md`, outside
      the repository) carries these rules: TDD with the red output kept, a
      control per behaviour, no edits to `BUILD-LOG.md`, `HARDENING-PLAN.md`,
      `DECISIONS.md`, `SPEC.md` or any generated file.
    - **Models, by how much a mistake would cost:** `gpt-6-astra` (frontier)
      for rows whose correctness is subtle; `gpt-6.1-sol` (the workhorse) at
      `medium` for well-specified fixes and `high` where the behaviour has
      edges; `gpt-6-luna` for documents only. 🧠 rows and DECISION write-ups are
      never delegated.
    - **The lane's own gate is narrower, and the full gate runs here.** Parts
      of the suite bind sockets the sandbox forbids without network (lane A's
      first run stopped on `bind: operation not permitted`), and giving the
      sandbox network was refused as a weakening. So a lane runs the tests of
      every package it touches, plus `vet`, `gofmt` and `staticcheck` on them,
      and commits on that; nothing reaches `master` without the full gate run
      here on integration.
    - **Integration is a loop sub-checkpoint, done here, never by Codex:**
      fetch the branch, read every line of the diff, rerun each control the
      report names, rebase onto `master`, run the full gate, write the journal
      entry and tick the row, push. A lane whose work does not survive review
      is sent back with the reason, or redone here.
    - At most **two lanes at once**, on files disjoint from each other and
      from the row the loop is on.
    - **Order by model (owner's instruction, 2026-10-07):** a firing on
      Mythos takes the first 🧠 row and lets finished lanes wait; a firing on
      Opus integrates finished lanes and takes untagged rows, and stops with a
      notification at the first 🧠 row. No Mythos firing is spent on work
      Opus can do.

---

## 2. Decisions this plan rests on

- **D-068 (taken 2026-10-07): the cold-model gate passes on two consecutive
  sealed runs with zero behaviour-changing defects** (severity H or M in the
  report's own rating), every low-severity finding recorded in §12.1's
  not-vectored list. Replaces "a run's verdict reads exactly `SPEC
  SUFFICIENT`", which four runs have shown a stochastic reader cannot
  deliver.
- **D-070 (taken 2026-10-07): `dup-entry` is keyed on the signed content**
  — the preimage without `sigs` — for every entry, accepted or rejected
  (audit SEC-001, option A); per-device sequence numbers are recorded for
  v1.1.
- **D-072 (open, written 2026-10-08):** five protocol questions from the
  audit — a frozen watchdog's evictions, an empty `labels` map, the Ed25519
  rule at the edges, log-key retirement, enforcing under `quorum none` — with
  a recommendation each; `BUILD-LOG.md`'s DECISION block says how to answer.
  Rows 021r–033r wait on their part; nothing else does.
- **D-071 (taken 2026-10-07, under the owner's instruction to review KEYTRANS
  -10 §7.2 and build what it shows missing): the witness clock survives a
  restart; a restarted node asks the peers its held head proves; a node with
  no held head corroborates its first head with a peer before trusting it for
  long**, enforcing it meanwhile only when no peer answers. Node contract; no
  wire format, no vector.
- **D-069 (recorded 2026-10-07 in H1-e): a node's stored checkpoint, and what it
  learned from it, survive a restart and a reboot.**
  §10's `stored_cp` and §11 rule 4's "forever" already imply it; the node did
  not do it (F1). This is a node-contract clarification taken under the
  user's 2026-10-07 instruction to follow the review's recommendations; it
  changes no wire format and no vector.

---

## 3. The checkpoints, in order

Legend: ⏱ rough size in firings · 🔒 security-relevant · **[user]** not
looped · **[decision]** stops for the user at a point named in the steps.

### Stage A — make the tree safe

#### H0 · 6.5m-0 · Land the pile ⏱1
*Why:* 174 files (+5,299/−990) of reviewed work — BUILD-LOG rows
6.5l-vii-d-v … d-xii-v, d-stamp, run 13 and the 6.5l-ix triage row — sit
uncommitted since 2026-10-02. One `git checkout` from gone (F4).
- a. Inventory the pile by area (`git status`, `git diff --stat`); confirm
  nothing outside `~/norn` was edited.
- b. **Secret scan** of the diff and every untracked file: `PRIVATE KEY`,
  `seed`, 64-hex strings outside `testdata/vectors/keys.json`, tokens, any
  path under `cmd/norn/norn-witness/` (a witness key was scrubbed from
  history once — it must never return).
- c. Confirm the three deleted vectors (`policies/no-trailing-newline.txt`,
  `trust-bad/29-…`, `30-…`) are generator-owned removals: `make vectors
  vectors-log` must reproduce the tree exactly.
- d. Full gate.
- e. Record D-068 in `DECISIONS.md`; add the hardening rows to
  `BUILD-LOG.md` (done when this plan was written).
- f. **Commit as one gate-green commit** whose message enumerates every row
  it lands. *Deviation from the review, recorded:* the review asked for one
  commit per row, but the rows' intermediate trees never existed and cannot
  be reconstructed from interleaved files (`SPEC.md`, `BUILD-LOG.md`,
  `fixture.py`, `SHA256SUMS` are touched by most rows); per-row commits
  would be commits that never passed the gate. The row boundaries survive in
  `BUILD-LOG.md`'s narrative, one entry per row.
- g. Push. `PROGRESS.html` (Codex's local progress page) is left untracked.
*Acceptance:* `git status` shows only `PROGRESS.html`; `master ==
origin/master`; the full gate is green on the pushed head.

### Stage B — node hardening (review F1–F3) 🔒

#### H1 · 6.5m-i · The stored head survives a restart and a reboot (F1, SEC-004, SEC-006) ⏱5 🔒
*Why:* `agent.New` restored only a fork freeze. Until the first verify,
`a.last` was nil, so `logclient.Verify` got `Stored: nil` and skipped §10's
size and branch comparison entirely. A restarted node accepted any correctly
cosigned head, including an old one: every revocation since was undone.
*Design, settled in H1-a:* the head read back from the mirror is **held**
(compared against, and the source of learned keys and policy) but **never
enforced** until something verifies in the new process. Enforcing it would
let a restart during an outage reopen peers an `S_hard` drop had closed, and
the witness clock is not seeded from it for the same reason.
- a. A restart does not undo a revocation: red test with a revoked device
  and an older cosigned head; `restoreHead` verifies `RunDir/mirror` under
  the trust file; `anchorFor(held)` shared by the cycle and the restore.
  Guard test: a restored head is not enforced while the log is unreachable.
  Controls: no restore; held head not sent as stored; restored head enforced.
- b. An unusable mirror (corrupt, truncated, foreign) raises
  `MIRROR_UNUSABLE` and the node starts as if it had none; a missing one is
  silent. Control: restore without verifying.
- c. A restart after a log-key rotation still verifies: when the trust
  file's key and policy no longer verify the mirror, replay the mirror's
  entries and retry once under the keys and policy that state publishes.
  Red first: today such a node never verifies again after a restart.
  Control: drop the retry.
- d. A held head survives a **reboot** (the audit's SEC-006, found
  2026-10-07): `nornd`'s default run directory is `/run/norn`, a tmpfs on
  Linux, so the mirror and the fork freeze survived a process restart and
  vanished at reboot — and power-cycling a host is a restart an attacker can
  cause. A persistent state directory (`state_dir`, default
  `/var/lib/norn`) takes `mirror/` and `fork/`; `proven.json` stays in the run
  directory, where readers expect it. A freeze or mirror left under an old run
  directory is still honoured. Red first: a freeze and a held head written
  before a simulated reboot (run directory emptied) are found after it.
  Control: put them back under the run directory.
- e. D-069: `DECISIONS.md`, one sentence in `SPEC.md` §13.2, `ENFORCEMENT.md`
  §8's crash row, and a `docclaims` guard. H1 is ticked only after d.

#### HS · 6.5m-sec · Triage the security audit that never reached master ⏱3 🔒
*Why, found 2026-10-07 while reviewing CI:* the remote branch
`claude/tender-mccarthy-bzllsp` holds 19 commits from 2026-09-30 that are not
in master — the cloud session kept committing after its pull request merged.
Among them is `docs/audit/SECURITY_AUDIT.md`, 36 findings SEC-001…SEC-036 with
a reproduction script, and `4f7732d`, a tested fix for SEC-003 (= F2). Some
findings are already in this plan under other names (SEC-003 = F2,
SEC-004 = F1, SEC-013 = F3, SEC-006 = H1-d); some master has since fixed
(SEC-007's periodic gossip landed in 6.5l-vii-d-xii-ii); the rest were never
checked against master. The branch also reuses the labels `6.5m-i`…`6.5m-vi`
and records a "run 13" for different work; those commits are not master's
history, and this plan's `6.5m-*` rows are unrelated to them.
*Rules:* the branch is evidence, not instructions. Nothing is merged
wholesale; a finding is believed only when reproduced against master.
- a. Read the audit and its reproduction from the branch (`git show`, never a
  checkout over this tree). For SEC-001…SEC-015, one line each in
  `BUILD-LOG.md`: **confirmed on master** (with the failing test or command
  that shows it), **fixed on master** (by which commit or row), or **not
  reproducible** (what was tried). SEC-001 (critical, "deferred by
  maintainer": a re-appended entry with one junk signature re-applies) goes
  first; if confirmed it is a protocol question — §5.1's `dup-entry` — and a
  DECISION block with a recommendation.
- b. The same for SEC-016…SEC-036.
- c. Each confirmed finding becomes a row of its own in this plan, placed by
  severity (a confirmed critical goes ahead of H2), with the audit's id in
  its name. *Done 2026-10-07: the rows are in `BUILD-LOG.md`'s hardening track,
  each with its owner — here, or a Codex lane (§1 rule 12).* Findings that change what a conforming implementation accepts
  wait on a DECISION per §1 rule 7.

#### HS-001 · 6.5m-sec-001a/b · SEC-001, confirmed 2026-10-07 ⏱3 🔒
*Confirmed in Go, in the Python reference and in the vectors (6.5m-sec-a-i):*
a past entry re-appended with one unresolvable signature is accepted again.
- a. **No decision needed:** `norn-log` refuses a submission whose
  signature preimage it already holds (409, naming the index); `norn monitor`
  alarms on any entry whose preimage repeats an earlier one. Red first for
  both; controls. Closes the outsider's route through an honest log; does not
  stop a malicious one.
- b. **[decision]** The protocol fix, as the DECISION block settles —
  recommended: `dup-entry` keyed on the signed content. Both implementations,
  §4.0/§5.1/§5.2/§12.1, the log regenerated once with the negatives, vector 89
  re-declared, the "open defect" notes removed from README and
  `THREAT-MODEL.md`.

#### HS-004r · 6.5m-sec-004r · State loss (SEC-004's remainder; KEYTRANS -10 §7.2; D-071) ⏱3 🔒
*Why:* three gaps found by reading the agent against KT §7.2 on 2026-10-07,
recorded in D-071: the witness clock restarts at the first head seen, so a
restart lifts `S` and `S_hard`; a rebooted node reads its peer list from the
head verified in this process, so it cannot gossip while its log is down; a
node with no held head enforces its first head unchecked for a whole `T_g`.
- a. **Red test:** a node `degraded` (and, with `S_hard`, `hard_stale`) on a
  head restarts over the same state directory with the log serving the same
  head; today it is `fresh`. Write the clock's estimate of now to
  `<state_dir>/clock` (`durable.WriteFile`, a minute's cadence, whatever the
  log does); seed the clock from it at start as a quorum time at monotonic
  zero. A file that does not parse is `CLOCK_UNUSABLE` and ignored; a missing
  one is silent. Controls: no seed; no write.
- b. **Red test:** a node restarted with its log unreachable returns its
  proven peers from `PeerAddresses`, and a peer carries it (T2 after a
  reboot). `PeerAddresses` reads `held()`. Control: read `a.last`.
- c. 🧠 **Red tests:** (1) a fresh owner node whose log serves a branch and
  whose one peer holds the real log freezes in its first cycle with the
  table untouched; (2) a fresh node whose peer is unreachable enforces, says
  `FIRST_HEAD_UNCORROBORATED`, and on the next cycle — the peer up on the
  other branch, well inside `T_g` — proves the fork, empties the table and
  freezes; (3) a fresh node whose peer agrees is corroborated and asks again
  only on `T_g`. Controls: no same-cycle round (1 fails); no per-cycle retry
  (2 fails); no empty set on an uncorroborated fork (2's table assertion
  fails).
*Acceptance:* the tests, controls, full gate; `THREAT-MODEL.md` A13 and
`SPEC.md` §13.2/§15 as D-071 says.

#### H2 · 6.5m-ii · Network budgets: no fetch can stall enforcement (F2) ⏱2 🔒
*Why:* `gossip.Peer.Fetch` (`internal/gossip/server.go:111`) uses
`http.Get` — Go's default client, no timeout — inside `Once()`, which the
daemon calls synchronously. One proven peer that accepts and never answers
stops a watchdog node from evicting anything. The log fetcher has a 30 s
per-request timeout, but one `Verify` makes a request per bundle and tile.
- a. **Red test:** a loopback peer whose handler blocks forever; `Once()`
  must return within the round budget and the fake table must still have
  been reconciled (an injected rogue key evicted in watchdog mode). Run it
  under a goroutine with a hard test deadline so a regression fails rather
  than hangs.
- b. **Red test:** the same for evidence polling (`pollEvidence`).
- c. **Red test:** a log fetcher that answers each request slowly — one
  `Verify` stops at its overall budget and the cycle reconciles on
  `a.last` (`ENFORCING_ON_STALE_STATE`).
- d. Implement, **starting from the branch's `4f7732d` (SEC-003)**: port its
  client and its red-first tests (a silent, a trickling and a redirecting
  peer; a silent log; the watchdog probe) onto master, crediting the commit,
  and check each still fails without the fix here. Then what it left open: a gossip `http.Client` with a per-request timeout (default
  5 s — a tunnel neighbour); a per-round budget for `askPeers` and
  `pollEvidence`; a budget wrapper for `logclient.Fetcher` that refuses
  further fetches once a `Verify`'s deadline has passed (no interface change
  needed: the wrapper is a `Fetcher`). Defaults and flags in
  `cmd/nornd/config.go`, refused if absurd (like `hard-stale`).
- e. Controls: remove the client timeout (a fails within the hard
  deadline); remove the round budget; remove the verify budget (c fails).
*Acceptance:* three tests, controls, full gate; `GOSSIP.md`/§15 state the
budgets as implementation defaults, not protocol.

#### H3 · 6.5m-iii · An unchanged head is a reconcile-only cycle (F3a) ⏱1
*Why:* `DefaultPoll` is 200 ms (`cmd/nornd/config.go:236`) and every cycle
runs the full `Verify` — every bundle, every tile, a full replay. At 10⁴
entries and fifty nodes that is a self-inflicted denial of service.
- a. **Red test** with a counting `Fetcher`: 50 cycles over an unchanged
  log make 50 `checkpoint` requests and **zero** bundle or tile requests.
- b. **Red test:** when the checkpoint bytes change, the next cycle does a
  full verification (today's path) and adopts the new head.
- c. **Red test:** a log whose tiles are corrupted *after* the head was
  verified is caught by the periodic full re-verify (default every
  5 minutes and on every gossip round), not ignored forever.
- d. Implement the fast path in `Once()`: fetch `checkpoint`; if the bytes
  equal `a.last.SignedCheckpoint` and no full re-verify is due, skip
  `Verify`, recompute freshness from the clock, run the gossip and evidence
  rounds on their cadence, reconcile.
- e. Controls: remove the short-circuit (a fails); remove the periodic
  re-verify (c fails).

#### H4 · 6.5m-iv · Incremental fetch and replay (F3b–c) ⏱3 🔒
*Why:* a grown head still re-fetches and replays everything.
- a. **`replay.Replayer`**: a resumable fold that carries the state **and**
  the seen-set of entry hashes (`replay.go:106`) — `Replay(anchor,
  entries)` becomes `New(anchor).Apply(entries...)`. **Property test:** for
  the fixture log and every split point k, applying `entries[:k]` then
  `entries[k:]` yields byte-identical `state.json` to a full replay; the same
  for `served-large/`. Control: drop the seen-set carry-over → the
  `dup-entry` vectors and the property test fail.
- b. **`logclient.VerifyFrom(held *Result, f, anchor)`**: fetch only the
  bundles and tiles beyond the held size; rebuild the tree by appending to
  the held one; compute the consistency of held→new locally (no supplied
  proof, §10); then the same checks as `Verify` for the new head (codes
  unchanged). **Property test:** for every pair of sizes in the fixture,
  `VerifyFrom` and `Verify` give the same result, code for code, on every
  `served-bad/`, `detect/` and `checkpoints-bad/` case.
- c. **Counting test:** one appended entry causes exactly the new bundle and
  the changed tiles to be fetched.
- d. The agent uses `VerifyFrom` when it holds a head and falls back to
  `Verify` on any doubt (fork evidence, mirror restore, the periodic full
  re-verify from H3).
- e. Controls for each: a wrong tile offset, a skipped consistency check, a
  replay resumed without its seen-set — each must fail a named test.
- f. The mirror writes only the bundles and tiles that changed, each through
  `internal/durable` (H1-d-iii), checkpoint last; and the twin `publishKey`
  functions in `keyfile` and `wgkey` (6.5m-sec-025) fold into `durable` as
  an exclusive publish: today it rewrites every file
  on every new head and syncs none, so after a power cut its head can name a
  file the disk never received, and the restart it exists for is unprotected.

### Stage C — the spec gate under D-068

#### H5 · 6.5l-ix · Run 13's findings ⏱6–8 **[decision]**
*Why:* run 13 (`SPEC-DEFECTS-13.md`): 1,353/1,353 checks pass, 19 defects,
verdict `SPEC INSUFFICIENT`. Same pattern as 6.5l-vii-d.
- a. **Triage, against this implementation first** (guardrail 4): for each
  of D1–D19, does Go and/or Python already do the right thing (suite gap) or
  not (bug here)? Record the table in `BUILD-LOG.md`.
- b. **One DECISION block for every finding the triage puts in rule 7's
  first class, with a recommendation each — then continue with c–e while it
  waits.** Expected at least: D2 (which
  log keys verify bundles and receipts after a rotation; §8's "only
  `norn.trust`" promise), D6 (whose note rules win where C2SP is laxer), D9
  (a `policy` entry with two `log` lines), D12 (a refusal code for a served
  log whose entry 0 is not the genesis — the closed list would grow), D13
  (CBOR simple values other than the four named). If the block is still open
  when c–e and f's undecided-free parts are done, H5 and H6 wait and the
  loop moves on to H7.
- c. **The log grows once** (one regeneration + anchors): D1
  `bad-rotate-unknown-body-key` / `bad-revoke-unknown-body-key` and "closed"
  in both §5.1 rows; D3 an accepted n-of-n threshold; D4's replay two-fault
  orderings; D17's log-side boundaries.
- d. **Receipts, checkpoints, policies, trust:** D4's receipt orderings
  (two-fault receipts), D18's unreached served-path and receipt refusals,
  D10 (vkey name syntax, U+00A0), D7 ("the same keys"), D8 (a directive after
  `quorum`).
- e. **Fork and proofs:** D14 a sound same-size fork in `sound`; D15
  `proofs/at-the-cap` and `proofs-bad/one-past-the-cap` (bundles grown with
  unlisted witnesses' cosignature lines); D4's §11.1 held-before-policy
  two-fault file.
- f. **Prose:** D4's "may reverse" sentence becomes "still normative, merely
  untested"; D5 one definition of age (§8.1 cites §15) with a
  `staleness.json` case built from two (T, learned-at) pairs; D11 the name a
  learned log key signs under; D16 the served-rotated codes; D19 the
  coverage rows; and the decisions from b, applied.
- Every sub-step: controls, regenerate, full gate, commit, push.

#### H6 · 6.5l-x · Sealed runs until D-068 is met ⏱1 per run + fixes
*Needs:* H5 complete, including its decisions.
- a. Seal from the pushed `HEAD` with `git archive` (`SPEC.md` +
  `testdata/vectors/` + empty `work/`), verify every digest, confirm no path
  back to `~/norn`.
- b. A fresh general-purpose agent with run 11's prompt verbatim except the
  directory and the report number (`BUILD-LOG.md` 6.5l-vii-c records it).
- c. **Audit its transcript, not its word:** tool calls naming `~/norn` = 0,
  web calls = 0, decisions logged before the first vector read; copy
  `SPEC-DEFECTS-N.md` and its decisions file in.
- d. Count the H and M findings. **Zero → this run counts toward D-068;
  otherwise the counter resets** and its findings become the next
  6.5l-ix-style row before the next run.
- e. Two consecutive clean runs → tick 6.5l-vii and `PLAN.md` Phase 6 line 1
  with both reports' names and commits.

### Stage D — testable and runnable without hardware

#### H7 · 6.5m-v · Mesh simulation: T1–T8 in CI ⏱5 🔒
*Why:* every agent test drives one `Once()` against fakes; the daemon has
never met a slow, split or lying network (F7). `GOSSIP.md` §8's T1–T8 are
the Phase 4 security properties and exist only on paper.
- a. **`internal/sim`**: N `Agent`s, each with a `peertable.Fake`, an
  injectable monotonic clock, and a real gossip HTTP server on a loopback
  port; a programmable log `Fetcher` per client (honest, stalled, branch A/B
  per client, replay an older head, kill witnesses, skew a node's wall
  clock); a deterministic scheduler so a test runs in seconds, not T_g
  multiples of real time.
- b. T2 (log freeze → peers carry the head), T4 (replay rejected), T6
  (witness quorum loss → hold, degrade, recover).
- c. T1 (split view with colluding witnesses → both nodes prove the fork,
  freeze, proven set unchanged) and T1b (evidence propagation to a node that
  saw only one branch, ≤ 3·T_g in simulated time).
- d. T5 (wall clock +2 h → `CLOCK_SKEW`, not degraded) and T7 (revoke
  latency ≤ T_c + T_g + T_poll in simulated time, the number written to a
  result file).
- e. T3 (honest witnesses, lying log, receipt check) and T8 offline (an
  anchored checkpoint passes `--anchored`, a tampered one fails).
- f. `make lab-sim`; a CI job; each scenario prints its measured simulated
  latency. Controls: for each T, disable the mechanism it proves (gossip,
  evidence polling, the fork comparison, the skew rule) and watch exactly
  that scenario fail.
*Note:* simulated time proves ordering and bounds in the code; it does not
replace the lab's wall-clock measurements (H-user rows), and the result
files say so.

#### H8 · 6.5m-vi · Observe-mode deployment kit ⏱3
- a. `contrib/systemd/nornd.service`: observe by default; `Restart=always`;
  `AmbientCapabilities=CAP_NET_ADMIN` and nothing else;
  `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`,
  `RuntimeDirectory=norn` (gives `/run/norn`), `StateDirectory`, read-only
  trust file path. A test parses the unit and checks each hardening line.
- b. `contrib/nornd.toml.example`, every key commented, observe mode; a test
  loads it with `LoadConfig`.
- c. **`/metrics`** on the tunnel address beside gossip, Prometheus text
  format written by hand (no new dependency), exactly the nine names
  `GOSSIP.md` §9 argued about; tests for each; `GOSSIP.md` §9 stops saying
  "planned".
- d. `contrib/norn-log/Dockerfile` (static build, non-root, read-only root
  filesystem). Verified only if a container daemon is running — otherwise
  the row says "written, not built" and H-user U2 builds it.
- e. `OBSERVE.md`: one page, "watch your WireGuard mesh with Norn for a
  week" — install, trust file, observe, what each alarm means, how to stop.
  Every command in it is run in a test or by the user in U1.

#### H9 · 6.5m-viii · Reconcile 2.6b with 4.4 ⏱<1
*Correction to the review, found while writing this plan:* the review (and
`NEXT-CHECKPOINTS.md` 6.8c) read `BUILD-LOG.md` row 2.6b, which still says
"⬜ Phase 4". That row is stale. Row 4.4 closed it: the
`internal/interop` test drives an unmodified `omniwitness` built by `make
witness`, and `PLAN.md`'s line is already ticked "Closed by 4.4". There is
nothing to build.
- a. Run `NORN_REQUIRE_WITNESS=1 go test ./internal/interop/` with the
  binaries in `build/` and confirm the test **ran** (not skipped) and
  passed. If `build/omniwitness` is missing, `make witness` (Go module
  downloads only).
- b. Control: strip the witness line handling (the test's own negative
  half already does this; confirm it fails as it says).
- c. Mark row 2.6b "✅ closed by 4.4" with the commit, so the two rows stop
  disagreeing. No other change.

#### H10 · 6.5m-ix · Tailscale / Headscale observe via LocalAPI (D-014) ⏱3
- a. A minimal LocalAPI client (unix socket, `status` and the IPN bus
  watcher) written against the documented JSON — no `tailscale.com`
  dependency (a `depgraph` test forbids it).
- b. A read-only peer source producing `peertable.Peer`s; `nornd -backend
  tailscale` forces observe mode and refuses `owner`/`watchdog`.
- c. Tests against a fake LocalAPI server: proven peer silent, unproven
  peer → `UNPROVEN_PEER` from the event (not a poll), removed peer, socket
  missing.
- d. Validation against a real `tailscaled` is user row U6.

### Stage E — maintenance and honesty

#### H11 · 6.5m-x · Log server scales and rate-limits (F8) ⏱2
*Needs:* H4-a (the resumable replayer).
- a. The server keeps its replayed state in memory (H4's `Replayer`) and
  folds a candidate onto a copy; `deadline()` reads `mmd` from that state.
  Counting test: a submission replays one entry, not the log.
- b. A per-source token bucket returning §7's 429; tests.
- c. `THREAT-MODEL.md` A3/A8: only a signer-key holder can grow the log;
  the courtesy check refuses garbage.

#### H12 · 6.5m-xi · Split `cmd/norn-genlog` by vector directory (F9) ⏱1
No behaviour change: one file per vector set, `make vectors-check` and
`git diff --stat testdata/` empty are the proof.

#### HC · 6.5m-ci · CI on supported runtimes ⏱<1
Every run warns that `actions/checkout@v4`, `actions/setup-go@v5` and
`actions/setup-python@v5` target Node 20, which GitHub now forces onto Node
24, and that `ubuntu-latest` moves to Ubuntu 26 on 2026-10-19. Bump the three
actions to their Node 24 majors (read each changelog first), and confirm the
Linux job and the reference job are green with no deprecation annotation. The
govulncheck job is `workflow_dispatch`, not `schedule:`, until the owner lifts
the Actions-budget rule (2026-11-01).

#### H13 · 6.5m-xii · Documents tell the truth about scale and plans (F10–F12) ⏱1
- a. `THREAT-MODEL.md` §6: the scale ceiling as numbers (entries × bytes ×
  nodes; replay time on a Pi measured or stated as unmeasured).
- b. Every "planned" in `ENROLLMENT.md`/`GOSSIP.md` checked against the
  code; what H8 built is no longer planned.
- c. `docclaims` guards for each new factual sentence.

#### H14 · 6.7 · `contrib/verify-py/`: an independent verifier, kept ⏱2
A fresh agent on a sealed copy (the gate prompt's constraints verbatim)
builds a Python standard-library verifier and a harness over every vector;
committed as written with `PROVENANCE.md` (sealed commit, prompt, date,
transcript audit); `make verify-py`, in `make ci`; never edited by hand.

#### H15 · 6.6 · Phase 6 gate audit ⏱1
*Needs:* H6 finished, or the gate line recorded as open with the reason.
Each `PLAN.md` gate line and each `PUBLICATION.md` inventory row against
what exists (✅ fails if missing, ⬜ fails if present); what needs people.

#### H16 · 6.10 · Hand-over material for the human gate lines ⏱2
- a. `TRY-NORN.md`: a stranger goes from a clean checkout to offline
  verification, the simulation (`make lab-sim`) and an observe-mode node,
  every command copy-pasteable and run in a test.
- b. A review packet for the comparison table: each claim, its source, and
  the questions for a reviewer who has run two of the systems.

### Stage F — your hand-over

#### H17 · 7.0 · `ACTION-PLAN.md`: how to test Norn, and how to present it ⏱2
*Needs:* every row H0–H16 ✅, or blocked on a recorded decision that the
plan then states as open.
- a. **Your test plan**, in order, each step with what you should see and
  what to send back: offline verification; the simulation; a local witness;
  observe mode on one node of your real mesh for a day, then the whole mesh
  for seven (U1); reading the alarms; what "it works" means and what it does
  not claim.
- b. **Read `wireguard.com`'s contact guidance at that time** (WebFetch the
  page, record what it says verbatim) and draft the presentation email in
  exactly the form it asks for — plain text, the right list or address, no
  attachments if it says so — with an honest status: what is built, what is
  measured, what is not, the repository link, and what is being asked of
  them.
- c. A pre-send checklist: repository visibility, license, the README status
  line, which numbers come from a real deployment. **Nothing is sent by the
  loop.**
- d. After H17, the loop stops itself (`CronDelete`) and sends a one-line
  notification.

### Stage G — yours, not looped **[user]**

| row | what | needs |
|---|---|---|
| U1 · 6.5m-vii | observe mode on the homelab mesh: one node a day, then all nodes for seven days; alarms to ntfy | access to the nodes |
| U2 · 6.8d, 6.9a–f | a stock nginx serving the log (`PLAN.md` Phase 2's last open line), the container lab (`lab/compose.yaml`), the chaos container, T1–T8 on real kernels, the Phase 3 measurements, patched NetBird/Headscale, the six demos | a container runtime with disk, or the NAS |
| U3 · 6.9g | a real OpenTimestamps anchor upgraded to a Bitcoin attestation | contacting public calendars |
| U4 · 6.9h | the lab on TrueNAS `.155` with the Pi and a VPS as witnesses | NAS/VPS access and keys |
| U5 · 6.9i | enrollment with a phone and a hardware key, timed | you, a phone, a key |
| U6 | the LocalAPI watcher against a real `tailscaled`/Headscale | a Tailscale node |
| U7 | an outside person runs it; a reviewer checks the comparison table; the email to the WireGuard team; publication per `PUBLICATION.md` | other people |

---

### Not scheduled: Phase 7

`PLAN.md`'s backlog — FIDO2 `ed25519-sk`, dual-key rotate grace, the NetBird
upstream admission hook, macOS/Windows agents, public witness onboarding,
multi-log validity, policy transparency, an Internet-Draft, and D-065's
closed codes for trust files, requests and policies (v1.1). None starts
without the user choosing it.

### Decisions the user rows need, asked once

1. Where the lab runs first: containers on this Mac (a runtime started and
   disk freed) or straight to the NAS.
2. How the builder reaches the NAS, the Pi and the VPS, and with which keys.
3. Public network actions: OpenTimestamps calendars, posting anywhere, the
   email.
4. People: who holds the phone and the key, who runs the lab as a stranger,
   who reviews the comparison table.

## 4. Order rationale

Stage A first because nothing else is safe while five days of work are one
command from lost. Stage B before the spec loop because the three node bugs
are live in any deployment and none of them touches `SPEC.md`'s protocol.
Stage C's decision block is raised early (H5-b) so it is answered while the
loop keeps working. Stage D makes the security properties checkable on every
push before any hardware exists. Stage F comes last because the test plan
and the email must describe what is true at the end, not what was hoped at
the start.
