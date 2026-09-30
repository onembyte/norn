# Norn — Security audit (COWORKER.md §36, first assignment)

**Date:** 2026-09-30 · **Scope:** commit `7f77554` on `claude/tender-mccarthy-bzllsp`
(128-entry fixture, 752 Go tests, `make ci` green) · **Method:** read-only.

**How this was produced.** Six auditors, one per area (repository map and
features; entries and replay; checkpoints, witnesses and trust; enforcement
and daemons; drift from `COWORKER.md`; dependencies, tooling and tests), each
working in a scratch copy of the tree. Every finding rated MEDIUM or higher
then went to a second agent told to *refute* it: re-read the cited code,
follow every earlier check, look for a test or vector that already pins the
behaviour, and check whether the repository already documents it as a
limitation. CRITICAL and HIGH findings went to a third agent for severity
calibration under §31's "do not inflate". Severities below are the
**calibrated** ones; where the auditor's rating differed, both are shown.
LOW findings were not independently verified and are listed as reported.

Several auditors found the same defect from different directions. Each
defect appears once below, with the areas that found it.

**Severity scale** (from the audit brief, applied as if Norn were deployed
as its documents describe; pre-release status does not lower a rating):
CRITICAL — an in-model attacker defeats the core invariant (a peer installed
without witnessed authorization, silent replacement or resurrection,
undetectable split view) with realistic effort. HIGH — the invariant fails
under a plausible condition, or a documented security property is false.
MEDIUM — defence-in-depth gap, fail-open edge, or a spec/implementation
divergence with security relevance. LOW — hardening, clarity, minor
divergence.

## Summary

| ID | Severity | Finding | Status |
|---|---|---|---|
| SEC-001 | **CRITICAL** | A validly signed entry can be re-applied by adding one junk signature: revoked devices return, policies roll back | **Deferred by maintainer** (documented, reproduction shipped) |
| SEC-002 | **CRITICAL** | One colluding witness (not *k*) plus the log hides a revocation from chosen nodes, fresh and unalarmed, because gossip never runs while a view is fresh | Open |
| SEC-003 | **HIGH** (two verifiers: CRITICAL) | One silent proven peer stalls every node's enforcement loop forever: gossip fetch has no timeout and precedes reconcile | **Bounded** (2026-09-30): every peer read and every submission has a deadline and follows no redirect; the structural half — reconcile before peer I/O, a cycle-overrun alarm — is open |
| SEC-004 | **HIGH** | Verifier state is not durable: a restarted node accepts a rolled-back checkpoint as `fresh` and reinstalls revoked devices | Open |
| SEC-005 | MEDIUM | Fork evidence is built and checked under the trust file's key and policy only: not produced for a longer branch or after a log-key rotation; weaker evidence still freezes | Open |
| SEC-006 | MEDIUM | The fork freeze lives under `/run/norn` by default and is lost at reboot | Open |
| SEC-007 | MEDIUM | Checkpoint gossip runs only when a view is stale; GOSSIP §2/§6, D-016 and PLAN's T1 "software half closed" claim otherwise | Open |
| SEC-008 | MEDIUM (auditor: HIGH) | No shipped tool can build `revoke`, `rotate` or any governance entry; the runbooks describe commands that do not exist | Open |
| SEC-009 | MEDIUM | Cosignatures are attributed to policy witnesses by note name only | Open |
| SEC-010 | MEDIUM | A rejected `params` entry still changes state, and in Go the change depends on map iteration order | Open |
| SEC-011 | MEDIUM | Log-store crash recovery can silently shrink the log | Open |
| SEC-012 | MEDIUM | Owner mode never converges on an enrolled node: its own key is in the desired set and WireGuard ignores it | Open |
| SEC-013 | MEDIUM | Every poll re-downloads and replays the whole log before reconciling, so the eviction window follows log latency, not T_poll | Open |
| SEC-014 | MEDIUM | Log-key rotation never retires a key; SPEC §4.3, §9.4 and ENROLLMENT §6/R7 disagree | Open |
| SEC-015 | MEDIUM | No fuzzing reaches a replay handler; the post-genesis target has been skipping | Open |
| SEC-016 … SEC-036 | LOW | See the table at the end | Open |

**What held up.** The cryptographic and byte layers are sound. No auditor
found a way to have a peer accepted without a valid log signature and a
witness quorum under the node's current anchor. Deterministic CBOR is
enforced strictly on the way in; every signature is domain-separated and
binds version, type, network, `ts`, `after` and body; replay resolves keys
in the state before the entry; expiry is judged only at evaluation time.
The failures are at the edges: identity for de-duplication (SEC-001),
what the witness bound actually is (SEC-002), unbounded I/O on the
enforcement path (SEC-003), and what survives a restart (SEC-004).

---

## SEC-001 — Re-appending a signed entry with one junk signature re-applies it

**Severity:** CRITICAL (verified: confirmed CRITICAL, both lenses)
**Found by:** entry-replay · **Status:** deferred by the maintainer on
2026-09-30; recorded in `THREAT-MODEL.md` A2; reproduction at
`docs/audit/repro/replay_junk_signature.py`.

**Location.** `internal/replay/replay.go:109-125` (seen set keyed on
SHA-256 of the raw bytes), `:166-193` (`countRole` skips a signature whose
`kid` does not resolve); `internal/entry/entry.go:136-146` (the preimage
excludes `sigs`); `internal/logserver/logserver.go:109-141` (unauthenticated
`/add`, whose courtesy check is the same replay); `contrib/norn-ref/nornref/replay.py:449-457`
(same design); `SPEC.md` §4.0 `entry_hash`, §5.1 step 1, §5.2; `DECISIONS.md` D-031.

**Description.** `dup-entry` is keyed on the entry's bytes as received.
`sigs` sits outside every signature's preimage, and §5.2 says a signature
that does not verify is "ignored, not fatal". So any past entry, with one
well-formed signature appended whose `kid` resolves to nothing, is a new
`entry_hash` whose original signatures still count. It passes the seen
set and replays exactly like the original. Dropping a surplus signature or
changing a signature's declared role also works. No key is needed: the
log's `/add` takes no credentials and its acceptance check is replay.

**Consequence.** On the shipped fixture, 18 accepted entries re-apply.
`spare`, revoked at entry 39, becomes `active` again; re-applying
`28-policy` undoes `49-policy-rotated` and drops the witness quorum from
3-of-3 to 2-of-3. The same route restores a rotated-away WireGuard key
and undoes a `signer_remove`. Preconditions are the default state after an
ordinary revocation: the original signers still hold the role at the
current threshold. Re-revoking does not help; there are 2^64 junk kids.
The only durable remedy is to rotate every authority key that signed the
original entry. The replayed entry is logged and witnessed, so a monitor
*could* see it, but `internal/monitor/rules.go` reports an enroll at Info
and no rule flags a repeated preimage.

**Documents this makes false.** `THREAT-MODEL.md` A2 "cannot forge valid
entries" and "append invalid entries — harmless", G3, `README.md` G3,
`DECISIONS.md` D-031 (written to close exactly this resurrection).

**Evidence.** Reproduced independently by the auditor (Go, against an
honest `logserver`: `POST /add` → 200, size 127, `spare` active) and by the
verifier at HEAD; also in the Python reference. The shipped vectors
`log/70-profile-base` and `log/89-two-sig-base` are the same `note` with
identical preimage and different `sigs`, and the manifest requires *both*
accepted, so the conformance suite currently pins the vulnerable behaviour.

**Recommended fix.** Key the seen set on SHA-256 of the signature preimage
(the envelope without `sigs`) for every entry that decodes, keeping the
raw-bytes hash for entries that do not. Update §4.0/§5.1/§12.1, supersede
D-031, change the Python reference and `logserver` (a sig-variant
resubmission returns 409 or the existing receipt), re-declare vector 89,
and add negatives: extra unresolvable signature, dropped surplus
signature, changed role, each applied to enroll-after-revoke, rotate
rollback, signer_add-after-remove and policy rollback. Trade-off to
record: an under-signed entry that lands in the log burns its preimage,
and signers re-issue with a new `ts`.

---

## SEC-002 — One colluding witness plus the log hides a revocation, and nobody looks

**Severity:** CRITICAL (verified: confirmed CRITICAL, both lenses; each
half alone is MEDIUM–HIGH, the composite is CRITICAL)
**Found by:** map-features (composite); the gossip half also by
checkpoint-witness-trust, enforcement-ops and coworker-drift (SEC-007).

**Location.** `THREAT-MODEL.md:121-124` (A9 "< k witnesses … no effect on
correctness"), `README.md:91` (G2 "fewer than k witnesses colluding");
`internal/agent/agent.go:335-338` (peers asked only when verify fails or
the view is stale); `internal/agent/fork.go:83` (evidence poll fetches
only evidence somebody already produced); `internal/monitor/watch.go:142,213-218`
(each node verified alone, no stored head, no cross-check);
`GOSSIP.md:14,22,174,187`; `internal/agent/gossip_test.go:148`
(`TestPeersAreNotAskedWhenTheLogAnswers` pins the behaviour).

**Description.** Two faults combine.

1. *The documented bound is wrong.* Two k-of-N quorums are guaranteed to
   share only 2k−N witnesses. Under the shipped policy (`group home 2 pi
   vps friend`, 2-of-3) that is **one**. The log pushes checkpoints to
   witnesses, so it can show honest `pi` only branch A and honest `vps`
   only branch B; each stays consistent with itself; the colluding third
   cosigns both. Nothing in the repository states the 2k−N bound.
2. *The backstop is not implemented.* GOSSIP.md ("witnesses guard against
   the log; gossip guards against the witnesses"; §6 "every T_g a node
   pulls `/norn/checkpoint` from r=3 proven peers"; T1 detection within
   2·T_g) is normative via SPEC §15. The agent asks peers only when the log
   fails or the view is stale. The monitor never compares heads.

**Consequence.** Log operator (A2) plus one witness — a combination the
threat model says has no effect — keeps chosen nodes on a branch that
omits a revocation, freshly cosigned, indefinitely. Those nodes install
the revoked key, report `fresh`, never freeze, raise nothing, and the
monitor raises nothing. In the documented homelab (log host plus a Pi on
the same LAN) that pair is realistic to compromise. The A2 row "withhold →
detected via staleness" is also false for the chosen nodes.

**Evidence.** Auditor probe: branch A = fixture entries[:12] (includes
`11-revoke-pi-cam`) cosigned by {pi, friend}; branch B = entries[:11]
cosigned by {vps, friend}; node2 on B gossiping with node1 for 20 cycles.
`node2 size=11 active=[laptop nas pi-cam] freshness=fresh frozen=false`;
monitor rounds: no non-entry alerts. Reproduced by the verifier.

**Recommended fix.** (a) Correct G2 and A9 to the quorum-intersection bound
and have `trust.Validate`/genesis refuse or warn on policies whose quorums
need not intersect; state the liveness trade-off of a 3-of-3 default.
(b) Implement GOSSIP §2/§6 as written: every T_g, fetch only
`/norn/checkpoint` from r proven peers regardless of freshness, verify
signature and quorum, compare with the held head; fetch tiles only on a
larger head or a different root. This is cheap and restores T1 whatever
the policy. (c) Have the monitor compare every node's head with the log's
and its previous view. (d) Regression test from the probe.

---

## SEC-003 — One silent proven peer stalls enforcement everywhere, silently

**Severity:** HIGH, top of the band (verified: six votes HIGH, two votes
CRITICAL; rated HIGH here per "do not inflate", with the condition for
CRITICAL stated below)
**Found by:** map-features, checkpoint-witness-trust, enforcement-ops,
deps-tooling-tests (all independently, all reproduced).
**Status:** the minimal fix landed 2026-09-30: `gossip.Peer` reads through a
client with a 10 s overall deadline, the same header deadline and no
redirects (`gossip.FetchTimeout`), and `logclient.Submit` shares `Fetch`'s
30 s bound. "Forever" is now at most r × 10 s of peer I/O per cycle. The
regression tests are the silent peer and the trickling peer in
`internal/gossip`, the silent log in `internal/logclient`, and the audit's
own probe in `internal/agent`: watchdog mode, one unproven key, three silent
peers, `Once()` returns and evicts. Reconcile still runs *after* the peer
I/O, and no cycle-overrun alarm exists; the monitor reads nodes through the
same bounded client but has no round-level test.

**Location.** `internal/gossip/server.go:111` (`http.Get` — `DefaultClient`,
no `Timeout`, no `ResponseHeaderTimeout`); `internal/agent/fork.go:83-94`
(`pollEvidence`, synchronous, every T_g whatever the log does);
`internal/agent/agent.go:378-383` (`pollEvidence` runs *before*
`reconcile`); `agent.go:649` (`askPeers`, same fetcher);
`cmd/nornd/main.go:251-270` (single loop, no deadline, no watchdog);
`internal/monitor/watch.go:84-85,130-134` (monitor reads nodes serially
with the same fetcher).

**Description.** Every other outbound client in the repository has a
timeout (log 30 s, witness 10 s, OTS 15 s, sinks 10 s). The gossip client
does not. A proven peer whose gossip port accepts TCP and never answers
blocks `Once()` forever at the first T_g that selects it. `gossip.Choose`
draws r=3 random proven peers each round, so every node picks it within
a few rounds. A monitor that watches the same node hangs too.

**Consequence.** After the stall: no reconcile, no eviction, no DEGRADED /
hard-stale / UNPROVEN_PEER alarm (all raised inside the stuck cycle), no
`proven.json` update. A compromised member (A6) can do this before it is
revoked, and then its own revocation never lands on stalled nodes. In
watchdog mode any key the control plane injects afterwards stays. False
as written: `THREAT-MODEL.md:102` (A6 "withhold gossip — DoS at most"),
`:105` ("Revoke takes effect within T_c + T_g + T_poll"), G4 ("or that
node alarms"), `ENFORCEMENT.md` watchdog window "≤ T_poll". The node's
gossip server keeps serving its old mirror, so the monitor's heartbeat
stays green; only a checkpoint-age warning fires after S, and only if the
monitor is not itself hung. A benign peer whose `nornd` is stopped but
whose kernel still completes handshakes into the listen backlog produces
the same hang.

**Why HIGH and not CRITICAL.** A6 alone extends only its own already
authorized tenure; installing a *new* unauthorized key needs A1 as well.
Two verifiers rated CRITICAL on the grounds that "a peer the log no longer
proves stays installed with no signal" is the core invariant. **Re-rate
CRITICAL** if the A1-alone path is demonstrated on kernel WireGuard: in
watchdog mode, the documented swap attack gives the rogue key a proven
peer's `/32`, cryptokey routing sends the next evidence poll into the
rogue tunnel, and the first cycle after a restart hangs before its first
eviction.

**Evidence.** Four independent scratch tests; e.g. watchdog mode, healthy
log, one unproven key installed, a peer that accepts and never writes:
`Once() still blocked after 20s; unproven key still installed=true,
interface writes=0`. Control with `Peers=nil`: evicted in 0.39 s.

**Recommended fix.** Give `gossip.Peer` (and the monitor) an `http.Client`
with `Timeout`, `ResponseHeaderTimeout`, a byte budget and no redirects;
thread a per-cycle deadline through the fetcher; reconcile against the
last good state *before* any peer or evidence I/O, or run gossip and
evidence polling off the enforcement goroutine; add a cycle-overrun
alarm; tests for a silent peer, a slow-loris peer and a slow log, each
asserting an injected key is still evicted within the documented bound.
Also give `logclient.Submit` (`http.go:79`) a timeout.

---

## SEC-004 — Verifier state does not survive a restart

**Severity:** HIGH (verified: six votes, all HIGH)
**Found by:** map-features, checkpoint-witness-trust, enforcement-ops,
coworker-drift (all reproduced).

**Location.** `internal/agent/agent.go:204-260` (`New` restores only the
fork freeze), `:276-281` (`Stored`/`Held` come only from in-memory
`a.last`), `:361` (the only assignment of `a.last`), `:287-296` (keys and
policy fall back to the trust file when `a.last` is nil), `:618`
(`PeerAddresses` returns nil while `a.last` is nil);
`internal/freshness/clock.go:41-46` (first `Observe` adopts the served
quorum time as "now"); `cmd/nornd/main.go:36` (`DefaultRunDir = "/run/norn"`).

**Description.** The stored checkpoint that drives SPEC §10's size and
consistency rule, the held tree, the witness clock, and the keys and
policy learned by replay all live in memory. Nothing reloads them from
the mirror the node writes. Every process restart is first contact:
`Stored=nil` disables the rollback check, and the first genuinely signed,
quorum-cosigned head the node is served, however old, is accepted with
age 0 and reported `fresh`. While fresh, peers are not asked.

**Consequence.** Whoever serves the node's first fetch after a restart —
the log operator (A2), an on-path attacker on an `http://` log URL (A5,
which SPEC §9.1's example allows), any mirror, or a proven peer while the
log is down (A6) — can hand it a pre-revocation snapshot. In owner mode
the revoked device's key is reinstalled. The only immediate signal is
CLOCK_SKEW, logged at INFO, whose text says "nothing about what this node
enforces has changed", and which fires only if the snapshot is more than
Δclock (5 min) behind the wall clock. With an honest peer reachable the
window is about S + T_g (~10–11 min) per restart; with gossip off or cut,
it is unbounded (the node repeats DEGRADED but enforces the old view).
False as written: `THREAT-MODEL.md:89` (A5 "replay an old checkpoint —
rejected"), `PLAN.md:186` (ticked), G4, `SPEC.md:1305` ("a node restarted
from its stored one"), `logclient/client.go:105` (its own contract).

**Evidence.** Four scratch tests; e.g. the same process refuses the old
view ("this checkpoint has 126 entries and this node already holds 127"),
then a new `Agent` on the same RunDir: `after restart: size 126, freshness
fresh, nas installed: true, events map[CLOCK_SKEW:1 …]`.

**Recommended fix.** Persist the adopted signed checkpoint, the held tree
or mirror, the newest quorum time and the freeze in a durable state
directory (e.g. `/var/lib/norn`, systemd `StateDirectory`), separate from
`/run`; load and re-verify them in `agent.New` and pass them as
`Stored`/`Held`; restore learned keys and policy by replaying the mirror;
seed the clock conservatively (start stale until a head at least as new
as the persisted one is seen); let a restarted node use the persisted
proven set for peers and, in owner mode, enforce it at boot; specify all
of this in SPEC §10/§11; name a possible rollback in the startup
CLOCK_SKEW message; add restart-rollback and reboot tests.

---

## SEC-005 — Fork evidence is built and checked under the trust file only

**Severity:** MEDIUM (auditor: HIGH; verified: refute confirmed HIGH,
severity calibrated MEDIUM because the precondition — ≥k witnesses
cosigning two histories — is out of the stated threat model)
**Found by:** checkpoint-witness-trust, enforcement-ops.

**Location.** `internal/agent/fork.go:104-105,184-195`;
`internal/forkevidence/evidence.go:91-97,126-143,208-211`;
`cmd/norn/verifyevidence.go:55-60`; `fork.go:56-63` (`loadFreeze` runs no
`Check`).

**Description.** Three effects of one design gap. (a) `writeEvidence`
always calls `Build(held, …, conflicting)` and `Build` asks the held tree
for `HeadAt(conflicting.Size)`, which fails whenever the served branch is
*longer* than the held one — the natural shape of a growing log. The
node freezes in memory only, writes no file, and a restart unfreezes it.
(b) `forkevidence.Check` verifies both heads under the trust file's log
key alone, so after a §9.4 rotation every genuine fork fails the node's
own self-check; `verify-evidence` has the same limit. (c) Peer evidence is
adopted under the trust file's policy, not the replayed one, so heads a
node would itself refuse as under-cosigned still freeze it network-wide.

**Consequence.** A forking log (with a colluding quorum) suppresses
evidence by construction: it only has to show the victim the longer
branch. T1b propagation and G2's "non-repudiable proof held forever" fail
in that case. After a routine D-020 key rotation, the evidence mechanism
is inert. Effect (c) is an availability attack needing the trust anchor's
old keys. None of this is documented; PLAN.md:198 (D3, ticked) says the
opposite.

**Recommended fix.** When the conflicting head is longer, build evidence
with the roles swapped (held = the served tree, which the node has).
Give `Check` a key set (trust key plus keys learned by replay) and the
node's current policy, and pass them from the agent, `pollEvidence` and
`verify-evidence`. Persist a freeze marker even when evidence cannot be
built. Run `Check` in `loadFreeze`. Make §11.1 say a node that has
replayed a `policy` MUST use it. Tests for the longer-branch, rotated-key
and raised-policy cases.

---

## SEC-006 — The fork freeze is lost at reboot

**Severity:** MEDIUM (verified: confirmed)
**Found by:** map-features; sub-point of SEC-004 in three other areas.

`cmd/nornd/main.go:36` defaults RunDir to `/run/norn`; `internal/agent/fork.go:17-22,44-66`
stores and reloads `fork/*.evidence` from it. FHS clears `/run` at boot
(tmpfs on systemd). `fork.go:18-21` itself says a freeze that lasts only
"until somebody reboots the machine" is "a thing an attacker can arrange".
`TestTheFreezeSurvivesARestart` uses `t.TempDir()`, so it covers a process
restart only. `BUILD-LOG` 4.6b's "a daemon an attacker reboots comes back
frozen" is true for a process restart and false for a host reboot with
defaults. MEDIUM because a provable fork already needs ≥k colluding
witnesses; the freeze is containment after that. Fix with SEC-004: a
durable state directory, refuse to start if it is on tmpfs, document the
split.

---

## SEC-007 — Checkpoint gossip runs only when stale

**Severity:** MEDIUM (verified three times: confirmed MEDIUM; one auditor
rated HIGH, calibrated down because the attacker is out of the threat model
on its own — see SEC-002 for the in-model composite)
**Found by:** checkpoint-witness-trust, enforcement-ops, coworker-drift.

`internal/agent/agent.go:338` is the only caller of `askPeers`, guarded by
`verifyErr != nil || a.isStale(result)`; `isStale` needs S = 10 min, not
T_g = 30 s. `pollEvidence` fetches only evidence somebody already wrote.
The monitor verifies each node with no stored head and never compares
roots. So two nodes kept fresh on different branches never compare heads,
and GOSSIP T1 as written cannot happen. The choice is recorded in
`BUILD-LOG` 4.5d/4.5e and the `agent.go:335` comment as a bandwidth
decision, but GOSSIP §1/§2/§6/T1 (normative via SPEC §15), `DECISIONS.md`
D-016 and `PLAN.md:183` ("software half closed") still claim the property.
`TestAForkedPeerIsAForkNotABrokenNeighbour` reaches detection only after
"the log goes quiet", contradicting its own doc comment. The fix is cheap
(SEC-002 (b)); the alternative is to supersede D-016 and correct GOSSIP
and PLAN.

---

## SEC-008 — No tooling for revoke, rotate or governance entries

**Severity:** MEDIUM (auditor: HIGH; verified four times: calibrated
MEDIUM — no attacker gains anything, the failure is loud, `norn submit`
accepts any entry type so a hand-built entry can be submitted)
**Found by:** map-features, coworker-drift.

`cmd/norn/main.go:36-47` has ten commands; `norn sign` (`sign.go:166-167`)
refuses any type but `enroll`; outside tests `entry.Sign` is called only
for enroll, genesis and the vector generator; `nornd` signs nothing
although D-055 says it signs rotate and self-revoke at boot. Yet
`ENROLLMENT.md` §4–5 document `norn rotate`, three forms of `norn revoke`,
`norn migrate` (R5) and `norn-log restore` (R6); runbooks R1–R8 and R10
depend on them; `cmd/norn/doc.go:1` and `PLAN.md:118` list `revoke`. An
operator following R10 after a stolen device, or R2 after a stolen signer
key, finds "unknown command" and has to write Go inside the module or use
the Python reference's `entry.sign`. This would be HIGH the moment Norn is
declared deployable. Fix: implement `norn revoke` (signer, root, `--self`),
`norn rotate` (with `after` set by default) and a governance builder
through the existing sign/submit flow, refusing `-yes` for root; until
then say in README, ENROLLMENT and `doc.go` that only `enroll` exists.

---

## SEC-009 — Cosignatures are attributed to policy witnesses by note name only

**Severity:** MEDIUM, low end (verified: partially confirmed MEDIUM)
**Found by:** checkpoint-witness-trust.

`cosign.Verify` matches a line on name *and* key id, as §10 requires, but
every quorum caller (`logclient/client.go:282`, `proof/proof.go:203`,
`forkevidence/evidence.go:223`, `freshness/quorumtime.go:169`) throws the
key away and calls `policy.Label(c.Name)`, which returns the short name of
the *first* witness line whose key carries that note name. Nothing refuses
two witness keys with the same note name (`policy.Parse` refuses duplicate
short names and duplicate vkey text; `trust.Validate` duplicate short
names). With a flat k-of-N group this can only undercount (fails closed).
With a nested or asymmetric policy ("one org AND one external"), two
external witnesses sharing a note name can meet the org half. Needs an
operator to provision both keys, so MEDIUM low. Fix: have `cosign.Verify`
return the matched key and map by key, or refuse duplicate note names in
`Parse` and `Validate`; add a vector.

---

## SEC-010 — A rejected `params` entry still changes state, nondeterministically in Go

**Severity:** MEDIUM (verified: confirmed)
**Found by:** entry-replay.

`internal/replay/handlers.go:354-375` writes `st.Params[key]` inside `for
key, value := range env.Body` before later keys are type-checked; Go
randomises map order. `contrib/norn-ref/nornref/replay.py:327-343` has the
same pattern in canonical order. Both break §5.1 "a rejected entry …
changes nothing else", and they disagree with each other. Body
`{rotate_needs_signer:false, checkpoint_interval:true}` signed by a root
quorum: 200 Go replays gave `rotate_needs_signer=false` 26 times and
`true` 174 times, so whether a later device-only rotate installs a new
key differs between nodes and between polls (state is rebuilt from
genesis on every fetch). `monitor/rules.go:149-153` tells the operator a
rejected entry means "nothing is at risk", which is false here. Needs a
root quorum signing a malformed body and a log that does not validate
(§6 allows it). Fix: validate into a temporary map and merge on success
in both implementations; add a mixed-validity vector, a no-side-effect
property test and a replay-determinism test.

---

## SEC-011 — Log-store crash recovery can silently shrink the log

**Severity:** MEDIUM (verified: confirmed, with a stronger reproduction)
**Found by:** checkpoint-witness-trust.

`internal/tlogstore/store.go:265-272` removes every other file in a `.p/`
directory *before* creating, syncing and renaming the new partial bundle;
the parent directory is never fsynced; `readBundle` (`:174-195`) globs
`base.p/*` and reads `matches[0]`, and Go's `Glob` matches dotfiles, so a
leftover `.tmp-*` sorts first; `recover` never reads the on-disk
checkpoint, so it cannot tell it recovered fewer entries than it
advertised; `Open` then signs and cosigns a smaller head. The realistic
cases are an empty `.p/` directory or a zero-length tmp after a power cut,
which drop the log to the last full-bundle boundary — size 0 for any log
under 256 entries, genesis included. Nodes and honest witnesses refuse
the shrunk head (fail closed; with a self-witness, FORK). Package comment
and `BUILD-LOG.md:283` claim "a crash leaves a log … behind what is on
disk, never ahead"; `PLAN.md:162` is ticked on clean restarts only. Fix:
write and rename the new partial first, then remove older widths; ignore
dotfiles and pick the widest valid partial; fsync the directory; refuse
to open when the recovered size is below the on-disk checkpoint.

---

## SEC-012 — Owner mode never converges on an enrolled node

**Severity:** MEDIUM (verified twice: confirmed)
**Found by:** map-features, enforcement-ops.

`agent.desired()` (`agent.go:495-514`) includes every proven device, and
every mesh member's own device is proven. wireguard-go
(`device/uapi.go:282-290`, confirmed in the module cache) and the Linux
kernel (`set_peer`, from source, not executed here) silently ignore a
peer whose key is the interface's own. So `actual` never equals
`desired`, `routingDiffers` is true every cycle, and owner mode issues
`ReplacePeers:true` every T_poll (200 ms), which removes and re-adds every
peer. `peertable.Fake` stores any key, so `TestNothingHappensWhenNothing-
Changes` and `PLAN.md:172` ("fifty further cycles write nothing") hold
only against the fake. Observe and watchdog emit MISSING_PEER for the
node's own key every cycle. No authorization impact; a self-inflicted
outage in the flagship mode that pushes operators to weaker modes. Fix:
read the interface key (`wgctrl Device.PublicKey`), exclude it from
`desired` and gossip addresses, make the fake model the kernel (own key
ignored, prefixes masked, nil keepalive = leave), re-run the no-writes
gate against it.

---

## SEC-013 — Every poll re-downloads and replays the whole log before reconciling

**Severity:** MEDIUM (verified: confirmed)
**Found by:** enforcement-ops.

`Once()` calls `logclient.Verify` first (`agent.go:318`): checkpoint, every
entry bundle, tree rebuild, every hash tile, full replay; reconcile comes
at `:383`. Nothing is cached, although SPEC §10's pseudocode names a
`PermanentCache`. Each HTTP request may take up to 30 s and succeed. So the
documented watchdog window "≤ T_poll + reconfigure latency"
(`ENFORCEMENT.md` §3, `THREAT-MODEL.md:164`, `PLAN.md:171`) is really the
sum of log I/O, peer I/O and full replay: ~30 s during a black-holed log,
minutes against a slow-but-valid log, with no alarm because the head stays
fresh. Measured: 4 fetches and ~25 ms per cycle at 126 entries. Owner mode
is unaffected. Fix: split verification (every T_g, cached immutable tiles,
incremental replay) from reconciliation (every T_poll against the last
verified set, never waiting on I/O); measure the latency histogram
ENFORCEMENT §4 promises.

---

## SEC-014 — Log-key rotation never retires a key; three documents disagree

**Severity:** MEDIUM (verified twice: one MEDIUM, one LOW; MEDIUM kept
because a runbook for a *compromised* key describes a recovery that does
not happen)
**Found by:** checkpoint-witness-trust, coworker-drift.

`agent.go:287-291` trusts the trust file's log key plus every key any
`log_key` entry ever published; `logclient.KeysFrom` ignores `overlap` and
`since_index`. That matches SPEC §9.4 ("overlap is an obligation on the
log, not a rule for a verifier"; keys accumulate) and was the maintainer's
recorded choice (BUILD-LOG 6.5g-ii). But SPEC §4.3's `log_key` row still
says "both keys valid for overlap", SPEC §16.3 makes ENROLLMENT normative
for the overlap rules, ENROLLMENT §6 says "then new only", and R7 offers
rotation as the remedy for "log key compromised". Cold gate H3
(SPEC-DEFECTS-6) raised this and was marked closed without the §4.3 row,
§16.3 or ENROLLMENT changing. An operator following R7 believes a stolen
key is neutralised; it keeps A2-class capability until re-genesis. Fix:
one decision — verifier-side retirement (since_index + overlap in witness
time, plus a `log_key_revoke`) or state that rotation is not revocation —
then make §4.3, §9.4, §16.3, ENROLLMENT §6 and R7 agree.

---

## SEC-015 — No fuzzing reaches a replay handler

**Severity:** MEDIUM (verified: confirmed; "one could argue LOW")
**Found by:** entry-replay; corroborated by deps-tooling-tests.

`internal/replay/fuzz_test.go:43-46` opens `00-genesis.cbor`; the fixture
file is `0-genesis.cbor` (renamed when names became index-derived), so
`FuzzReplayAfterAValidGenesis` calls `f.Skip` on every run.
`FuzzReplayNeverPanics` uses an all-zero anchor, so no input can pass the
entry-0 leaf-hash check. Both feed a single entry, so multi-entry state
bugs (SEC-001, SEC-010) are unreachable by fuzzing. `PLAN.md:154` is
ticked and `PUBLICATION.md:188` claims "83 million fuzz executions
against the replay path"; by `BUILD-LOG.md:226`'s own breakdown 54.6M were
the CBOR decoder and 26.8M the target that cannot pass genesis, so at
most 2.4M ever reached a handler, and at HEAD none do. Fix: load genesis
by manifest index and `Fatal` rather than `Skip`; add a fixture-seeded
multi-entry target with sig-array mutations asserting determinism, no
side effects on rejection and the `active_wg` invariant; add
`enrollreq.Decode`, `keyfile.Parse`, `forkevidence.Parse`, note/cosign and
`policy.Parse` targets; a Go-vs-Python differential corpus; a scheduled
CI run; re-annotate the gate.

---

## LOW findings (as reported; not independently verified)

| ID | Area | Finding | Location |
|---|---|---|---|
| SEC-016 | entry-replay (calibrated MEDIUM→LOW) | Python reference accepts CBOR `true` for `v`, `ts`, `after`, `thr`, `overlap`, genesis thresholds; different reason for non-text `t`; uncaught `TypeError` on non-integer `after` (contradicts "never raises"). D-051 overstates the earlier fix. No vector covers it | `nornref/replay.py:83,85,102,275,300,308,383,462` |
| SEC-017 | deps (MEDIUM→LOW) | `go.mod` says `go 1.26.0` with no `toolchain`; govulncheck (offline DB) finds 23 reachable stdlib advisories at 1.26.0, 0 at 1.26.8; CI never scans | `go.mod:3`, `.github/workflows/ci.yml` |
| SEC-018 | deps (MEDIUM→LOW) | `nornd` reads label `allowed_ips`; SPEC §4.0, D-026, the fixture, `norn enroll` and ENROLLMENT use `ip`. Fixture-style devices are installed unrouted (fail closed) | `internal/endpoint/endpoint.go:145`, `ENFORCEMENT.md:122` |
| SEC-019 | deps (MEDIUM→LOW) | Unmasked CIDR hints (`10.9.0.5/24`) are never `.Masked()`; real WireGuard masks, so owner mode rewrites the whole table every cycle; 4-in-6 prefixes likely rejected every cycle | `endpoint.go:198`, `file.go:60`, `config.go:102`, `peertable.go:84` |
| SEC-020 | map-features / coworker-drift (MEDIUM→LOW) | README/PUBLICATION overclaim: "works beside Headscale" (no code path; tailscaled is observe-only and unwritten), G1 drops "in enforce mode", comparison row "no" unqualified by mode; `ENFORCEMENT.md:134` lists the unwritten integration as "Norn today" | `README.md:8,90,111,117`, `PUBLICATION.md:14,76` |
| SEC-021 | enforcement-ops (MEDIUM→LOW) | A frozen node stops evicting altogether; `ENFORCEMENT.md:152`'s watchdog "same" is wrong in watchdog mode; FORK and FROZEN_BY_FORK log at INFO | `agent.go:310-316,379-381` |
| SEC-022 | entry-replay | Go refuses a validly signed request with `labels: {}` (preimage rebuilt without it); Python accepts. §16.1 silent | `enrollreq.go:71-77,115-125` |
| SEC-023 | entry-replay | Ed25519 edge cases differ: Go accepts small-order keys / identity-R, libsodium refuses. §3/§16.1 specify no verification semantics (SPEC-DEFECTS-7 flagged it) | `replay.go:65-67`, `enrollreq.go:182-191` |
| SEC-024 | entry-replay | `keyfile.Parse` claims to check seed vs public key; `PrivateKey.Public()` only copies the stored half | `keyfile.go:184-196` |
| SEC-025 | entry-replay | Key-file writes check with `Stat` then `Rename` (TOCTOU) and never fsync | `keyfile.go:251-277`, `wgkey.go:106-131` |
| SEC-026 | entry-replay | §4.2's domain prefix does not stop reuse when signer keys live in a general-purpose, forwarded ssh-agent (signing oracle) | `SPEC.md` §4.2, `ENROLLMENT.md:38`, `sshagent.go` |
| SEC-027 | checkpoint | Signed-note parsing is malleable: `StdEncoding` ignores `\r`/`\n` and non-zero padding bits; a 76-byte line under the log's name+id (or 68 under a witness's) is *skipped*, where §7 says malformed | `note.go:169,177,212`, `cosign.go:78`, `tlog.go:104` |
| SEC-028 | checkpoint | A `quorum none` head accepted after a witness clock exists reports `hard_stale` (age from year 1), not `unknown` | `agent.go:703-709`, `proven.go:157-164` |
| SEC-029 | checkpoint | Genesis mismatch is not refused: `Verify` returns an empty aborted state and owner mode enforces it (empties the table) | `client.go:198-200`, `agent.go:361` |
| SEC-030 | checkpoint | Monitor describes entries replay *rejected* as if valid, attributed to the forged signatures' kids | `monitor/watch.go:96-105`, `plainlog.go:91-113` |
| SEC-031 | checkpoint | Trust file: Go accepts extra `anchor` members (Python refuses); witness `url: ""` accepted and dropped, so the fingerprint is over the re-encoding, not the bytes | `trust.go:148-163,184-186,323-366` |
| SEC-032 | checkpoint | In-log `policy` entries are not checked for usable keys; one root typo (or a 0x01 witness key) bricks every node until re-provisioned | `handlers.go:338-351`, `policy.go:118-135` |
| SEC-033 | enforcement | Security events logged at INFO and repeated at 5 Hz with no de-dup; `unknown` freshness never alarmed; enforcing modes allowed under `quorum none`/1-of-1 (GOSSIP §3 says observe-only); CLOCK_SKEW computed on peer-adopted heads; `proven.json` not rewritten on failed cycles | `cmd/nornd/main.go:306-313`, `agent.go:387-405,417-442` |
| SEC-034 | enforcement | `norn-log`: idle self-witnessed log never republishes; HTTP server has no timeouts; `/add` triggers a full replay under the write mutex per request; gossip server's "unreachable outside the tunnel" is false under Linux's weak host model | `cmd/norn-log/main.go:151-154`, `logserver.go:94-146`, `gossip/server.go:131-149` |
| SEC-035 | enforcement | Owner mode strips WireGuard preshared keys (`Peer` has no PSK field); overlapping allowed-ips among proven peers are not refused (routing form of the swap attack); `norn status` judges expiry by the wall clock; monitor `status.Alerts` written without synchronisation | `peertable.go:65-70`, `endpoint.go:76-105`, `status.go:59-60`, `monitor.go:132-148` |
| SEC-036 | deps | CI: no govulncheck, no scheduled run, witness interop never exercised (test skips; PLAN gate ticked), actions pinned by tag, no `permissions:`, pynacl unpinned; `make lint` fails on a host Go < 1.26; `vectors-check` cannot catch a stale extra file in `fork/`; several adversarial tests `t.Skip` when their vector is missing | `.github/workflows/ci.yml`, `Makefile:26,67`, `cmd/norn-genlog/main.go:1319` |

## Protocol ambiguities surfaced

Collected from all six areas; each is a place where SPEC, GOSSIP,
ENFORCEMENT or ENROLLMENT either says nothing or says two things.

- Entry identity for de-duplication (§4.0/§5.1/D-031): bytes as received vs
  authorized content; `sigs` is unsigned and malleable (SEC-001).
- What a node MUST persist across restart and reboot: stored checkpoint,
  held tree, newest quorum time, learned keys and policy, freeze
  (SEC-004/006). §10 says only "store cp"; §11 says "forever".
- Freshness at first contact: no rule for a node with no prior witness
  time; the implementation takes the first quorum time as now.
- Witness quorum semantics: G2/A9 bound collusion by k; the grammar admits
  non-intersecting quorums; nothing says whether to refuse or warn
  (SEC-002).
- Checkpoint gossip cadence: GOSSIP §2/§6 every T_g vs the implementation's
  only-when-stale (SEC-007).
- Log-key overlap: §4.3 vs §9.4 vs ENROLLMENT §6 (SEC-014); policy rotation
  (R8) has no overlap rule and no path for a node bootstrapping late.
- §11.1 "its own policy: the trust file's, or one it has replayed" does not
  say which a node that has replayed must use (SEC-005); §11.1 names a
  single log key and ignores rotated ones; §8.1/§11.1 "checkable by someone
  holding only `norn.trust`" is false after any rotation.
- §7: a line whose name and key id match a trusted key but whose payload
  length does not fit that key's algorithm — malformed (refuse) or not this
  key's line (skip)? The code skips (SEC-027).
- §10 per-line refusal: anyone who can alter bytes in transit can veto a
  head by adding a bad line under a listed name+id (both public); worth
  stating this is equivalent to withholding.
- §4.4 `after` is optional and only a lower bound; no entry binds prior
  state; two rotations without `after` can be reordered by the log.
- Historical WireGuard keys: `dup-wg` covers active keys only; re-enrolling
  a revoked `wg_pk` is unspecified and unalarmed.
- §5.1 rotate step order: both implementations return `unknown-device`
  before validating `device_pk` length; a spec-literal reader returns
  `decode`. No vector.
- §16.1: whether a present-but-empty `labels` map is legal (SEC-022).
- §3/§16.1: Ed25519 verification semantics and key validity (SEC-023).
- §5.3: an expired-but-`active` device still reserves its id and `wg_pk`
  until revoked; a reader may extend "treated as revoked" to the duplicate
  checks.
- Reserved label names (`ip` vs `allowed_ips`), canonical CIDR form, and
  whether a node's own device belongs in its desired set (SEC-012/018/019).
- The `unknown` freshness state has no alarm requirement; whether enforcing
  modes are permitted under `quorum none`; GOSSIP §3's "1-of-1 only in
  observe" is unenforceable.
- No document bounds how long a node may wait on a log, peer or evidence
  fetch; G4 and the watchdog window silently assume every fetch terminates
  (SEC-003/013).
- `POST /norn/hint` is listed in GOSSIP §6 and refused by the read-only
  server; GOSSIP §2 acquires from all `log_urls`, `nornd` uses only the
  first.
- SPEC §10's pseudocode still names torchwood (`VerifyCheckpoint`,
  `TileFetcher`, `PermanentCache`); the implementation uses
  `x/mod/sumdb/tlog` and its own store.

## Reproductions and probes

The auditors' scratch tests are not part of the repository. The one
reproduction that ships is `docs/audit/repro/replay_junk_signature.py`
(SEC-001). The probes for SEC-002, SEC-003, SEC-004, SEC-005, SEC-010,
SEC-011 and SEC-012 are described precisely enough above to be rebuilt as
regression tests, and `docs/audit/ROADMAP.md` lists them as the first
deliverable of each fix.
