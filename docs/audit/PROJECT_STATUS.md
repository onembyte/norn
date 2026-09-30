# Norn — Project status (docs/COWORKER-v1.md §36, first assignment)

**Date:** 2026-09-30 · **Commit:** `7f77554` · **Updated:** 2026-09-30 at
`5b1f915` · **Companion documents:** `SECURITY_AUDIT.md` (findings, with
IDs `SEC-nnn`) and `ROADMAP.md`.

This is the read-only audit `docs/COWORKER-v1.md` §36 asks for before any
architectural change. It records what exists, what works, what is
incomplete, and where the documents and the code disagree. Nothing was
rewritten to produce it.

## Since the audit (2026-09-30, `37c253d..5b1f915`)

The sections after this one are the audit as written at `7f77554`; a
statement the later commits made false is corrected in place, and line
references are still `7f77554`'s (the §4.3 blank line, `SPEC.md:296`
then, is `SPEC.md:309` at `5b1f915`).

- **SEC-003, the minimal half** (`4f7732d`). Every `gossip.Peer` read —
  the node's and `norn monitor`'s — has a 10 s deadline
  (`gossip.FetchTimeout`), the same `ResponseHeaderTimeout` and refuses
  redirects. `logclient.Submit` now shares `HTTP.Fetch`'s 30 s
  `logclient.Timeout` and still follows redirects. Tests: a silent, a
  trickling and a redirecting peer (`internal/gossip`), a silent log on
  submission (`internal/logclient`), a watchdog cycle with three silent
  peers that returns and evicts (`internal/agent`). The structural half
  is open: reconcile still runs after the peer I/O (`askPeers`,
  `pollEvidence`), so every ask of a silent peer costs a cycle up to
  10 s first, a peer that answers each read just inside the deadline
  costs 10 s per file, and nothing alarms on an overrun.
- **SEC-005 (a)** (`bdb3086`, 6.5m-iv). `agent.writeEvidence` swaps the
  roles when the served branch is the longer one, so evidence is written
  there too (`TestAForkOnTheLongerBranchStillLeavesEvidence`,
  `detect/fork-on-a-longer-branch`). (b) and (c) are open:
  `forkevidence.Check` still runs under the trust file's log key and
  policy only, `loadFreeze` runs no `Check`, and a node that cannot build
  evidence still freezes in memory only.
- **Two partial effects on LOW findings.** 6.5m-i (`f83018a`): replay
  refuses, as `decode`, a `policy` entry whose `witness` key does not
  parse as a cosignature verifier key (SEC-032 for `witness` lines; the
  `log` line's key is not checked;
  `log/129-bad-policy-witness-key-not-a-cosigner`). 6.5m-ii (`dcdd6a4`):
  `note.Split` refuses a signature line that is not exactly its payload's
  encoding, so non-zero padding bits and a `\r` no longer pass (SEC-027
  for signature lines;
  `checkpoints-bad/24-signature-non-canonical-pad-bits`). The rest of
  SEC-027 stands: the checkpoint's root line is still decoded leniently
  (`tlog.ParseCheckpoint`), and a line of the other algorithm's length
  under a listed name and key id is still skipped.
- **Cold-model gate.** Run 12 (`4348001`): `SPEC INSUFFICIENT`, 553/553
  checks, 14 defects, one High (`SPEC-DEFECTS-12.md`); 6.5m-i, -ii, -iv
  and -v (`f83018a`, `dcdd6a4`, `bdb3086`, `afde20f`) closed all but D3.
  Run 13 (`be385d9`): `SPEC SUFFICIENT WITH GAPS`, 886/886 checks, 8
  defects, none High (`SPEC-DEFECTS-13.md`). 6.5n-i to -iv are planned;
  the PLAN gate line stays open. Run 12's D3 and run 13's D1 are one
  decision, `ROADMAP.md` D-l. Before run 12, 6.5l-v-a, -v-b and -vi
  (`87a5d32`, `a62ebf6`, `345806a`) closed run 11's D4, D6 and D10 and
  recorded closed reason codes as D-k.
- **Documentation integrity pass** (the commit after `5b1f915`). Corrects
  the §5 rows below for README, PLAN, THREAT-MODEL, ENFORCEMENT, GOSSIP,
  ENROLLMENT, LAB and PUBLICATION; unticks five PLAN gate lines (14 → 9 of
  38); records D-060–D-077 in `DECISIONS.md` (D-066 supersedes D-011, D-062
  supersedes D-017's definition); fixes four false code comments; adds
  `SECURITY.md`, `CONTRIBUTING.md`, `docs/HANDOFF.md` and
  `docs/upstream/OFFICIAL_PROJECT_CHECKLIST.md`. The three `SPEC.md` items
  remain.
- **Counts.** 774 `Test` functions (752 at the audit), 4 fuzz targets,
  49 packages. The fixture log is 130 entries, 88 rejecting (128 and 86).
- **`COWORKER.md`** (`5b1f915`) is the maintainer's revised plan,
  verbatim; the first version, which this audit cites by section, is
  `docs/COWORKER-v1.md`, and every citation points there.

## 1. Repository map

One Go module, `github.com/onembyte/norn` (`go 1.26.0`), 49 packages: 5
under `cmd/`, 44 under `internal/`. 774 `Test` functions at `5b1f915` (752
at the audit), 4 fuzz targets. Beside the Go code: a Python reference
implementation (`contrib/norn-ref`, written from `SPEC.md` alone,
generates most vectors), an OpenTimestamps vector generator
(`contrib/ots-vector`), and a vector suite with three provenances
(`testdata/vectors`). Thirteen cold-model gate reports (twelve
`SPEC-DEFECTS*.md` and `SPEC-DECISIONS-11.md`) and a 483 KB `BUILD-LOG.md`
(430 KB at the audit) sit at the repository root.

| Package | Role | Path |
|---|---|---|
| `cmd/norn` | operator CLI: `audit`, `enroll`, `init`, `monitor`, `sign`, `stamp`, `status`, `submit`, `verify`, `verify-evidence` | tooling, offline verification |
| `cmd/nornd` | the node daemon: observe (default), owner, watchdog modes | **enforcement** |
| `cmd/norn-log` | the log's write side: `POST /add`, checkpoint signing, witness push or `-self-witness` | log infrastructure |
| `cmd/norn-witness` | `func main() {}` — a stub that exits 0 | — |
| `cmd/norn-genlog` | Go-provenance vector generator | tests only |
| `internal/agent` | one `nornd` cycle: verify → (peers if failed/stale) → evidence poll → reconcile → publish | **enforcement** |
| `internal/reconcile`, `peertable`, `wgdev` | pure `Decide`/`Apply`; the only kernel-facing code (`wgctrl`), fenced by `internal/depgraph` | **enforcement** |
| `internal/endpoint`, `fight` | keyless routing/endpoint providers (static, hints file, labels); re-add detection | enforcement |
| `internal/logclient` | SPEC §10 verifier loop: signature, origin, quorum, every bundle, tree rebuild, stored-head comparison, tiles, replay | **verification** |
| `internal/replay`, `state`, `entry`, `enrollreq`, `fields`, `cbor`, `cjson`, `bech32m`, `genesis` | SPEC §4–§5, §14, §16 | **verification** |
| `internal/tlog`, `tlogstore`, `note`, `cosign`, `policy`, `trust`, `proof`, `receipt`, `forkevidence`, `freshness`, `proven` | checkpoints, tiles, notes, cosignatures, tlog-policy, trust file, bundles, receipts, evidence, witness-time clock, `proven.json` | **verification** |
| `internal/gossip`, `mirror`, `monitor`, `plainlog` | read-only tunnel HTTP server and peer fetcher; mirror writer; `norn monitor` | node / monitor |
| `internal/logserver`, `witness`, `ots` | `/add` handler; tlog-witness client; OpenTimestamps (advisory, fenced off the enforcement path) | log / advisory |
| `internal/keyfile`, `wgkey`, `sshagent`, `sshwire`, `qrterm` | key files, ssh-agent signing, QR output | tooling |
| `internal/wg` | empty package whose doc comment claims it reconciles the peer table | — |
| `internal/specdoc`, `docclaims`, `depgraph`, `interop` | tests that hold the documents, the README and the import graph to the code; the transparency-dev/witness interop test (skips unless built) | tests |

## 2. What works end to end

Built and run in a scratch copy: `norn init` → `norn-log -self-witness`
→ `norn submit` (genesis) → `norn enroll` → `norn sign` → `norn submit
-wait` → `norn verify` / `status` / `audit`. The README demo reproduces
exactly (`FORK PROVEN` at size 41 from a trust anchor alone). `nornd` is
a complete agent with three modes, witness-time freshness, gossip, fork
freeze and fight detection — and **it has only ever run against
`peertable.Fake`**. Without a WireGuard interface it refuses to start;
every Phase 3 lab gate is open.

**Present as stubs or not built:** entry construction for anything but
`genesis` and `enroll` (SEC-008); `cmd/norn-witness`; `internal/wg`; the
Tailscale/Headscale LocalAPI observer; NetBird/Headscale endpoint
providers; nftables; `reconcile.json` and every metric ENFORCEMENT §4/§9
and GOSSIP §9 name; `POST /norn/hint`; paper roots; `lab/` and `demo/`.

## 3. Architecture as data flows

1. **Device.** `norn enroll` makes an Ed25519 identity key (OpenSSH file)
   and an X25519 WireGuard key, and emits a signed request (CBOR →
   bech32m `norn1…` text or QR).
2. **Signer.** `norn sign` checks the request and builds a
   deterministic-CBOR `enroll` envelope. Signatures cover
   `"norn/entry/v1\n" ‖ CBOR(envelope without sigs)` and carry an `after`
   guard; threshold signing appends signatures.
3. **Log.** `norn submit` → `POST /add`. The log runs an advisory replay,
   appends to a POSIX tlog-tiles directory, returns a signed receipt,
   signs a checkpoint on every append and every 60 s, and pushes it to
   tlog-witnesses (external omniwitness) or cosigns locally.
4. **Node.** `nornd` runs `agent.Once` every 200 ms: `logclient.Verify`
   (log-key signature → origin → witness quorum → every bundle → tree
   rebuild → compare with the stored head, held in memory only → tiles
   → `replay.Replay`), then `proven.Devices` (active and unexpired at
   checkpoint time), then `endpoint.Desired`, then `reconcile.Decide` /
   `Apply` through `wgctrl`. Peers are asked only when the log fails or
   is stale; evidence is polled every T_g.
5. **Publish.** `proven.json`, proof bundles, a mirror and fork evidence
   under `/run/norn`, served read-only on the tunnel address.

Where the design departs from `docs/COWORKER-v1.md` and the departure is
**recorded and sound**: Ed25519 device identity separate from the WG key
(D-008, D-032); deterministic CBOR with domain separation (D-027); two-tier
root/signer quorums (D-007, D-028, D-033); current state by full local
replay rather than an authenticated map (D-004); unmodified C2SP
tlog-witness/cosignature/policy (D-003, D-018) interop-tested against
transparency-dev/witness; no chain, OpenTimestamps advisory only (D-009);
enforcement at the `wgctrl` peer table with no WireGuard patch (D-013);
Tessera replaced by the repo's own `tlogstore` with a measured reason and
an upgrade trigger (D-049); privacy declared a non-goal. Where it departs
**without a record**: see §5.

## 4. Security assumptions actually made by the code

- Trust is rooted in a `norn.trust` file compared by fingerprint out of
  band. It pins `net`, `origin`, `genesis_hash`, the log key, the witness
  keys and the policy.
- A checkpoint is accepted iff its log signature verifies (trust key or a
  key learned by replay), its origin matches byte for byte, and the
  witness policy is satisfied by lines matching on name **and** key id.
- A peer is installed iff replay of the whole log yields the device
  `active` and unexpired at the checkpoint's witness time. No code path
  writes a key replay did not prove.
- The witness-time clock plus monotonic time is the only clock for
  freshness; the wall clock feeds CLOCK_SKEW only.
- Assumed and **not held by the code**: that entry identity is the
  authorized content (SEC-001); that fewer than *k* colluding witnesses
  cannot split a view (SEC-002: the real bound is 2k−N); that every
  network fetch terminates (SEC-003; held since `4f7732d` for peer reads
  and submissions — log fetches already had a 30 s deadline — but
  reconcile still runs after the peer I/O); that the stored head, clock, keys, policy and
  freeze survive a restart (SEC-004/006); that fork evidence can always
  be built and checked (SEC-005; built on the longer branch too since
  `bdb3086`, still checked under the trust file's key and policy only).

## 5. Where the documents and the implementation differ

Beyond the security findings, the drift audit found these material
differences. "Undocumented" means no decision entry or known-limitation
note exists.

| Document says | Code does | Recorded? |
|---|---|---|
| GOSSIP §2/§6, D-016: pull peer checkpoints every T_g; T1 detected ≤ 2·T_g | peers asked only when the log fails or is stale | BUILD-LOG 4.5d only (bandwidth); GOSSIP, D-016 and PLAN:183 uncorrected |
| THREAT-MODEL A5 "replay an old checkpoint — rejected"; PLAN:186 ticked | true within one process only | no |
| SPEC §11 / G2 "held forever"; BUILD-LOG 4.6b "a rebooted daemon comes back frozen" | freeze under `/run/norn`, cleared at boot | no |
| ENROLLMENT §4–5, D-055, `cmd/norn/doc.go`, PLAN:118: `norn revoke`, `rotate`, `migrate`, `norn-log restore`, `nornd` signs at boot | only `genesis` and `enroll` can be built; `nornd` signs nothing | no |
| SPEC §4.3 "both keys valid for overlap"; ENROLLMENT §6 "then new only"; §16.3 makes ENROLLMENT normative | keys accumulate forever (SPEC §9.4) | §9.4 and BUILD-LOG 6.5g-ii record the choice; §4.3, §16.3, ENROLLMENT §6/R7 uncorrected |
| SPEC §4.0, D-026, fixture, `norn enroll`: reserved label `ip` | `nornd` reads `allowed_ips` (ENFORCEMENT §5) | no |
| SPEC §8.1 / §11.1 "checkable by someone holding only `norn.trust`" | false after any log-key or policy rotation | `served-rotated/cases.json` says a trust-only reader must refuse; the prose was not qualified |
| README:8/117 "works beside Headscale"; ENFORCEMENT:134 "Norn today" lists the LocalAPI observer | no Tailscale code exists; PLAN:177 "Not started" | PLAN and D-014 honest; README, PUBLICATION:14/76 and ENFORCEMENT:134 not |
| README G1 unqualified; comparison row "no" | G1 holds in owner mode only; default is observe (D-005) | THREAT-MODEL G1 says "in enforce mode"; README drops it |
| THREAT-MODEL A7 "key substitution — prevented" | SPEC §16.1 withdrew that claim (BUILD-LOG:311) | THREAT-MODEL not updated |
| PLAN:154 fuzz gate ticked; PUBLICATION:188 "83M executions against the replay path" | the post-genesis target skips; ≤2.4M ever reached a handler | no |
| PLAN:163 witness interop ticked; PUBLICATION:56 | the test skips in CI (no `make witness`, no `NORN_REQUIRE_WITNESS`) | no |
| PLAN:172 "fifty further cycles write nothing" | true against the fake only; real WireGuard ignores the node's own key (SEC-012) | no |
| GOSSIP §3: `cmd/norn-witness` is a one-command wrapper; PLAN:121/125 layout lists `internal/wg` as the reconciler | empty stub; empty package | no |
| ENFORCEMENT §4/§9, GOSSIP §6/§9: `reconcile.json`, latency histogram, metrics, `POST /norn/hint` | none exist; the gossip server refuses non-GET | no |
| README:35 `norn verify` prints "the only set of peers a node would install" | it prints replay status; `nornd` also drops expired devices | no |
| D-011 (reuse tlog-proof@v1) | SPEC §8.1 is Norn's own format | D-066 supersedes it (recorded 2026-09-30) |
| PLAN fixed decisions and SPEC §6/§10 name Tessera and torchwood | neither is a dependency | D-049 covers Tessera; D-066 covers torchwood for bundles; PLAN's fixed decisions corrected 2026-09-30 |
| DECISIONS index "D-001…D-025" in PLAN | DECISIONS ran to D-059; Phase 4–6 decisions lived only in BUILD-LOG | D-060–D-077 recorded 2026-09-30; PLAN's index corrected |
| SPEC §4.3 type table | split by a blank line at `SPEC.md:296`; the last three rows render as text | BUILD-LOG says D9 fixed it |
| README:11–12 package, test and gate-line counts | correct at the audit (49, 752, 14 of 38) and at `5b1f915` (49, 774, 14 of 38), re-counted, and 9 of 38 after the documentation pass unticked five; `internal/docclaims` fails when any of the three drifts | — |
| README demo transcript | correct; reproduces byte for byte | — |

## 6. Protocol ambiguities

Listed in `SECURITY_AUDIT.md` § "Protocol ambiguities surfaced". The ones
that decide behaviour between two conforming implementations, and are
therefore candidates for SPEC errata rather than code: entry identity
(§4.0/§5.1), persistence across restart (§10/§11), first-contact
freshness, quorum intersection, gossip cadence, log-key overlap, which
policy a replayed node uses for evidence (§11.1), payload-length vs
"not this key's line" (§7), empty `labels` (§16.1), Ed25519 semantics
(§3), and reserved label names.

## 7. Missing tests (collected)

**Adversarial (COWORKER-v1 §19), currently absent:**
- Sig-array variants of logged entries refused as duplicates: extra
  unresolvable kid, dropped surplus signature, changed role — for
  enroll-after-revoke, rotate rollback, signer_add-after-remove, policy
  rollback, and a previously rejected entry (SEC-001). Only exact byte
  copies are vectored today (13, 85, 112, 113).
- `logserver`: an anonymous `/add` of a sig variant must not create a
  second leaf.
- Split view under the shipped 2-of-3 policy with one colluding witness,
  both nodes fresh: detected within 2·T_g (SEC-002). The existing fork
  test empties the fetcher first.
- A gossip peer that accepts TCP and never answers, a slow-loris peer, a
  slow log: reconcile still runs within a bound, an injected key is still
  evicted, the monitor round completes (SEC-003). Since `4f7732d`: the
  silent and the trickling peer in `internal/gossip`, a silent log on
  submission in `internal/logclient`, and a watchdog cycle with three
  silent peers that still evicts in `internal/agent`. Still absent: the
  trickling peer and a slow log at the node, and the monitor round.
- Restart: a new `Agent` on the same RunDir refuses an older cosigned
  head and does not report `fresh`; freeze survives a wipe of `/run`;
  learned policy survives (SEC-004/006).
- Fork after a log-key rotation; evidence under a raised policy must not
  freeze (SEC-005). The fork on the longer branch has a test since
  `bdb3086` (`TestAForkOnTheLongerBranchStillLeavesEvidence`).
- Policy with two witness keys sharing a note name (SEC-009).
- No-side-effect property for every rejected entry; replay determinism
  across N runs and against Python (SEC-010).
- `tlogstore` crash between partial removal and rename; leftover
  `.tmp-*`; recovered size below the on-disk checkpoint (SEC-011).
- A kernel-faithful `peertable.Fake` (own key ignored, prefixes masked,
  one owner per prefix, nil keepalive = leave) and the owner-mode suite
  re-run against it (SEC-012/019).
- `quorum none` after a clock exists → `unknown`; genesis mismatch →
  refuse and keep last-known-good; monitor never attributes rejected
  entries; note malleability (`\r` on a signature line, a line of the
  other algorithm's length under a matching name+id; non-zero padding bits
  are vectored since `dcdd6a4`); trust file with extra `anchor` members /
  `url ""`; in-log `policy` with an unusable `log` key (an unusable
  `witness` key is vectored since `f83018a`).
- Bool-as-uint envelope/body vectors, non-text `t`, non-integer `after`;
  request with `labels: {}`; Ed25519 small-order/non-canonical inputs;
  rotate with malformed `device_pk` on an unknown device (step order).
- Fuzzing: fix and extend (SEC-015).

**Integration:** any test of `nornd`/`wgdev` against a real WireGuard
interface (a Linux CI job in a netns); `make witness` + interop test with
`NORN_REQUIRE_WITNESS=1` in CI; CLI end-to-end for revoke/rotate/governance
once they exist; `-race` over the monitor with the status handler.

**Guards:** every file in each Go-generated vector directory named by its
manifest (stale files in `fork/` survive `vectors-check`); skip-if-vector-
missing tests turned into failures; a specdoc check that a table row never
follows a blank line.

## 8. Missing documents

- `SECURITY.md` (disclosure process) and `CONTRIBUTING.md` — COWORKER-v1 §22/§27.
  `PUBLICATION.md` plans a public launch without either.
- A durable-state section for `nornd`: what it keeps, where (not `/run`),
  what a restart forgets, what happens at boot before the first
  verification, required capabilities, that the gossip port must be
  firewalled from non-tunnel interfaces.
- An honest statement of which entry types have tooling, in README,
  ENROLLMENT §4–5 and `cmd/norn/doc.go`.
- Corrected G2/A9 with the 2k−N bound and a justified homelab default.
- Superseding decision entries for: D-011 (own bundle format), D-026
  (label names), peers-only-when-stale vs D-016, S_hard/offline policy,
  policy-grammar comment tolerance, log-key retirement, the privacy
  model (COWORKER-v1 §13), and the SEC-001 identity change once decided.
- A complete information-leakage statement (labels incl. endpoints,
  reasons, notes, expiry, signer attribution) in README, THREAT-MODEL §7
  and PLAN non-goals.
- Network timeout and resource bounds; the fact that verification and
  reconciliation share one loop.
- Fork recovery for operators (clearing a freeze; a new trust file with
  the same origin does not clear it); the policy-rotation runbook for late
  or offline nodes.
- A `nornd.toml` reference and a sample systemd unit.
- `PRIOR-ART.md`: Netmaker, DefGuard, Google Key Transparency (COWORKER-v1 §9).
- An architecture overview mapping packages to roles (this document's §1
  and §3 are a start).
- A dependency record (why each module, which binary links it, license,
  update and scan policy) — `DEPENDENCY_AUDIT.md` when written.

## 9. Dependency concerns

Six direct modules, all MIT/BSD-3/Apache-2.0; every cryptographic
primitive from the standard library; `go mod tidy -diff` clean; `go mod
verify` clean; `internal/depgraph` fences `wgctrl` into `nornd`/`wgdev`
and OTS off the enforcement path. Concerns:

- `go.mod` `go 1.26.0` with no `toolchain` directive; CI builds on exactly
  1.26.0. Against an offline vulndb snapshot: 23 reachable stdlib advisories
  at 1.26.0 (incl. an HTTP/2 client loop reachable from the log fetch), 0
  at 1.26.8. No govulncheck in Makefile or CI (SEC-017).
- `golang.zx2c4.com/wireguard/wgctrl`: untagged 2024-12-31 pseudo-version,
  no newer upstream; pins `mdlayher/netlink` v1.7.2 (v1.11.2 exists). It is
  the only kernel-facing dependency. `Device()` returns the interface
  private key into `nornd`'s heap every poll, and reading requires
  `CAP_NET_ADMIN`, so observe mode cannot drop privilege.
- `rsc.io/qr` v0.2.0 (2018, unmaintained), output-only.
- `golang.org/x/crypto` v0.52.0 / `x/net` v0.54.0 carry 11 module-level
  advisories Norn does not call; `x/crypto/ripemd160` (deprecated) is used
  by the advisory OTS path only.
- `transparency-dev/formats` is a direct require used only by tests; it
  pulls a pre-1.0 `filippo.io/mldsa` into `go.sum` (not linked into
  binaries).
- `encoding/base64.StdEncoding` is non-strict (`\r`, `\n`, padding bits);
  §6/§7 exactness needs `.Strict()` plus explicit `\r` rejection (SEC-027).
  A decode/re-encode round trip now holds the receipt's leaf line
  (`87a5d32`) and every signature line (`dcdd6a4`) to one spelling; the
  checkpoint's root line (`tlog.ParseCheckpoint`) is still lenient.
- `net/http` `DefaultClient` (no timeout, follows redirects incl.
  https→http) in `gossip.Peer` and `logclient.Submit` (SEC-003). Both
  replaced in `4f7732d`: `gossip.Peer` has a 10 s deadline and refuses
  redirects; `logclient.Submit` has a 30 s deadline and still follows
  them.
- The Python oracle's only crypto dependency, `pynacl`, is installed
  unpinned and unhashed in CI; libsodium and Go's `crypto/ed25519`
  disagree on small-order inputs (SEC-023).
- `make lint` builds staticcheck with the host toolchain and fails on a
  host Go older than 1.26; the pinned 2025.1.1 predates Go 1.26.
- `make witness` builds the pinned transparency-dev/witness from a
  throwaway `go.mod` with no committed `go.sum`.
- Hand-written signed-note, cosignature, tlog-policy and tlog-witness
  client code (D-053) replaces upstream at runtime; the upstream
  cross-check tests are the only guard and must stay mandatory.

## 10. Recommended cleanup (no code restructuring)

- Delete `internal/wg`; make `cmd/norn-witness` exit non-zero with a
  pointer to `make witness`, or delete it; fix GOSSIP §3 and PLAN's layout.
- Fix `cmd/norn/doc.go:1` (lists `revoke`, omits `audit`, `stamp`,
  `verify-evidence`).
- Remove the blank line at `SPEC.md:296`; drop the torchwood references in
  SPEC §6/§10; fix the "v0 (draft)" title against "v1, frozen".
- Refresh PLAN: the DECISIONS index, the Tessera/torchwood fixed-decisions
  table, the repo layout, the stale 5.7 line about `audit --by`, and the
  ticks at :154, :163, :172, :183, :186, :198 until their conditions hold.
- Move the thirteen cold-model reports into `docs/gates/` and consider
  splitting `BUILD-LOG.md` by phase; promote its decisions into
  DECISIONS.md.
- Correct THREAT-MODEL A7, README G1 and the backend claims, and
  ENFORCEMENT:134.
- Stale comments: `ots/anchor.go:11-13` (digest range), `agent.Config.Now`,
  `checkClock` and `askPeers` path descriptions, `agent.go:674-680`,
  `keyfile.go:191-193`.
- `proven.Write` never removes bundles of devices no longer proven; the
  mirror leaves superseded partial tiles.
- `nornd` ignores `log_urls[1:]`.
- Python: unused `_expires` and `SELF_AUTHORISED` in `replay.py`; `if True:`
  wrapper in `cbor.py:141`. Go: package-level `min` shadowing the builtin
  in `cbor.go:301`; kid validation duplicated in `entry/decode.go` and
  `replay/handlers.go`; `signatureValid` re-encodes the preimage per
  signature; `state.Parse` (float64 round trip) used only by tests.
- `.gitignore` comment about `make` putting binaries in `/bin` is wrong.
