# Official WireGuard project-list checklist

This is the checklist from `COWORKER.md` §16. A box is ticked only when a file
or test in this repository shows it is true, and the evidence is cited beside
it. Every unticked box gives the reason in one line. Checked on 2026-09-30,
at `5b1f915` plus the documentation integrity pass.

Finishing this list is not a reason to contact the WireGuard team. §16 asks
for a final technical review first. The open findings in
`docs/audit/SECURITY_AUDIT.md` come before any of it.

- [ ] **repository public**: `git remote` is `https://github.com/onembyte/norn`,
  and the GitHub API reports that repository as `private` (checked
  2026-09-30).
- [x] **clear open-source license**: `LICENSE` is the Apache License 2.0
  (D-025).
- [ ] **README polished**: `README.md` exists, and `internal/docclaims` checks
  its counts, its quickstart commands and their output. But the ROADMAP's
  documentation integrity pass is still correcting its claims, and nobody who
  has run the rivals has reviewed its comparison table. That is a Phase 6
  gate in `PLAN.md`, and it is open.
- [x] **architecture documented**: `PLAN.md` (phases, fixed decisions),
  `ENFORCEMENT.md`, `GOSSIP.md`, `ENROLLMENT.md`, `DECISIONS.md`, and the
  package map and data flow in `docs/audit/PROJECT_STATUS.md`. Where these
  documents disagree with the code is listed in `PROJECT_STATUS.md` and in the
  ROADMAP's integrity pass.
- [x] **threat model documented**: `THREAT-MODEL.md` has twelve adversaries,
  six guarantees and the non-goals. It was corrected on 2026-09-30 wherever
  the audit found it claiming what the code does not do.
- [x] **protocol documented**: `SPEC.md` (v1), with the vectors in
  `testdata/vectors/`. Cold-model gate run 13 returned `SPEC SUFFICIENT WITH
  GAPS` (`SPEC-DEFECTS-13.md`). The `PLAN.md` gate line, a verifier built from
  `SPEC.md` alone, is still open.
- [x] **SECURITY.md**: `SECURITY.md`, added in this pass. The reporting
  channel it names is GitHub private vulnerability reporting, which needs a
  public repository with the feature switched on. Neither is true today.
- [x] **CONTRIBUTING.md**: `CONTRIBUTING.md`, added in this pass.
- [ ] **reproducible demo**: there is no `lab/`, no `demo/`, and no
  `make lab-up` or `make demos` (`LAB.md`). The offline quickstart in
  `README.md` is reproducible, and `TestTheQuickstartCommandsRun` runs it, but
  it is not the attack demo the Phase 5 gates in `PLAN.md` require.
- [x] **CI green**: `.github/workflows/ci.yml` runs `make ci` and `make lint`
  on ubuntu-latest and macos-latest, and `make ref-test` and
  `make vectors-check`. GitHub Actions reported success for every push from
  `37c253d` to `5b1f915` (runs 12 to 23). SEC-036 lists the gaps: no
  govulncheck, no scheduled run, and `internal/interop` skips because CI does
  not run `make witness`.
- [x] **adversarial tests**: 88 of the 130 fixture entries must be refused,
  each for its recorded reason (`testdata/vectors/log/`). The refusing vector
  directories are `trust-bad/` (45), `checkpoints-bad/`, `proofs-bad/`,
  `served-bad/`, `receipts-bad/`, `fork/` and `detect/`. The tests include
  `TestTheSwapAttack` (`internal/reconcile`),
  `TestAnIntruderIsGoneAfterExactlyOneCycle` and
  `TestASilentPeerDoesNotStallEnforcement` (`internal/agent`), and
  `TestTheSignatureBlindSetIsComputedNotAsserted` (`internal/specdoc`). Two
  gaps remain. No fuzz input reaches a replay handler (SEC-015). Every
  enforcement test runs against `peertable.Fake`.
- [ ] **tagged release**: `git tag` lists nothing, and GitHub lists no tags.
- [ ] **installation instructions**: `README.md` builds `norn` with
  `go build` for offline verification only. Nothing explains installing or
  running `nornd`, `norn-log` or a witness, and there is no service unit and no
  package.
- [ ] **Linux tested**: the unit suite runs on ubuntu-latest in CI, but no test
  drives a real WireGuard interface. `TestAgainstARealInterfaceIfOneExists`
  (`internal/wgdev`) skips when there is none, and the Phase 3 lab gates are
  open.
- [ ] **standard WireGuard tested**: no test runs against kernel WireGuard or
  `wireguard-go` on a real interface. The reason is the same as for the line
  above.
- [x] **no unnecessary WireGuard fork**: the tree contains no WireGuard source.
  `go.mod` requires the unmodified `golang.zx2c4.com/wireguard/wgctrl` and has
  no `replace` directive. Enforcement polls the peer table and patches nothing
  (D-013).
- [x] **no custom cryptographic primitives**: Ed25519 and SHA-256 come from
  Go's standard library (`crypto/ed25519`, `crypto/sha256`), and the Python
  reference uses pynacl. The hand-written code is wire formats only: CBOR,
  bech32m, signed notes and the ssh-agent client. D-053 set the rule, and
  D-055 and D-059 apply it: "hand-write wire formats, never crypto
  primitives". Still open: SPEC does not
  pin Ed25519 verification semantics (SEC-023, D-h).
- [ ] **stable wgctrl/wg integration**: `internal/wgdev` wraps `wgctrl`
  (D-059) but has never run against a real interface. Four owner-mode findings
  are open: SEC-012, SEC-018, SEC-019 and SEC-035.
- [ ] **external review requested**: agents inside this project ran the
  2026-09-30 audit (`docs/audit/`). No outside review request is recorded. The
  Phase 6 review gate in `PLAN.md` is open.
- [ ] **useful testers/users**: the Phase 6 gate "One person outside this
  homelab runs the lab and files an issue" in `PLAN.md` is open, and no lab
  exists.
- [ ] **upstream team contacted for technical feedback**: not done. §16 says
  to finish this list and a final technical review first.
