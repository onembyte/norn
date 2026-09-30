# Security policy

Norn is pre-release. It has no releases and no tags, and it has never guarded
a network anyone depends on. Do not deploy it to protect something that
matters. A security report is still worth sending: finding what breaks the
design before anyone relies on it is the point of this stage.

## Known open findings

Open findings exist, and they are serious. A security audit of this
repository on 2026-09-30 (`docs/audit/SECURITY_AUDIT.md`) found two CRITICAL,
two HIGH, eleven MEDIUM and twenty-one LOW issues. None of the four CRITICAL
and HIGH findings is closed:

- **SEC-001 (CRITICAL).** An entry already in the log can be re-submitted
  with one junk signature added, and replay applies it again, so a revoked
  device can come back. The maintainer chose to document this and not fix it
  yet (decision D-a). `THREAT-MODEL.md` A2 records it, and
  `docs/audit/repro/replay_junk_signature.py` reproduces it.
- **SEC-002 (CRITICAL).** One colluding witness plus the log can hide a
  revocation from chosen nodes, because checkpoint gossip runs only when a
  node's view is stale. This is open.
- **SEC-003 (HIGH).** A silent peer can stall a node's enforcement loop. Since
  `4f7732d` every peer read has a 10 s deadline, so the stall is bounded. The
  structural fix is open.
- **SEC-004 (HIGH).** Verifier state does not survive a restart. A restarted
  node accepts a rolled-back checkpoint as fresh. This is open.

`docs/audit/SECURITY_AUDIT.md` gives the status of every finding.
`docs/audit/ROADMAP.md` gives the order of work and the decisions that are the
maintainer's. `THREAT-MODEL.md` states what Norn claims to defend, and its
guarantees table (§4) names the findings that limit each claim today. If your
report matches one of these findings, it is already known. A new way to reach
it, or a worse consequence than the audit describes, is still a new report.

## Reporting a vulnerability

Do not put vulnerability details in a public issue, pull request, commit
message or discussion.

Report through GitHub's private vulnerability reporting on
`github.com/onembyte/norn`: open the repository's **Security** tab, then
choose **Report a vulnerability**. This opens a draft security advisory that
only you and the maintainer can see.

GitHub offers private vulnerability reporting only on public repositories,
and the maintainer has to switch it on. On 2026-09-30 the repository is
private. If you can read it and the form is missing, open an issue that says
only that you have a security report and asks for a private channel. Leave
out every detail.

A report is most useful when it includes:

- the commit hash you tested;
- the component: a `cmd/` binary, an `internal/` package,
  `contrib/norn-ref/`, a `SPEC.md` section or a vector in `testdata/vectors/`;
- which guarantee (G1 to G6) or adversary (A1 to A12) in `THREAT-MODEL.md` it
  defeats;
- a reproduction. The best one is a failing test or a vector that differs from
  a valid one in one way, as `CONTRIBUTING.md` describes.

No response time is promised. So far a confirmed finding has been handled the
same way each time. Its status is kept in `docs/audit/SECURITY_AUDIT.md`, and
the fix comes with a regression test. SEC-003's tests were written to fail
against the old code before it changed. When the fix would change the
protocol or a recorded decision, it goes to the maintainer as a decision in
`docs/audit/ROADMAP.md`, as SEC-001 did.

## Scope

In scope:

- The Go implementation: `cmd/norn`, `cmd/nornd`, `cmd/norn-log` and every
  package under `internal/`.
- The protocol: `SPEC.md` and the documents it relies on (`GOSSIP.md`,
  `ENFORCEMENT.md`, `ENROLLMENT.md`). A flaw in the specification counts as a
  vulnerability even when the code follows it faithfully.
- The Python reference in `contrib/norn-ref/`, and the vectors in
  `testdata/vectors/`. A vector that pins unsafe behaviour, or a case where
  the two implementations disagree on accept or refuse, is in scope.
- A document that claims a security property the code does not have. On the
  audit's severity scale, a false documented security property is HIGH.

Out of scope:

- What `THREAT-MODEL.md` §7 lists as non-goals: availability under a hostile
  control plane, log or witness set; a stolen WireGuard private key before it
  is revoked; a log colluding with a full witness quorum; the channel that
  delivers `norn.trust`; the privacy of the log's contents; traffic policy
  between authorised peers. A split view that needs fewer colluding witnesses
  than the documents say (SEC-002) is in scope.
- WireGuard itself, `wgctrl`, and other upstream dependencies. Report those to
  their own projects.
- `cmd/norn-genlog`, which only generates test vectors, and
  `cmd/norn-witness`, which is an empty placeholder.
