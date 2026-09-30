# Norn — Codex / Claude Code Coworker Plan

## Purpose

This file is persistent project context for AI coding agents working on **Norn** and related WireGuard ecosystem contributions.

Agents should read this file at the beginning of every substantial work session.

The immediate engineering focus is **Norn**. At the same time, the repository should preserve structured context for other WireGuard contribution opportunities so they are not forgotten, duplicated, or mixed into Norn without an explicit architectural decision.

---

# 1. Project Identity

**Project:** Norn  
**Author:** Franco Michetti (`onembyte`)  
**Language:** Go  
**Started:** 2026-09-18

Core thesis:

> **No peer without witnessed authorization.**

Norn is intended to be:

> **A coordinator-independent trust and key-transparency layer for WireGuard.**

The core architectural objective is to separate **coordination** from **peer authorization**.

A coordinator may discover peers, exchange endpoints, distribute routing configuration, and propose WireGuard public keys.

It must not have unilateral authority to silently invent, replace, rotate, or resurrect a WireGuard identity.

Conceptually:

```text
Headscale ─┐
NetBird ───┤
Netmaker ──┤
innernet ──┼────► Norn ─────► WireGuard
wg-quick ──┤
custom ────┘
```

---

# 2. Current Primary Focus

Unless the human owner explicitly changes priorities, the current primary focus is:

```text
NORN
```

Work on Norn should prioritize:

1. threat model
2. protocol correctness
3. authorization model
4. device identity model
5. revocation semantics
6. current-state verification
7. transparency log integration
8. witnesses
9. freshness/offline behavior
10. WireGuard enforcement
11. tests
12. documentation
13. reproducible demo
14. upstream readiness

Do not expand Norn into a generic VPN control plane.

---

# 3. Parallel WireGuard Contribution Tracks

These are **persistent project-memory items**.

They are not discarded while Norn is being developed.

They should remain documented, researched, and periodically re-evaluated.

| Contribution area | Difficulty | Good first upstream work? | Relation to Norn |
| --- | --- | --- | --- |
| Testing infrastructure | Medium | **Yes** | Medium |
| Documentation / developer docs | Low–Medium | **Yes** | Medium |
| `wgctrl-go` fixes/tests | Medium | **Yes**, if a real issue is found | **Very high** |
| `wg-dynamic` | Medium–High | After research/contact | **High** |
| Mesh networking tools | High | Later | **Very high** |
| WireGuard utilities | Medium | Yes | High |
| Dynamic provisioning web app | Medium | Possibly | Medium–High |
| `wireguard-go` contribution | High | After learning codebase | High |
| `wireguard-go` maintainership | Very High | Not initially | High |
| Kernel performance TODOs | Very High | No | Low |
| Lock/buffer auditing | Very High | No | Medium |
| Timer/crypto-sensitive work | Very High | No | Medium |

These tracks must remain part of the project context even when inactive.

---

# 4. Workstream Rules

Each contribution track should be treated as an independent workstream.

Do not mix unrelated upstream experiments into Norn core.

Preferred project structure:

```text
docs/
└── upstream/
    ├── WIREGUARD_READINESS.md
    ├── OFFICIAL_PROJECT_CHECKLIST.md
    ├── TODO_RESEARCH.md
    ├── CONTRIBUTION_TRACKER.md
    ├── WGCTRL_GO.md
    ├── WG_DYNAMIC.md
    ├── MESH_TOOLS.md
    ├── WG_UTILITIES.md
    ├── DYNAMIC_PROVISIONING.md
    ├── WIREGUARD_GO.md
    └── KERNEL_ADVANCED.md
```

Create these files only when useful; do not create empty documentation for appearance.

---

# 5. Persistent Contribution Tracker

Maintain:

```text
docs/upstream/CONTRIBUTION_TRACKER.md
```

Use this structure:

```markdown
# WireGuard Contribution Tracker

## Current focus

Norn

## Candidate workstreams

### Testing infrastructure
Status:
Last researched:
Relevant repositories:
Open opportunity:
Next action:
Blocked by:

### Documentation / developer docs
Status:
Last researched:
Relevant repositories:
Open opportunity:
Next action:
Blocked by:

### wgctrl-go
Status:
Last researched:
Relevant repositories:
Open opportunity:
Next action:
Blocked by:

### wg-dynamic
Status:
Last researched:
Relevant repositories:
Open opportunity:
Next action:
Blocked by:

### Mesh networking tools
Status:
Last researched:
Relevant repositories:
Open opportunity:
Next action:
Blocked by:

### WireGuard utilities
Status:
Last researched:
Relevant repositories:
Open opportunity:
Next action:
Blocked by:

### Dynamic provisioning
Status:
Last researched:
Relevant repositories:
Open opportunity:
Next action:
Blocked by:

### wireguard-go contribution
Status:
Last researched:
Relevant repositories:
Open opportunity:
Next action:
Blocked by:

### wireguard-go maintainership
Status:
Last researched:
Readiness:
Next action:
Blocked by:

### Kernel / advanced work
Status:
Last researched:
Required knowledge:
Next action:
Blocked by:
```

Agents should update this tracker when research materially changes the status of a workstream.

---

# 6. Status Vocabulary

Use the following states consistently:

```text
BACKLOG
RESEARCHING
VALIDATED
READY
IN_PROGRESS
BLOCKED
WAITING_UPSTREAM
DONE
NOT_RECOMMENDED
STALE
```

Do not mark something `READY` merely because it appears on `wireguard.com/todo/`.

Verify current upstream status first.

---

# 7. Norn Security Invariant

The primary invariant is:

```text
A WireGuard peer MUST NOT be installed
unless Norn can verify its authorization.
```

Long-term verification should include:

```text
authorization
+
current state
+
revocation state
+
transparency inclusion
+
log consistency
+
witness policy
+
freshness policy
```

Conceptually:

```text
proposed WireGuard peer
          │
          ▼
┌─────────────────────────┐
│          Norn           │
│                         │
│ authorization valid?    │
│ key current?            │
│ revoked?                │
│ inclusion valid?        │
│ history consistent?     │
│ witnesses sufficient?   │
│ checkpoint fresh?       │
└────────────┬────────────┘
             │
          APPROVED
             │
             ▼
      install WG peer
```

WireGuard itself should remain unmodified unless a future architectural review proves that this is unavoidable.

---

# 8. Threat Model

Assume the following may become malicious or compromised:

```text
coordination server
API server
network transport
DNS
individual log mirror
individual witness
individual administrator credential
```

Norn should attempt to protect against:

```text
coordinator inserts unauthorized peer

coordinator replaces a legitimate WireGuard key

silent unauthorized key rotation

silent peer resurrection after revocation

history rewriting

log equivocation / split views

stale authorization state being presented as current

deletion of historical authorization events
```

Norn does NOT automatically protect against:

```text
compromised endpoint

stolen active WireGuard private key

compromise of sufficient Norn authority keys

compromise of sufficient witness quorum

malicious local root / kernel

denial of service

traffic analysis

malicious routing configuration

malicious DNS configuration

malicious ACLs outside Norn's authorization scope
```

Do not let documentation imply otherwise.

---

# 9. Identity Model

Do not permanently equate device identity with a WireGuard key.

Preferred model:

```text
Norn Device Identity
        │
        ├── stable identity key
        │
        └── current WireGuard credential
                         │
                         ├── WG key A
                         ├── WG key B
                         └── WG key C
```

A device should be able to rotate its WireGuard credential without becoming a new device.

Do not invent custom cryptographic primitives.

---

# 10. Initial Event Model

Review whether this event set remains sufficient:

```text
GENESIS

AUTHORITY_ADD
AUTHORITY_REVOKE

DEVICE_ENROLL
DEVICE_REVOKE

WG_KEY_BIND
WG_KEY_ROTATE
WG_KEY_REVOKE
```

Every event should eventually define:

```text
protocol version
network ID
event type
sequence / logical ordering
device identity
new state
previous state when relevant
issuer identity
timestamp when appropriate
authorization signature
canonical serialized representation
```

Avoid ambiguous serialization.

---

# 11. Transparency Architecture

Norn should not depend on blockchain for its primary operation.

Preferred architecture:

```text
signed authorization events
          │
          ▼
append-only Merkle transparency log
          │
          ▼
signed checkpoints
          │
          ▼
independent witnesses
          │
          ▼
client verification
```

Evaluate Tessera as infrastructure.

Norn owns:

```text
event semantics
authorization semantics
WireGuard semantics
revocation semantics
identity model
current-state model
verification policy
adapters
client enforcement
```

Tessera may own:

```text
Merkle log construction
append-only storage
tree tiles
checkpoints
inclusion mechanisms
consistency mechanisms
storage backends
```

Do not build a custom transparency engine unless a documented technical need exists.

---

# 12. Current-State and Revocation Problem

An inclusion proof alone does not prove that a key is currently authorized.

Example:

```text
event 10: DEVICE_ENROLL Alice
event 25: WG_KEY_BIND Alice K1
event 78: WG_KEY_REVOKE Alice K1
```

The inclusion proof for event 25 remains valid after event 78.

Norn therefore needs authenticated current-state semantics.

Investigate:

```text
authenticated map
sparse Merkle tree
KEYTRANS-style searchable authenticated state
locally replayed deterministic state
signed state snapshots
```

Never claim that historical inclusion proves absence of later revocation.

---

# 13. Freshness

A valid old proof may describe stale authorization.

Norn must have explicit freshness behavior.

Potential policy:

```toml
[verification]
max_checkpoint_age = "10m"
offline_grace_period = "8h"
fail_mode = "closed"
```

Potential profiles:

```text
STRICT
BALANCED
OFFLINE
```

Any availability tradeoff must be explicit.

---

# 14. Witnesses

Evaluate independent witnesses.

Conceptual model:

```text
                   Norn Log
                      │
              signed checkpoint
                      │
         ┌────────────┼────────────┐
         ▼            ▼            ▼
      Witness A    Witness B    Witness C
         │            │            │
         └────────────┼────────────┘
                      │
                  quorum
                      │
                      ▼
                client accepts
```

Investigate C2SP witness protocols before creating custom witness mechanics.

Explicitly analyze split-view attacks.

---

# 15. WireGuard Enforcement

Prefer integration without modifying WireGuard.

Concept:

```text
coordinator proposes peer
          │
          ▼
      Norn Agent
          │
    verifies state
          │
          ▼
       approved?
        /     \
      yes      no
      │         │
      ▼         X
wgctrl peer   reject
```

Research `wgctrl-go` as the preferred Go integration boundary.

Compare it against:

- invoking `wg`
- direct userspace configuration protocol
- direct Netlink

Document the choice in an ADR.

---

# 16. Official WireGuard Project-List Goal

Long-term target:

Norn should become mature enough that contacting the WireGuard team about technical review and possible inclusion on the official related-project list is defensible.

Do not optimize the codebase for marketing.

Optimize for technical credibility.

Maintain:

```text
docs/upstream/OFFICIAL_PROJECT_CHECKLIST.md
```

Suggested checklist:

```text
[ ] repository public
[ ] clear open-source license
[ ] README polished
[ ] architecture documented
[ ] threat model documented
[ ] protocol documented
[ ] SECURITY.md
[ ] CONTRIBUTING.md
[ ] reproducible demo
[ ] CI green
[ ] adversarial tests
[ ] tagged release
[ ] installation instructions
[ ] Linux tested
[ ] standard WireGuard tested
[ ] no unnecessary WireGuard fork
[ ] no custom cryptographic primitives
[ ] stable wgctrl/wg integration
[ ] external review requested
[ ] useful testers/users
[ ] upstream team contacted for technical feedback
```

Do not automatically contact upstream when this checklist is complete.

Perform a final technical review first.

---

# 17. WireGuard TODO Research Rules

When reviewing official TODO items:

1. verify the item is still relevant
2. inspect the actual repository
3. inspect recent commits
4. inspect existing patches
5. inspect mailing-list discussion where relevant
6. identify whether somebody already owns the work
7. estimate contribution scope
8. identify required expertise
9. find the smallest legitimate contribution

Never assume an old TODO page means the task remains open exactly as written.

---

# 18. Contribution Ladder

Preferred progression:

```text
Stage 1
Understand repositories and development process.

Stage 2
Reproduce test environment.

Stage 3
Submit a small legitimate test or documentation improvement.

Stage 4
Submit a small code improvement.

Stage 5
Work on a TODO item with maintainer coordination.

Stage 6
Become a recurring contributor.

Stage 7
Consider maintaining a subsystem/project.
```

Do not manufacture trivial pull requests just to advance through stages.

---

# 19. Priority Parallel Tracks

## A. Testing infrastructure

Research:

- missing code paths in tests
- `netns.sh`
- latency testing
- packets-per-second testing
- buffer-bloat coverage
- regression opportunities

Goal:

Find a small meaningful upstream contribution that improves confidence without altering protocol behavior.

---

## B. Documentation / developer docs

Research genuine documentation gaps.

Possible areas:

- configuration internals
- peer lifecycle
- AllowedIPs behavior
- userspace configuration protocol
- developer setup
- architecture documentation

Avoid cosmetic-only contributions.

---

## C. `wgctrl-go`

High relevance to Norn.

Research:

- current maintenance
- open issues
- test gaps
- platform behavior
- API limitations
- edge cases useful to Norn
- documentation gaps

If a real defect or missing test is found, this may be one of the strongest early upstream contribution targets.

---

## D. `wg-dynamic`

Research before implementation.

Determine:

- current status
- recent activity
- remaining intent
- protocol status
- whether upstream still wants contributions
- overlap with modern control planes
- overlap with Norn

Contact upstream before large implementation work.

---

## E. Mesh networking tools

This is highly relevant conceptually.

Research whether Norn should:

```text
remain only a trust layer
```

or whether:

```text
a separate mesh project should consume Norn
```

Do not turn Norn into a control plane without an explicit ADR.

---

## F. WireGuard utilities

Search for genuinely missing focused tools.

Potential areas:

```text
configuration validation
AllowedIPs conflict analysis
topology inspection
safe configuration diffing
configuration linting
peer diagnostics
troubleshooting utilities
```

Search existing projects first.

---

## G. Dynamic provisioning web application

Research whether a modern implementation remains useful.

Do not build another generic WireGuard dashboard.

Identify the exact missing capability before implementation.

---

## H. `wireguard-go`

Contribution is a possible future goal.

Before touching it deeply, understand:

- codebase
- tests
- supported platforms
- userspace WireGuard internals
- release process
- performance constraints
- protocol responsibility

---

## I. `wireguard-go` maintainership

Long-term possibility only.

Maintain a separate readiness assessment:

```text
docs/upstream/WIREGUARD_GO.md
```

Use:

```text
NOT_READY
POSSIBLE_LATER
READY_TO_DISCUSS
```

Do not volunteer for maintainership until contribution history and technical readiness justify it.

---

## J. Kernel / advanced work

Includes:

```text
kernel performance TODOs
lock auditing
buffer auditing
GRO
trie improvements
per-peer PMTU
timers
crypto-sensitive behavior
```

Treat this as advanced work.

Do not choose it merely for prestige.

Only proceed after building the necessary Linux networking/kernel expertise.

---

# 20. Required Project-Memory Updates

At the end of a meaningful work session, update persistent context when something changed.

At minimum consider updating:

```text
docs/upstream/CONTRIBUTION_TRACKER.md
docs/upstream/TODO_RESEARCH.md
docs/upstream/WIREGUARD_READINESS.md
docs/audit/PROJECT_STATUS.md
docs/audit/ROADMAP.md
```

Record:

```text
what changed
what was learned
decisions made
links/evidence
current blockers
next action
```

Do not rely on the conversational memory of Codex, Claude Code, or any other agent.

Important decisions must live in the repository.

---

# 21. Session Handoff

Before ending a substantial session, leave a short handoff.

Preferred file:

```text
docs/HANDOFF.md
```

Keep it compact:

```markdown
# Current Handoff

## Current focus

## Completed

## In progress

## Important decisions

## Open security questions

## Blockers

## Exact next actions

## Files changed

## Tests run

## Upstream workstreams affected
```

Update rather than endlessly appending stale handoffs.

---

# 22. ADRs

Important architecture decisions belong in:

```text
docs/decisions/
```

Example ADRs:

```text
ADR-001 Do not modify WireGuard handshake
ADR-002 Separate device identity from WG key
ADR-003 Transparency-log implementation
ADR-004 Canonical event encoding
ADR-005 Authority quorum model
ADR-006 Current-state proof structure
ADR-007 Witness policy
ADR-008 Freshness/offline policy
ADR-009 WireGuard integration boundary
```

Do not bury architecture decisions only in chat history.

---

# 23. First Assignment for a New Agent

When Codex or Claude Code first receives this file:

1. read the complete repository
2. read all existing project docs
3. inspect `git status`
4. inspect recent commits
5. run tests
6. run build/static tooling
7. identify the current Norn milestone
8. inspect the upstream contribution tracker
9. identify stale context
10. update project-memory files before major implementation work

Then provide:

```text
CURRENT NORN STATUS
CURRENT SECURITY RISKS
CURRENT MILESTONE
NEXT 5 NORN TASKS
UPSTREAM CONTRIBUTION STATUS
UPSTREAM ITEMS WORTH RESEARCHING NEXT
```

Do not perform a large refactor before this review.

---

# 24. Final Rule

Norn remains the primary project.

The WireGuard upstream tracks are persistent strategic workstreams, not distractions.

Use this hierarchy:

```text
1. Keep Norn technically correct.

2. Keep Norn's architecture focused.

3. Preserve knowledge about upstream opportunities.

4. Make legitimate WireGuard contributions when a validated opportunity appears.

5. Build enough credibility and quality that Norn can eventually be presented to the WireGuard team for technical review.
```

Important project context must be stored in repository documentation rather than depending on any individual AI agent's conversation history.
