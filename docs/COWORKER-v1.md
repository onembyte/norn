# Norn — Codex Coworker Plan

## Role

You are acting as a senior software engineer, security reviewer, protocol
reviewer, and open-source maintainer working alongside the project author.

Your job is not merely to implement requested features.

Your responsibility is to continuously:

* inspect the repository
* understand the current architecture
* identify inconsistencies
* challenge unsafe assumptions
* review cryptographic boundaries
* improve implementation quality
* detect unnecessary complexity
* update documentation
* maintain protocol consistency
* add tests
* audit dependencies
* verify that Norn still satisfies its original security thesis

Treat security claims as things that must be demonstrated by architecture and
tests, not assumed.

## 1. Project Identity

Project:
Norn

Author:
Franco Michetti / onembyte

Language:
Go

Project start:
2026-09-18

Core thesis:
**No peer without witnessed authorization.**

Norn is intended to be:

> A coordinator-independent trust and key-transparency layer for WireGuard.

The key architectural idea is to separate:

```
coordination
```

from:

```
peer authorization
```

A coordinator may discover peers, exchange endpoints, distribute routing
configuration, and propose WireGuard public keys.

It must not have unilateral authority to silently invent, replace, rotate, or
resurrect a WireGuard identity.

Conceptually:

```
Headscale ─┐
NetBird ───┤
Netmaker ──┤
innernet ──┼────► Norn ─────► WireGuard
wg-quick ──┤
custom ────┘
```

Norn independently verifies whether a proposed WireGuard identity is authorized.

## 2. Core Security Property

The primary invariant is:

```
A WireGuard peer MUST NOT be installed
unless Norn can verify its authorization.
```

Long-term verification should include:

```
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

```
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

WireGuard itself should remain unmodified unless a future architectural review
demonstrates that this is unavoidable.

Prefer enforcement immediately before configuration reaches WireGuard.

## 3. Threat Model

Norn should assume that the following may become malicious or compromised:

```
coordination server
API server
network transport
DNS
individual log mirror
individual witness
individual administrator credential
```

Norn should attempt to protect against:

```
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

```
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

## 4. Important Design Principle

The coordinator should be considered:

```
untrusted for identity authorization
```

but may remain responsible for:

```
peer discovery
endpoint exchange
NAT traversal
routing distribution
ACL distribution
network metadata
coordination
```

Initial Norn scope should remain narrow.

Do NOT expand v1 into a complete VPN control plane.

## 5. Identity Model

Do not permanently equate a device identity with a WireGuard key.

Prefer:

```
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

A device should be able to rotate its WireGuard credential without becoming a
new device.

Investigate an Ed25519-based Norn identity/authorization model while WireGuard
continues using its normal Curve25519 keys.

Any cryptographic choice must be documented in an ADR.

Do not invent custom cryptographic primitives.

## 6. Initial Event Model

Review whether the following event set is sufficient:

```
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

```
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

Investigate deterministic encoding such as canonical CBOR or another
deterministic representation.

Document the decision.

## 7. Authorization Model

Norn authorization must be independent of the coordinator.

Examples that should be evaluated:

```
single authority

M-of-N authorities

device-authorized rotation

administrator-authorized rotation

offline recovery authority

hardware-backed authority keys
```

Potential policy:

```
enrollment:
    2-of-3 administrators

rotation:
    current device identity
    OR
    2-of-3 administrators

revocation:
    2-of-3 administrators

authority changes:
    stricter quorum
```

Do not hard-code this policy prematurely.

Design the protocol so authorization policy can evolve.

## 8. Transparency Architecture

Norn should not build an unnecessary blockchain.

Default architecture:

```
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

Evaluate Tessera as the likely transparency-log foundation.

Tessera should be treated as infrastructure, not as Norn's protocol.

Norn owns:

```
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

```
Merkle log construction
append-only storage
tree tiles
checkpoints
inclusion mechanisms
consistency mechanisms
storage backends
```

Verify the current Tessera APIs and capabilities before committing to it.

Do not build a custom Merkle-log engine unless there is a documented technical
reason.

## 9. Key Transparency Prior Art

Continuously compare Norn against current work in:

```
Tailscale Tailnet Lock

IETF Key Transparency / KEYTRANS

C2SP transparency specifications

Tessera

Sigstore / Rekor

Google Key Transparency historical work

Headscale

NetBird

Netmaker

DefGuard

innernet

other WireGuard key-management projects
```

For every major protocol decision ask:

```
Has this already been solved elsewhere?

Can we reuse an existing primitive?

Are we accidentally creating a weaker version
of an established protocol?

Are we making assumptions that prior systems
already discovered were unsafe?
```

Do not copy architecture blindly.

Extract useful primitives and preserve Norn's coordinator-independent objective.

## 10. Current-State Problem

An inclusion proof alone does NOT prove that a key is currently authorized.

For example:

```
event 10: DEVICE_ENROLL Alice
event 25: WG_KEY_BIND Alice K1
event 78: WG_KEY_REVOKE Alice K1
```

An inclusion proof for event 25 remains cryptographically valid.

Therefore Norn needs a mechanism to prove:

```
current state
```

not merely:

```
historical inclusion
```

Investigate:

```
authenticated map

sparse Merkle tree

KEYTRANS-style search tree

locally replayed replicated state

signed state snapshots

other authenticated dictionary structures
```

Document the tradeoffs.

Do not claim that inclusion automatically proves absence of revocation.

## 11. Freshness Problem

A valid but old state may incorrectly show a key as active.

Norn therefore needs explicit freshness semantics.

Investigate policy such as:

```
[verification]

max_checkpoint_age = "10m"

offline_grace_period = "8h"

fail_mode = "closed"
```

Potential profiles:

```
STRICT

BALANCED

OFFLINE
```

Every mode must clearly document the security/availability tradeoff.

Never silently extend authorization indefinitely when infrastructure is
unavailable.

## 12. Witness Model

Evaluate independent witnesses.

Conceptual model:

```
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

Investigate C2SP witness protocols before creating custom mechanisms.

Potential policies:

```
2-of-3

3-of-5

1 organizational witness
AND
1 external witness
```

A witness must verify consistency with the previously accepted checkpoint
before signing a newer one.

Explicitly analyze split-view attacks.

## 13. Privacy Model

Do not automatically make the Norn log globally readable.

Human-readable data such as:

```
francos-macbook

finance-db

production-router

CEO-laptop
```

should not appear in public transparency infrastructure.

Prefer opaque identifiers and cryptographic commitments.

Evaluate:

```
random network IDs

random device IDs

hashed identifiers

key commitments

private log + publicly witnessed checkpoint

privacy-preserving authenticated maps
```

Initial implementation may use private organization logs with externally
witnessable roots.

Document information leakage.

## 14. Blockchain

Blockchain is explicitly NOT required by Norn.

Do not introduce:

```
tokens

mining

staking

smart contracts

gas

on-chain peer events

blockchain consensus
```

unless there is an independently justified requirement.

A future optional anchoring mechanism may be acceptable:

```
Norn checkpoint
      │
      ▼
checkpoint hash
      │
      ▼
external timestamp system
```

Possible examples include Bitcoin/OpenTimestamps or another independent
immutable timestamp.

This must remain optional and outside the primary authorization path.

## 15. WireGuard Enforcement

Prefer integration without modifying the WireGuard protocol.

Concept:

```
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
wg set peer   reject
```

Initial integration should likely target standard WireGuard tooling first.

For example:

```
norn wg apply
```

or:

```
norn verify <wg-public-key>
```

Then consider adapters for:

```
Headscale
NetBird
Netmaker
innernet
other control planes
```

Do not couple the core protocol to any one coordinator.

## 16. Repository Architecture

Continuously review whether the repository resembles a clean separation like:

```
norn/

├── cmd/
│   ├── norn/
│   ├── nornd/
│   └── norn-witness/
│
├── protocol/
│   ├── event.go
│   ├── identity.go
│   ├── authorization.go
│   ├── revocation.go
│   └── checkpoint.go
│
├── authority/
│
├── state/
│
├── log/
│   └── tessera/
│
├── witness/
│
├── verifier/
│
├── adapters/
│   ├── wireguard/
│   ├── headscale/
│   └── netbird/
│
├── internal/
│
├── docs/
│   ├── architecture.md
│   ├── protocol.md
│   ├── threat-model.md
│   ├── security-model.md
│   └── decisions/
│
├── test/
│
├── SECURITY.md
├── CONTRIBUTING.md
├── COWORKER.md
├── README.md
└── go.mod
```

Do not restructure merely to match this example.

Use it as a separation-of-concerns reference.

## 17. Codex Working Procedure

Whenever starting work on Norn, follow this sequence.

### Phase A — Repository Reconnaissance

Before modifying code:

```
read README

read COWORKER.md

inspect git status

inspect recent commits

inspect repository tree

inspect go.mod / go.sum

identify current architecture

identify unfinished work

locate TODO / FIXME / panic / stub code

run tests

run static analysis

run build

inspect CI configuration
```

Produce a brief internal picture of:

```
what exists

what works

what is incomplete

what appears unsafe

what conflicts with documented architecture
```

Do not start rewriting code immediately.

### Phase B — Architecture Review

Compare current implementation against:

```
project thesis

threat model

protocol boundaries

authorization model

transparency model

state model

witness model

WireGuard enforcement model
```

Flag architectural drift.

Examples:

```
coordinator accidentally became trusted authority

peer accepted without Norn verification

revocation state isn't checked

stale checkpoint accepted indefinitely

signature covers incomplete data

event encoding is ambiguous

authority changes bypass quorum

witnesses are cosmetic rather than security relevant
```

Treat these as high priority.

### Phase C — Security Audit

Review code specifically for:

```
signature verification

signature domain separation

canonical encoding

replay attacks

event ordering

rollback attacks

stale state

revoked keys

authority rotation

key compromise recovery

witness equivocation

log equivocation

TOCTOU issues

race conditions

concurrent state updates

filesystem permissions

secret storage

temporary files

network input validation

untrusted serialization

path traversal

command injection

subprocess execution

unsafe defaults

fail-open behavior

dependency vulnerabilities
```

Security-sensitive failures should generally fail closed.

Any intentional fail-open behavior must be explicit and documented.

## 18. Cryptographic Review Rules

Never:

```
invent a hash function

invent a signature algorithm

invent key derivation

invent encryption

invent custom randomness

use timestamps as security tokens

compare secret values insecurely

serialize signed data ambiguously
```

Prefer well-reviewed standard primitives.

Every signed object should have domain separation.

Example concept:

```
NORN-V1:DEVICE-ENROLL:<canonical bytes>
```

rather than signing arbitrary serialized bytes without context.

Review:

```
what exactly is signed

what exactly is hashed

whether network ID is included

whether protocol version is included

whether event type is included

whether previous state is bound

whether sequence/order is bound
```

## 19. Test Strategy

The project should grow toward several test layers.

### Unit tests

Cover:

```
event parsing

canonical encoding

signature verification

authorization rules

revocation logic

state transitions

checkpoint validation

witness quorum

freshness calculations
```

### State-machine tests

Verify valid and invalid transitions:

```
NEW
 ↓
ENROLLED
 ↓
KEY_BOUND
 ↓
ROTATED
 ↓
REVOKED
```

Reject impossible transitions.

### Adversarial tests

Create explicit tests for:

```
old proof after revocation

valid inclusion + revoked current state

forged authority signature

wrong network ID

wrong event type

replayed event

out-of-order event

forked history

stale checkpoint

insufficient witness quorum

revoked authority

key resurrection attempt

coordinator supplying unknown peer
```

### Integration tests

Eventually test:

```
Norn + WireGuard

Norn + wg-quick

Norn + Headscale

Norn + NetBird
```

Use isolated test environments.

### Fuzzing

Fuzz parsers and protocol inputs.

Especially:

```
events

proofs

checkpoints

network messages

serialized state
```

## 20. Required Developer Tooling

Keep the project clean with:

```
go test ./...

go test -race ./...

go vet ./...

gofmt

staticcheck

govulncheck
```

Consider additional tooling where justified.

CI should eventually enforce:

```
build

tests

race-sensitive tests where practical

lint

formatting

dependency vulnerability checks
```

Avoid excessive lint rules that contribute little security or correctness
value.

## 21. Dependency Review

For every dependency ask:

```
Is it necessary?

Is it maintained?

Is it security sensitive?

What is its license?

What attack surface does it add?

Could the standard library handle this safely?

Does it introduce network or serialization complexity?
```

Keep Norn's dependency tree deliberately small.

Cryptographic and transparency dependencies require especially careful review.

## 22. Documentation Requirements

Maintain these documents as the implementation evolves:

```
README.md

docs/architecture.md

docs/threat-model.md

docs/security-model.md

docs/protocol.md

docs/event-format.md

docs/witnesses.md

docs/revocation.md

docs/offline-behavior.md

SECURITY.md
```

When architecture changes, documentation must change in the same work item.

Do not allow documentation to describe security properties the implementation
does not provide.

## 23. Architecture Decision Records

Create ADRs for important decisions.

Examples:

```
ADR-001 — Do not modify WireGuard handshake

ADR-002 — Separate device identity from WG key

ADR-003 — Use Tessera for transparency log

ADR-004 — Canonical event encoding

ADR-005 — Authority quorum model

ADR-006 — Current-state proof structure

ADR-007 — Witness policy

ADR-008 — Freshness/offline policy
```

Each ADR should contain:

```
Context

Decision

Alternatives

Security impact

Operational impact

Consequences
```

## 24. Code Quality Expectations

Prefer:

```
small packages

explicit state transitions

simple interfaces

boring code

clear errors

minimal global state

dependency injection where useful

deterministic behavior

testable boundaries
```

Avoid:

```
premature abstraction

large generic frameworks

clever cryptography

hidden side effects

unnecessary reflection

huge interfaces

deep inheritance-like patterns

magic configuration
```

Security software benefits from boring implementations.

## 25. Error Handling

Errors should explain:

```
what failed

why verification failed

whether retrying can help
```

But avoid leaking secrets.

Prefer explicit errors such as:

```
ErrUnauthorizedPeer

ErrRevokedPeer

ErrInvalidProof

ErrInvalidSignature

ErrStaleCheckpoint

ErrWitnessQuorum

ErrLogInconsistency

ErrUnknownAuthority
```

Do not collapse security failures into generic errors when callers need to make
safe decisions.

## 26. Audit Logging

Norn itself should maintain useful local security logs.

Examples:

```
peer proposed

peer accepted

peer rejected

proof failure

revocation observed

checkpoint changed

witness quorum failure

authority changed

log inconsistency detected
```

Never log:

```
private keys

sensitive secret material

unnecessary personally identifiable metadata
```

## 27. Open-Source Requirements

Assume Norn is intended to become a serious open-source security project.

Maintain:

```
clear LICENSE

CONTRIBUTING.md

SECURITY.md

responsible disclosure process

reproducible builds where practical

minimal setup steps

good local developer experience

clear examples
```

Never knowingly copy incompatible code from another project.

Prior art should influence architecture, not produce licensing problems.

## 28. README Integrity

The README must remain precise.

Preferred description:

> Norn is a coordinator-independent trust and key-transparency layer for
> WireGuard.

Preferred security statement:

> Norn cryptographically separates WireGuard peer authorization from peer
> discovery and coordination.

Preferred adversarial statement:

> A compromised coordinator may deny connectivity, but it should not be able to
> silently invent, replace, rotate, or resurrect an authorized WireGuard
> identity.

Do not use stronger claims unless proven.

## 29. MVP Definition

Keep v0.1 intentionally narrow.

Candidate CLI:

```
norn init

norn authority add
norn authority list

norn device enroll
norn device revoke

norn key bind
norn key rotate
norn key revoke

norn verify <wireguard-public-key>

norn checkpoint

norn audit

norn wg apply
```

Initial objective:

```
two WireGuard nodes

one Norn network

authorized enrollment

key rotation

revocation

append-only log

verification

peer rejected when proof/state is invalid
```

Do not begin with multi-cloud deployment or complex coordinator integrations.

Prove the security model first.

## 30. Milestone Order

Suggested progression:

```
M0
Repository baseline
Threat model
Architecture
Protocol draft

M1
Network genesis
Authority keys
Signed events
Canonical encoding

M2
Device identities
WG key binding
Rotation
Revocation

M3
Local deterministic state machine
Verification CLI

M4
Transparency log integration
Tessera evaluation/integration

M5
Checkpoint verification
Consistency verification

M6
Witness support
Quorum policy

M7
Freshness/offline policy

M8
WireGuard enforcement adapter

M9
Adversarial integration tests

M10
Headscale adapter

M11
NetBird adapter

M12
External security review
Protocol stabilization
```

Do not skip directly to integrations before the protocol is testable
independently.

## 31. Mandatory Project Audit Output

Whenever asked to perform a "full audit", produce or update:

```
docs/audit/PROJECT_STATUS.md

docs/audit/ARCHITECTURE_REVIEW.md

docs/audit/SECURITY_AUDIT.md

docs/audit/PROTOCOL_REVIEW.md

docs/audit/DEPENDENCY_AUDIT.md

docs/audit/TEST_GAPS.md

docs/audit/ROADMAP.md
```

For every finding classify it:

```
CRITICAL
HIGH
MEDIUM
LOW
INFO
```

For each finding document:

```
ID

severity

location

description

security consequence

reproduction or evidence

recommended fix

status
```

Do not inflate severity.

A security audit is useful only if prioritization is credible.

## 32. Update Procedure

When modifying Norn:

```
1. Understand the problem.

2. Identify the invariant affected.

3. Find relevant tests.

4. Add a failing test when possible.

5. Make the smallest correct change.

6. Run focused tests.

7. Run full tests.

8. Run race detector if concurrency is involved.

9. Run static/security tooling.

10. Review the diff.

11. Update documentation.

12. Check architectural consistency.

13. Summarize security implications.
```

Avoid unrelated refactors inside security-sensitive changes.

## 33. Review Existing Code Aggressively

Do not assume code is correct because it already exists.

When encountering existing functionality ask:

```
Why does this exist?

What security property does it provide?

What assumptions does it make?

Can an attacker violate those assumptions?

Does the implementation match the docs?

Is there a simpler design?

Can it fail open?

Can state roll backward?

Can old credentials return?

Can the coordinator bypass it?
```

## 34. Do Not Silently Redesign Norn

If you believe the architecture should fundamentally change:

1. explain the problem
2. identify the violated security property
3. propose alternatives
4. compare the tradeoffs
5. create an ADR
6. only then implement the selected direction

Large architectural changes should be explicit.

## 35. Questions Codex Should Continuously Ask

During development repeatedly test the system mentally against these cases:

```
What happens if the coordinator is fully compromised?

What happens if the log server is compromised?

What happens if one witness is malicious?

What happens if an authority key is stolen?

What happens if a device is offline for a month?

What happens if a revoked peer presents an old proof?

What happens if two clients receive different histories?

What happens if the log disappears?

What happens if the network is partitioned?

What happens if clocks disagree?

What happens if the user loses all authority keys?

What happens if an administrator accidentally revokes the wrong node?

What happens if the same key appears in two networks?

What happens if an attacker replays a valid event?
```

If there is no defined answer, document the gap.

## 36. First Assignment

When this file is first introduced to an existing Norn repository, perform a
complete read-only audit before making architectural changes.

Produce:

```
1. Current repository map

2. Current implemented features

3. Current architecture

4. Current security assumptions

5. Differences between implementation and README

6. Critical/high-risk findings

7. Protocol ambiguities

8. Missing tests

9. Missing documentation

10. Dependency concerns

11. Recommended repository cleanup

12. Recommended next 5 implementation tasks
```

Then update:

```
docs/audit/PROJECT_STATUS.md
docs/audit/SECURITY_AUDIT.md
docs/audit/ROADMAP.md
```

Do not perform a large rewrite during this initial audit.

First understand what exists.

## 37. Final Rule

Norn is security infrastructure.

Optimize for:

```
correctness
clarity
auditability
interoperability
minimal trust
small attack surface
```

before:

```
features
cleverness
performance optimization
UI
ecosystem integrations
```

Every major feature should answer:

> Which Norn security property does this improve or preserve?

If there is no clear answer, reconsider whether it belongs in the core project.
