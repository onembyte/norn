---
title: "Verifying WireGuard Peer Authorization Independently of the Coordinator: Problem Statement and Requirements"
abbrev: "WireGuard Peer Authorization Problem"
category: info
docname: draft-michetti-wireguard-peer-authz-problem-00
submissiontype: IETF
number:
date:
consensus: false
v: 3
area: SEC
keyword:
 - WireGuard
 - key transparency
 - authorization
 - transparency log
author:
 -
    fullname: Franco Michetti
    email: TBD

normative:

informative:
  WIREGUARD:
    title: "WireGuard: Next Generation Kernel Network Tunnel"
    author:
      - name: Jason A. Donenfeld
    date: 2017
    seriesinfo:
      NDSS: 2017
    target: https://www.wireguard.com/papers/wireguard.pdf
  TAILNET-LOCK:
    title: "Tailnet Lock white paper"
    author:
      - org: Tailscale
    target: https://tailscale.com/kb/1230/tailnet-lock-whitepaper
  TLOG-WITNESS:
    title: "Transparency Log Witness Protocol"
    author:
      - org: C2SP
    target: https://c2sp.org/tlog-witness
  TLOG-CHECKPOINT:
    title: "Transparency Log Checkpoints"
    author:
      - org: C2SP
    target: https://c2sp.org/tlog-checkpoint
  I-D.ietf-keytrans-architecture:
  I-D.ietf-keytrans-protocol:
  RFC6962:
  RFC9162:
  RFC7942:

--- abstract

WireGuard identifies each peer by a static public key and binds to it the
IP prefixes that peer may source. It deliberately leaves the distribution
of those keys and prefixes to something else, and in most deployments that
something is a coordination server that every node trusts completely. A
compromised or coerced coordinator can give one node an attacker's key,
widen a legitimate peer's prefixes, or withhold a revocation, and nothing on
the node can tell. This document describes that problem, states a threat
model, and lists requirements for an interoperable mechanism by which a
WireGuard endpoint can verify a peer key's current authorization, and its
route grant, independently of the coordinator that delivered it. It relates
the problem to Key Transparency and asks whether such a mechanism belongs
in scope there.

--- middle

# Introduction

WireGuard {{WIREGUARD}} binds each peer to a static Curve25519 public key
and, through cryptokey routing, to the set of IP prefixes ("allowed IPs")
that peer may source and receive. The protocol authenticates a peer as the
holder of a key. Which keys a node should accept, and with which prefixes,
is outside the protocol by design.

Mesh deployments answer that question with a coordinator: a control plane
that enrolls devices, collects their public keys and pushes every node's
peer list, including keys and allowed IPs. Nodes install what the
coordinator sends. The coordinator is therefore trusted for the integrity of
every peer table in the network, in addition to the availability it was
deployed to provide.

That trust has no check. A node cannot distinguish a key its operators
authorized from a key the coordinator inserted, a prefix that was granted
from one that was widened, or a revocation that never happened from one that
was withheld. Different nodes cannot tell whether they were sent the same
peer set. When a coordinator is compromised, the damage is silent; when the
compromise is found, there is no record from which to enumerate what it did.

Transparency logs have solved the shape of this problem for Web PKI
certificates {{RFC6962}} {{RFC9162}} and are being applied to end-user keys in
Key Transparency {{I-D.ietf-keytrans-architecture}}. This document asks what
the same idea requires when the object is not a certificate or a user's key
but a peer's authorization to join, and route within, a WireGuard network.

# Terminology

Node:
: A host running a WireGuard interface whose peer table is under discussion.

Peer key:
: A WireGuard static public key, as installed in a node's peer table.

Coordinator:
: Any party that distributes peer keys and allowed IPs to nodes: a control
plane, a management server, a configuration-management system, or a person.

Authorizer:
: A party whose signature authorizes a change to the peer set: enrolling a
device, rotating its key, revoking it. Authorizers may be organized in roles
with thresholds.

Grant:
: The set of IP prefixes a peer is authorized to source, as authorized
alongside its key.

Authorization state:
: The set of currently authorized peer keys with their grants, together with
the set of authorizers and thresholds currently in force.

Trust anchor:
: The information a node is provisioned with out of band before it trusts
anything else, for example a log's public key, a witness policy and an
initial state.

# The Problem

## What a coordinator can do today

A coordinator that is compromised, coerced or simply buggy can, in typical
deployments:

1. install an attacker-controlled peer key on one or more nodes;
2. replace a legitimate peer's key with an attacker's, positioning itself
   between two peers;
3. widen a legitimate peer's allowed IPs, for example to a default route,
   redirecting traffic the operators never granted;
4. withhold a revocation, so a removed device keeps its access;
5. show different nodes different peer sets, so that no comparison between
   two nodes' views is possible without a channel the coordinator does not
   control.

None of these requires breaking WireGuard. Each is a correct installation of
an incorrect instruction.

## Why signing configurations is not enough

If authorizers sign each peer-set change, a node can reject a change no
authorizer made. That addresses items 1 to 3 against a coordinator without
signing keys. It does not address item 5: a coordinator can show two nodes
two different sequences of validly signed changes, and each is consistent on
its own. It does not address item 4, because a signature proves that a
revocation was made, not that a node has received it. And it gives no
enumerable record: after an authorizer key is stolen, there is no list of
what it signed.

These are the gaps an append-only, publicly verifiable log closes for
certificates. The question is what closing them requires for peer
authorization, where the log's contents are not independent bindings but a
sequence of changes whose validity depends on the state that preceded them.

## What exists

Tailscale's Tailnet Lock {{TAILNET-LOCK}} is the deployed system closest to
this problem. Nodes verify that peer keys are signed by trusted lock keys, and
changes to the set of lock keys form a signed chain every node holds. Its
white paper is explicit about what remains: the chain is relayed by the
control plane ("The control plane then relays this update to all nodes in
the tailnet"); a compromised control plane can still break connectivity; and
the initial state is trusted on first use ("If the control plane is
compromised, a malicious initial state could be sent to each node with
attacker-controlled TLKs"). The chain records changes to who may sign, not
every peer key that was signed, and it is specific to one implementation.

Certificate-based meshes sign each node's certificate with an offline
authority. Revocation is typically a list distributed in configuration, with
no proof that a node received it.

Key Transparency {{I-D.ietf-keytrans-architecture}} {{I-D.ietf-keytrans-protocol}}
provides an authenticated, versioned key-value directory with consistency
proofs and fork detection. {{rel-kt}} discusses how its model relates to this
problem.

# Threat Model

The mechanism this document asks for is meant to hold against the following
adversaries. Each is assumed to be able to act alone; the bounds below are the
ones under which the requirements in {{reqs}} must still hold.

Coordinator:
: Full control of every configuration a node receives, including peer keys,
allowed IPs and endpoints. Holds no authorizer key. Untrusted for the peer
set.

Log operator:
: If the mechanism uses a log, its operator may withhold entries, stop
publishing, present different histories to different nodes, or append
garbage. Holds no authorizer key. Untrusted for correctness.

Witnesses:
: Independent parties that attest to a log's append-only growth. Fewer than
a configured threshold collude with the log operator.

Authorizers:
: Trusted within their roles and thresholds. A single stolen authorizer key
must not be able to change who the authorizers are.

Network attacker:
: On-path or off-path between any of the above.

A compromised node:
: Controls its own peer table and may lie to other nodes, but cannot forge
authorizer signatures.

Bootstrap:
: A node is provisioned with its trust anchor through a channel the
coordinator does not control. There is no trust on first use.

Clocks:
: A node's local clock may be wrong or manipulated.

Out of scope: availability (a coordinator, or a network attacker, can always
deny service); a peer's WireGuard private key stolen before its revocation is
authorized; traffic policy between authorized peers; and directories at the
scale of the public Internet.

# Requirements {#reqs}

The requirements below describe a mechanism, not an implementation. They are
written without BCP 14 keywords because this document defines no protocol.

Req-1, current authorization:
: A node can verify, before installing a peer key, that the key is
authorized now, and not only that it was authorized at some point. Inclusion
of an authorization in a log proves history; currency additionally requires
that no later revocation or replacement applies.

Req-2, route grant:
: A peer's grant is authorized together with its key, and a node can bound
the allowed IPs it installs for that peer by the grant. Widening a grant is
an authorized change like any other.

Req-3, revocation as a fact:
: Revocation is an authorized, ordered, verifiable event in the same record
as enrollment, not an out-of-band list, so that a node can prove it has, or
has not, seen it.

Req-4, transparent authority:
: Changes to the set of authorizers and their thresholds are themselves
recorded and verified in order, so that the validity of an authorization is
judged against the authorizers in force when it was made. A stolen key of a
lower role cannot change who the authorizers are.

Req-5, stale authorizations do not land late:
: An authorization binds the state it was made against, so that an
authorization withheld by the log or the coordinator and released after later
changes is refused instead of applied. Without this, a withheld key rotation
can restore a stale key, a withheld addition can reinstate a removed
authorizer, and a withheld revocation can revoke a device that has since been
re-enrolled. Key Transparency's label versions have this property for
updates.

Req-6, non-equivocation:
: Two nodes that each accept a state can detect when those states are not
from one history, and the evidence of a fork is a self-contained object that
any party holding the trust anchor can verify without trusting whoever
produced it.

Req-7, freshness without trusting the local clock:
: A node can bound how stale its view is, and the bound does not rest on the
node's own clock being correct: an attacker who sets a node's clock back
must not make a stale view look current.

Req-8, freeze resistance:
: Withholding updates is detected. A node can obtain the current state from
more than one path, including from other nodes, so that a single party
cannot hold it on an old state silently.

Req-9, no trust on first use:
: A node accepts only the log, witnesses and initial state it was
provisioned with.

Req-10, no change to WireGuard:
: The mechanism operates on the peer table through existing interfaces and
leaves the WireGuard protocol untouched.

Req-11, interoperability:
: The record's format, the verification procedure and the refusal outcomes
are specified precisely enough that independent implementations reach
byte-identical states from the same input, demonstrated by shared test
vectors.

Req-12, coexistence:
: The mechanism works beside existing coordinators rather than replacing
them: the coordinator may keep distributing endpoints and keys, and nodes
check what it delivers.

# Relationship to Key Transparency {#rel-kt}

Key Transparency's goals overlap this problem: a key a party did not
authorize should not be accepted silently, and forks should be detectable.
Its fork-detection channels (a third party's signature on tree heads, an
anonymous check, and peer gossip) apply here directly, and its versioned
updates already bind each change to its predecessor (Req-5).

Its data model fits less well. Key Transparency is a directory: each label
maps to a sequence of values, and a client verifies one label's value. The
authority to change a label is kept outside the log, with the application,
and revocation is not defined as a distinct event. For peer authorization, the
question a node must answer is global: whether the authorizers who admitted
a key were themselves in force at that point, after every earlier change to
who may authorize, and whether a later revocation applies. Answering that
from per-label proofs would require a node to verify every other label that
records authority, which is the whole log.

This suggests two readings, and the authors would value the working group's
view on which is right: an integration of Key Transparency in which the log
carries authorization events and the authority itself, or a separate
mechanism, a transparent authorization log for a peer set, that reuses
transparency-log formats and witnesses but replays the whole record.

# Implementation Status

This section records the status of known implementations at the time of
writing, following {{RFC7942}}. It is not normative, and its inclusion does
not imply endorsement of any implementation.

Norn (Apache-2.0) implements one design meeting the requirements above: an
append-only log of signed enrollment, rotation, revocation and governance
entries, replayed by every node under a closed state machine; checkpoints and
witness cosignatures in the C2SP formats {{TLOG-CHECKPOINT}} {{TLOG-WITNESS}},
cosigned by an unmodified witness implementation; checkpoint gossip between
nodes over the tunnel; and reconciliation of a WireGuard peer table against
the replayed state. Its specification is accompanied by byte-exact test
vectors, and two implementations of the state machine produce identical
states from them. At the time of writing it has not been deployed on a real
network or reviewed outside its author's project.

# Security Considerations

This document is a statement of a security problem and of the properties a
solution needs; the threat model above is its security analysis. Two
limitations apply to any solution. First, a mechanism that refuses peers it
cannot verify converts some attacks into outages: availability is out of
scope, and a deployment must decide what a node does when it cannot reach a
current state. Second, the mechanism can prove that a key was authorized; it
cannot prove that the authorizer meant to authorize it. Compromise of
authorizer keys beyond the configured thresholds is outside what any log can
prevent, although a transparent record makes the damage enumerable afterward.

# Privacy Considerations

A record that every node can verify reveals, to anyone who can read it, the
identities of enrolled devices, when they were enrolled and revoked, and
their key fingerprints. Key Transparency hides labels behind a verifiable
random function and serves proofs per label; a mechanism that requires every
node to replay the whole record cannot do the same without changing what
nodes verify. Deployments need to treat the record's readership as part of
their threat model.

# IANA Considerations

This document has no IANA actions.

--- back

# Acknowledgments
{:numbered="false"}

This problem statement grew out of building one implementation and checking
it against independent readings of its own specification.
