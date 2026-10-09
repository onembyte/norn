# Norn against IETF Key Transparency — the mapping

Written 2026-10-08 from the datatracker's current text, not from memory:
`draft-ietf-keytrans-protocol-05` (6 July 2026, Standards Track, an active
working-group document) and `draft-ietf-keytrans-architecture-10` (7 October
2026, submitted to the IESG as Informational). The KEYTRANS charter says the
working group "may standardize integrations of this verifiability mechanism
with other protocols"; no integration document exists yet, not even the MLS
one on its own milestone list. This file is the evidence row H21's problem
statement rests on, and the answer to the question the IETF brief asked: is an
*integration* document honest, or is the artifact a *problem statement*?

## The two data models, in one paragraph each

**KEYTRANS** is an authenticated dictionary. A *label* (a user identifier)
maps to a sequence of *versions*, each a *value* (unstructured bytes, such as
a public key). A prefix tree keyed by a VRF of the label commits to the
current label→version→value mappings; a log tree records, in order, a
timestamp and the prefix tree's root at each change. A client asks the log a
question — *search* a label's greatest version, *update* a label it owns,
*monitor* a label — and receives proofs against a signed `TreeHead`; it keeps
the last tree head and some subtrees and requires each answer to be consistent
with what it held. Equivocation is detected by a third-party auditor's
signature on tree heads, by an anonymous check, or by peer gossip (architecture
§3.3), not automatically. Values are whatever the service operator chooses;
the log does not interpret them, and the prefix tree keeps labels private from
anyone who cannot guess them.

**Norn** is a replicated replay log. Every entry is a signed, typed event —
`enroll`, `rotate`, `revoke`, `signer_add`, `policy`, … (§4.3) — and the
network's *current state* is not served by anyone: every node derives it by
replaying every entry from the genesis under a closed state machine (§5) that
checks each entry's signatures against the signer and root sets *as they were
at that point* (§5.1). The log is a C2SP tiled log with signed checkpoints,
cosigned by witnesses under a `tlog-policy` quorum (§6, §7, §9.1, §10); nodes
gossip checkpoints over the tunnel (§15); a fork is proven by a self-contained
evidence file (§11). The log is public to anyone who can read it, and small —
a mesh of tens to tens of thousands of devices. The two choices are opposite
on purpose: KEYTRANS scales to billions of labels by giving each client proofs
about the few labels it cares about; Norn gives each node the whole history
because the authorization it enforces is *global* — who may sign depends on
every earlier governance entry, and a device's admission is a function of the
entire state, not of its own label.

## The mapping

Verdicts: **equivalent** (the same object with the same role), **partial**
(a related object that covers some of the role), **none** (nothing in
KEYTRANS plays the role).

| Norn concept | SPEC | KEYTRANS (protocol -05 / architecture -10) | Verdict | Notes |
|---|---|---|---|---|
| Network (`net`, origin, genesis hash) | §2, §9 | a Transparency Log instance with its configuration (ciphersuite, RMW, `max_ahead`/`max_behind`) | **partial** | KEYTRANS has no pinned genesis: a client's first `TreeHead` is trusted on first use unless an out-of-band check is made. Norn pins the genesis hash in the trust file (G6, no TOFU). |
| Device identity (`device_id`, `device_pk`) | §2, §4.3, §16 | a *label* (identifier) and its *owner*; the owner authorizes updates | **partial** | A label's owner is whoever the service operator lets update it; Norn's device signs its own enrollment request (§16) and its own rotation (§4.3), and *signers* — a separate, thresholded role — admit it. KEYTRANS has one authority per label, not a quorum. |
| WireGuard key binding (`wg_pk` in an `enroll`) | §4.3, §16.1 | a *value* under a label | **partial** | The value is opaque bytes; a WireGuard key fits. What KEYTRANS cannot express is the *binding* — that this value is a Curve25519 key authorized for a WireGuard interface by named signers — which is Norn's entry type and signature rule. |
| Grant (the `ip` label: the bound on allowed-ips) | §4.0, §13.1, D-073 | — | **none** | Routes are WireGuard's cryptokey routing; no dictionary of keys knows what a value is allowed to source. |
| Enrollment (`enroll`: a device's request plus a signer quorum) | §4.3, §5.1, §16 | *update* of a label by its owner; in Third-Party Management mode the Service Operator signs each new value | **partial** | KEYTRANS authorizes an update by the label's owner alone (or the operator); Norn requires `signer_thr` of the current signers *and* the device's own signature over its request. The quorum, and the fact that the signer set is itself in the log, have no equivalent. |
| Rotation (`rotate`) | §4.3, D-032 | a new *version* of the label's value | **partial** | A version is a value change; Norn's rotation keeps the device identity, proves possession of the incoming key, and may require a signer. |
| Revocation (`revoke`) | §4.3, §5.1, §5.3 | — | **none** | The protocol defines no revocation and no tombstone; a prefix leaf may be *removed* after it has appeared in a distinguished entry, and entries past the log's maximum lifetime are pruned (Appendix D). Removal is the operator's act and leaves no statement of *why*; Norn's `revoke` is a signed, replayed fact with three independent authorizations, and the device stays in the state as `revoked`. |
| Governance: roots, signers, thresholds, `log_key`, `policy`, `params` | §4.3, §5.1, §9.4 | — | **none** | KEYTRANS keeps the authority to update outside the log (the service operator, the label owner). Norn puts the authority *in* the log so that it is transparent too: `signer_add`, `root_thr`, a log-key rotation (§9.4) and a witness-policy change are entries every node replays. This is G3 — the log cannot grant access — and it is the reason the state is global. |
| Current state (the replayed state, canonical JSON) | §5, §5.3 | the prefix tree at the latest log entry (the current label→value map) | **partial** | Both answer "what is current now". KEYTRANS serves it with a proof per label; Norn derives it locally, byte-identically across implementations (§5.3, §14). KEYTRANS's answer is per label; Norn's includes who may sign, which is not a label. |
| Proof bundle (one per peer: entry, inclusion proof, checkpoint) | §8, §8.1 | a *search* response: inclusion of the label's version in the prefix tree and of that tree in the log tree, under the tree head | **partial** | The same shape — a proof that a value is in the log under a signed head — and the same limit §8.1 states: inclusion proves history, not currency; Norn's condition 3 adds "and replay says `active`". |
| Checkpoint (signed note, C2SP `tlog-checkpoint`) | §6, §10 | `TreeHead` (and `AuditorTreeHead`) | **equivalent** | A signed tree size and root. KEYTRANS's is in TLS presentation language; Norn's is the C2SP signed note so that unmodified witnesses and monitors work. |
| Witness (C2SP `tlog-witness` cosignature; quorum by `tlog-policy`) | §7, §9.1, §10 | *Third-Party Auditor*: verifies the log is built correctly and signs an `AuditorTreeHead` | **partial** | Both are a second signature from a party assumed not to collude with the log. A KEYTRANS auditor re-verifies construction (it needs the data); a C2SP witness checks only append-only consistency (it needs a proof) and cosigns, which is why anyone can run one and why a quorum of several is cheap. KEYTRANS has one auditor, not a policy over many. |
| Peer gossip of checkpoints | §15 | architecture §3.3: peer-to-peer gossip as one of three fork-detection channels; "gossip must form a connected graph" | **equivalent** in role | KEYTRANS names it and leaves it to the application; Norn specifies it (over the tunnel, `T_g`, `r = 3` peers) because the tunnel *is* the application. |
| Monitor | §13.3, `LAB.md` §3 | *monitoring* is a user operation (owner monitoring, contact monitoring) within the Reasonable Monitoring Window; no monitor actor | **partial** | KEYTRANS monitoring is per label and per client, bounded by the RMW and the log entry maximum lifetime. Norn's monitor reads the whole log and describes every entry; nothing is pruned, so there is no window to miss. |
| Freshness (`fresh`/`degraded`/`hard_stale`/`unknown`, the witness clock) | §8.1, §15 | `max_behind` (a response may be that stale), `max_ahead`/`max_behind` clock-skew bounds, "recently issued" distinguished entries left to application policy | **partial** | KEYTRANS bounds how stale an answer may be; Norn ties the age of the held head, measured in *witness* time, to what the enforcer does (hold, alarm, empty the table). The enforcement half is the part that is Norn's. |
| Fork evidence (a self-contained file; closed refusal codes) | §11, §11.1 | "non-repudiable proof that can be published" (architecture §3.3); forks are detected, not automatically | **partial** | KEYTRANS says such proof exists; Norn defines its bytes, its verification order and what a node does on holding one (freeze). |
| Trust file (`norn.trust`: log key, witnesses, policy, genesis) | §9 | the log's public key and configuration, obtained however the application obtains them | **partial** | KEYTRANS does not say how a client learns the log's key; Norn makes it a provisioned, fingerprinted document (§9.3) and refuses anything it was not provisioned with. |
| Enforcement (owner, watchdog, observe; the peer table) | §13 | — | **none** | KEYTRANS ends at "the client has a verified value"; what a WireGuard node *does* with it is the whole of §13. |
| Label privacy (VRF-keyed prefix tree) | — | the prefix tree, `VRF(label)` | **none, the other way** | Norn has nothing like it and states the cost: device names, enrollment times and key fingerprints are visible to anyone who can read the log (`THREAT-MODEL.md` §7). |
| Scale: efficient per-label lookup, partitioning across logs | — | implicit binary search over log entries, binary ladders (Appendices A, B), partitioning (architecture) | **none, the other way** | Norn replicates everything; it is a design for a mesh, not a directory. |

## What the mapping says

**Where the two agree** is the goal and the *fork-detection taxonomy*. The
architecture's three channels — a third-party signature on tree heads, an
anonymous check, peer gossip — are exactly the three Norn builds: witness
cosignatures under a quorum, the monitor and `norn verify` reading the log
from elsewhere, and gossip over the tunnel. Its §7.2 on state loss is what
`THREAT-MODEL.md` A13 and D-071 answer. A checkpoint is a tree head, a proof
bundle is a search response, a witness is an auditor with a weaker job and a
quorum. Norn should cite all of this and claim none of it as its own.

**Where they part** is not incidental. KEYTRANS keeps the authority to change
a label *outside* the log and makes the log a transparent record of what that
authority did; Norn puts the authority *inside* the log so that the authority
itself is transparent — who may sign, how many, under which witness policy —
and that is why the state is global and every node replays everything. The
rows marked **none** on Norn's side are all consequences of that one choice
plus the fact that the value is a WireGuard key: revocation as a signed fact,
thresholded governance, the grant on routes, and enforcement. No value format
layered on KEYTRANS carries them: a Norn entry stored as a KEYTRANS value
would need its client to replay every *other* label's governance entries to
know whether the signatures on this one counted, which is full replication
again, through a dictionary built to avoid it.

**Where each *none* belongs**, as the plan asks:

| Norn concept with no KEYTRANS equivalent | Belongs in |
|---|---|
| The grant (allowed-ips bounded by the enrollment) | an **integration layer** for WireGuard — the one rule that only makes sense for cryptokey routing |
| Revocation as a signed, replayed fact | a **separate document**: the authorization model, which KEYTRANS deliberately leaves to the application |
| Governance in the log (roots, signers, thresholds, policy, log-key rotation) | the same **separate document** |
| Enforcement modes and the peer-table contract | **implementation policy**, stated as requirements on a node (what §13 does) |
| Freshness tied to enforcement (`S`, `S_hard`, the witness clock) | the **separate document**, as requirements, with the thresholds as implementation policy |
| Fork evidence as a defined file with a verification order | **Norn extension** of what the architecture calls "non-repudiable proof": a format, where KEYTRANS has a sentence |

## The verdict the brief asked for

An **integration document** — "Key Transparency for WireGuard Peer
Authorization", using `draft-ietf-keytrans-protocol` as the mechanism — would
not be honest. It would have to say that the mechanism carries the key but not
the authorization, the revocation, the governance or the routes, and that a
conforming implementation must replicate the whole log anyway; what remained
of KEYTRANS would be a tree head and an inclusion proof, which C2SP's formats
already give Norn with working witnesses.

The honest artifact is a **problem statement**: that an interoperable
mechanism by which a WireGuard endpoint verifies a peer key's *current*
authorization — and its route grant — independently of the coordinator that
distributes it, has no standard; that KEYTRANS's goals and its fork-detection
taxonomy apply and its data model does not, for the reason above; and that
the open question for the working group is whether a transparent
*authorization* log, as distinct from a transparent *directory*, is in scope
for an integration, or is a different document. That question is row U8's
email to `keytrans@ietf.org`, with this file as the evidence; H21 writes the
draft and nobody sends it until U8 is answered.

Rechecked claims, so they can be rechecked again: KEYTRANS defines no
revocation (protocol -05, §15.2 leaf removal and Appendix D pruning are the
nearest); fork detection is "not automatic" and rests on an auditor, an
anonymous check or gossip (architecture -10 §3.3); the charter permits
integrations and lists none shipped; freshness is a bound on staleness
(`max_behind`), not an enforcement ladder.
