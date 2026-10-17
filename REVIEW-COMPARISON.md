# Norn — Comparison review packet

For someone who has run at least two of Tailnet Lock, Nebula and NetBird in
anger. The ask in `PUBLICATION.md` §4 is: **"which row is unfair?"**
`PLAN.md` Phase 6 keeps that review gate open. This packet prepares the review;
it does not complete it.

The questions and cells below are copied verbatim from README's "How Norn
compares" table, in its order. Sources for the other systems are only those
`PRIOR-ART.md` cites. They have not been checked over the network for this
packet. Where it cites nothing for a cell, that gap is stated here. A nearby
claim is not a source for a stronger one. Norn's sources are in this tree.

## Can the control plane add a device you never approved?

- Tailnet Lock: no, while it is on

  Source: `PRIOR-ART.md` §1, new node keys must be signed by a TLK, and §5, admission while lock is on; [Tailnet Lock whitepaper](https://tailscale.com/docs/concepts/tailnet-lock-whitepaper).

- Nebula: no — only the offline CA can

  Source: `PRIOR-ART.md` §5 says the offline CA signs certificates and the lighthouse cannot add peers. It cites no document or link for that admission claim.

- NetBird: yes

  Source: `PRIOR-ART.md` §5 says the management server decides the peer set and can silently add a peer. It cites no document or link for NetBird.

  NetBird 0.81 (2026-10-15) added a certificate posture check ([release](https://github.com/netbirdio/netbird/releases/tag/v0.81.0), [documentation](https://docs.netbird.io/manage/access-control/posture-checks/device-certificates)). The management server issues and judges that challenge, so it does not constrain a compromised management server; the documentation says the check does not tie the certificate to a user or a hostname.

- Norn: no

  Source: `SPEC.md` §§5.1 and 13–13.1: replay authorises enrollments; providers cannot authorise keys. `internal/agent/gate_test.go`, `TestAnIntruderIsGoneAfterExactlyOneCycle`, checks eviction. `THREAT-MODEL.md` A1 and §5 distinguish observe, owner and watchdog; watchdog has a polling window.

Questions for the operator:

- In your deployment, could the coordination server add a node while lock was enabled, without a trusted key signing it?
- Could a Nebula lighthouse or NetBird management server admit a peer without the approval described here? What did "approved" mean in your setup?
- If you used NetBird's certificate posture check (0.81 and later), did anything other than the management server enforce it?
- Does Norn's "no" fairly describe observe and watchdog deployments, including packets inside the reconciliation window?

## Can the control plane widen a legitimate peer's routes?

- Tailnet Lock: yes — signatures cover node keys; the control plane keeps addresses, routes and packet filters

  Source: `PRIOR-ART.md` §1 describes node-key signatures, but does not make or cite the claim about addresses, routes and packet filters. No source for that full cell is supplied there.

- Nebula: no — the CA signs each host's IPs and subnets into its certificate

  Source: `PRIOR-ART.md` §5 describes CA-signed certificates, but says nothing about signed IPs or subnets. No source for this cell is supplied there.

- NetBird: yes

  Source: `PRIOR-ART.md` §5 addresses peer admission, not route widening. No source for this cell is supplied there.

- Norn: no — under `routes = granted`, the enrollment's grant bounds them

  Source: `SPEC.md` §4.0 defines the enrollment grant; §§4.5 and 13.1 define `routes = granted` and withholding prefixes outside it. `internal/agent/routes_test.go`, `TestAProviderCannotWidenAPeersRoutes`, checks that bound.

Questions for the operator:

- With Tailnet Lock enabled, could the control plane change a signed node's addresses, advertised routes or packet filters without another signature?
- Could your Nebula lighthouse change a host's IPs or subnets beyond its certificate? Could NetBird widen them without your approval?
- Under `routes = granted`, could a Norn provider install a prefix outside the enrollment grant, and does the row state the relevant mode clearly enough?

## Is there a record of **every key ever authorised**?

- Tailnet Lock: no — the chain records who may *sign*, not what was signed

  Source: `PRIOR-ART.md` §1, "Node-key signatures are not in the chain"; [Tailnet Lock whitepaper](https://tailscale.com/docs/concepts/tailnet-lock-whitepaper).

- Nebula: no

  Source: `PRIOR-ART.md` §5 lists transparency as none. It cites no document or link establishing the absence of a record of every authorised key.

- NetBird: no

  Source: `PRIOR-ART.md` §5 lists transparency as none. It cites no document or link for NetBird or this absence claim.

- Norn: yes, append-only

  Source: `SPEC.md` §§4.3, 5 and 6: enrollment, rotation and revocation entries, replay and the append-only Merkle log. `THREAT-MODEL.md` A3 and A8 explain published, attributable actions.

Questions for the operator:

- Could you recover every node key ever signed by a Tailnet Lock key, including nodes no longer present, from the authority chain?
- Did your Nebula or NetBird deployment retain a complete, checkable history of authorised keys that this row overlooks?
- Would you count Norn's logged enrollment and rotation history as "every key ever authorised", or is the scope of that phrase unfair?

## Can a third party check that record without being trusted?

- Tailnet Lock: —

  Source: `PRIOR-ART.md` §1 says the chain lacks node-key signatures and mentions no witnesses or gossip; [Tailnet Lock whitepaper](https://tailscale.com/docs/concepts/tailnet-lock-whitepaper). The dash supplies no positive claim about third-party checking.

- Nebula: —

  Source: `PRIOR-ART.md` §5 lists transparency as none, with no document or link for this cell. The dash supplies no positive claim about third-party checking.

- NetBird: —

  Source: `PRIOR-ART.md` §5 lists transparency as none, with no document or link for NetBird. The dash supplies no positive claim about third-party checking.

- Norn: yes — witnessed checkpoints, replayable by anyone

  Source: `SPEC.md` §§6, 9 and 10 define published log files, witness policy and verification with replay. `norn verify -trust <trust-file> -log <log-directory>` checks the record offline; README's "Try it" runs that command against the shipped log. The verifier needs the trust anchor, not authority to add entries.

Questions for the operator:

- Could an independent operator verify your system's historical authorisations without becoming an authority or trusting the coordinator's account of them?
- Do the dashes conceal a third-party verification path you actually used?
- Are Norn's trust-anchor and witness-policy requirements comparable to the trust requirements of that path?

## A signing key is stolen. Afterwards, can you enumerate what it signed?

- Tailnet Lock: no

  Source: `PRIOR-ART.md` §1 explicitly says a stolen TLK leaves no append-only record of which node keys were signed; [Tailnet Lock whitepaper](https://tailscale.com/docs/concepts/tailnet-lock-whitepaper).

- Nebula: no

  Source: `PRIOR-ART.md` §5 says transparency is none but does not discuss enumerating signatures after CA-key theft. No source for this cell is supplied there.

- NetBird: no

  Source: `PRIOR-ART.md` §5 says transparency is none but does not discuss enumerating signatures after key theft. No source for this cell is supplied there.

- Norn: yes — `norn audit --by`

  Source: `norn audit -trust <trust-file> -log <log-directory> -by <16-hex-kid>`; `cmd/norn/audit_test.go`, `TestAuditListsWhatOneKeySigned` and `TestAuditShowsRejectedEntriesToo`. `THREAT-MODEL.md` A3 and A8 explain attribution to a signer key.

Questions for the operator:

- After a TLK or CA key was stolen, could you enumerate the node keys it signed, including keys no longer deployed? How?
- What retained NetBird records let you enumerate actions attributable to the stolen key, rather than just the current peer set?
- Does `norn audit --by` answer the incident question you would ask, including rejected entries and the limits of what reached the log?

## Control plane goes silent or withholds updates

- Tailnet Lock: acknowledged freeze attack

  Source: `PRIOR-ART.md` §1, control-plane-only AUM distribution and the acknowledged freeze attack; [Tailnet Lock whitepaper](https://tailscale.com/docs/concepts/tailnet-lock-whitepaper).

- Nebula: certs keep working until they expire

  Source: `PRIOR-ART.md` §5 describes certificates and blocklist revocation but does not state that certificates keep working until expiry when updates stop. No source for this cell is supplied there.

- NetBird: undetected

  Source: `PRIOR-ART.md` §5 does not discuss detection of withheld updates in NetBird. No source for this cell is supplied there.

- Norn: nodes gossip checkpoints over the tunnel; staleness alarms

  Source: `SPEC.md` §§8.1, 13.2 and 15 define freshness alarms and checkpoint gossip over the WireGuard interface. `internal/agent/gossip_test.go`, `TestHealthyLogChecksPeerCheckpointAtGossipInterval`, checks gossip even with a healthy direct log. `THREAT-MODEL.md` A1 and A2 describe withholding; §8 notes the risk when peers cannot reach each other.

Questions for the operator:

- When your coordination server withheld updates, what alarm or independent update path told you about it?
- For Nebula, did certificates alone determine continued access, or did your deployment detect withholding or stop access sooner?
- With all Norn gossip paths unavailable, do its staleness alarms justify the distinction this row draws?

## Revocation

- Tailnet Lock: via the control plane

  Source: `PRIOR-ART.md` §1 says AUMs are distributed only via the control plane and can remove trusted TLKs; [Tailnet Lock whitepaper](https://tailscale.com/docs/concepts/tailnet-lock-whitepaper). It does not separately cite a node-revocation procedure for this cell.

- Nebula: `pki.blocklist`, shipped in config

  Source: `PRIOR-ART.md` §5 states `pki.blocklist` in config and describes lost blocklist delivery; [Nebula blocklist / CVE-2026-61699](https://advisories.gitlab.com/golang/github.com/forgekeep/nebula-mesh/CVE-2026-61699/). This is an advisory about nebula-mesh, not a separately cited Nebula revocation manual.

- NetBird: via the control plane

  Source: `PRIOR-ART.md` §5 names the management server as peer-set authority but gives no revocation procedure. No source for this cell is supplied there.

- Norn: a logged entry, with a bounded window and an alarm if it is missed

  Source: `SPEC.md` §§4.3 and 5.1 define logged revocation; §§8.1, 13.2 and 15 define freshness, alarms and reconciliation. `THREAT-MODEL.md` A6 gives `T_c + T_g + T_poll`; §6 gives the parameters. `internal/agent/gate_test.go`, `TestARevokeEntryEvictsTheDevice`, checks eviction. §13.2 retains the last verified set in degraded mode and makes hard-stale disconnection opt-in; the window needs those operating conditions reviewed.

Questions for the operator:

- How did you revoke a node with Tailnet Lock or NetBird, and could that revocation reach peers while the control plane withheld it?
- How did you distribute Nebula's blocklist and confirm that every host applied it? Does the nebula-mesh advisory fairly represent your system?
- Does Norn's claimed bounded window match a partitioned deployment that keeps the last verified set and has no hard-stale cutoff?

## Runs beside your existing stack

- Tailnet Lock: Tailscale only

  Source: `PRIOR-ART.md` §1 says TKA is tied to Tailscale's control plane; [Tailnet Lock whitepaper](https://tailscale.com/docs/concepts/tailnet-lock-whitepaper), and [Headscale #1307](https://github.com/juanfont/headscale/issues/1307), the unimplemented integration request cited there.

- Nebula: Nebula only

  Source: `PRIOR-ART.md` §5 describes Nebula's CA and lighthouse, but does not state or cite the "Nebula only" integration limit. No source for this cell is supplied there.

- NetBird: NetBird only

  Source: `PRIOR-ART.md` §5 describes NetBird's management server, but does not state or cite the "NetBird only" integration limit. No source for this cell is supplied there.

- Norn: NetBird with a kernel WireGuard interface, innernet or `wg-quick`; Tailscale/Headscale observe only, not yet run against a real tailscaled

  Source: `ENFORCEMENT.md` §§2, 3 and 6: kernel WireGuard access, reconciliation beside another writer, the integration matrix and LocalAPI observe limitations. §6 says NetBird and innernet watchdog operation flaps and needs a hook. `SPEC.md` §13.1 defines the modes. README's opening paragraph and status line retain the real-deployment qualification; these are implementation paths, not lab results.

Questions for the operator:

- Have you run Tailnet Lock, Nebula or NetBird beside a different existing stack in a way the "only" cells exclude?
- On a real NetBird or innernet interface, does Norn's reconciliation coexist usefully with the other writer, or do the flapping and hook requirements make this wording unfair?
- Have you exercised Norn's Tailscale/Headscale observe path against tailscaled, and does the cell's unvalidated qualification describe that limitation accurately?

## Would I run it on something that matters today?

- Tailnet Lock: yes, it is GA

  Source: `PRIOR-ART.md` §Sources cites [Tailnet Lock GA](https://tailscale.com/blog/tailnet-lock-ga). That sources GA, not the personal operational judgement in "yes".

- Nebula: yes

  Source: `PRIOR-ART.md` §5 names Nebula but gives no source for this operational-readiness judgement. No source for this cell is supplied there.

- NetBird: yes

  Source: `PRIOR-ART.md` §5 names NetBird but gives no source for this operational-readiness judgement. No source for this cell is supplied there.

- Norn: **no** — see the status line above

  Source: README's status line: no Norn has guarded a network anyone depends on, and gates needing a lab, measurement or second pair of eyes remain open. `PLAN.md` Phase 6 includes the still-open comparison review gate. This is the owner's deployment judgement, not a protocol guarantee.

Questions for the operator:

- Which of these systems have you trusted with a network that matters, and what operating evidence would make its "yes" unfair?
- Does GA tell you enough about Tailnet Lock's readiness in your deployment, compared with the unqualified Nebula and NetBird answers?
- Does Norn's status line give you enough evidence for its "no", without implying the other three have equivalent deployment requirements?

Send findings back by opening an issue or replying to the owner. Name the row
and cell, the version and configuration you operated, what happened, and the
document or reproducible observation that contradicts the wording. A missing
source is a useful finding too.
