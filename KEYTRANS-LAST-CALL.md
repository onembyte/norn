# `draft-ietf-keytrans-architecture-10` in IETF Last Call — the review

Written 2026-10-11 at the owner's request, after a research alert reported the
Last Call. Every claim below was checked against the source, not the alert.

## What was checked

| Fact | Source | Value |
|---|---|---|
| Revision and date | datatracker, document page | `-10`, 7 October 2026 |
| IESG state | datatracker, document page | "In Last Call (ends 2026-10-23)"; WG state "Submitted to IESG for Publication" |
| Intended status | datatracker | Informational |
| Responsible AD | datatracker | Deb Cooley |
| Last Call issued | datatracker, history | 2026-10-09 |
| Where comments go | the Last Call announcement | `last-call@ietf.org`, with `keytrans@ietf.org` copied |
| Text reviewed | `ietf.org/archive/id/draft-ietf-keytrans-architecture-10.txt` | 1456 lines, SHA-256 `e4b59711b021fdd2…` |
| Mechanism behind it | `draft-ietf-keytrans-protocol-05` (6 July 2026, still the current revision) | SHA-256 `b47356a9a56fff1d…` |

`KEYTRANS-MAPPING.md` already maps every Norn concept onto these two
documents; this file does not repeat it. It asks a narrower question: does
`-10` have a defect, seen from Norn's security model, that is worth a Last Call
comment before 2026-10-23?

## The verdict

**No architectural defect.** Where `-10` and Norn part — authority kept
outside the log, no revocation as a fact, enforcement out of scope — they part
by design, for a different problem (a directory of user keys, not an
authorization log for a mesh), and `KEYTRANS-MAPPING.md` already says so. A
scope argument is not Last Call material for an Informational architecture;
it belongs to row U8's email and H21's problem statement, after the lab soak.

**Two small, substantive Security Considerations gaps, and one editorial
one.** Each is a property the protocol draft creates and the architecture,
which is where an application designer reads the security model, does not
state. None blocks publication. Each is one or two sentences to fix.

## Against Norn's four questions

**Authorization roles.** `-10` §3 leaves authorization to the application:
"Most applications will likely want to, at minimum, prevent users from
modifying labels they do not own. The exact mechanism … is left to the
application." In Contact Monitoring and Third-Party Auditing the log operator
can publish any value and KT guarantees only that it is *detected* within a
bounded time (§7); in Third-Party Management the operator authenticates each
new version and the manager cannot add one (§4.3). That is coherent for its
scope. Norn's answer differs — the authority is in the log and the log cannot
grant access (G3) — and that is a different design, not a gap in `-10`.

One convergence is worth recording. §4.3 requires the operator to "prevent
the same version of a label from being submitted to the third-party manager
multiple times with different associated values": a KEYTRANS update is bound
to a version, which is a compare-and-swap on the label. D-077 (3), taken the
same week, makes every Norn entry that changes state a compare-and-swap on
the object it changes (`prev`, `stale-state`), for the same reason — an
authorization that names only its target can be replayed against a later
state. The two designs now agree on that point, and `KEYTRANS-MAPPING.md`'s
rotation and enrollment rows should say so when row 6.13 next touches it.

**Consistency.** §3.3's three channels (a third party's signature, an
anonymous check, peer gossip) are the three Norn builds, and §4's rule that a
threshold of third parties "MUST be at least a majority … to prevent
different subsets from authenticating forked views" is the bound
`THREAT-MODEL.md` derives for k-of-N witness quorums (two quorums share at
least 2k−N witnesses). Nothing to comment.

**Freshness.** The gap. §7.1 item 3: "applications configure an upper bound
on how stale a query response can be without being rejected", and §7 lists
that bound among the parameters that make detection time bounded. Neither
says what the bound is measured against. The protocol says it: `max_ahead` and
`max_behind` are "the maximum amount of time … that a tree head may be ahead
of or behind the user's local clock" (protocol -05, the `Configuration`
fields). The word "clock" does not occur in `-10`. So the architecture's
bounded-detection claim rests on the client's clock being right, and an
adversary who can set a client's clock back — unauthenticated time sync, a
coerced device — makes a stale response fresh again, which is exactly the
attack §7.1 item 3 exists to stop. Norn met the same problem and answered it
in `SPEC.md` §5.3 and §8.1 (A11, D-071): the local clock never supplies an
instant, only a duration since a time witnesses vouched for, and that witness
clock survives a restart.

**Credentials, and what "revocation" means for them.** The second gap.
§3.2 presents credentials as bindings that "can be verified with minimal
network access", verified "without contacting the transparency log", in the
role a certificate plays. The protocol says when one stops being acceptable:
when the distinguished log entry it rests on is no longer "recent", and
"Applications define their own policy for what constitutes a 'recently
issued' distinguished log entry" (protocol -05 §14). So after a label owner
replaces a value — a compromised key, say — anyone who still holds a
credential over the old value can present it until that window closes, and
the window is judged on the recipient's clock. That interval is the
revocation latency of a key change for every application that uses
credentials, and `-10` never says so: the word "revocation" does not occur in
it either. Norn's equivalent is `SPEC.md` §8.1: a proof bundle proves history,
not currency, and condition 3 plus the freshness ladder decide currency.

**Fork recovery.** Editorial. §3.3 and §7.1 item 2 say a user shown a fork
"hold[s] on to this forked view forever and reject[s] the output of any
subsequent queries that are inconsistent with it", and that the user can
publish a proof. Nothing says what happens to that user next: it can no
longer use the log. §5 lists "to recover from log failure, such as the
compromise of the log's private keys or the loss of its data" as the reason
for immediate migration, and §5.2 describes it: that is the recovery path,
but nothing connects it to §3.3. Norn's answer is a defined freeze and a new trust file (§11).

## The draft comment

**A draft. Nothing has been sent.** If the owner chooses to send it, it goes
to `last-call@ietf.org` with `keytrans@ietf.org` copied, before 2026-10-23,
from the owner's own address. It does not mention Norn on purpose: row U8
introduces Norn to the working group after the lab soak, and a Last Call
comment should stand on its technical content alone.

> Subject: Last Call: draft-ietf-keytrans-architecture-10 — two Security
> Considerations clarifications
>
> I have read draft-ietf-keytrans-architecture-10 and support its
> publication. Two clarifications to Section 7 would, I think, help
> application designers, who will read the security model here rather than
> in the protocol document. A third is editorial.
>
> 1. Freshness depends on the client's clock. Section 7.1, item 3, says
> applications bound how stale a query response may be, and Section 7 lists
> that bound among the parameters that make detection time bounded. The
> protocol measures it against the user's local clock (max_ahead and
> max_behind in the configuration). The architecture does not say so. A
> client whose clock can be set back accepts responses older than the bound,
> which reopens the attack item 3 exists to prevent. Suggested text for 7.1:
> "This bound is measured against the user's clock, and protects only as far
> as that clock is correct. Applications whose clients cannot rely on their
> clock should consider deriving the current time from a source the
> transparency log does not control, for example a third party's signed
> timestamp, and measuring only elapsed time locally."
>
> 2. Credentials and key changes. Section 3.2 presents credentials as
> bindings verified without contacting the log. The protocol expires a
> credential when the distinguished log entry it rests on is no longer
> "recent", by application policy. So after a label owner replaces a value,
> for example after a key compromise, credentials over the old value remain
> acceptable until that window closes, judged on the recipient's clock. That
> interval is the revocation latency of a key change for applications that
> use credentials. Suggested text, in 3.2 or 7: "A credential remains
> verifiable after the label's value changes, until the distinguished log
> entry it relies on is no longer recent. Applications should choose the
> window with key compromise in mind, since it bounds how long a replaced
> key can still be presented in a credential."
>
> 3. Editorial: Sections 3.3 and 7.1 say a user who detects a fork keeps it
> and rejects inconsistent responses from then on, but not how such a user
> recovers. Section 5 names recovery from log failure as a reason for
> immediate migration, described in Section 5.2; a sentence pointing there
> would close the loop.

## What this changes for Norn

Nothing in `SPEC.md`. The freshness and credential points are ones Norn
already answers, which is why they were visible from here. The convergence on
version-bound updates goes into `KEYTRANS-MAPPING.md` at row 6.13. Whether to
send the comment is the owner's decision, like every message to the IETF.
