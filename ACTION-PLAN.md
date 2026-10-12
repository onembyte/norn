# Norn — how to test it, and how to present it

Row H17 of `HARDENING-PLAN.md`. Drafted **2026-10-12**, at the owner's request,
before every row it depends on is done; §5 lists what is still open, and the
row is not ticked until those are closed and the facts below are rechecked.
**Nothing in this file has been sent, and nothing in it is sent by anyone but
the owner.**

## 0. Where things stand

What exists and is checked by the gate: a frozen `SPEC.md`; a byte-exact vector
suite with three provenances; the Go node agent, log server, witness wrapper and
CLI; a Python reference implementation that produces the same states byte for
byte; an independent verifier built cold from the specification alone
(`contrib/verify-py/`, the third such build, which passes every check); a
simulation of the attack scenarios. The
README's status line has the current counts.

What has not happened: nothing has run on a real kernel or a real network; no
outside person has reviewed it; no number in any document comes from a real
deployment. Steps 1–4 below can run today on any machine with Go. Steps 5–7
are row U1 and need your mesh.

## 1. Your test plan

Each step says what to run, what you should see, and what to send back. Run
them in order; a step that shows anything else stops the plan there.

**Step 1 — offline verification (five minutes).** From a clean checkout:

```sh
go build -o norn ./cmd/norn && go build -o nornd ./cmd/nornd
./norn verify -trust testdata/vectors/trust.cbor -log testdata/vectors/served
```

You should see `network    norn-testnet`, `size       162 entries` and
`13 device(s), 8 active:` — a log replayed from its pinned genesis, its
checkpoint's witness quorum checked, and the only peer set a node would
install. Send back: nothing, unless the output differs.

**Step 2 — a fork, proven offline.**

```sh
./norn verify-evidence -trust testdata/vectors/trust.cbor testdata/vectors/fork/evidence.cbor
```

You should see `FORK PROVEN`, `at size     41 entries` and the three witnesses
that were meant to prevent it. This is the file a node publishes when the log
signs two histories; anyone holding the trust file can check it without
trusting the accuser. Send back: nothing, unless it differs.

**Step 3 — the simulation (about ten seconds).**

```sh
make lab-sim
```

Real agents, fake peer tables, an in-memory network, scenarios T1–T7: a rogue
key, adoption, an under-quorum head, a replayed log, clock skew, staleness,
eviction. You should see one line per scenario and the closing caveat that
simulated time proves ordering and bounds, not wall-clock behaviour. Send back:
the latency lines and `t7.json` from `${TMPDIR:-/tmp}/norn-lab-sim`.

**Step 4 — an unmodified witness cosigns a Norn checkpoint.**

```sh
make witness
NORN_REQUIRE_WITNESS=1 go test -count=1 -v -run TestAnUnmodifiedWitnessCosignsANornCheckpoint ./internal/interop
```

`make witness` builds `transparency-dev/witness` at the pinned commit (a Go
module download) into `build/`; the test starts it, has it cosign a Norn
checkpoint, and verifies the cosignature. `NORN_REQUIRE_WITNESS=1` turns the test's
skip-when-not-built into a failure, so a missing binary cannot pass silently.
You should see `--- PASS: TestAnUnmodifiedWitnessCosignsANornCheckpoint`.
Send back: nothing, unless it fails or skips.

**Step 5 — your own network (the prerequisite for U1).** The shipped trust file
describes the fixtures, not your mesh. Run the root ceremony (`ENROLLMENT.md`
§2, `norn init`): roots, a signer, the log key, the genesis, and the trust
file's fingerprint. Serve the log (`norn-log -dir … -key … -trust …`) on the
NAS, run at least one witness somewhere with a different failure mode (the Pi),
and enrol each device of the mesh (`ENROLLMENT.md` §3). Every node gets
`norn.trust` through a channel you trust and compares the fingerprint with the
one `norn init` printed. Send back: the fingerprint and `norn verify` against
your log.

**Step 6 — observe mode, one node for a day, then all nodes for seven (U1).**
Follow `OBSERVE.md`: install, `mode = "observe"`, alarms routed to your ntfy.
Observe reads the peer table and never writes it. Then, deliberately: add a
peer by hand on one node (expect `UNPROVEN_PEER` within one cycle), and stop
the log for an hour (expect `VERIFY_FAILED` while it is down, `DEGRADED` once
the network's staleness limit passes — ten minutes by default — and both
clearing after you restart it). Send back: the daily alarm list, `norn status` from each node,
and anything in `/run/norn/proven.json` you did not expect.

**Step 7 — reading the alarms.** `OBSERVE.md` §Alarms lists each one, what it
means and what to do. In a healthy week you should see only `MISSING_PEER`
(normal while a device is off) and the alarms you caused in step 6.

**What "it works" means after U1:** for seven days every peer in every table
was in the proven set, every unexpected key raised `UNPROVEN_PEER`, freshness
stayed `fresh` except when you broke it, and the deliberate faults raised the
documented alarms. **What it does not claim:** anything about owner or watchdog
enforcement on a real kernel (those are U2's lab measurements), availability,
or protection from a stolen WireGuard private key before it is revoked
(`THREAT-MODEL.md` §7).

## 2. The message to the WireGuard team

**What `wireguard.com` says, verbatim**, fetched 2026-10-12 04:52 UTC
(`/` SHA-256 `3ba735a9ab49db80…`, `/todo/` SHA-256 `5e32c5cd7d7f6b2c…`):

- `/todo/`, on its list of projects: "Mesh Networking Tools It is possible to
  build a mesh network out of WireGuard using WireGuard as the building block.
  Write a tool that builds meshes and has peers discover each other, taking
  into account important authentication and trust properties." And: "If
  you're interested in working on any of these, please write an email to the
  WireGuard development team" — linked to `team@wireguard.com`.
- `/`, Email Contact: "If you'd like to contact us privately for a particular
  reason, you may reach us at team@wireguard.com." And: "Keep in mind, though,
  that "support" requests are much better suited for our IRC channel."
- `/`, Mailing List: "Get involved in the WireGuard development discussion by
  joining the mailing list." "Submit patches using git-send-email, similar to
  the style of LKML."
- `/`, Security Contact: "Please report any security issues to, and only to,
  security@wireguard.com."

**The form that follows from it.** `team@wireguard.com`, because the `/todo/`
page asks people working on a listed item to write there, and Norn is one part
of the mesh-tools item: the trust half. Not the mailing list first: it is where
WireGuard itself is developed and patches are sent, and Norn proposes no patch;
the list is for an announcement after the repository is public and reviewed
(`PUBLICATION.md` §5, step 3). Not `security@`: this is not a WireGuard
vulnerability. The page states no format; plain text, short, no attachments,
one link, is the form a busy kernel team reads.

**The draft** (plain text; send from your own address):

```text
Subject: Peer-key authorization for WireGuard meshes (the "Mesh Networking Tools" item)

Hi,

The /todo page lists mesh networking tools that have peers discover each
other "taking into account important authentication and trust
properties", and asks anyone working on one to write here. I have been
building the trust half of that: a way for a WireGuard node to check that
a peer key it is about to install was actually authorized, independently
of the coordination server that handed it over.

Norn records every device enrollment, key rotation and revocation in an
append-only log, cosigned by independent witnesses in the C2SP tlog
formats. Each node replays that log and installs only the keys, and the
allowed IPs, that the log proves. It changes nothing in WireGuard: it
reads and writes the peer table through the normal interfaces, beside
wg-quick, innernet or NetBird.

Where it stands: the specification is frozen and has a byte-exact
test-vector suite; a Go implementation and a Python reference produce
identical results; an independent verifier was written from the
specification alone. It has not yet run on a real network, and nobody
outside has reviewed it. Measurements on a real mesh come next.

https://github.com/onembyte/norn (Apache-2.0); the threat model is in
THREAT-MODEL.md.

I am not proposing any change to WireGuard. What would help me most is
whether this is the kind of tool that item had in mind, and whether
there is a WireGuard behaviour or a threat I have not accounted for.

Thank you for WireGuard.

Franco Michetti
```

Update the "Where it stands" paragraph on the day you send it, from the
README's status line: if U1 has run, say what it showed.

## 3. The message to the KEYTRANS working group (row U8)

**What the IETF says**, checked 2026-10-12 at the datatracker: the list is
`keytrans@ietf.org`; subscribe at `https://www.ietf.org/mailman/listinfo/keytrans`
(post after subscribing, or the message waits for a moderator); archive at
`https://mailarchive.ietf.org/arch/browse/keytrans/`; chairs Prachi Jain and
Shivan Kaul Sahib; responsible AD Deb Cooley. The charter: "The WG may
standardize integrations of this verifiability mechanism with other
protocols". The Note Well applies to anything posted: "By participating in the
IETF you agree to follow IETF processes and policies", including disclosing
patents you know of that cover a contribution, "or not participate in the
discussion" (BCP 79). Norn is Apache-2.0 and you hold no patent on it; the draft
says so in one line.

**When.** Row U8 says after the lab soak, so that "a working implementation"
means one that has run. It is separate from the Last Call comment in
`KEYTRANS-LAST-CALL.md`, which is time-boxed (2026-10-23) and deliberately does
not mention Norn.

**The draft** (plain text; the form U8 names: the problem, the threat model,
the WireGuard case, the relationship to KEYTRANS, a working implementation,
where guidance is needed):

```text
Subject: Scope question: transparent authorization for WireGuard peer keys

Hi all,

A scope question for the working group, with an implementation behind it.

The problem. In WireGuard mesh deployments a coordination server hands
every node its peers' public keys and allowed IPs, and the nodes trust it
completely: a compromised or coerced coordinator can give one node an
attacker's key, or widen a peer's routes, and nothing on the node can
tell. There is no interoperable way for a node to check that a peer key's
current authorization, and its route grant, came from the parties allowed
to grant it, independently of the server that delivered it.

Threat model, briefly: the coordinator and the log operator are
untrusted; fewer than k of N witnesses collude with the log; signer and
root keys are trusted within their thresholds; the trust anchor is
provisioned out of band, with no trust on first use.

Relationship to KEYTRANS. The goals overlap, and the architecture's
fork-detection channels (a third party's signature, an anonymous check,
gossip) apply directly. The data model fits less well. What a node must
check is not one label's latest value but whether the authority that
admitted the key was itself valid at that point: who could sign, under
which thresholds, after which revocations. That makes the state global
rather than per label, and puts the authorization, the revocation and the
route grant in exactly the part KEYTRANS leaves to applications.

Implementation: Norn, https://github.com/onembyte/norn (Apache-2.0). A
frozen specification with byte-exact test vectors; a Go node agent and a
Python reference that agree byte for byte; C2SP tlog formats, cosigned by
an unmodified witness. I know of no patent or patent application covering
it.

The question: is a transparent authorization log for a peer set, as
distinct from a transparent key directory, something the group would
consider in scope as an integration, or is it better written up first as
a separate problem statement? Either answer tells me what to write next.

Franco Michetti
```

Before sending, replace "agree byte for byte" with what U1 showed, if it has
run, and read the list's archive for the month to make sure the question has
not just been asked.

## 4. Before anything is sent

Each box is a fact to check on the day, not a promise made today.

**The repository**
- [ ] **Visibility.** Private today. Both messages link to it: make it public
  first (after `PUBLICATION.md` §5's gates and the private review), or send
  without the link and offer access.
- [x] **License.** `LICENSE` is Apache-2.0.
- [ ] **README status line.** Dated 2026-10-07; the counts in it are guarded by
  the build, the date is not.
- [ ] **`RELEASE-NOTES-v0.1.md` is stale.** It calls D-072 and D-074 unresolved
  (both are decided), counts 13 cold-model runs (there are 14), and predates
  D-075, D-076 and D-077. Refresh it when you tag v0.1 (U8).
- [ ] **`make verify-py` green.** Green since the third cold build (6.5l-xii-d,
  2026-10-12); recheck on the day, since a vector added after its seal is
  recorded in `contrib/verify-py.known-failures`.
- [ ] **Which numbers come from a real deployment.** None, today. Every message
  says so, and stays true to it.

**What the 2026-10-12 audit of the tracked files and history found**
- No private key material is tracked. The only private-key marker is
  `cmd/norn/govern.go` recognising an OpenSSH key file by its header; nothing
  under `cmd/norn/norn-witness/` exists; `testdata/vectors/keys.json` holds the
  fixtures' test seeds, published on purpose and described as test keys.
- [ ] **`PUBLICATION.md` §8, "The career angle (one paragraph, for Franco)", names
  Gungnir**, which is private by your decision. Remove that paragraph, or at
  least the Gungnir sentence, before the repository is public — a public repo's
  history keeps it, so remove it in a commit before the first public push, or
  publish a fresh history.
- [ ] **Commit author email.** 364 commits carry your personal address. Publishing
  the history publishes it. Your choice: accept it; rewrite the history to your
  GitHub no-reply address (a force push, only on your explicit request); or
  publish a new repository from a squashed tree.
- [ ] **`mythos_optimization_addition.md`** is an operating note written for the
  build model, not documentation, and contains a local path. Recommendation:
  move it out of the repository before publishing. `BUILD-LOG.md`,
  `HARDENING-PLAN.md` and `DECISIONS.md` describe the AI-assisted process
  (Claude and Codex lanes, cold-model gate runs) and are the project's record
  of how each thing was checked; recommendation: keep them, and say plainly in
  the README that Norn was built with AI assistance under that gate. A reader
  finding it in the log before the README says it is a worse first impression
  than the README saying it.
- Example addresses in the fixtures and docs are private RFC 1918 addresses;
  they route nowhere and need no change.

**The messages**
- [ ] Plain text, no attachments, one link, from your own address.
- [ ] WireGuard: `team@wireguard.com` only; not the list until after publication
  and review; never `security@` for this.
- [ ] KEYTRANS: subscribed first; the Note Well line is true; the archive read.
- [ ] Each status sentence rechecked against the README on the day.

## 5. What is still open before this row is done

`HARDENING-PLAN.md` H17 needs every row H0–H19 done, or blocked on a decision
it states. Open today: H6 (D-068's two consecutive clean cold-model runs: run
15 waits on run 14's fixes, 6.5l-xi-c-ii to -iv, and on the third cold build,
6.5l-xii-d); H15 (the Phase 6 gate audit, after H6); and the owner's rows U1–U9.
H21's problem statement (`standards/`) waits on U8's answer by design. When those
close, this file's facts are rechecked, the row is ticked, and the loop stops
itself as H17 (d) says.
