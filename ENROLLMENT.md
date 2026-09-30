# Norn — Enrollment, Signer Keys, Recovery

Written **2026-09-18** (plan part 7). The part that decides whether anyone runs a
2-of-3 root. Rule: **every flow must work with a laptop and a phone camera**; no
mobile app in v0.

**Status, 2026-09-30: much of this is not built.** `norn` has ten subcommands —
`audit`, `enroll`, `init`, `monitor`, `sign`, `stamp`, `status`, `submit`,
`verify` and `verify-evidence` (`commands` in `cmd/norn/main.go`). Shipped tools
build exactly two entry types: `genesis` (`norn init`) and `enroll`
(`norn enroll`, then `norn sign`, which refuses any other type). Replay applies
every type `SPEC.md` §4.3 defines, and `norn submit` sends any well-formed entry
for this network, so a `revoke`, `rotate` or governance entry built some other
way (for example with `entry.sign` in the Python reference,
`contrib/norn-ref/nornref/entry.py`) can be submitted, and replay applies it if
it is valid. But **no `norn revoke`, `norn rotate`, governance builder,
`norn migrate`, `norn trust import`, `norn sign --pending`, pending inbox or
`norn-log restore` exists**, `nornd` signs nothing, and paper keys (tier 3) are
not implemented (SEC-008, open; `docs/audit/ROADMAP.md` task 5). Each place
below that describes one of them says so.

## 1. Key tiers

| Tier | Where the key lives | Ed25519? | Use |
|---|---|---|---|
| 0 | an **OpenSSH private key file**, unencrypted, mode 0600 (`ssh-keygen -t ed25519 -N ""`) | ✓ | **device keys** (meant for `nornd` to sign `rotate` and self-`revoke` with nobody at the keyboard — not implemented, SEC-008), lab, CI |
| 1 | an **ssh-agent** (OpenSSH agent, 1Password/Bitwarden SSH agent, gpg-agent, macOS keychain-backed agent) | ✓ | **signers (default)** |
| 2 | hardware with **touch**: Tillitis TKey (native Ed25519 signer app, via its agent), YubiKey OpenPGP applet (Ed25519, touch policy on, via gpg-agent) | ✓ | **roots (default)** |
| 3 | **paper**: 24-word mnemonic → Ed25519 seed, sealed envelope | ✓ | root backups, the third root. **Not implemented**: no wordlist is chosen (`internal/genesis`); a root held elsewhere joins by `norn init -root-pub` |
| — | Secure Enclave, TPM 2.0 | ✗ P-256 only | **not supported**; say so in docs so nobody wastes an evening |
| v1 | YubiKey FIDO2 `ed25519-sk` (signature is a FIDO assertion, not raw Ed25519) | ~ | Phase 7: second signature kind `ed25519-sk` in `sigs[]` |

**One abstraction: the ssh-agent protocol.** `norn sign` asks `SSH_AUTH_SOCK` to sign
the raw preimage (§SPEC 4.2); for Ed25519 keys an agent returns a plain Ed25519
signature, so TKey, YubiKey-OpenPGP, software keys and password-manager agents all
look identical to Norn. `kid` = derived from the agent's public key. No Norn key
store to secure, no key format to invent.

**Tier 0 is a file because a daemon cannot type a passphrase.** `nornd` is meant
to sign `rotate` and self-`revoke` at boot with nobody present (it signs nothing
yet, SEC-008), so that key lives on disk under 0600 — and an encrypted file would not help, since the passphrase would have
to live beside it. So Norn **refuses** a passphrase-protected key and says what to
do instead: `ssh-add` it once and let Norn use the agent, which is tier 1. The two
tiers are **one format**: `ssh-add` loads a key `norn` wrote, unchanged, and that
is a test, not a claim (`internal/keyfile`). An earlier draft of this table said
tier 0 was an age-style scrypt file; that would have meant inventing a key format
and importing a KDF to protect a secret a daemon must read unattended.

**Binding, and tested:** Norn **verifies every signature an agent returns** before
using it (`internal/sshagent`). An agent is a separate process — sometimes another
vendor's, sometimes a piece of hardware — and a signature that does not verify has
to fail in the CLI, not in somebody else's replay. Keys of other types in the same
agent are skipped, not refused: the user's RSA login key living next to a Norn
signer is the normal case.

## 2. Root ceremony (homelab, ~10 minutes)

```
root-1  hardware (TKey or YubiKey), touch required, lives on the admin's keyring
root-2  paper, envelope at home
root-3  paper, envelope at a relative's / a friend's
root_thr = 2 · signer_thr = 1 · signer-1 = laptop ssh-agent key
```

`norn init` walks it: generates root-2/3 as words on screen (never written to disk),
asks you to read them back, verifies, generates `genesis`, asks root-1 and root-2
to sign (touch; type words), submits, prints the trust file as QR + fingerprint.
Org default: `root_thr = 2` of ≥ 3 hardware keys held by different people, `signer_thr = 1..2`.

**What `norn init` does today.** No words, no read-back, no QR and no submit.
Roots come from `-root` key files (created if absent, and they sign), `-root-agent`
kids in the ssh-agent (they sign) and `-root-pub` hex public keys (they join
without signing); signers, the log key, log URLs and witnesses come from flags
too. It builds and signs `genesis`, writes `genesis.cbor`, `norn.trust` and
`norn.trust.toml` into `-out`, and prints the fingerprint — 16 base32
characters in groups, not words (`trust.Fingerprint`). Submitting the genesis
entry is a separate `norn submit`.

## 3. Enrolling a device

```
device$  norn enroll --name pi-cam [--wg-key /etc/wireguard/wg0.key | --gen] [--expires 30d] [--label ip=10.9.0.14/32]
         → creates device identity key (/var/lib/norn/device.key, tier 0/1)
         → prints an ENROLLMENT REQUEST as QR + text  (norn1… ≈ 200 chars)
         → optionally POSTs it to <log>/pending (convenience inbox; untrusted)

admin$   norn sign norn1…            # or: norn sign --pending
         pi-cam  wg=…7f2a  device=…c910  labels ip=10.9.0.14/32  expires 30d
         sign with signer-1 (agent: 1Password) ? [touch/confirm]
         → full `enroll` entry → norn submit → receipt → waits for inclusion
         ✓ pi-cam active at index 41 · checkpoint 42 · cosigned pi, vps
```

`norn submit` keeps the receipt on disk **before** it starts waiting, because
§SPEC 7 says to hold it until inclusion is verified and a process that dies
mid-wait must not take the evidence with it. It re-verifies the whole log on
every poll — inclusion in a log that no longer checks out is not inclusion — and
if the deadline passes with the leaf still absent it says so plainly: that
receipt is now proof the log misbehaved (`THREAT-MODEL.md` A2), and it should be
kept.

```
device$  norn trust import  <QR of norn.trust>       # once per device, out of band
         fingerprint: "coral-mango-tiger-piano" — matches the admin's screen?  [y]
         nornd starts, sees itself in the log, is active on every peer ≤ T_c + T_g
```

**What exists of this flow today.** `norn enroll` takes `-name`, `-net` or
`-trust`, `-key` (default `/var/lib/norn/device.key`, a tier 0 file created if
absent), one of `-wg-key`, `-wg-pub` or `-gen`, `-expires`, repeated `-label`,
and `-qr` / `-no-qr`; it prints the request as text, and as a QR on a terminal.
It POSTs nothing: there is no pending inbox and no `norn sign --pending`.
`norn sign -trust <file> (-key <file> | -agent-kid <kid>) <file or ->` reads
the request, or a partially signed entry, from a file or stdin — not from its
argument — and writes the entry to stdout or `-o`; then
`norn submit -trust <file> -wait <entry>` sends it and waits for inclusion. There is no `norn trust import`:
a device is handed `norn.trust` as a file, and the fingerprint `norn init`
printed is compared by hand. The `ip` label in the example is the one
`SPEC.md` §4.0 reserves, but `nornd`'s `labels` endpoint provider reads
`allowed_ips` (SEC-018; decision D-f; `ENFORCEMENT.md` §5).

Enrollment request = CBOR `{net, device_id, device_pk, wg_pk, labels, expires, ts}`
signed by the device key (proof of possession, D-008); the normative format is
`SPEC.md` §16. `norn sign` verifies that signature **before** showing the prompt,
so a request whose device key did not sign it is never displayed.

The signer's entry **embeds that request verbatim** (`SPEC.md` §4.3): the device
is headless and one-way, so it can never sign the envelope the signer builds,
and an entry that merely *restated* its claims would let a signer enrol a key
the device never asked for. The signer chooses `ts` and `after`; it cannot touch
`device_id`, `device_pk`, `wg_pk`, labels or expiry without destroying the proof.

Precisely what that proves, since an earlier draft of this paragraph overclaimed
it: the signature proves possession of the **device** key and binds `wg_pk` to
it. It does **not** prove possession of the WireGuard key, which is X25519 and
by §3 never signs. A device can ask to enrol a WireGuard key it does not hold —
and gets nothing for it: if the key is already active the entry is refused
`dup-wg`, and if it is not, the device has enrolled a key it cannot handshake
with. See `SPEC.md` §16.1.

Threshold signing (`signer_thr > 1`): each `norn sign` appends one signature to the
entry; the pending inbox (not implemented) or a file carries partials; `norn submit`
refuses until the threshold is met — in practice the log does: `norn submit`
counts no signatures itself, and `norn-log`'s advisory replay (`SPEC.md` §6)
answers 409 for an entry short of its threshold, which `norn submit` reports.
Appending is safe because the preimage excludes `sigs` (`SPEC.md` §4.2), so a
second signer changes nothing the first one signed — and `norn sign` never rewrites `ts` or `after` on an entry that already carries
signatures, which would invalidate them. It reports progress after every run
("2 of 2 signer signatures. Ready for `norn submit`"), because a signer who stops
one signature short has done nothing at all. Every prompt shows the entry hash and the human summary;
`--yes` exists for signer entries in scripts and **does not exist** for root entries.
Not yet true of the code: `norn sign` accepts `-yes` with `-role root` on the
`enroll` entries it builds, and the entries only roots sign have no builder at all
(SEC-008).

## 4. Rotation, revocation, expiry

- **Rotate** (`norn rotate` on the device): new WG key, `rotate` entry signed by the
  device key (+ a signer if `rotate_needs_signer`). The device keeps the old WG key
  until it sees the entry included, then swaps; peers switch at their next checkpoint.
  Gap ≤ T_c + T_g. Overlapping dual-key grace is v1 backlog.
- **Revoke**: `norn revoke pi-cam --reason lost` (signer) · `norn revoke --self`
  (device, on suspicion) · `norn revoke pi-cam --root` (emergency, roots). Effect on
  every honest node ≤ T_c + T_g + T_poll (G4), measured by lab T7.
- **Expiry**: `enroll.expires` for guests and contractors; evaluated at checkpoint
  time, so a laptop that never comes back simply falls out.

**Status.** Neither `norn rotate` nor `norn revoke` exists, in any of the forms
above, and `nornd` signs nothing (SEC-008, open; `docs/audit/ROADMAP.md` task 5).
Replay applies `rotate` and `revoke` entries, and `nornd` acts on them within one
cycle — `TestARevokeEntryEvictsTheDevice` appends a hand-built `revoke` to a real
log between two cycles — but no shipped tool builds one. The G4 bound is not
measured: lab T7 does not exist (`GOSSIP.md` §8), and today the bound also carries
the log and peer I/O each cycle does before it reconciles (SEC-003, SEC-013) and
does not survive a restart (SEC-004). Expiry is implemented: `norn enroll
-expires`, and `nornd` judges it at the checkpoint's witness time
(`proven.EvaluationTime`); `norn status` judges it by the local wall clock
instead (SEC-035).

## 5. Recovery runbooks

Every runbook is a `norn` subcommand or a numbered list; nothing here rewrites
history. Append-only means recovery = *new entries that supersede*.

**Most of these cannot be run with shipped tools yet.** The last column says what
exists on 2026-09-30. Only `enroll` and `genesis` entries have a builder
(SEC-008), and no runbook has been executed in a lab.

| # | Situation | Procedure | Downtime | Tools today |
|---|---|---|---|---|
| R1 | Signer key **lost** | roots: `signer_remove` + `signer_add` | none | no builder for either entry |
| R2 | Signer key **stolen** | roots: `signer_remove`; `norn audit --by <kid> --since <t>` lists everything that key signed; `revoke` rogue devices; re-`enroll` any it wrongly revoked | none for honest peers | `norn audit -by -since` and `norn enroll` / `sign` exist; no builder for `signer_remove` or `revoke` |
| R3 | One root of 2-of-3 lost or stolen | remaining two: `root_remove` + `root_add` (new paper key). **Do it the same day** — with one root gone, the next loss is R5 | none | no builder for either entry; paper keys not implemented |
| R4 | Device rebuilt / device key lost | `revoke` + fresh `enroll` | that device only | `enroll` only; no `revoke` builder |
| R5 | Root quorum lost or stolen | **re-genesis**: `norn migrate` builds a new `genesis` under new roots, auto-generates re-enrollment requests for every active device (device keys persist), batch-signs them, produces one new trust file. Deliver it to each device out of band. This is the one procedure that touches every device, and it is the price of losing the roots; `norn migrate` makes it an afternoon, not a month | until each device imports the new trust file | `norn migrate` does not exist; `norn init` builds a new network, and each device re-enrols by hand |
| R6 | Log storage lost | `norn-log restore --from <any node>` — every node holds all tiles; the log resumes at the same size with the same key | none for nodes (they gossip meanwhile) | `norn-log restore` does not exist; `nornd` does keep a mirror of the tiles under `<run dir>/mirror` |
| R7 | Log **key** compromised or lost | roots publish `log_key` entry (§6); the log signs checkpoints with **both** keys for `overlap` (30 d) so nodes with old trust files still verify while they replay the rotation | none | no `log_key` builder; `norn-log` signs with one key (`-key`); verifiers never retire a key (§6, SEC-014) |
| R8 | Witness key rotation / policy change | roots publish `policy` entry (§6); same overlap logic for cosignatures | none | no `policy` builder; a replayed `policy` replaces the old one at once, with no overlap (`SPEC.md` §9.4) |
| R9 | Node's trust file lost | re-deliver (QR); nothing else changes | that node only | re-deliver the file; no QR or import command exists |
| R10 | Device stolen | `revoke`; evicted everywhere ≤ G4 bound; the device key can do nothing but self-revoke | none | no `revoke` builder, self or otherwise |

## 6. Two governance entries this forces (→ SPEC v0.1)

| `t` | body | signatures | effect |
|---|---|---|---|
| `log_key` | `pk` (new log verifier key), `overlap` (uint s) | ≥ `root_thr` roots | nodes accept checkpoints signed by old **or** new key until `overlap` elapses, then new only |
| `policy` | `text` (verbatim tlog-policy) | ≥ `root_thr` roots | replaces the witness policy in replayed state |

Consequence: `norn.trust` carries the **initial** log key and policy plus the genesis
hash; everything after that evolves inside the log under root signatures. A fresh
node with an old trust file still bootstraps because of the overlap window, and a
node that replayed the rotation trusts the new keys from its own state (G6 holds:
it never trusts anything not rooted in its trust file).

**"Then new only" is not what the specification or the code does (SEC-014,
open).** `SPEC.md` §9.4 makes `overlap` an obligation on the log to keep signing
with the superseded key, not a rule for verifiers: keys learned from `log_key`
entries accumulate beside the trust file's key and are never retired, and replay
records `overlap` without anything reading it (`logclient.KeysFrom`). So
rotation is not revocation: a checkpoint signed by a compromised old key still
passes the log-signature check of every node that holds that key, the trust
file's key included (the witness quorum is still required). `norn-log` signs
with one key, so it cannot keep the overlap either. Whether verifiers retire
keys, or the documents say plainly that they do not, is decision D-d
(`docs/audit/ROADMAP.md`). No shipped tool builds either entry (SEC-008).

## 7. UX principles (binding)

1. What you sign is what you see: every prompt shows device name, key fingerprints, labels, expiry, entry hash.
2. Hardware roots need a touch; there is no `--yes` for root entries.
3. Paper keys are typed, never pasted from a file, and never stored by `norn`.
4. Any flow that needs a second device works with a phone camera and a QR.
5. `norn status` on any node shows: proven peers, checkpoint age, degraded/fork state, and the last five log entries in plain words ("2 h ago: signer-1 enrolled pi-cam").

How far the code keeps them, on 2026-09-30. Rule 1 holds for `norn sign`, the
one command that signs entries after genesis. Rule 2 does not yet: `norn sign`
accepts `-yes` with `-role root`, and the touch is whatever the signing agent
enforces (SEC-008). Rule 3 has nothing to apply to: paper keys are not
implemented. Rule 4 holds for the enrollment request, which `norn enroll` prints
as a QR, and not for the trust file, which has no QR output and no import
command. Rule 5 in part: `norn status` fetches and verifies the log itself and
prints the proven, revoked and expired devices, the quorum time with an age by
the local clock, and the last five entries in plain words; it does not show the
degraded or fork state, which only a running `nornd` tracks (`GOSSIP.md` §5), and
it judges expiry by the wall clock (SEC-035).
