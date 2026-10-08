# Norn — Enrollment, Signer Keys, Recovery

Written **2026-09-18** (plan part 7). The part that decides whether anyone runs a
2-of-3 root. `SPEC.md` owns every rule an interoperable node needs from this
document — key handling, signing and the root `--yes` refusal in §16.3,
enrollment requests and the display rule in §16, log-key rotation and `overlap`
in §9.4, entry bodies in §4.3. This document is **informative**: the ceremony's
runbook and the reasoning, and where it disagrees with `SPEC.md`, the SPEC and
the implemented node win. Flows marked **planned** below are direction, not promises. Rule:
**every flow must work with a laptop and a phone camera**; no mobile app in v0.

## 1. Key tiers

| Tier | Where the key lives | Ed25519? | Use |
|---|---|---|---|
| 0 | an **OpenSSH private key file**, unencrypted, mode 0600 (`ssh-keygen -t ed25519 -N ""`) | ✓ | **device keys** — the key that signs `rotate` and self-`revoke` (`SPEC.md` §4.3) with nobody at the keyboard — lab, CI |
| 1 | an **ssh-agent** (OpenSSH agent, 1Password/Bitwarden SSH agent, gpg-agent, macOS keychain-backed agent) | ✓ | **signers (default)** |
| 2 | hardware with **touch**: Tillitis TKey (native Ed25519 signer app, via its agent), YubiKey OpenPGP applet (Ed25519, touch policy on, via gpg-agent) | ✓ | **roots (default)** |
| 3 | **paper**: 24-word mnemonic → Ed25519 seed, sealed envelope — **planned**; `norn init` does not generate paper keys yet | ✓ | root backups, the third root |
| — | Secure Enclave, TPM 2.0 | ✗ P-256 only | **not supported**; say so in docs so nobody wastes an evening |
| v1 | YubiKey FIDO2 `ed25519-sk` (signature is a FIDO assertion, not raw Ed25519) | ~ | Phase 7: second signature kind `ed25519-sk` in `sigs[]` |

**One abstraction: the ssh-agent protocol.** `norn sign` asks `SSH_AUTH_SOCK` to sign
the raw preimage (§SPEC 4.2); for Ed25519 keys an agent returns a plain Ed25519
signature, so TKey, YubiKey-OpenPGP, software keys and password-manager agents all
look identical to Norn. `kid` = derived from the agent's public key. No Norn key
store to secure, no key format to invent.

A signer key in an ssh-agent can be used by anything that can reach the
agent's socket: any process running as that user, or a host you connect to with
agent forwarding (`ssh -A`). The §4.2 domain prefix prevents cross-protocol
signature reuse; it does not restrict who can ask the agent to sign. Use a
dedicated agent for Norn keys and never forward it. Require confirmation for
each use with `ssh-add -c`, or use a hardware key that requires a touch.

**Tier 0 is a file because a device cannot type a passphrase.** The device key
signs `rotate` and self-`revoke` (`SPEC.md` §4.3) with nobody at the keyboard, so
that key lives on disk under 0600 — and an encrypted file would not help, since
the passphrase would have to live beside it. So Norn **refuses** a
passphrase-protected key and says what to
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

`norn init` walks the implemented part: it takes root, signer and log keys from
files and agents (tiers 0–2), builds `genesis`, prints every public key and the
trust file's fingerprint, and refuses a trust file whose `genesis_hash` does not
match entry 0. The fingerprint is Crockford base32, four groups of four
(`7f3x-2hnq-9kd4-vp2w`), and every node is provisioned to compare it against the
admin's screen (`SPEC.md` §9.3). The paper-root steps — words on screen, read
them back, verify — are **planned**, and when paper arrives it will follow §7
rule 3 below.
Org default: `root_thr = 2` of ≥ 3 hardware keys held by different people, `signer_thr = 1..2`.

## 3. Enrolling a device

```
device$  norn enroll --name pi-cam [--wg-key /etc/wireguard/wg0.key | --gen] [--expires 30d] [--label ip=10.9.0.14/32]
         → creates device identity key (/var/lib/norn/device.key, tier 0/1)
         → prints an ENROLLMENT REQUEST as QR + text  (norn1… ≈ 200 chars)
         → optionally POSTs it to <log>/pending (convenience inbox; untrusted; **planned**)

admin$   norn sign norn1…            # the --pending inbox is planned; today the
                                      # request is pasted or piped
         pi-cam  wg=…7f2a  device=…c910  labels ip=10.9.0.14/32  expires 30d
         sign with signer-1 (agent: 1Password) ? [touch/confirm]
         → full `enroll` entry → norn submit → receipt → waits for inclusion
         ✓ pi-cam active at index 41 · checkpoint 42 · cosigned pi, vps

`norn submit` keeps the receipt on disk **before** it starts waiting, because
§SPEC 7 says to hold it until inclusion is verified and a process that dies
mid-wait must not take the evidence with it. It re-verifies the whole log on
every poll — inclusion in a log that no longer checks out is not inclusion — and
if the deadline passes with the leaf still absent it says so plainly: that
receipt is now proof the log misbehaved (`THREAT-MODEL.md` A2), and it should be
kept.

device$  # planned: `norn trust import <QR of norn.trust>`. Today: copy norn.trust
         # to the device out of band, and compare its fingerprint (7f3x-2hnq-
         # 9kd4-vp2w form) with the admin's screen before trusting it (§9.3).
         nornd starts, sees itself in the log, is active on every peer ≤ T_c + T_g
```

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
entry; the pending inbox (or a pasted blob) carries partials; `norn submit` refuses
until the threshold is met. Appending is safe because the preimage excludes `sigs`
(`SPEC.md` §4.2), so a second signer changes nothing the first one signed — and
`norn sign` never rewrites `ts` or `after` on an entry that already carries
signatures, which would invalidate them. It reports progress after every run
("2 of 2 signer signatures. Ready for `norn submit`"), because a signer who stops
one signature short has done nothing at all. Every prompt shows the entry hash and the human summary;
`--yes` exists for signer entries in scripts and **does not exist** for root
entries — `norn sign` refuses the combination outright, and the rule is
normative in `SPEC.md` §16.3.

## 4. Rotation, revocation, expiry

- **Rotate** (the `rotate` entry is normative, `SPEC.md` §4.3; the `norn rotate`
  subcommand exists): the device runs
  `norn rotate -trust norn.trust -device pi-cam -wg-key /etc/wireguard/wg0-new.key -key /var/lib/norn/device.key -yes -o rotate.cbor`.
  Add `-new-key device-new.key` to rotate its identity too; both identity keys sign.
  When `rotate_needs_signer` is on, a signer extends it with
  `norn rotate -trust norn.trust -device pi-cam -role signer -key signer.key -in rotate.cbor -o rotate.cbor`;
  repeat with distinct signers until `signer_thr` is met, then submit with
  `norn submit -trust norn.trust rotate.cbor`. The device keeps the old WG key
  until it sees the entry included, then swaps; peers switch at their next checkpoint.
  Gap ≤ T_c + T_g. Overlapping dual-key grace is v1 backlog.
- **Revoke** (the entry is normative, `SPEC.md` §4.3; the `norn revoke` subcommand
  exists): a signer runs `norn revoke -trust norn.trust -device pi-cam -reason lost -key signer.key -o revoke.cbor`.
  If more signatures are needed, another signer extends it with `-in revoke.cbor`;
  submit the completed entry with `norn submit -trust norn.trust revoke.cbor`.
  A device self-revokes with `-role device` and its own key file; roots revoke
  in an emergency with `-role root` and interactive confirmation. Effect on
  every honest node ≤ T_c + T_g + T_poll (G4), measured by lab T7.
- **Expiry**: `enroll.expires` for guests and contractors; evaluated at checkpoint
  time, so a laptop that never comes back simply falls out.

## 5. Recovery runbooks

Every runbook is a `norn` subcommand or a numbered list; nothing here rewrites
history. Append-only means recovery = *new entries that supersede*.

| # | Situation | Procedure | Downtime |
|---|---|---|---|
| R1 | Signer key **lost** | roots: `norn govern -trust norn.trust -t signer_remove -kid LOST_KID -key root.key -o remove.cbor`, then `norn govern -trust norn.trust -t signer_add -pk replacement.pub -key root.key -o add.cbor` | none |
| R2 | Signer key **stolen** | roots: `norn govern -trust norn.trust -t signer_remove -kid STOLEN_KID -key root.key -o remove.cbor` first, to stop the bleeding; then `norn audit -trust norn.trust -by STOLEN_KID` lists everything that key signed — it reads the log, so it works after the removal, and without `-since`, because the thief chose the `ts` of every entry it signed; `revoke` rogue devices; re-`enroll` any it wrongly revoked | none for honest peers |
| R3 | One root of 2-of-3 lost or stolen | remaining two: `norn govern -trust norn.trust -t root_remove -kid LOST_KID -key root.key -o remove.cbor`, then `norn govern -trust norn.trust -t root_add -pk replacement.pub -key root.key -o add.cbor` (new root key). **Do it the same day** — with one root gone, the next loss is R5 | none |
| R4 | Device rebuilt / device key lost | `revoke` + fresh `enroll` | that device only |
| R5 | Root quorum lost or stolen | **re-genesis** (`norn migrate` is **planned**, not built): build a new `genesis` under new roots, auto-generate re-enrollment requests for every active device (device keys persist), batch-sign them, produce one new trust file. Deliver it to each device out of band. This is the one procedure that touches every device, and it is the price of losing the roots; `norn migrate` will make it an afternoon, not a month | until each device imports the new trust file |
| R6 | Log storage lost | **planned**: `norn-log restore --from <any node>` — every node holds all tiles; the log resumes at the same size with the same key | none for nodes (they gossip meanwhile) |
| R7 | Log **key** compromised or lost | roots build `norn govern -trust norn.trust -t log_key -pk new-log.pub -overlap 2592000 -key root.key -o log-key.cbor` (§6); the log signs checkpoints with **both** keys for `overlap` (30 d) so nodes with old trust files still verify while they replay the rotation | none |
| R8 | Witness key rotation / policy change | roots build `norn govern -trust norn.trust -t policy -policy witnesses.policy -key root.key -o policy.cbor` (§6); same overlap logic for cosignatures | none |
| R9 | Node's trust file lost | re-deliver (QR); nothing else changes | that node only |
| R10 | Device stolen | `revoke`; evicted everywhere ≤ G4 bound; the device key can do nothing but self-revoke | none |

For each governance entry above, each additional root confirms and extends the
same file with `norn govern -trust norn.trust -t TYPE -key another-root.key -in entry.cbor -o entry.cbor`.
Once the observed `root_thr` is met, publish it with
`norn submit -trust norn.trust entry.cbor` and verify inclusion before building
a change that depends on it. Replace `TYPE`, filenames and key ids with the
values for that runbook. Root authority always requires confirmation; `-yes`
is refused.

## 6. The two governance entries (normative in `SPEC.md` §§4.3 and 9.4)

| `t` | body | signatures | effect |
|---|---|---|---|
| `log_key` | `pk` (new log verifier key), `overlap` (uint s) | ≥ `root_thr` roots | the log signs checkpoints with **both** keys for at least `overlap` — an obligation on the **log** (`SPEC.md` §9.4), not a rule a verifier times — and verifier keys accumulate: a learned key is never retired |
| `policy` | `text` (verbatim tlog-policy) | ≥ `root_thr` roots | replaces the witness policy in replayed state |

Build a log-key rotation with
`norn govern -trust norn.trust -t log_key -pk new-log.pub -overlap 2592000 -key root.key -o log-key.cbor`,
or a policy replacement with
`norn govern -trust norn.trust -t policy -policy witnesses.policy -key root.key -o policy.cbor`.
Extend with the other roots and submit as in §5; policy text is parsed before
confirmation and included verbatim in the entry.

Consequence: `norn.trust` carries the **initial** log key and policy plus the genesis
hash; everything after that evolves inside the log under root signatures. A fresh
node with an old trust file still bootstraps because of the overlap window, and a
node that replayed the rotation trusts the new keys from its own state (G6 holds:
it never trusts anything not rooted in its trust file).

## 7. UX principles

The normative ones live in `SPEC.md`: rule 1 is §16.1's display rule, rule 2 is
§16.3's root `--yes` refusal. The rest are how the tools should feel.

1. What you sign is what you see: every prompt shows device name, key fingerprints, labels, expiry, entry hash.
2. Hardware roots need a touch; there is no `--yes` for root entries.
3. Paper keys are typed, never pasted from a file, and never stored by `norn` — the rule the **planned** tier-3 flow will follow.
4. Any flow that needs a second device works with a phone camera and a QR.
5. `norn status` on any node shows: proven peers, checkpoint age, degraded/fork state, and the last five log entries in plain words ("2 h ago: signer-1 enrolled pi-cam").
