# Norn — Enrollment, Signer Keys, Recovery

Written **2026-09-18** (plan part 7). The part that decides whether anyone runs a
2-of-3 root. Rule: **every flow must work with a laptop and a phone camera**; no
mobile app in v0.

## 1. Key tiers

| Tier | Where the key lives | Ed25519? | Use |
|---|---|---|---|
| 0 | an **OpenSSH private key file**, unencrypted, mode 0600 (`ssh-keygen -t ed25519 -N ""`) | ✓ | **device keys** (`nornd` signs `rotate` and self-`revoke` with nobody at the keyboard), lab, CI |
| 1 | an **ssh-agent** (OpenSSH agent, 1Password/Bitwarden SSH agent, gpg-agent, macOS keychain-backed agent) | ✓ | **signers (default)** |
| 2 | hardware with **touch**: Tillitis TKey (native Ed25519 signer app, via its agent), YubiKey OpenPGP applet (Ed25519, touch policy on, via gpg-agent) | ✓ | **roots (default)** |
| 3 | **paper**: 24-word mnemonic → Ed25519 seed, sealed envelope | ✓ | root backups, the third root |
| — | Secure Enclave, TPM 2.0 | ✗ P-256 only | **not supported**; say so in docs so nobody wastes an evening |
| v1 | YubiKey FIDO2 `ed25519-sk` (signature is a FIDO assertion, not raw Ed25519) | ~ | Phase 7: second signature kind `ed25519-sk` in `sigs[]` |

**One abstraction: the ssh-agent protocol.** `norn sign` asks `SSH_AUTH_SOCK` to sign
the raw preimage (§SPEC 4.2); for Ed25519 keys an agent returns a plain Ed25519
signature, so TKey, YubiKey-OpenPGP, software keys and password-manager agents all
look identical to Norn. `kid` = derived from the agent's public key. No Norn key
store to secure, no key format to invent.

**Tier 0 is a file because a daemon cannot type a passphrase.** `nornd` signs
`rotate` and self-`revoke` at boot with nobody present, so that key lives on disk
under 0600 — and an encrypted file would not help, since the passphrase would have
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

device$  norn trust import  <QR of norn.trust>       # once per device, out of band
         fingerprint: "coral-mango-tiger-piano" — matches the admin's screen?  [y]
         nornd starts, sees itself in the log, is active on every peer ≤ T_c + T_g
```

Enrollment request = CBOR `{net, device_id, device_pk, wg_pk, labels, expires, ts}`
signed by the device key (proof of possession, D-008); the normative format is
`SPEC.md` §16. `norn sign` verifies that signature **before** showing the prompt,
so a request whose device key did not sign it is never displayed.

Precisely what that proves, since an earlier draft of this paragraph overclaimed
it: the signature proves possession of the **device** key and binds `wg_pk` to
it. It does **not** prove possession of the WireGuard key, which is X25519 and
by §3 never signs. A device can ask to enrol a WireGuard key it does not hold —
and gets nothing for it: if the key is already active the entry is refused
`dup-wg`, and if it is not, the device has enrolled a key it cannot handshake
with. See `SPEC.md` §16.1.

Threshold signing (`signer_thr > 1`): each `norn sign` appends one signature to the
entry; the pending inbox (or a pasted blob) carries partials; `norn submit` refuses
until the threshold is met. Every prompt shows the entry hash and the human summary;
`--yes` exists for signer entries in scripts and **does not exist** for root entries.

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

## 5. Recovery runbooks

Every runbook is a `norn` subcommand or a numbered list; nothing here rewrites
history. Append-only means recovery = *new entries that supersede*.

| # | Situation | Procedure | Downtime |
|---|---|---|---|
| R1 | Signer key **lost** | roots: `signer_remove` + `signer_add` | none |
| R2 | Signer key **stolen** | roots: `signer_remove`; `norn audit --by <kid> --since <t>` lists everything that key signed; `revoke` rogue devices; re-`enroll` any it wrongly revoked | none for honest peers |
| R3 | One root of 2-of-3 lost or stolen | remaining two: `root_remove` + `root_add` (new paper key). **Do it the same day** — with one root gone, the next loss is R5 | none |
| R4 | Device rebuilt / device key lost | `revoke` + fresh `enroll` | that device only |
| R5 | Root quorum lost or stolen | **re-genesis**: `norn migrate` builds a new `genesis` under new roots, auto-generates re-enrollment requests for every active device (device keys persist), batch-signs them, produces one new trust file. Deliver it to each device out of band. This is the one procedure that touches every device, and it is the price of losing the roots; `norn migrate` makes it an afternoon, not a month | until each device imports the new trust file |
| R6 | Log storage lost | `norn-log restore --from <any node>` — every node holds all tiles; the log resumes at the same size with the same key | none for nodes (they gossip meanwhile) |
| R7 | Log **key** compromised or lost | roots publish `log_key` entry (§6); the log signs checkpoints with **both** keys for `overlap` (30 d) so nodes with old trust files still verify while they replay the rotation | none |
| R8 | Witness key rotation / policy change | roots publish `policy` entry (§6); same overlap logic for cosignatures | none |
| R9 | Node's trust file lost | re-deliver (QR); nothing else changes | that node only |
| R10 | Device stolen | `revoke`; evicted everywhere ≤ G4 bound; the device key can do nothing but self-revoke | none |

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

## 7. UX principles (binding)

1. What you sign is what you see: every prompt shows device name, key fingerprints, labels, expiry, entry hash.
2. Hardware roots need a touch; there is no `--yes` for root entries.
3. Paper keys are typed, never pasted from a file, and never stored by `norn`.
4. Any flow that needs a second device works with a phone camera and a QR.
5. `norn status` on any node shows: proven peers, checkpoint age, degraded/fork state, and the last five log entries in plain words ("2 h ago: signer-1 enrolled pi-cam").
