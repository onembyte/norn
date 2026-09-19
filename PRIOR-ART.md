# Norn — Prior Art Review

Reviewed **2026-09-18** before writing a single line of design. Question asked:
*does an open, protocol-level, implementation-independent key-transparency layer
for WireGuard peer keys already exist?*

**Verdict: no.** The pieces exist separately; nothing assembles them for network
access. Details, closest neighbours, and exactly what gap remains are below.

---

## 1. Closest neighbour: Tailscale Tailnet Lock (TKA)

The only shipping system that defends the threat Norn targets — a compromised
control plane injecting a rogue node key. Design (from the whitepaper):

- Append-only chain of **Authority Update Messages (AUMs)**, each hashing its
  parent, signed by a trusted **Tailnet Lock Key (TLK)**. Ed25519, BLAKE2,
  deterministic CBOR. Every node holds the chain and verifies locally.
- New node keys must be signed by a TLK (`tailscale lock sign`) before peers
  accept them.
- Forks resolved deterministically (signer weight → prefer RemoveKey → lower hash).

What it does **not** do — every item below is stated in Tailscale's own whitepaper:

| Gap | Whitepaper wording | Consequence |
|---|---|---|
| AUMs distributed **only via the control plane** | "The control plane relays authority update messages to each node" | A compromised control plane can **withhold** updates (freeze attack). Acknowledged: "does not prevent a compromised control plane from breaking connectivity… such as by failing to distribute new node keys." |
| **No witnesses, no gossip** | none mentioned | Split-view resistance rests on deterministic fork resolution alone; no external party ever attests to the chain. |
| **Trust-on-first-use** | "a malicious initial state could be sent to each node with attacker-controlled TLKs" | Bootstrapping is the weak point; they propose (but haven't shipped) pre-provisioned expected state. |
| **Node-key signatures are not in the chain** | "AUMs only contain information about changes to Tailnet Lock state… adding or removing trusted TLKs" | TKA is an *authority chain*, not a *key transparency log*. A stolen TLK can sign rogue node keys and there is no append-only record of which node keys were ever signed. This is the CT property TKA lacks. |
| Tied to Tailscale's control plane | — | Headscale feature request [#1307](https://github.com/juanfont/headscale/issues/1307) open since April 2023, labelled `tailscale-feature-gap`, unimplemented. |

The `tailscale.com/tka` package is BSD-3 open source and is worth reading for
its state-machine and fork-resolution code. A Rust port
([tailscale-rs #7](https://github.com/GeiserX/tailscale-rs/issues/7)) has
verification logic but no chain replay or sync; its author's rollout note —
*ship verify-and-log before fail-closed enforcement* — is adopted as a Norn rule.

## 2. Key transparency (messaging)

- **IETF KEYTRANS WG** — architecture draft -08 (Apr 2026), protocol draft on
  standards track. Scope: end-user public keys for E2E *messaging*, billions of
  identities, prefix trees + log trees. Not network access; deliberately
  over-engineered for a closed mesh of 10¹–10⁵ devices.
- **WhatsApp, Apple iMessage CKV, Signal** — shipped KT, same scope.
- **CONIKS / SEEMless / Parakeet / ClaimChain** — the academic lineage. Same scope.

Norn borrows the *properties* (non-equivocation, inclusion proofs, monitors) and
rejects the *data structure* (no prefix tree — full replication instead).

## 3. Transparency-log infrastructure (reuse, don't reinvent)

- **Certificate Transparency** (RFC 6962 / 9162) — the proof the model works.
- **static-ct-api / Sunlight / Tessera** — tiled logs served as static files
  from a web server or object storage. Cheap enough to run on a NAS.
- **C2SP specs**: `tlog-tiles`, `tlog-checkpoint`, `tlog-cosignature`,
  `tlog-witness`, `tlog-policy` — the exact wire formats Norn should adopt so
  existing witnesses and monitors work unchanged.
- **Witness ecosystem** — Sigsum witnesses, transparency-dev `witness`
  (omniwitness), ArmoredWitness (15 hardware devices deployed). The witness
  protocol: submit checkpoint + consistency proof, receive cosignature.
- **Filippo Valsorda's transparent keyserver** — logs `vrf(email) || H(pubkey)`
  for age keys, uses Tessera + tlog-tiles + witness-network policy files. Closest
  *architectural* template. Scope is user keys, explicitly not device or network keys.

## 4. Device-key sigchains

- **Keybase** — per-user sigchains of device additions/revocations, aggregated
  into a Merkle tree whose root was anchored to Bitcoin and later Stellar. The
  closest *conceptual* prior art for "device keys in a verifiable log", but for
  identity/chat/KBFS, not for tunnel peers, and effectively dormant since 2020.

## 5. Mesh VPNs: how each one trusts its coordinator

| System | Who decides the peer set | Compromised coordinator can silently add a peer? | Transparency |
|---|---|---|---|
| Plain WireGuard | you, by hand | n/a (no coordinator) | none |
| Tailscale | control plane | **no**, if Tailnet Lock on | authority chain only |
| Headscale | control plane | **yes** ([#1432](https://github.com/juanfont/headscale/issues/1432)) | none |
| NetBird | management server | **yes** | none |
| ZeroTier | network controller | **yes** | none |
| innernet | coordination server | **yes** (experimental, unaudited) | none |
| Nebula | offline CA signs certs; lighthouse only discovers | lighthouse: no. **CA: yes** | none; revocation = `pki.blocklist` in config |

Nebula is the interesting one: certs from an offline CA are *almost* the right
shape, but revocation is a config-file blocklist with no proof of delivery.
**CVE-2026-61699** (nebula-mesh): the management agent silently discarded the
blocklist, so revoked hosts kept full mesh access for up to 30 days. That is
precisely the failure class "no proof, no peer" turns from silent into loud.

## 6. Academic: WireGuard + certificates

Abdelgawad & Roy, *Incorporating Certificates with the WireGuard VPN Protocol*
(UT Austin course project, May 2022) — adds a certificate exchange round trip
before the Noise handshake and proves it secure in eCK. Explicitly out of scope:
transparency logs and revocation. Their conclusion is Norn's positioning:
*"a more practical approach is to add a layer of certificate support above the
WireGuard key exchange"* rather than touching the protocol.

## 7. Adjacent things that are not this

- **Sigstore / Rekor** — transparency for software artifacts. Right machinery, wrong objects.
- **SPIFFE / SPIRE** — workload identity with short-lived SVIDs; server is fully trusted, no log.
- **step-ca / internal PKI** — private CAs explicitly *avoid* CT.
- **"Blockchain VPNs"** (Orchid, Mysterium, Sentinel) — the chain does payments; the tunnel is plain WireGuard.
- **SSH host-key transparency** — searched; no project found.
- **IoT Merkle-log papers (2024–26)** — log *integrity*, not key distribution.

---

## The gap, precisely

Nothing open provides, for WireGuard peer keys:

1. **A key transparency log** (every enrollment, rotation and revocation is an
   append-only, witnessed entry) — TKA logs authority changes only.
2. **Peer-to-peer checkpoint gossip over the tunnel itself** — TKA is
   control-plane-only and admits the freeze attack.
3. **External witness cosigning** via the standard `tlog-witness` protocol — TKA
   has none.
4. **Pre-provisioned trust anchors** (log key + witness policy + genesis hash
   delivered out of band) — TKA is TOFU.
5. **Enforcement independent of the control plane** — reconcile the kernel's
   WireGuard peer table against the proven set, so it works beside Headscale,
   NetBird, innernet or plain `wg-quick` without patching any of them.

Each piece has shipped somewhere. The assembly has not. That is Norn.

## Sources

- WireGuard paper — https://www.wireguard.com/papers/wireguard.pdf
- Tailnet Lock whitepaper — https://tailscale.com/docs/concepts/tailnet-lock-whitepaper
- Tailnet Lock GA — https://tailscale.com/blog/tailnet-lock-ga
- tka package — https://pkg.go.dev/tailscale.com/tka
- tailscale-rs TKA issue — https://github.com/GeiserX/tailscale-rs/issues/7
- Headscale #1307 (Tailnet Lock request) — https://github.com/juanfont/headscale/issues/1307
- Headscale #1432 (compromise considerations) — https://github.com/juanfont/headscale/issues/1432
- IETF KEYTRANS — https://datatracker.ietf.org/wg/keytrans/about/
- KEYTRANS architecture -08 — https://datatracker.ietf.org/doc/draft-ietf-keytrans-architecture/08/
- KEYTRANS protocol — https://datatracker.ietf.org/doc/draft-ietf-keytrans-protocol/
- Static CT API — https://c2sp.org/static-ct-api@v1.1.0
- tlog-witness — https://c2sp.org/tlog-witness
- tlog-policy — https://c2sp.org/tlog-policy
- Sunlight — https://letsencrypt.org/2024/03/14/introducing-sunlight
- Witness network — https://blog.transparency.dev/can-i-get-a-witness-network
- ArmoredWitness — https://github.com/transparency-dev/armored-witness
- Sigsum design — https://git.sigsum.org/sigsum/plain/doc/design.md
- Transparent keyserver (Valsorda) — https://words.filippo.io/keyserver-tlog/
- Transparent logs for skeptical clients (Cox) — https://research.swtch.com/tlog
- Keybase sigchains — https://book.keybase.io/docs/server#meet-your-sigchain-and-everyone-elses
- Keybase Merkle root in Stellar — https://keybase.io/docs/server_security/merkle_root_in_stellar_blockchain
- Nebula blocklist / CVE-2026-61699 — https://advisories.gitlab.com/golang/github.com/forgekeep/nebula-mesh/CVE-2026-61699/
- innernet — https://github.com/tonarino/innernet
- Abdelgawad & Roy, cert-WG — https://www.cs.utexas.edu/~dwu4/courses/sp22/static/projects/AbdelgawadRoy.pdf
- Orchid — https://www.orchid.com/vpn/
- Rekor — https://docs.sigstore.dev/logging/overview/
- SPIFFE concepts — https://spiffe.io/docs/latest/spiffe-about/spiffe-concepts/
