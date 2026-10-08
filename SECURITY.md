# Security policy

## Status

Norn is pre-release and has no supported version. Nothing has run on a real
kernel or been reviewed by an outside party. The [README status](README.md)
has the current project status.

## Reporting a vulnerability

Please report vulnerabilities privately, never in a public issue. Once the
repository is public, use its GitHub **Security** tab → **Report a
vulnerability** (GitHub offers private reporting on public repositories only).
Until then the repository is private, and anyone who can read it was invited by
the owner and can reach the owner directly; the owner's contact is in their
GitHub profile. There is no bounty. No response-time promise or disclosure
deadline is established.

In scope are the log and its verifier (replay, checkpoints, cosignatures,
proofs, fork evidence and receipts); `nornd` enforcement in owner and watchdog
modes, including the grant bound on routes; trust-file parsing; enrollment
requests and signing tools (`norn sign`, `revoke`, `rotate` and `govern`); and
any divergence between the Go implementation and Python reference on a vector.

The out-of-scope items are the [explicit non-goals in
THREAT-MODEL.md §7](THREAT-MODEL.md#7-explicit-non-goals-repeated-from-planmd-so-this-file-stands-alone):

> Availability under A1/A2/A9 · stolen WG private key before revocation · colluding log + witness quorum · security of the `norn.trust` delivery channel · privacy of log contents (device names, enrollment times, key fingerprints are visible to anyone who can read the log) · traffic policy between authorized peers · internet-scale directories.

Vulnerabilities in WireGuard itself or in a coordinator should be reported
upstream.

A useful report includes the vector or input, which implementation you tested,
and the expected and observed refusal code. See
[`testdata/vectors/README.md`](testdata/vectors/README.md) for how the suite
expresses cases.
