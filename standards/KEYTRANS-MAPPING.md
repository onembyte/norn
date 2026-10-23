# Mapping Norn's authorization log onto Key Transparency

## Status and scope

This is a mapping study of how Norn's authorization log could be carried by Key Transparency and what that would, and would not, provide. It is not a proposal and changes nothing in Norn. Norn v1 keeps `tlog-tiles` transport and `tlog-witness` cosignatures (SPEC §§6, 9, 10).

The KEYTRANS side was checked against `draft-ietf-keytrans-protocol-05`, the July 2026 revision. The editor's-copy commits `cbadcdca` and `c6cce0d5`, dated 2026-10-21, are noted as verification context; BUILD-LOG.md's F5 entry records their fixes to update-response verification: one non-inclusion proof for version zero when no prior version exists, and tracking timestamps consumed by a combined proof. Norn's side is from SPEC.

## The mapping

Use one label per network. The label is Norn's 16-byte network id, which fits KEYTRANS's `opaque label<0..2^8-1>` (KEYTRANS §13.1; SPEC §2). Norn log index *i* maps to version *i* of that label. Genesis is version 0; versions are assigned sequentially in the order given (KEYTRANS §13.5).

`UpdateValue.value`, an `opaque<0..2^32-1>`, carries the signed CBOR entry, up to `MAX_ENTRY_BYTES` = 65,535 bytes (KEYTRANS §11.5; SPEC §4.0). A node fetches versions 0 through *N* with fixed-version searches (KEYTRANS §§7, 13.1), verifies each entry, replays the sequence under SPEC §5, and derives the proven peer set. After that, it fetches only versions after the last version it verified.

## What the mapping solves

One label gives the sequence a single total order across objects. The replay position answers which signer set was in effect when an enrollment landed, as it does in Norn today (SPEC §§4.2–4.4, 5).

The peer set comes from replaying the whole version sequence. A node can therefore evict any key absent from the derived set. Per-device labels behind a VRF would not let a node enumerate all labels and establish that completeness (KEYTRANS §§11.7, 13.1; SPEC §5).

## What differs

| Topic | KEYTRANS | Norn v1 | Consequence under the mapping |
|---|---|---|---|
| Authorization | Values are opaque to the protocol; applications supply their meaning (KEYTRANS §§11.5, 13.1). | Replay decides whether each entry is authorized and applies its state transition (SPEC §§4.2, 4.3, 5). | Norn's replay rules decide authorization, unchanged by the mapping. |
| Writers | Access control belongs to the application, outside the protocol (KEYTRANS §13.2); in Third-Party Management mode the Service Operator enforces it and authorizes every new version (KEYTRANS §15.1). An update is a compare-and-set on `greatest_version` (KEYTRANS §13.5). | Signatures in the log authorize every write (SPEC §§4.2, 4.3, 5). | The operator cannot forge an entry value, but gates every write and can censor it. Multiple signers' submissions are serialized by that operator. |
| Catch-up | A fixed-version search returns the requested value (KEYTRANS §13.1). An update response returns the versions created in one log entry, on the label owner's update path (KEYTRANS §13.5). | `tlog-tiles` serves entry bundles of up to 256 entries per request (SPEC §6). | A reader reconstructing the history makes one fixed-version search per version; bulk update responses do not provide a reader's history. |
| Witnessing | A tree head is signed by the log and has at most one `AuditorTreeHead`, only in Third-Party Auditing mode (KEYTRANS §§11.2, 11.4). Clients compare roots through an anonymous or peer channel to detect a split view (KEYTRANS §10.2). | Norn requires a k-of-N witness quorum under the trust file's policy (SPEC §§9, 10). | The mapping gives up Norn's witness quorum. Split-view resistance then depends on clients comparing heads out of band. |
| Retention | A maximum lifetime is optional; expired log entries may be pruned, and old prefix-tree versions need not be retained (KEYTRANS §7.1, Appendix D). | Replay starts from genesis and uses the ordered entries (SPEC §5). | A deployment carrying Norn this way must leave maximum lifetime undefined so the full version history remains available. |
| Privacy | KEYTRANS uses commitments and a VRF for label-version lookups (KEYTRANS §§11.6, 11.7). | Norn's public network id identifies the network (SPEC §2). | A single public label uses none of KEYTRANS's label-hiding mechanisms. |
| Authority named by an entry | A value is associated with its label and version; KEYTRANS does not define Norn's signer-set authorization (KEYTRANS §§11.5, 13.5). | Norn binds authority by position, `after` and `prev`, and an entry names no signer-set, root-set, `params`, policy or log-key version (SPEC §4.4, D-081). | Unchanged by the mapping: the value is the signed entry, and replay judges its authority where it lands. |

## Verification detail

An implementation of this mapping verifies search responses under KEYTRANS §13.1. Update-response verification is also subject to the editor's-copy changes of 2026-10-21, recorded in the F5 journal entry; those changes concern proof processing, and none of the mapping claims above depends on them.

Vector bounds. KEYTRANS writes its structures in the TLS presentation language (KEYTRANS §2.1), where a vector's bound counts bytes, not elements (RFC 8446 §3.4). Read that way, `UpdateRequest.values<0..2^8-1>` admits 255 bytes of encoded values in one update: one value of at most 251 bytes, less than the 533-byte genesis entry of Norn's vector log or the median of its 162 entries, 382 bytes. KEYTRANS §2.1 lets an implementation choose another encoding for transmission, so this limits a TLS-encoded update, not the mapping; whether the bound is meant as a count is a question for the draft.

## Conclusion

KEYTRANS with one label is a viable transport for Norn's entries: the entry format and replay rules carry over unchanged. It would cost Norn its witness quorum (KEYTRANS provides at most one auditor), native bulk catch-up, and an operator that gates writes. What it would add is label privacy, which a public roster does not use; its consistency proofs Norn already has from its tiles and checkpoints (KEYTRANS §§11.6, 11.7, 12; SPEC §§6, 10). Norn v1 keeps its transport. A KEYTRANS profile remains possible future work. The problem statement in this directory should say that the authorization layer, rather than the log, is what it adds.

## References

- “Key Transparency Protocol,” `draft-ietf-keytrans-protocol-05`, July 2026. Sections cited above; source text checked from the supplied draft.
- `ietf-wg-keytrans/draft-protocol`, editor's-copy commits `cbadcdca` and `c6cce0d5`, 2026-10-21.
- KEYTRANS list thread, 2026-10-18 to 2026-10-20: Felix Linker and Orie Steele.
- Norn, `SPEC.md`, version 1, §§2, 4.0, 4.2–4.4, 5, 6, 9, 10, 13.
