"""The canonical vector fixture: one valid entry per type (SPEC.md §12).

Kept separate from the generator script so tests can import the fixture without
writing files.
"""

from __future__ import annotations

import hashlib

from typing import Any

from nacl.bindings import crypto_core_ed25519_add, crypto_scalarmult_ed25519_base_noclamp

from . import entry, keys, note, trust

NET = bytes.fromhex("6e6f726e2d746573746e65742d303031")  # "norn-testnet-001"
T0 = 1_760_000_000

# §3.1 edges use public test material, never a second derivation of the keys.
ORDER_EIGHT = bytes.fromhex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05")
NONCANONICAL_POINT = bytes.fromhex("0100000000000000000000000000000000000000000000000000000000000080")

ROOTS = ["root1", "root2", "root3"]
SIGNERS = ["signer1", "signer2"]
DEVICES = ["nas", "laptop", "pi-cam"]

WITNESSES = ["pi", "vps", "friend"]

EXTRA_KEYS = (["signer3", "root4", "logkey", "logkey2", "spare", "printer", "nas-id2", "printer-id2", "escaped", "contractor", "halfsigned", "labelcap",
              "rootrevoked", "stranger", "astral", "sundial", "logkey3", "router", "badgrant"]
              + [f"witness-{w}" for w in WITNESSES])

KEYS: dict[str, keys.Ed25519] = {
    name: keys.Ed25519.from_name(name)
    for name in ROOTS + SIGNERS + DEVICES + EXTRA_KEYS
}
WG: dict[str, bytes] = {
    name: keys.x25519_public(name)
    for name in DEVICES + ["laptop2", "nas2", "spare", "printer", "rogue", "escaped", "contractor", "halfsigned", "labelcap", "rootrevoked", "astral", "sundial", "router", "badgrant"]
}

#: Every canonical-JSON escape rule (SPEC §14.2) in one value: the characters
#: that must be escaped, the ones that must NOT be (/ < > & DEL, non-ASCII),
#: and multi-byte UTF-8 including an astral-plane character.
ESCAPE_TORTURE = (
    'quote" backslash\\ slash/ lt< gt> amp& '
    'bs\b tab\t lf\n ff\f cr\r '
    'vt\x0b nul\x00 unit\x1f del\x7f '
    'ntilde-\u00f1 cjk-\u65e5\u672c emoji-\U0001f511 rtl-\u05d0\n'
    # Cold gate run 12, D19: §14.2 writes these verbatim, and Go's
    # encoding/json escapes them even with SetEscapeHTML(false). No vector
    # held either character, so a reader on a default JSON library produced
    # different state.json bytes and nothing could say so.
    'ls-\u2028 ps-\u2029 '
    'quorum home\n'
)

#: Label keys and values exercising recursive object-key sorting over UTF-8.
UNICODE_LABELS = {
    # D18a: these are opaque advisory hints at request validation and replay.
    # Keep malformed values in the accepted log so a reader that adds syntax
    # checks cannot silently diverge from the reference state.
    'ip': 'not-a-cidr',
    'endpoint': 'not-an-endpoint',
    's\u00edtio': 'Bah\u00eda Blanca',
    '\u8a18\u9332': '\u3066\u3059\u3068',
    'a<b&c': 'x>y',
}

ORIGIN = trust.origin_for(NET)
LOG_URLS = ["https://log.norn.example/testnet", "http://10.0.0.155:8099/norn"]
WITNESS_URLS = {
    "pi": "http://10.0.0.153:8100",
    "vps": "https://witness.example.net",
    "friend": "https://bastion.example.org/w",
}


def log_vkey() -> str:
    """The log's verifier key. Its note name is the origin (SPEC §2)."""
    return note.vkey(ORIGIN, KEYS["logkey"].public)


def witness_vkey(name: str) -> str:
    """A witness publishes a *cosignature* key (c2sp.org/tlog-cosignature).

    Algorithm 0x04, not 0x01: the byte is part of the key id, so the same key
    published as a note signer is a different verifier. Norn shipped the wrong
    one until 4.1a, which meant a trust file naming a real witness would have
    been rejected by its own validator.
    """
    return note.vkey(f"norn-witness/{name}", KEYS[f"witness-{name}"].public,
                     note.ALG_COSIGNATURE)


def policy_text() -> str:
    """Verbatim c2sp.org/tlog-policy: 2 of 3 witnesses in separate places."""
    lines = [f"log {log_vkey()} {LOG_URLS[0]}"]
    lines += [f"witness {w} {witness_vkey(w)} {WITNESS_URLS[w]}" for w in WITNESSES]
    lines += ["group home 2 " + " ".join(WITNESSES), "quorum home"]
    return "\n".join(lines) + "\n"


def trust_file() -> dict[str, Any]:
    """The trust anchor a node is provisioned with out of band (SPEC §9)."""
    genesis_hash = entry.leaf_hash(entry.encode(genesis()))
    return trust.build(
        net=NET,
        name="norn-testnet",
        genesis_hash=genesis_hash,
        log_key=log_vkey(),
        log_urls=LOG_URLS,
        witnesses=[{"name": w, "key": witness_vkey(w), "url": WITNESS_URLS[w]}
                   for w in WITNESSES],
        policy=policy_text(),
        anchor={"type": "opentimestamps", "max_lag": 86400, "mode": "advisory"},
    )


def _signed(env: dict[str, Any], signers: list[tuple[str, str]]) -> dict[str, Any]:
    for name, role in signers:
        entry.sign(env, KEYS[name], role)
    return env


def genesis(after: int | None = None) -> dict[str, Any]:
    env = entry.new("genesis", NET, ts=T0, after=after, body={
        "name": "norn-testnet",
        "roots": [KEYS[n].public for n in ROOTS],
        "root_thr": 2,
        "signers": [KEYS[n].public for n in SIGNERS],
        "signer_thr": 1,
        # `mmd` is deliberately NOT the §4.5 default: without one non-default
        # value here, a `params` entry that *replaces* rather than merges is
        # indistinguishable from one that merges (gate run 4, variant 9).
        #
        # And `checkpoint_interval` is deliberately ABSENT. §5.3 says the
        # genesis `params` is *overlaid* on the §4.5 defaults; while this body
        # set all four keys, overlay and replace reached the same state and
        # cold gate run 7's `genesis-params-replace` passed (J12). The value in
        # `state.json` now comes from the default and from nowhere else.
        "params": {"staleness": 600, "mmd": 45, "rotate_needs_signer": False},
    })
    return _signed(env, [("root1", "root"), ("root2", "root")])


def enroll(device: str, ts_offset: int, after: int | None = None,
           labels: dict[str, str] | None = None, expires: int | None = None,
           signers: list[tuple[str, str]] | None = None) -> dict[str, Any]:
    env = entry.new("enroll", NET, ts=T0 + ts_offset, after=after,
                    body=_enroll_body(device, labels=labels, expires=expires))
    return _signed(env, signers or [("signer1", "signer")])


def catalogue() -> list[tuple[str, dict[str, Any]]]:
    """One valid entry per type, in a plausible order. Names become file names."""
    out: list[tuple[str, dict[str, Any]]] = [
        ("00-genesis", genesis()),
        ("01-enroll", enroll("nas", 60, after=1)),
        ("02-enroll-labels", enroll("laptop", 120, after=2,
                                    labels={"ip": "10.9.0.2/32", "endpoint": "192.0.2.10:51820"})),
        ("03-enroll-expires", enroll("pi-cam", 180, after=3, expires=T0 + 2_592_000)),
        ("04-rotate", _signed(entry.new("rotate", NET, ts=T0 + 240, after=4, body={
            "device_id": "laptop", "wg_pk": WG["laptop2"]}), [("laptop", "device")])),
        ("05-revoke", _signed(entry.new("revoke", NET, ts=T0 + 300, after=5, body={
            "device_id": "pi-cam", "reason": "decommissioned"}), [("signer1", "signer")])),
        ("06-signer_add", _signed(entry.new("signer_add", NET, ts=T0 + 360, after=6, body={
            "pk": KEYS["signer3"].public}), [("root1", "root"), ("root2", "root")])),
        ("07-signer_thr", _signed(entry.new("signer_thr", NET, ts=T0 + 420, after=7, body={
            "thr": 2}), [("root1", "root"), ("root2", "root")])),
        ("08-signer_remove", _signed(entry.new("signer_remove", NET, ts=T0 + 480, after=8, body={
            "kid": KEYS["signer2"].id}), [("root1", "root"), ("root3", "root")])),
        ("09-root_add", _signed(entry.new("root_add", NET, ts=T0 + 540, after=9, body={
            "pk": KEYS["root4"].public}), [("root1", "root"), ("root2", "root")])),
        ("10-root_thr", _signed(entry.new("root_thr", NET, ts=T0 + 600, after=10, body={
            "thr": 3}), [("root1", "root"), ("root2", "root")])),
        ("11-root_remove", _signed(entry.new("root_remove", NET, ts=T0 + 660, after=11, body={
            "kid": KEYS["root4"].id}), [("root1", "root"), ("root2", "root"), ("root3", "root")])),
        ("12-log_key", _signed(entry.new("log_key", NET, ts=T0 + 720, after=12, body={
            "pk": KEYS["logkey2"].public, "overlap": 2_592_000}),
            [("root1", "root"), ("root2", "root"), ("root3", "root")])),
        ("13-policy", _signed(entry.new("policy", NET, ts=T0 + 780, after=13, body={
            "text": policy_text()}),
            [("root1", "root"), ("root2", "root"), ("root3", "root")])),
        ("14-params", _signed(entry.new("params", NET, ts=T0 + 840, after=14, body={
            "staleness": 900, "rotate_needs_signer": True}),
            [("root1", "root"), ("root2", "root"), ("root3", "root")])),
        ("15-note", _signed(entry.new("note", NET, ts=T0 + 900, after=15, body={
            "text": "quarterly key review completed"}), [("signer1", "signer")])),
    ]
    return out



# -- byte-level patches that violate exactly one encoding-profile rule --------

def _patch_nonshortest(raw: bytes) -> bytes:
    """Re-encode the `v` value 1 as 0x1801 instead of 0x01 (RFC 8949 §4.2.1)."""
    needle = cbor.encode("v") + cbor.encode(1)
    assert needle in raw, "v:1 not found"
    return raw.replace(needle, cbor.encode("v") + b"\x18\x01", 1)


def _patch_null(raw: bytes) -> bytes:
    """Replace the `after` value with CBOR null, which the profile forbids."""
    needle = cbor.encode("after") + cbor.encode(56)
    assert needle in raw, "after not found"
    return raw.replace(needle, cbor.encode("after") + b"\xf6", 1)


def _patch_unsorted(raw: bytes) -> bytes:
    """Swap the first two map entries so the keys are no longer in order."""
    head = raw[:1]
    first = cbor.encode("t") + cbor.encode("note")
    second = cbor.encode("v") + cbor.encode(1)
    assert raw[1:].startswith(first + second), "unexpected leading map order"
    rest = raw[1 + len(first) + len(second):]
    return head + second + first + rest

# -- the replay fixture log (SPEC §12) -----------------------------------

from collections import namedtuple  # noqa: E402  (kept next to its only user)

from . import cbor  # noqa: E402

LogItem = namedtuple("LogItem", "name raw reason")


def _first_rejected(builder: "_Builder") -> bytes:
    """Bytes of the first entry the log already rejected.

    Looked up rather than indexed by number: entry numbers shift whenever a
    vector is inserted earlier, and a stale index here would silently point at
    an *accepted* entry, turning a dup-entry vector into something else.
    """
    return next(item.raw for item in builder.items if item.reason)


def _first_undecodable(builder: "_Builder") -> bytes:
    """Bytes of the first entry that fails §5.1 *step 2* -- it does not decode.

    Distinct from `_first_rejected`, and the distinction is the whole point:
    step 1 records `entry_hash` before step 2 runs, so a copy of an entry that
    never decoded is still `dup-entry`. A copy of one that decoded and was
    rejected later cannot tell that reading from the other.
    """
    for item in builder.items:
        try:
            cbor.decode(item.raw)
        except cbor.ProfileError:
            return item.raw
    raise AssertionError(
        "no undecodable entry to copy: the seen-set timing would pin nothing")


class _Builder:
    """Accumulates a log, assigning each entry `after` = its own index.

    Every entry is appended with the reason it is expected to be rejected for,
    or None when it must take effect. That expectation is the test oracle.
    """

    def __init__(self) -> None:
        self.items: list[LogItem] = []

    @property
    def index(self) -> int:
        return len(self.items)

    def add(self, name: str, env: dict[str, Any], reason: str | None = None) -> None:
        self.items.append(LogItem(name, entry.encode(env), reason))

    def add_raw(self, name: str, raw: bytes, reason: str | None) -> None:
        self.items.append(LogItem(name, raw, reason))

    def build(self, kind: str, body: dict[str, Any], signers: list[tuple[str, str]],
              after: int | None = None, ts_offset: int | None = None) -> dict[str, Any]:
        env = entry.new(kind, NET, ts=T0 + (ts_offset if ts_offset is not None else self.index * 60),
                        after=self.index if after is None else after, body=body)
        return _signed(env, signers)


def _enroll_body(device: str, wg: str | None = None, signer: str | None = None,
                 labels: dict[str, str] | None = None, expires: int | None = None,
                 ts_offset: int = 0) -> dict[str, Any]:
    """An `enroll` body: the device's request, verbatim (SPEC §4.3).

    The device signs the *request*, never the envelope -- it is headless and
    one-way and never sees the envelope the signer builds. `signer` names a
    different key to sign the request with, which is how a forged-consent
    negative is built.
    """
    from . import enrollreq
    request = enrollreq.new(net=NET, device_id=device, device_pk=KEYS[device].public,
                            wg_pk=WG[wg or device], ts=T0 + ts_offset,
                            labels=labels or None, expires=expires)
    enrollreq.sign(request, KEYS[signer or device], strict=signer is None)
    return {"request": enrollreq.encode(request)}


def _raw_enroll_body(fields: dict[str, Any], signer: str) -> dict[str, Any]:
    """An enroll body whose request breaks a §16.1 field rule.

    `enrollreq.new` would refuse to build these, which is the point: they can
    only come from a hostile or broken device, and replay must reject them.
    """
    from . import enrollreq
    request = dict(fields)
    request["sig"] = KEYS[signer].sign(enrollreq.preimage(request))
    return {"request": cbor.encode(request)}


def log() -> list[LogItem]:
    """A 49-entry log: valid entries interleaved with one per reason code."""
    b = _Builder()
    b.add(f"{b.index}-genesis", genesis())

    b.add(f"{b.index}-enroll-nas", b.build("enroll", _enroll_body("nas"),
                                   [("signer1", "signer")]))
    b.add(f"{b.index}-enroll-laptop", b.build("enroll", _enroll_body(
        "laptop", labels={"ip": "10.9.0.2/32", "endpoint": "192.0.2.10:51820"}),
        [("signer1", "signer")]))
    b.add(f"{b.index}-enroll-pi-cam", b.build("enroll", _enroll_body("pi-cam", expires=T0 + 2_592_000),
                                      [("signer1", "signer")]))

    b.add(f"{b.index}-bad-dup-id", b.build("enroll", _enroll_body("nas", wg="nas2"),
                                   [("signer1", "signer")]), "dup-id")
    b.add(f"{b.index}-bad-dup-wg", b.build("enroll", _enroll_body("spare", wg="nas"),
                                   [("signer1", "signer")]), "dup-wg")
    b.add(f"{b.index}-bad-no-device-sig", b.build("enroll",
                                          _enroll_body("printer", signer="spare"),
                                          [("signer1", "signer")]), "no-device-sig")
    b.add(f"{b.index}-bad-threshold", b.build("enroll", _enroll_body("printer"),
                                      [("printer", "device")]), "threshold")

    b.add(f"{b.index}-rotate-laptop", b.build("rotate", {"device_id": "laptop", "wg_pk": WG["laptop2"]},
                                      [("laptop", "device")]))
    b.add(f"{b.index}-bad-unknown-device", b.build("rotate", {"device_id": "ghost", "wg_pk": WG["rogue"]},
                                           [("nas", "device")]), "unknown-device")
    b.add(f"{b.index}-bad-after", b.build("note", {"text": "signed against a future log size"},
                                  [("signer1", "signer")], after=999), "after")

    b.add(f"{b.index}-revoke-pi-cam", b.build("revoke", {"device_id": "pi-cam", "reason": "decommissioned"},
                                      [("signer1", "signer")]))
    b.add(f"{b.index}-bad-not-active", b.build("revoke", {"device_id": "pi-cam", "reason": "again"},
                                       [("signer1", "signer")]), "not-active")
    b.add_raw(f"{b.index}-bad-dup-entry", b.items[1].raw, "dup-entry")
    b.add(f"{b.index}-bad-dup-genesis", genesis(after=14), "dup-genesis")

    bogus = {"v": entry.VERSION, "t": "bogus", "net": NET, "ts": T0, "after": b.index,
             "body": {"text": "not a real type"}, "sigs": []}
    entry.sign(bogus, KEYS["signer1"], "signer")
    b.add_raw(f"{b.index}-bad-unknown-type", cbor.encode(bogus), "unknown-type")

    b.add(f"{b.index}-signer_add-signer3", b.build("signer_add", {"pk": KEYS["signer3"].public},
                                           [("root1", "root"), ("root2", "root")]))
    b.add(f"{b.index}-bad-dup-key", b.build("signer_add", {"pk": KEYS["signer3"].public},
                                    [("root1", "root"), ("root2", "root")]), "dup-key")
    b.add(f"{b.index}-signer_thr-2", b.build("signer_thr", {"thr": 2},
                                     [("root1", "root"), ("root2", "root")]))
    b.add(f"{b.index}-bad-thr", b.build("signer_thr", {"thr": 99},
                                [("root1", "root"), ("root2", "root")]), "bad-thr")
    b.add(f"{b.index}-bad-unknown-key", b.build("signer_remove", {"kid": KEYS["root4"].id},
                                        [("root1", "root"), ("root2", "root")]), "unknown-key")
    b.add(f"{b.index}-signer_remove-signer2", b.build("signer_remove", {"kid": KEYS["signer2"].id},
                                              [("root1", "root"), ("root3", "root")]))

    b.add(f"{b.index}-root_add-root4", b.build("root_add", {"pk": KEYS["root4"].public},
                                       [("root1", "root"), ("root2", "root")]))
    b.add(f"{b.index}-root_thr-3", b.build("root_thr", {"thr": 3},
                                   [("root1", "root"), ("root2", "root")]))
    roots3 = [("root1", "root"), ("root2", "root"), ("root3", "root")]
    b.add(f"{b.index}-root_remove-root4", b.build("root_remove", {"kid": KEYS["root4"].id}, roots3))
    b.add(f"{b.index}-bad-root-invariant", b.build("root_remove", {"kid": KEYS["root3"].id}, roots3),
          "root-invariant")
    b.add(f"{b.index}-bad-threshold-root", b.build("signer_add", {"pk": KEYS["root4"].public},
                                           [("root1", "root")]), "threshold")

    b.add(f"{b.index}-log_key", b.build("log_key", {"pk": KEYS["logkey2"].public, "overlap": 2_592_000},
                                roots3))
    b.add(f"{b.index}-policy", b.build("policy", {"text": policy_text()}, roots3))
    b.add(f"{b.index}-params", b.build("params", {"staleness": 900, "rotate_needs_signer": True}, roots3))

    both = [("signer1", "signer"), ("signer3", "signer")]
    b.add(f"{b.index}-note", b.build("note", {"text": "quarterly key review completed"},
                             [("signer1", "signer")]))
    b.add(f"{b.index}-enroll-printer", b.build("enroll", _enroll_body("printer"),
                                       both))

    wrong_net = entry.new("note", b"\xff" * 16, ts=T0, after=32, body={"text": "wrong network"})
    entry.sign(wrong_net, KEYS["signer1"], "signer")
    b.add_raw(f"{b.index}-bad-decode-net", entry.encode(wrong_net), "decode")

    b.add(f"{b.index}-enroll-pi-cam-again", b.build("enroll", _enroll_body("pi-cam"),
                                            both))
    b.add(f"{b.index}-bad-rotate-needs-signer", b.build("rotate", {"device_id": "nas", "wg_pk": WG["nas2"]},
                                                [("nas", "device")]), "threshold")
    b.add(f"{b.index}-rotate-nas", b.build("rotate", {"device_id": "nas", "wg_pk": WG["nas2"]},
                                   [("nas", "device")] + both))
    b.add(f"{b.index}-revoke-self-laptop", b.build("revoke", {"device_id": "laptop", "reason": "lost"},
                                           [("laptop", "device")]))
    b.add(f"{b.index}-enroll-spare", b.build("enroll", _enroll_body("spare"),
                                     both))
    b.add(f"{b.index}-note-final", b.build("note", {"text": "end of fixture"}, [("root1", "root")]))
    b.add(f"{b.index}-revoke-spare", b.build("revoke", {"device_id": "spare", "reason": "returned"},
                                     [("signer1", "signer"), ("signer3", "signer")]))

    # D8: a device may rotate its identity key while keeping its WireGuard key
    # (otherwise software-key -> hardware-key migration would churn every peer
    # table), but may never take a key active for another device.
    b.add(f"{b.index}-rotate-device-key-only", b.build("rotate", {
        "device_id": "nas", "wg_pk": WG["nas2"], "device_pk": KEYS["nas-id2"].public},
        [("nas", "device"), ("nas-id2", "device")] + both))
    b.add(f"{b.index}-bad-dup-wg-rotate", b.build("rotate", {
        "device_id": "printer", "wg_pk": WG["nas2"]},
        [("printer", "device")] + both), "dup-wg")

    # Tier-3 answers, each previously undecided by the prose *and* the vectors.
    b.add(f"{b.index}-bad-thr-root", b.build("root_thr", {"thr": 99}, roots3), "bad-thr")       # D11
    b.add(f"{b.index}-bad-revoke-unauthorised", b.build(                                        # D12
        "revoke", {"device_id": "printer", "reason": "no authority"},
        [("laptop", "device")]), "threshold")
    unknown_role = {"v": entry.VERSION, "t": "note", "net": NET, "ts": T0 + 9000,
                    "after": b.index, "body": {"text": "role outside the enum"}, "sigs": []}
    entry.sign(unknown_role, KEYS["signer1"], "signer")
    unknown_role["sigs"][0]["role"] = "admin"
    b.add_raw(f"{b.index}-bad-unknown-role", cbor.encode(unknown_role), "decode")               # D18
    b.add_raw(f"{b.index}-bad-missing-sigs", cbor.encode({                                      # D19
        "v": entry.VERSION, "t": "note", "net": NET, "ts": T0 + 9000, "after": b.index,
        "body": {"text": "no sigs key at all"}}), "decode")
    # D20, and D-032: the *current* device key signs, so replay gets past the
    # current-key check and reaches the proof-of-possession rule on the
    # incoming `device_pk`, which nothing signs. Carrying no device signature
    # at all -- as this vector did until 6.5c -- is refused three checks
    # earlier and leaves D-032 untested, which is how gate run 5 deleted the
    # check outright and still passed every vector.
    b.add(f"{b.index}-bad-rotate-no-new-key-sig", b.build(
        "rotate", {"device_id": "printer", "wg_pk": WG["printer"],
                   "device_pk": KEYS["printer-id2"].public},
        [("printer", "device")] + both), "no-device-sig")
    b.add(f"{b.index}-bad-order-enroll", b.build(                                               # D21
        "enroll", _enroll_body("nas", wg="rogue", signer="signer1"),
        both), "no-device-sig")
    b.add(f"{b.index}-bad-order-governance", b.build(                                           # D21
        "signer_add", {"pk": KEYS["signer3"].public}, [("root1", "root")]), "threshold")

    # Canonical-JSON escaping (SPEC §14.2). Every escape rule in one value, so a
    # second implementation cannot pass while disagreeing about `<`, DEL or an
    # emoji -- none of which appear anywhere else in the suite.
    # A real policy, because §5.1 now requires a `policy` entry to be one. The
    # canonical-JSON escape torture moved to a label value below, where free
    # text belongs and where it still reaches `state.json`.
    rotated = policy_text().replace("group home 2 ", "group home 3 ")
    b.add(f"{b.index}-policy-rotated", b.build("policy", {"text": rotated}, roots3))
    # ...and the refusal that rule needs.
    b.add(f"{b.index}-bad-policy-unparseable", b.build(
        "policy", {"text": ESCAPE_TORTURE}, roots3), "decode")
    b.add(f"{b.index}-enroll-unicode-labels", b.build("enroll", _enroll_body(
        "escaped", labels=UNICODE_LABELS), both))

    # §5.3's `expires` rule needs a device that actually carries one.
    b.add(f"{b.index}-enroll-contractor", b.build("enroll", _enroll_body(
        "contractor", expires=T0 + 7_776_000),
        both))

    # E5: `sigs: []` is well-formed but unauthorised -- `threshold`, not `decode`.
    b.add_raw(f"{b.index}-bad-empty-sigs", cbor.encode({
        "v": entry.VERSION, "t": "note", "net": NET, "ts": T0 + 9000,
        "after": b.index, "body": {"text": "well-formed, unsigned"}, "sigs": []}), "threshold")

    # H4: the other shape of `sigs: []`. The envelope carries no signature and
    # the embedded request still carries the device's own, so §5.1's enroll
    # order passes the device-signature check and fails the signer count. §4.0
    # claimed `no-device-sig` for this until cold gate run 6 built the case the
    # suite lacked -- and reason codes are consensus state (§5.3), so one wrong
    # sentence split `state.json` on identical log bytes.
    unsigned_enroll = entry.new("enroll", NET, ts=T0 + 9000, after=b.index,
                                body=_enroll_body("halfsigned"))
    unsigned_enroll["sigs"] = []
    b.add_raw(f"{b.index}-bad-enroll-empty-sigs", cbor.encode(unsigned_enroll), "threshold")

    # Cold gate run 6: five rules the prose pins and no vector did. Each was a
    # variant that passed every check, and each splits `state.rejected`.

    # §4.4's floor is `after > index`. The fixture's values were 999, 5091 and
    # 5 at indices 10, 91 and 75 -- never at or beside the boundary -- so
    # rejecting only above `index + 1` passed everything.
    b.add(f"{b.index}-after-at-its-own-index", b.build(
        "note", {"text": "after equals this entry's own index"}, [("signer1", "signer")],
        after=b.index))
    b.add(f"{b.index}-bad-after-by-one", b.build(
        "note", {"text": "after is one past this entry's index"}, [("signer1", "signer")],
        after=b.index + 1), "after")

    # §5.1: an enroll's request `net` must equal the entry's. The only net
    # negative patched the *envelope*, so skipping this check passed.
    other_net = bytes(16)
    foreign = enrollreq_new_with_net(other_net, "halfsigned")
    b.add(f"{b.index}-bad-request-net", b.build(
        "enroll", {"request": foreign}, both), "decode")

    # §5.1's enroll order: `dup-id` decides before `dup-wg`. Wrong in both ways
    # -- an active device_id, and a WireGuard key active for another device.
    b.add(f"{b.index}-bad-dup-id-and-wg", b.build(
        "enroll", _enroll_body("nas", wg="printer"), both), "dup-id")

    # §5.2: a `device` signature's `kid` must resolve, not merely verify. The
    # preimage excludes `sigs` entirely, so rewriting a `kid` leaves the
    # signature intact and a reader that searches for any key that verifies
    # accepts it.
    wrong_kid = b.build("rotate", {"device_id": "printer", "wg_pk": WG["printer"]},
                        [("printer", "device")] + both)
    for sig in wrong_kid["sigs"]:
        if sig["role"] == "device":
            sig["kid"] = keys.kid(KEYS["stranger"].public)
    wrong_kid["sigs"].sort(key=lambda x: x["kid"])
    b.add_raw(f"{b.index}-bad-device-sig-wrong-kid", cbor.encode(wrong_kid), "no-device-sig")

    # H6: the same governance entry, with one byte after it. Every signature
    # still verifies -- a preimage covers the decoded envelope, not the raw
    # bytes -- and the `entry_hash` differs, so `dup-entry` does not fire. A
    # decoder that reads one item and stops applies this twice, which run 6
    # used to grow `state.log_keys` from two to three.
    doubled = _entry_raw(b, "log_key") + b"\x00"
    b.add_raw(f"{b.index}-bad-trailing-byte", doubled, "decode")

    # E6: a malformed `kid` is a schema violation, not an unresolvable key.
    bad_kid = entry.new("note", NET, ts=T0 + 9000, after=53, body={"text": "bad kid"})
    entry.sign(bad_kid, KEYS["signer1"], "signer")
    bad_kid["sigs"][0]["kid"] = "NOTHEX"
    b.add_raw(f"{b.index}-bad-kid-format", cbor.encode(bad_kid), "decode")

    # E9: defends D-028. This leaves ONE signer while `signer_thr` is 2 -- the
    # network cannot enrol until roots add a signer, and that is the point:
    # removing a compromised signer key must never be blocked. Placed last so it
    # does not starve earlier entries of signatures.
    b.add(f"{b.index}-signer_remove-below-threshold",
          b.build("signer_remove", {"kid": KEYS["signer3"].id}, roots3))
    # ...and the recovery roots must then perform, which is the other half of
    # the D-028 argument: the degraded state is real but recoverable. Re-adding
    # the same key keeps the fixture's terminal state usable; a real recovery
    # would add a replacement key.
    b.add(f"{b.index}-signer_add-recover",
          b.build("signer_add", {"pk": KEYS["signer3"].public}, roots3))

    # E12: the encoding profile had no negative vectors at all, so a decoder
    # that skipped every profile check scored a clean pass. Each of these is a
    # valid entry patched at the byte level to violate exactly one rule.
    base = entry.encode(_signed(entry.new(
        "note", NET, ts=T0 + 9000, after=56, body={"text": "profile probe"}),
        [("signer1", "signer")]))
    b.add_raw(f"{b.index}-bad-cbor-nonshortest", _patch_nonshortest(base), "decode")
    b.add_raw(f"{b.index}-bad-cbor-null", _patch_null(base), "decode")
    b.add_raw(f"{b.index}-bad-cbor-unsorted-keys", _patch_unsorted(base), "decode")

    # Closed schemas, envelope and body (SPEC §4.1/§4.3). Run 3 shipped a
    # variant leaving bodies open and passed the whole suite -- as did this
    # implementation at the time. Two implementations agreeing by accident is
    # not a pinned rule.
    unknown_env = entry.new("note", NET, ts=T0 + 9000, after=59, body={"text": "x"})
    entry.sign(unknown_env, KEYS["signer1"], "signer")
    unknown_env["extra"] = 1
    b.add_raw(f"{b.index}-bad-unknown-envelope-key", cbor.encode(unknown_env), "decode")
    b.add(f"{b.index}-bad-unknown-body-key", b.build(
        "note", {"text": "x", "surprise": "extra"}, [("signer1", "signer")]), "decode")

    # `thr: 0` -- the half of §5.2's bad-thr clause both other vectors miss,
    # since they use 99. A well-formed uint, so it is bad-thr and not decode.
    b.add(f"{b.index}-bad-thr-zero", b.build("signer_thr", {"thr": 0}, roots3), "bad-thr")

    # A control: the exact entry each encoding negative is a patch of. Without
    # it a reader cannot tell whether a negative is rejected for its one
    # deliberate fault or for something incidental.
    base_after = b.index
    b.add_raw(f"{b.index}-profile-base", profile_base(base_after), None)
    for name, raw in profile_negatives(base_after):
        b.add_raw(f"{b.index}-bad-{name}", raw, "decode")
    for name, raw in field_negatives():
        b.add_raw(f"{b.index}-bad-{name}", raw, "decode")

    # §4.4: `after` is a floor, not an equality. Every other `after` in this
    # fixture equals its own index, so a variant demanding equality passed.
    b.add(f"{b.index}-after-below-index", b.build(
        "note", {"text": "signed long ago, submitted late"},
        [("signer1", "signer")], after=5))

    # §5.1 step 1: the seen set records an entry "whether or not it is later
    # rejected" (D-031). This repeats entry 67, which was itself rejected.
    b.add_raw(f"{b.index}-bad-repeat-of-rejected", _first_rejected(b), "dup-entry")

    # A signer count strictly between zero and the threshold. The other
    # `threshold` negatives all carry zero valid signer signatures.
    b.add(f"{b.index}-bad-one-of-two-signers", b.build("enroll", _enroll_body(
        "halfsigned", wg="rogue"),
        [("signer1", "signer")]), "threshold")

    # §4.3: a key counts only for the role it currently holds. This is a valid
    # signature by a signer key that declares itself `root`.
    mismatch = entry.new("note", NET, ts=T0 + 9000, after=75,
                         body={"text": "signer key claiming root"})
    entry.sign(mismatch, KEYS["signer1"], "root")
    b.add_raw(f"{b.index}-bad-role-mismatch", entry.encode(mismatch), "threshold")

    # Controls for the last two encoding negatives, which patch a different
    # base than `profile_base`: a label key exactly at the 23-byte cap, and an
    # entry with two signatures in the correct kid order.
    b.add_raw(f"{b.index}-labelcap-base", labelled_base(base_after), None)
    b.add_raw(f"{b.index}-two-sig-base", two_sig_base(base_after), None)

    # §5.3: `log_key` APPENDS. With only one rotation in the log, an
    # implementation that keeps just the latest is indistinguishable.
    #
    # And a THIRD key rather than the anchor's own. This republished
    # `KEYS["logkey"]` -- the trust file's key -- so a reader that *replaced*
    # `log_keys` instead of keeping the anchor's key alongside it (§9.4) still
    # ended up holding it, and `log-keys-replace-trust-key` passed the whole
    # suite (cold gate run 8, D11). Now neither published key is the anchor's,
    # so only a reader that keeps both can read `served/checkpoint`.
    b.add(f"{b.index}-log_key-second", b.build(
        "log_key", {"pk": KEYS["logkey3"].public, "overlap": 604_800}, roots3))

    # §4.3: a `note` needs a signer or a root; a device signature will not do.
    b.add(f"{b.index}-bad-device-signed-note", b.build(
        "note", {"text": "signed by a device"}, [("nas-id2", "device")]), "threshold")

    # §4.3 lists roots as an authorisation path for `revoke`; none used it.
    b.add(f"{b.index}-enroll-rootrevoked", b.build("enroll", _enroll_body(
        "rootrevoked", wg="rootrevoked"),
        both))
    b.add(f"{b.index}-revoke-by-roots", b.build(
        "revoke", {"device_id": "rootrevoked", "reason": "root quorum"}, roots3))

    # §5.1: step 7 precedes step 8, so an under-signed governance entry with a
    # malformed body is `threshold` and never reaches the body check.
    b.add(f"{b.index}-bad-undersigned-malformed", b.build(
        "signer_thr", {"thr": 2, "surprise": "extra"}, [("root1", "root")]), "threshold")

    # A signer that was REMOVED earlier must be inert. Nothing tested this,
    # which means nothing tested the point of `signer_remove`: signer2 is
    # removed at entry 21, and this note is signed by it alone. The Phase 1
    # gate names this case explicitly.
    b.add(f"{b.index}-bad-removed-signer", b.build(
        "note", {"text": "signed by a removed signer"},
        [("signer2", "signer")]), "threshold")

    # ...and a key that was never in the set at all.
    b.add(f"{b.index}-bad-stranger-signer", b.build(
        "note", {"text": "signed by a stranger"},
        [("stranger", "signer")]), "threshold")

    # A signature that is syntactically perfect and cryptographically wrong.
    # Without these an implementation that never calls Ed25519 reproduces the
    # entire manifest (gate run 4 proved it).
    for name, raw in forged_signature_negatives(b.index):
        reason = "no-device-sig" if "device" in name else "threshold"
        b.add_raw(f"{b.index}-bad-{name}", raw, reason)

    # §5.1 calls its order normative and rests that claim on vectors that are
    # "simultaneously wrong in more than one way". For four of its precedence
    # pairs no such vector existed, so cold gate run 5 swapped each order in
    # turn and still reproduced the whole manifest. Each entry below is wrong
    # in exactly two ways; only the earlier step's code may appear.

    # Step 3 (envelope closedness) precedes step 4 (`unknown-type`).
    unknown_and_open = {
        "v": entry.VERSION, "t": "teleport", "net": NET,
        "ts": T0 + b.index * 60, "after": b.index,
        "body": {"text": "neither a known type nor a closed envelope"},
        "sigs": [], "surprise": "an unpermitted envelope key"}
    b.add_raw(f"{b.index}-bad-precedence-decode-before-unknown-type",
              cbor.encode(unknown_and_open), "decode")

    # Step 3 (the envelope schema) precedes step 6 (`after`). A reader that
    # decodes leniently, reads `after` and applies the schema afterwards is
    # what run 10's V213 models, and nothing separated it: no entry was
    # malformed in the envelope AND out of order at the same time. This one is
    # both, and only `decode` may appear.
    open_and_late = {
        "v": entry.VERSION, "t": "note", "net": NET,
        "ts": T0 + b.index * 60, "after": b.index + 5000,
        "body": {"text": "an unpermitted envelope key, and from the future"},
        "sigs": [], "surprise": "an unpermitted envelope key"}
    b.add_raw(f"{b.index}-bad-precedence-decode-before-after",
              cbor.encode(open_and_late), "decode")

    # Step 6 (`after`) precedes step 7 (the signature count).
    b.add(f"{b.index}-bad-precedence-after-before-threshold", b.build(
        "note", {"text": "from the future, and unsigned"}, [],
        after=b.index + 5000), "after")

    # `enroll`: the signer count precedes `dup-id`. `nas` is active, and one
    # signer is below `signer_thr` = 2.
    b.add(f"{b.index}-bad-precedence-threshold-before-dup-id", b.build(
        "enroll", _enroll_body("nas"), [("signer1", "signer")]), "threshold")

    # `rotate`: with `rotate_needs_signer` on, the signer count precedes
    # `dup-wg`. `printer` is active and signs with its current key; the new
    # WireGuard key belongs to `nas`.
    # `nas` rotated to `nas2` at entry 35, so `WG["nas"]` is not active and
    # using it would leave this entry wrong in only one way.
    b.add(f"{b.index}-bad-precedence-threshold-before-dup-wg", b.build(
        "rotate", {"device_id": "printer", "wg_pk": WG["nas2"]},
        [("printer", "device"), ("signer1", "signer")]), "threshold")

    # §4.3 gives `revoke` three *independent* authorisations. One signer (of
    # two) and two roots (of three) is short on every one of them, and reaches
    # a quorum only if the three counts are pooled into one -- the reading the
    # suite could not rule out until this entry existed.
    b.add(f"{b.index}-bad-revoke-neither-quorum", b.build(
        "revoke", {"device_id": "escaped", "reason": "short on every count"},
        [("signer1", "signer"), ("root1", "root"), ("root2", "root")]), "threshold")

    # §5.1's `params` rule requires a non-empty body. Stated, never refused.
    b.add(f"{b.index}-bad-params-empty", b.build("params", {}, roots3), "decode")

    # §14.1 sorts object keys bytewise over the **UTF-8** encoding. Until this
    # entry, no key in the suite lay outside the basic multilingual plane, so
    # UTF-16 code-unit order -- what a JavaScript implementation gets for free
    # -- agreed everywhere. The two disagree only across U+E000: an astral
    # character is a surrogate pair beginning 0xD800 in UTF-16, below U+E000,
    # and begins 0xF0 in UTF-8, above it.
    b.add(f"{b.index}-enroll-astral-labels", b.build(
        "enroll", _enroll_body("astral", labels={"\ue000": "private use",
                                                 "\U0001f512": "astral",
                                                 "escapes": ESCAPE_TORTURE}),
        both))

    # --- Cold gate run 7: five rules the prose states and no vector reached.

    # §5.1's `params` rule is "non-empty, only §4.5 keys, each of the right
    # type" and only the first third was ever refused: the suite's one
    # unknown-body-key negative is a *note*, so `allow-unknown-param` and
    # `params-loose-type` both reproduced the whole manifest. This is the
    # widest divergence in the machine -- the two readings end with a
    # different `staleness`, and so with a different freshness verdict.
    b.add(f"{b.index}-bad-params-unknown-key", b.build(
        "params", {"staleness": 900, "mtu": 1420}, roots3), "decode")
    # A bool where a uint belongs. CBOR `true` is one byte and every loose
    # decoder turns it into 1 -- Python's own `isinstance(True, int)` says yes,
    # which is how the reference implementation accepted this until now.
    b.add(f"{b.index}-bad-params-wrong-type", b.build(
        "params", {"staleness": True}, roots3), "decode")

    # §5.1's `enroll` table: the request's signature is checked *before* the
    # signer count. §4.0 explains the consequence twice -- "an unsigned
    # `enroll` is `threshold` and not `no-device-sig`, because the embedded
    # request is still signed by the device" -- and the vector it names has a
    # valid request signature, so it cannot tell the two orders apart. This is
    # the other half: the request is *not* signed by the device, and the entry
    # carries no signers either.
    unconsented = entry.new("enroll", NET, ts=T0 + b.index * 60, after=b.index,
                            body=_enroll_body("halfsigned", signer="signer1"))
    unconsented["sigs"] = []
    b.add_raw(f"{b.index}-bad-enroll-unsigned-request-no-signers",
              cbor.encode(unconsented), "no-device-sig")

    # ...and the check before that one: the request's `net` decides before its
    # signature does.
    b.add(f"{b.index}-bad-enroll-request-net-and-sig", b.build(
        "enroll", {"request": enrollreq_new_with_net(bytes(16), "halfsigned",
                                                     signer="signer1")},
        both), "decode")

    # §5.1's `rotate` table: `dup-wg` decides before the proof of possession on
    # the incoming `device_pk`. `printer` is active and signs with its current
    # key, so every earlier check passes; `WG["nas2"]` belongs to `nas`; and
    # nothing signs for `printer-id2`.
    b.add(f"{b.index}-bad-rotate-dupwg-and-no-new-key-sig", b.build(
        "rotate", {"device_id": "printer", "wg_pk": WG["nas2"],
                   "device_pk": KEYS["printer-id2"].public},
        [("printer", "device")] + both), "dup-wg")

    # §5.1 step 1 records `entry_hash` *before* step 2 decodes, and records
    # entry 0's too. Neither property was exercised: the suite's repeat was of
    # an entry that decodes cleanly, and its `dup-entry` copy was of entry 1.
    b.add_raw(f"{b.index}-bad-repeat-of-undecodable",
              _first_undecodable(b), "dup-entry")
    b.add_raw(f"{b.index}-bad-repeat-of-genesis", b.items[0].raw, "dup-entry")

    # D-070 (audit SEC-001): a duplicate is a repeated *signed content*, not a
    # repeated byte string. `sigs` lies outside every signature, so a past
    # entry with one unresolvable signature added, a surplus one dropped or a
    # role relabelled is new bytes whose original signatures still count --
    # and keyed on bytes it applied again: `enroll-spare` re-enrolled a device
    # revoked two entries later, `policy` rolled the quorum back from three of
    # three to two of three, `rotate-nas` and `signer_add-signer3` each undid
    # a later entry. Every copy is `dup-entry`, at step 1, before any rule
    # that would otherwise judge it.
    by_name = {item.name: item.raw for item in b.items}
    for name in ("enroll-spare", "policy", "rotate-nas", "signer_add-signer3"):
        original = next(raw for label, raw in by_name.items() if label.endswith("-" + name))
        b.add_raw(f"{b.index}-bad-copy-{name}-extra-sig",
                  _copy_with_extra_signature(original), "dup-entry")
    original = next(raw for label, raw in by_name.items() if label.endswith("-enroll-spare"))
    b.add_raw(f"{b.index}-bad-copy-enroll-spare-role-relabelled",
              _copy_with_role_relabelled(original), "dup-entry")
    original = next(raw for label, raw in by_name.items() if label.endswith("-two-sig-base"))
    b.add_raw(f"{b.index}-bad-copy-two-sig-base-surplus-dropped",
              _copy_with_surplus_dropped(original), "dup-entry")

    # SEC-010: a rejected `params` entry changes nothing. `mmd` is valid and
    # sorts first; `staleness` is a bool where a uint belongs. A handler that
    # writes as it validates has changed `mmd` by the time it rejects.
    b.add(f"{b.index}-bad-params-mixed-validity",
          b.build("params", {"mmd": 60, "staleness": True}, roots3), "decode")

    # --- J12's tail: rules some *other* rule happened to refuse first.

    # §4.0 bounds a `kid` in a `signer_remove`/`root_remove` **body** to
    # `^[0-9a-f]{16}$`, and says why the distinction matters: a malformed kid
    # is `decode`, one that merely fails to resolve is `unknown-key`. The only
    # kid-format negative put the bad kid in `sigs`, so the body half was
    # explained and never exercised.
    b.add(f"{b.index}-bad-kid-format-in-body", b.build(
        "signer_remove", {"kid": "NOT-A-KID-AT-ALL"}, roots3), "decode")

    # §5.2: a signature counts only if its `kid` names a key the entry may be
    # signed by *in that role*. `bad-role-mismatch` pins the root/signer
    # direction; this is the device one. `printer` really did sign -- under
    # role `signer`, where its key resolves to nothing -- so the entry is not
    # merely unsigned, and `device-sig-any-role` is the only reading that
    # accepts it.
    b.add(f"{b.index}-bad-device-sig-wrong-role", b.build(
        "rotate", {"device_id": "printer", "wg_pk": WG["printer"]},
        [("printer", "signer")] + both), "no-device-sig")

    # §4.0 caps `revoke`'s `reason` at 256 bytes. `bad-text-too-long` covers
    # `note` and `policy`, whose cap is 4096 and a different rule -- so this
    # one was stated, and the Python reference did not implement it at all.
    # Cold gate run 11, D6. This was 257 ASCII bytes -- over the cap in bytes
    # AND in characters, so a reader counting runes refused it too and nothing
    # separated the two readings. `reason` is the clearest case of the four:
    # free-form human text, where 256 bytes is about 85 CJK characters, so a
    # revocation written in any non-Latin script is `decode` for one reader and
    # accepted by the other -- and the two then disagree about whether the
    # device is revoked at all. 128 two-byte characters and one ASCII byte is
    # 257 bytes and 129 characters: over the cap one way and well under it
    # the other. §12.1 records the same fix for the map-key cap in run 9.
    # Cold gate run 12, D16: this was 258 bytes, so a cap of 257 refused it
    # too -- the boundary was never pinned. 257 is one byte past it.
    b.add(f"{b.index}-bad-revoke-reason-too-long", b.build(
        "revoke", {"device_id": "nas", "reason": "é" * 128 + "a"}, roots3), "decode")

    # §4.3 deliberately does NOT constrain the embedded request's `ts` against
    # the entry's: the device is headless and its clock is advisory (§4.1).
    # Every request in the fixture was older than the entry carrying it, so a
    # reader who added the obvious `request.ts <= entry.ts` check diverged and
    # nothing could say so. This entry is a *positive* one.
    b.add(f"{b.index}-enroll-request-from-the-future", b.build(
        "enroll", _enroll_body("sundial", ts_offset=10 * 86400), both))

    # Cold gate run 8, D26. §4.0 bounds `text` at "≤ 4096" and `reason` at
    # "0-256", and §4.3 marks `reason` OPTIONAL -- so an empty one of each, and
    # an absent `reason`, are all legal. Every `note` and `revoke` in the
    # fixture carried a non-empty string, so `text-min-one-byte`,
    # `reason-min-one-byte` and `revoke-reason-required` all passed: three
    # readings that reject entries this document accepts. Positives, because a
    # lower bound nobody wrote is only visible in what is *accepted*.
    b.add(f"{b.index}-note-empty-text", b.build(
        "note", {"text": ""}, [("signer1", "signer")]))
    b.add(f"{b.index}-revoke-empty-reason", b.build(
        "revoke", {"device_id": "escaped", "reason": ""}, roots3))
    b.add(f"{b.index}-revoke-no-reason", b.build(
        "revoke", {"device_id": "sundial"}, roots3))

    # §4.1's `sigs` elements are a closed map of `kid`, `role`, `sig`. Stated,
    # and no entry ever carried a fourth key: `sigs-allow-fourth-key` passed.
    fourth = b.build("note", {"text": "a fourth key in a signature"},
                     [("signer1", "signer")])
    fourth["sigs"][0]["extra"] = "an unpermitted signature key"
    b.add_raw(f"{b.index}-bad-sigs-fourth-key", cbor.encode(fourth), "decode")

    # §4.1: `v` MUST be 1. No entry in the suite had any other value, so a
    # reader that never looked at `v` reproduced the whole manifest.
    wrong_v = b.build("note", {"text": "version two"}, [("signer1", "signer")])
    wrong_v["v"] = 2
    b.add_raw(f"{b.index}-bad-version-two", cbor.encode(wrong_v), "decode")

    # §5.1's `rotate` rule: `not-active` for a device that is known and
    # revoked. The only `not-active` vector is a *revoke*, so
    # `rotate-revoked-is-unknown` -- reporting `unknown-device` instead --
    # passed. `laptop` was revoked at entry 36 and is still known.
    b.add(f"{b.index}-bad-rotate-revoked", b.build(
        "rotate", {"device_id": "laptop", "wg_pk": WG["laptop2"]},
        [("laptop", "device")] + both), "not-active")

    # §5.1: `dup-key` is "already a root **or** a signer". Every dup-key vector
    # added a key back into the role it was already in, so a reader checking
    # only that role reproduced the whole manifest. `signer1` is a signer here,
    # and adding it as a root is the cross-role case.
    b.add(f"{b.index}-bad-root_add-existing-signer", b.build(
        "root_add", {"pk": KEYS["signer1"].public}, roots3), "dup-key")

    # Cold gate run 9, D15. §16.1 requires `expires > ts`, and the only vector
    # for it is a *request* (`requests-bad/expires-at-ts`). An `enroll` decodes
    # its embedded request under §16.1, so the rule applies at the entry layer
    # too -- and `enroll-skip-expires-rule` passed, because no entry ever
    # carried a request that broke it.
    expired = _raw_enroll_body({
        "v": 1, "ts": T0, "net": NET, "device_id": "halfsigned",
        "device_pk": KEYS["halfsigned"].public, "wg_pk": WG["halfsigned"],
        "expires": T0,
    }, "halfsigned")
    b.add(f"{b.index}-bad-enroll-request-expires-at-ts", b.build(
        "enroll", expired, both), "decode")

    # Cold gate run 11, D8. §4.2 says signatures are verified against the key
    # the `kid` resolves to in the state BEFORE this entry, and no entry in the
    # log was ever signed by a key it was itself adding -- so
    # `ResolveKeysAfterEntry`, which lets a `root_add`'s incoming key count
    # toward its own quorum, passed all 622 checks.
    #
    # `root_thr` is 3 here and the roots are root1..root3, so this carries TWO
    # valid root signatures and a third by `root4`, the key in its own body.
    # Under §4.2 that is two of three and the entry is `threshold`; under the
    # other reading it is a root quorum that bootstraps itself. §9.4 makes the
    # same ordering argument for log keys -- "a stolen log key cannot name its
    # own successor" -- and the root-key version of it was stated once in §4.2
    # and exercised by nothing.
    b.add(f"{b.index}-bad-root_add-counts-its-own-key", b.build(
        "root_add", {"pk": KEYS["root4"].public},
        [("root1", "root"), ("root2", "root"), ("root4", "root")]), "threshold")

    # Cold gate run 12, D1. §4.0: `sigs` has no repeated `kid`, and an array
    # that repeats one is `decode`; §4.3: a key counts at most once. No entry
    # ever repeated a kid, so neither rule was checked -- and a reader lax
    # about both lets one root meet a three-root quorum alone. One root's
    # signature element, three times, on a `signer_add` for a stranger.
    repeated = b.build("signer_add", {"pk": KEYS["stranger"].public}, [("root1", "root")])
    repeated["sigs"] = repeated["sigs"] * 3
    b.add(f"{b.index}-bad-repeated-kid", repeated, "decode")

    # Cold gate run 12, D6. §5.1 step 3 checks the envelope "per §4.1", and
    # §4.1 gives every member a type -- which step 3 did not say it checks.
    # Each entry below is signed over its wrong-typed member, so a reader that
    # defers the type check does not fail on a signature: it reaches a later
    # step and answers differently, or accepts.
    def wrong_type(kind: str, body: Any, signers: list[tuple[str, str]],
                   **members: Any) -> dict[str, Any]:
        env = entry.new(kind, NET, ts=T0 + b.index * 60, after=b.index, body=body)
        env.update(members)
        return _signed(env, signers)

    # Under-signed too: a reader that checks the body's type at step 8 says
    # `threshold` (step 7) for a body that is not a map at all.
    b.add(f"{b.index}-bad-body-not-a-map",
          wrong_type("signer_add", 5, [("root1", "root")]), "decode")
    # A reader that checks `t` at step 4 says `unknown-type`.
    b.add(f"{b.index}-bad-t-not-text",
          wrong_type("note", {"text": "t is a number"}, [("signer1", "signer")], t=7), "decode")
    # A reader that only compares `after` with the index accepts these two.
    b.add(f"{b.index}-bad-after-not-a-uint",
          wrong_type("note", {"text": "after is text"}, [("signer1", "signer")], after="0"),
          "decode")
    b.add(f"{b.index}-bad-ts-not-a-uint",
          wrong_type("note", {"text": "ts is text"}, [("signer1", "signer")], ts=str(T0)),
          "decode")

    # Cold gate run 12, D9. §5.1's type rules run their checks "in the order
    # written", and nothing exercised the order inside `revoke`, nor where
    # `rotate`'s device signature sits between "currently active" and the
    # signer threshold. Each entry fails two checks; the earlier decides.
    # `ghost` was never enrolled and nobody signed: `unknown-device`, not
    # `threshold`.
    b.add(f"{b.index}-bad-revoke-unknown-unsigned", b.build(
        "revoke", {"device_id": "ghost", "reason": "never enrolled"}, []), "unknown-device")
    # `laptop` is revoked and the rotation is unsigned: `not-active`, not
    # `no-device-sig`.
    b.add(f"{b.index}-bad-rotate-revoked-unsigned", b.build(
        "rotate", {"device_id": "laptop", "wg_pk": WG["rogue"]}, []), "not-active")
    # `printer` is active, `rotate_needs_signer` is on, and nobody signed:
    # the device signature is checked first -- `no-device-sig`, not
    # `threshold`.
    b.add(f"{b.index}-bad-rotate-needs-signer-unsigned", b.build(
        "rotate", {"device_id": "printer", "wg_pk": WG["rogue"]}, []), "no-device-sig")

    # Cold gate run 12, D16. Every byte cap was pinned only from above, and
    # two bytes above at that, so a reader whose cap was one too high or one
    # too low passed. At the cap: a 4096-byte `text` is accepted, and a
    # 256-byte `reason` passes the body check and reaches the next one --
    # `ghost` was never enrolled, so `unknown-device`, where a reader whose
    # cap is one byte too strict says `decode`.
    b.add(f"{b.index}-note-text-at-the-cap", b.build(
        "note", {"text": "é" * 2048}, [("signer1", "signer")]))
    b.add(f"{b.index}-bad-revoke-reason-at-the-cap", b.build(
        "revoke", {"device_id": "ghost", "reason": "é" * 128}, roots3), "unknown-device")
    # §4.0 allows a boolean in one place, `params.rotate_needs_signer`, and
    # §4.3 types it as one. Only "a bool where a uint belongs" was vectored;
    # the reverse -- the flag given as 1 -- was accepted by a reader that
    # treats any truthy value as on.
    b.add(f"{b.index}-bad-params-flag-as-uint", b.build(
        "params", {"rotate_needs_signer": 1}, roots3), "decode")

    # Cold gate run 13, D1. §4.0 closes every body, but §5.1's `rotate` and
    # `revoke` rows said "well-formed" where the others say "well-formed and
    # closed", and the one unknown-body-key vector was a `note`. A reader that
    # took the rows at their word re-keyed or revoked a device on a body with
    # a key nobody defined. Each entry below is otherwise valid -- signed by
    # the device and both signers, or by both signers -- so the extra key is
    # the only thing that refuses it.
    b.add(f"{b.index}-bad-rotate-unknown-body-key", b.build("rotate", {
        "device_id": "printer", "wg_pk": WG["rogue"], "comment": "x"},
        [("printer", "device")] + both), "decode")
    b.add(f"{b.index}-bad-revoke-unknown-body-key", b.build("revoke", {
        "device_id": "printer", "reason": "lost", "comment": "x"}, both), "decode")
    # Run 13, D3. `1 ≤ thr ≤ len(set)` was pinned at 0 and at 99, never at
    # its top: no entry set a threshold equal to the set's size, so a reader
    # that wrote `<` passed. Two signers, two required.
    b.add(f"{b.index}-signer_thr-2-of-2", b.build("signer_thr", {"thr": 2}, roots3))
    # Run 13, D9. The policy grammar permits more than one `log` line, and
    # the policy suite's `two-log-lines` says so to a parser -- but no entry
    # ever carried one, so replay's "MUST parse" was checked against a single
    # log line only. The current policy, plus the first key the roots
    # published: what a rotation looks like from outside. The second line
    # follows the first, not `quorum` -- whether anything may follow `quorum`
    # is run 13's D8, a question this vector does not answer.
    first_log, rest = rotated.split("\n", 1)
    b.add(f"{b.index}-policy-two-log-lines", b.build("policy", {
        "text": f"{first_log}\nlog {note.vkey(ORIGIN, KEYS['logkey2'].public)}\n{rest}"},
        roots3))

    # Run 13, D4. §5.1's order is normative, and five adjacent pairs had no
    # entry with a fault on each side, so a reader that swapped either pair
    # passed. Each entry below fails two checks; the earlier decides.
    #
    # Step 4 before step 6: an unknown `t` that also names an `after` past its
    # own index -- `unknown-type`, not `after`.
    ahead = {"v": entry.VERSION, "t": "bogus", "net": NET, "ts": T0 + b.index * 60,
             "after": b.index + 1, "body": {"text": "unknown type, after ahead"}, "sigs": []}
    entry.sign(ahead, KEYS["signer1"], "signer")
    b.add_raw(f"{b.index}-bad-precedence-unknown-type-before-after", cbor.encode(ahead),
              "unknown-type")
    # Step 5 before step 6: a second genesis with an `after` past its own
    # index -- `dup-genesis`, not `after`.
    b.add(f"{b.index}-bad-precedence-dup-genesis-before-after", genesis(after=b.index + 1),
          "dup-genesis")
    # Step 7 before step 8 for `note`, which has its own step-7 rule: unsigned,
    # and one byte over the text cap -- `threshold`, not `decode`.
    # `bad-undersigned-malformed` is the governance form of this pair.
    b.add(f"{b.index}-bad-precedence-note-threshold-before-body", b.build(
        "note", {"text": "x" * 4097}, []), "threshold")
    # Inside `revoke`: currently `active` before the authorisation. `laptop`
    # revoked itself at entry 36, and nobody signs -- `not-active`, not
    # `threshold`. `bad-revoke-unknown-unsigned` orders the check before it.
    b.add(f"{b.index}-bad-precedence-revoke-not-active-before-threshold", b.build(
        "revoke", {"device_id": "laptop", "reason": "again"}, []), "not-active")
    # Step 3 before step 7: an unsigned `signer_add` for another network --
    # `decode`, not `threshold`. `bad-decode-net` is signed, so a reader that
    # judged `net` after authorisation still called it `decode`.
    foreign = entry.new("signer_add", b"\xff" * 16, ts=T0 + b.index * 60, after=b.index,
                        body={"pk": KEYS["stranger"].public})
    b.add_raw(f"{b.index}-bad-precedence-net-before-threshold", entry.encode(foreign), "decode")

    # D-073. The `ip` label is the device's grant -- the prefixes the signers
    # authorised it to source -- parsed as a whole, masked, sorted. `router`
    # is enrolled with host addresses on wider prefixes, so the grant a reader
    # computes differs from the label it reads; `badgrant`'s label has one
    # prefix that does not parse, and a label that does not parse as a whole
    # is no grant at all, not the prefixes that did parse.
    b.add(f"{b.index}-enroll-router-granted", b.build("enroll", _enroll_body(
        "router", labels={"ip": "10.9.1.5/24, fd00::5/64"}), both))
    b.add(f"{b.index}-enroll-badgrant-label-not-a-grant", b.build("enroll", _enroll_body(
        "badgrant", labels={"ip": "10.9.2.0/24, nope"}), both))
    # `routes` is the one text-valued parameter and its value set is closed:
    # the default named explicitly is accepted; another word, or a number, is
    # `decode` -- as a bool where a uint belongs is.
    b.add(f"{b.index}-params-routes-granted", b.build("params", {"routes": "granted"}, roots3))
    b.add(f"{b.index}-bad-params-routes-unknown-value", b.build(
        "params", {"routes": "open"}, roots3), "decode")
    b.add(f"{b.index}-bad-params-routes-wrong-type", b.build(
        "params", {"routes": 1}, roots3), "decode")

    # SEC-016: booleans are profile items, but these fields are uints (§5.1).
    # Every entry has the full root quorum. Coercing true to 1 would put both
    # thresholds within their sets and accept all three, changing the state.
    b.add(f"{b.index}-bad-signer_thr-bool", b.build(
        "signer_thr", {"thr": True}, roots3), "decode")
    b.add(f"{b.index}-bad-root_thr-bool", b.build(
        "root_thr", {"thr": True}, roots3), "decode")
    b.add(f"{b.index}-bad-log_key-overlap-bool", b.build(
        "log_key", {"pk": KEYS["logkey3"].public, "overlap": True}, roots3), "decode")

    return b.items


# -- negative fixtures (SPEC §12.1) --------------------------------------

def genesis_aborts() -> list[tuple[str, bytes, "replay.Anchor"]]:
    """Every distinct way entry 0 can make replay abort with `bad-genesis`.

    Each case is a one-entry log with its own anchor, because an abort stops
    replay and so cannot share a log with anything else.
    """
    from . import replay

    good = entry.encode(genesis())
    good_anchor = replay.Anchor(NET, entry.leaf_hash(good))
    cases: list[tuple[str, bytes, replay.Anchor]] = [
        # the anchor pins a different genesis
        ("01-hash-mismatch", good, replay.Anchor(NET, bytes(32))),
    ]

    # entry 0 is not a genesis at all
    not_genesis = _signed(entry.new("note", NET, ts=T0, after=0,
                                    body={"text": "index 0 is not a genesis"}),
                          [("signer1", "signer")])
    raw = entry.encode(not_genesis)
    cases.append(("02-not-genesis", raw, replay.Anchor(NET, entry.leaf_hash(raw))))

    # a genesis for another network
    other = _signed(entry.new("genesis", b"\xff" * 16, ts=T0, body=genesis()["body"]),
                    [("root1", "root"), ("root2", "root")])
    raw = entry.encode(other)
    cases.append(("03-wrong-net", raw, replay.Anchor(NET, entry.leaf_hash(raw))))

    # `after` must be 0 at index 0
    ahead = genesis(after=7)
    raw = entry.encode(ahead)
    cases.append(("04-after-nonzero", raw, replay.Anchor(NET, entry.leaf_hash(raw))))

    # a body that cannot be applied: threshold above the number of roots
    body = dict(genesis()["body"], root_thr=9)
    bad_body = _signed(entry.new("genesis", NET, ts=T0, body=body),
                       [("root1", "root"), ("root2", "root")])
    raw = entry.encode(bad_body)
    cases.append(("05-root-thr-above-set", raw, replay.Anchor(NET, entry.leaf_hash(raw))))

    # bootstrap shortfall: root_thr is 2, only one root signed
    under = _signed(entry.new("genesis", NET, ts=T0, body=genesis()["body"]),
                    [("root1", "root")])
    raw = entry.encode(under)
    cases.append(("06-under-root-threshold", raw, replay.Anchor(NET, entry.leaf_hash(raw))))

    # entry 0 that does not decode at all (SPEC §5.1 entry-0 step 2)
    raw = b"\xa1\x61t\xf9\x3c\x00"  # a map whose value is a float: outside the profile
    cases.append(("07-undecodable", raw, replay.Anchor(NET, entry.leaf_hash(raw))))

    # body invariants beyond the threshold check (entry-0 step 6)
    dup_root = dict(genesis()["body"], roots=[KEYS["root1"].public, KEYS["root1"].public])
    env = _signed(entry.new("genesis", NET, ts=T0, body=dup_root),
                  [("root1", "root"), ("root2", "root")])
    raw = entry.encode(env)
    cases.append(("08-duplicate-root", raw, replay.Anchor(NET, entry.leaf_hash(raw))))

    overlap = dict(genesis()["body"], signers=[KEYS["root1"].public, KEYS["signer1"].public])
    env = _signed(entry.new("genesis", NET, ts=T0, body=overlap),
                  [("root1", "root"), ("root2", "root")])
    raw = entry.encode(env)
    cases.append(("09-role-overlap", raw, replay.Anchor(NET, entry.leaf_hash(raw))))

    # `case` rather than `name`, because `name` is also a genesis body key and
    # a case that damages it would collide with this parameter.
    # §5.1 entry-0 step 7 counts signatures **in the `root` role**. Every
    # genesis in the suite declared `root`, so `genesis-sigs-any-role` -- which
    # counts a signature whatever role it claims -- passed (run 8, D20).
    wrong_role = _signed(entry.new("genesis", NET, ts=T0, body=genesis()["body"]),
                         [("root1", "signer"), ("root2", "signer")])
    raw = entry.encode(wrong_role)
    cases.append(("18-bootstrap-sigs-wrong-role", raw,
                  replay.Anchor(NET, entry.leaf_hash(raw))))

    # §5.1 entry-0 step 7 resolves genesis signatures against the `roots` in
    # the body -- and which key SET it resolves against was pinned by nothing:
    # every genesis in the suite was signed by keys that are in `roots`, so a
    # reader that also bootstrap-resolved against `signers` reproduced the whole
    # suite (run 10, D15). Step 6 requires the two disjoint, so this is a real
    # fork: signed only by `signers`, each line declaring `root`, it is a
    # working network under that reading and `bad-genesis` under this one.
    from_signers = _signed(entry.new("genesis", NET, ts=T0, body=genesis()["body"]),
                           [(SIGNERS[0], "root"), (SIGNERS[1], "root")])
    raw = entry.encode(from_signers)
    cases.append(("19-bootstrap-sigs-from-signers", raw,
                  replay.Anchor(NET, entry.leaf_hash(raw))))

    def bad_body(case: str, **changes: Any) -> None:
        body = dict(genesis()["body"], **changes)
        env = _signed(entry.new("genesis", NET, ts=T0, body=body),
                      [("root1", "root"), ("root2", "root")])
        raw = entry.encode(env)
        cases.append((case, raw, replay.Anchor(NET, entry.leaf_hash(raw))))

    bad_body("10-duplicate-signer",
             signers=[KEYS["signer1"].public, KEYS["signer1"].public])
    bad_body("11-signer-thr-above-set", signer_thr=9)
    bad_body("12-empty-roots", roots=[])
    # Entry-0 step 6: "`params`, if present, has only §4.5 keys". No genesis in
    # the suite carried a `params` map at all, so the two readings differ by
    # the entire log -- one aborts to the zero state, the other replays 100-odd
    # entries -- and `allow-unknown-param` passed regardless.
    bad_body("13-params-unknown-key", params={"staleness": 900, "mtu": 1420})
    # §4.0 bounds `name` at 1-64 bytes and `genesis/` had no case at either
    # end, so `no-name-len` passed -- and the Python reference had no such
    # check, which is what an unpinned rule looks like from the inside.
    # Run 11, D6: 33 two-byte characters is 66 bytes and 33 characters, over
    # the 64-byte cap and under it in runes.
    bad_body("14-name-too-long", name="é" * 33)
    # Cold gate run 8, D20: the keys of a genesis `params` were checked and the
    # values were not, so `genesis-params-no-typecheck` and
    # `genesis-params-nonempty` both passed -- while a `params` *entry* has
    # required both since Phase 1.
    bad_body("16-params-wrong-type", params={"staleness": True})
    bad_body("17-params-empty", params={})
    bad_body("15-name-empty", name="")
    # Run 13, D17: 66 bytes and empty are both far from the cap, so a reader
    # whose cap was 65 passed. One byte past it, in characters that make it
    # 33 runes -- under the cap for a reader counting those.
    bad_body("20-name-one-past-the-cap", name="é" * 32 + "a")

    # SEC-016: each boolean is the only fault. The two root signatures meet
    # the quorum even if a reader mistakes true for the uint 1.
    bad_body("21-root-thr-bool", root_thr=True)
    bad_body("22-signer-thr-bool", signer_thr=True)

    # Keep the two honest signatories in roots. Appending the edge key leaves
    # their quorum intact, so only §3.1's point rule can abort these geneses.
    for name, public in (("23-root-order-eight", ORDER_EIGHT),
                         ("24-root-noncanonical", NONCANONICAL_POINT)):
        bad_body(name, roots=[KEYS[n].public for n in ROOTS] + [public])

    assert good_anchor  # the good anchor is exercised by the log fixture
    return cases


def admission_log() -> list[LogItem]:
    """An isolated log for §3.1 key admission, not the served fixture.

    A refused admission must leave the keys unchanged. Honest entries before
    and after the refusals make stopping early an observable wrong answer.
    """
    mixed = crypto_core_ed25519_add(KEYS["signer3"].public, ORDER_EIGHT)
    builder = _Builder()
    builder.add("00-genesis", genesis())
    for kind in ("signer_add", "root_add", "log_key"):
        body = {"pk": mixed}
        if kind == "log_key":
            body["overlap"] = 60
        builder.add(f"{builder.index:02d}-{kind}-mixed-order",
                    builder.build(kind, body, [("root1", "root"), ("root2", "root")]),
                    "decode")
    builder.add("04-signer_add-honest", builder.build(
        "signer_add", {"pk": KEYS["signer3"].public}, [("root1", "root"), ("root2", "root")]))
    builder.add("05-enroll-honest", builder.build(
        "enroll", _enroll_body("pi-cam"), [("signer1", "signer")]))
    incoming = crypto_core_ed25519_add(KEYS["spare"].public, ORDER_EIGHT)
    rotate = builder.build("rotate", {"device_id": "pi-cam", "wg_pk": WG["spare"],
                                     "device_pk": incoming}, [("pi-cam", "device")])
    # Sign with the honest scalar but hash A + T. Cofactoring kills [k]T,
    # so this proves possession to a cofactored verifier but fails §3.1.
    key = KEYS["spare"]
    expanded = bytearray(hashlib.sha512(key.seed).digest())
    expanded[0] &= 248
    expanded[31] = (expanded[31] & 63) | 64
    a = int.from_bytes(expanded[:32], "little")
    message = entry.preimage(rotate)
    r = int.from_bytes(hashlib.sha512(bytes(expanded[32:]) + message).digest(), "little") % keys.L
    while True:
        R = crypto_scalarmult_ed25519_base_noclamp(r.to_bytes(32, "little"))
        k = int.from_bytes(hashlib.sha512(R + incoming + message).digest(), "little") % keys.L
        # A challenge divisible by 8 would also satisfy the cofactorless
        # equation. Keep this vector on the edge where the equations part.
        if k % 8:
            break
        r = (r + 1) % keys.L
    signature = R + ((r + k * a) % keys.L).to_bytes(32, "little")
    rotate["sigs"].append({"kid": keys.kid(incoming), "role": "device", "sig": signature})
    rotate["sigs"].sort(key=lambda sig: (sig["kid"], sig["role"]))
    builder.add("06-rotate-mixed-order", rotate, "decode")
    small = note.vkey("norn-witness/pi", ORDER_EIGHT, note.ALG_COSIGNATURE)
    builder.add("07-policy-small-order", builder.build(
        "policy", {"text": f"witness pi {small}\nquorum pi\n"},
        [("root1", "root"), ("root2", "root")]), "decode")
    builder.add("08-policy-honest", builder.build(
        "policy", {"text": f"witness pi {witness_vkey('pi')}\nquorum pi\n"},
        [("root1", "root"), ("root2", "root")]))
    return builder.items


def genesis_accepts() -> list[tuple[str, bytes, "replay.Anchor"]]:
    """Geneses a reader MUST accept, one single-entry log each (run 13, D17).

    A bound has two sides, and `genesis_aborts` holds only the refusing one: a
    reader whose `name` cap was 63 bytes refused no vector, and on a real
    network it would abort the whole log.
    """
    from . import replay

    cases: list[tuple[str, bytes, replay.Anchor]] = []
    # Exactly 64 bytes, 32 runes.
    body = dict(genesis()["body"], name="é" * 32)
    env = _signed(entry.new("genesis", NET, ts=T0, body=body),
                  [("root1", "root"), ("root2", "root")])
    raw = entry.encode(env)
    cases.append(("01-name-at-the-cap", raw, replay.Anchor(NET, entry.leaf_hash(raw))))
    return cases


def policy_grammar() -> list[tuple[str, str, bool, str]]:
    """(name, text, accept, why) — §9.1's restated grammar, both sides of each rule.

    Cold gate run 8 (D12): the only policy text in the suite was the fixture's
    own and one negative that is not a policy at all, so nine readings of the
    grammar all passed -- and six of them were places the two implementations
    in this repository already disagreed. Each case below is a whole policy
    that differs from a valid one in exactly one way.
    """
    log = f"log {log_vkey()} {LOG_URLS[0]}"
    pi = f"witness pi {witness_vkey('pi')} {WITNESS_URLS['pi']}"
    vps = f"witness vps {witness_vkey('vps')} {WITNESS_URLS['vps']}"
    witness_alias = note.vkey(
        "norn-witness/alias", KEYS["witness-pi"].public, note.ALG_COSIGNATURE)
    log_alias = note.vkey("norn/alias", KEYS["logkey"].public)
    log_as_witness = note.vkey(
        "norn-witness/log-alias", KEYS["logkey"].public, note.ALG_COSIGNATURE)
    bad_log_id = _vkey_with_wrong_id()
    bad_witness_id = _witness_vkey_with_wrong_id("pi")

    return [
        ("minimal", f"{log}\n{pi}\nquorum pi\n", True,
         "one log, one witness, one quorum"),
        ("bad-no-trailing-newline", f"{log}\n{pi}\nquorum pi", False,
         "every directive line, including the final one, ends in line feed"),
        ("quorum-none-empty", "quorum none\n", True,
         "the predefined `none` quorum needs neither logs nor witnesses"),
        ("reserved-words-as-names",
         f"witness all {witness_vkey('pi')}\nwitness spare {witness_vkey('vps')}\n"
         "group any any all spare\nquorum any\n", True,
         "`all` and `any` are special only in the threshold position"),
        ("blank-and-whitespace-lines",
         f"{log}\n\n{pi}\n \t \nquorum pi\n", True,
         "a line that is empty, or only spaces and tabs, is ignored"),
        ("nested-group",
         f"{log}\n{pi}\n{vps}\ngroup inner any pi vps\n"
         "group outer all inner\nquorum outer\n", True,
         "a group may name a group; it counts as one member, satisfied or not"),
        ("no-log-line", f"{pi}\nquorum pi\n", True,
         "`log` is not required by the grammar: the trust file carries the log key"),
        ("comment-and-indent",
         f"{log}\n  # a comment, indented\n\t{pi}\nquorum pi\n", True,
         "a line whose first non-space character is `#` is ignored, and leading "
         "spaces and tabs are not part of a field"),
        # The stray character goes between a two-field directive's two fields,
        # where reading it as a separator yields a policy that *parses*. In the
        # URL -- where it used to be -- a separator reading gives a four-field
        # `witness` line, which the field-count rule refuses; the whitespace
        # rule was then pinned by nothing and could be deleted with the suite
        # still green (cold gate run 10, D9).
        ("bad-vertical-tab", f"{log}\n{pi}\nquorum\vpi\n",
         False, "only ASCII space and tab separate fields, anywhere in a line"),
        ("bad-duplicate-name", f"{log}\n{pi}\nwitness pi {witness_vkey('vps')}\nquorum pi\n",
         False, "a name is defined once"),
        ("bad-forward-reference",
         f"{log}\ngroup g all pi\n{pi}\nquorum g\n", False,
         "a group names previously-defined members only"),
        ("bad-quorum-forward-reference",
         f"{log}\n{pi}\nquorum home\ngroup home any pi\n", False,
         "the quorum names a previously-defined witness or group"),
        ("directive-after-quorum",
         f"{log}\n{pi}\ngroup home any pi\nquorum home\n{vps}\n"
         "group unused all vps\n", True,
         "lines may follow quorum; the unused witness and group do not change its meaning"),
        ("bad-redefinition-after-use",
         f"{log}\n{pi}\n{vps}\ngroup home any pi\nquorum home\n"
         "group home any vps\n", False,
         "a name is defined once, even after an earlier quorum line used it"),
        ("bad-witness-name-none",
         f"{log}\nwitness none {witness_vkey('pi')}\nquorum none\n", False,
         "`none` is predefined and cannot be defined as a witness or group"),
        ("bad-group-name-none",
         f"{log}\n{pi}\ngroup none any pi\nquorum none\n", False,
         "`none` is predefined and cannot be defined as a witness or group"),
        ("bad-none-group-member",
         f"{log}\n{pi}\ngroup home any none\nquorum home\n", False,
         "the predefined `none` is not a group member"),
        ("bad-group-witness-name-collision",
         f"{log}\n{pi}\n{vps}\ngroup pi any vps\nquorum pi\n", False,
         "witness and group names share one namespace"),
        ("bad-two-quorums", f"{log}\n{pi}\nquorum pi\nquorum pi\n", False,
         "there is exactly one quorum line"),
        ("bad-no-quorum", f"{log}\n{pi}\n", False,
         "there is exactly one quorum line"),
        ("bad-empty-group", f"{log}\n{pi}\ngroup g all\nquorum g\n", False,
         "a group has at least one member"),
        ("bad-unknown-keyword", f"{log}\n{pi}\nwitnesses vps x\nquorum pi\n", False,
         "every line is one of the four directives"),
        ("bad-quorum-undefined", f"{log}\n{pi}\nquorum nobody\n", False,
         "the quorum names something the policy defines"),
        # Cold gate run 9, D7: five rules §9.1 states with no negative at all,
        # two of which change what a quorum *means*.
        ("bad-duplicate-member", f"{log}\n{pi}\n{vps}\ngroup home 2 pi pi\nquorum home\n",
         False, "no member twice -- `2 of pi pi` is met by one witness"),
        ("bad-k-zero", f"{log}\n{pi}\n{vps}\ngroup home 0 pi vps\nquorum home\n",
         False, "1 <= k <= n -- k=0 is met by nobody, so an uncosigned head passes"),
        ("threshold-at-size",
         f"{log}\n{pi}\n{vps}\ngroup home 2 pi vps\nquorum home\n", True,
         "the inclusive upper threshold `k = n` is valid"),
        ("bad-k-above-size",
         f"{log}\n{pi}\n{vps}\ngroup home 3 pi vps\nquorum home\n", False,
         "a numeric threshold MUST satisfy `k ≤ n`"),
        ("bad-k-leading-zero",
         f"{log}\n{pi}\n{vps}\ngroup home 02 pi vps\nquorum home\n", False,
         "k is canonical decimal: two spellings of a quorum are two policies "
         "that look different and are not"),
        ("bad-carriage-return", f"{log}\n{pi}\nquorum\rpi\n",
         False, "only ASCII space and tab; `bad-vertical-tab` covers only one of the three"),
        ("bad-uppercase-keyword", f"{log}\nWITNESS pi {witness_vkey('pi')}\nquorum pi\n",
         False, "the four directives are lowercase"),
        # Cold gate run 10, D9 and D10. Arity was the rule doing the work and
        # §9.1 did not contain it; the comment rule left three readings alive.
        ("bad-extra-field", f"{log}\n{pi}\nquorum pi extra\n", False,
         "a directive takes the fields its production allows and no more"),
        ("comment-tab-indented", f"{log}\n\t# a comment, tab-indented\n{pi}\nquorum pi\n",
         True, "the indent before a `#` is spaces *and tabs*; only-U+0020 reads "
         "this line as a directive named `#`"),
        ("bad-trailing-comment", f"{log}\n{pi}\nquorum pi # note\n", False,
         "`#` after a directive's fields is an ordinary character, so this is a "
         "`quorum` line with two names; a reader that strips from `#` accepts it"),
        ("witness-url-fragment",
         f"{log}\nwitness pi {witness_vkey('pi')} https://example/w#tag\nquorum pi\n",
         True, "a `#` inside a field is content: a reader for which `#` is illegal "
         "anywhere refuses a URL with a fragment in it"),
        # Cold gate run 11, D2. §9.1's `log lines` row argued from "no key may
        # appear twice in one policy", a rule the table never stated, and
        # nothing here repeated a key. The Go parser refused a repeat and this
        # one did not, so a `policy` entry listing one key under two names was
        # `decode` on one side and replayed on the other.
        ("bad-duplicate-key",
         f"{log}\n{pi}\nwitness vps {witness_vkey('pi')}\nquorum pi\n", False,
         "a verifier key appears once: under two names, one cosignature line "
         "would count as two witnesses"),
        ("bad-log-key-as-witness",
         f"{log}\nwitness pi {log_as_witness}\nquorum pi\n", False,
         "the same public key cannot appear on a `log` and a `witness` line"),
        ("bad-duplicate-witness-public-key-alias",
         f"{log}\n{pi}\nwitness alias {witness_alias}\nquorum pi\n", False,
         "vkey names and IDs do not make one public key into two witnesses"),
        ("bad-duplicate-log-public-key-alias",
         f"{log}\nlog {log_alias}\n{pi}\nquorum pi\n", False,
         "a duplicate log is detected by its public key, despite another vkey name"),
        ("bad-log-vkey-malformed",
         f"log not-a-vkey {LOG_URLS[0]}\n{pi}\nquorum pi\n", False,
         "each log field is a parsed C2SP verifier key"),
        ("bad-log-vkey-id",
         f"log {bad_log_id} {LOG_URLS[0]}\n{pi}\nquorum pi\n", False,
         "a verifier key's declared key ID matches its name, algorithm and public key"),
        ("bad-witness-vkey-id",
         f"{log}\nwitness pi {bad_witness_id}\nquorum pi\n", False,
         "a verifier key's declared key ID matches its name, algorithm and public key"),
        ("bad-witness-vkey-malformed",
         f"{log}\nwitness pi not-a-vkey\nquorum pi\n", False,
         "each witness field is a parsed C2SP verifier key"),
        ("bad-log-vkey-algorithm",
         f"log {witness_vkey('pi')} {LOG_URLS[0]}\n{pi}\nquorum pi\n", False,
         "a log verifier key uses algorithm `0x01`"),
        ("bad-witness-vkey-algorithm",
         f"{log}\nwitness pi {log_vkey()}\nquorum pi\n", False,
         "a witness verifier key uses algorithm `0x04`"),
        ("bad-vkey-name-space",
         f"log {note.vkey(ORIGIN + ' bad', KEYS['logkey'].public)} {LOG_URLS[0]}\n"
         f"{pi}\nquorum pi\n", False,
         "a verifier key name is ASCII 0x21-0x7E without '+', so no space"),
        # The other half of the same row: the grammar permits more than one
        # `log` line. A trust file cannot carry two (each must be `log_key`,
        # and the key rule refuses a repeat), but a `policy` entry has no such
        # correspondence, and a policy naming a log's old and new key is
        # exactly what a rotation looks like from outside.
        ("two-log-lines",
         f"{log}\nlog {note.vkey(ORIGIN, KEYS['logkey2'].public)}\n{pi}\nquorum pi\n",
         True, "the grammar permits more than one `log` line; only a trust file's "
         "correspondence rule limits it to one"),
        ("bad-duplicate-log-line",
         f"{log}\nlog {log_vkey()}\n{pi}\nquorum pi\n", False,
         "multiple log lines with the same public key are forbidden"),
        ("bad-log-lines-same-key-alias",
         f"{log}\nlog {log_alias}\n{pi}\nquorum pi\n", False,
         "multiple log lines with the same public key are forbidden"),
        # Cold gate run 11, D12. "Any other whitespace character" was not a
        # set. This parser refused all of str.isspace() that can occur in a
        # line -- 26 characters -- and the Go one refused three of them, so the
        # two disagreed on 23 and no vector could tell. The set is
        # closed now: 0x0B, 0x0C, 0x0D. `bad-form-feed` is the third, placed
        # like the other two where a separator reading would parse.
        ("bad-form-feed", f"{log}\n{pi}\nquorum\fpi\n",
         False, "0x0C is one of the three characters that are errors"),
        # Each of the three twice, because one placement pins only one lax
        # reading. Between `quorum` and `pi`, a reader that SPLITS on the
        # character gets `quorum pi` and accepts; one that keeps it as CONTENT
        # gets a single field, an unknown keyword, and refuses anyway -- so
        # those three vectors let the content reading through. Inside a URL
        # it is the other way round: content parses, and a split makes five
        # fields, which the field count refuses. Only the error reading
        # refuses all six for the rule they are named after.
        ("bad-vertical-tab-in-url",
         f"{log}\nwitness pi {witness_vkey('pi')} https://example/w\vx\nquorum pi\n",
         False, "0x0B is an error, not content: kept as content, this URL parses"),
        ("bad-form-feed-in-url",
         f"{log}\nwitness pi {witness_vkey('pi')} https://example/w\fx\nquorum pi\n",
         False, "0x0C is an error, not content: kept as content, this URL parses"),
        ("bad-carriage-return-in-url",
         f"{log}\nwitness pi {witness_vkey('pi')} https://example/w\rx\nquorum pi\n",
         False, "0x0D is an error, not content: kept as content, this URL parses"),
        ("bad-crlf",
         f"{log}\r\n{pi}\nquorum pi\n", False,
         "carriage return is forbidden; a directive line ends with line feed only"),
        ("bad-control-nul",
         f"{log}\nwitness pi {witness_vkey('pi')} https://example/\x00x\nquorum pi\n", False,
         "ASCII controls other than tab and line feed are forbidden in every line"),
        ("bad-control-unit-separator",
         f"{log}\nwitness pi {witness_vkey('pi')} https://example/\x1fx\nquorum pi\n", False,
         "ASCII controls other than tab and line feed are forbidden in every line"),
        ("bad-control-del",
         f"{log}\nwitness pi {witness_vkey('pi')} https://example/\x7fx\nquorum pi\n", False,
         "ASCII controls other than tab and line feed are forbidden in every line"),
        ("bad-control-in-comment",
         f"{log}\n# ignored comment\x00\n{pi}\nquorum pi\n", False,
         "control bytes are refused before comment lines are ignored"),
        ("u0085-is-content",
         f"{log}\nwitness pi {witness_vkey('pi')} https://example/w\u0085x\nquorum pi\n",
         True, "non-ASCII octets are content, even when Unicode labels them whitespace"),
        ("nbsp-is-content",
         f"{log}\nwitness pi {witness_vkey('pi')} https://example/w x\nquorum pi\n",
         True, "U+00A0 is not in the closed set, so it is content: a reader that "
         "refuses it, or splits on it, refuses a policy this document allows"),
    ]


def policy_evaluations() -> dict[str, list[dict[str, Any]]]:
    """(case) -> what a quorum means, for the policies that parse.

    Cold gate run 9, D7. `policies/` asked one question -- does this parse --
    so three readings that change the *arithmetic* all passed. Nothing in the
    suite took a policy and a set of cosigners and asked for a verdict.
    """
    return {
        "directive-after-quorum": [
            {"cosigners": [], "satisfied": False, "why": "nobody cosigned"},
            {"cosigners": ["pi"], "satisfied": True,
             "why": "the quorum names home, defined earlier as any of pi"},
            {"cosigners": ["vps"], "satisfied": False,
             "why": "the trailing witness is not a member of the quorum"},
            {"cosigners": ["pi", "vps"], "satisfied": True,
             "why": "pi satisfies the original group; the trailing witness counts for nothing"},
        ],
        "minimal": [
            {"cosigners": ["pi"], "satisfied": True, "why": "the quorum names pi"},
            {"cosigners": [], "satisfied": False, "why": "nobody cosigned"},
            {"cosigners": ["vps"], "satisfied": False,
             "why": "a witness the quorum does not name counts for nothing"},
        ],
        # The case that separates a nested group from a flattened one. `outer`
        # is `all` of ONE member, and that member is `inner`, which is `any` of
        # two -- so pi alone satisfies it. Flatten `outer` to {pi, vps} and
        # `all` becomes two, which pi alone does not.
        "nested-group": [
            {"cosigners": ["pi"], "satisfied": True,
             "why": "a nested group counts as one member, met as its own threshold decides"},
            {"cosigners": ["vps"], "satisfied": True, "why": "inner is `any` of pi and vps"},
            {"cosigners": [], "satisfied": False, "why": "inner is met by nobody"},
        ],
        "no-log-line": [
            {"cosigners": ["pi"], "satisfied": True,
             "why": "the log line is not what a quorum is about"},
        ],
    }


def trust_rejections() -> list[tuple[str, dict[str, Any]]]:
    """Trust files that MUST be rejected (SPEC §9.1)."""
    def damaged(**changes: Any) -> dict[str, Any]:
        doc = trust_file()
        for key, value in changes.items():
            if value is _REMOVE:
                doc.pop(key, None)
            else:
                doc[key] = value
        return doc

    base = trust_file()
    # The derived origin with its first letter upper-cased: `norn/` is five
    # characters, and base32's first character here is a letter, not a digit.
    cased = ORIGIN[:5] + ORIGIN[5].upper() + ORIGIN[6:]
    noncanonical_witness = note.vkey("norn-witness/pi", NONCANONICAL_POINT, note.ALG_COSIGNATURE)
    return [
        # The key ID and policy name the very same damaged point, so only
        # §3.1 refuses it, not correspondence or verifier-key framing.
        ("47-witness-noncanonical-point", damaged(
            witnesses=[dict(base["witnesses"][0], key=noncanonical_witness)]
            + [dict(w) for w in base["witnesses"][1:]],
            policy=_policy_with(witness_key=("pi", noncanonical_witness)))),
        ("01-unknown-key", dict(base, surprise="unexpected member")),
        ("02-wrong-version", damaged(version=2)),
        ("03-short-net", damaged(net=b"\x00" * 8)),
        ("04-origin-mismatch", damaged(origin="norn/wrongorigin")),
        ("05-short-genesis-hash", damaged(genesis_hash=b"\x00" * 8)),
        ("06-bad-log-key", damaged(log_key="not-a-verifier-key")),
        # Isolated: no witnesses and no policy witness names. `quorum none`
        # needs no cosignatures, so only the explicit witness minimum refuses.
        ("07-no-witnesses", damaged(
            witnesses=[], policy=f"log {log_vkey()} {LOG_URLS[0]}\nquorum none\n")),
        # Isolated: retain every expected witness plus one duplicate `pi`;
        # names and keys still correspond, so only uniqueness refuses.
        ("08-duplicate-witness-name", damaged(witnesses=[
            *[dict(w) for w in base["witnesses"]], dict(base["witnesses"][0])])),
        ("09-policy-without-quorum", damaged(policy="log x\nwitness pi y\n")),
        ("10-missing-policy", damaged(policy=_REMOVE)),
        # Isolated the same way `13` is, and for the same reason: the policy
        # carries the damaged key too, so §9.1's correspondence rule is
        # satisfied and ONLY "the log key's note name MUST equal `origin`" can
        # refuse this file. Without that, the rule was deletable with no vector
        # noticing (cold gate run 10, D12/V93).
        ("11-log-key-name-mismatch",
         damaged(log_key=note.vkey("someone/else", KEYS["logkey"].public),
                 policy=_policy_with(
                     log_key=note.vkey("someone/else", KEYS["logkey"].public)))),
        ("12-witness-key-unparseable",
         damaged(witnesses=[dict(base["witnesses"][0], key="nonsense")])),
        # Isolated: `net` stays 16 bytes, `log_key` is renamed to agree with
        # the wrong origin, and the POLICY carries that same renamed key -- so
        # the correspondence rule agrees too and ONLY "origin derives from net"
        # can reject this. The policy was the half this case forgot, which left
        # the derivation rule deletable (cold gate run 10, D12/V90).
        ("13-origin-only", damaged(
            origin=ORIGIN + "a",
            log_key=note.vkey(ORIGIN + "a", KEYS["logkey"].public),
            policy=_policy_with(log_key=note.vkey(ORIGIN + "a", KEYS["logkey"].public)))),
        # Isolated: a missing key that no other rule also catches.
        ("14-missing-name", damaged(name=_REMOVE)),
        # The two kinds of key are not interchangeable: a witness signs
        # cosignatures (algorithm 0x04) and the log signs notes (0x01). A file
        # that mixes them names keys nobody can use, and both directions parse
        # cleanly, so only this rule rejects them.
        # Cold gate run 8, D5. This listed ONE witness against a policy naming
        # three, so the correspondence rule refused it and the algorithm MUST
        # was never reached -- the same defect 6.5h-vi-b fixed in `07` and
        # `08`. All three witnesses are listed now, and `pi`'s note key is put
        # in the policy line too, so names and keys correspond exactly and the
        # only thing wrong with the file is the algorithm of one key.
        ("15-witness-key-is-a-note-key", damaged(
            witnesses=[dict(base["witnesses"][0],
                            key=note.vkey("norn-witness/pi", KEYS["witness-pi"].public))]
                      + base["witnesses"][1:],
            policy=_policy_with_pi_note_key())),
        # Isolated: the policy names the same cosignature key, so the
        # correspondence rule agrees and ONLY "`log_key` MUST NOT be a
        # cosignature key" can refuse it (cold gate run 10, D12/V92).
        ("16-log-key-is-a-cosignature-key",
         damaged(log_key=note.vkey(ORIGIN, KEYS["logkey"].public, note.ALG_COSIGNATURE),
                 policy=_policy_with(log_key=note.vkey(
                     ORIGIN, KEYS["logkey"].public, note.ALG_COSIGNATURE)))),
        # `witnesses` and `policy` must name the same parties: a quorum over
        # a witness the node cannot reach, or a listed witness nothing
        # requires, is an operator believing they configured something.
        # A perfectly valid cosigner key under a name the policy never
        # mentions: everything about it parses, so only the agreement rule
        # can reject it.
        ("17-witness-not-in-policy",
         damaged(witnesses=base["witnesses"] + [
             {"name": "extra",
              "key": note.vkey("norn-witness/extra", KEYS["spare"].public,
                               note.ALG_COSIGNATURE),
              "url": "https://nowhere.example"}])),
        ("18-policy-names-an-unlisted-witness",
         damaged(witnesses=base["witnesses"][:2])),
        # §9.1 marks exactly one key OPTIONAL. The rest were mandatory only by
        # inference, and only `name` and `policy` were ever vectored missing,
        # so an implementation treating the others as optional passed the
        # whole suite.
        ("19-missing-version", damaged(version=_REMOVE)),
        ("20-missing-net", damaged(net=_REMOVE)),
        ("21-missing-origin", damaged(origin=_REMOVE)),
        ("22-missing-genesis-hash", damaged(genesis_hash=_REMOVE)),
        ("23-missing-log-key", damaged(log_key=_REMOVE)),
        ("24-missing-log-urls", damaged(log_urls=_REMOVE)),
        ("25-missing-witnesses", damaged(witnesses=_REMOVE)),
        # Cold gate run 7, J12: four §9.1 rules whose only vector tripped a
        # *different* rule first, so removing each of them passed the suite.
        #
        # `14-missing-name` covers an absent `name`; the 1-64 byte bound has
        # two ends and neither was reached.
        ("26-name-too-long", damaged(name="é" * 33)),  # run 11, D6: 66 bytes, 33 chars
        ("27-name-empty", damaged(name="")),
        # `24-missing-log-urls` covers absent. Present-and-empty is a different
        # code path in both implementations.
        ("28-empty-log-urls", damaged(log_urls=[])),
        # Cold gate run 8, D22: seven §9.1 members the table shows and never
        # constrains. Three were live disagreements -- the witness-name cap,
        # the anchor's completeness, and `anchor.mode`, which neither side
        # constrained at all.
        ("31-witness-open-schema", damaged(witnesses=[
            dict(base["witnesses"][0], surprise="an unpermitted witness key")]
            + base["witnesses"][1:])),
        # Renamed in the policy too, so correspondence holds and only the
        # length bound can refuse this file.
        ("32-witness-name-too-long", damaged(
            witnesses=[dict(base["witnesses"][0], name="w" * 65)] + base["witnesses"][1:],
            policy=_policy_with(rename="w" * 65))),
        ("33-log-url-empty-string", damaged(log_urls=[""])),
        ("34-anchor-missing-member", damaged(
            anchor={"type": "opentimestamps", "mode": "advisory"})),
        ("35-anchor-unknown-mode", damaged(
            anchor={"type": "opentimestamps", "max_lag": 86400, "mode": "enforcing"})),
        ("36-policy-log-key-mismatch", damaged(
            policy=_policy_with(log_key=note.vkey(ORIGIN, KEYS["logkey2"].public)))),
        # D21: a verifier key is `name+<keyid>+<data>` and the id is a hash of
        # the name, the key AND the algorithm -- which is what makes a note key
        # and a cosignature key over the same public key two different
        # verifiers. Every shipped key had a correct id, so a reader that never
        # checked one passed the suite.
        # Cold gate run 11, D3. This one was given a different treatment from
        # `11`, `13` and `16` while §12.1 claimed the same: the damaged id was
        # left out of the policy, so the `log`-line correspondence rule refused
        # the file and `TrustNoKeyIDCheck` -- a loader that takes a declared id
        # as an opaque label -- passed all 622 checks. The damage goes in both
        # halves now, so only the id check can refuse it.
        ("37-log-key-id-mismatch", damaged(
            log_key=_vkey_with_wrong_id(),
            policy=_policy_with(log_key=_vkey_with_wrong_id()))),
        # D9, the composite `37` alone cannot close. §7 makes a key id bind the
        # name, and §10's cosignature match leans on that -- but only while
        # somebody recomputes the id. With `TrustNoKeyIDCheck` and a line
        # matched on the id alone, a reader has verified nothing about the
        # name, and no shipped file carried a mis-declared WITNESS id.
        # Cold gate run 11, D7. §9.1 says the log key's note name MUST EQUAL
        # the origin, and `LogKeyNamePrefix` -- a prefix match -- passed all
        # 622 checks, because `11` uses `someone/else`, which is a prefix of
        # nothing. The name here is the origin plus one base32 character, so
        # only equality can refuse it; the policy carries it too, or the
        # correspondence rule decides instead (the lesson `37` taught).
        ("40-log-key-name-suffix", damaged(
            log_key=note.vkey(ORIGIN + "a", KEYS["logkey"].public),
            policy=_policy_with(log_key=note.vkey(ORIGIN + "a", KEYS["logkey"].public)))),
        ("39-witness-key-id-mismatch", damaged(
            witnesses=[dict(base["witnesses"][0], key=_witness_vkey_with_wrong_id("pi"))]
            + [dict(w) for w in base["witnesses"][1:]],
            policy=_policy_with(witness_key=("pi", _witness_vkey_with_wrong_id("pi"))))),
        # Cold gate run 9, D8. §9.1 states MAX_TRUST_BYTES and nothing in the
        # suite was ever close, so a reader with no cap -- or a cap of a
        # million -- passed everything. Padded with *valid* `log_urls`, whose
        # count nothing bounds, so the file is correct in every other respect
        # and only its size can refuse it.
        ("38-oversize", damaged(log_urls=base["log_urls"] + [
            f"https://mirror{i}.norn.example/testnet" for i in range(2000)])),
        # Cold gate run 12, D16. `38-oversize` is thousands of bytes over, so
        # a cap one byte too lax passed. Exactly one byte past, and correct in
        # every other respect: only the size refuses it.
        ("41-one-past-the-cap", trust_of_size(trust.MAX_TRUST_BYTES + 1)),
        # D10(b): all names correspond and only pi's key differs between the
        # witness array and policy. The stranger key is valid and unique.
        ("42-witness-key-mismatch", damaged(
            witnesses=[dict(base["witnesses"][0], key=note.vkey(
                "norn-witness/stranger", KEYS["stranger"].public,
                note.ALG_COSIGNATURE))] + [dict(w) for w in base["witnesses"][1:]])),
        # D10(c): the required anchor members remain intact; only an unknown
        # nested member violates the closed-map rule.
        ("43-anchor-unknown-member", damaged(anchor={
            "type": "opentimestamps", "max_lag": 86400, "mode": "advisory",
            "note": "unexpected",
        })),
        # D14a/D-062. A verifier key holds 33 bytes (algorithm plus Ed25519
        # public key), so its base64 has no padding bits. Go's decoder ignored
        # a CR inside the data. The policy's optional log line is omitted here
        # so correspondence cannot refuse this file instead; removing only
        # the CR then leaves a valid trust anchor.
        ("44-log-key-base64-cr", damaged(
            log_key=_vkey_with_ignored_cr(log_vkey()),
            policy="".join(line for line in base["policy"].splitlines(keepends=True)
                           if not line.startswith("log ")))),
        # Cold gate run 13, D18. Isolated the way `13` is: one letter of the
        # origin changes case, `log_key` is renamed to agree with it, and the
        # policy carries that renamed key, so the name rule and the
        # correspondence rule both agree and ONLY "`origin` MUST equal
        # `norn/` + lowercase unpadded base32(`net`)" can refuse it. A reader
        # that derives the origin and compares it case-insensitively accepts
        # this file (run 13's `trust-origin-casefold`).
        ("45-origin-case-changed", damaged(
            origin=cased,
            log_key=note.vkey(cased, KEYS["logkey"].public),
            policy=_policy_with(log_key=note.vkey(cased, KEYS["logkey"].public)))),
        # The other half of the same survivor: `origin` is honest and the log
        # key's note name differs from it only in the case of one letter, the
        # policy carrying that key too, so ONLY "its note name MUST equal
        # `origin`" can refuse it. `11` and `40` differ by more than case, so a
        # reader comparing the name case-insensitively passed both.
        ("46-log-key-name-case-changed", damaged(
            log_key=note.vkey(cased, KEYS["logkey"].public),
            policy=_policy_with(log_key=note.vkey(cased, KEYS["logkey"].public)))),
        # D-074 (d): the policy carries pi's own public key under another key
        # name -- a valid verifier key, its id recomputed -- and the witness
        # entry is honest. Compared as parsed public keys the two halves agree;
        # compared as verifier keys, which §9.1 says and §10's matching needs,
        # they name different keys, and only correspondence refuses the file.
        ("48-policy-witness-key-renamed", damaged(
            policy=_policy_with(witness_key=("pi", note.vkey(
                "norn-witness/pi-alt", note.parse_vkey(base["witnesses"][0]["key"]).public,
                note.ALG_COSIGNATURE))))),
        # D-074 (f): a key id is lowercase hex and a key name is one or more
        # ASCII bytes 0x21-0x7E without '+'. Each breaks one of those on pi's
        # key, carried into the policy too, so only that rule refuses it. No
        # case carries U+001C, the character the two implementations once
        # disagreed on: §9.1 forbids control bytes anywhere in policy text, so
        # a trust file with it in a key name is refused by that rule as well,
        # and the key-name tests in both implementations pin it instead.
        ("49-witness-key-id-uppercase", damaged(
            witnesses=[dict(base["witnesses"][0], key=_vkey_with_uppercase_id(base["witnesses"][0]["key"]))]
            + [dict(w) for w in base["witnesses"][1:]],
            policy=_policy_with(witness_key=("pi", _vkey_with_uppercase_id(base["witnesses"][0]["key"]))))),
        ("50-witness-key-name-not-ascii", damaged(
            witnesses=[dict(base["witnesses"][0], key=_pi_key_named("norn-witness/p\u00ed"))]
            + [dict(w) for w in base["witnesses"][1:]],
            policy=_policy_with(witness_key=("pi", _pi_key_named("norn-witness/p\u00ed"))))),
    ]


def _vkey_with_uppercase_id(vkey: str) -> str:
    name, key_id, data = vkey.split("+", 2)
    if key_id.upper() == key_id:
        raise ValueError("this key id has no letter whose case could change")
    return f"{name}+{key_id.upper()}+{data}"


def _pi_key_named(name: str) -> str:
    """pi's own cosigning key under another name, its id recomputed."""
    return note.vkey(name, note.parse_vkey(witness_vkey("pi")).public, note.ALG_COSIGNATURE)


def _vkey_with_ignored_cr(vkey: str) -> str:
    name, key_id, data = vkey.split("+", 2)
    if len(data) != 44 or "=" in data:
        raise ValueError("fixture verifier-key data must encode exactly 33 bytes")
    return f"{name}+{key_id}+{data[:12]}\r{data[12:]}"


def _vkey_with_wrong_id() -> str:
    """The log's verifier key with one hex digit of its key id flipped.

    Everything else about it is correct: the name is the origin, the algorithm
    is a note key, the public key is the one the log signs with. Only the id
    disagrees, so only the id check can refuse it.
    """
    name, key_id, data = log_vkey().split("+", 2)
    flipped = ("1" if key_id[0] != "1" else "2") + key_id[1:]
    return "+".join([name, flipped, data])


def _witness_vkey_with_wrong_id(name: str) -> str:
    """A witness's verifier key with one hex digit of its key id flipped.

    The name, the algorithm and the public key are all correct, so only the id
    check can refuse it -- provided the same string goes into the policy too
    (run 11, D3 is the case where it did not).
    """
    label, key_id, data = witness_vkey(name).split("+", 2)
    flipped = ("1" if key_id[0] != "1" else "2") + key_id[1:]
    return "+".join([label, flipped, data])


def _policy_with(**subs: str) -> str:
    """`policy_text()` with a `witness` renamed or the `log` key replaced.

    A trust negative about one member must leave the policy/witness
    correspondence intact, or that rule decides instead -- the defect 6.5h-vi-b
    found in `07` and `08` and run 8 found again in `15`.
    """
    rename, log_key = subs.get("rename"), subs.get("log_key")
    witness_key = subs.get("witness_key")
    lines = []
    for line in policy_text().split("\n"):
        fields = line.split(" ")
        if log_key and fields[0] == "log":
            fields[1] = log_key
        if witness_key and fields[0] == "witness" and fields[1] == witness_key[0]:
            fields[2] = witness_key[1]
        if rename and fields[0] == "witness" and fields[1] == "pi":
            fields[1] = rename
        if rename and fields[0] == "group":
            fields = [f if f != "pi" else rename for f in fields]
        lines.append(" ".join(fields))
    return "\n".join(lines)


def trust_acceptances() -> list[tuple[str, dict[str, Any]]]:
    """Trust files §9.1 permits, which only a positive can show.

    These pin optional witness URLs, unknown advisory anchor types, and
    application-specific URL text that the trust parser leaves opaque.
    """
    base = trust_file()
    without_url = [{k: v for k, v in base["witnesses"][0].items() if k != "url"}]
    urls = dict(base)
    urls["log_urls"] = ["http://[invalid"]
    urls["witnesses"] = [dict(w) for w in base["witnesses"]]
    urls["witnesses"][0]["url"] = ""
    urls["witnesses"][1]["url"] = "http://[invalid"
    urls["policy"] = base["policy"].replace(LOG_URLS[0], "http://[invalid", 1).replace(
        WITNESS_URLS["vps"], "http://other.invalid", 1)
    return [
        ("witness-without-url", dict(base, witnesses=without_url + base["witnesses"][1:])),
        ("url-fields-are-opaque", urls),
        # Anchoring is advisory (D-009): a reader that cannot check an unknown
        # type simply does not check it. An unknown `mode` is different and is
        # refused, because an unrecognised enforcement mode is not ignorable.
        ("anchor-unknown-type", dict(base, anchor={
            "type": "roughtime", "max_lag": 86400, "mode": "advisory"})),
        # D16: `anchor` is the one member §9.1 marks OPTIONAL, and all forty
        # trust files carried one -- so a reader that required it rejected
        # nothing in the suite.
        ("no-anchor", {k: v for k, v in base.items() if k != "anchor"}),
        # Cold gate run 12, D16: exactly MAX_TRUST_BYTES, which a cap one byte
        # too strict refuses.
        ("at-the-cap", trust_of_size(trust.MAX_TRUST_BYTES)),
    ]


def trust_of_size(target: int) -> dict[str, Any]:
    """The fixture's trust file, padded to exactly `target` encoded bytes.

    Padded the way `38-oversize` is, with *valid* `log_urls` -- whose count
    nothing bounds -- so the file is correct in every respect but its size:
    mirrors up to a little under the target, then one filler URL whose length
    makes up the rest exactly.
    """
    base = trust_file()

    def encoded(urls: list[str]) -> int:
        return len(trust.encode(dict(base, log_urls=urls)))

    mirrors = [f"https://mirror{i}.norn.example/testnet" for i in range(target // 32)]
    # The most mirrors that still leave room for a filler: measured, not
    # estimated -- CBOR's header sizes change with lengths and counts.
    lo, hi = 0, len(mirrors)
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if encoded(base["log_urls"] + mirrors[:mid]) + 300 <= target:
            lo = mid
        else:
            hi = mid - 1
    urls = base["log_urls"] + mirrors[:lo]
    filler = 100
    for _ in range(8):
        doc = dict(base, log_urls=urls + ["https://pad.norn.example/" + "p" * filler])
        gap = target - len(trust.encode(doc))
        if gap == 0:
            return doc
        filler += gap
    raise ValueError(f"cannot pad the trust file to exactly {target} bytes")


def _policy_with_pi_note_key() -> str:
    """`policy_text()` with `pi`'s verifier key replaced by its NOTE key.

    So that `15-witness-key-is-a-note-key` corresponds with its own policy and
    only §9.1's "a witness key is a cosignature key" can refuse it. The policy
    grammar does not constrain key algorithms -- that is the trust file's rule,
    which is exactly the one under test.
    """
    wrong = note.vkey("norn-witness/pi", KEYS["witness-pi"].public)
    lines = []
    for line in policy_text().split("\n"):
        fields = line.split(" ")
        if len(fields) >= 3 and fields[0] == "witness" and fields[1] == "pi":
            fields[2] = wrong
            line = " ".join(fields)
        lines.append(line)
    return "\n".join(lines)


_REMOVE = object()


# -- isolating encoding negatives (SPEC §4.0) ----------------------------
#
# A negative that puts a forbidden item where a typed field lives is
# over-determined: an implementation with strict typing rejects it for the type
# and never exercises the encoding rule. Every case below decodes to the SAME
# valid entry under a lenient decoder, so only enforcement of the encoding rule
# rejects it. `decode_leniently` proves that rather than asserting it.

def profile_base(after: int) -> bytes:
    """A plain, valid note entry: the thing each negative is a patch of."""
    env = entry.new("note", NET, ts=T0 + 9000, after=after, body={"text": "profile probe"})
    return entry.encode(_signed(env, [("signer1", "signer")]))


def _tag_the_value(raw: bytes, key: str) -> bytes:
    """Wrap a value in CBOR tag 0. A decoder that unwraps tags sees no change."""
    needle = cbor.encode(key)
    at = raw.index(needle) + len(needle)
    return raw[:at] + b"\xc0" + raw[at:]


def _indefinite_text(raw: bytes, value: str) -> bytes:
    """Re-encode a text string as an indefinite-length chunked string."""
    body = value.encode("utf-8")
    definite = cbor.encode(value)
    chunked = b"\x7f" + cbor.encode(value[:1]) + cbor.encode(value[1:]) + b"\xff"
    assert definite in raw
    return raw.replace(definite, chunked, 1)


def _indefinite_map(raw: bytes) -> bytes:
    """Re-encode the envelope map with an indefinite length and a break."""
    assert raw[0] >> 5 == 5, "expected a definite-length map header"
    return b"\xbf" + raw[1:] + b"\xff"


def _patch_nonshortest_length(raw: bytes) -> bytes:
    """Widen a text string's *length header*: `6d` becomes `78 0d`.

    The same string, the same value, an encoding RFC 8949 §4.2.1 does not
    permit. `_patch_nonshortest` above patches an integer, which is the only
    reading of "shortest form" a reader gets from §4.0's Integers row -- and a
    reader who stops there accepts this file, so one logical entry has several
    legal encodings (cold gate run 10, D7).
    """
    value = "profile probe".encode("utf-8")
    definite = bytes([0x60 | len(value)]) + value
    assert definite in raw, "the body text is not a one-byte-header string"
    return raw.replace(definite, b"\x78" + bytes([len(value)]) + value, 1)


def _duplicate_key(raw: bytes) -> bytes:
    """Repeat a key-value pair. Last-wins decoders see an identical entry."""
    pair = cbor.encode("v") + cbor.encode(entry.VERSION)
    at = raw.index(pair)
    count = raw[0] & 0x1F
    assert count < 23, "map header must stay one byte"
    return bytes([0xA0 | (count + 1)]) + raw[1:at] + pair + raw[at:]


def enrollreq_new_with_net(net: bytes, device: str, signer: str | None = None) -> bytes:
    """An enrollment request for another network.

    Signed by the device, so the only thing wrong with the entry carrying it is
    that the request's `net` is not the entry's -- SPEC 5.1's check, which
    nothing exercised because the one net negative patched the envelope
    instead. `signer` names another key to sign with, which makes the request
    wrong in the *second* way as well and so pins which check runs first.
    """
    from . import enrollreq
    request = enrollreq.new(net=net, device_id=device, device_pk=KEYS[device].public,
                            wg_pk=WG[device], ts=T0)
    enrollreq.sign(request, KEYS[signer or device], strict=signer is None)
    return enrollreq.encode(request)


def _entry_raw(b: Any, kind: str) -> bytes:
    """The bytes of the first accepted entry of this type, already in the log.

    Taken from the log rather than rebuilt, so the duplicate really is the
    entry the log applied -- a fresh one would differ in `ts` and prove
    nothing about replaying the same entry twice.
    """
    for item in b.items:
        if item.reason:
            continue
        if cbor.decode(item.raw).get("t") == kind:
            return item.raw
    raise SystemExit(f"no accepted {kind} entry to duplicate")


def _oversize_map_key(raw: bytes) -> bytes:
    """Grow a 23-byte label key to 24, past the profile cap.

    A lenient decoder reads a 24-byte text key happily, so only the cap rejects
    this. The key lives in `labels`, whose values are free-form, rather than in
    a schema position where a closed-schema check would fire first.
    """
    key = "k" * 23
    definite = cbor.encode(key)
    assert definite in raw
    return raw.replace(definite, b"\x78\x18" + key.encode() + b"k", 1)


def _invalid_utf8(raw: bytes) -> bytes:
    """Corrupt one byte inside a text string. Lenient decoders substitute."""
    definite = cbor.encode("profile probe")
    assert definite in raw
    return raw.replace(definite, definite[:2] + b"\xff" + definite[3:], 1)


def _integer_too_large(raw: bytes, ts: int) -> bytes:
    """Re-encode `ts` above 2**63-1. A lenient decoder reads a big int."""
    needle = cbor.encode("ts") + cbor.encode(ts)
    assert needle in raw, "ts value not found"
    return raw.replace(
        needle, cbor.encode("ts") + b"\x1b\xff\xff\xff\xff\xff\xff\xff\xff", 1)


def _unsorted_sigs(raw: bytes) -> bytes:
    """Swap two signature maps so `sigs` is no longer ordered by kid."""
    env = cbor.decode(raw)
    assert len(env["sigs"]) == 2, "needs exactly two signatures"
    first, second = (cbor.encode(x) for x in env["sigs"])
    assert first + second in raw
    return raw.replace(first + second, second + first, 1)


def labelled_base(after: int) -> bytes:
    """A valid enrolment whose request carries a 23-byte label key.

    The oversize-key control moved into the request with the labels: after
    SPEC §4.3 put the device's consent in the body, no *entry* body has a
    free-form map left, so the cap is exercised where free-form keys still
    exist. `requests-bad/oversize-label-key` is the rejecting half.
    """
    env = entry.new("enroll", NET, ts=T0 + 9000, after=after,
                    body=_enroll_body("labelcap", labels={"k" * 23: "at the cap"}))
    return entry.encode(_signed(env, [("signer1", "signer"), ("signer3", "signer")]))


def _copy_with_extra_signature(raw: bytes) -> bytes:
    """The same signed content with one unresolvable signature appended.

    Sorted last, so the sigs-ordering rule does not refuse it first; a zero
    signature under a `kid` nothing resolves is ignored (§5.2), not fatal.
    """
    env = cbor.decode(raw)
    junk = {"kid": "f" * 16, "role": "signer", "sig": bytes(64)}
    env["sigs"] = sorted(env["sigs"] + [junk], key=lambda s: s["kid"])
    return entry.encode(env)


def _copy_with_role_relabelled(raw: bytes) -> bytes:
    """The same signed content with the first signature's role changed."""
    env = cbor.decode(raw)
    env["sigs"][0]["role"] = "root" if env["sigs"][0]["role"] != "root" else "signer"
    return entry.encode(env)


def _copy_with_surplus_dropped(raw: bytes) -> bytes:
    """The same signed content with every signature but the first dropped."""
    env = cbor.decode(raw)
    env["sigs"] = env["sigs"][:1]
    return entry.encode(env)


def two_sig_base(after: int) -> bytes:
    """A valid note with two signatures: the sigs-ordering control.

    Its text differs from `profile_base`'s on purpose: since D-070 two entries
    with one signed content are one entry, and a control that is itself
    `dup-entry` controls nothing.
    """
    env = entry.new("note", NET, ts=T0 + 9000, after=after, body={"text": "two-signature probe"})
    return entry.encode(_signed(env, [("signer1", "signer"), ("root1", "root")]))


def _patched_and_signed(after: int, patch, body: dict[str, Any] | None = None,
                        kind: str = "note",
                        signers: list[tuple[str, str]] | None = None) -> bytes:
    """Apply `patch` to an entry and sign the PATCHED preimage.

    Patching a byte inside the preimage and keeping the original signature
    makes the vector over-determined: it is then rejected for the broken
    signature, not for the encoding rule it names. Signing afterwards leaves
    the rule as the only fault. `patch` is applied identically to the
    with-signatures and without-signatures encodings, which is safe because it
    only ever rewrites a value, never a map header.
    """
    signers = signers or [("signer1", "signer")]
    body = body if body is not None else {"text": "profile probe"}
    env = entry.new(kind, NET, ts=T0 + 9000, after=after, body=body)
    unsigned = {k: v for k, v in env.items() if k != "sigs"}
    preimage = entry.PREIMAGE_PREFIX + patch(cbor.encode(unsigned))
    env["sigs"] = sorted(
        ({"kid": KEYS[n].id, "role": r, "sig": KEYS[n].sign(preimage)}
         for n, r in signers),
        key=lambda sig: sig["kid"])
    return patch(cbor.encode(env))


def profile_negatives(base_after: int) -> list[tuple[str, bytes]]:
    base = profile_base(base_after)
    both = [("signer1", "signer"), ("signer3", "signer")]
    return [
        # Patches outside the preimage, or that leave it byte-identical: the
        # original signatures stay valid, so the encoding rule is the only fault.
        ("tag-wrapped-value", _tag_the_value(base, "ts")),
        ("indefinite-text", _indefinite_text(base, "profile probe")),
        ("indefinite-map", _indefinite_map(base)),
        ("duplicate-map-key", _duplicate_key(base)),
        ("cbor-nonshortest-length", _patch_nonshortest_length(base)),
        # Patches inside the preimage: re-signed afterwards (see above).
        ("invalid-utf8", _patched_and_signed(base_after, _invalid_utf8)),
        ("integer-too-large", _patched_and_signed(
            base_after, lambda raw: _integer_too_large(raw, T0 + 9000))),
        # `oversize-map-key` lives in `requests-bad/` now: after SPEC §4.3 put
        # the device's consent in the body, no *entry* body has a free-form map
        # left, and the cap has to be tested where a free-form key can still be
        # written without a closed-schema check firing first.
        ("unsorted-sigs", _unsorted_sigs(two_sig_base(base_after))),
    ]


def decode_leniently(raw: bytes) -> dict[str, Any]:
    """A permissive CBOR reader: unwraps tags, joins chunks, last key wins.

    Exists only to demonstrate that each negative above is a valid entry to a
    decoder that skips the encoding rules -- i.e. that the vector tests the rule
    and nothing else.
    """
    pos = 0

    def head() -> tuple[int, int]:
        nonlocal pos
        initial = raw[pos]; pos += 1
        major, extra = initial >> 5, initial & 0x1F
        if extra < 24:
            return major, extra
        if extra == 31:
            return major, -1
        size = 1 << (extra - 24)
        n = int.from_bytes(raw[pos:pos + size], "big"); pos += size
        return major, n

    def value() -> Any:
        nonlocal pos
        major, n = head()
        if major == 6:
            return value()
        if major == 0:
            return n
        if major in (2, 3):
            if n == -1:
                out = b"" if major == 2 else ""
                while raw[pos] != 0xFF:
                    out += value()
                pos += 1
                return out
            chunk = raw[pos:pos + n]; pos += n
            return chunk if major == 2 else chunk.decode("utf-8", errors="replace")
        if major == 4:
            if n == -1:
                out = []
                while raw[pos] != 0xFF:
                    out.append(value())
                pos += 1
                return out
            return [value() for _ in range(n)]
        if major == 5:
            out: dict[str, Any] = {}
            if n == -1:
                while raw[pos] != 0xFF:
                    k = value(); out[k] = value()
                pos += 1
                return out
            for _ in range(n):
                k = value(); out[k] = value()
            return out
        if major == 7:
            return {20: False, 21: True}.get(n)
        raise ValueError(f"major {major}")

    return value()


def forged_signature_negatives(after: int) -> list[tuple[str, bytes]]:
    """Signatures that are syntactically perfect and cryptographically wrong.

    Without these, an implementation that never calls Ed25519 at all reproduces
    the whole manifest -- gate run 4 demonstrated exactly that. The kid resolves
    in the declared role and the signature is 64 bytes, so only verification
    itself separates these from valid entries.
    """
    def forge(sig: dict[str, Any]) -> dict[str, Any]:
        flipped = bytearray(sig["sig"])
        flipped[0] ^= 0x01
        return {**sig, "sig": bytes(flipped)}

    note_env = entry.new("note", NET, ts=T0 + 9000, after=after, body={"text": "forged"})
    entry.sign(note_env, KEYS["signer1"], "signer")
    note_env["sigs"] = [forge(note_env["sigs"][0])]

    # The device's consent is the embedded request (SPEC §4.3), so the forgery
    # that matters is a request whose signature is the right shape and wrong.
    from . import enrollreq
    request = enrollreq.new(net=NET, device_id="forged",
                            device_pk=KEYS["halfsigned"].public, wg_pk=WG["halfsigned"],
                            ts=T0 + 9000)
    enrollreq.sign(request, KEYS["halfsigned"])
    request["sig"] = bytes(b ^ 0x01 for b in request["sig"])
    enrol = entry.new("enroll", NET, ts=T0 + 9000, after=after,
                      body={"request": enrollreq.encode(request)})
    _signed(enrol, [("signer1", "signer"), ("signer3", "signer")])

    return [
        ("forged-signer-sig", cbor.encode(note_env)),
        ("forged-device-sig", cbor.encode(enrol)),
    ]


def field_negatives() -> list[tuple[str, bytes]]:
    """Field constraints from §4.0 that had no rejecting vector.

    Since SPEC §4.3 moved the device's claims into the embedded request, these
    are faults *inside* the request: a `device_id` the §2 grammar forbids, a
    short key. The entry around each one is well formed and properly signed by
    two signers, so only validating the request itself rejects them -- an
    implementation that treats `request` as opaque bytes accepts all three.
    """
    def enrol(body: dict[str, Any]) -> bytes:
        env = entry.new("enroll", NET, ts=T0 + 9000, after=62, body=body)
        return entry.encode(_signed(env, [("signer1", "signer"), ("signer3", "signer")]))

    ok = {"v": 1, "ts": T0 + 9000, "net": NET, "device_id": "probe",
          "device_pk": KEYS["spare"].public, "wg_pk": WG["rogue"]}

    # Run 11, D6: multi-byte, so 4097 bytes and 2049 characters -- over the
    # 4096-byte cap and far under it counted in runes. Cold gate run 12, D16:
    # it was 4098, so a cap of 4097 refused it too; 4097 is one byte past.
    long_note = entry.new("note", NET, ts=T0 + 9000, after=62,
                          body={"text": "é" * 2048 + "a"})
    _signed(long_note, [("signer1", "signer")])

    bad_sig = entry.new("note", NET, ts=T0 + 9000, after=62, body={"text": "short sig"})
    _signed(bad_sig, [("signer1", "signer")])
    bad_sig["sigs"][0]["sig"] = bad_sig["sigs"][0]["sig"][:63]

    return [
        ("device_id-uppercase",
         enrol(_raw_enroll_body(dict(ok, device_id="Probe"), "spare"))),
        ("device_id-leading-dot",
         enrol(_raw_enroll_body(dict(ok, device_id=".probe"), "spare"))),
        ("pk-length",
         enrol(_raw_enroll_body(dict(ok, device_pk=KEYS["spare"].public[:31]), "spare"))),
        ("sig-length", cbor.encode(bad_sig)),
        ("text-too-long", entry.encode(long_note)),
    ]


# -- enrollment requests (SPEC §16) ---------------------------------------

def _request(device: str, key_name: str, wg_name: str, ts_offset: int,
             **extra: Any) -> dict[str, Any]:
    from . import enrollreq
    req = enrollreq.new(net=NET, device_id=device, device_pk=KEYS[key_name].public,
                        wg_pk=WG[wg_name], ts=T0 + ts_offset, **extra)
    return enrollreq.sign(req, KEYS[key_name])


def _padding_request() -> dict[str, Any]:
    """A valid 203-byte request whose 5-bit encoding has one padding bit."""
    return _request("pi-ca", "pi-cam", "pi-cam", 10)


def _label_cap_request() -> dict[str, Any]:
    """A valid request with one label value exactly 256 UTF-8 bytes long."""
    return _request("pi-cam", "pi-cam", "pi-cam", 10,
                    labels={"ip": "é" * 128})


def enroll_requests() -> list[tuple[str, dict[str, Any]]]:
    """Requests a signer MUST accept, once it has verified the signature."""
    return [
        ("req-minimal", _request("pi-cam", "pi-cam", "pi-cam", 10)),
        ("req-labelled", _request("laptop", "laptop", "laptop", 20,
                                  labels={"ip": "10.9.0.11/32", "owner": "franco"},
                                  expires=T0 + 30 * 86400)),
        # Mirrors `enroll-unicode-labels`: the text form must survive a label
        # that is not ASCII, because canonical JSON and CBOR disagree about
        # what "length" means for one (SPEC §14.2).
        ("req-unicode", _request("nas", "nas", "nas", 30,
                                 labels={"site": "buenos-aires ñ", "emoji": "\U0001f512"})),
        # §2 boundary: 64 bytes is the longest device_id there is.
        ("req-long-id", _request("d" + "e" * 63, "printer", "printer", 40)),
        # D15: 8*203 mod 5 = 4, so its text form has one zero padding bit.
        ("req-padding-base", _padding_request()),
        # D16: exactly 256 UTF-8 bytes, distinct from a 256-character limit.
        ("req-label-at-cap", _label_cap_request()),
        # D18a: reserved label names do not make their advisory values a
        # second schema; the signed request remains valid with opaque text.
        ("req-reserved-hints", _request(
            "pi-cam", "pi-cam", "pi-cam", 50,
            labels={"ip": "not-a-cidr", "endpoint": "not-an-endpoint"})),
        # Run 13, D17: `labels` is "≤ 32 entries", and no request carried more
        # than two, so a reader whose cap was 31 passed. Thirty-two.
        ("req-labels-at-the-cap", _request(
            "pi-cam", "pi-cam", "pi-cam", 60,
            labels={f"k{i:02d}": "v" for i in range(32)})),
    ]


def request_negatives() -> list[tuple[str, str, str]]:
    """(name, text form, why) — every one MUST be refused.

    Returned as text because that is the form a signer is handed: a QR or a
    pasted string. Structural cases are encoded into a *valid* bech32m wrapper,
    so the wrapper never masks the rejection the case is about.
    """
    from . import bech32m, enrollreq

    def text(req: dict[str, Any]) -> str:
        return bech32m.encode(enrollreq.HRP, cbor.encode(req))

    def mutate(resign: bool = True, **over: Any) -> str:
        """Patch a valid request, and re-sign it over the patched preimage.

        Re-signing is the default because a negative that names a field rule
        must fail for *that* rule: SPEC §4.0 states the standard for the entry
        profile, and until 6.5g-vi nothing applied it here, so eleven of
        fifteen field negatives were refused by Ed25519 before their own rule
        was reached. `resign=False` is for the cases that are *about* the
        signature, where a valid one would defeat the point.
        """
        req = dict(_request("pi-cam", "pi-cam", "pi-cam", 10))
        for key, value in over.items():
            if value is _ABSENT:
                req.pop(key)
            else:
                req[key] = value
        if resign and "sig" in req:
            enrollreq.sign(req, KEYS["pi-cam"], strict=False)
        return text(req)

    good = _request("pi-cam", "pi-cam", "pi-cam", 10)
    base = cbor.encode(good)
    _pad_excess, _pad_nonzero = _padding_negatives(_padding_request())

    # A request whose signature is by another key: syntactically perfect and
    # cryptographically wrong. Without it, a decoder that never calls Ed25519
    # passes this whole directory -- the lesson of `bad-forged-signer-sig`.
    forged = dict(good)
    forged["sig"] = KEYS["nas"].sign(enrollreq.preimage(good))

    # RFC 8032 signing, except that R carries an order-8 component. The
    # challenge covers that R, not the honest one: this signature satisfies
    # the cofactored equation and fails the cofactorless one by exactly -T.
    torsion = dict(good)
    key = KEYS["pi-cam"]
    expanded = bytearray(hashlib.sha512(key.seed).digest())
    expanded[0] &= 248
    expanded[31] = (expanded[31] & 63) | 64
    a = int.from_bytes(expanded[:32], "little")
    message = enrollreq.preimage(torsion)
    r = int.from_bytes(hashlib.sha512(bytes(expanded[32:]) + message).digest(), "little") % keys.L
    honest_R = crypto_scalarmult_ed25519_base_noclamp(r.to_bytes(32, "little"))
    mixed_R = crypto_core_ed25519_add(honest_R, ORDER_EIGHT)
    k = int.from_bytes(hashlib.sha512(mixed_R + key.public + message).digest(), "little") % keys.L
    torsion["sig"] = mixed_R + ((r + k * a) % keys.L).to_bytes(32, "little")
    raised = dict(good)
    raised["sig"] = good["sig"][:32] + (int.from_bytes(good["sig"][32:], "little") + keys.L).to_bytes(32, "little")

    cases = [
        ("small-order-device-pk", mutate(device_pk=ORDER_EIGHT), "device_pk is not a valid point; its signature cannot verify under NORN-ED25519-v1"),
        ("torsion-R-signature", text(torsion), "signature R has an order-8 component; the cofactored equation holds"),
        ("S-plus-L-signature", text(raised), "signature scalar S + L is not below L"),
        ("unknown-key", mutate(extra=1), "closed schema: an unknown key"),
        ("missing-sig", mutate(resign=False, sig=_ABSENT), "unsigned"),
        ("wrong-version", mutate(v=2), "v is not 1"),
        ("short-net", mutate(net=NET[:8]), "net is not 16 bytes"),
        ("uppercase-device-id", mutate(device_id="Pi-Cam"), "§2 forbids uppercase"),
        ("leading-dash-device-id", mutate(device_id="-cam"), "§2 forbids a leading dash"),
        ("long-device-id", mutate(device_id="d" + "e" * 64), "65 bytes"),
        ("short-device-pk", mutate(device_pk=KEYS["pi-cam"].public[:31]), "not 32 bytes"),
        ("short-wg-pk", mutate(wg_pk=WG["pi-cam"][:31]), "not 32 bytes"),
        ("short-sig", mutate(resign=False, sig=good["sig"][:63]), "the `sig` field is not 64 bytes"),
        ("bool-expires", mutate(expires=True), "a CBOR bool where a uint is required"),
        ("expires-at-ts", _expires_at_ts(), "expires must be after ts"),
        ("empty-labels", mutate(labels={}), "present labels must carry at least one pair"),
        ("too-many-labels", mutate(labels={f"k{i}": "v" for i in range(33)}), "over 32 labels"),
        # Run 13, D17: label keys are 1-23 bytes, and only the top was vectored.
        ("empty-label-key", _empty_label_key(), "a label key of zero bytes, under §4.0's 1-23"),
        # Run 12, D16: 257 bytes but only 129 code points, so the one-past
        # vector distinguishes the byte cap from a character-counting reader.
        ("oversize-label", mutate(labels={"ip": "é" * 128 + "x"}),
         "label over 256 bytes"),
        ("non-string-label", mutate(labels={"ip": 1}), "label value is not text"),
        ("ts-is-text", mutate(ts="now"), "ts is not a uint"),
        ("unsorted-keys", text_of_unsorted(base), "map keys out of §4.0 order"),
        ("oversize-label-key", _oversize_label_key(), "a 24-byte map key, past §4.0's cap"),
        ("forged-signature", text(forged), "valid shape, signed by another key"),
        ("wrong-hrp", bech32m.encode("nrn", base), "the human-readable part is not `norn`"),
        ("plain-bech32", _as_bech32(enrollreq.HRP, base), "bech32, not bech32m"),
        ("mixed-case", _mixed_case(text(good)), "mixed case (SPEC §16.2)"),
        ("corrupt-character", _corrupt(text(good)), "one character changed"),
        ("excess-padding", _pad_excess,
         "six unused bits after an extra zero group, where SPEC 16.2 permits under five"),
        ("non-zero-padding", _pad_nonzero,
         "a padding bit set where SPEC 16.2 requires zero"),
    ]
    return cases


_ABSENT = object()


def text_of_unsorted(raw: bytes) -> str:
    """Swap the first two map entries, then wrap in a valid bech32m string."""
    from . import bech32m, enrollreq
    head = raw[:1]
    first = cbor.encode("v") + cbor.encode(1)
    second = cbor.encode("ts")
    assert raw[1:].startswith(first + second), "unexpected leading map order"
    ts_value = cbor.encode(cbor.decode(raw)["ts"])
    second += ts_value
    rest = raw[1 + len(first) + len(second):]
    return bech32m.encode(enrollreq.HRP, head + second + first + rest)


def _as_bech32(hrp: str, payload: bytes) -> str:
    """The same bytes under bech32's checksum constant instead of bech32m's."""
    from . import bech32m
    data = bech32m._convertbits(list(payload), 8, 5, pad=True)
    polymod = bech32m._polymod(bech32m._hrp_expand(hrp) + data + [0] * 6) ^ 1
    checksum = [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(bech32m.CHARSET[v] for v in data + checksum)


def hostile_inputs() -> list[tuple[str, bytes, str]]:
    """(name, raw bytes, what a decoder must say) — input that is not an entry.

    SPEC §4.0's two resource limits are unreachable by any *valid* entry, which
    is why neither had a vector until cold gate run 5 removed both and passed
    every check. They exist for input like this, so this is what they are
    tested with. Built as raw bytes rather than through the encoder: the
    encoder enforces the profile, and a generator that cannot express the
    hostile case cannot ship it.
    """
    # A byte string whose header promises 65536 bytes. A decoder must refuse it
    # on length alone, before allocating anything the header asked for.
    oversize = b"\x5a\x00\x01\x00\x00" + b"\x00" * 65536

    # 200 nested single-element arrays. Deterministic CBOR throughout; only the
    # depth is hostile, so nothing but the depth limit can refuse it.
    deep = b"\x81" * 200 + b"\x00"

    # Both sides of each limit. Cold gate run 6 enforced 4, 16 and 64 in place
    # of the profile's 8 and passed every vector, because `deep-nesting` only
    # bounds the limit from above: 200 is deeper than any of them. The same for
    # the size cap, whose only case was some 66 KB.
    # The top-level container is depth 1 (SPEC 4.0), so MAX_DEPTH nested
    # containers sit exactly at the limit and one more is past it.
    at_depth = b"\x81" * cbor.MAX_DEPTH + b"\x00"
    past_depth = b"\x81" * (cbor.MAX_DEPTH + 1) + b"\x00"

    # A byte string filling the entry exactly: a 3-byte header (0x59 + uint16)
    # and the rest content.
    at_size = b"\x59" + (cbor.MAX_ENTRY_BYTES - 3).to_bytes(2, "big") + \
        b"\x00" * (cbor.MAX_ENTRY_BYTES - 3)
    past_size = b"\x59" + (cbor.MAX_ENTRY_BYTES - 2).to_bytes(2, "big") + \
        b"\x00" * (cbor.MAX_ENTRY_BYTES - 2)

    # §4.0's third limit: every map key is 1-23 bytes. The signed request
    # negative `requests-bad/oversize-label-key` already reaches this decoder
    # rule before request-field validation. Keep this schema-free one-pair map
    # with a uint value too, so its key length is the only thing that can be
    # wrong.
    # Cold gate run 9, D18: both boundary keys were ASCII, so `1-23 bytes` and
    # `1-23 characters` gave the same answer and `key-cap-runes` passed. These
    # are multi-byte: 11 two-byte characters plus one ASCII is 23 bytes and 12
    # runes, and one more ASCII character is 24 bytes and 13 runes -- which a
    # rune-counting reader accepts and this profile does not.
    at_text = ("\u00e9" * 11 + "k").encode("utf-8")
    past_text = ("\u00e9" * 11 + "kk").encode("utf-8")
    assert len(at_text) == cbor.MAX_KEY_LEN, len(at_text)
    assert len(past_text) == cbor.MAX_KEY_LEN + 1, len(past_text)
    at_key = b"\xa1" + bytes([0x60 + len(at_text)]) + at_text + b"\x00"
    past_key = b"\xa1\x78" + bytes([len(past_text)]) + past_text + b"\x00"

    # Cold gate run 8, D15. Every banned item had a negative *inside an entry*
    # and every one of those is refused by a later rule too -- `65-bad-cbor-null`
    # puts the null in `after`, so a lenient decoder hands the envelope a
    # non-uint `after` and the reason is `decode` either way. The manifest
    # cannot tell the two readings apart, so the profile gets cases with no
    # schema above them to intervene first.
    bare = [
        ("bare-null", b"\xf6", "simple value"),
        ("bare-simple", b"\xf0", "simple value"),
        ("bare-undefined", b"\xf7", "simple value"),
        ("bare-float", b"\xf9\x3c\x00", "float"),
        ("bare-negative-integer", b"\x20", "major type"),
        ("bare-tag", b"\xc0\x00", "major type"),
        ("bare-indefinite-text", b"\x7f\x61\x61\xff", "indefinite"),
        ("bare-nontext-map-key", b"\xa1\x00\x00", "map key must be a text string"),
        ("bare-invalid-utf8", b"\x62\xff\xfe", "UTF-8"),
    ]

    return bare + [
        ("oversize-entry", oversize, "exceeds"),
        ("deep-nesting", deep, "deeper than"),
        ("at-the-depth-limit", at_depth, None),
        ("past-the-depth-limit", past_depth, "deeper than"),
        ("at-the-size-limit", at_size, None),
        ("past-the-size-limit", past_size, "exceeds"),
        ("at-the-key-limit", at_key, None),
        ("past-the-key-limit", past_key, f"map key must be 1-{cbor.MAX_KEY_LEN} bytes"),
    ]


def _expires_at_ts() -> str:
    """`expires == ts`, re-signed so §16.1's rule is the only thing wrong.

    Built by patching a valid request and signing again rather than through
    `enrollreq.new`, which refuses the value at construction -- the reference
    will not build an invalid request by accident, only on purpose.
    """
    from . import bech32m, enrollreq, keys as keymod
    request = dict(_request("pi-cam", "pi-cam", "pi-cam", 10))
    request["expires"] = request["ts"]
    enrollreq.sign(request, KEYS["pi-cam"])
    assert keymod.verify(KEYS["pi-cam"].public, enrollreq.preimage(request), request["sig"])
    return bech32m.encode(enrollreq.HRP, enrollreq.encode(request))


def _oversize_label_key() -> str:
    """A request whose label key is 24 bytes: one past the §4.0 cap.

    A lenient decoder reads a 24-byte text key happily, so only the cap rejects
    this -- and the key is in `labels`, whose keys are free-form, rather than in
    a schema position where a closed-schema check would fire first.
    """
    from . import bech32m, enrollreq, keys as keymod
    request = _request("labelcap", "labelcap", "labelcap", 10,
                       labels={"k" * 23: "at the cap"})
    # SPEC §4.0's construction rule: this patch cannot canonicalise, so the
    # request is re-signed over the *patched* preimage. Without that the file
    # is refused for its broken signature and the cap is never reached -- which
    # is what cold gate run 5 found, having disabled the cap entirely and still
    # passed every vector.
    patched_preimage = _oversize_map_key(enrollreq.preimage(request))
    signature = KEYS["labelcap"].sign(patched_preimage)
    assert keymod.verify(KEYS["labelcap"].public, patched_preimage, signature)
    patched = _oversize_map_key(enrollreq.encode(request))
    assert request["sig"] in patched
    patched = patched.replace(request["sig"], signature, 1)
    return bech32m.encode(enrollreq.HRP, patched)


def _empty_label_key() -> str:
    """A request whose one label key is the empty string (run 13, D17).

    §4.0 bounds map keys at 1-23 bytes and only the top was vectored. The
    encoder here refuses to write a zero-byte key, so it is patched in after
    encoding and the request re-signed over the patched preimage, as
    `_oversize_label_key` does at the other end: only the key's lower bound
    can refuse it.
    """
    from . import bech32m, enrollreq, keys as keymod
    request = _request("pi-cam", "pi-cam", "pi-cam", 10, labels={"empty-key-probe": "v"})
    probe = cbor.encode("empty-key-probe")

    def patch(raw: bytes) -> bytes:
        assert raw.count(probe) == 1
        return raw.replace(probe, cbor.encode(""), 1)

    patched_preimage = patch(enrollreq.preimage(request))
    signature = KEYS["pi-cam"].sign(patched_preimage)
    assert keymod.verify(KEYS["pi-cam"].public, patched_preimage, signature)
    patched = patch(enrollreq.encode(request))
    assert request["sig"] in patched
    patched = patched.replace(request["sig"], signature, 1)
    return bech32m.encode(enrollreq.HRP, patched)


def _padding_negatives(request: dict[str, Any]) -> tuple[str, str]:
    """Two bech32m strings whose *padding* is the only thing wrong.

    SPEC 16.2 requires the payload's padding to be under five bits and zero.
    Both rules were stated and enforced and neither was vectored, so a decoder
    that skipped them passed every file. Built from 5-bit groups directly and
    re-checksummed, so the wrapper is valid and only the padding rule refuses
    them.
    """
    from . import bech32m, enrollreq
    groups = bech32m._convertbits(list(enrollreq.encode(request)), 8, 5, True)

    # Five more bits of padding than the payload needs.
    excess = bech32m.encode_raw(enrollreq.HRP, groups + [0])

    # The same payload with a padding bit set. The last group carries the
    # padding, and the number of padding bits is 5 - (len(payload) * 8) % 5.
    nonzero = list(groups)
    pad_bits = (5 - (len(enrollreq.encode(request)) * 8) % 5) % 5
    if pad_bits == 0:
        raise SystemExit("this payload has no padding bits to corrupt; pick another")
    nonzero[-1] |= 1
    return excess, bech32m.encode_raw(enrollreq.HRP, nonzero)


def _mixed_case(text: str) -> str:
    return text[:8] + text[8:].upper()


def _corrupt(text: str) -> str:
    other = "q" if text[10] != "q" else "p"
    return text[:10] + other + text[11:]
