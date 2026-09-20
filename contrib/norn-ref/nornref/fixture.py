"""The canonical vector fixture: one valid entry per type (SPEC.md §12).

Kept separate from the generator script so tests can import the fixture without
writing files.
"""

from __future__ import annotations

from typing import Any

from . import entry, keys, note, trust

NET = bytes.fromhex("6e6f726e2d746573746e65742d303031")  # "norn-testnet-001"
T0 = 1_760_000_000

ROOTS = ["root1", "root2", "root3"]
SIGNERS = ["signer1", "signer2"]
DEVICES = ["nas", "laptop", "pi-cam"]

WITNESSES = ["pi", "vps", "friend"]

EXTRA_KEYS = (["signer3", "root4", "logkey", "logkey2", "spare", "printer", "nas-id2", "printer-id2", "escaped", "contractor", "halfsigned", "labelcap",
              "rootrevoked", "stranger"]
              + [f"witness-{w}" for w in WITNESSES])

KEYS: dict[str, keys.Ed25519] = {
    name: keys.Ed25519.from_name(name)
    for name in ROOTS + SIGNERS + DEVICES + EXTRA_KEYS
}
WG: dict[str, bytes] = {
    name: keys.x25519_public(name)
    for name in DEVICES + ["laptop2", "nas2", "spare", "printer", "rogue", "escaped", "contractor", "halfsigned", "labelcap", "rootrevoked"]
}

#: Every canonical-JSON escape rule (SPEC §14.2) in one value: the characters
#: that must be escaped, the ones that must NOT be (/ < > & DEL, non-ASCII),
#: and multi-byte UTF-8 including an astral-plane character.
ESCAPE_TORTURE = (
    'quote" backslash\\ slash/ lt< gt> amp& '
    'bs\b tab\t lf\n ff\f cr\r '
    'vt\x0b nul\x00 unit\x1f del\x7f '
    'ntilde-\u00f1 cjk-\u65e5\u672c emoji-\U0001f511 rtl-\u05d0\n'
    'quorum home\n'
)

#: Label keys and values exercising recursive object-key sorting over UTF-8.
UNICODE_LABELS = {
    'ip': '10.9.0.42/32',
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
        "params": {"checkpoint_interval": 60, "staleness": 600, "mmd": 45,
                   "rotate_needs_signer": False},
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
    b.add("00-genesis", genesis())

    b.add("01-enroll-nas", b.build("enroll", _enroll_body("nas"),
                                   [("signer1", "signer")]))
    b.add("02-enroll-laptop", b.build("enroll", _enroll_body(
        "laptop", labels={"ip": "10.9.0.2/32", "endpoint": "192.0.2.10:51820"}),
        [("signer1", "signer")]))
    b.add("03-enroll-pi-cam", b.build("enroll", _enroll_body("pi-cam", expires=T0 + 2_592_000),
                                      [("signer1", "signer")]))

    b.add("04-bad-dup-id", b.build("enroll", _enroll_body("nas", wg="nas2"),
                                   [("signer1", "signer")]), "dup-id")
    b.add("05-bad-dup-wg", b.build("enroll", _enroll_body("spare", wg="nas"),
                                   [("signer1", "signer")]), "dup-wg")
    b.add("06-bad-no-device-sig", b.build("enroll",
                                          _enroll_body("printer", signer="spare"),
                                          [("signer1", "signer")]), "no-device-sig")
    b.add("07-bad-threshold", b.build("enroll", _enroll_body("printer"),
                                      [("printer", "device")]), "threshold")

    b.add("08-rotate-laptop", b.build("rotate", {"device_id": "laptop", "wg_pk": WG["laptop2"]},
                                      [("laptop", "device")]))
    b.add("09-bad-unknown-device", b.build("rotate", {"device_id": "ghost", "wg_pk": WG["rogue"]},
                                           [("nas", "device")]), "unknown-device")
    b.add("10-bad-after", b.build("note", {"text": "signed against a future log size"},
                                  [("signer1", "signer")], after=999), "after")

    b.add("11-revoke-pi-cam", b.build("revoke", {"device_id": "pi-cam", "reason": "decommissioned"},
                                      [("signer1", "signer")]))
    b.add("12-bad-not-active", b.build("revoke", {"device_id": "pi-cam", "reason": "again"},
                                       [("signer1", "signer")]), "not-active")
    b.add_raw("13-bad-dup-entry", b.items[1].raw, "dup-entry")
    b.add("14-bad-dup-genesis", genesis(after=14), "dup-genesis")

    bogus = {"v": entry.VERSION, "t": "bogus", "net": NET, "ts": T0, "after": b.index,
             "body": {"text": "not a real type"}, "sigs": []}
    entry.sign(bogus, KEYS["signer1"], "signer")
    b.add_raw("15-bad-unknown-type", cbor.encode(bogus), "unknown-type")

    b.add("16-signer_add-signer3", b.build("signer_add", {"pk": KEYS["signer3"].public},
                                           [("root1", "root"), ("root2", "root")]))
    b.add("17-bad-dup-key", b.build("signer_add", {"pk": KEYS["signer3"].public},
                                    [("root1", "root"), ("root2", "root")]), "dup-key")
    b.add("18-signer_thr-2", b.build("signer_thr", {"thr": 2},
                                     [("root1", "root"), ("root2", "root")]))
    b.add("19-bad-thr", b.build("signer_thr", {"thr": 99},
                                [("root1", "root"), ("root2", "root")]), "bad-thr")
    b.add("20-bad-unknown-key", b.build("signer_remove", {"kid": KEYS["root4"].id},
                                        [("root1", "root"), ("root2", "root")]), "unknown-key")
    b.add("21-signer_remove-signer2", b.build("signer_remove", {"kid": KEYS["signer2"].id},
                                              [("root1", "root"), ("root3", "root")]))

    b.add("22-root_add-root4", b.build("root_add", {"pk": KEYS["root4"].public},
                                       [("root1", "root"), ("root2", "root")]))
    b.add("23-root_thr-3", b.build("root_thr", {"thr": 3},
                                   [("root1", "root"), ("root2", "root")]))
    roots3 = [("root1", "root"), ("root2", "root"), ("root3", "root")]
    b.add("24-root_remove-root4", b.build("root_remove", {"kid": KEYS["root4"].id}, roots3))
    b.add("25-bad-root-invariant", b.build("root_remove", {"kid": KEYS["root3"].id}, roots3),
          "root-invariant")
    b.add("26-bad-threshold-root", b.build("signer_add", {"pk": KEYS["root4"].public},
                                           [("root1", "root")]), "threshold")

    b.add("27-log_key", b.build("log_key", {"pk": KEYS["logkey2"].public, "overlap": 2_592_000},
                                roots3))
    b.add("28-policy", b.build("policy", {"text": policy_text()}, roots3))
    b.add("29-params", b.build("params", {"staleness": 900, "rotate_needs_signer": True}, roots3))

    both = [("signer1", "signer"), ("signer3", "signer")]
    b.add("30-note", b.build("note", {"text": "quarterly key review completed"},
                             [("signer1", "signer")]))
    b.add("31-enroll-printer", b.build("enroll", _enroll_body("printer"),
                                       both))

    wrong_net = entry.new("note", b"\xff" * 16, ts=T0, after=32, body={"text": "wrong network"})
    entry.sign(wrong_net, KEYS["signer1"], "signer")
    b.add_raw("32-bad-decode-net", entry.encode(wrong_net), "decode")

    b.add("33-enroll-pi-cam-again", b.build("enroll", _enroll_body("pi-cam"),
                                            both))
    b.add("34-bad-rotate-needs-signer", b.build("rotate", {"device_id": "nas", "wg_pk": WG["nas2"]},
                                                [("nas", "device")]), "threshold")
    b.add("35-rotate-nas", b.build("rotate", {"device_id": "nas", "wg_pk": WG["nas2"]},
                                   [("nas", "device")] + both))
    b.add("36-revoke-self-laptop", b.build("revoke", {"device_id": "laptop", "reason": "lost"},
                                           [("laptop", "device")]))
    b.add("37-enroll-spare", b.build("enroll", _enroll_body("spare"),
                                     both))
    b.add("38-note-final", b.build("note", {"text": "end of fixture"}, [("root1", "root")]))
    b.add("39-revoke-spare", b.build("revoke", {"device_id": "spare", "reason": "returned"},
                                     [("signer1", "signer"), ("signer3", "signer")]))

    # D8: a device may rotate its identity key while keeping its WireGuard key
    # (otherwise software-key -> hardware-key migration would churn every peer
    # table), but may never take a key active for another device.
    b.add("40-rotate-device-key-only", b.build("rotate", {
        "device_id": "nas", "wg_pk": WG["nas2"], "device_pk": KEYS["nas-id2"].public},
        [("nas", "device"), ("nas-id2", "device")] + both))
    b.add("41-bad-dup-wg-rotate", b.build("rotate", {
        "device_id": "printer", "wg_pk": WG["nas2"]},
        [("printer", "device")] + both), "dup-wg")

    # Tier-3 answers, each previously undecided by the prose *and* the vectors.
    b.add("42-bad-thr-root", b.build("root_thr", {"thr": 99}, roots3), "bad-thr")       # D11
    b.add("43-bad-revoke-unauthorised", b.build(                                        # D12
        "revoke", {"device_id": "printer", "reason": "no authority"},
        [("laptop", "device")]), "threshold")
    unknown_role = {"v": entry.VERSION, "t": "note", "net": NET, "ts": T0 + 9000,
                    "after": b.index, "body": {"text": "role outside the enum"}, "sigs": []}
    entry.sign(unknown_role, KEYS["signer1"], "signer")
    unknown_role["sigs"][0]["role"] = "admin"
    b.add_raw("44-bad-unknown-role", cbor.encode(unknown_role), "decode")               # D18
    b.add_raw("45-bad-missing-sigs", cbor.encode({                                      # D19
        "v": entry.VERSION, "t": "note", "net": NET, "ts": T0 + 9000, "after": 45,
        "body": {"text": "no sigs key at all"}}), "decode")
    # D20, and D-032: the *current* device key signs, so replay gets past the
    # current-key check and reaches the proof-of-possession rule on the
    # incoming `device_pk`, which nothing signs. Carrying no device signature
    # at all -- as this vector did until 6.5c -- is refused three checks
    # earlier and leaves D-032 untested, which is how gate run 5 deleted the
    # check outright and still passed every vector.
    b.add("46-bad-rotate-no-new-key-sig", b.build(
        "rotate", {"device_id": "printer", "wg_pk": WG["printer"],
                   "device_pk": KEYS["printer-id2"].public},
        [("printer", "device")] + both), "no-device-sig")
    b.add("47-bad-order-enroll", b.build(                                               # D21
        "enroll", _enroll_body("nas", wg="rogue", signer="signer1"),
        both), "no-device-sig")
    b.add("48-bad-order-governance", b.build(                                           # D21
        "signer_add", {"pk": KEYS["signer3"].public}, [("root1", "root")]), "threshold")

    # Canonical-JSON escaping (SPEC §14.2). Every escape rule in one value, so a
    # second implementation cannot pass while disagreeing about `<`, DEL or an
    # emoji -- none of which appear anywhere else in the suite.
    b.add("49-policy-escaping", b.build("policy", {"text": ESCAPE_TORTURE}, roots3))
    b.add("50-enroll-unicode-labels", b.build("enroll", _enroll_body(
        "escaped", labels=UNICODE_LABELS), both))

    # §5.3's `expires` rule needs a device that actually carries one.
    b.add("51-enroll-contractor", b.build("enroll", _enroll_body(
        "contractor", expires=T0 + 7_776_000),
        both))

    # E5: `sigs: []` is well-formed but unauthorised -- `threshold`, not `decode`.
    b.add_raw("52-bad-empty-sigs", cbor.encode({
        "v": entry.VERSION, "t": "note", "net": NET, "ts": T0 + 9000,
        "after": 52, "body": {"text": "well-formed, unsigned"}, "sigs": []}), "threshold")

    # E6: a malformed `kid` is a schema violation, not an unresolvable key.
    bad_kid = entry.new("note", NET, ts=T0 + 9000, after=53, body={"text": "bad kid"})
    entry.sign(bad_kid, KEYS["signer1"], "signer")
    bad_kid["sigs"][0]["kid"] = "NOTHEX"
    b.add_raw("53-bad-kid-format", cbor.encode(bad_kid), "decode")

    # E9: defends D-028. This leaves ONE signer while `signer_thr` is 2 -- the
    # network cannot enrol until roots add a signer, and that is the point:
    # removing a compromised signer key must never be blocked. Placed last so it
    # does not starve earlier entries of signatures.
    b.add("54-signer_remove-below-threshold",
          b.build("signer_remove", {"kid": KEYS["signer3"].id}, roots3))
    # ...and the recovery roots must then perform, which is the other half of
    # the D-028 argument: the degraded state is real but recoverable. Re-adding
    # the same key keeps the fixture's terminal state usable; a real recovery
    # would add a replacement key.
    b.add("55-signer_add-recover",
          b.build("signer_add", {"pk": KEYS["signer3"].public}, roots3))

    # E12: the encoding profile had no negative vectors at all, so a decoder
    # that skipped every profile check scored a clean pass. Each of these is a
    # valid entry patched at the byte level to violate exactly one rule.
    base = entry.encode(_signed(entry.new(
        "note", NET, ts=T0 + 9000, after=56, body={"text": "profile probe"}),
        [("signer1", "signer")]))
    b.add_raw("56-bad-cbor-nonshortest", _patch_nonshortest(base), "decode")
    b.add_raw("57-bad-cbor-null", _patch_null(base), "decode")
    b.add_raw("58-bad-cbor-unsorted-keys", _patch_unsorted(base), "decode")

    # Closed schemas, envelope and body (SPEC §4.1/§4.3). Run 3 shipped a
    # variant leaving bodies open and passed the whole suite -- as did this
    # implementation at the time. Two implementations agreeing by accident is
    # not a pinned rule.
    unknown_env = entry.new("note", NET, ts=T0 + 9000, after=59, body={"text": "x"})
    entry.sign(unknown_env, KEYS["signer1"], "signer")
    unknown_env["extra"] = 1
    b.add_raw("59-bad-unknown-envelope-key", cbor.encode(unknown_env), "decode")
    b.add("60-bad-unknown-body-key", b.build(
        "note", {"text": "x", "surprise": "extra"}, [("signer1", "signer")]), "decode")

    # `thr: 0` -- the half of §5.2's bad-thr clause both other vectors miss,
    # since they use 99. A well-formed uint, so it is bad-thr and not decode.
    b.add("61-bad-thr-zero", b.build("signer_thr", {"thr": 0}, roots3), "bad-thr")

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
    b.add(f"{b.index}-log_key-second", b.build(
        "log_key", {"pk": KEYS["logkey"].public, "overlap": 604_800}, roots3))

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

    def bad_body(name: str, **changes: Any) -> None:
        body = dict(genesis()["body"], **changes)
        env = _signed(entry.new("genesis", NET, ts=T0, body=body),
                      [("root1", "root"), ("root2", "root")])
        raw = entry.encode(env)
        cases.append((name, raw, replay.Anchor(NET, entry.leaf_hash(raw))))

    bad_body("10-duplicate-signer",
             signers=[KEYS["signer1"].public, KEYS["signer1"].public])
    bad_body("11-signer-thr-above-set", signer_thr=9)
    bad_body("12-empty-roots", roots=[])

    assert good_anchor  # the good anchor is exercised by the log fixture
    return cases


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
    return [
        ("01-unknown-key", dict(base, surprise="unexpected member")),
        ("02-wrong-version", damaged(version=2)),
        ("03-short-net", damaged(net=b"\x00" * 8)),
        ("04-origin-mismatch", damaged(origin="norn/wrongorigin")),
        ("05-short-genesis-hash", damaged(genesis_hash=b"\x00" * 8)),
        ("06-bad-log-key", damaged(log_key="not-a-verifier-key")),
        ("07-no-witnesses", damaged(witnesses=[])),
        ("08-duplicate-witness-name", damaged(witnesses=[
            dict(base["witnesses"][0]), dict(base["witnesses"][0])])),
        ("09-policy-without-quorum", damaged(policy="log x\nwitness pi y\n")),
        ("10-missing-policy", damaged(policy=_REMOVE)),
        ("11-log-key-name-mismatch",
         damaged(log_key=note.vkey("someone/else", KEYS["logkey"].public))),
        ("12-witness-key-unparseable",
         damaged(witnesses=[dict(base["witnesses"][0], key="nonsense")])),
        # Isolated: `net` stays 16 bytes and `log_key` is renamed to agree with
        # the wrong origin, so ONLY "origin derives from net" can reject this.
        ("13-origin-only", damaged(
            origin="norn/aaaaaaaaaaaaaaaaaaaaaaaaaa",
            log_key=note.vkey("norn/aaaaaaaaaaaaaaaaaaaaaaaaaa", KEYS["logkey"].public))),
        # Isolated: a missing key that no other rule also catches.
        ("14-missing-name", damaged(name=_REMOVE)),
        # The two kinds of key are not interchangeable: a witness signs
        # cosignatures (algorithm 0x04) and the log signs notes (0x01). A file
        # that mixes them names keys nobody can use, and both directions parse
        # cleanly, so only this rule rejects them.
        ("15-witness-key-is-a-note-key",
         damaged(witnesses=[dict(base["witnesses"][0],
                                 key=note.vkey("norn-witness/pi", KEYS["witness-pi"].public))])),
        ("16-log-key-is-a-cosignature-key",
         damaged(log_key=note.vkey(ORIGIN, KEYS["logkey"].public, note.ALG_COSIGNATURE))),
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
    ]


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


def _duplicate_key(raw: bytes) -> bytes:
    """Repeat a key-value pair. Last-wins decoders see an identical entry."""
    pair = cbor.encode("v") + cbor.encode(entry.VERSION)
    at = raw.index(pair)
    count = raw[0] & 0x1F
    assert count < 23, "map header must stay one byte"
    return bytes([0xA0 | (count + 1)]) + raw[1:at] + pair + raw[at:]


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


def two_sig_base(after: int) -> bytes:
    """A valid note with two signatures: the sigs-ordering control."""
    env = entry.new("note", NET, ts=T0 + 9000, after=after, body={"text": "profile probe"})
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

    long_note = entry.new("note", NET, ts=T0 + 9000, after=62, body={"text": "x" * 4097})
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

    def mutate(**over: Any) -> str:
        req = dict(_request("pi-cam", "pi-cam", "pi-cam", 10))
        for key, value in over.items():
            if value is _ABSENT:
                req.pop(key)
            else:
                req[key] = value
        return text(req)

    good = _request("pi-cam", "pi-cam", "pi-cam", 10)
    base = cbor.encode(good)

    # A request whose signature is by another key: syntactically perfect and
    # cryptographically wrong. Without it, a decoder that never calls Ed25519
    # passes this whole directory -- the lesson of `bad-forged-signer-sig`.
    forged = dict(good)
    forged["sig"] = KEYS["nas"].sign(enrollreq.preimage(good))

    cases = [
        ("unknown-key", mutate(extra=1), "closed schema: an unknown key"),
        ("missing-sig", mutate(sig=_ABSENT), "unsigned"),
        ("wrong-version", mutate(v=2), "v is not 1"),
        ("short-net", mutate(net=NET[:8]), "net is not 16 bytes"),
        ("uppercase-device-id", mutate(device_id="Pi-Cam"), "§2 forbids uppercase"),
        ("leading-dash-device-id", mutate(device_id="-cam"), "§2 forbids a leading dash"),
        ("long-device-id", mutate(device_id="d" + "e" * 64), "65 bytes"),
        ("short-device-pk", mutate(device_pk=KEYS["pi-cam"].public[:31]), "not 32 bytes"),
        ("short-wg-pk", mutate(wg_pk=WG["pi-cam"][:31]), "not 32 bytes"),
        ("short-sig", mutate(sig=good["sig"][:63]), "not 64 bytes"),
        ("bool-expires", mutate(expires=True), "a CBOR bool where a uint is required"),
        ("expires-at-ts", _expires_at_ts(), "expires must be after ts"),
        ("too-many-labels", mutate(labels={f"k{i}": "v" for i in range(33)}), "over 32 labels"),
        ("oversize-label", mutate(labels={"ip": "x" * 257}), "label over 256 bytes"),
        ("non-string-label", mutate(labels={"ip": 1}), "label value is not text"),
        ("ts-is-text", mutate(ts="now"), "ts is not a uint"),
        ("unsorted-keys", text_of_unsorted(base), "map keys out of §4.0 order"),
        ("oversize-label-key", _oversize_label_key(), "a 24-byte map key, past §4.0's cap"),
        ("forged-signature", text(forged), "valid shape, signed by another key"),
        ("wrong-hrp", bech32m.encode("nrn", base), "the human-readable part is not `norn`"),
        ("plain-bech32", _as_bech32(enrollreq.HRP, base), "bech32, not bech32m"),
        ("mixed-case", _mixed_case(text(good)), "mixed case (SPEC §16.2)"),
        ("corrupt-character", _corrupt(text(good)), "one character changed"),
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

    return [
        ("oversize-entry", oversize, "exceeds"),
        ("deep-nesting", deep, "deeper than"),
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


def _mixed_case(text: str) -> str:
    return text[:8] + text[8:].upper()


def _corrupt(text: str) -> str:
    other = "q" if text[10] != "q" else "p"
    return text[:10] + other + text[11:]
