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

EXTRA_KEYS = (["signer3", "root4", "logkey", "logkey2", "spare", "printer", "nas-id2", "printer-id2", "escaped"]
              + [f"witness-{w}" for w in WITNESSES])

KEYS: dict[str, keys.Ed25519] = {
    name: keys.Ed25519.from_name(name)
    for name in ROOTS + SIGNERS + DEVICES + EXTRA_KEYS
}
WG: dict[str, bytes] = {
    name: keys.x25519_public(name)
    for name in DEVICES + ["laptop2", "nas2", "spare", "printer", "rogue", "escaped"]
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
    return note.vkey(f"norn-witness/{name}", KEYS[f"witness-{name}"].public)


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
        "params": {"checkpoint_interval": 60, "staleness": 600, "mmd": 60,
                   "rotate_needs_signer": False},
    })
    return _signed(env, [("root1", "root"), ("root2", "root")])


def enroll(device: str, ts_offset: int, after: int | None = None,
           labels: dict[str, str] | None = None, expires: int | None = None,
           signers: list[tuple[str, str]] | None = None) -> dict[str, Any]:
    body: dict[str, Any] = {
        "device_id": device,
        "device_pk": KEYS[device].public,
        "wg_pk": WG[device],
    }
    if labels:
        body["labels"] = labels
    if expires is not None:
        body["expires"] = expires
    env = entry.new("enroll", NET, ts=T0 + ts_offset, after=after, body=body)
    return _signed(env, signers or [(device, "device"), ("signer1", "signer")])


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


# -- the replay fixture log (SPEC §12) -----------------------------------

from collections import namedtuple  # noqa: E402  (kept next to its only user)

from . import cbor  # noqa: E402

LogItem = namedtuple("LogItem", "name raw reason")


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


def _enroll_body(device: str, wg: str | None = None, **extra: Any) -> dict[str, Any]:
    body = {"device_id": device, "device_pk": KEYS[device].public, "wg_pk": WG[wg or device]}
    body.update(extra)
    return body


def log() -> list[LogItem]:
    """A 49-entry log: valid entries interleaved with one per reason code."""
    b = _Builder()
    b.add("00-genesis", genesis())

    b.add("01-enroll-nas", b.build("enroll", _enroll_body("nas"),
                                   [("nas", "device"), ("signer1", "signer")]))
    b.add("02-enroll-laptop", b.build("enroll", _enroll_body(
        "laptop", labels={"ip": "10.9.0.2/32", "endpoint": "192.0.2.10:51820"}),
        [("laptop", "device"), ("signer1", "signer")]))
    b.add("03-enroll-pi-cam", b.build("enroll", _enroll_body("pi-cam", expires=T0 + 2_592_000),
                                      [("pi-cam", "device"), ("signer1", "signer")]))

    b.add("04-bad-dup-id", b.build("enroll", _enroll_body("nas", wg="nas2"),
                                   [("nas", "device"), ("signer1", "signer")]), "dup-id")
    b.add("05-bad-dup-wg", b.build("enroll", _enroll_body("spare", wg="nas"),
                                   [("spare", "device"), ("signer1", "signer")]), "dup-wg")
    b.add("06-bad-no-device-sig", b.build("enroll", _enroll_body("printer"),
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
                                       [("printer", "device")] + both))

    wrong_net = entry.new("note", b"\xff" * 16, ts=T0, after=32, body={"text": "wrong network"})
    entry.sign(wrong_net, KEYS["signer1"], "signer")
    b.add_raw("32-bad-decode-net", entry.encode(wrong_net), "decode")

    b.add("33-enroll-pi-cam-again", b.build("enroll", _enroll_body("pi-cam"),
                                            [("pi-cam", "device")] + both))
    b.add("34-bad-rotate-needs-signer", b.build("rotate", {"device_id": "nas", "wg_pk": WG["nas2"]},
                                                [("nas", "device")]), "threshold")
    b.add("35-rotate-nas", b.build("rotate", {"device_id": "nas", "wg_pk": WG["nas2"]},
                                   [("nas", "device")] + both))
    b.add("36-revoke-self-laptop", b.build("revoke", {"device_id": "laptop", "reason": "lost"},
                                           [("laptop", "device")]))
    b.add("37-enroll-spare", b.build("enroll", _enroll_body("spare"),
                                     [("spare", "device")] + both))
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
    b.add("46-bad-rotate-no-new-key-sig", b.build(                                      # D20
        "rotate", {"device_id": "printer", "wg_pk": WG["printer"],
                   "device_pk": KEYS["printer-id2"].public},
        [("printer", "device")] + both), "no-device-sig")
    b.add("47-bad-order-enroll", b.build(                                               # D21
        "enroll", {"device_id": "nas", "device_pk": KEYS["nas"].public,
                   "wg_pk": WG["rogue"]}, both), "no-device-sig")
    b.add("48-bad-order-governance", b.build(                                           # D21
        "signer_add", {"pk": KEYS["signer3"].public}, [("root1", "root")]), "threshold")

    # Canonical-JSON escaping (SPEC §14.2). Every escape rule in one value, so a
    # second implementation cannot pass while disagreeing about `<`, DEL or an
    # emoji -- none of which appear anywhere else in the suite.
    b.add("49-policy-escaping", b.build("policy", {"text": ESCAPE_TORTURE}, roots3))
    b.add("50-enroll-unicode-labels", b.build("enroll", _enroll_body(
        "escaped", labels=UNICODE_LABELS),
        [("escaped", "device")] + both))
    return b.items
