"""Write the OpenTimestamps vectors, using the reference implementation.

Two files, for the two things `norn verify --anchored` has to tell apart:

* `sample.ots` — a proof over an arbitrary digest, with both branch kinds.
  Exercises the parser against bytes this project did not write.
* `checkpoint-<size>.ots` — a proof over the *fixture's* checkpoint body, so the
  end-to-end path (`anchors/<size>.ots` → this checkpoint) has something real
  to walk.

See README.md for how to run it.
"""

import hashlib
import pathlib
import sys

from opentimestamps.core.timestamp import Timestamp, DetachedTimestampFile
from opentimestamps.core.op import OpSHA256, OpAppend, OpPrepend
from opentimestamps.core.notary import BitcoinBlockHeaderAttestation, PendingAttestation
from opentimestamps.core.serialize import BytesSerializationContext

ROOT = pathlib.Path(__file__).resolve().parents[2]
ANCHORS = ROOT / "testdata" / "vectors" / "anchors"

#: The block the fixture's proofs claim. A round number, chosen so nobody
#: mistakes these for proofs of anything that happened.
HEIGHT = 800000

#: The instant the calendar branch is pending at.
CALENDAR = "https://alice.btc.calendar.opentimestamps.org"


def proof_over(digest: bytes) -> bytes:
    """A detached proof with one confirmed branch and one still pending."""
    timestamp = Timestamp(digest)

    confirmed = timestamp.ops.add(OpAppend(bytes.fromhex("0badc0de")))
    confirmed = confirmed.ops.add(OpSHA256())
    confirmed.attestations.add(BitcoinBlockHeaderAttestation(HEIGHT))

    pending = timestamp.ops.add(OpPrepend(bytes.fromhex("feed")))
    pending.attestations.add(PendingAttestation(CALENDAR))

    ctx = BytesSerializationContext()
    DetachedTimestampFile(OpSHA256(), timestamp).serialize(ctx)
    return ctx.getbytes()


def checkpoint_body() -> str:
    """The fixture's served checkpoint, without its signature lines.

    The body is what gets stamped: origin, size and root are the whole claim
    an anchor is making -- "this tree existed by then". The signatures are the
    log's, and the log is the party an anchor exists to constrain.
    """
    raw = (ROOT / "testdata" / "vectors" / "served" / "checkpoint").read_text()
    body, _, _ = raw.partition("\n\n")
    return body + "\n\n"


def calendar_response(digest: bytes) -> bytes:
    """What `POST <calendar>/digest` returns: a bare timestamp tree.

    Not a detached file -- no magic, no version, no file-hash op. The client
    is expected to know which digest it asked about. That asymmetry is why
    Norn can build an `.ots` by concatenation instead of carrying a
    serializer: a detached file is a fixed header followed by exactly these
    bytes.
    """
    timestamp = Timestamp(digest)
    branch = timestamp.ops.add(OpAppend(bytes.fromhex("cafe")))
    branch = branch.ops.add(OpSHA256())
    branch.attestations.add(PendingAttestation(CALENDAR))

    ctx = BytesSerializationContext()
    timestamp.serialize(ctx)
    return ctx.getbytes()


def checkpoint_size(body: str) -> int:
    """The tree size the body claims: SPEC §6's checkpoint is origin, size, root.

    Read rather than hardcoded. The anchor is named `<size>.ots` (§6), so a
    fixture that grows by one entry renames this file, and a constant here
    would quietly keep stamping a name the log no longer serves.
    """
    return int(body.split("\n")[1])


def main() -> int:
    ANCHORS.mkdir(parents=True, exist_ok=True)

    body = checkpoint_body()
    size = checkpoint_size(body)

    # An arbitrary digest, deliberately fixed: this file exercises the parser
    # against bytes this project did not write, and has nothing to do with the
    # fixture's size. Tying it to the size would churn it every time the log
    # gains an entry, for no gain at all.
    (ANCHORS / "sample.ots").write_bytes(
        proof_over(hashlib.sha256(b"norn checkpoint at size 90").digest())
    )

    name = f"checkpoint-{size}.ots"
    for stale in ANCHORS.glob("checkpoint-*.ots"):
        if stale.name != name:
            stale.unlink()
    (ANCHORS / name).write_bytes(
        proof_over(hashlib.sha256(body.encode()).digest())
    )
    (ANCHORS / "calendar-response.bin").write_bytes(
        calendar_response(hashlib.sha256(body.encode()).digest())
    )
    print(f"wrote sample.ots, {name} and calendar-response.bin into", ANCHORS)
    return 0


if __name__ == "__main__":
    sys.exit(main())
