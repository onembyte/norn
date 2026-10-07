"""Reference parser for C2SP tlog-policy and Norn SPEC §9.1."""

import re

from . import note


class PolicyError(ValueError):
    """The text is not a valid policy document."""


SEPARATORS = re.compile("[ \t]+")


def _read_vkey(text: str, algorithm: int, number: int, keys: set[bytes]) -> None:
    try:
        verifier = note.parse_vkey(text)
    except note.NoteError as exc:
        raise PolicyError(f"line {number}: invalid verifier key: {exc}") from exc
    if verifier.alg != algorithm:
        raise PolicyError(
            f"line {number}: verifier key algorithm 0x{verifier.alg:02x}, "
            f"want 0x{algorithm:02x}")
    if verifier.public in keys:
        raise PolicyError(f"line {number}: that public key is already in this policy")
    keys.add(verifier.public)


def _check_name(name: str, number: int, kind: str) -> None:
    if name == "none":
        raise PolicyError(f"line {number}: none is predefined and cannot be a {kind} name")


def parse(text: str) -> None:
    """Refuse anything outside the policy grammar; evaluation lives in Go."""
    if not text.endswith("\n"):
        raise PolicyError("the final directive must end in a line feed")

    names: set[str] = set()
    keys: set[bytes] = set()
    quorum_count = 0
    for number, line in enumerate(text.split("\n"), start=1):
        if any((ord(char) < 0x20 and char not in "\t\n") or ord(char) == 0x7F
               for char in line):
            raise PolicyError(f"line {number}: forbidden ASCII control byte")

        stripped = line.strip(" \t")
        if not stripped or stripped.startswith("#"):
            continue
        fields = [field for field in SEPARATORS.split(stripped) if field]
        keyword = fields[0]

        if keyword == "log":
            if not 2 <= len(fields) <= 3:
                raise PolicyError(f"line {number}: log takes a key and optional URL")
            _read_vkey(fields[1], note.ALG_ED25519, number, keys)
        elif keyword == "witness":
            if not 3 <= len(fields) <= 4:
                raise PolicyError(f"line {number}: witness takes a name, key and optional URL")
            name = fields[1]
            _check_name(name, number, "witness")
            if name in names:
                raise PolicyError(f"line {number}: {name!r} is already defined")
            _read_vkey(fields[2], note.ALG_COSIGNATURE, number, keys)
            names.add(name)
        elif keyword == "group":
            if len(fields) < 4:
                raise PolicyError(f"line {number}: group takes a name, threshold and members")
            name, threshold, members = fields[1], fields[2], fields[3:]
            _check_name(name, number, "group")
            if name in names:
                raise PolicyError(f"line {number}: {name!r} is already defined")
            for member in members:
                if member == "none":
                    raise PolicyError(f"line {number}: none cannot be a group member")
                if member not in names:
                    raise PolicyError(f"line {number}: {member!r} is not defined yet")
            if len(set(members)) != len(members):
                raise PolicyError(f"line {number}: a group member appears twice")
            if threshold not in ("all", "any"):
                if not re.fullmatch("[0-9]+", threshold):
                    raise PolicyError(f"line {number}: threshold is not canonical decimal")
                count = int(threshold)
                if threshold != str(count):
                    raise PolicyError(f"line {number}: threshold is not canonical decimal")
                if not 1 <= count <= len(members):
                    raise PolicyError(f"line {number}: threshold is outside 1..member count")
            names.add(name)
        elif keyword == "quorum":
            if len(fields) != 2:
                raise PolicyError(f"line {number}: quorum takes one name")
            if fields[1] != "none" and fields[1] not in names:
                raise PolicyError(f"line {number}: quorum target is not defined earlier")
            quorum_count += 1
        else:
            raise PolicyError(f"line {number}: unknown policy directive")

    if quorum_count != 1:
        raise PolicyError(f"policy has {quorum_count} quorum lines, expected one")
