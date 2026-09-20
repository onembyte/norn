"""Minimal `c2sp.org/tlog-policy` parser for the reference implementation.

Only enough to answer "is this a policy": four directives, whitespace that is
ASCII space and tab only, exactly one `quorum` line (SPEC 9.1). The reference
never evaluates a policy -- it only has to refuse a `policy` entry whose text
is not one (SPEC 5.1).
"""


class PolicyError(ValueError):
    """The text is not a `c2sp.org/tlog-policy` document."""


def parse(text: str) -> None:
    quorums = 0
    names: set[str] = set()
    for number, line in enumerate(text.split("\n"), start=1):
        if line == "":
            continue
        if line.strip(" \t") == "":
            raise PolicyError(f"line {number}: blank but not empty")
        fields = line.split()
        if any(c not in " \t" for c in line if c.isspace()):
            raise PolicyError(f"line {number}: whitespace outside space and tab")
        keyword = fields[0]
        if keyword == "log":
            if not 2 <= len(fields) <= 3:
                raise PolicyError(f"line {number}: log takes a key and an optional url")
        elif keyword == "witness":
            if not 3 <= len(fields) <= 4:
                raise PolicyError(f"line {number}: witness takes a name, a key and an optional url")
            names.add(fields[1])
        elif keyword == "group":
            if len(fields) < 3:
                raise PolicyError(f"line {number}: group takes a name, a threshold and members")
            threshold = fields[2]
            if threshold not in ("all", "any") and not threshold.isdigit():
                raise PolicyError(f"line {number}: {threshold!r} is not all, any or a count")
            names.add(fields[1])
        elif keyword == "quorum":
            if len(fields) != 2:
                raise PolicyError(f"line {number}: quorum takes one name")
            quorums += 1
            if fields[1] != "none" and fields[1] not in names:
                raise PolicyError(f"line {number}: quorum names {fields[1]!r}, which is not defined")
        else:
            raise PolicyError(f"line {number}: {keyword!r} is not a policy keyword")
    if quorums != 1:
        raise PolicyError(f"a policy has exactly one quorum line, found {quorums}")
