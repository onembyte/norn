"""Minimal `c2sp.org/tlog-policy` parser for the reference implementation.

Only enough to answer "is this a policy": four directives, whitespace that is
ASCII space and tab only, exactly one `quorum` line (SPEC 9.1). The reference
never evaluates a policy -- it only has to refuse a `policy` entry whose text
is not one (SPEC 5.1).
"""

import re


class PolicyError(ValueError):
    """The text is not a `c2sp.org/tlog-policy` document."""


# SPEC 9.1: the only characters that are errors in a line. The set is closed;
# every other character, other Unicode whitespace included, is content.
ERRORS = frozenset("\x0b\x0c\x0d")
SEPARATORS = re.compile("[ \t]+")


def _once(keys: set[str], key: str, number: int) -> None:
    """A verifier key appears once in a policy, on whatever line (SPEC 9.1).

    Under two names, one cosignature line matches both, and one witness
    answering once meets a threshold of two.
    """
    if key in keys:
        raise PolicyError(f"line {number}: that key is already in this policy")
    keys.add(key)


def parse(text: str) -> None:
    """Refuse anything that is not a `c2sp.org/tlog-policy` document.

    Cold gate run 8 (D12) found six rules where this parser and the Go one
    disagreed and no vector could tell: a whitespace-only line, a `#` comment,
    a vertical tab as a separator, a duplicate name, a forward reference and a
    `group` with no members. Four went the tolerant way and two the strict one. SPEC 9.1 now states all six and `policies/`
    vectors them; both implementations answer the same way here.

    Two more after cold gate run 11. D12: this parser refused the 26
    characters `str.isspace()` knows that can occur in a line, where the Go
    one refused three of them; SPEC 9.1 now closes the set at those three. D2:
    a verifier key could appear twice here, which the Go parser refused.
    """
    quorums = 0
    names: set[str] = set()
    keys: set[str] = set()
    for number, line in enumerate(text.split("\n"), start=1):
        if any(c in ERRORS for c in line):
            raise PolicyError(f"line {number}: 0x0B, 0x0C or 0x0D in a line")
        # Ignored: empty or whitespace-only lines, and comments. This parser
        # refused both and the Go one accepted both; SPEC 9.1 now states the
        # tolerant reading and `policies/` vectors it.
        stripped = line.strip(" \t")
        if stripped == "" or stripped.startswith("#"):
            continue
        # Runs of space and tab, and nothing else: `str.split()` with no
        # argument splits on every Unicode space, which made U+00A0 a
        # separator here and content in SPEC 9.1.
        fields = [f for f in SEPARATORS.split(stripped) if f]
        keyword = fields[0]
        if keyword == "log":
            if not 2 <= len(fields) <= 3:
                raise PolicyError(f"line {number}: log takes a key and an optional url")
            _once(keys, fields[1], number)
        elif keyword == "witness":
            if not 3 <= len(fields) <= 4:
                raise PolicyError(f"line {number}: witness takes a name, a key and an optional url")
            if fields[1] in names:
                raise PolicyError(f"line {number}: {fields[1]!r} is already defined")
            _once(keys, fields[2], number)
            names.add(fields[1])
        elif keyword == "group":
            # name, threshold and at least one member.
            if len(fields) < 4:
                raise PolicyError(f"line {number}: group takes a name, a threshold and members")
            if fields[1] in names:
                raise PolicyError(f"line {number}: {fields[1]!r} is already defined")
            threshold, members = fields[2], fields[3:]
            for member in members:
                # Previously defined only: a forward reference could describe a
                # cycle, and a cycle has no meaning here.
                if member not in names:
                    raise PolicyError(f"line {number}: {member!r} is not defined yet")
            if len(set(members)) != len(members):
                raise PolicyError(f"line {number}: a member appears twice in one group")
            if threshold not in ("all", "any"):
                if not threshold.isdigit():
                    raise PolicyError(f"line {number}: {threshold!r} is not all, any or a count")
                # Canonical decimal: `02` and `2` are the same number, and two
                # spellings of a quorum are two policies that look different
                # and are not.
                if threshold != str(int(threshold)):
                    raise PolicyError(f"line {number}: {threshold!r} is not canonical decimal")
                if not 1 <= int(threshold) <= len(members):
                    raise PolicyError(
                        f"line {number}: a threshold of {threshold} over "
                        f"{len(members)} member(s) can never be met")
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
