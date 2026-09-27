"""Minimal `c2sp.org/tlog-policy` parser for the reference implementation.

Only enough to answer "is this a policy": four directives, whitespace that is
ASCII space and tab only, exactly one `quorum` line (SPEC 9.1). The reference
never evaluates a policy -- it only has to refuse a `policy` entry whose text
is not one (SPEC 5.1).
"""

import re


class PolicyError(ValueError):
    """The text is not a `c2sp.org/tlog-policy` document."""


def parse(text: str) -> None:
    """Refuse anything that is not a `c2sp.org/tlog-policy` document.

    Cold gate run 8 (D12) found six rules where this parser and the Go one
    disagreed and no vector could tell: a whitespace-only line, a `#` comment,
    a vertical tab as a separator, a duplicate name, a forward reference and a
    `group` with no members. Four went the tolerant way and two the strict one. SPEC 9.1 now states all six and `policies/`
    vectors them; both implementations answer the same way here.
    """
    quorums = 0
    logs = 0
    names: set[str] = set()
    keys: set[str] = set()
    for number, line in enumerate(text.split("\n"), start=1):
        # SPEC 9.1's ban is a CLOSED set of three bytes, and every other byte
        # is content. This used `str.isspace()`, which is Unicode-aware, so a
        # non-breaking space was an error here and ordinary content in Go --
        # a policy the two implementations disagreed about, which is a `policy`
        # entry that is `decode` for one node and applied by the other (cold
        # gate run 11, D12).
        for ch in line:
            if ch in "\v\f\r":
                raise PolicyError(
                    f"line {number}: {ch!r} is not a separator and not content")
        # Ignored: empty or whitespace-only lines, and comments. This parser
        # refused both and the Go one accepted both; SPEC 9.1 now states the
        # tolerant reading and `policies/` vectors it.
        stripped = line.strip(" \t")
        if stripped == "" or stripped.startswith("#"):
            continue
        # Runs of space and tab, and nothing else: `str.split()` with no
        # argument splits on every Unicode space, which would make a
        # non-breaking space a separator now that it is no longer refused.
        fields = re.split(r"[ \t]+", stripped)
        keyword = fields[0]
        if keyword == "log":
            if not 2 <= len(fields) <= 3:
                raise PolicyError(f"line {number}: log takes a key and an optional url")
            logs += 1
            _claim_key(keys, fields[1], number)
        elif keyword == "witness":
            if not 3 <= len(fields) <= 4:
                raise PolicyError(f"line {number}: witness takes a name, a key and an optional url")
            if fields[1] in names:
                raise PolicyError(f"line {number}: {fields[1]!r} is already defined")
            _claim_key(keys, fields[2], number)
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
    # SPEC 9.1's `log count` row. Its `log lines` row argued this followed from
    # key uniqueness -- it does not, because two `log` lines may carry two
    # different keys, and until run 11 (D2) neither implementation enforced it.
    if logs > 1:
        raise PolicyError(f"a policy carries at most one log line, found {logs}")


def _claim_key(keys: set[str], vkey: str, number: int) -> None:
    """A `vkey` is used once in a policy (SPEC 9.1's `keys` row).

    The same key under two names makes `group home 2 a b` satisfiable by one
    witness answering once -- the failure the `group` members row exists to
    prevent, stated there for members and missing for keys until run 11 (D2).
    """
    if vkey in keys:
        raise PolicyError(f"line {number}: that key is already in this policy")
    keys.add(vkey)
