"""SPEC §9.1's restated `tlog-policy` grammar, at the reference parser.

Cold gate run 11, defects D2 and D12. §9.1's `log lines` row argues that a
Norn policy carries at most one `log` line "since a `log` line that is present
must name `norn.trust.log_key` and no key may appear twice in one policy, a
second one cannot be written". Both premises are rules and neither was written
down anywhere else -- so, measured before the fix:

    same key under two names   Go refuses   · this parser accepted
    two `log` lines            Go accepts   · this parser accepted   (both right:
                                                                upstream allows it)
    U+00A0 inside a URL        Go accepts   · this parser refused

The last is D12: §9.1 names \\r, \\v, \\f after an em dash, which reads as
examples. This parser used Python's `str.isspace()`, which is Unicode-aware,
so a non-breaking space was an error here and content in Go. The set is closed
-- those three bytes and nothing else.

A policy that one implementation refuses and the other accepts is a `policy`
log entry that is `decode` for one and applied by the other, which splits
`state.json` and every quorum after it.
"""

import unittest

from nornref import policy

KEY = "norn-witness/pi+051d1c51+BHeagefoK0s3F5shdMl1Ahsd1ZCE9MC5F5gvM3cLTnZa"
LOG_A = "norn/x+bea4a666+AV6v97lmGyW99eHglI8syFAU2uY+/HuHHq0VYz9Rmio1"
LOG_B = "norn/y+11111111+AV6v97lmGyW99eHglI8syFAU2uY+/HuHHq0VYz9Rmio2"


class KeysAreUsedOnce(unittest.TestCase):
    def test_the_control_parses(self):
        policy.parse(f"witness a {KEY}\nquorum a\n")

    def test_one_key_under_two_names_is_refused(self):
        """`group home 2 a b` would otherwise be met by one witness answering
        once -- the failure §9.1's `group` members row exists to prevent,
        stated there for members and missing for keys."""
        with self.assertRaises(policy.PolicyError):
            policy.parse(f"witness a {KEY}\nwitness b {KEY}\nquorum a\n")

    def test_a_key_on_both_a_log_and_a_witness_line_is_refused(self):
        with self.assertRaises(policy.PolicyError):
            policy.parse(f"log {KEY}\nwitness a {KEY}\nquorum a\n")


class LogLinesFollowTheUpstreamGrammar(unittest.TestCase):
    """D2, corrected. `c2sp.org/tlog-policy` rules out only "multiple log lines
    with the same public key"; several with distinct keys are grammatical, and
    §9.1 promises not to redefine that grammar. An at-most-one rule shipped
    briefly (6.5l-iii) and was a redefinition. A trust file still cannot carry
    a second one -- that is the correspondence rule's job, not the grammar's."""

    def test_two_log_lines_with_distinct_keys_parse(self):
        policy.parse(f"log {LOG_A}\nlog {LOG_B}\nwitness w {KEY}\nquorum w\n")

    def test_two_log_lines_with_the_same_key_are_refused(self):
        with self.assertRaises(policy.PolicyError):
            policy.parse(f"log {LOG_A}\nlog {LOG_A}\nwitness w {KEY}\nquorum w\n")


class TheWhitespaceBanIsThreeBytes(unittest.TestCase):
    @staticmethod
    def _line(mid: str) -> str:
        return f"witness a {KEY} https://example/{mid}w\nquorum a\n"

    def test_the_three_named_bytes_are_errors(self):
        for name, ch in (("carriage return", "\r"),
                         ("vertical tab", "\v"),
                         ("form feed", "\f")):
            with self.subTest(name=name), self.assertRaises(policy.PolicyError):
                policy.parse(self._line(ch))

    def test_every_other_byte_is_content(self):
        """A Unicode whitespace definition refuses policies §9.1 allows."""
        for name, ch in (("non-breaking space", " "),
                         ("en quad", " "),
                         ("ideographic space", "　")):
            with self.subTest(name=name):
                policy.parse(self._line(ch))


if __name__ == "__main__":
    unittest.main()
