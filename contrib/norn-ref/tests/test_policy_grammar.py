"""C2SP tlog-policy grammar rules at the independent Python parser.

The cases pin definition order, names, verifier keys, line endings, controls,
and duplicate public keys, alongside the original quorum grammar.
"""

import json
from pathlib import Path
import unittest

from nornref import fixture, note, policy

KEY = fixture.witness_vkey("pi")
LOG_A = fixture.log_vkey()
LOG_B = note.vkey("norn/second-log", fixture.KEYS["logkey2"].public)
LOG_ALIAS = note.vkey("norn/alias", fixture.KEYS["logkey"].public)
LOG_AS_WITNESS = note.vkey("norn-witness/log-alias", fixture.KEYS["logkey"].public,
                           note.ALG_COSIGNATURE)


class LinesMayFollowQuorumButNamesKeepTheirMeaning(unittest.TestCase):
    def _vector(self, name, accept, says):
        cases = {item[0]: item[1:] for item in fixture.policy_grammar()}
        self.assertTrue(name in cases, f"the {name} policy vector is missing")
        text, actual, why = cases[name]
        self.assertEqual(actual, accept)
        self.assertTrue(why)
        root = Path(__file__).resolve().parents[3] / "testdata" / "vectors" / "policies"
        doc = json.loads((root / "cases.json").read_text())
        shipped = next(case for case in doc["cases"] if case["name"] == name)
        self.assertEqual(shipped["accept"], accept)
        self.assertEqual(shipped["why"], why)
        self.assertEqual(doc["rules"][name], {"section": "9.1", "says": says})
        self.assertEqual((root / f"{name}.txt").read_bytes(), text.encode())
        return text, shipped.get("evaluate", [])

    def test_directives_after_quorum_leave_its_members_unchanged(self):
        text, evaluations = self._vector(
            "directive-after-quorum", True, "lines may appear in **any order**")
        lines = text.splitlines(keepends=True)
        self.assertEqual(len(lines), 6)
        self.assertEqual(lines[2:4], ["group home any pi\n", "quorum home\n"])
        self.assertTrue(lines[4].startswith("witness vps "))
        self.assertEqual(lines[5], "group unused all vps\n")
        policy.parse(text)
        base = "".join(lines[:4])
        policy.parse(base)
        # The reference parses grammar only. Pin the simple quorum's meaning
        # from its exact members; Go executes these same shipped evaluations.
        self.assertEqual(evaluations, fixture.policy_evaluations()["directive-after-quorum"])
        self.assertEqual([(e["cosigners"], e["satisfied"]) for e in evaluations],
                         [([], False), (["pi"], True), (["vps"], False), (["pi", "vps"], True)])
        for candidate in (text, base):
            target = next(line.split()[1] for line in candidate.splitlines()
                          if line.startswith("quorum "))
            members = next(line.split()[3:] for line in candidate.splitlines()
                           if line.startswith(f"group {target} "))
            for e in evaluations:
                self.assertEqual(bool(set(members) & set(e["cosigners"])), e["satisfied"])

    def test_redefinition_after_quorum_use_is_the_only_fault(self):
        text, _ = self._vector(
            "bad-redefinition-after-use", False, "nothing defined later changes an earlier line")
        lines = text.splitlines(keepends=True)
        self.assertEqual(len(lines), 6)
        self.assertEqual(lines[3:], ["group home any pi\n", "quorum home\n", "group home any vps\n"])
        with self.assertRaisesRegex(policy.PolicyError, "'home' is already defined"):
            policy.parse(text)
        policy.parse("".join(lines[:-1]))


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
            policy.parse(f"log {LOG_A}\nwitness a {LOG_AS_WITNESS}\nquorum a\n")


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

    def test_same_public_key_with_another_name_is_still_duplicate(self):
        with self.assertRaises(policy.PolicyError):
            policy.parse(f"log {LOG_A}\nlog {LOG_ALIAS}\nwitness w {KEY}\nquorum w\n")

class OnlyTabAndLineFeedAreAllowedASCIIControls(unittest.TestCase):
    @staticmethod
    def _line(mid: str) -> str:
        return f"witness a {KEY} https://example/{mid}w\nquorum a\n"

    def test_all_other_ascii_controls_are_errors(self):
        chars = [*(chr(n) for n in range(0x20) if n not in (0x09, 0x0A)), "\x7f"]
        for ch in chars:
            name = f"U+{ord(ch):04X}"
            with self.subTest(name=name), self.assertRaises(policy.PolicyError):
                policy.parse(self._line(ch))

    def test_non_ascii_whitespace_is_content(self):
        for name, ch in (("non-breaking space", " "), ("next-line", "\u0085"),
                         ("en quad", " "),
                         ("ideographic space", "　")):
            with self.subTest(name=name):
                policy.parse(self._line(ch))

    def test_final_line_feed_is_required(self):
        with self.assertRaises(policy.PolicyError):
            policy.parse(f"witness a {KEY}\nquorum a")

    def test_quorum_must_follow_its_definition(self):
        with self.assertRaises(policy.PolicyError):
            policy.parse(f"quorum a\nwitness a {KEY}\n")


if __name__ == "__main__":
    unittest.main()
