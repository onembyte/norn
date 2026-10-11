package specdoc

import (
	"strings"
	"testing"
)

// The second cold build found four passages that obscured existing contracts.
// Keep the corrections and reject the stale wording so another reader does not
// infer different refusal precedence, code comparisons or anchor obligations.
func TestTheSecondColdBuildsProseFindingsAreFixed(t *testing.T) {
	doc := load(t)
	for _, c := range []struct {
		section, name, want, stale string
	}{
		{"11.1", "version_example", "and a file with `version: 3` and a key no version defines is `version`, not `schema` (`fork/bad-version-and-unknown-key`) |", "and a file with `version: 2` and a key version 1 lacks is `version` |"},
		{"12", "codes_contract", "in words, and **not the bytes your implementation must produce**.** What a\n" +
			"reader compares is the `codes` map wherever a manifest has one: replay's reason\n" +
			"codes (§5.2), a receipt's (§7), a checkpoint's and a bundle's (§10.1) and fork\n" +
			"evidence's (§11.1) are all closed lists. `says` stays a hint beside them, and\n" +
			"where a manifest gives no code the rule it names is what a reader checks. A\n" +
			"reader is expected to map each `says` onto its own error by hand,", "in words, and **not the bytes your implementation must produce**.** §5.2 gives\n" +
			"replay a closed list of reason codes; no other refusing layer has one, so\n" +
			"outside replay there is nothing for a second implementation to emit and nothing\n" +
			"to compare. A reader is expected to map each `says` onto its own error by hand,"},
		{"3.1", "key_admission", "   A key that is not is refused as `decode` at its entry type's body step\n" +
			"   (§5.1, §5.2) — for a governance entry that step follows the root quorum, so\n" +
			"   an under-signed one is `threshold` first — and where a request is decoded\n" +
			"   (§16); it makes a trust file invalid. One rule throughout: every key that", "   A key that is not is refused as `decode` where the entry or request is\n" +
			"   decoded, and makes a trust file invalid. One rule throughout: every key that"},
		{"12.1", "ots_attestations", "- **OpenTimestamps attestations.** §6 and §12 state the anchor's digest\n" +
			"  contract — exactly which bytes are hashed — and `anchors/cases.json` pins it.\n" +
			"  The proof tree, its calendar reply and any Bitcoin attestation are\n" +
			"  `python-opentimestamps`'s format, which this document does not describe, so\n" +
			"  no reader is asked to validate them; anchoring is advisory (D-009).\n" +
			"- **`quorum none` accepting an uncosigned head.**", ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			section, ok := doc.Section(c.section)
			if !ok {
				t.Fatalf("§%s is missing", c.section)
			}
			body := strings.Join(strings.Fields(section.Body), " ")
			want := strings.Join(strings.Fields(c.want), " ")
			if !strings.Contains(body, want) {
				t.Errorf("§%s: missing corrected passage %q", c.section, want)
			}
			stale := strings.Join(strings.Fields(c.stale), " ")
			if stale != "" && strings.Contains(body, stale) {
				t.Errorf("§%s: still contains replaced passage %q", c.section, stale)
			}
		})
	}
}
