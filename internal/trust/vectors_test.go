package trust

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/onembyte/norn/internal/cbor"
)

// --- Cold-model gate run 10, defect D12 ---------------------------------
//
// Three §9.1 MUSTs about the log key, each deletable from this implementation
// with no vector noticing. `V90` (drop "`origin` is `norn/` + base32(`net`)"),
// `V93` (drop "the log key's note name equals `origin`") and `V92` (drop
// "`log_key` MUST NOT be a cosignature key") each passed all 236 checks.
//
// The cause is the same in all three: the negative damages `log_key` or
// `origin` and leaves the **policy** carrying the original key, so §9.1's
// correspondence rule — a `log` line, if present, MUST be `norn.trust.log_key`
// — refuses the file before the rule the case is named after is reached. Run
// 10 called `V90`/`V93` the sharpest pair: two separate MUSTs, each with no
// observable effect, and only deleting *both* lets a file through.
//
// A negative is about the rule it names or it is about nothing, so each of
// these carries its damaged key in its policy too.

func trustBad(t *testing.T, name string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "vectors",
		"trust-bad", name+".cbor"))
	if err != nil {
		t.Fatal(err)
	}
	// Decoded, not parsed: `Parse` is what these files exist to fail.
	value, err := cbor.Decode(raw)
	if err != nil {
		t.Fatalf("%s does not even decode, so it cannot be about a §9.1 rule: %v",
			name, err)
	}
	doc, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("%s is not a map", name)
	}
	return doc
}

func TestTheLogKeyNegativesDoNotAlsoBreakTheCorrespondenceRule(t *testing.T) {
	for _, name := range []string{
		"11-log-key-name-mismatch",
		"13-origin-only",
		"16-log-key-is-a-cosignature-key",
		// Cold gate run 11, D3: the fourth, and the one 6.5k-v-a missed.
		"37-log-key-id-mismatch",
	} {
		t.Run(name, func(t *testing.T) {
			doc := trustBad(t, name)
			logKey, _ := doc["log_key"].(string)
			text, _ := doc["policy"].(string)
			if logKey == "" || text == "" {
				t.Fatalf("the case carries log_key=%q and a %d-byte policy", logKey, len(text))
			}
			var found bool
			for _, line := range strings.Split(text, "\n") {
				fields := strings.Fields(line)
				if len(fields) < 2 || fields[0] != "log" {
					continue
				}
				found = true
				if fields[1] != logKey {
					t.Errorf("the policy's log line names\n  %s\nand `log_key` is\n  %s\n"+
						"so §9.1's correspondence rule refuses this file and the rule it "+
						"is named after is never reached", fields[1], logKey)
				}
			}
			if !found {
				t.Error("the policy carries no `log` line, so the correspondence rule " +
					"is vacuous here and the case says less than it could")
			}
			// It must still be refused, of course.
			raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "vectors",
				"trust-bad", name+".cbor"))
			if err != nil {
				t.Fatal(err)
			}
			doc2, err := Parse(raw)
			if err == nil {
				err = doc2.Validate()
			}
			if err == nil {
				t.Error("the file must be refused")
			}
		})
	}
}
