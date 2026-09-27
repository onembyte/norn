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
		// Run 11, D3: §12.1 claimed this one got the same treatment and it did
		// not. Its damaged id was left out of the policy, so the correspondence
		// rule refused the file and `TrustNoKeyIDCheck` -- a loader that takes
		// a declared key id as an opaque label, which is the natural thing to
		// do since the id is also what you match on -- passed all 622 checks.
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

// --- Cold-model gate run 11, defects D3 and D9 --------------------------
//
// The witness half of the same rule. §7 makes a key id bind the name, the
// algorithm and the public key, and §10 leans on that: a cosignature line
// counts when its name **and** id match. Both halves of that test imply each
// other — but only while somebody recomputes the id. Take the recomputation
// away and `TrustNoKeyIDCheck,CosigIDOnlyMatch` has verified nothing about the
// name at all, and the pair passed all 622 checks because no shipped trust
// file carried a mis-declared *witness* key id.

func TestTheWitnessKeyIDNegativeDoesNotAlsoBreakTheCorrespondenceRule(t *testing.T) {
	const name = "39-witness-key-id-mismatch"
	doc := trustBad(t, name)

	witnesses, ok := doc["witnesses"].([]any)
	if !ok || len(witnesses) == 0 {
		t.Fatalf("%s carries no witnesses", name)
	}
	text, _ := doc["policy"].(string)
	if text == "" {
		t.Fatalf("%s carries no policy", name)
	}

	// Every witness the array lists must appear in the policy under the same
	// name with the same key, or §9.1's correspondence rule refuses the file
	// before the key-id rule is reached — which is exactly how `37` went wrong.
	inPolicy := map[string]string{}
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[0] == "witness" {
			inPolicy[fields[1]] = fields[2]
		}
	}
	var damaged int
	for _, w := range witnesses {
		m, _ := w.(map[string]any)
		wname, _ := m["name"].(string)
		key, _ := m["key"].(string)
		got, listed := inPolicy[wname]
		if !listed {
			t.Errorf("witness %q is in the array and not in the policy, so the "+
				"correspondence rule refuses this file", wname)
			continue
		}
		if got != key {
			t.Errorf("witness %q is %s in the array and %s in the policy; the "+
				"damage must be carried into both or the correspondence rule "+
				"decides instead of the key-id rule", wname, key, got)
		}
		if key != honestWitnessKey(t, wname) {
			damaged++
		}
	}
	if damaged != 1 {
		t.Errorf("%d witness keys differ from the honest anchor's; the case needs "+
			"exactly one, or it is about something other than a single mis-declared id",
			damaged)
	}

	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "vectors",
		"trust-bad", name+".cbor"))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := Parse(raw)
	if err == nil {
		err = parsed.Validate()
	}
	if err == nil {
		t.Error("the file must be refused")
	}
}

// honestWitnessKey is the key the shipped anchor publishes for this witness.
func honestWitnessKey(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "vectors", "trust.cbor"))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range doc.Witnesses {
		if w.Name == name {
			return w.Key
		}
	}
	t.Fatalf("the anchor lists no witness %q", name)
	return ""
}

// D7's third variant: the log key's note name "MUST equal `origin`", and
// `LogKeyNamePrefix` — a prefix match on that name — passed all 622 checks.
// `11-log-key-name-mismatch` uses `someone/else`, which is not a prefix of
// anything, so nothing separated the two readings.
func TestTheLogKeyNameComparisonIsEquality(t *testing.T) {
	const name = "40-log-key-name-suffix"
	doc := trustBad(t, name)

	origin, _ := doc["origin"].(string)
	logKey, _ := doc["log_key"].(string)
	if origin == "" || logKey == "" {
		t.Fatalf("%s carries origin=%q log_key=%q", name, origin, logKey)
	}
	keyName, _, _ := strings.Cut(logKey, "+")
	if keyName == origin || !strings.HasPrefix(keyName, origin) {
		t.Errorf("the log key is named %q and the origin is %q; the name must be "+
			"the origin plus at least one character, or a prefix match is not "+
			"separated from equality", keyName, origin)
	}

	// And, as `37` taught, the damage has to reach the policy too, or the
	// correspondence rule refuses the file before this rule is consulted.
	text, _ := doc["policy"].(string)
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "log" && fields[1] != logKey {
			t.Errorf("the policy's log line names %s and `log_key` is %s, so the "+
				"correspondence rule decides instead", fields[1], logKey)
		}
	}

	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "vectors",
		"trust-bad", name+".cbor"))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := Parse(raw)
	if err == nil {
		err = parsed.Validate()
	}
	if err == nil {
		t.Error("the file must be refused")
	}
}
