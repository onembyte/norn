package trust

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/onembyte/norn/internal/cbor"
	"github.com/onembyte/norn/internal/note"
)

// Cold gate run 13, D18. One letter of the origin changes case, and the log
// key's note name and the policy's `log` line agree with it, so only the exact
// derivation of `origin` from `net` can refuse the file: a reader comparing the
// derived origin case-insensitively accepts it. `checkpoints-bad/22` pins the
// same rule on the checkpoint side.
func TestTheTrustOriginCaseIsTheOnlyFault(t *testing.T) {
	const name = "45-origin-case-changed"
	doc := trustBad(t, name)
	origin, _ := doc["origin"].(string)
	net, _ := doc["net"].([]byte)
	derived, err := OriginFor(net)
	if err != nil {
		t.Fatal(err)
	}
	if len(origin) != len(derived) || !strings.EqualFold(origin, derived) {
		t.Fatalf("origin %q must differ only in case from %q", origin, derived)
	}
	differences := 0
	for i := range origin {
		if origin[i] != derived[i] {
			differences++
		}
	}
	if differences != 1 {
		t.Fatalf("origin differs in %d letters, want one", differences)
	}
	vkey, _ := doc["log_key"].(string)
	logKey, err := parseKey(vkey)
	if err != nil {
		t.Fatal(err)
	}
	if logKey.Name != origin {
		t.Errorf("log_key is named %q, not the case's origin %q, so the name rule "+
			"refuses this file too and a case-insensitive derivation passes", logKey.Name, origin)
	}

	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "vectors",
		"trust-bad", name+".cbor"))
	if err != nil {
		t.Fatal(err)
	}
	anchor, err := Parse(raw)
	if err == nil {
		err = anchor.Validate()
	}
	if err == nil || !strings.Contains(err.Error(), "origin does not derive from net") {
		t.Errorf("the case-changed origin was not refused by the derivation rule: %v", err)
	}
}

// The other half of the same survivor: `origin` is honest and the log key's
// note name differs from it only in one letter's case, the policy agreeing, so
// only "its note name MUST equal `origin`" can refuse the file. `11` and `40`
// differ by more than case, so a reader folding the name comparison passed.
func TestTheLogKeyNameCaseIsTheOnlyFault(t *testing.T) {
	const name = "46-log-key-name-case-changed"
	doc := trustBad(t, name)
	origin, _ := doc["origin"].(string)
	net, _ := doc["net"].([]byte)
	if derived, err := OriginFor(net); err != nil || origin != derived {
		t.Fatalf("origin %q is not the derived %q (%v), so the derivation rule decides", origin, derived, err)
	}
	vkey, _ := doc["log_key"].(string)
	logKey, err := parseKey(vkey)
	if err != nil {
		t.Fatal(err)
	}
	if logKey.Name == origin || !strings.EqualFold(logKey.Name, origin) {
		t.Fatalf("log_key is named %q; want %q with one letter's case changed", logKey.Name, origin)
	}

	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "vectors",
		"trust-bad", name+".cbor"))
	if err != nil {
		t.Fatal(err)
	}
	anchor, err := Parse(raw)
	if err == nil {
		err = anchor.Validate()
	}
	if err == nil || !strings.Contains(err.Error(), "not the origin") {
		t.Errorf("the case-changed log key name was not refused by the name rule: %v", err)
	}
}

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

func TestNoncanonicalLogVerifierKeyIsTheOnlyTrustFault(t *testing.T) {
	const name = "44-log-key-base64-cr"
	doc := trustBad(t, name)
	key, ok := doc["log_key"].(string)
	if !ok || strings.Count(key, "\r") != 1 {
		t.Fatalf("%s must change one verifier-key data character only", name)
	}
	policyText, ok := doc["policy"].(string)
	if !ok {
		t.Fatal("policy is not text")
	}
	for _, line := range strings.Split(policyText, "\n") {
		if strings.HasPrefix(line, "log ") {
			t.Fatal("a log line would make key correspondence a second fault")
		}
	}

	// Removing only the ignored CR repairs the file. This proves the omitted
	// optional policy log line does not itself cause the refusal.
	doc["log_key"] = strings.ReplaceAll(key, "\r", "")
	repaired, err := cbor.Encode(doc)
	if err != nil {
		t.Fatal(err)
	}
	anchor, err := Parse(repaired)
	if err == nil {
		err = anchor.Validate()
	}
	if err != nil {
		t.Fatalf("removing the CR did not repair the anchor: %v", err)
	}

	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "vectors",
		"trust-bad", name+".cbor"))
	if err != nil {
		t.Fatal(err)
	}
	anchor, err = Parse(raw)
	if err == nil {
		err = anchor.Validate()
	}
	if err == nil || !strings.Contains(err.Error(), "log_key:") ||
		!strings.Contains(err.Error(), "base64") {
		t.Errorf("noncanonical verifier key was not refused at log_key base64: %v", err)
	}
}

func TestTheLogKeyNegativesDoNotAlsoBreakTheCorrespondenceRule(t *testing.T) {
	for _, name := range []string{
		"11-log-key-name-mismatch",
		"13-origin-only",
		"16-log-key-is-a-cosignature-key",
		"45-origin-case-changed",
		"46-log-key-name-case-changed",
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

// Cold gate run 12, D10. Each trust rule needs a file that reaches only that
// rule; otherwise a stricter earlier check can hide its removal.
func TestRunTwelveTrustNegativesAreIsolated(t *testing.T) {
	t.Run("origin is not a prefix comparison", func(t *testing.T) {
		doc := parseBad(t, isolated(t, "origin-only"))
		derived, err := OriginFor(doc.Net)
		if err != nil {
			t.Fatal(err)
		}
		if doc.Origin != derived+"a" {
			t.Fatalf("origin %q is not the derived origin plus one character %q", doc.Origin, derived+"a")
		}
		key, err := parseKey(doc.LogKey)
		if err != nil {
			t.Fatal(err)
		}
		if key.Name != doc.Origin {
			t.Errorf("log key name %q differs from the damaged origin %q", key.Name, doc.Origin)
		}
		for _, line := range strings.Split(doc.Policy, "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 2 && fields[0] == "log" && fields[1] != doc.LogKey {
				t.Errorf("policy log key %q differs from log_key %q", fields[1], doc.LogKey)
			}
		}
	})

	t.Run("witness key correspondence", func(t *testing.T) {
		doc := parseBad(t, isolated(t, "witness-key-mismatch"))
		policyKeys := map[string]string{}
		for _, line := range strings.Split(doc.Policy, "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 3 && fields[0] == "witness" {
				policyKeys[fields[1]] = fields[2]
			}
		}
		if len(policyKeys) != len(doc.Witnesses) {
			t.Fatalf("%d policy witness names for %d records", len(policyKeys), len(doc.Witnesses))
		}
		mismatches := 0
		for _, witness := range doc.Witnesses {
			parsed, err := parseKey(witness.Key)
			if err != nil || !parsed.IsCosigner() {
				t.Errorf("witness %q does not carry a valid cosignature key: %v", witness.Name, err)
			}
			key, ok := policyKeys[witness.Name]
			if !ok {
				t.Errorf("witness %q has no policy definition", witness.Name)
				continue
			}
			if key != witness.Key {
				mismatches++
			}
		}
		if mismatches != 1 {
			t.Errorf("%d witness keys disagree between the array and policy; want exactly one", mismatches)
		}
	})

	t.Run("anchor is closed", func(t *testing.T) {
		doc := parseBad(t, isolated(t, "anchor-unknown-member"))
		if len(doc.Anchor) != 4 || doc.Anchor["note"] != "unexpected" {
			t.Fatalf("anchor = %#v; want the three required members and one unknown", doc.Anchor)
		}
		for _, key := range []string{"type", "max_lag", "mode"} {
			if _, ok := doc.Anchor[key]; !ok {
				t.Errorf("anchor is also missing required member %q", key)
			}
		}
	})
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

// The optional policy log line is absent so it cannot mask log-key admission.
func TestTheTrustLogKeySmallOrderPointIsTheOnlyFault(t *testing.T) {
	const name = "55-log-key-small-order"
	doc := trustBad(t, name)
	key, err := note.ParseVerifierKey(doc["log_key"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if key.Name != doc["origin"] {
		t.Fatal("log key name differs from origin")
	}
	for _, line := range strings.Split(doc["policy"].(string), "\n") {
		if strings.HasPrefix(line, "log ") {
			t.Fatal("policy log line could mask point admission")
		}
	}
	raw, err := cbor.Encode(doc)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := Parse(raw)
	if err == nil {
		err = parsed.Validate()
	}
	if err == nil || !strings.Contains(err.Error(), "log_key is not a valid point") {
		t.Fatalf("Go: want invalid log_key point, got %v", err)
	}
	honestRaw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "vectors", "trust.cbor"))
	if err != nil {
		t.Fatal(err)
	}
	honest, err := Parse(honestRaw)
	if err != nil {
		t.Fatal(err)
	}
	doc["log_key"] = honest.LogKey
	raw, err = cbor.Encode(doc)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err = Parse(raw)
	if err == nil {
		err = parsed.Validate()
	}
	if err != nil {
		t.Fatalf("repair: %v", err)
	}
}
