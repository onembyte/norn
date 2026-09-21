package trust

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Written from SPEC.md §9. The shipped anchor is the oracle for the happy
// path; trust-bad/ is the oracle for refusal, and every one of those files
// decodes cleanly, so only validation can reject them.

func vectorRoot() string { return filepath.Join("..", "..", "testdata", "vectors") }

func loadGood(t *testing.T) *Trust {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(vectorRoot(), "trust.cbor"))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

func TestTheShippedAnchorValidates(t *testing.T) {
	if err := loadGood(t).Validate(); err != nil {
		t.Errorf("the shipped trust file must validate: %v", err)
	}
}

func TestAnchorRoundTripsByteExact(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(vectorRoot(), "trust.cbor"))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	again, err := doc.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if string(again) != string(raw) {
		t.Error("re-encoding the trust file must reproduce its bytes, since the " +
			"fingerprint is taken over them")
	}
}

func TestFingerprintMatchesTheShippedFile(t *testing.T) {
	want, err := os.ReadFile(filepath.Join(vectorRoot(), "trust.fingerprint"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := loadGood(t).Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	if got != strings.TrimSpace(string(want)) {
		t.Errorf("fingerprint %s, want %s", got, strings.TrimSpace(string(want)))
	}
	if len(strings.Split(got, "-")) != 4 {
		t.Errorf("fingerprint %q should be four groups of four", got)
	}
	if strings.ContainsAny(got, "ILOU") {
		t.Error("Crockford base32 excludes I, L, O and U")
	}
}

func TestOriginDerivesFromNet(t *testing.T) {
	doc := loadGood(t)
	got, err := OriginFor(doc.Net)
	if err != nil {
		t.Fatal(err)
	}
	if got != doc.Origin {
		t.Errorf("derived origin %s, want %s", got, doc.Origin)
	}
	if strings.ContainsAny(strings.TrimPrefix(got, "norn/"), "=") {
		t.Error("origin base32 is unpadded")
	}
	if got != strings.ToLower(got) {
		t.Error("origin base32 is lowercase")
	}
}

func TestGenesisHashIsTheLeafHashOfEntryZero(t *testing.T) {
	doc := loadGood(t)
	if len(doc.GenesisHash) != 32 {
		t.Fatalf("genesis_hash must be 32 bytes, got %d", len(doc.GenesisHash))
	}
	if hex.EncodeToString(doc.GenesisHash) == strings.Repeat("00", 32) {
		t.Error("genesis_hash must not be the zero hash")
	}
}

// Every damaged anchor must be refused -- and must decode first, so that the
// refusal comes from validation rather than from the codec.
func TestEveryDamagedAnchorIsRejected(t *testing.T) {
	matches, err := filepath.Glob(filepath.Join(vectorRoot(), "trust-bad", "*.cbor"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) < 14 {
		t.Fatalf("expected at least 14 rejected anchors, found %d", len(matches))
	}
	for _, path := range matches {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		doc, err := Parse(raw)
		if err != nil {
			// Parse enforces §9.1 shape, which is part of validation; that is
			// a refusal too. Only a codec-level failure would be wrong here.
			continue
		}
		if err := doc.Validate(); err == nil {
			t.Errorf("%s: accepted, but this anchor must be refused", filepath.Base(path))
		}
	}
}

func TestTheLogKeyMustBeNamedForTheOrigin(t *testing.T) {
	doc := loadGood(t)
	parsed, err := parseKey(doc.LogKey)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Name != doc.Origin {
		t.Errorf("log key is named %q but the origin is %q", parsed.Name, doc.Origin)
	}
}

// --- Cold-model gate run 7, defect J12 ----------------------------------
//
// Four §9.1 rules that `trust-bad/` states and no file reaches. Each has a
// vector that violates it, and each of those vectors trips a *different* rule
// first -- so `trust-no-witness-min`, `trust-no-dup-witness`,
// `trust-no-name-len` and `trust-allow-empty-log-urls` all passed the suite.
//
// A negative is only worth the rule it isolates. The check below is not "is it
// refused" -- the sweep above already asks that -- but "is everything else
// about it correct", which is what makes the refusal attributable.

func parseBad(t *testing.T, name string) *Trust {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(vectorRoot(), "trust-bad", name+".cbor"))
	if err != nil {
		t.Fatalf("the case is missing: %v", err)
	}
	// Deliberately not Parse: these are read as documents so the test can look
	// at fields the validator is about to refuse.
	doc, err := Parse(raw)
	if err != nil {
		t.Fatalf("%s no longer decodes, so it cannot isolate a validation rule: %v",
			name, err)
	}
	if err := doc.Validate(); err == nil {
		t.Fatalf("%s is accepted; it must be refused", name)
	}
	return doc
}

// policyWitnessNames is every short name a `witness` directive declares.
func policyWitnessNames(t *testing.T, policy string) []string {
	t.Helper()
	var names []string
	for _, line := range strings.Split(policy, "\n") {
		fields := strings.FieldsFunc(line, func(r rune) bool { return r == ' ' || r == '\t' })
		if len(fields) >= 3 && fields[0] == "witness" {
			names = append(names, fields[1])
		}
	}
	return names
}

func TestTheTrustRulesEachHaveAnIsolatedNegative(t *testing.T) {
	// §9.1: "A file with no witnesses MUST be rejected." `07-no-witnesses`
	// breaks the policy/witness correspondence at the same time, and that rule
	// fires first, so the MUST itself was never reached.
	t.Run("no witnesses, and a policy that agrees", func(t *testing.T) {
		doc := parseBad(t, isolated(t, "no-witnesses-only"))
		if len(doc.Witnesses) != 0 {
			t.Fatalf("%d witnesses: this is not the no-witness case", len(doc.Witnesses))
		}
		if names := policyWitnessNames(t, doc.Policy); len(names) != 0 {
			t.Errorf("the policy names %v, so the correspondence rule refuses this "+
				"file before the witness minimum is reached", names)
		}
	})

	// §9.1: a witness `name` is unique within the file. `08` lists only `pi`
	// twice, so the policy names two witnesses the file does not, and the
	// correspondence rule decides.
	t.Run("a duplicate name that agrees with the policy", func(t *testing.T) {
		doc := parseBad(t, isolated(t, "duplicate-witness-name-only"))
		seen, dup := map[string]int{}, ""
		keys := map[string]string{}
		for _, w := range doc.Witnesses {
			seen[w.Name]++
			if seen[w.Name] > 1 {
				dup = w.Name
				if keys[w.Name] != w.Key {
					t.Errorf("the two %q entries carry different keys, so the "+
						"correspondence rule refuses this file first", w.Name)
				}
			}
			keys[w.Name] = w.Key
		}
		if dup == "" {
			t.Fatal("no name appears twice: this is not the duplicate case")
		}
		named := map[string]bool{}
		for _, n := range policyWitnessNames(t, doc.Policy) {
			named[n] = true
		}
		for name := range seen {
			if !named[name] {
				t.Errorf("witness %q is not in the policy, so correspondence decides", name)
			}
		}
		for name := range named {
			if seen[name] == 0 {
				t.Errorf("the policy names %q, which the file does not list", name)
			}
		}
	})

	// §9.1 bounds `name` at 1-64 bytes. `14-missing-name` covers absent only.
	for _, c := range []struct{ suffix, why string }{
		{"name-too-long", "over the 64-byte cap"},
		{"name-empty", "under the 1-byte floor"},
	} {
		t.Run(c.suffix, func(t *testing.T) {
			doc := parseBad(t, isolated(t, c.suffix))
			if n := len(doc.Name); n >= 1 && n <= 64 {
				t.Errorf("name is %d bytes, which §9.1 permits -- the file is %s "+
					"by no measure", n, c.why)
			}
		})
	}

	// §9.1: `log_urls` is an array of text, **≥ 1**. `24-missing-log-urls`
	// covers absent; present-and-empty is a different code path in both
	// implementations.
	t.Run("empty log_urls", func(t *testing.T) {
		doc := parseBad(t, isolated(t, "empty-log-urls"))
		if len(doc.LogURLs) != 0 {
			t.Errorf("%d log_urls: the case is meant to carry an empty array",
				len(doc.LogURLs))
		}
	})
}

// isolated finds the shipped case whose name ends in this suffix, so the
// numeric prefix can move as cases are inserted.
func isolated(t *testing.T, suffix string) string {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(vectorRoot(), "trust-bad", "*-"+suffix+".cbor"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 {
		t.Fatalf("%d trust-bad cases end in %q; §9.1's rule is unpinned without "+
			"exactly one", len(matches), suffix)
	}
	return strings.TrimSuffix(filepath.Base(matches[0]), ".cbor")
}

// --- Cold-model gate run 8, defect D5 -----------------------------------
//
// §12.1 said `15` and `16` "parse cleanly as verifier keys and are refused
// only by the algorithm rule". For `16` that was true. `15` listed **one**
// witness against a policy naming three, so §9.1's correspondence rule
// refused it and the witness-key-algorithm MUST was never reached:
// `trust-no-witness-key-alg` — dropping that MUST outright — passed all 582
// checks.
//
// This is the same defect 6.5h-vi-b found in `07` and `08`, in a third file
// nobody thought to look at. So this test asks the question of the whole
// directory rather than of one case: any negative that is *about* a witness
// key must correspond with its policy, or it is about correspondence instead.

func TestTheWitnessKeyAlgorithmNegativeIsIsolated(t *testing.T) {
	doc := parseBad(t, isolated(t, "witness-key-is-a-note-key"))

	named := map[string]string{}
	for _, line := range strings.Split(doc.Policy, "\n") {
		fields := strings.FieldsFunc(line, func(r rune) bool { return r == ' ' || r == '\t' })
		if len(fields) >= 3 && fields[0] == "witness" {
			named[fields[1]] = fields[2]
		}
	}
	if len(named) != len(doc.Witnesses) {
		t.Errorf("the file lists %d witnesses and its policy names %d, so the "+
			"correspondence rule refuses it before the algorithm rule is reached",
			len(doc.Witnesses), len(named))
	}
	for _, w := range doc.Witnesses {
		key, ok := named[w.Name]
		if !ok {
			t.Errorf("witness %q is not in the policy, so correspondence decides", w.Name)
			continue
		}
		if key != w.Key {
			t.Errorf("witness %q has one key in `witnesses` and another in the policy, "+
				"so correspondence decides", w.Name)
		}
	}

	// ...and the defect it IS about has to be present.
	var noteKey bool
	for _, w := range doc.Witnesses {
		if v, err := parseKey(w.Key); err == nil && !v.IsCosigner() {
			noteKey = true
		}
	}
	if !noteKey {
		t.Error("no witness publishes a note key, so this case is not about the " +
			"algorithm rule at all")
	}
}
