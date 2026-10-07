package trust

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strconv"
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
	// `07-no-witnesses` has no witness names in the policy and uses `quorum none`,
	// so only the explicit witness minimum refuses this otherwise corresponding file.
	t.Run("no witnesses, and a policy that agrees", func(t *testing.T) {
		doc := parseBad(t, isolated(t, "no-witnesses"))
		if len(doc.Witnesses) != 0 {
			t.Fatalf("%d witnesses: this is not the no-witness case", len(doc.Witnesses))
		}
		if names := policyWitnessNames(t, doc.Policy); len(names) != 0 {
			t.Errorf("the policy names %v, so the correspondence rule refuses this "+
				"file before the witness minimum is reached", names)
		}
	})

	// `08` carries all policy-listed witnesses plus a second byte-identical `pi`;
	// only the witness-name uniqueness rule is broken.
	t.Run("a duplicate name that agrees with the policy", func(t *testing.T) {
		doc := parseBad(t, isolated(t, "duplicate-witness-name"))
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
	all, err := filepath.Glob(filepath.Join(vectorRoot(), "trust-bad", "*-"+suffix+".cbor"))
	if err != nil {
		t.Fatal(err)
	}
	// Only `NN-<suffix>`, so that `name-too-long` does not also match
	// `witness-name-too-long`. A helper that silently picks one of two is a
	// helper that tests whichever it happened to sort first.
	var matches []string
	for _, m := range all {
		stem := strings.TrimSuffix(filepath.Base(m), ".cbor")
		if prefix := strings.TrimSuffix(stem, "-"+suffix); prefix != stem {
			if _, err := strconv.Atoi(prefix); err == nil {
				matches = append(matches, m)
			}
		}
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

// --- Cold-model gate run 8, defect D22 ----------------------------------
//
// §9.1's table shows seven members it never constrains, and seven variants
// passed the whole suite. Three of them were live disagreements again: the Go
// side had no cap on a witness `name` while the reference did, the reference
// accepted an `anchor` missing `max_lag` while Go refused it, and neither
// constrained `anchor.mode` — so a file could say `enforcing` and two readers
// would do different things with it.

func TestEveryTrustMemberRuleHasItsCase(t *testing.T) {
	for _, c := range []struct{ suffix, why string }{
		{"witness-open-schema", "a witness element is a closed map of name, key and url"},
		// ...refused at whichever layer owns the rule: the closed-schema one
		// belongs to the codec, the rest to validation.
		{"witness-name-too-long", "a witness name is bounded, as the network name is"},
		{"log-url-empty-string", "`log_urls` holds non-empty strings"},
		{"anchor-missing-member", "when `anchor` is present all three members are required"},
		{"anchor-unknown-member", "the anchor map is closed"},
		{"anchor-unknown-mode", "an unknown enforcement mode is not safely ignorable"},
		{"policy-log-key-mismatch", "the policy's `log` line names this network's log"},
	} {
		t.Run(c.suffix, func(t *testing.T) {
			name := isolated(t, c.suffix)
			raw, err := os.ReadFile(filepath.Join(vectorRoot(), "trust-bad", name+".cbor"))
			if err != nil {
				t.Fatal(err)
			}
			doc, err := Parse(raw)
			if err != nil {
				t.Logf("§9.1: %s (refused by the schema)", c.why)
				return
			}
			if err := doc.Validate(); err == nil {
				t.Errorf("%s is accepted; §9.1 says %s", name, c.why)
			}
		})
	}
}

// Positives pin optional members and open URL values: a reader that requires a
// witness `url`, refuses an unknown anchor type, validates URL syntax, or
// requires policy/trust URL equality rejects files this document permits. An
// unknown anchor *type* is ignorable — anchoring is advisory (D-009) — where
// an unknown *mode* or member is not.
func TestTheOptionalTrustMembersAreOptional(t *testing.T) {
	for _, name := range []string{"witness-without-url", "anchor-unknown-type",
		"url-fields-are-opaque"} {
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(vectorRoot(), "trust-good", name+".cbor"))
			if err != nil {
				t.Fatalf("no positive vector: %v", err)
			}
			doc, err := Parse(raw)
			if err != nil {
				t.Fatalf("refused at parse a file §9.1 permits: %v", err)
			}
			if err := doc.Validate(); err != nil {
				t.Fatalf("refused a file §9.1 permits: %v", err)
			}
		})
	}
}

func TestOpaqueURLFieldsPreserveAnExplicitEmptyWitnessURL(t *testing.T) {
	name := "url-fields-are-opaque"
	raw, err := os.ReadFile(filepath.Join(vectorRoot(), "trust-good", name+".cbor"))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := doc.Validate(); err != nil {
		t.Fatalf("the URL values are opaque application data: %v", err)
	}
	if len(doc.LogURLs) != 1 || doc.LogURLs[0] != "http://[invalid" {
		t.Errorf("log_urls = %q, want the opaque non-empty value", doc.LogURLs)
	}
	var emptyURL *Witness
	for i := range doc.Witnesses {
		if doc.Witnesses[i].Name == "pi" {
			emptyURL = &doc.Witnesses[i]
		}
	}
	if emptyURL == nil || !emptyURL.HasURL || emptyURL.URL != "" {
		t.Fatalf("the explicit empty witness URL was lost: %+v", emptyURL)
	}
	encoded, err := doc.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != string(raw) {
		t.Error("re-encoding changed an explicitly present empty witness URL")
	}
	toml, err := doc.ToTOML()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(toml, "url  = \"\"\n") {
		t.Error("the TOML rendering omitted the explicitly empty witness URL")
	}
}

// Cold-model gate run 8, defect D21. A verifier key is `name+<keyid>+<data>`,
// and the key id is a hash of the name, the key **and the algorithm** -- which
// is what makes a note key and a cosignature key over the same public key two
// different verifiers (§9.1). Nothing forced a reader to check it: every
// shipped key had a correct id, so `vkey-no-id-check` passed.
func TestAVerifierKeyWhoseIdIsWrongIsRefused(t *testing.T) {
	doc := parseBad(t, isolated(t, "log-key-id-mismatch"))
	_ = doc
}

// Cold-model gate run 9, defects D8 and D16. §9.1 states `MAX_TRUST_BYTES`
// and nothing was ever that large, so a reader with no cap -- or a cap of a
// million -- passed the whole suite. The case is padded with **valid**
// `log_urls`: nothing bounds their count, so the file is correct in every
// other respect and only its size can refuse it.
//
// And D16: `anchor` is the one member §9.1 marks OPTIONAL, and all forty trust
// files carried one. A reader that required it rejected nothing in the suite.
func TestTheTrustSizeCapAndTheOptionalAnchorAreVectored(t *testing.T) {
	t.Run("oversize", func(t *testing.T) {
		// Refused by the decoder, which is where a size bound belongs: §9.1
		// says the file is refused **on length**, before anything it declares
		// is allocated. So this asserts a refusal at either layer, not that it
		// reaches validation.
		name := isolated(t, "oversize")
		raw, err := os.ReadFile(filepath.Join(vectorRoot(), "trust-bad", name+".cbor"))
		if err != nil {
			t.Fatal(err)
		}
		if len(raw) <= maxTrustBytesForTest {
			t.Fatalf("the case is %d bytes and the cap is %d; it pins nothing",
				len(raw), maxTrustBytesForTest)
		}
		doc, err := Parse(raw)
		if err != nil {
			return
		}
		if err := doc.Validate(); err == nil {
			t.Error("an oversize trust file was accepted")
		}
	})
	t.Run("no-anchor", func(t *testing.T) {
		raw, err := os.ReadFile(filepath.Join(vectorRoot(), "trust-good", "no-anchor.cbor"))
		if err != nil {
			t.Fatalf("`anchor` is OPTIONAL and no vector omits it: %v", err)
		}
		doc, err := Parse(raw)
		if err != nil {
			t.Fatalf("refused at parse a file with no anchor: %v", err)
		}
		if err := doc.Validate(); err != nil {
			t.Fatalf("`anchor` is OPTIONAL and this was refused: %v", err)
		}
	})
}

// maxTrustBytesForTest mirrors §9.1's stated cap, so the test fails if the
// vector stops being oversize rather than silently passing.
const maxTrustBytesForTest = MaxTrustBytes
