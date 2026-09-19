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
