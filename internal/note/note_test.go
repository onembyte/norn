package note

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Written from SPEC.md §7, which restates the signed-note framing so an
// implementer needs nothing else. The shipped receipt is the oracle.

func vectorRoot() string { return filepath.Join("..", "..", "testdata", "vectors") }

func TestKeyIDBindsTheNameAndAlgorithm(t *testing.T) {
	pub := ed25519.NewKeyFromSeed(make([]byte, 32)).Public().(ed25519.PublicKey)
	want := sha256.Sum256(append(append([]byte("a.example"), '\n', AlgEd25519), pub...))
	if got := KeyID("a.example", pub); !equal(got, want[:4]) {
		t.Errorf("KeyID = %x, want %x", got, want[:4])
	}
	if equal(KeyID("a.example", pub), KeyID("b.example", pub)) {
		t.Error("the key id must bind the name, so one key under two names has two ids")
	}
}

func equal(a, b []byte) bool { return string(a) == string(b) }

func TestVerifierKeyRoundTripsEvenWhenBase64ContainsPlus(t *testing.T) {
	// Standard base64 emits "+", so parsing must split at most twice.
	var withPlus ed25519.PublicKey
	for i := byte(0); i < 200; i++ {
		seed := make([]byte, 32)
		seed[0] = i
		pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
		if strings.Contains(base64.StdEncoding.EncodeToString(append([]byte{AlgEd25519}, pub...)), "+") {
			withPlus = pub
			break
		}
	}
	if withPlus == nil {
		t.Skip("no probe key produced a + in its encoding")
	}
	vkey := VerifierKey("norn/x", withPlus)
	parsed, err := ParseVerifierKey(vkey)
	if err != nil {
		t.Fatalf("a key whose base64 contains + must still parse: %v", err)
	}
	if !equal(parsed.Public, withPlus) || parsed.Name != "norn/x" {
		t.Errorf("round trip lost information: %+v", parsed)
	}
}

func TestParseVerifierKeyRejectsMalformed(t *testing.T) {
	for _, bad := range []string{"", "a+b", "a+zz+AAAA", "name+00000000+not base64!"} {
		if _, err := ParseVerifierKey(bad); err == nil {
			t.Errorf("ParseVerifierKey(%q) should have failed", bad)
		}
	}
}

func TestTheShippedReceiptVerifiesUnderTheTrustLogKey(t *testing.T) {
	signed, err := os.ReadFile(filepath.Join(vectorRoot(), "receipt.note"))
	if err != nil {
		t.Fatal(err)
	}
	var meta struct {
		Origin     string `json:"origin"`
		LeafHash   string `json:"leaf_hash"`
		Deadline   uint64 `json:"deadline"`
		TextSHA256 string `json:"text_sha256"`
	}
	raw, err := os.ReadFile(filepath.Join(vectorRoot(), "receipt.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &meta); err != nil {
		t.Fatal(err)
	}

	text, sigs, err := Split(string(signed))
	if err != nil {
		t.Fatal(err)
	}
	// The signed text runs through the newline ending the last text line and
	// excludes the blank separator -- the boundary §7 states explicitly.
	sum := sha256.Sum256([]byte(text))
	if got := hex.EncodeToString(sum[:]); got != meta.TextSHA256 {
		t.Errorf("signed-text hash %s, want %s", got, meta.TextSHA256)
	}
	if len(sigs) == 0 {
		t.Fatal("the receipt carries no signature line")
	}

	body, err := ReceiptText(meta.Origin, mustHex(t, meta.LeafHash), meta.Deadline)
	if err != nil {
		t.Fatal(err)
	}
	if body != text {
		t.Errorf("rebuilt receipt text differs:\n got %q\nwant %q", body, text)
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSignThenVerify(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(make([]byte, 32))
	pub := priv.Public().(ed25519.PublicKey)
	vkey := VerifierKey("norn/test", pub)

	signed, err := Sign("hello\nworld\n", "norn/test", priv)
	if err != nil {
		t.Fatal(err)
	}
	text, err := Verify(signed, []string{vkey})
	if err != nil {
		t.Fatalf("a note must verify under its own key: %v", err)
	}
	if text != "hello\nworld\n" {
		t.Errorf("got %q", text)
	}

	tampered := strings.Replace(signed, "world", "wortd", 1)
	if _, err := Verify(tampered, []string{vkey}); err == nil {
		t.Error("a tampered note must not verify")
	}
	other := ed25519.NewKeyFromSeed(append(make([]byte, 31), 9)).Public().(ed25519.PublicKey)
	if _, err := Verify(signed, []string{VerifierKey("norn/test", other)}); err == nil {
		t.Error("a note must not verify under an unrelated key")
	}
}

func TestSignRejectsTextWithoutATrailingNewline(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(make([]byte, 32))
	if _, err := Sign("no newline", "norn/test", priv); err == nil {
		t.Error("note text must end with a newline")
	}
}

// Cold-model gate run 12, defect D13. §7 says a key name contains no space and
// the line splits at its first one; neither parser here refused a verifier key
// whose name carries a space, or a signature line whose name is empty.
func TestAKeyNameIsNonEmptyAndContainsNoSpace(t *testing.T) {
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	if _, err := ParseVerifierKey(VerifierKey("norn testnet", key.Public().(ed25519.PublicKey))); err == nil {
		t.Error("a verifier key whose name contains a space was accepted")
	}
	signed, err := Sign("norn/testnet\n1\nAAAA\n", "norn/testnet", key)
	if err != nil {
		t.Fatal(err)
	}
	text, block, _ := strings.Cut(signed, "\n\n")
	_, payload, _ := strings.Cut(strings.TrimPrefix(strings.TrimRight(block, "\n"), SigPrefix), " ")
	if _, _, err := Split(text + "\n\n" + SigPrefix + " " + payload + "\n"); err == nil {
		t.Error("a signature line with an empty name was accepted")
	}
	if _, _, err := Split(signed); err != nil {
		t.Fatalf("the control does not split: %v", err)
	}
}
