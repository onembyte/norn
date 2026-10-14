package note

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
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

func TestVerifierKeyBase64RejectsIgnoredLineBreaks(t *testing.T) {
	public := ed25519.NewKeyFromSeed(make([]byte, 32)).Public().(ed25519.PublicKey)
	for _, key := range []string{
		VerifierKey("norn/test", public),
		CosignerVerifierKey("norn-witness/test", public),
	} {
		parts := strings.SplitN(key, "+", 3)
		data := parts[2]
		if len(data) != 44 || strings.Contains(data, "=") {
			t.Fatalf("33-byte verifier-key data must have 44 base64 characters and no padding: %q", data)
		}
		original, err := base64.StdEncoding.DecodeString(data)
		if err != nil || len(original) != 33 {
			t.Fatalf("canonical key data does not decode to 33 bytes: %v", err)
		}
		for _, lineBreak := range []string{"\r", "\n"} {
			mutatedData := data[:12] + lineBreak + data[12:]
			decoded, err := base64.StdEncoding.DecodeString(mutatedData)
			if err != nil || !equal(decoded, original) {
				t.Fatalf("lax decoding changed the key bytes: %v", err)
			}
			mutated := parts[0] + "+" + parts[1] + "+" + mutatedData
			if _, err := ParseVerifierKey(mutated); err == nil {
				t.Errorf("ParseVerifierKey accepted a line break in %d-byte key data: %q", len(original), mutated)
			}
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

// RFC 4648 §3.5 requires unused base64 pad bits to be zero. DecodeString
// accepts alternate final characters with the same bytes, so Split must
// reject the alternate spelling in both payload sizes it frames.
func TestSplitRejectsNonzeroSignaturePayloadPadBits(t *testing.T) {
	checkpoint, err := os.ReadFile(filepath.Join(vectorRoot(), "served", "checkpoint"))
	if err != nil {
		t.Fatal(err)
	}
	signed := string(checkpoint)
	lines := strings.Split(strings.TrimSuffix(signed, "\n"), "\n")
	found := map[int]bool{}
	for i, line := range lines {
		if !strings.HasPrefix(line, SigPrefix) {
			continue
		}
		cut := strings.LastIndex(line, " ") + 1
		blob := line[cut:]
		raw, err := base64.StdEncoding.DecodeString(blob)
		if err != nil {
			t.Fatal(err)
		}
		if len(raw) != 68 && len(raw) != 76 {
			t.Fatalf("unexpected signature payload length %d", len(raw))
		}
		bad := withNonzeroPadBits(t, blob)
		decoded, err := base64.StdEncoding.DecodeString(bad)
		if err != nil || !equal(decoded, raw) {
			t.Fatalf("mutated %d-byte payload does not decode to the same bytes: %v", len(raw), err)
		}
		mutated := append([]string(nil), lines...)
		mutated[i] = line[:cut] + bad
		if _, _, err := Split(strings.Join(mutated, "\n") + "\n"); !errors.Is(err, ErrNote) {
			t.Errorf("Split accepted nonzero pad bits in the %d-byte payload: %v", len(raw), err)
		}
		found[len(raw)] = true
	}
	for _, length := range []int{68, 76} {
		if !found[length] {
			t.Errorf("served checkpoint has no %d-byte signature payload", length)
		}
	}
}

func withNonzeroPadBits(t *testing.T, encoded string) string {
	t.Helper()
	canonical, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || base64.StdEncoding.EncodeToString(canonical) != encoded {
		t.Fatalf("input is not canonical base64: %v", err)
	}
	padding := len(encoded) - len(strings.TrimRight(encoded, "="))
	if padding == 0 {
		t.Fatal("test input has no padding bits")
	}
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	position := len(encoded) - padding - 1
	value := strings.IndexByte(alphabet, encoded[position])
	unused := padding * 2
	mask := (1 << unused) - 1
	mutated := []byte(encoded)
	mutated[position] = alphabet[(value&^mask)|1]
	return string(mutated)
}

// D-078 (4), cold gate run 15's L2. A note's text lines are non-empty (§7),
// so a note whose first line is blank has an empty first text line: it is
// malformed framing, refused here, not a text that fails a signature later.
func TestSplitRefusesANoteWhoseFirstLineIsBlank(t *testing.T) {
	signed, err := Sign("hello\nworld\n", "norn/test", ed25519.NewKeyFromSeed(make([]byte, 32)))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Split(signed); err != nil {
		t.Fatalf("the honest note does not split: %v", err)
	}
	for _, bad := range []string{"\n" + signed, "\n\n" + signed[strings.Index(signed, "\n\n")+2:]} {
		if text, _, err := Split(bad); err == nil {
			t.Errorf("a note whose first line is blank split, text %q", text)
		}
	}
	if _, err := Sign("\nhello\n", "norn/test", ed25519.NewKeyFromSeed(make([]byte, 32))); err == nil {
		t.Error("a text whose first line is blank was signed")
	}
}
