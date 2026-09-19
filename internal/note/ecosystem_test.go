package note_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	upstream "golang.org/x/mod/sumdb/note"

	"github.com/onembyte/norn/internal/note"
	"github.com/onembyte/norn/internal/trust"
)

// PLAN.md ground rule 3: reuse the transparency ecosystem, do not fork it.
//
// Until now both sides of the note encoding were mine -- my signer and my
// verifier agreeing proves only that I am consistent with myself. This checks
// against Go's canonical implementation, the one the whole transparency
// ecosystem uses. Flagged as unverified in checkpoint 0.5; verified here.

func vectorRoot() string { return filepath.Join("..", "..", "testdata", "vectors") }

func loadTrust(t *testing.T) *trust.Trust {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(vectorRoot(), "trust.cbor"))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := trust.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

func TestUpstreamAcceptsOurVerifierKeysUnchanged(t *testing.T) {
	doc := loadTrust(t)
	keys := []string{doc.LogKey}
	for _, w := range doc.Witnesses {
		keys = append(keys, w.Key)
	}
	for _, vkey := range keys {
		v, err := upstream.NewVerifier(vkey)
		if err != nil {
			t.Errorf("golang.org/x/mod/sumdb/note rejects our verifier key %q: %v",
				vkey[:min(len(vkey), 40)], err)
			continue
		}
		ours, err := note.ParseVerifierKey(vkey)
		if err != nil {
			t.Fatal(err)
		}
		if v.Name() != ours.Name {
			t.Errorf("name disagreement: upstream %q, ours %q", v.Name(), ours.Name)
		}
		// Upstream exposes the key id as a uint32; ours is the same four bytes.
		wantID := uint32(ours.ID()[0])<<24 | uint32(ours.ID()[1])<<16 |
			uint32(ours.ID()[2])<<8 | uint32(ours.ID()[3])
		if v.KeyHash() != wantID {
			t.Errorf("key id disagreement: upstream %08x, ours %08x", v.KeyHash(), wantID)
		}
	}
}

func TestUpstreamVerifiesTheShippedReceipt(t *testing.T) {
	doc := loadTrust(t)
	signed, err := os.ReadFile(filepath.Join(vectorRoot(), "receipt.note"))
	if err != nil {
		t.Fatal(err)
	}
	v, err := upstream.NewVerifier(doc.LogKey)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := upstream.Open(signed, upstream.VerifierList(v))
	if err != nil {
		t.Fatalf("upstream cannot open our receipt: %v", err)
	}
	// The signed text boundary must agree: upstream returns exactly the text
	// our own Split returns, which is what receipt.json's hash pins.
	ourText, _, err := note.Split(string(signed))
	if err != nil {
		t.Fatal(err)
	}
	if opened.Text != ourText {
		t.Errorf("signed-text disagreement:\nupstream %q\nours     %q", opened.Text, ourText)
	}
	var meta struct {
		TextSHA256 string `json:"text_sha256"`
	}
	raw, err := os.ReadFile(filepath.Join(vectorRoot(), "receipt.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &meta); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(opened.Text))
	if hex.EncodeToString(sum[:]) != meta.TextSHA256 {
		t.Error("the text upstream returns does not hash to receipt.json's text_sha256")
	}
}

func TestUpstreamOpensWhatWeSign(t *testing.T) {
	skey, vkey, err := upstream.GenerateKey(rand.Reader, "norn/interop")
	if err != nil {
		t.Fatal(err)
	}
	// Recover the raw Ed25519 private key by signing with upstream and
	// checking ours verifies -- and the reverse below.
	signer, err := upstream.NewSigner(skey)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := upstream.Sign(&upstream.Note{Text: "norn/receipt/v1\nhello\n"}, signer)
	if err != nil {
		t.Fatal(err)
	}
	text, err := note.Verify(string(signed), []string{vkey})
	if err != nil {
		t.Fatalf("we cannot verify what upstream signed: %v", err)
	}
	if text != "norn/receipt/v1\nhello\n" {
		t.Errorf("text round trip: got %q", text)
	}
}

func TestOurSignatureOpensUpstream(t *testing.T) {
	// Build a key pair, sign with ours, open with upstream.
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	priv := ed25519From(seed)
	vkey := note.VerifierKey("norn/interop", priv.Public().(ed25519.PublicKey))

	signed, err := note.Sign("norn/receipt/v1\nhello\n", "norn/interop", priv)
	if err != nil {
		t.Fatal(err)
	}
	v, err := upstream.NewVerifier(vkey)
	if err != nil {
		t.Fatalf("upstream rejects a verifier key we produced: %v", err)
	}
	opened, err := upstream.Open([]byte(signed), upstream.VerifierList(v))
	if err != nil {
		t.Fatalf("upstream cannot open a note we signed: %v", err)
	}
	if opened.Text != "norn/receipt/v1\nhello\n" {
		t.Errorf("text disagreement: %q", opened.Text)
	}
	if len(opened.Sigs) != 1 || opened.Sigs[0].Name != "norn/interop" {
		t.Errorf("unexpected signature list: %+v", opened.Sigs)
	}
}

func TestOurKeyIDDerivationMatchesUpstream(t *testing.T) {
	for i := 0; i < 32; i++ {
		seed := make([]byte, 32)
		seed[0] = byte(i)
		priv := ed25519From(seed)
		name := "norn/" + strings.Repeat("x", i%7+1)
		vkey := note.VerifierKey(name, priv.Public().(ed25519.PublicKey))
		v, err := upstream.NewVerifier(vkey)
		if err != nil {
			t.Fatalf("upstream rejects our key %d: %v", i, err)
		}
		ours := note.KeyID(name, priv.Public().(ed25519.PublicKey))
		want := uint32(ours[0])<<24 | uint32(ours[1])<<16 | uint32(ours[2])<<8 | uint32(ours[3])
		if v.KeyHash() != want {
			t.Errorf("key %d: upstream %08x, ours %08x", i, v.KeyHash(), want)
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
