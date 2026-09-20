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

	cosigner "github.com/transparency-dev/formats/note"
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

// The trust file carries two kinds of key, and they belong to two different
// ecosystems. The **log key** is a note key, and `x/mod/sumdb/note` -- the
// package the whole transparency world uses -- must accept it. The **witness
// keys** are cosignature keys (algorithm 0x04), which sumdb deliberately does
// not know; `transparency-dev/formats/note` is what understands those, and it
// is the package a real witness uses.
//
// This test asserted the wrong thing until 4.1a: it required sumdb to accept
// the witness keys, and passed only because Norn was encoding them as note
// keys. Both sides were wrong in the same way, which is exactly the failure a
// cross-check is supposed to be immune to.
func TestUpstreamAcceptsTheLogKeyUnchanged(t *testing.T) {
	doc := loadTrust(t)
	v, err := upstream.NewVerifier(doc.LogKey)
	if err != nil {
		t.Fatalf("golang.org/x/mod/sumdb/note rejects our log key: %v", err)
	}
	ours, err := note.ParseVerifierKey(doc.LogKey)
	if err != nil {
		t.Fatal(err)
	}
	if ours.IsCosigner() {
		t.Fatal("the log key must be a note key, not a cosignature key")
	}
	if v.Name() != ours.Name {
		t.Errorf("name disagreement: upstream %q, ours %q", v.Name(), ours.Name)
	}
	wantID := uint32(ours.ID()[0])<<24 | uint32(ours.ID()[1])<<16 |
		uint32(ours.ID()[2])<<8 | uint32(ours.ID()[3])
	if v.KeyHash() != wantID {
		t.Errorf("key id disagreement: upstream %08x, ours %08x", v.KeyHash(), wantID)
	}
}

// And the witness keys must be the kind a witness actually publishes.
func TestWitnessKeysAreCosignatureKeys(t *testing.T) {
	doc := loadTrust(t)
	if len(doc.Witnesses) == 0 {
		t.Fatal("the trust vector has no witnesses")
	}
	for _, w := range doc.Witnesses {
		ours, err := note.ParseVerifierKey(w.Key)
		if err != nil {
			t.Fatalf("%s: %v", w.Name, err)
		}
		if !ours.IsCosigner() {
			t.Errorf("%s is published as a note key; a witness publishes algorithm 0x%02x",
				w.Name, note.AlgCosignature)
		}
		// The package a real witness uses must accept it as it stands.
		if _, err := cosigner.NewVerifierForCosignatureV1(w.Key); err != nil {
			t.Errorf("%s: transparency-dev/formats rejects it: %v", w.Name, err)
		}
		// And sumdb must *not*: these are not note keys, and a build that
		// accepted them there would be back where 4.1a started.
		if _, err := upstream.NewVerifier(w.Key); err == nil {
			t.Errorf("%s parsed as a plain note key", w.Name)
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
