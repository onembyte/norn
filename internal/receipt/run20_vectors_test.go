package receipt

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/onembyte/norn/internal/note"
)

// Submitted-leaf binding and local expiry are omitted so the leaf's own
// width is the deciding check, and empty text reaches framing first.
func TestRunTwentyReceiptBoundariesAndTheirRepairs(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "vectors")
	keys := anchorLogKey(t, root)
	leaf, org, deadline := receiptFacts(t, root)
	seed := sha256.Sum256([]byte("norn/testvector/v1\nlogkey"))
	private := ed25519.NewKeyFromSeed(seed[:])
	for _, name := range []string{"leaf-31-bytes.note", "empty-signed-text.note"} {
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(root, "receipt-bad", name))
			if err != nil {
				t.Fatal(err)
			}
			want := Code("leaf-hash")
			if name == "empty-signed-text.note" {
				want = Code("note")
			}
			_, err = Check(string(raw), keys, org, nil, time.Time{})
			if code, ok := CodeOf(err); !ok || code != want {
				t.Fatalf("code=%q, want %q: %v", code, want, err)
			}
			var text string
			if name == "leaf-31-bytes.note" {
				text, err = note.Verify(string(raw), keys)
				if err != nil {
					t.Fatal(err)
				}
				lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
				short, err := base64.StdEncoding.Strict().DecodeString(lines[2])
				if err != nil || len(short) != 31 {
					t.Fatal("expected canonical 31-byte leaf")
				}
				if base64.StdEncoding.EncodeToString(short) != lines[2] {
					t.Fatal("noncanonical leaf")
				}
				lines[2] = base64.StdEncoding.EncodeToString(append(short, 0))
				text = strings.Join(lines, "\n") + "\n"
			} else {
				prefix := "\n— " + org + " "
				if !bytes.HasPrefix(raw, []byte(prefix)) {
					t.Fatal("empty text is not followed directly by signature framing")
				}
				payload, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSuffix(string(raw[len(prefix):]), "\n"))
				if err != nil || len(payload) != 68 {
					t.Fatal("bad framed payload")
				}
				vk, err := note.ParseVerifierKey(keys[0])
				if err != nil {
					t.Fatal(err)
				}
				if !ed25519.Verify(vk.Public, nil, payload[4:]) {
					t.Fatal("signature over empty text is not genuine")
				}
				text, err = note.ReceiptText(org, leaf, uint64(deadline))
				if err != nil {
					t.Fatal(err)
				}
			}
			repair, err := note.Sign(text, org, private)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Check(repair, keys, org, nil, time.Time{}); err != nil {
				t.Fatal("field-only repair refused", err)
			}
			t.Log("field-only repair accepted")
		})
	}
}
