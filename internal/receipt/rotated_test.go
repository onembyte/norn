package receipt

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/onembyte/norn/internal/note"
	"github.com/onembyte/norn/internal/trust"
)

// §7, §8, D-074 (a), as a shipped vector: a receipt the log signed with the key
// its roots published has two correct answers, decided by what the reader
// holds. One holding only trust.cbor refuses it as `log-signature`; one that
// has replayed the rotation, and so trusts the published key, accepts it.
// receipt-rotated/ says which key and points at the receipt.
func TestTheRotatedReceiptHasBothAnswers(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "vectors")
	var c struct {
		Receipt  string `json:"receipt"`
		SignedBy string `json:"signed_by"`
		Fresh    string `json:"fresh"`
		Informed string `json:"informed"`
	}
	raw, err := os.ReadFile(filepath.Join(root, "receipt-rotated", "cases.json"))
	if err != nil {
		t.Fatalf("the rotated-receipt vector is missing: %v", err)
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	signed, err := os.ReadFile(filepath.Join(root, "receipt-rotated", c.Receipt))
	if err != nil {
		t.Fatal(err)
	}
	blob, err := os.ReadFile(filepath.Join(root, "trust.cbor"))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := trust.Parse(blob)
	if err != nil {
		t.Fatal(err)
	}
	published, err := hex.DecodeString(c.SignedBy)
	if err != nil {
		t.Fatal(err)
	}
	if c.Fresh != string(LogSignature) || c.Informed != "accept" {
		t.Fatalf("cases.json says fresh %q, informed %q; want log-signature and accept", c.Fresh, c.Informed)
	}

	_, err = Check(string(signed), []string{doc.LogKey}, doc.Origin, nil, time.Time{})
	if code, _ := CodeOf(err); code != LogSignature {
		t.Errorf("a reader holding only trust.cbor: %q, want log-signature: %v", code, err)
	}
	informed := []string{doc.LogKey, note.VerifierKey(doc.Origin, published)}
	if _, err := Check(string(signed), informed, doc.Origin, nil, time.Time{}); err != nil {
		t.Errorf("a reader that trusts the published key refused the receipt: %v", err)
	}
}
