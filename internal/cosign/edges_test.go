package cosign

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/onembyte/norn/internal/refusal"
)

// §3.1 item 3 on a witness's line: an honest cosignature with S + L is a
// listed witness's line that does not verify, so §10.1 calls it `cosignature`.
func TestTheRaisedScalarCosignatureIsRefused(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(vectorRoot(), "checkpoints-bad", "31-cosignature-S-plus-L.checkpoint"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = Verify(string(raw), witnessKeys(t))
	if code, ok := refusal.CodeOf(err); !ok || code != refusal.Cosignature {
		t.Fatalf("S + L cosignature: %v", err)
	}
}
