package forkevidence

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/onembyte/norn/internal/evrefusal"
)

// D-079 (1), from cold gate run 16. The policy fork evidence carries decides
// nothing, and §3.1 item 2 listed the point check only where a key enters
// state, so a reader that checks keys there and nowhere else proved a fork
// from a file whose carried policy names a small-order witness key, while
// this one refused it. The decision: a policy parses one way everywhere, and
// the file is `policy`. This pins the answer Go already gave.
func TestTheCarriedPolicysKeysAreValidPointsOrTheFileIsPolicy(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "vectors")
	raw, err := os.ReadFile(filepath.Join(root, "fork", "evidence.cbor"))
	if err != nil {
		t.Fatal(err)
	}
	ev, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	// The order-8 witness key `log-admission/07-policy-small-order` carries,
	// under pi's name with its id recomputed: the grammar accepts it, and
	// only the point check refuses it.
	ev.Policy = "witness pi norn-witness/pi+29cbce49+BCbolY/CsiewRcP0ifLvmPDV36wF08YzObE4AohtU/wF\nquorum pi\n"
	raw, err = ev.Encode()
	if err != nil {
		t.Fatal(err)
	}
	ev, err = Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	anchor := shippedAnchor(t, root)
	_, err = Check(ev, anchor.Origin, []string{anchor.LogKey}, anchor.Policy)
	code, _ := evrefusal.CodeOf(err)
	if code != evrefusal.Policy || !strings.Contains(err.Error(), "valid point") {
		t.Fatalf("Go answers %q (%v), SPEC states policy for a carried key that is not a valid point", code, err)
	}
}
