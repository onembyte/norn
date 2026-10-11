package tlog

import (
	"strings"
	"testing"

	"github.com/onembyte/norn/internal/cosign"
	"github.com/onembyte/norn/internal/note"
	"github.com/onembyte/norn/internal/policy"
	"github.com/onembyte/norn/internal/refusal"
	"github.com/onembyte/norn/internal/trust"
)

// A re-signed size overflow must reach the body parser, with every witness
// still verifying. Repairing the size recovers the honest body exactly.
func TestTheCheckpointIntegerBoundHasAReSignedVector(t *testing.T) {
	bad := read(t, "checkpoints-bad", "33-size-above-2-63.checkpoint")
	anchor, err := trust.Parse([]byte(read(t, "trust.cbor")))
	if err != nil {
		t.Fatal(err)
	}
	keys := []string{anchor.LogKey}
	_, err = Verify(bad, keys)
	if got, _ := refusal.CodeOf(err); got != refusal.Checkpoint {
		t.Fatalf("got %q (%v), want checkpoint", got, err)
	}
	body, err := note.Verify(bad, keys)
	if err != nil {
		t.Fatal(err)
	}
	honest, err := note.Verify(read(t, "served", "checkpoint"), keys)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(body, "\n")
	if lines[1] != "9223372036854775808" {
		t.Fatal("size is not exactly one past the integer bound")
	}
	lines[1] = strings.Split(honest, "\n")[1]
	if strings.Join(lines, "\n") != honest {
		t.Fatal("the size is not the only body fault")
	}
	if _, err := ParseCheckpoint(strings.Join(lines, "\n")); err != nil {
		t.Fatal(err)
	}
	rules, err := policy.Parse(anchor.Policy)
	if err != nil {
		t.Fatal(err)
	}
	signatures, err := cosign.Verify(bad, rules.Keys())
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, sig := range signatures {
		names[sig.Name] = true
	}
	if len(names) != 3 {
		t.Fatalf("%d witnesses verify, want all three", len(names))
	}
}
