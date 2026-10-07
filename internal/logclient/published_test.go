package logclient

import (
	"crypto/ed25519"
	"crypto/sha256"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/onembyte/norn/internal/note"
)

// On a log that verifies, what a log publishes is exactly what verifying it
// replays: one replay, read two ways.
func TestPublishedIsWhatVerifyReplays(t *testing.T) {
	dir, anchor := servedLog(t)
	verified, err := Verify(Dir(dir), anchor)
	if err != nil {
		t.Fatal(err)
	}
	published, err := Published(Dir(dir), anchor.Anchor)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(published, verified.State) {
		t.Error("Published and Verify replayed the same log to different states")
	}
}

// Its one purpose is the case Verify refuses: a head signed by a key this
// anchor has not learned yet. So it must answer there -- which is also why
// nothing it returns may be enforced.
func TestPublishedAnswersWhereVerifyCannot(t *testing.T) {
	dir, anchor := servedLog(t)
	raw, err := os.ReadFile(filepath.Join(dir, "checkpoint"))
	if err != nil {
		t.Fatal(err)
	}
	text, _, err := note.Split(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	seed := sha256.Sum256([]byte("norn/logclient-test/a-key-nobody-trusts"))
	stranger, err := note.Sign(text, "norn/test", ed25519.NewKeyFromSeed(seed[:]))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "checkpoint"), []byte(stranger), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(Dir(dir), anchor); err == nil {
		t.Fatal("verified a head signed by a key the anchor does not hold")
	}
	published, err := Published(Dir(dir), anchor.Anchor)
	if err != nil {
		t.Fatalf("Published refused a log it only has to read: %v", err)
	}
	if len(published.Devices) == 0 {
		t.Error("the published state is empty")
	}
}

func TestPublishedNeedsEveryBundle(t *testing.T) {
	dir, anchor := servedLog(t)
	bundles, err := filepath.Glob(filepath.Join(dir, "tile", "entries", "*"))
	if err != nil || len(bundles) == 0 {
		t.Fatalf("no bundles to remove: %v", err)
	}
	if err := os.RemoveAll(bundles[0]); err != nil {
		t.Fatal(err)
	}
	if _, err := Published(Dir(dir), anchor.Anchor); err == nil {
		t.Error("Published replayed a log with a bundle missing")
	}
}
