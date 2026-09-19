package tlogstore

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"testing"

	upstream "golang.org/x/mod/sumdb/tlog"

	"github.com/onembyte/norn/internal/note"
	"github.com/onembyte/norn/internal/tlog"
)

// A log is only useful if it survives being stopped. These tests care about
// three properties in particular, because they are the ones a log operator can
// violate without anyone noticing: entries keep their order, the tree head is
// reproducible from what is on disk, and size never goes backwards.

// testLogKey is the key these stores sign their checkpoints with. SPEC §6
// makes the checkpoint a signed note, so a store cannot publish one without a
// key; deriving it keeps failures reproducible.
func testLogKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	seed := sha256.Sum256([]byte("norn/tlogstore-test/log-key"))
	return ed25519.NewKeyFromSeed(seed[:])
}

func suiteEntries(t *testing.T) [][]byte {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join("..", "..", "testdata", "vectors", "log", "*.cbor"))
	if err != nil {
		t.Fatal(err)
	}
	out := make([][]byte, 0, len(matches))
	for _, path := range matches {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, raw)
	}
	return out
}

func TestAppendedEntriesReadBackInOrder(t *testing.T) {
	dir := t.TempDir()
	store, err := Open(dir, "norn/test", testLogKey(t))
	if err != nil {
		t.Fatal(err)
	}
	entries := suiteEntries(t)
	for _, raw := range entries {
		if _, err := store.Append(raw); err != nil {
			t.Fatal(err)
		}
	}
	if store.Size() != int64(len(entries)) {
		t.Fatalf("size %d, want %d", store.Size(), len(entries))
	}
	for i, want := range entries {
		got, err := store.Entry(int64(i))
		if err != nil {
			t.Fatalf("entry %d: %v", i, err)
		}
		if string(got) != string(want) {
			t.Fatalf("entry %d read back differently", i)
		}
	}
}

func TestReopeningReproducesTheSameHead(t *testing.T) {
	dir := t.TempDir()
	entries := suiteEntries(t)

	store, err := Open(dir, "norn/test", testLogKey(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range entries {
		if _, err := store.Append(raw); err != nil {
			t.Fatal(err)
		}
	}
	before := store.Checkpoint()

	reopened, err := Open(dir, "norn/test", testLogKey(t))
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	after := reopened.Checkpoint()
	if after != before {
		t.Errorf("reopening changed the checkpoint:\n before %+v\n after  %+v", before, after)
	}
	// And it must keep appending from where it left off, not from zero.
	if _, err := reopened.Append([]byte("one more")); err != nil {
		t.Fatal(err)
	}
	if reopened.Size() != int64(len(entries))+1 {
		t.Errorf("size after reopen+append is %d, want %d", reopened.Size(), len(entries)+1)
	}
}

func TestCheckpointSizeIsMonotonic(t *testing.T) {
	dir := t.TempDir()
	store, err := Open(dir, "norn/test", testLogKey(t))
	if err != nil {
		t.Fatal(err)
	}
	var last int64 = -1
	for _, raw := range suiteEntries(t)[:20] {
		if _, err := store.Append(raw); err != nil {
			t.Fatal(err)
		}
		cp := store.Checkpoint()
		if cp.Size <= last {
			t.Fatalf("checkpoint size went from %d to %d", last, cp.Size)
		}
		last = cp.Size
	}
}

func TestTheServedCheckpointParsesAndMatches(t *testing.T) {
	dir := t.TempDir()
	store, _ := Open(dir, "norn/test", testLogKey(t))
	for _, raw := range suiteEntries(t)[:5] {
		if _, err := store.Append(raw); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(filepath.Join(dir, "checkpoint"))
	if err != nil {
		t.Fatalf("a served log has a checkpoint file: %v", err)
	}
	// The file *is* the signed note (§6): it must verify under the log's own
	// key, and the head it carries must be the head the store holds.
	public := testLogKey(t).Public().(ed25519.PublicKey)
	parsed, err := tlog.Verify(string(raw), []string{note.VerifierKey("norn/test", public)})
	if err != nil {
		t.Fatalf("the served checkpoint must verify under the log key: %v", err)
	}
	if parsed != store.Checkpoint() {
		t.Errorf("served checkpoint %+v differs from in-memory %+v", parsed, store.Checkpoint())
	}
	if _, err := tlog.Verify(string(raw), nil); err == nil {
		t.Error("a checkpoint verified with no key at all")
	}
}

func TestInclusionProofsVerifyAgainstTheServedHead(t *testing.T) {
	dir := t.TempDir()
	store, _ := Open(dir, "norn/test", testLogKey(t))
	entries := suiteEntries(t)
	for _, raw := range entries {
		if _, err := store.Append(raw); err != nil {
			t.Fatal(err)
		}
	}
	cp := store.Checkpoint()
	for _, index := range []int64{0, 5, 50, cp.Size - 1} {
		proof, err := store.InclusionProof(index)
		if err != nil {
			t.Fatalf("proof %d: %v", index, err)
		}
		if err := upstream.CheckRecord(proof, cp.Size, cp.Root, index,
			tlog.LeafHash(entries[index])); err != nil {
			t.Errorf("proof for %d does not verify against the served head: %v", index, err)
		}
	}
}

func TestTheLayoutIsTheOneWeServe(t *testing.T) {
	dir := t.TempDir()
	store, _ := Open(dir, "norn/test", testLogKey(t))
	for _, raw := range suiteEntries(t) {
		if _, err := store.Append(raw); err != nil {
			t.Fatal(err)
		}
	}
	var found []string
	_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			rel, _ := filepath.Rel(dir, path)
			found = append(found, filepath.ToSlash(rel))
		}
		return nil
	})
	joined := strings.Join(found, "\n")
	for _, want := range []string{"checkpoint", "tile/entries/", "tile/0/"} {
		if !strings.Contains(joined, want) {
			t.Errorf("expected %q in the served layout, got:\n%s", want, joined)
		}
	}
	// No temporary files may survive a clean run.
	for _, name := range found {
		if strings.Contains(name, ".tmp") {
			t.Errorf("a temporary file survived: %s", name)
		}
	}
}

// The gate asks that a restart lose and reorder nothing, and that checkpoint
// size stay monotonic. Verifying an untouched log after reopening shows
// nothing was lost; this shows the log keeps *counting* from where it was.
// A store that recovered its entries but restarted its size would publish a
// checkpoint claiming fewer entries than it serves.
func TestSizeKeepsCountingAcrossARestart(t *testing.T) {
	dir := t.TempDir()
	entries := suiteEntries(t)

	store, err := Open(dir, "norn/test", testLogKey(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range entries[:10] {
		if _, err := store.Append(raw); err != nil {
			t.Fatal(err)
		}
	}
	before := store.Checkpoint()

	reopened, err := Open(dir, "norn/test", testLogKey(t))
	if err != nil {
		t.Fatal(err)
	}
	if got := reopened.Size(); got != before.Size {
		t.Fatalf("reopened at size %d, was %d", got, before.Size)
	}
	if reopened.Checkpoint() != before {
		t.Fatalf("the checkpoint changed across a restart: %+v -> %+v",
			before, reopened.Checkpoint())
	}

	index, err := reopened.Append(entries[10])
	if err != nil {
		t.Fatal(err)
	}
	if index != before.Size {
		t.Errorf("the entry after a restart landed at index %d, want %d", index, before.Size)
	}
	if after := reopened.Checkpoint(); after.Size != before.Size+1 {
		t.Errorf("size went %d -> %d across a restart and one append",
			before.Size, after.Size)
	}

	// And the entries are still in order: entry 0 is still entry 0.
	first, err := reopened.Entry(0)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, entries[0]) {
		t.Error("the first entry is not the one that was appended first")
	}
}
