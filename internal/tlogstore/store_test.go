package tlogstore

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	upstream "golang.org/x/mod/sumdb/tlog"

	"github.com/onembyte/norn/internal/cosign"
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
	return ed25519.NewKeyFromSeed(seedOf("norn/tlogstore-test/log-key"))
}

func seedOf(label string) []byte {
	seed := sha256.Sum256([]byte(label))
	return seed[:]
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

func TestFullTileRemovesItsSupersededPartialPath(t *testing.T) {
	dir := t.TempDir()
	store, err := Open(dir, "norn/test", testLogKey(t))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < tlog.TileWidth-1; i++ {
		if _, err := store.Append([]byte{byte(i)}); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	partial := filepath.Join(dir, filepath.FromSlash(tlog.TilePath(0, 0, tlog.TileWidth-1)))
	if _, err := os.Stat(partial); err != nil {
		t.Fatalf("width %d partial tile is missing: %v", tlog.TileWidth-1, err)
	}
	if _, err := store.Append([]byte{0xff}); err != nil {
		t.Fatalf("append the tile's final leaf: %v", err)
	}
	full := filepath.Join(dir, filepath.FromSlash(tlog.TilePath(0, 0, tlog.TileWidth)))
	if _, err := os.Stat(full); err != nil {
		t.Fatalf("full tile is missing: %v", err)
	}
	if _, err := os.Stat(filepath.Dir(partial)); !os.IsNotExist(err) {
		t.Errorf("superseded partial tile path %s still exists (stat error %v)", filepath.Dir(partial), err)
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

// A log that has witnesses must serve a checkpoint carrying their
// cosignatures, not just its own signature: §10 step 3 makes the quorum part
// of what a verifier checks, so a head no witness has corroborated is a head
// no correctly-configured node will accept. The store does not know how a
// cosignature is obtained -- over `tlog-witness` from a real witness (4.3), or
// from a key held locally in a test -- so it asks a Cosigner.
func TestACosignerReachesTheServedCheckpoint(t *testing.T) {
	dir := t.TempDir()
	witnessKey := ed25519.NewKeyFromSeed(seedOf("norn/tlogstore-test/witness"))
	store, err := Open(dir, "norn/test", testLogKey(t), WithCosigner(CosignerFunc(func(signed string) (string, error) {
		body, _, err := note.Split(signed)
		if err != nil {
			return "", err
		}
		line, err := cosign.Sign(body, "a-witness", witnessKey, time.Unix(1_760_003_600, 0))
		if err != nil {
			return "", err
		}
		return signed + line + "\n", nil
	})))
	if err != nil {
		t.Fatal(err)
	}

	for _, raw := range suiteEntries(t)[:3] {
		if _, err := store.Append(raw); err != nil {
			t.Fatal(err)
		}
	}

	raw, err := os.ReadFile(filepath.Join(dir, "checkpoint"))
	if err != nil {
		t.Fatal(err)
	}
	// Every republished checkpoint carries it, not only the first.
	cosignatures, err := cosign.Verify(string(raw),
		[]string{note.CosignerVerifierKey("a-witness", witnessKey.Public().(ed25519.PublicKey))})
	if err != nil || len(cosignatures) != 1 {
		t.Errorf("the served checkpoint lost its cosignature (%v):\n%s", err, raw)
	}
	// And the log's own signature still verifies over the same body.
	public := testLogKey(t).Public().(ed25519.PublicKey)
	if _, err := tlog.Verify(string(raw), []string{note.VerifierKey("norn/test", public)}); err != nil {
		t.Errorf("cosigning broke the log's own signature: %v", err)
	}
}

// A cosigner that returns an error is broken, and a broken cosigner fails the
// publish rather than silently producing a bare head.
//
// This is *not* the unreachable-witness case. `GOSSIP.md`'s T6 says a witness
// outage must not stop a log, so `witness.Submitter` returns the head with
// whatever it collected and never errors for a witness that is merely down.
// An error arriving here means the cosigning machinery itself failed.
func TestAFailingCosignerFailsTheAppend(t *testing.T) {
	dir := t.TempDir()
	unreachable := CosignerFunc(func(string) (string, error) {
		return "", errors.New("witness unreachable")
	})
	if _, err := Open(dir, "norn/test", testLogKey(t), WithCosigner(unreachable)); err == nil {
		t.Fatal("opening with an unreachable witness looked like success")
	}

	store, err := Open(dir, "norn/test", testLogKey(t))
	if err != nil {
		t.Fatal(err)
	}
	store.cosigner = unreachable
	if _, err := store.Append([]byte("an entry")); err == nil {
		t.Fatal("an append succeeded although no witness corroborated the head")
	}
}

// A store that gains a witness -- a log that was running before the network
// had one, or one restarted with new keys -- must republish its head, not wait
// for the next append. Otherwise it serves a checkpoint produced under the old
// configuration, which here means one no verifier will accept, while every
// status line reports a healthy log.
func TestOpeningRepublishesTheCheckpoint(t *testing.T) {
	dir := t.TempDir()
	store, err := Open(dir, "norn/test", testLogKey(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range suiteEntries(t)[:4] {
		if _, err := store.Append(raw); err != nil {
			t.Fatal(err)
		}
	}
	before, err := os.ReadFile(filepath.Join(dir, "checkpoint"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(before), "a-witness") {
		t.Fatal("this log has no witness yet")
	}

	witnessKey := ed25519.NewKeyFromSeed(seedOf("norn/tlogstore-test/witness"))
	reopened, err := Open(dir, "norn/test", testLogKey(t), WithCosigner(CosignerFunc(
		cosign.Append([]cosign.Signer{{Name: "a-witness", Key: witnessKey}},
			cosign.At(time.Unix(1_760_003_600, 0))))))
	if err != nil {
		t.Fatal(err)
	}
	if reopened.Size() != 4 {
		t.Fatalf("size = %d, want 4", reopened.Size())
	}

	after, err := os.ReadFile(filepath.Join(dir, "checkpoint"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cosign.Verify(string(after),
		[]string{note.CosignerVerifierKey("a-witness", witnessKey.Public().(ed25519.PublicKey))}); err != nil {
		t.Errorf("opening with a cosigner left the old uncosigned head served: %v", err)
	}
}

// A log may hold one witness key itself and ask others over the network. Both
// have to reach the checkpoint: two calls to WithCosigner would otherwise mean
// the second silently replaces the first, and an operator who configured both
// would lose the remote witnesses without being told.
func TestCosignersCombine(t *testing.T) {
	dir := t.TempDir()
	first := CosignerFunc(func(signed string) (string, error) { return signed + "one\n", nil })
	second := CosignerFunc(func(signed string) (string, error) { return signed + "two\n", nil })

	store, err := Open(dir, "norn/test", testLogKey(t), WithCosigner(Cosigners(first, second)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Append([]byte("an entry")); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(filepath.Join(dir, "checkpoint"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "one\n") || !strings.Contains(string(raw), "two\n") {
		t.Errorf("both cosigners must reach the checkpoint:\n%s", raw)
	}
}

// fiveEntries opens a fresh store, appends five fixture entries, and returns
// the directory and the partial-bundle directory the five live in.
func fiveEntries(t *testing.T) (dir, partial string) {
	t.Helper()
	dir = t.TempDir()
	store, err := Open(dir, "norn/test", testLogKey(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range suiteEntries(t)[:5] {
		if _, err := store.Append(raw); err != nil {
			t.Fatal(err)
		}
	}
	return dir, filepath.Join(dir, "tile", "entries", "000.p")
}

// SEC-011. A power cut between creating a temporary file and writing it
// leaves an empty `.tmp-*` in the partial-bundle directory; the glob that
// finds partials matched dotfiles and read the first match, and an empty file
// decodes to no entries -- so a 5-entry log reopened at size 0, and the store
// signed and published that head. Temporaries are not bundles.
func TestALeftoverTemporaryDoesNotShrinkTheLogOnReopen(t *testing.T) {
	dir, partial := fiveEntries(t)
	if err := os.WriteFile(filepath.Join(partial, ".tmp-000"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(dir, "norn/test", testLogKey(t))
	if err != nil {
		t.Fatal(err)
	}
	if reopened.Size() != 5 {
		t.Fatalf("reopened at size %d, want 5: a leftover temporary was read as the bundle", reopened.Size())
	}
}

// A crash between writing the new partial and removing the old one leaves two
// widths side by side. The log is the longer one; the shorter is what a crash
// left, and reading it by luck of directory order shrinks the log by one.
func TestTwoPartialWidthsResolveToTheWider(t *testing.T) {
	dir, partial := fiveEntries(t)
	// Rebuild the 4-entry partial exactly as the store wrote it before the
	// fifth append, beside the 5-entry one.
	four, err := tlog.EncodeBundle(suiteEntries(t)[:4])
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(partial, "4"), four, 0o644); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(dir, "norn/test", testLogKey(t))
	if err != nil {
		t.Fatal(err)
	}
	if reopened.Size() != 5 {
		t.Fatalf("reopened at size %d, want 5: the narrower partial was read", reopened.Size())
	}
}

// A partial whose name claims a width it does not hold is not the log either:
// the widest name wins only when the file decodes to exactly that many
// entries, or a lying name would shrink -- or worse, misorder -- the log.
func TestAPartialIsReadOnlyAtTheWidthItsNameClaims(t *testing.T) {
	dir, partial := fiveEntries(t)
	four, err := tlog.EncodeBundle(suiteEntries(t)[:4])
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(partial, "9"), four, 0o644); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(dir, "norn/test", testLogKey(t))
	if err != nil {
		t.Fatal(err)
	}
	if reopened.Size() != 5 {
		t.Fatalf("reopened at size %d, want 5: a file named 9 holding four entries was read", reopened.Size())
	}
}

// SEC-011, the damage a reader cannot resolve. If the bundles recover fewer
// entries than the checkpoint this store last signed and published claims,
// the entries are lost, and a store that opened anyway would sign and publish
// a smaller head -- a log that shrank, which every node refuses as a rollback
// and a self-witnessed log proves as a fork against itself. Refusing to open
// is the honest answer: the operator restores the bundles first.
func TestAStoreRefusesToOpenBelowTheCheckpointItSigned(t *testing.T) {
	dir, partial := fiveEntries(t)
	if err := os.RemoveAll(partial); err != nil {
		t.Fatal(err)
	}
	_, err := Open(dir, "norn/test", testLogKey(t))
	if err == nil {
		t.Fatal("a store whose bundles are gone opened, and would have published a smaller head")
	}
	for _, want := range []string{"5", "0", "restore"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal should carry %q: %v", want, err)
		}
	}
}

// The checkpoint is written last, so a crash before it leaves a checkpoint
// behind the bundles; that is the designed case and must still open, at the
// bundles' size. A checkpoint torn by the crash is the same case.
func TestAStoreOpensWhenTheCheckpointIsBehindOrTorn(t *testing.T) {
	t.Run("behind", func(t *testing.T) {
		dir, _ := fiveEntries(t)
		four, err := tlog.Build(suiteEntries(t)[:4])
		if err != nil {
			t.Fatal(err)
		}
		signed, err := four.Checkpoint("norn/test").Sign(testLogKey(t))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "checkpoint"), []byte(signed), 0o644); err != nil {
			t.Fatal(err)
		}
		reopened, err := Open(dir, "norn/test", testLogKey(t))
		if err != nil {
			t.Fatalf("a checkpoint behind the bundles refused to open: %v", err)
		}
		if reopened.Size() != 5 {
			t.Errorf("reopened at %d, want the bundles' 5", reopened.Size())
		}
	})
	t.Run("torn", func(t *testing.T) {
		dir, _ := fiveEntries(t)
		if err := os.WriteFile(filepath.Join(dir, "checkpoint"), []byte("norn/test\n5\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(dir, "norn/test", testLogKey(t)); err != nil {
			t.Fatalf("a torn checkpoint refused to open: %v", err)
		}
	})
}
