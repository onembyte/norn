package mirror

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/onembyte/norn/internal/logclient"
	"github.com/onembyte/norn/internal/replay"
	"github.com/onembyte/norn/internal/tlog"
	"github.com/onembyte/norn/internal/trust"
)

// `GOSSIP.md` part 6: "it holds all of them -- full replication". A node that
// only remembered the checkpoint could tell a peer what it believes but could
// not prove it, and the whole point of gossip is that a peer serves **data,
// never claims**. So a node writes down what it verified, in the same
// `tlog-tiles` layout it read.

func vectors() string { return filepath.Join("..", "..", "testdata", "vectors") }

// verified is the fixture's log, read through the real verifier.
func verified(t *testing.T) *logclient.Result {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(vectors(), "trust.cbor"))
	if err != nil {
		t.Fatal(err)
	}
	_ = raw
	result, err := logclient.Verify(
		logclient.Dir(filepath.Join(vectors(), "served")), anchorOf(t))
	if err != nil {
		t.Fatal(err)
	}
	return result
}

// The property that matters: what a node writes down is something the
// verifier accepts, byte for byte, with no log running.
func TestAMirrorVerifiesLikeTheLogItCopied(t *testing.T) {
	result := verified(t)
	dir := t.TempDir()

	if err := Write(dir, result.Checkpoint, result.SignedCheckpoint, result.Served); err != nil {
		t.Fatal(err)
	}

	anchor := anchorOf(t)
	back, err := logclient.Verify(logclient.Dir(dir), anchor)
	if err != nil {
		t.Fatalf("a node's own mirror does not verify: %v", err)
	}
	if back.Checkpoint != result.Checkpoint {
		t.Errorf("the mirrored head differs: %+v vs %+v", back.Checkpoint, result.Checkpoint)
	}
	// Including the cosignatures: a peer serving a head stripped of them would
	// be serving one no correctly-configured node accepts.
	if len(back.Cosignatures) != len(result.Cosignatures) {
		t.Errorf("mirrored %d cosignatures, the log served %d",
			len(back.Cosignatures), len(result.Cosignatures))
	}
}

// The layout is the served one, because a peer is read by exactly the code
// that reads a log.
func TestTheMirrorIsTheServedLayout(t *testing.T) {
	result := verified(t)
	dir := t.TempDir()
	if err := Write(dir, result.Checkpoint, result.SignedCheckpoint, result.Served); err != nil {
		t.Fatal(err)
	}

	for _, want := range []string{"checkpoint", "tile/entries", "tile/0"} {
		if _, err := os.Stat(filepath.Join(dir, filepath.FromSlash(want))); err != nil {
			t.Errorf("a mirror must contain %s: %v", want, err)
		}
	}
}

// An unchanged log must not be rewritten. A node polls every T_poll, and a
// mirror that rewrote a hundred files a second would make the 24-hour soak a
// disk benchmark -- the same property 3.8 required of the peer table.
func TestAnUnchangedMirrorIsNotRewritten(t *testing.T) {
	result := verified(t)
	dir := t.TempDir()
	if err := Write(dir, result.Checkpoint, result.SignedCheckpoint, result.Served); err != nil {
		t.Fatal(err)
	}
	before := modTimes(t, dir)

	for i := 0; i < 5; i++ {
		if err := Write(dir, result.Checkpoint, result.SignedCheckpoint, result.Served); err != nil {
			t.Fatal(err)
		}
	}
	after := modTimes(t, dir)

	for path, was := range before {
		now, ok := after[path]
		if !ok {
			t.Errorf("%s disappeared", path)
			continue
		}
		if !now.ModTime().Equal(was.ModTime()) {
			t.Errorf("%s was rewritten although nothing changed", path)
		}
	}
}

// And a log that grew is mirrored again.
func TestAGrownLogIsMirroredAgain(t *testing.T) {
	result := verified(t)
	dir := t.TempDir()
	if err := Write(dir, result.Checkpoint, result.SignedCheckpoint, result.Served); err != nil {
		t.Fatal(err)
	}

	// A different head: one entry shorter is still a valid, different log.
	shorter := result.Served[:len(result.Served)-1]
	signed := headFor(t, shorter)
	if err := Write(dir, headOf(t, shorter), signed, shorter); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(filepath.Join(dir, "checkpoint"))
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != signed {
		t.Error("the mirror still serves the old head")
	}
}

// A checkpoint that does not describe the entries handed over is a caller bug,
// and writing it would produce a mirror that serves a head its own tiles
// contradict -- which every peer reading it would report as a broken log.
func TestAMismatchedCheckpointIsRefused(t *testing.T) {
	result := verified(t)
	dir := t.TempDir()

	if err := Write(dir, result.Checkpoint, result.SignedCheckpoint, result.Served[:10]); err == nil {
		t.Fatal("a checkpoint was written over entries it does not describe")
	}
}

// --- helpers ---------------------------------------------------------------

func anchorOf(t *testing.T) logclient.Anchor {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(vectors(), "trust.cbor"))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := trust.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return logclient.Anchor{
		Anchor:  replay.Anchor{Net: doc.Net, GenesisHash: doc.GenesisHash},
		LogKeys: []string{doc.LogKey}, Policy: doc.Policy,
	}
}

func originOf(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(vectors(), "trust.cbor"))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := trust.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return doc.Origin
}

func modTimes(t *testing.T, dir string) map[string]os.FileInfo {
	t.Helper()
	out := map[string]os.FileInfo{}
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			out[path] = info
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// headOf is the parsed head over `entries`.
func headOf(t *testing.T, entries [][]byte) tlog.Checkpoint {
	t.Helper()
	tree, err := tlog.Build(entries)
	if err != nil {
		t.Fatal(err)
	}
	return tlog.Checkpoint{Origin: originOf(t), Size: tree.Size(), Root: tree.Head()}
}

// headFor signs a head over `entries` with the fixture's log key, which is how
// a shorter-but-valid log appears.
func headFor(t *testing.T, entries [][]byte) string {
	t.Helper()
	tree, err := tlog.Build(entries)
	if err != nil {
		t.Fatal(err)
	}
	cp := tlog.Checkpoint{Origin: originOf(t), Size: tree.Size(), Root: tree.Head()}
	signed, err := cp.Sign(fixtureLogKey(t))
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func fixtureLogKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(vectors(), "keys.json"))
	if err != nil {
		t.Fatal(err)
	}
	var keys struct {
		Ed25519 map[string]struct{ Seed string } `json:"ed25519"`
	}
	if err := json.Unmarshal(raw, &keys); err != nil {
		t.Fatal(err)
	}
	seed, err := hex.DecodeString(keys.Ed25519["logkey"].Seed)
	if err != nil || len(seed) != ed25519.SeedSize {
		t.Fatalf("no usable log key seed")
	}
	return ed25519.NewKeyFromSeed(seed)
}
