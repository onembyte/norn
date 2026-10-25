package logclient

import (
	"path/filepath"
	"reflect"
	"testing"
)

// D-082 (1): a peer can serve fewer witness lines for the same tree. The
// result must keep the evidence the caller already holds, since a later fork
// is proved with that note, and keep the time it accepted with those lines.
func TestAReReadKeepsTheStoredNotesCosignatures(t *testing.T) {
	fresh := shippedLogAnchor(t)
	dir := filepath.Join(vectorRoot(), "served")
	held, err := Verify(Dir(dir), fresh)
	if err != nil {
		t.Fatal(err)
	}
	fresh.Stored, fresh.Held, fresh.StoredResult = &held.Checkpoint, held.Tree, held
	overlay := servedWith(t, dir, readFile(t, filepath.Join(vectorRoot(), "served-superseded", "checkpoint")))
	for _, incremental := range []bool{false, true} {
		t.Run(map[bool]string{false: "Verify", true: "VerifyFrom"}[incremental], func(t *testing.T) {
			var got *Result
			if incremental {
				got, err = VerifyFrom(held, Dir(overlay), fresh)
			} else {
				got, err = Verify(Dir(overlay), fresh)
			}
			if err != nil {
				t.Fatal(err)
			}
			if got.SignedCheckpoint != held.SignedCheckpoint || !reflect.DeepEqual(got.Cosignatures, held.Cosignatures) {
				t.Errorf("re-read replaced the held note's %d cosignatures with %d", len(held.Cosignatures), len(got.Cosignatures))
			}
			if !got.QuorumTime.Equal(*held.QuorumTime) {
				t.Errorf("re-read moved T: %d -> %d", held.QuorumTime.Unix(), got.QuorumTime.Unix())
			}
		})
	}
}
