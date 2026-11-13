package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/onembyte/norn/internal/cosign"
	"github.com/onembyte/norn/internal/logclient"
	"github.com/onembyte/norn/internal/peertable"
	"github.com/onembyte/norn/internal/proven"
	"github.com/onembyte/norn/internal/reconcile"
	"github.com/onembyte/norn/internal/trust"
)

// Re-reading a thin copy must keep the full acceptance on disk, including
// when a new process has only the persisted acceptance to start from.
func TestTheAgentRetainsItsAcceptanceWhenAReReadHasOnlyOneCosignature(t *testing.T) {
	dir := filepath.Join(vectors(), "served-superseded")
	read := func(path string) []byte {
		t.Helper()
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	var meta struct {
		Thin struct {
			File, Fresh, Informed, Retains string
			Time                           int64 `json:"informed_quorum_time"`
		} `json:"thin_copy"`
	}
	if err := json.Unmarshal(read(filepath.Join(dir, "cases.json")), &meta); err != nil {
		t.Fatal(err)
	}
	c := meta.Thin
	if c.File != "one-cosignature.checkpoint" || c.Fresh != "quorum" || c.Informed != "accept" || c.Retains != "../served/checkpoint" || c.Time != 1760003607 {
		t.Fatal("missing thin-copy acceptance history")
	}
	doc, err := trust.Parse(read(filepath.Join(vectors(), "trust.cbor")))
	if err != nil {
		t.Fatal(err)
	}
	initial := filepath.Join(vectors(), "served")
	honest, thin := read(filepath.Join(dir, c.Retains)), read(filepath.Join(dir, c.File))
	for _, mode := range []string{"incremental", "full", "restart"} {
		t.Run(mode, func(t *testing.T) {
			runDir, stateDir := t.TempDir(), t.TempDir()
			fake := peertable.NewFake()
			newAgent := func(log string) *Agent {
				t.Helper()
				node, err := New(Config{Anchor: doc, Fetcher: logclient.Dir(log), Device: fake, Mode: reconcile.Owner, RunDir: runDir, StateDir: stateDir, Emit: (&recorder{}).emit, Now: func() time.Time { return time.Unix(fixtureCosignedAt, 0) }, Mono: func() time.Duration { return 0 }})
				if err != nil {
					t.Fatal(err)
				}
				return node
			}
			node := newAgent(initial)
			if err := node.Once(); err != nil {
				t.Fatal(err)
			}
			first := *node.last
			if first.SignedCheckpoint != string(honest) || first.AcceptancePolicy != doc.Policy || first.QuorumTime == nil || first.QuorumTime.Unix() != c.Time || len(first.Cosignatures) != 3 {
				t.Fatal("must first accept full served under trust")
			}
			first.Cosignatures = append([]cosign.Cosignature(nil), first.Cosignatures...)
			at := *first.QuorumTime
			first.QuorumTime = &at
			peers, err := fake.Peers()
			if err != nil {
				t.Fatal(err)
			}
			mirrorDir := filepath.Join(stateDir, proven.MirrorDir)
			persisted := runTwentyOneMirror(t, mirrorDir)
			overlay := t.TempDir()
			if err := filepath.WalkDir(initial, func(path string, d os.DirEntry, err error) error {
				if err != nil {
					return err
				}
				rel, err := filepath.Rel(initial, path)
				if err != nil {
					return err
				}
				target := filepath.Join(overlay, rel)
				if d.IsDir() {
					return os.MkdirAll(target, 0o755)
				}
				return os.WriteFile(target, read(path), 0o644)
			}); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(overlay, "checkpoint"), thin, 0o644); err != nil {
				t.Fatal(err)
			}
			if mode == "restart" {
				runDir = t.TempDir()
				node = newAgent(overlay)
				if node.restored == nil || node.restored.SignedCheckpoint != first.SignedCheckpoint || node.restored.AcceptancePolicy != first.AcceptancePolicy || !reflect.DeepEqual(node.restored.Cosignatures, first.Cosignatures) || !reflect.DeepEqual(node.restored.QuorumTime, first.QuorumTime) {
					t.Fatal("restart failed to restore full acceptance")
				}
			} else {
				node.cfg.Fetcher = logclient.Dir(overlay)
				if mode == "full" {
					node.fullVerifiedSet = false
				}
			}
			if err := node.Once(); err != nil {
				t.Fatalf("held thin copy: %v", err)
			}
			got := node.last
			if got == nil || got.SignedCheckpoint != first.SignedCheckpoint || got.AcceptancePolicy != first.AcceptancePolicy || !reflect.DeepEqual(got.Cosignatures, first.Cosignatures) || !reflect.DeepEqual(got.QuorumTime, first.QuorumTime) {
				t.Fatal("thin reread changed retained acceptance")
			}
			after, err := fake.Peers()
			if err != nil || !reflect.DeepEqual(after, peers) {
				t.Fatal("thin reread changed peers", err)
			}
			if !reflect.DeepEqual(runTwentyOneMirror(t, mirrorDir), persisted) {
				t.Fatal("thin reread changed persisted mirror or acceptance")
			}
		})
	}
}
