package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/onembyte/norn/internal/cosign"
	"github.com/onembyte/norn/internal/logclient"
	"github.com/onembyte/norn/internal/peertable"
	"github.com/onembyte/norn/internal/proven"
	"github.com/onembyte/norn/internal/reconcile"
	"github.com/onembyte/norn/internal/refusal"
	"github.com/onembyte/norn/internal/trust"
)

// The persisted accepting policy survives replay dropping friend and a
// process restart. Refusing a forged copy changes neither evidence nor peers.
func TestTheAgentRetainsItsAcceptanceWhenAReReadForgesADroppedWitness(t *testing.T) {
	dir := filepath.Join(vectors(), "held-policy")
	var meta struct {
		Trust, Initial, Copy string
		Codes                map[string]string
		Retains              map[string]string
	}
	raw, e := os.ReadFile(filepath.Join(dir, "cases.json"))
	if e != nil {
		t.Fatal(e)
	}
	if e := json.Unmarshal(raw, &meta); e != nil {
		t.Fatal(e)
	}
	if meta.Codes["held-forged-friend"] != "cosignature" || meta.Codes["replayed-forged-friend"] != "accept" || meta.Retains["policy"] != "trust.policy" || meta.Retains["quorum_time"] != "initial acceptance" {
		t.Fatal("held reader and retained acceptance must be explicit")
	}
	raw, e = os.ReadFile(filepath.Join(dir, meta.Trust))
	if e != nil {
		t.Fatal(e)
	}
	doc, e := trust.Parse(raw)
	if e != nil {
		t.Fatal(e)
	}
	initial := filepath.Join(dir, meta.Initial)
	honest, e := os.ReadFile(filepath.Join(dir, meta.Retains["checkpoint"]))
	if e != nil {
		t.Fatal(e)
	}
	forged, e := os.ReadFile(filepath.Join(dir, meta.Copy))
	if e != nil {
		t.Fatal(e)
	}
	for _, mode := range []string{"incremental", "full", "restart"} {
		t.Run(mode, func(t *testing.T) {
			runDir, stateDir := t.TempDir(), t.TempDir()
			fake := peertable.NewFake()
			newAgent := func(log string) *Agent {
				t.Helper()
				node, e := New(Config{Anchor: doc, Fetcher: logclient.Dir(log), Device: fake, Mode: reconcile.Owner, RunDir: runDir, StateDir: stateDir, Emit: (&recorder{}).emit, Now: func() time.Time { return time.Unix(fixtureCosignedAt, 0) }, Mono: func() time.Duration { return 0 }})
				if e != nil {
					t.Fatal(e)
				}
				return node
			}
			node := newAgent(initial)
			if e := node.Once(); e != nil {
				t.Fatal(e)
			}
			first := *node.last
			if first.SignedCheckpoint != string(honest) || first.AcceptancePolicy != doc.Policy || first.QuorumTime == nil || len(first.Cosignatures) != 3 || strings.Contains(first.State.Policy, "witness friend ") {
				t.Fatal("initial acceptance must precede dropping friend")
			}
			first.Cosignatures = append([]cosign.Cosignature(nil), first.Cosignatures...)
			at := *first.QuorumTime
			first.QuorumTime = &at
			peers, e := fake.Peers()
			if e != nil {
				t.Fatal(e)
			}
			mirrorDir := filepath.Join(stateDir, proven.MirrorDir)
			persisted := runTwentyOneMirror(t, mirrorDir)
			records, e := filepath.Glob(filepath.Join(mirrorDir, "acceptance-*.json"))
			if e != nil || len(records) != 1 {
				t.Fatal("one persisted acceptance required", e)
			}
			overlay := t.TempDir()
			// The copy changes only the head; all entry and hash tiles remain served.
			if e := filepath.WalkDir(initial, func(path string, d os.DirEntry, err error) error {
				if err != nil {
					return err
				}
				rel, e := filepath.Rel(initial, path)
				if e != nil {
					return e
				}
				target := filepath.Join(overlay, rel)
				if d.IsDir() {
					return os.MkdirAll(target, 0o755)
				}
				b, e := os.ReadFile(path)
				if e != nil {
					return e
				}
				return os.WriteFile(target, b, 0o644)
			}); e != nil {
				t.Fatal(e)
			}
			if e := os.WriteFile(filepath.Join(overlay, "checkpoint"), forged, 0o644); e != nil {
				t.Fatal(e)
			}
			if mode == "restart" {
				runDir = t.TempDir()
				node = newAgent(overlay)
				if node.restored == nil || node.restored.AcceptancePolicy != first.AcceptancePolicy || node.restored.SignedCheckpoint != first.SignedCheckpoint || !reflect.DeepEqual(node.restored.Cosignatures, first.Cosignatures) || !reflect.DeepEqual(node.restored.QuorumTime, first.QuorumTime) {
					t.Fatal("restart did not restore persisted acceptance")
				}
			} else {
				node.cfg.Fetcher = logclient.Dir(overlay)
				if mode == "full" {
					node.fullVerifiedSet = false
				}
			}
			if code, _ := refusal.CodeOf(node.Once()); string(code) != meta.Codes["held-forged-friend"] {
				t.Fatalf("forged held copy = %q, want cosignature", code)
			}
			held := node.last
			if held == nil {
				held = node.restored
			}
			if held == nil || held.SignedCheckpoint != first.SignedCheckpoint || held.AcceptancePolicy != first.AcceptancePolicy || !reflect.DeepEqual(held.Cosignatures, first.Cosignatures) || !reflect.DeepEqual(held.QuorumTime, first.QuorumTime) {
				t.Fatal("refusal changed held acceptance")
			}
			after, e := fake.Peers()
			if e != nil || !reflect.DeepEqual(after, peers) {
				t.Fatal("refusal changed peers", e)
			}
			if !reflect.DeepEqual(runTwentyOneMirror(t, mirrorDir), persisted) {
				t.Fatal("refusal changed mirror checkpoint or persisted acceptance")
			}
			if e := os.WriteFile(filepath.Join(overlay, "checkpoint"), honest, 0o644); e != nil {
				t.Fatal(e)
			}
			if e := node.Once(); e != nil {
				t.Fatalf("honest copy repair: %v", e)
			}
			if !reflect.DeepEqual(runTwentyOneMirror(t, mirrorDir), persisted) {
				t.Fatal("honest copy changed retained mirror evidence")
			}
		})
	}
}

func runTwentyOneMirror(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	if e := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, e := filepath.Rel(dir, path)
		if e != nil {
			return e
		}
		raw, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		out[rel] = string(raw)
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	return out
}
