package proof

import (
	"encoding/json"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/onembyte/norn/internal/cbor"
	"github.com/onembyte/norn/internal/logclient"
	"github.com/onembyte/norn/internal/refusal"
	"github.com/onembyte/norn/internal/replay"
	"github.com/onembyte/norn/internal/tlog"
	"github.com/onembyte/norn/internal/trust"
)

// Inclusion at an older consistent head is evidence, while installation is
// decided by the state the reader accepted and stored through its own head.
func TestOlderBundleHeadsUseTheStoredHeadsReplayForInstallation(t *testing.T) {
	const dir = "proofs-older-head/"
	var meta struct {
		Trust            string
		StoredCheckpoint string `json:"stored_checkpoint"`
		StoredLog        string `json:"stored_log"`
		Reader           struct {
			Policy string
			Held   string `json:"held_checkpoint"`
		}
		Cases []struct {
			Name, File, Device, Says string
			Index                    int64
			HeadSize                 int64 `json:"head_size"`
			Consistent               bool
		}
		Codes              map[string]string
		Installs           map[string]string
		BundleHeadInstalls map[string]string `json:"bundle_head_installs"`
	}
	if err := json.Unmarshal(d080Read(t, dir+"cases.json"), &meta); err != nil {
		t.Fatal(err)
	}
	if meta.Trust != "../trust.cbor" || meta.StoredLog != "../served" || meta.StoredCheckpoint != "../served/checkpoint" || meta.Reader.Policy != "replayed" || meta.Reader.Held != meta.StoredCheckpoint || len(meta.Cases) != 2 {
		t.Fatal("older bundles must name the stored acceptance and replay source")
	}
	doc, err := trust.Parse(d080Read(t, dir+meta.Trust))
	if err != nil {
		t.Fatal(err)
	}
	a := logclient.Anchor{Anchor: replay.FromTrust(doc), Origin: doc.Origin, LogKeys: []string{doc.LogKey}, Policy: doc.Policy}
	stored, err := logclient.Verify(logclient.Dir(filepath.Join("..", "..", "testdata", "vectors", dir, meta.StoredLog)), a)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Checkpoint.Size != 162 || stored.SignedCheckpoint != string(d080Read(t, dir+meta.StoredCheckpoint)) || stored.AcceptancePolicy != doc.Policy || len(stored.Cosignatures) != 3 || stored.QuorumTime == nil {
		t.Fatal("must retain served's verified size-162 acceptance")
	}
	current := replay.Replay(a.Anchor, stored.Served)
	if !reflect.DeepEqual(current, stored.State) {
		t.Fatal("stored replay disagrees with verified state")
	}
	anchor := Anchor{Origin: a.Origin, LogKeys: append(append([]string{}, a.LogKeys...), logclient.KeysFrom(a.Origin, current)...), Policy: logclient.PolicyFrom(current)}
	installs := map[string]string{}
	oldInstalls := map[string]string{}
	seen := map[string]bool{}
	for _, c := range meta.Cases {
		t.Run(c.Name, func(t *testing.T) {
			if seen[c.Device] || (c.Device != "laptop" && c.Device != "nas") || c.Name != c.Device+"-older-head" || c.File != c.Name+".bundle" || c.Says == "" || c.HeadSize != 10 || !c.Consistent || meta.Codes[c.Name] != "accept" {
				t.Fatal("missing older-head case or outcome")
			}
			seen[c.Device] = true
			b, err := Decode(d080Read(t, dir+c.File))
			if err != nil {
				t.Fatal(err)
			}
			if err := b.Check(anchor); err != nil {
				t.Fatalf("older bundle must accept: %v", err)
			}
			cp, err := tlog.Verify(b.Checkpoint, anchor.LogKeys)
			if err != nil {
				t.Fatal(err)
			}
			index := int64(1)
			if c.Device == "laptop" {
				index = 2
			}
			if cp.Size != c.HeadSize || b.Index != index || c.Index != index || b.Device != c.Device || !reflect.DeepEqual(b.Entry, stored.Served[index]) {
				t.Fatal("wrong older head, device or enrolment")
			}
			prefix, err := stored.Tree.HeadAt(min(cp.Size, stored.Checkpoint.Size))
			if err != nil || prefix != cp.Root {
				t.Fatal("older bundle's signed root is not the stored tree's prefix", err)
			}
			older := replay.Replay(a.Anchor, stored.Served[:cp.Size])
			old := older.Devices[c.Device]
			wantOld := map[string]string{"laptop": "bd4637856399f9ce5cd8044ad1f684c6486d3983f5b58171267113d743838f46", "nas": "116f00fac8f42a3061d84684e114f7bebb590c54d0b33feb2a6ad68f02883961"}[c.Device]
			if old.Status != "active" || old.WgPk != wantOld {
				t.Fatal("counter-reading must keep the old active key")
			}
			oldInstalls[c.Device] = old.WgPk
			// This is the consumer's condition 3, not an extra bundle check.
			device := current.Devices[c.Device]
			if device.Status == "active" {
				installs[c.Device] = device.WgPk
			}
			want, present := meta.Installs[c.Device]
			got, installed := installs[c.Device]
			if installed != present || got != want {
				t.Errorf("installation = %q/%v, want stored replay %q/%v", got, installed, want, present)
			}
			if old.WgPk == want {
				t.Fatal("counter-reading does not separate the case")
			}
		})
	}
	want := map[string]string{"nas": "2a955fd268cf9d55ba383ba35237a3f626b5141ac92089ccb915e17b86bde82f"}
	if !seen["laptop"] || !seen["nas"] || !reflect.DeepEqual(meta.Installs, want) || !reflect.DeepEqual(installs, want) || !reflect.DeepEqual(oldInstalls, meta.BundleHeadInstalls) || reflect.DeepEqual(oldInstalls, want) {
		t.Fatalf("stored installs = %v, manifest = %v; bundle-head reading = %v", installs, meta.Installs, oldInstalls)
	}
}

func TestASoundBundleCarriesAnEntryExactlyAtTheCap(t *testing.T) {
	var meta struct {
		Sound []struct {
			Name, File, Device, Says string
			Index                    int64
		}
		Codes   map[string]string
		Devices []string
	}
	if err := json.Unmarshal(d080Read(t, "proofs/cases.json"), &meta); err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, c := range meta.Sound {
		if c.Name != "entry-at-the-cap" {
			continue
		}
		found++
		if c.File != "entry-at-the-cap.bundle" || c.Device != "nas" || c.Index != 1 || c.Says == "" || meta.Codes[c.Name] != "accept" {
			t.Fatal("missing cap-positive contract")
		}
		b, err := Decode(d080Read(t, "proofs/"+c.File))
		if err != nil {
			t.Fatal(err)
		}
		if len(b.Entry) != cbor.MaxEntryBytes || b.Index != c.Index || b.Device != c.Device {
			t.Fatal("entry must reach exactly 65535 bytes")
		}
		checkRunTwentyOneInclusion(t, b)
		if err := b.Check(shippedAnchor(t)); err != nil {
			t.Fatalf("entry at inclusive cap: %v", err)
		}
	}
	if found != 1 || len(meta.Sound) != 14 {
		t.Fatal("missing unique sound entry-at-the-cap bundle")
	}
	_, err := Decode(d080Read(t, "proofs-bad/oversize-entry.bundle"))
	if code, _ := refusal.CodeOf(err); code != refusal.Bundle {
		t.Fatalf("65536-byte entry = %q (%v), want bundle", code, err)
	}
}
