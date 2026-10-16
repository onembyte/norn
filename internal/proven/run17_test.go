package proven

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/onembyte/norn/internal/logclient"
	"github.com/onembyte/norn/internal/replay"
	"github.com/onembyte/norn/internal/trust"
)

func TestRunSeventeenQuorumNoneRetainsExpiryWithoutAClock(t *testing.T) {
	root := vectorRoot()
	dir := filepath.Join(root, "quorum-none")
	read := func(file string) []byte {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join(dir, file))
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	var manifest struct {
		Cases []struct {
			Name, File string
			Proven     []string
		}
		Codes map[string]string
	}
	if err := json.Unmarshal(read("cases.json"), &manifest); err != nil {
		t.Fatal(err)
	}
	doc, err := trust.Parse(read("trust.cbor"))
	if err != nil {
		t.Fatal(err)
	}
	anchor := logclient.Anchor{Anchor: replay.FromTrust(doc), Origin: doc.Origin, LogKeys: []string{doc.LogKey}, Policy: doc.Policy}
	if len(manifest.Cases) != 2 {
		t.Fatal("both heads need proven sets")
	}
	expected := []string{"astral", "badgrant", "contractor", "labelcap", "nas", "pi-cam", "printer", "router"}
	for _, c := range manifest.Cases {
		if !reflect.DeepEqual(c.Proven, expected) {
			t.Fatalf("manifest must retain the fixed no-clock set: %v", c.Proven)
		}
		t.Run(c.Name, func(t *testing.T) {
			if manifest.Codes[c.Name] != "accept" {
				t.Fatal("both heads must accept")
			}
			head := read(c.File)
			fetch := runSeventeenHead{Dir: logclient.Dir(filepath.Join(root, "served")), head: head}
			result, err := logclient.Verify(fetch, anchor)
			if err != nil {
				t.Fatal(err)
			}
			now := time.Unix(1_800_000_000, 0)
			set, err := FromResult(result, now, Freshness{State: Unknown})
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, d := range set.Devices {
				got = append(got, d.DeviceID)
			}
			if !reflect.DeepEqual(got, c.Proven) {
				t.Fatalf("Go proves %v, SPEC states %v", got, c.Proven)
			}
			if result.QuorumTime != nil || set.Checkpoint.CosignedAt != nil || !EvaluationTime(result).IsZero() {
				t.Fatal("no quorum time may be invented")
			}
			kept := false
			for _, id := range got {
				kept = kept || id == "contractor"
			}
			if !kept {
				t.Fatal("contractor must remain proven")
			}
			if reflect.DeepEqual(Devices(result.State, now), got) {
				t.Fatal("a wall clock reader must drop contractor")
			}
		})
	}
	sound, _ := verified(t)
	if EvaluationTime(sound).IsZero() {
		t.Fatal("normal quorum twin must have a clock")
	}
}

type runSeventeenHead struct {
	logclient.Dir
	head []byte
}

func (f runSeventeenHead) Fetch(path string) ([]byte, error) {
	if path == "checkpoint" {
		return f.head, nil
	}
	return f.Dir.Fetch(path)
}
