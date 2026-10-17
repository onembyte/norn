package proven

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/onembyte/norn/internal/proof"
)

// D-080 (5), row 6.5l-xv-i (lane BX). `proofs/forged` and `halfsigned` are
// sound bundles around enrollments replay refused: inclusion proves the entry
// is in the log, never that replay accepted it, so condition 3 installs
// nothing for either and `installs` is unchanged (§8.1).
func TestD080ShippedIncludedButRefusedEnrollmentsInstallNothing(t *testing.T) {
	result, doc := verified(t)
	set, err := FromResult(result, time.Unix(1_760_003_600, 0), Freshness{State: Unknown})
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct{ Installs map[string]string }
	raw, err := os.ReadFile(filepath.Join(vectorRoot(), "proofs/cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		id    string
		index uint64
	}{{"forged", 98}, {"halfsigned", 57}} {
		t.Run(c.id, func(t *testing.T) {
			for _, name := range []string{"nas", c.id, "laptop-revoke"} {
				raw, err := os.ReadFile(filepath.Join(vectorRoot(), "proofs", name+".bundle"))
				if err != nil {
					t.Fatal(err)
				}
				b, err := proof.Decode(raw)
				if err != nil {
					t.Fatal(err)
				}
				if err := b.Check(proof.Anchor{Origin: doc.Origin, LogKeys: []string{doc.LogKey}, Policy: doc.Policy}); err != nil {
					t.Fatal(err)
				}
			}
			rejected := false
			for _, r := range result.State.Rejected {
				if r.Index == c.index {
					rejected = true
				}
			}
			if !rejected {
				t.Fatal("replay must have rejected the included enrollment")
			}
			if _, ok := result.State.Devices[c.id]; ok {
				t.Fatal("refused enrollment must create no device")
			}
			for _, id := range []string{c.id, "laptop"} {
				if _, ok := manifest.Installs[id]; ok {
					t.Fatal("manifest installs a refused or revoked device")
				}
				for _, d := range set.Devices {
					if d.DeviceID == id {
						t.Fatal("proven set installs a refused or revoked device")
					}
				}
			}
			nas := false
			for _, d := range set.Devices {
				if d.DeviceID == "nas" {
					nas = true
				}
			}
			if !nas || manifest.Installs["nas"] != result.State.Devices["nas"].WgPk {
				t.Fatal("accepted twin must install nas's replayed key")
			}
			t.Logf("proofs/%s.bundle: accept, installs nothing; nas installs its replayed key", c.id)
		})
	}
}
