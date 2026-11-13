package replay

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/onembyte/norn/internal/entry"
)

func TestTheRunTwentyTwoGenesisBodiesAreTheirOnlyFaults(t *testing.T) {
	var index struct {
		Cases []string
		Rules map[string]run22Rule
	}
	if err := json.Unmarshal(run22Read(t, filepath.Join(vectorRoot(), "genesis", "cases.json")), &index); err != nil {
		t.Fatal(err)
	}
	baseAnchor, fixture, _ := loadCase(t, filepath.Join(vectorRoot(), "log"))
	for _, c := range []struct {
		name string
		rule run22Rule
	}{
		{"28-signer-order-eight", run22Rule{"3.1", "of a point of order exactly `L`"}},
		{"29-root-thr-zero", run22Rule{"5.1", "`1 ≤ root_thr ≤ len(roots)`"}},
		{"30-signer-thr-zero", run22Rule{"5.1", "`1 ≤ signer_thr ≤ len(signers)`"}},
		{"31-params-flag-uint", run22Rule{"4.5", "whether `rotate` needs a signer countersignature"}},
		{"32-params-routes-open", run22Rule{"4.5", "any text but `granted` or `advisory`"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			count := 0
			for _, n := range index.Cases {
				if n == c.name {
					count++
				}
			}
			if count != 1 || index.Rules[c.name] != c.rule {
				t.Fatal("missing genesis case or rule", c.name)
			}
			dir := filepath.Join(vectorRoot(), "genesis", c.name)
			anchor, raw, m := loadCase(t, dir)
			if len(raw) != 1 || len(m.Entries) != 1 || m.Entries[0].Index != 0 || m.Entries[0].Name != "00-genesis" || m.Entries[0].Reason != ReasonBadGenesis {
				t.Fatal("abort must be a single-entry log")
			}
			if !bytes.Equal(anchor.GenesisHash, entry.LeafHash(raw[0])) || !bytes.Equal(anchor.Net, baseAnchor.Net) || anchor.Policy != baseAnchor.Policy || anchor.LogKey != baseAnchor.LogKey {
				t.Fatal("anchor must pin its own leaf and retain the fixture trust")
			}
			env := run22Decode(t, raw[0])
			run22Authenticate(t, env, "root", "root1", "root2", "root3")
			bad := Replay(anchor, raw)
			if bad.Size != 0 || len(bad.Rejected) != 1 || lastOutcome(bad, 0) != ReasonBadGenesis {
				t.Fatal("genesis did not abort")
			}
			got, _ := bad.MarshalCanonical()
			if !bytes.Equal(got, run22Read(t, filepath.Join(dir, "state.json"))) {
				t.Fatal("abort state differs")
			}
			zero := Replay(anchor, nil)
			zero.Rejected = bad.Rejected
			z, _ := zero.MarshalCanonical()
			if !bytes.Equal(got, z) {
				t.Fatal("abort is not the full zero state")
			}
			body := env["body"].(map[string]any)
			base := run22Decode(t, fixture[0])["body"].(map[string]any)
			switch c.name {
			case "28-signer-order-eight":
				signers := body["signers"].([]any)
				badPoint := notValidPoints(t, publicOf(t, "signer1"))["small-order"]
				if len(signers) != 3 || !bytes.Equal(signers[2].([]byte), badPoint) {
					t.Fatal("bad point belongs only at the end of signers")
				}
				body["signers"] = signers[:2]
			case "29-root-thr-zero", "30-signer-thr-zero":
				field := "root_thr"
				if c.name == "30-signer-thr-zero" {
					field = "signer_thr"
				}
				if body[field] != uint64(0) {
					t.Fatal("threshold must be uint zero")
				}
				body[field] = base[field]
			case "31-params-flag-uint":
				params := body["params"].(map[string]any)
				if params["rotate_needs_signer"] != uint64(1) {
					t.Fatal("flag must be uint one")
				}
				params["rotate_needs_signer"] = false
				base["params"] = map[string]any{"rotate_needs_signer": false}
			case "32-params-routes-open":
				params := body["params"].(map[string]any)
				if params["routes"] != "open" {
					t.Fatal("routes must be open")
				}
				params["routes"] = "granted"
				base["params"] = map[string]any{"routes": "granted"}
			}
			if !reflect.DeepEqual(body, base) {
				t.Fatal("repair changed another genesis body field")
			}
			fixed := run22Sign(t, env, "root", "root1", "root2", "root3")
			anchor.GenesisHash = entry.LeafHash(fixed)
			good := Replay(anchor, [][]byte{fixed})
			if good.Size != 1 || len(good.Rejected) != 0 {
				t.Fatal("field-only genesis repair refused")
			}
			if c.name == "30-signer-thr-zero" {
				unsigned := run22Decode(t, fixture[1])
				unsigned["sigs"] = []any{}
				extra := run22Encode(t, unsigned)
				badAnchor := anchor
				badAnchor.GenesisHash = entry.LeafHash(raw[0])
				continued := Replay(badAnchor, [][]byte{raw[0], extra})
				b, _ := continued.MarshalCanonical()
				if !bytes.Equal(b, got) {
					t.Fatal("abort evaluated the unsigned enrollment")
				}
				continued = Replay(anchor, [][]byte{fixed, extra})
				if continued.Size != 2 || len(continued.Rejected) != 1 || lastOutcome(continued, 1) != ReasonThreshold || len(continued.Devices) != 0 {
					t.Fatal("repaired genesis must expose enrollment threshold")
				}
			}
			t.Log("field-only repair accepted with renewed roots and own-leaf pin")
		})
	}
}
