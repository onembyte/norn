package tlog

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/onembyte/norn/internal/cosign"
	"github.com/onembyte/norn/internal/note"
	"github.com/onembyte/norn/internal/policy"
	"github.com/onembyte/norn/internal/trust"
)

// A checkpoint can state the largest size without a feasible served tree.
// This walker checks its authenticated body and witness quorum only.
func TestEveryPositiveCheckpointOnlyCaseAcceptsAtItsInclusiveBound(t *testing.T) {
	var m struct {
		Cases []struct {
			Name, File, Layer string
			ServeOver         string `json:"serve_over"`
		}
		Codes map[string]string
	}
	if err := json.Unmarshal([]byte(read(t, "checkpoints-good", "cases.json")), &m); err != nil {
		t.Fatal(err)
	}
	if len(m.Cases) != 2 || len(m.Codes) != 2 {
		t.Fatal("need both positive layers")
	}
	anchor, err := trust.Parse([]byte(read(t, "trust.cbor")))
	if err != nil {
		t.Fatal(err)
	}
	if err := anchor.Validate(); err != nil {
		t.Fatal(err)
	}
	rules, err := policy.Parse(anchor.Policy)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, c := range m.Cases {
		if seen[c.Name] || m.Codes[c.Name] != "accept" || c.File != c.Name+".checkpoint" {
			t.Fatal("invalid positive case or code")
		}
		seen[c.Name] = true
		if c.Layer == "served" {
			if c.Name != "cosignature-time-at-the-cap" || c.ServeOver != "../served" {
				t.Fatal("unexpected served case")
			}
			continue
		}
		if c.Name != "size-at-the-cap" || c.Layer != "checkpoint" || c.ServeOver != "" {
			t.Fatal("size case must remain checkpoint-only")
		}
		t.Run(c.Name, func(t *testing.T) {
			signed := read(t, "checkpoints-good", c.File)
			body, _, err := note.Split(signed)
			if err != nil {
				t.Fatal(err)
			}
			ordinary := read(t, "served", "checkpoint")
			ordinaryBody, _, err := note.Split(ordinary)
			if err != nil {
				t.Fatal(err)
			}
			lines := strings.Split(ordinaryBody, "\n")
			lines[1] = "9223372036854775807"
			if body != strings.Join(lines, "\n") {
				t.Fatal("body must change only the size line to the exact cap")
			}
			cp, err := Verify(signed, []string{anchor.LogKey})
			if err != nil {
				t.Fatalf("positive checkpoint: %v", err)
			}
			if cp.Size != 1<<63-1 || cp.Origin != anchor.Origin {
				t.Fatal("checkpoint lost the exact size or origin")
			}
			cosigs, err := cosign.Verify(signed, rules.Keys())
			if err != nil {
				t.Fatal(err)
			}
			if len(cosigs) != 3 {
				t.Fatal("need every fixture witness")
			}
			var labels []string
			for _, sig := range cosigs {
				label, ok := rules.LabelFor(sig.Name, sig.Public)
				if !ok {
					t.Fatal("unlisted witness")
				}
				labels = append(labels, label)
			}
			if !rules.Satisfied(labels) {
				t.Fatal("checkpoint lacks its quorum")
			}
			if _, err := Verify(ordinary, []string{anchor.LogKey}); err != nil {
				t.Fatalf("ordinary-size guard: %v", err)
			}
			t.Log("log-signed size 9223372036854775807 and all three cosignatures: accept at checkpoint layer; ordinary-size guard: accept")
		})
	}
	if !seen["size-at-the-cap"] || !seen["cosignature-time-at-the-cap"] {
		t.Fatal("missing positive layer")
	}
}
