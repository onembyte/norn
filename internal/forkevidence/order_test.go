package forkevidence

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/onembyte/norn/internal/cbor"
	"github.com/onembyte/norn/internal/evrefusal"
)

// --- 6.5l-vii-b-ii: Parse checks in §11.1's order -------------------------
//
// §11.1's table puts `version` (step 2) before `schema` (step 3), and that is
// the order with a reason behind it: a key set is only closed relative to a
// version, so a reader cannot judge the schema of a version it does not
// speak. Parse checked the key set first, so a file carrying `version: 2`
// and a key version 1 lacks was `schema` here and `version` there -- the
// kind of disagreement codes exist to make visible, and no file had both.
//
// The same table types `held_root` and each `proof` hash as `bytes (32)`, so
// a hash of any other length is a step-3 `schema` fault. Check measured them
// after `held`, `conflicting` and `size`, and coded a short proof hash
// `proof`. Both lengths are now Parse's.

// fromValid decodes the shipped valid evidence as a map, lets the case change
// it, and encodes it again: one fault, or two, on an otherwise sound file.
func fromValid(t *testing.T, change func(m map[string]any)) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "vectors", "fork", "evidence.cbor"))
	if err != nil {
		t.Fatal(err)
	}
	value, err := cbor.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	m := value.(map[string]any)
	change(m)
	out, err := cbor.Encode(m)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestParseFollowsSection11_1sOrder(t *testing.T) {
	short := make([]byte, 31)
	for _, c := range []struct {
		name   string
		want   evrefusal.Code
		change func(m map[string]any)
	}{
		// Two faults: §11.1 step 2 decides.
		{"a version this reader does not speak, and a key version 1 lacks", evrefusal.Version,
			func(m map[string]any) { m["version"] = uint64(2); m["surprise"] = "a v2 field" }},
		{"no version at all, and a key version 1 lacks", evrefusal.Version,
			func(m map[string]any) { delete(m, "version"); m["surprise"] = "a v2 field" }},
		{"a version that is text", evrefusal.Version,
			func(m map[string]any) { m["version"] = "1" }},
		// One fault each, in the schema step.
		{"an unknown key under version 1", evrefusal.Schema,
			func(m map[string]any) { m["surprise"] = "x" }},
		{"a missing key under version 1", evrefusal.Schema,
			func(m map[string]any) { delete(m, "policy") }},
		{"a held_root of 31 bytes", evrefusal.Schema,
			func(m map[string]any) { m["held_root"] = short }},
		{"a proof hash of 31 bytes", evrefusal.Schema,
			func(m map[string]any) { m["proof"].([]any)[0] = short }},
		{"a proof hash of 33 bytes", evrefusal.Schema,
			func(m map[string]any) { m["proof"].([]any)[0] = make([]byte, 33) }},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := Parse(fromValid(t, c.change))
			if err == nil {
				t.Fatal("Parse accepted it")
			}
			if got, _ := evrefusal.CodeOf(err); got != c.want {
				t.Errorf("refused as %q, want %q: %v", got, c.want, err)
			}
			if !errors.Is(err, ErrEvidence) {
				t.Errorf("no longer ErrEvidence: %v", err)
			}
		})
	}
}

// Check takes an *Evidence, and not every one comes from Parse: the agent
// checks evidence it has just built. So Check keeps its length checks as a
// backstop -- but a wrong length is §11.1's `schema` wherever it is caught,
// not `proof`.
func TestCheckCodesAWrongLengthAsSchema(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "vectors")
	raw, err := os.ReadFile(filepath.Join(root, "fork", "evidence.cbor"))
	if err != nil {
		t.Fatal(err)
	}
	anchor := shippedAnchor(t, root)
	for name, spoil := range map[string]func(ev *Evidence){
		"held_root": func(ev *Evidence) { ev.HeldRoot = ev.HeldRoot[:31] },
		"proof":     func(ev *Evidence) { ev.Proof[0] = ev.Proof[0][:31] },
	} {
		t.Run(name, func(t *testing.T) {
			ev, err := Parse(raw)
			if err != nil {
				t.Fatal(err)
			}
			spoil(ev)
			_, err = Check(ev, anchor.Origin, anchor.LogKey, anchor.Policy)
			if got, _ := evrefusal.CodeOf(err); got != evrefusal.Schema {
				t.Errorf("refused as %q, want %q: %v", got, evrefusal.Schema, err)
			}
		})
	}
}

// The two orderings above are vectors only if some shipped file fails both
// steps and is coded with the earlier one. Each property is computed from the
// file's bytes, not read from its name or its hint.
func TestTheParseOrderHasItsVectors(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "vectors", "fork")
	var doc struct {
		Codes map[string]evrefusal.Code `json:"codes"`
	}
	raw, err := os.ReadFile(filepath.Join(root, "cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	decoded := func(name string) map[string]any {
		body, err := os.ReadFile(filepath.Join(root, name+".cbor"))
		if err != nil {
			t.Fatal(err)
		}
		value, err := cbor.Decode(body)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		return value.(map[string]any)
	}
	seven := map[string]bool{"version": true, "held": true, "conflicting": true,
		"size": true, "held_root": true, "proof": true, "policy": true}
	// The size the held checkpoint states: its second line.
	heldSize := func(m map[string]any) uint64 {
		held, _ := m["held"].(string)
		lines := strings.SplitN(held, "\n", 3)
		if len(lines) < 2 {
			return 0
		}
		n, _ := strconv.ParseUint(lines[1], 10, 64)
		return n
	}
	for _, order := range []struct {
		name    string
		earlier evrefusal.Code
		both    func(m map[string]any) bool
	}{
		{"version before schema", evrefusal.Version, func(m map[string]any) bool {
			v, _ := m["version"].(uint64)
			var unknown bool
			for k := range m {
				unknown = unknown || !seven[k]
			}
			return v != Version && unknown
		}},
		{"a hash's length before the size", evrefusal.Schema, func(m map[string]any) bool {
			r, _ := m["held_root"].([]byte)
			size, _ := m["size"].(uint64)
			return len(r) != hashSize && size > heldSize(m)
		}},
	} {
		t.Run(order.name, func(t *testing.T) {
			for name, code := range doc.Codes {
				if code == order.earlier && order.both(decoded(name)) {
					return
				}
			}
			t.Errorf("no fork/ file is coded %q while also failing the later step, so a "+
				"reader that runs them the other way round passes every file", order.earlier)
		})
	}
}
