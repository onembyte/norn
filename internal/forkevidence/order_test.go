package forkevidence

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/onembyte/norn/internal/cbor"
	"github.com/onembyte/norn/internal/evrefusal"
	"github.com/onembyte/norn/internal/policy"
	"github.com/onembyte/norn/internal/refusal"
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
	return fromFile(t, "evidence", change)
}

// fromFile is fromValid over any shipped fork/ file.
func fromFile(t *testing.T, name string, change func(m map[string]any)) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "vectors", "fork", name+".cbor"))
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
			_, err = Check(ev, anchor.Origin, []string{anchor.LogKey}, anchor.Policy)
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

// --- 6.5l-vii-b-iii: the rest of §11.1's order ---------------------------
//
// Each case below fails two adjacent steps of §11.1's table, so the earlier
// one has to decide. A reader that runs the pair the other way round refuses
// the same file with the later code.

func TestEvidenceIsCheckedInSection11_1sOrder(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "vectors")
	anchor := shippedAnchor(t, root)
	garbage := "not a checkpoint"
	flip := func(m map[string]any) {
		h := append([]byte(nil), m["proof"].([]any)[0].([]byte)...)
		h[0] ^= 0x01
		m["proof"].([]any)[0] = h
	}
	heldSize := func(m map[string]any) uint64 {
		var size uint64
		for i, line := range strings.SplitN(m["held"].(string), "\n", 3) {
			if i == 1 {
				size, _ = strconv.ParseUint(line, 10, 64)
			}
		}
		return size
	}
	for _, c := range []struct {
		name string
		want evrefusal.Code
		raw  func(t *testing.T) []byte
	}{
		{"oversize before cbor", evrefusal.Oversize, func(t *testing.T) []byte {
			return bytes.Repeat([]byte{0xff}, MaxEvidenceBytes+1)
		}},
		{"schema before policy", evrefusal.Schema, func(t *testing.T) []byte {
			return fromValid(t, func(m map[string]any) { m["surprise"] = "x"; m["policy"] = "not a policy" })
		}},
		{"policy before held", evrefusal.Policy, func(t *testing.T) []byte {
			return fromValid(t, func(m map[string]any) { m["policy"] = "not a policy"; m["held"] = garbage })
		}},
		{"held before conflicting", evrefusal.Held, func(t *testing.T) []byte {
			return fromValid(t, func(m map[string]any) { m["held"] = garbage; m["conflicting"] = garbage })
		}},
		{"conflicting before size", evrefusal.Conflicting, func(t *testing.T) []byte {
			return fromValid(t, func(m map[string]any) {
				m["conflicting"] = garbage
				m["size"] = heldSize(m) + 5
			})
		}},
		{"size before proof", evrefusal.Size, func(t *testing.T) []byte {
			return fromValid(t, func(m map[string]any) { m["size"] = heldSize(m) + 1; flip(m) })
		}},
		// bad-consistent is a log and its own earlier self: the roots agree.
		// With a forged proof as well, the proof step decides.
		{"proof before consistent", evrefusal.Proof, func(t *testing.T) []byte {
			return fromFile(t, "bad-consistent", flip)
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			ev, err := Parse(c.raw(t))
			if err == nil {
				_, err = Check(ev, anchor.Origin, []string{anchor.LogKey}, anchor.Policy)
			}
			if err == nil {
				t.Fatal("accepted")
			}
			if got, _ := evrefusal.CodeOf(err); got != c.want {
				t.Errorf("refused as %q, want %q: %v", got, c.want, err)
			}
		})
	}
}

// A `held` or `conflicting` refusal is a checkpoint failing §10, and §10.1
// already names how: the evidence code says which checkpoint, and the
// verifier code inside it says why. Both are on the chain.
func TestACheckpointRefusalCarriesItsSection10_1Code(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "vectors")
	anchor := shippedAnchor(t, root)
	for _, c := range []struct {
		name         string
		outer        evrefusal.Code
		inner        refusal.Code
		change       func(m map[string]any)
		readerOrigin string
	}{
		{"held does not frame", evrefusal.Held, refusal.Note,
			func(m map[string]any) { m["held"] = "not a checkpoint" }, ""},
		{"conflicting does not frame", evrefusal.Conflicting, refusal.Note,
			func(m map[string]any) { m["conflicting"] = "not a checkpoint" }, ""},
		{"held is for another origin", evrefusal.Held, refusal.Origin,
			func(m map[string]any) {}, "norn/elsewhere"},
	} {
		t.Run(c.name, func(t *testing.T) {
			ev, err := Parse(fromValid(t, c.change))
			if err != nil {
				t.Fatal(err)
			}
			origin := anchor.Origin
			if c.readerOrigin != "" {
				origin = c.readerOrigin
			}
			_, err = Check(ev, origin, []string{anchor.LogKey}, anchor.Policy)
			if got, _ := evrefusal.CodeOf(err); got != c.outer {
				t.Errorf("evidence code %q, want %q: %v", got, c.outer, err)
			}
			if got, _ := refusal.CodeOf(err); got != c.inner {
				t.Errorf("verifier code %q, want %q: %v", got, c.inner, err)
			}
		})
	}
}

// What is wrong with the reader -- its own policy, its own log key -- is its
// configuration, not the file. It is still ErrEvidence, because nothing can
// be concluded, and it carries no §11.1 code, which describes the file. It is
// reported before the file is read, whatever state the file is in.
func TestAReaderConfigurationFaultCarriesNoCode(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "vectors")
	anchor := shippedAnchor(t, root)
	for _, file := range []struct {
		name string
		raw  func(t *testing.T) []byte
	}{
		{"sound evidence", func(t *testing.T) []byte { return fromValid(t, func(map[string]any) {}) }},
		{"evidence whose carried policy is broken", func(t *testing.T) []byte {
			return fromValid(t, func(m map[string]any) { m["policy"] = "not a policy" })
		}},
	} {
		for name, call := range map[string]func(ev *Evidence) error{
			"its own policy does not parse": func(ev *Evidence) error {
				_, err := Check(ev, anchor.Origin, []string{anchor.LogKey}, "quorum\n")
				return err
			},
			"its own log key does not parse": func(ev *Evidence) error {
				_, err := Check(ev, anchor.Origin, []string{"not a key"}, anchor.Policy)
				return err
			},
		} {
			t.Run(file.name+"/"+name, func(t *testing.T) {
				ev, err := Parse(file.raw(t))
				if err != nil {
					t.Fatal(err)
				}
				err = call(ev)
				if err == nil {
					t.Fatal("accepted")
				}
				if code, ok := evrefusal.CodeOf(err); ok {
					t.Errorf("a reader's configuration fault was reported as the file's %q: %v", code, err)
				}
				if !errors.Is(err, ErrEvidence) {
					t.Errorf("no longer ErrEvidence: %v", err)
				}
			})
		}
	}
}

// §11.1 argues two of its orders in prose -- the size bound "before any
// parse", and "a file wrong in both is refused as `held`" -- so each has a
// shipped two-fault file. Both properties are computed from the bytes. And
// every one of the ten codes is reached by some file: until this step `cbor`
// was reached by none.
func TestTheEvidenceOrderHasItsVectors(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "vectors")
	anchor := shippedAnchor(t, root)
	var doc struct {
		Codes map[string]evrefusal.Code `json:"codes"`
	}
	raw, err := os.ReadFile(filepath.Join(root, "fork", "cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	read := func(name string) []byte {
		body, err := os.ReadFile(filepath.Join(root, "fork", name+".cbor"))
		if err != nil {
			t.Fatal(err)
		}
		return body
	}
	rules, err := policy.Parse(anchor.Policy)
	if err != nil {
		t.Fatal(err)
	}
	fails := func(signed string) bool {
		_, err := verified(signed, anchor.Origin, []string{anchor.LogKey}, rules)
		return err != nil
	}
	for _, order := range []struct {
		name    string
		earlier evrefusal.Code
		both    func(body []byte) bool
	}{
		{"the size bound before any parse", evrefusal.Oversize, func(body []byte) bool {
			_, err := cbor.Decode(body)
			return len(body) > MaxEvidenceBytes && err != nil
		}},
		{"held before conflicting", evrefusal.Held, func(body []byte) bool {
			ev, err := Parse(body)
			return err == nil && fails(ev.Held) && fails(ev.Conflicting)
		}},
	} {
		t.Run(order.name, func(t *testing.T) {
			for name, code := range doc.Codes {
				if code == order.earlier && order.both(read(name)) {
					return
				}
			}
			t.Errorf("no fork/ file is coded %q while also failing the later step", order.earlier)
		})
	}
	reached := map[evrefusal.Code]bool{}
	for _, code := range doc.Codes {
		reached[code] = true
	}
	for _, code := range evrefusal.All() {
		if !reached[code] {
			t.Errorf("no fork/ file is refused as %q", code)
		}
	}
}
