package state

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// Written from SPEC.md §5.3. The shipped states are the oracle: decoding one
// into the typed model and serialising it back must return the same bytes,
// which exercises the schema, the field set, and §14 together.

func suiteStates(t *testing.T) []string {
	t.Helper()
	root := filepath.Join("..", "..", "testdata", "vectors")
	paths := []string{filepath.Join(root, "state.json")}
	genesis, err := filepath.Glob(filepath.Join(root, "genesis", "*", "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	return append(paths, genesis...)
}

func TestEverySuiteStateRoundTripsByteExact(t *testing.T) {
	paths := suiteStates(t)
	if len(paths) < 13 {
		t.Fatalf("expected the log state plus every genesis state, found %d", len(paths))
	}
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		st, err := Parse(raw)
		if err != nil {
			t.Errorf("%s: %v", path, err)
			continue
		}
		again, err := st.MarshalCanonical()
		if err != nil {
			t.Errorf("%s: %v", path, err)
			continue
		}
		if !bytes.Equal(raw, again) {
			t.Errorf("%s: re-serialised state differs from the file", path)
		}
	}
}

func TestEveryFieldIsAlwaysEmitted(t *testing.T) {
	// §5.3: every field is present even in a state that aborted at genesis.
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "vectors",
		"genesis", "01-hash-mismatch", "state.json"))
	if err != nil {
		t.Skip("genesis case not present")
	}
	st, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if st.Size != 0 {
		t.Errorf("an aborted replay has size 0, got %d", st.Size)
	}
	if len(st.Net) != 16 {
		t.Error("net comes from the anchor and survives an abort")
	}
	if st.Params["checkpoint_interval"] == nil {
		t.Error("params defaults survive an abort")
	}
	out, err := st.MarshalCanonical()
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{`"active_wg"`, `"devices"`, `"log_keys"`, `"policy"`,
		`"rejected"`, `"roots"`, `"signers"`, `"name"`, `"size"`} {
		if !bytes.Contains(out, []byte(field)) {
			t.Errorf("field %s must be emitted even after an abort", field)
		}
	}
}

func TestActiveWgIsDerivableFromDevices(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "vectors", "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	st, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	// §5.3 says active_wg MUST equal the active devices' keys. It is serialised
	// anyway, so a second implementation can be shown to agree on it.
	want := map[string]string{}
	for id, d := range st.Devices {
		if d.Status == StatusActive {
			want[d.WgPk] = id
		}
	}
	if len(want) != len(st.ActiveWg) {
		t.Fatalf("active_wg has %d entries, active devices have %d", len(st.ActiveWg), len(want))
	}
	for key, id := range want {
		if st.ActiveWg[key] != id {
			t.Errorf("active_wg[%s] = %q, want %q", key, st.ActiveWg[key], id)
		}
	}
}

func TestDeviceZeroValuesArePresentNotAbsent(t *testing.T) {
	raw, _ := os.ReadFile(filepath.Join("..", "..", "testdata", "vectors", "state.json"))
	st, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	var sawZeroExpiry, sawNonZeroExpiry bool
	for _, d := range st.Devices {
		if d.Expires == 0 {
			sawZeroExpiry = true
			if d.Labels == nil {
				t.Error("labels must be an empty map, never absent (§5.3)")
			}
		} else {
			sawNonZeroExpiry = true
		}
	}
	if !sawZeroExpiry || !sawNonZeroExpiry {
		t.Error("the fixture must carry devices both with and without an expiry")
	}
}
