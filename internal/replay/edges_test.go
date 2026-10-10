package replay

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/onembyte/norn/internal/cbor"
	"github.com/onembyte/norn/internal/entry"
)

// These logs isolate key admission without changing the served fixture's state.
func TestTheAdmissionLogReplaysToItsManifestAndState(t *testing.T) {
	dir := filepath.Join(vectorRoot(), "log-admission")
	anchor, entries, m := loadCase(t, dir)
	if len(entries) != 5 {
		t.Fatalf("%d entries; want genesis, three refusals and an honest addition", len(entries))
	}
	st := Replay(anchor, entries)
	reasons := map[int]string{}
	for _, r := range st.Rejected {
		reasons[int(r.Index)] = r.Reason
	}
	for _, e := range m.Entries {
		if reasons[e.Index] != e.Reason {
			t.Errorf("%s: got %q, want %q", e.Name, reasons[e.Index], e.Reason)
		}
	}
	if len(reasons) != 3 || len(st.Signers) != 3 {
		t.Errorf("want three refusals and three signers; got %+v", st)
	}
	want, err := os.ReadFile(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := st.MarshalCanonical()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("admission state differs from state.json: %s", got)
	}
	// An entry refused for its key still has the honest root quorum.
	for i := 1; i < len(entries); i++ {
		env, err := entry.Decode(entries[i])
		if err != nil {
			t.Fatal(err)
		}
		valid := 0
		for _, sig := range env.Sigs {
			if pk, ok := st.Roots[sig.Kid]; ok {
				public, err := hex.DecodeString(pk)
				if err != nil {
					t.Fatal(err)
				}
				verified, err := entry.Verify(env, sig, public)
				if err == nil && verified {
					valid++
				}
			}
		}
		if valid < 2 {
			t.Fatalf("entry %d has only %d valid root signatures", i, valid)
		}
	}
}

func TestTheEd25519GenesisEdgesAbortOnlyForTheirKeys(t *testing.T) {
	for _, name := range []string{"23-root-order-eight", "24-root-noncanonical"} {
		t.Run(name, func(t *testing.T) {
			anchor, raw, _ := loadCase(t, filepath.Join(vectorRoot(), "genesis", name))
			value, err := cbor.Decode(raw[0])
			if err != nil {
				t.Fatal(err)
			}
			env := value.(map[string]any)
			body := env["body"].(map[string]any)
			roots := body["roots"].([]any)
			if len(roots) != 4 {
				t.Fatalf("want three honest roots plus the edge key, got %d", len(roots))
			}
			decoded, err := entry.Decode(raw[0])
			if err != nil {
				t.Fatal(err)
			}
			valid := 0
			for _, sig := range decoded.Sigs {
				for _, root := range roots[:3] {
					pk := root.([]byte)
					verified, err := entry.Verify(decoded, sig, pk)
					if entry.Kid(pk) == sig.Kid && err == nil && verified {
						valid++
					}
				}
			}
			if valid != 2 {
				t.Fatalf("want two honest root signatures, got %d", valid)
			}
			st := Replay(anchor, raw)
			if st.Size != 0 || len(st.Rejected) != 1 || st.Rejected[0].Reason != ReasonBadGenesis {
				t.Fatalf("edge genesis admitted: %+v", st)
			}
		})
	}
}
