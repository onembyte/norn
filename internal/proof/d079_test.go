package proof

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/onembyte/norn/internal/refusal"
	"github.com/onembyte/norn/internal/tlog"
)

// D-079 (2), from cold gate run 16. A bundle proves inclusion, not
// acceptance, so a log may hold an `enroll` whose request does not decode
// (`log/79`, an uppercase id) and anyone can wrap it. Three readers gave three
// answers: accept by comparing the label with the request's text, `binding`
// because the request does not decode, `bundle` because the label fails the
// grammar. Two rules give them one answer each: `device` follows §2's grammar
// (`bundle`, step 1), and an entry whose request does not decode names no
// device (`binding`, step 4). `device` was the one `device_id` in the protocol
// without the grammar.
func TestABundlesDeviceFollowsTheGrammarAndAnUndecodableRequestNamesNoDevice(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "vectors")
	read := func(path string) []byte {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join(root, path))
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	files, err := filepath.Glob(filepath.Join(root, "log", "*.cbor"))
	if err != nil {
		t.Fatal(err)
	}
	index := func(p string) int {
		n, _ := strconv.Atoi(strings.SplitN(filepath.Base(p), "-", 2)[0])
		return n
	}
	sort.Slice(files, func(i, j int) bool { return index(files[i]) < index(files[j]) })
	entries := make([][]byte, len(files))
	for i, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		entries[i] = raw
	}
	const rejected = 79
	if !strings.Contains(filepath.Base(files[rejected]), "bad-device_id-uppercase") {
		t.Fatalf("log/79 is %s, not the uppercase enroll", filepath.Base(files[rejected]))
	}
	tree, err := tlog.Build(entries)
	if err != nil {
		t.Fatal(err)
	}
	path, err := tree.InclusionProof(rejected)
	if err != nil {
		t.Fatal(err)
	}
	checkpoint := string(read("served/checkpoint"))
	anchor := shippedAnchor(t)
	answer := func(t *testing.T, b *Bundle) (refusal.Code, error) {
		t.Helper()
		raw, err := b.Encode()
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := Decode(raw)
		if err == nil {
			err = decoded.Check(anchor)
		}
		code, _ := refusal.CodeOf(err)
		return code, err
	}

	// A sound bundle relabelled outside the grammar: the label is malformed
	// before anything in the bundle is checked, whatever the entry says.
	sound, err := Decode(read("proofs/nas.bundle"))
	if err != nil {
		t.Fatal(err)
	}
	sound.Device = "NAS"
	if code, err := answer(t, sound); code != refusal.Bundle {
		t.Errorf("a sound bundle labelled NAS: Go answers %q (%v), SPEC states bundle", code, err)
	}

	// log/79 under the label its request carries, which is outside the
	// grammar: bundle, at step 1, before the entry is looked at.
	wrapped, err := Build("Probe", rejected, entries[rejected], path, checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	if code, err := answer(t, wrapped); code != refusal.Bundle {
		t.Errorf("log/79 labelled Probe: Go answers %q (%v), SPEC states bundle", code, err)
	}

	// The same entry under a well-formed label: the proof holds, and the
	// entry names no device because its request does not decode.
	wrapped.Device = "probe"
	code, err := answer(t, wrapped)
	if code != refusal.Binding || err == nil || !strings.Contains(err.Error(), "does not decode") {
		t.Errorf("log/79 labelled probe: Go answers %q (%v), SPEC states binding for an entry that names no device", code, err)
	}
}
