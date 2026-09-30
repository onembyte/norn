package proof

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/onembyte/norn/internal/enrollreq"
	"github.com/onembyte/norn/internal/entry"
)

// Cold-model gate run 11, defect D14. §8.1's condition 3 said replay must
// yield the device "as `active` with that `wg_pk`", and "that" had no
// antecedent. The nearest candidate is the bundle's, and under that reading a
// node drops every device that has rotated: a bundle proves the entry that
// made its device active, `rotate` leaves `since_index` on the enrol, and so
// the bundle's entry names the key the device was enrolled with.
//
// No vector joined a bundle to the key a node installs. `proofs/cases.json`
// tested only whether a bundle checks out, and `proven/cases.json` is computed
// from `state.json` alone. A node that read condition 3 strictly passed the
// whole suite and quietly dropped `nas`.

// keyInEntry is the WireGuard key the bundled entry itself names: inside the
// request for an `enroll`, in the body for a `rotate`. It is what the strict
// reading compares against, which is why this test has to compute it.
func keyInEntry(t *testing.T, raw []byte) []byte {
	t.Helper()
	env, err := entry.Decode(raw)
	if err != nil {
		t.Fatalf("the bundled entry does not decode: %v", err)
	}
	if env.T == "enroll" {
		body, ok := env.Body["request"].([]byte)
		if !ok {
			t.Fatal("the bundled enroll carries no request")
		}
		request, err := enrollreq.Decode(body)
		if err != nil {
			t.Fatal(err)
		}
		return request.WGPK
	}
	key, ok := env.Body["wg_pk"].([]byte)
	if !ok {
		t.Fatalf("a bundled %q entry names no key", env.T)
	}
	return key
}

func TestTheInstalledKeyIsTheReplayedOneNotTheBundles(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "vectors")

	raw, err := os.ReadFile(filepath.Join(root, "proofs", "cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Devices  []string          `json:"devices"`
		Installs map[string]string `json:"installs"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}

	raw, err = os.ReadFile(filepath.Join(root, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	var st struct {
		Devices map[string]struct {
			Status string `json:"status"`
			WgPk   string `json:"wg_pk"`
		} `json:"devices"`
	}
	if err := json.Unmarshal(raw, &st); err != nil {
		t.Fatal(err)
	}

	if len(manifest.Installs) != len(manifest.Devices) {
		t.Fatalf("`installs` names %d devices and `devices` lists %d; every shipped "+
			"bundle needs the key a node installs beside it", len(manifest.Installs),
			len(manifest.Devices))
	}

	anchor := shippedAnchor(t)
	var rotated []string
	for _, id := range manifest.Devices {
		raw, err := os.ReadFile(filepath.Join(root, "proofs", id+".bundle"))
		if err != nil {
			t.Fatal(err)
		}
		bundle, err := Decode(raw)
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		// Conditions 1 and 3 of §8.1, in the only order that makes sense: a
		// bundle that does not check out proves nothing about any key.
		if err := bundle.Check(anchor); err != nil {
			t.Fatalf("%s: the shipped bundle does not check out: %v", id, err)
		}
		device, ok := st.Devices[id]
		if !ok || device.Status != "active" {
			t.Fatalf("%s: replay does not yield it as active, so it has no bundle to "+
				"install from", id)
		}
		// The manifest is generated from the same replay. Checked anyway: an
		// `installs` that drifted from `state.json` would be a second answer
		// to one question.
		if manifest.Installs[id] != device.WgPk {
			t.Errorf("%s: `installs` says %s and replay gives %s", id,
				manifest.Installs[id], device.WgPk)
		}
		if hex.EncodeToString(keyInEntry(t, bundle.Entry)) != device.WgPk {
			rotated = append(rotated, id)
		}
	}

	// The vector is only worth having if the two readings disagree on it. If
	// every bundle's entry carried the installed key, a node comparing them
	// would pass, and condition 3 would be unpinned again.
	sort.Strings(rotated)
	if len(rotated) == 0 {
		t.Fatal("every shipped bundle's entry carries the key replay gives, so a " +
			"node that requires the two to match passes the whole suite. At least " +
			"one active device has to have rotated since the entry its bundle proves")
	}
	t.Logf("a node comparing the bundle's key with replay's drops %v", rotated)
}

// §8.1 names `nas` and quotes both keys, so a reader can check the claim by
// hand. Those quotations go stale when the fixture changes and nothing else
// would notice.
func TestTheSpecQuotesNasKeysAsTheyShip(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "vectors")
	raw, err := os.ReadFile(filepath.Join(root, "proofs", "nas.bundle"))
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	enrolled := hex.EncodeToString(keyInEntry(t, bundle.Entry))

	raw, err = os.ReadFile(filepath.Join(root, "proofs", "cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Installs map[string]string `json:"installs"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	installed := manifest.Installs["nas"]
	if enrolled == installed {
		t.Fatal("nas's bundle carries the key a node installs, so §8.1's worked " +
			"example no longer shows two different keys")
	}

	spec, err := os.ReadFile(filepath.Join("..", "..", "SPEC.md"))
	if err != nil {
		t.Fatal(err)
	}
	for what, key := range map[string]string{"enrolled": enrolled, "installed": installed} {
		quoted := "`" + key[:8] + "…`"
		if !strings.Contains(string(spec), quoted) {
			t.Errorf("SPEC.md does not quote nas's %s key as %s", what, quoted)
		}
	}
	if bundle.Index != 1 || !strings.Contains(string(spec), "enrolment at index 1") {
		t.Errorf("nas's bundle proves index %d, and §8.1 says it proves the enrolment "+
			"at index 1", bundle.Index)
	}
}
