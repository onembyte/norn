package replay

import (
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/onembyte/norn/internal/note"
	"github.com/onembyte/norn/internal/policy"
	"github.com/onembyte/norn/internal/trust"
)

// Replay permits minimal anchors in unit tests, but every distributed anchor
// must supply the four fields a verifier takes from its trust file (§5).
func TestEveryShippedAnchorIsOneATrustFileCouldGive(t *testing.T) {
	root := vectorRoot()
	anchors := map[string]json.RawMessage{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || d.Name() != "manifest.json" {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var doc map[string]json.RawMessage
		if err := json.Unmarshal(raw, &doc); err != nil {
			return err
		}
		if anchor, ok := doc["anchor"]; ok {
			dir, err := filepath.Rel(root, filepath.Dir(path))
			if err != nil {
				return err
			}
			anchors[filepath.ToSlash(dir)] = anchor
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{"log", "log-cas", "log-edges", "log-admission", "log-empty"} {
		if _, ok := anchors[dir]; !ok {
			t.Errorf("%s has no shipped anchor", dir)
		}
	}
	for _, parent := range []string{"genesis", "genesis-good"} {
		dirs, err := os.ReadDir(filepath.Join(root, parent))
		if err != nil {
			t.Fatal(err)
		}
		count := 0
		for _, dir := range dirs {
			if dir.IsDir() {
				count++
				if _, ok := anchors[parent+"/"+dir.Name()]; !ok {
					t.Errorf("%s/%s has no shipped anchor", parent, dir.Name())
				}
			}
		}
		if count == 0 {
			t.Errorf("%s has no case directories", parent)
		}
	}
	refused := 0
	for dir, raw := range anchors {
		if !t.Run(dir, func(t *testing.T) { checkShippedAnchor(t, raw) }) {
			refused++
		}
	}
	t.Logf("refused %d of %d shipped anchors", refused, len(anchors))
}

func checkShippedAnchor(t *testing.T, raw json.RawMessage) {
	t.Helper()
	var a map[string]string
	if err := json.Unmarshal(raw, &a); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"net", "genesis_hash", "log_key", "policy"} {
		if _, ok := a[key]; !ok {
			t.Errorf("anchor is missing %s", key)
		}
	}
	if len(a) != 4 || t.Failed() {
		t.Fatalf("anchor must have exactly net, genesis_hash, log_key, policy; got %d keys", len(a))
	}
	net, err := hex.DecodeString(a["net"])
	if err != nil || len(net) != 16 {
		t.Fatalf("net must be 16 bytes of hex: %v", err)
	}
	genesis, err := hex.DecodeString(a["genesis_hash"])
	if err != nil || len(genesis) != 32 {
		t.Fatalf("genesis_hash must be 32 bytes of hex: %v", err)
	}
	key, keyErr := note.ParseVerifierKey(a["log_key"])
	if keyErr != nil {
		t.Errorf("log_key: %v", keyErr)
	}
	p, policyErr := policy.Parse(a["policy"])
	if policyErr != nil {
		t.Errorf("policy: %v", policyErr)
	}
	if keyErr != nil || policyErr != nil {
		return
	}
	origin, err := trust.OriginFor(net)
	if err != nil {
		t.Fatal(err)
	}
	tr := &trust.Trust{Version: trust.Version, Net: net, Origin: origin,
		Name: "shipped anchor", GenesisHash: genesis, LogKey: a["log_key"],
		LogURLs: []string{"https://example.invalid/log"}, Policy: a["policy"]}
	for _, w := range p.Witnesses {
		tr.Witnesses = append(tr.Witnesses, trust.Witness{Name: w.Name, Key: w.Key})
	}
	if err := tr.Validate(); err != nil {
		t.Error(err)
	}
	// Preserve the parsed public key while removing name/algorithm failures
	// that would mask D-077 (6). The trust validator still owns disjointness;
	// the original verifier key above must also pass all its checks.
	tr.LogKey = note.VerifierKey(origin, key.Public)
	if tr.LogKey != a["log_key"] {
		if err := tr.Validate(); err != nil {
			t.Errorf("public-key invariant: %v", err)
		}
	}
}
