package replay

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/onembyte/norn/internal/entry"
)

// privateKey is one of the fixture's Ed25519 keys, by its keys.json name.
func privateKey(t *testing.T, name string) ed25519.PrivateKey {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(vectorRoot(), "keys.json"))
	if err != nil {
		t.Fatal(err)
	}
	var keys struct {
		Ed25519 map[string]struct{ Seed string } `json:"ed25519"`
	}
	if err := json.Unmarshal(raw, &keys); err != nil {
		t.Fatal(err)
	}
	seed, err := hex.DecodeString(keys.Ed25519[name].Seed)
	if err != nil || len(seed) != ed25519.SeedSize {
		t.Fatalf("keys.json has no usable %s seed", name)
	}
	return ed25519.NewKeyFromSeed(seed)
}

// §5.1: a rejected entry changes nothing. The `params` handler wrote each key
// as it validated it, so an entry with one good key and one bad one was
// rejected `decode` after the good key had already landed -- and in Go the
// keys are visited in map order, so whether `mmd` changed depended on the
// run. Two nodes replaying one log disagreed on how long the log may take to
// include an entry, and a node disagreed with itself from one poll to the
// next (audit SEC-010). Two hundred replays, because the old behaviour was
// a coin toss weighted about one in six.
func TestARejectedParamsEntryChangesNothingEveryTime(t *testing.T) {
	anchor, entries, _ := loadCase(t, filepath.Join(vectorRoot(), "log"))
	before := Replay(anchor, entries)
	if before.Params["mmd"] == uint64(60) {
		t.Fatal("the fixture already has mmd = 60; nothing here is tested")
	}
	env := &entry.Envelope{V: entry.Version, T: "params", Net: anchor.Net, TS: 1_760_700_000,
		Body: map[string]any{"mmd": uint64(60), "staleness": true}}
	for _, name := range []string{"root1", "root2", "root3", "root4"} {
		key := privateKey(t, name)
		if _, ok := before.Roots[entry.Kid(key.Public().(ed25519.PublicKey))]; ok {
			if err := entry.Sign(env, key, "root"); err != nil {
				t.Fatal(err)
			}
		}
	}
	raw, err := entry.Encode(env)
	if err != nil {
		t.Fatal(err)
	}
	log := append(append([][]byte(nil), entries...), raw)
	for i := 0; i < 200; i++ {
		after := Replay(anchor, log)
		last := after.Rejected[len(after.Rejected)-1]
		if last.Index != uint64(len(entries)) || last.Reason != ReasonDecode {
			t.Fatalf("replay %d: the mixed entry was not rejected decode: %+v", i, last)
		}
		if !reflect.DeepEqual(after.Params, before.Params) {
			t.Fatalf("replay %d: a rejected params entry changed params from %v to %v",
				i, before.Params, after.Params)
		}
	}
}
