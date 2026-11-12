package proof

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/onembyte/norn/internal/cbor"
	"github.com/onembyte/norn/internal/cosign"
	"github.com/onembyte/norn/internal/entry"
	"github.com/onembyte/norn/internal/policy"
	"github.com/onembyte/norn/internal/tlog"
	upstream "golang.org/x/mod/sumdb/tlog"
)

var runTwentyOneBundles = []string{"bool-v", "bool-index", "entry-prev-bool", "entry-after-bool", "entry-sigs-malformed-kid", "entry-net-15-bytes"}

func runTwentyOneBundleName(name string) bool {
	for _, n := range runTwentyOneBundles {
		if n == name {
			return true
		}
	}
	return false
}

// Every negative keeps its authenticated inclusion. Only the named schema
// field differs from its accepted twin, with signatures renewed over content.
func checkRunTwentyOneBundlePairs(t *testing.T) {
	t.Helper()
	for _, name := range runTwentyOneBundles {
		t.Run(name+" repair", func(t *testing.T) { checkRunTwentyOneBundlePair(t, name) })
	}
}

func checkRunTwentyOneBundlePair(t *testing.T, name string) {
	t.Helper()
	var meta struct {
		Cases   []struct{ Name string }
		Codes   map[string]string
		Rules   map[string]struct{ Section, Says string }
		Repairs map[string]string
	}
	if err := json.Unmarshal(d080Read(t, "proofs-bad/cases.json"), &meta); err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, c := range meta.Cases {
		if c.Name == name {
			count++
		}
	}
	section, phrase, code := "4.0", "schemas MUST reject them outside `params.rotate_needs_signer`", "bundle"
	if strings.HasPrefix(name, "entry-") {
		section, phrase, code = "8.1", "set of members, each of its type: `v` 1,", "binding"
	}
	if name == "entry-sigs-malformed-kid" {
		phrase = "well-formed `sigs`"
	}
	if name == "entry-net-15-bytes" {
		phrase = "a 16-byte `net`"
	}
	if count != 1 || meta.Codes[name] != code || meta.Rules[name].Section != section || meta.Rules[name].Says != phrase || meta.Repairs[name] == "" {
		t.Fatalf("missing %s case, code, rule or repair", name)
	}
	decodeMap := func(raw []byte) map[string]any {
		t.Helper()
		v, e := cbor.DecodeWithin(raw, MaxBundleBytes)
		if e != nil {
			t.Fatal(e)
		}
		return v.(map[string]any)
	}
	raw := d080Read(t, "proofs-bad/"+name+".bundle")
	twin := d080Read(t, "proofs-bad/"+meta.Repairs[name])
	m := decodeMap(raw)
	if len(m) != 6 || m["device"] != "nas" {
		t.Fatal("must retain the closed nas bundle")
	}
	repaired, err := Decode(twin)
	if err != nil {
		t.Fatal(err)
	}
	if err := repaired.Check(shippedAnchor(t)); err != nil {
		t.Fatalf("repair must accept: %v", err)
	}
	if name == "bool-v" || name == "bool-index" {
		field := "v"
		if name == "bool-index" {
			field = "index"
		}
		if m[field] != true || repaired.Index != 1 {
			t.Fatal("boolean must replace uint 1")
		}
		m[field] = uint64(1)
		got, e := cbor.Encode(m)
		if e != nil || !bytes.Equal(got, twin) || !bytes.Equal(twin, d080Read(t, "proofs/nas.bundle")) {
			t.Fatal("uint-only repair must recover nas byte for byte")
		}
	} else {
		negative, e := Decode(raw)
		if e != nil {
			t.Fatal(e)
		}
		checkRunTwentyOneInclusion(t, negative)
		checkRunTwentyOneInclusion(t, repaired)
		if negative.Index != 1 || repaired.Index != 1 {
			t.Fatal("entry pairs require two-leaf trees")
		}
		n, r := decodeMap(negative.Entry), decodeMap(repaired.Entry)
		for i, env := range []map[string]any{n, r} {
			sigs := env["sigs"].([]any)
			if len(sigs) != 1 {
				t.Fatal("one genuine device signature required")
			}
			sig := sigs[0].(map[string]any)
			if sig["role"] != "device" || len(sig["sig"].([]byte)) != 64 {
				t.Fatal("kid fault must not hide another signature fault")
			}
			if name != "entry-sigs-malformed-kid" || i == 1 {
				if sig["kid"] != runTwentyOneKid() {
					t.Fatal("wrong fixture kid")
				}
			}
			delete(env, "sigs")
			encoded, e := cbor.Encode(env)
			if e != nil {
				t.Fatal(e)
			}
			seed := sha256.Sum256([]byte("norn/testvector/v1\nnas"))
			key := ed25519.NewKeyFromSeed(seed[:])
			if !ed25519.Verify(key.Public().(ed25519.PublicKey), append([]byte(entry.PreimagePrefix), encoded...), sig["sig"].([]byte)) {
				t.Fatal("entry signature must cover its actual hostile content")
			}
			env["sigs"] = sigs
		}
		switch name {
		case "entry-prev-bool", "entry-after-bool":
			field := "prev"
			if name == "entry-after-bool" {
				field = "after"
			}
			if n[field] != true || r[field] != uint64(1) {
				t.Fatal("only boolean to uint 1 repairs the guard")
			}
			n[field] = uint64(1)
		case "entry-sigs-malformed-kid":
			s := n["sigs"].([]any)[0].(map[string]any)
			if s["kid"] != "NOT-A-KID" {
				t.Fatal("malformed kid missing")
			}
			s["kid"] = runTwentyOneKid()
		case "entry-net-15-bytes":
			if len(n["net"].([]byte)) != 15 || !bytes.Equal(n["net"].([]byte), r["net"].([]byte)[:15]) {
				t.Fatal("only final network byte may be absent")
			}
			n["net"] = r["net"]
		}
		delete(n, "sigs")
		delete(r, "sigs")
		if !reflect.DeepEqual(n, r) {
			t.Fatal("repair changed another envelope field")
		}
		if repaired.Checkpoint == negative.Checkpoint {
			t.Fatal("entry repair must renew the authenticated tree")
		}
	}
	t.Log("field-only repair accepted; signatures, checkpoint, quorum and inclusion verified")
}

func runTwentyOneKid() string {
	seed := sha256.Sum256([]byte("norn/testvector/v1\nnas"))
	return entry.Kid(ed25519.NewKeyFromSeed(seed[:]).Public().(ed25519.PublicKey))
}

func checkRunTwentyOneInclusion(t *testing.T, b *Bundle) {
	t.Helper()
	a := shippedAnchor(t)
	cp, e := tlog.Verify(b.Checkpoint, a.LogKeys)
	if e != nil {
		t.Fatal(e)
	}
	if cp.Origin != a.Origin || cp.Size != 2 {
		t.Fatal("must be this network's two-leaf tree")
	}
	rules, e := policy.Parse(a.Policy)
	if e != nil {
		t.Fatal(e)
	}
	sigs, e := cosign.Verify(b.Checkpoint, rules.Keys())
	if e != nil {
		t.Fatal(e)
	}
	var names []string
	for _, s := range sigs {
		if n, ok := rules.LabelFor(s.Name, s.Public); ok {
			names = append(names, n)
		}
	}
	if len(sigs) != 3 || !rules.Satisfied(names) {
		t.Fatal("genuine three-witness quorum required")
	}
	if e := upstream.CheckRecord(b.Proof, cp.Size, cp.Root, b.Index, tlog.LeafHash(b.Entry)); e != nil {
		t.Fatal(e)
	}
	tree, e := tlog.Build([][]byte{d080Read(t, "log/0-genesis.cbor"), b.Entry})
	if e != nil || tree.Head() != cp.Root {
		t.Fatal("head must commit genesis and this entry")
	}
}
