package proof

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/onembyte/norn/internal/cbor"
	"github.com/onembyte/norn/internal/enrollreq"
	"github.com/onembyte/norn/internal/entry"
	"github.com/onembyte/norn/internal/refusal"
	"github.com/onembyte/norn/internal/tlog"
	upstream "golang.org/x/mod/sumdb/tlog"
)

func d080Read(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "vectors", path))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// A signed tree really commits each malformed entry: an inclusion failure
// must never mask the size or envelope rule this pair ships.
func TestD080ShippedEntryRefusalsHaveSoundTwins(t *testing.T) {
	var m struct {
		Cases []struct{ Name string }
		Codes map[string]string
	}
	if err := json.Unmarshal(d080Read(t, "proofs-bad/cases.json"), &m); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ name, code string }{{"oversize-entry", "bundle"}, {"rotate-v2", "binding"}} {
		t.Run(c.name, func(t *testing.T) {
			sound, err := Decode(d080Read(t, "proofs/nas-rotate.bundle"))
			if err != nil {
				t.Fatal(err)
			}
			if err := sound.Check(shippedAnchor(t)); err != nil {
				t.Fatal(err)
			}
			found := 0
			for _, listed := range m.Cases {
				if listed.Name == c.name {
					found++
				}
			}
			if found != 1 || m.Codes[c.name] != c.code {
				t.Error("case must be listed with code " + c.code)
			}
			raw := d080Read(t, "proofs-bad/"+c.name+".bundle")
			if len(raw) >= MaxBundleBytes {
				t.Fatal("entry case must be below MAX_BUNDLE_BYTES")
			}
			value, err := cbor.DecodeWithin(raw, MaxBundleBytes)
			if err != nil {
				t.Fatal(err)
			}
			doc := value.(map[string]any)
			embedded := doc["entry"].([]byte)
			v, err := cbor.DecodeWithin(embedded, MaxBundleBytes)
			if err != nil {
				t.Fatal(err)
			}
			env := v.(map[string]any)
			body := env["body"].(map[string]any)
			if env["t"] != "rotate" || body["device_id"] != "nas" || doc["device"] != "nas" || doc["index"] != uint64(1) {
				t.Fatal("must prove a rotate naming nas at index 1")
			}
			if c.name == "oversize-entry" {
				if len(embedded) != 65536 || env["v"] != uint64(1) {
					t.Fatal("must be a version-1 entry of exactly 65536 bytes")
				}
				if len(body["padding"].([]byte)) == 0 {
					t.Fatal("entry must be padded")
				}
				delete(body, "padding")
			} else {
				if env["v"] != uint64(2) {
					t.Fatal("entry must have version 2")
				}
				env["v"] = uint64(1)
			}
			fixed, err := cbor.Encode(env)
			if err != nil || !bytes.Equal(fixed, sound.Entry) {
				t.Fatal("repairing just size or version must recover the real nas rotate")
			}
			// Verify the actual malformed leaf independently of Decode's step 1.
			b := *sound
			b.Entry, b.Index, b.Checkpoint = embedded, 1, doc["checkpoint"].(string)
			b.Proof = nil
			for _, item := range doc["proof"].([]any) {
				var h upstream.Hash
				copy(h[:], item.([]byte))
				b.Proof = append(b.Proof, h)
			}
			cp, err := tlog.Verify(b.Checkpoint, shippedAnchor(t).LogKeys)
			if err != nil || cp.Size != 2 || len(b.Proof) != 1 {
				t.Fatalf("need a signed two-leaf head and real sibling: %v", err)
			}
			if err := upstream.CheckRecord(b.Proof, cp.Size, cp.Root, 1, tlog.LeafHash(embedded)); err != nil {
				t.Fatal(err)
			}
			// Check must reach binding, after the checkpoint quorum and real path.
			if got, _ := refusal.CodeOf(b.Check(shippedAnchor(t))); got != refusal.Binding {
				t.Fatalf("independent checkpoint/path check answers %q, want binding", got)
			}
			back, err := Decode(raw)
			if c.name == "oversize-entry" && err == nil {
				t.Error("oversize entry must fail Decode at step 1")
			}
			if err == nil {
				err = back.Check(shippedAnchor(t))
			}
			if got, _ := refusal.CodeOf(err); string(got) != c.code {
				t.Fatalf("Go answers %q (%v), SPEC states %s", got, err, c.code)
			}
			t.Logf("proofs-bad/%s.bundle: %s; proofs/nas-rotate.bundle: accept", c.name, c.code)
		})
	}
}

// A bundle proves inclusion even when replay rejects the request it carries.
func TestD080ShippedRequestBindingDecodesWithoutSignatureOrNetworkChecks(t *testing.T) {
	var m struct {
		Sound []struct {
			Name, File, Device string
			Index              int64
		}
		Codes    map[string]string
		Installs map[string]string
	}
	if err := json.Unmarshal(d080Read(t, "proofs/cases.json"), &m); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name, entry string
		index       int64
	}{{"forged", "98-bad-forged-device-sig", 98}, {"halfsigned", "57-bad-request-net", 57}} {
		t.Run(c.name, func(t *testing.T) {
			good, err := Decode(d080Read(t, "proofs/nas.bundle"))
			if err != nil {
				t.Fatal(err)
			}
			if err := good.Check(shippedAnchor(t)); err != nil {
				t.Fatal(err)
			}
			found := 0
			for _, listed := range m.Sound {
				if listed.Name == c.name {
					found++
					if listed.File != c.name+".bundle" || listed.Device != c.name || listed.Index != c.index {
						t.Fatal("wrong sound metadata")
					}
				}
			}
			if found != 1 || m.Codes[c.name] != "accept" {
				t.Error("bundle must be listed under sound with accept")
			}
			if _, ok := m.Installs[c.name]; ok {
				t.Fatal("a refused enrollment installs nothing")
			}
			b, err := Decode(d080Read(t, "proofs/"+c.name+".bundle"))
			if err != nil {
				t.Fatal(err)
			}
			if b.Device != c.name || b.Index != c.index || !bytes.Equal(b.Entry, d080Read(t, "log/"+c.entry+".cbor")) || b.Checkpoint != string(d080Read(t, "served/checkpoint")) {
				t.Fatal("must prove the unchanged logged entry at the served head under its own label")
			}
			env, err := entry.Decode(b.Entry)
			if err != nil {
				t.Fatal(err)
			}
			req, err := enrollreq.Decode(env.Body["request"].([]byte))
			if err != nil {
				t.Fatal(err)
			}
			if c.name == "forged" && (enrollreq.Verify(req) || !bytes.Equal(req.Net, env.Net)) {
				t.Fatal("forged signature must be the request's sole consumer fault")
			}
			if c.name == "halfsigned" && (!enrollreq.Verify(req) || bytes.Equal(req.Net, env.Net)) {
				t.Fatal("other network must be the request's sole consumer fault")
			}
			if err := b.Check(shippedAnchor(t)); err != nil {
				t.Fatalf("Go refuses %v, SPEC states accept", err)
			}
			b.Device = "nas"
			if got, _ := refusal.CodeOf(b.Check(shippedAnchor(t))); got != refusal.Binding {
				t.Fatal("wrong label must still be binding")
			}
			t.Logf("proofs/%s.bundle: accept; wrong-label twin: binding", c.name)
		})
	}
}
