package proof

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/onembyte/norn/internal/cbor"
	"github.com/onembyte/norn/internal/entry"
	"github.com/onembyte/norn/internal/logclient"
	"github.com/onembyte/norn/internal/refusal"
	"github.com/onembyte/norn/internal/replay"
	"github.com/onembyte/norn/internal/tlog"
	"github.com/onembyte/norn/internal/trust"
	upstream "golang.org/x/mod/sumdb/tlog"
)

func TestRunSeventeenBundleRefusalsHaveSoundTwins(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "vectors")
	read := func(t *testing.T, path string) []byte {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join(root, path))
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	var manifest struct{ Codes map[string]string }
	if err := json.Unmarshal(read(t, "proofs-bad/cases.json"), &manifest); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ name, code string }{{"short-proof-hash", "bundle"}, {"request-device-pk-small-order", "binding"}, {"pk-length-under-own-id", "binding"}} {
		t.Run(c.name, func(t *testing.T) {
			if manifest.Codes[c.name] != c.code {
				t.Error("manifest must name " + c.code)
			}
			sound := read(t, "proofs/nas.bundle")
			good, err := Decode(sound)
			if err != nil {
				t.Fatal(err)
			}
			if err := good.Check(shippedAnchor(t)); err != nil {
				t.Fatal(err)
			}
			raw := read(t, "proofs-bad/"+c.name+".bundle")
			b, err := Decode(raw)
			if err == nil {
				err = b.Check(shippedAnchor(t))
			}
			code, _ := refusal.CodeOf(err)
			if string(code) != c.code {
				t.Fatalf("Go answers %q (%v), SPEC states %s", code, err, c.code)
			}
			if c.name == "short-proof-hash" {
				value, err := cbor.DecodeWithin(raw, MaxBundleBytes)
				if err != nil {
					t.Fatal(err)
				}
				m := value.(map[string]any)
				hashes := m["proof"].([]any)
				if len(hashes[0].([]byte)) != 31 {
					t.Fatal("first hash must have 31 bytes")
				}
				original, _ := cbor.DecodeWithin(sound, MaxBundleBytes)
				hashes[0] = original.(map[string]any)["proof"].([]any)[0]
				fixed, err := cbor.Encode(m)
				if err != nil || !bytes.Equal(fixed, sound) {
					t.Fatal("restoring hash must recover nas.bundle")
				}
			} else {
				// Check the proof separately so an earlier checkpoint or inclusion fault
				// cannot masquerade as a binding refusal.
				cp, err := tlog.Verify(b.Checkpoint, shippedAnchor(t).LogKeys)
				if err != nil {
					t.Fatal(err)
				}
				if err := upstream.CheckRecord(b.Proof, cp.Size, cp.Root, b.Index, tlog.LeafHash(b.Entry)); err != nil {
					t.Fatal(err)
				}
				env, err := entry.Decode(b.Entry)
				if err != nil {
					t.Fatal(err)
				}
				req, err := cbor.Decode(env.Body["request"].([]byte))
				if err != nil {
					t.Fatal(err)
				}
				if req.(map[string]any)["device_id"] != b.Device {
					t.Fatal("label must be the request's own id")
				}
				if c.name == "pk-length-under-own-id" && (b.Index != 81 || b.Device != "probe" || !bytes.Equal(b.Entry, read(t, "log/81-bad-pk-length.cbor")) || b.Checkpoint != string(read(t, "served/checkpoint"))) {
					t.Fatal("must prove unchanged entry 81 at served head under probe")
				}
				if c.name == "request-device-pk-small-order" && len(req.(map[string]any)["device_pk"].([]byte)) != 32 {
					t.Fatal("point refusal needs a 32-byte key")
				}
			}
			t.Logf("proofs-bad/%s: %s; proofs/nas.bundle: accept", c.name, code)
		})
	}
}

func TestRunSeventeenBundleUsesTheReadersReplayedPolicy(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "vectors")
	read := func(t *testing.T, path string) []byte {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join(root, path))
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	doc, err := trust.Parse(read(t, "trust.cbor"))
	if err != nil {
		t.Fatal(err)
	}
	result, err := logclient.Verify(logclient.Dir(filepath.Join(root, "served")), logclient.Anchor{Anchor: replay.FromTrust(doc), Origin: doc.Origin, LogKeys: []string{doc.LogKey}, Policy: doc.Policy})
	if err != nil {
		t.Fatal(err)
	}
	b, err := Decode(read(t, "replayed-policy/nas.bundle"))
	if err != nil {
		t.Fatal(err)
	}
	anchor := shippedAnchor(t)
	if err := b.Check(anchor); err != nil {
		t.Fatal(err)
	}
	anchor.Policy = logclient.PolicyFrom(result.State)
	if code, _ := refusal.CodeOf(b.Check(anchor)); code != refusal.Quorum {
		t.Fatalf("Go answers %q, SPEC states quorum", code)
	}
	sound, err := Decode(read(t, "proofs/nas.bundle"))
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, line := range strings.Split(sound.Checkpoint, "\n") {
		if !strings.HasPrefix(line, "— norn-witness/friend ") {
			lines = append(lines, line)
		}
	}
	if b.Checkpoint != strings.Join(lines, "\n") {
		t.Fatal("only friend's line may be removed")
	}
	b.Checkpoint = sound.Checkpoint
	restored, err := b.Encode()
	if err != nil || !bytes.Equal(restored, read(t, "proofs/nas.bundle")) {
		t.Fatal("restoring friend must recover nas.bundle")
	}
	if err := sound.Check(anchor); err != nil {
		t.Fatal(err)
	}
}
