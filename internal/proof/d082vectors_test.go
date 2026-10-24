package proof

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/onembyte/norn/internal/cbor"
	"github.com/onembyte/norn/internal/ed25519v1"
	"github.com/onembyte/norn/internal/enrollreq"
	"github.com/onembyte/norn/internal/entry"
	"github.com/onembyte/norn/internal/refusal"
	"github.com/onembyte/norn/internal/tlog"
	upstream "golang.org/x/mod/sumdb/tlog"
)

// These five reader shapes separate structural binding from replay. Each
// has a real path under a signed, quorum-cosigned head, so an earlier refusal
// cannot hide either an over-wide binding check or a missing envelope check.
func TestD082BundlesBindStructureWithoutReplayingTheEntry(t *testing.T) {
	for _, c := range []struct{ name, dir, code string }{
		{"enroll-other-net", "proofs", "accept"},
		{"rotate-small-order-pk", "proofs", "accept"},
		{"rotate-open-body", "proofs", "accept"},
		{"enroll-open-body", "proofs", "accept"},
		{"rotate-no-ts", "proofs-bad", "binding"},
	} {
		t.Run(c.name, func(t *testing.T) {
			var m struct {
				Sound []struct {
					Name, File, Device string
					Index              int64
				}
				Cases []struct{ Name string }
				Codes map[string]string
				Rules map[string]struct{ Section, Says string }
			}
			if err := json.Unmarshal(d080Read(t, c.dir+"/cases.json"), &m); err != nil {
				t.Fatal(err)
			}
			listed := 0
			for _, s := range m.Sound {
				if s.Name == c.name {
					listed++
					if s.File != c.name+".bundle" || s.Device != "nas" || s.Index != 1 {
						t.Error("sound case must name nas at index 1")
					}
				}
			}
			for _, s := range m.Cases {
				if s.Name == c.name {
					listed++
				}
			}
			if listed != 1 || m.Codes[c.name] != c.code {
				t.Fatalf("manifest must list %s once with code %s", c.name, c.code)
			}
			phrase := "Binding is structural"
			if c.code == "binding" {
				phrase = "`ts`, a map `body`, well-formed `sigs`"
			}
			if rule := m.Rules[c.name]; rule.Section != "8.1" || !strings.Contains(rule.Says, phrase) {
				t.Fatal("case must cite D-082's structural binding sentence in §8.1")
			}
			b, err := Decode(d080Read(t, c.dir+"/"+c.name+".bundle"))
			if err != nil {
				t.Fatal(err)
			}
			if b.Device != "nas" || b.Index != 1 {
				t.Fatal("must prove nas at index 1")
			}
			cp, err := tlog.Verify(b.Checkpoint, shippedAnchor(t).LogKeys)
			if err != nil || cp.Size != 2 {
				t.Fatalf("need a signed two-leaf head: %v", err)
			}
			if err := upstream.CheckRecord(b.Proof, cp.Size, cp.Root, b.Index, tlog.LeafHash(b.Entry)); err != nil {
				t.Fatal(err)
			}
			// Relabel the same leaf: binding is after the head's signature,
			// quorum and inclusion proof, and cannot be their stand-in.
			wrong := *b
			wrong.Device = "printer"
			if got, _ := refusal.CodeOf(wrong.Check(shippedAnchor(t))); got != refusal.Binding {
				t.Fatalf("sound checkpoint, quorum and inclusion must reach binding: %v", got)
			}
			value, err := cbor.Decode(b.Entry)
			if err != nil {
				t.Fatal(err)
			}
			env := value.(map[string]any)
			body := env["body"].(map[string]any)
			if env["v"] != uint64(1) {
				t.Fatal("each binding case must keep envelope version 1")
			}
			if strings.HasPrefix(c.name, "rotate-") {
				if env["t"] != "rotate" || body["device_id"] != "nas" || env["prev"] != uint64(35) || len(body["wg_pk"].([]byte)) != entry.KeyLen {
					t.Fatal("must carry the nas rotate, its current prev and a 32-byte WG key")
				}
				if _, present := env["after"]; present {
					t.Fatal("the reader's rotate binding cases carry no after")
				}
			} else if env["t"] != "enroll" {
				t.Fatal("must carry an enroll")
			}
			if c.code == "accept" {
				if _, err := entry.Decode(b.Entry); err != nil {
					t.Fatalf("sound case must keep a well-formed entry envelope: %v", err)
				}
			}
			switch c.name {
			case "enroll-other-net", "enroll-open-body":
				req, err := enrollreq.Decode(body["request"].([]byte))
				if err != nil || !enrollreq.Verify(req) || req.DeviceID != "nas" || !bytes.Equal(req.Net, []byte("norn-testnet-001")) {
					t.Fatalf("must carry nas's valid request for this network: %v", err)
				}
				if c.name == "enroll-other-net" {
					if bytes.Equal(env["net"].([]byte), req.Net) || len(body) != 1 {
						t.Fatal("only the envelope network must differ")
					}
				} else if len(body) != 2 || body["x"] != uint64(1) || !bytes.Equal(env["net"].([]byte), req.Net) {
					t.Fatal("body must be {request, x} in this network")
				}
			case "rotate-small-order-pk":
				pk := body["device_pk"].([]byte)
				if hex.EncodeToString(pk) != "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05" || ed25519v1.ValidPoint(pk) {
					t.Fatal("incoming device_pk must have order 8")
				}
			case "rotate-open-body":
				if len(body) != 3 || body["x"] != uint64(1) {
					t.Fatal("rotate body must have an unknown x beside device_id and wg_pk")
				}
			case "rotate-no-ts":
				if _, ok := env["ts"]; ok {
					t.Fatal("envelope must lack ts")
				}
				if _, err := entry.Decode(b.Entry); err == nil || !strings.Contains(err.Error(), `missing envelope key "ts"`) {
					t.Fatalf("sole envelope fault must be missing ts: %v", err)
				}
				// Adding only ts restores structural binding, independently
				// of the path, which commits the unmodified leaf.
				env["ts"] = uint64(1_760_009_000)
				fixed, err := cbor.Encode(env)
				if err != nil {
					t.Fatal(err)
				}
				if subject, err := subjectOf(fixed); err != nil || subject != "nas" {
					t.Fatalf("adding only ts must repair binding: %q %v", subject, err)
				}
			}
			err = b.Check(shippedAnchor(t))
			got := "accept"
			if err != nil {
				code, _ := refusal.CodeOf(err)
				got = string(code)
			}
			if got != c.code {
				t.Fatalf("Go answers %s (%v), want %s", got, err, c.code)
			}
			t.Logf("%s/%s.bundle: %s", c.dir, c.name, got)
		})
	}
}
