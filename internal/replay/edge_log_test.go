package replay

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"strings"
	"testing"

	"github.com/onembyte/norn/internal/cbor"
	"github.com/onembyte/norn/internal/enrollreq"
	"github.com/onembyte/norn/internal/entry"
	"github.com/onembyte/norn/internal/note"
)

// Each negative has one defect. Its repaired request or body must replay.
func checkEdgeLog(t *testing.T) {
	dir := vectorRoot() + "/log-edges"
	anchor, raw, m := loadCase(t, dir)
	if len(raw) != 13 {
		t.Fatalf("got %d edge entries, want 13", len(raw))
	}
	st := Replay(anchor, raw)
	want, err := os.ReadFile(dir + "/state.json")
	if err != nil {
		t.Fatal(err)
	}
	got, err := st.MarshalCanonical()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Error("edge state differs from state.json")
	}
	if len(st.Devices["nas"].Labels) != 0 {
		t.Error("re-enrollment kept old labels")
	}
	for _, it := range m.Entries {
		t.Run(it.Name, func(t *testing.T) {
			if got := lastOutcome(st, it.Index); got != it.Reason {
				t.Fatalf("got %q, want %q", got, it.Reason)
			}
			if it.Reason == "" {
				return
			}
			env, err := entry.Decode(raw[it.Index])
			if err != nil {
				t.Fatal(err)
			}
			switch {
			case strings.Contains(it.Name, "device-id-newline"), strings.Contains(it.Name, "request-identity"):
				value, err := cbor.Decode(env.Body["request"].([]byte))
				if err != nil {
					t.Fatal(err)
				}
				req := value.(map[string]any)
				if strings.Contains(it.Name, "device-id-newline") {
					req["device_id"] = "nas2"
				} else {
					req["device_pk"] = publicOf(t, "spare")
				}
				delete(req, "sig")
				preimage, err := cbor.Encode(req)
				if err != nil {
					t.Fatal(err)
				}
				req["sig"] = ed25519.Sign(privateKey(t, "spare"), append([]byte(enrollreq.PreimagePrefix), preimage...))
				repaired, err := cbor.Encode(req)
				if err != nil {
					t.Fatal(err)
				}
				env.Body["request"] = repaired
			case strings.Contains(it.Name, "unknown"):
				// Dropping the extra key exposes unknown-device; the same body with
				// a known active record must be accepted as well.
				delete(env.Body, "extra")
				env.Sigs = nil
				role, key := "device", "spare"
				if env.T == "revoke" {
					role, key = "signer", "signer1"
				}
				if err := entry.Sign(env, privateKey(t, key), role); err != nil {
					t.Fatal(err)
				}
				if got := lastOutcome(Replay(anchor, appended(t, raw[:it.Index], env)), it.Index); got != ReasonUnknownDevice {
					t.Fatalf("body repair: got %q, want unknown-device", got)
				}
				env.Body["device_id"] = "nas2"
			case strings.Contains(it.Name, "witness-note-key"):
				env.Body["text"] = "witness w " + note.CosignerVerifierKey("edge-witness", publicOf(t, "spare")) + "\nquorum w\n"
			default:
				t.Fatal("negative has no repair")
			}
			env.Sigs = nil
			signers := []struct{ name, role string }{{"signer1", "signer"}}
			if env.T == "policy" {
				signers = []struct{ name, role string }{{"root1", "root"}, {"root2", "root"}}
			}
			if env.T == "rotate" {
				signers = []struct{ name, role string }{{"spare", "device"}}
			}
			before := Replay(anchor, raw[:it.Index])
			id, _ := env.Body["device_id"].(string)
			if env.T == "enroll" {
				req, err := enrollreq.Decode(env.Body["request"].([]byte))
				if err != nil {
					t.Fatal(err)
				}
				id = req.DeviceID
			}
			env.Prev = before.Previous(env.T, id)
			for _, s := range signers {
				if err := entry.Sign(env, privateKey(t, s.name), s.role); err != nil {
					t.Fatal(err)
				}
			}
			if got := lastOutcome(Replay(anchor, appended(t, raw[:it.Index], env)), it.Index); got != "" {
				t.Fatalf("repaired entry rejected %q", got)
			}
		})
	}
}

func checkClosedGenesisBody(t *testing.T) {
	anchor, raw, _ := loadCase(t, vectorRoot()+"/genesis/26-body-unknown-key")
	if got := lastOutcome(Replay(anchor, raw), 0); got != ReasonBadGenesis {
		t.Fatalf("got %q, want bad-genesis", got)
	}
	env, err := entry.Decode(raw[0])
	if err != nil {
		t.Fatal(err)
	}
	delete(env.Body, "extra")
	env.Sigs = nil
	for _, name := range []string{"root1", "root2"} {
		if err := entry.Sign(env, privateKey(t, name), "root"); err != nil {
			t.Fatal(err)
		}
	}
	repaired := appended(t, nil, env)
	anchor.GenesisHash = entry.LeafHash(repaired[0])
	st := Replay(anchor, repaired)
	if st.Size != 1 || len(st.Rejected) != 0 {
		t.Fatalf("body repair did not accept: %+v", st.Rejected)
	}
}
