package replay

import (
	"bytes"
	"crypto/ed25519"
	"testing"

	"github.com/onembyte/norn/internal/cbor"
	"github.com/onembyte/norn/internal/enrollreq"
	"github.com/onembyte/norn/internal/entry"
)

// Each repair is judged at the refused entry's prefix, before a later
// accepted sibling could turn its signed content into a duplicate.
func checkRunTwentyRule(t *testing.T, anchor Anchor, raw [][]byte, i int) {
	t.Helper()
	before := Replay(anchor, raw[:i])
	check := func(value []byte, want string) {
		t.Helper()
		if got := lastOutcome(Replay(anchor, append(append([][]byte{}, raw[:i]...), value)), i); got != want {
			t.Fatalf("run 20 outcome = %q, want %q", got, want)
		}
	}
	source := raw[i]
	above := []byte{0x62, 't', 's', 0x1b, 0x80, 0, 0, 0, 0, 0, 0, 0}
	cap := []byte{0x62, 't', 's', 0x1b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	if i == 40 {
		if bytes.Count(source, above) != 1 {
			t.Fatal("expected ts exactly 2^63")
		}
		source = bytes.Replace(source, above, cap, 1)
	}
	value, err := cbor.Decode(source)
	if err != nil {
		t.Fatal(err)
	}
	env := value.(map[string]any)
	sign := func(keys []string, role string) []byte {
		t.Helper()
		env["sigs"] = []any{}
		unsigned := map[string]any{}
		for k, v := range env {
			if k != "sigs" {
				unsigned[k] = v
			}
		}
		encoded, err := cbor.Encode(unsigned)
		if err != nil {
			t.Fatal(err)
		}
		preimage := append([]byte(entry.PreimagePrefix), encoded...)
		sigs := []any{}
		for _, key := range keys {
			pk := privateKey(t, key)
			sigs = append(sigs, map[string]any{"kid": entry.Kid(pk.Public().(ed25519.PublicKey)), "role": role, "sig": ed25519.Sign(pk, preimage)})
		}
		// The fixture root keys are ordered by kid rather than human key name.
		if len(sigs) == 2 && sigs[0].(map[string]any)["kid"].(string) > sigs[1].(map[string]any)["kid"].(string) {
			sigs[0], sigs[1] = sigs[1], sigs[0]
		}
		env["sigs"] = sigs
		result, err := cbor.Encode(env)
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	switch i {
	case 37, 38:
		if i == 37 {
			if _, ok := env["prev"]; ok {
				t.Fatal("prev must be absent")
			}
		} else if env["prev"] == before.Versions["params"] {
			t.Fatal("prev must be stale")
		}
		env["prev"] = before.Versions["params"]
		check(sign([]string{"root1", "root2"}, "root"), "")
	case 39:
		if env["prev"] != before.Versions["params"] || Replay(anchor, raw[:i+1]).Versions["params"] != uint64(i) {
			t.Fatal("current params version not stored")
		}
	case 40:
		sig := env["sigs"].([]any)[0].(map[string]any)["sig"].([]byte)
		unsigned := map[string]any{}
		for k, v := range env {
			if k != "sigs" {
				unsigned[k] = v
			}
		}
		encoded, err := cbor.Encode(unsigned)
		if err != nil {
			t.Fatal(err)
		}
		hostile := bytes.Replace(encoded, cap, above, 1)
		if !ed25519.Verify(publicOf(t, "signer1"), append([]byte(entry.PreimagePrefix), hostile...), sig) {
			t.Fatal("hostile preimage was not genuinely signed")
		}
		repair := sign([]string{"signer1"}, "signer")
		if !bytes.Equal(repair, raw[41]) {
			t.Fatal("cap repair changes more than ts and signatures")
		}
		check(repair, "")
	case 41:
		if env["ts"] != uint64(1<<63-1) {
			t.Fatal("expected cap")
		}
	case 42:
		if env["after"] != true {
			t.Fatal("expected boolean after")
		}
		env["after"] = uint64(1)
		repair := sign([]string{"signer1"}, "signer")
		if !bytes.Equal(repair, raw[43]) {
			t.Fatal("after-only repair differs")
		}
		check(repair, "")
	case 43:
		if env["after"] != uint64(1) {
			t.Fatal("expected uint after")
		}
	case 44:
		req, err := enrollreq.Decode(env["body"].(map[string]any)["request"].([]byte))
		if err != nil {
			t.Fatal(err)
		}
		st := Replay(anchor, raw[:i+1])
		d := st.Devices[req.DeviceID]
		if req.TS != 100 || req.Expires == nil || *req.Expires != 200 || env["ts"].(uint64) <= 200 || !enrollreq.Verify(req) || d.Status != "active" || d.Expires != 200 || d.Version != uint64(i) {
			t.Fatal("elapsed expiry must remain active in replay")
		}
		env["ts"] = uint64(150)
		check(sign([]string{"signer1"}, "signer"), "")
	}
	t.Log("run 20 field-only guard accepted")
}

func checkRunTwentyOrder(t *testing.T, anchor Anchor, raw [][]byte, i int) {
	t.Helper()
	before := Replay(anchor, raw[:i])
	decode := func() *entry.Envelope {
		e, err := entry.Decode(raw[i])
		if err != nil {
			t.Fatal(err)
		}
		return e
	}
	check := func(e *entry.Envelope, want string) []byte {
		t.Helper()
		e.Sigs = nil
		for _, key := range []string{"root1", "root2"} {
			if err := entry.Sign(e, privateKey(t, key), "root"); err != nil {
				t.Fatal(err)
			}
		}
		encoded, err := entry.Encode(e)
		if err != nil {
			t.Fatal(err)
		}
		if got := lastOutcome(Replay(anchor, append(append([][]byte{}, raw[:i]...), encoded)), i); got != want {
			t.Fatalf("point/prev repair = %q, want %q", got, want)
		}
		return encoded
	}
	e := decode()
	if e.Prev == nil || *e.Prev == before.Versions["log_key"] {
		t.Fatal("expected stale prev")
	}
	if i == 42 {
		if len(e.Body["pk"].([]byte)) != 32 {
			t.Fatal("point must have the correct width")
		}
		e.Body["pk"] = publicOf(t, "logkey2")
		if !bytes.Equal(check(e, ReasonStaleState), raw[43]) {
			t.Fatal("point-only sibling differs")
		}
		e = decode()
		e.Prev = before.Previous("log_key", "")
		check(e, ReasonDecode)
	}
	e = decode()
	e.Body["pk"] = publicOf(t, "logkey2")
	e.Prev = before.Previous("log_key", "")
	check(e, "")
	t.Log("point-only and prev-only repairs expose the next code; both apply")
}
