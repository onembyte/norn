package replay

import (
	"bytes"
	"crypto/ed25519"
	"testing"

	"github.com/onembyte/norn/internal/cbor"
	"github.com/onembyte/norn/internal/enrollreq"
	"github.com/onembyte/norn/internal/entry"
)

// Renew signatures over the hostile fields themselves, so a signature failure
// cannot mask a missing schema check. Every twin applies at both prefixes.
func checkRunTwentyOneRule(t *testing.T, anchor Anchor, raw [][]byte, i int) {
	t.Helper()
	if i%2 == 0 {
		return
	}
	decode := func(raw []byte) map[string]any {
		t.Helper()
		v, err := cbor.Decode(raw)
		if err != nil {
			t.Fatal(err)
		}
		return v.(map[string]any)
	}
	encode := func(v map[string]any) []byte {
		t.Helper()
		b, err := cbor.Encode(v)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	env := decode(raw[i])
	sigs := env["sigs"].([]any)
	if len(sigs) != 1 {
		t.Fatal("expected one genuine signer")
	}
	sig := sigs[0].(map[string]any)
	delete(env, "sigs")
	if sig["kid"] != entry.Kid(publicOf(t, "signer1")) || sig["role"] != "signer" || !ed25519.Verify(publicOf(t, "signer1"), append([]byte(entry.PreimagePrefix), encode(env)...), sig["sig"].([]byte)) {
		t.Fatal("hostile envelope signature is not genuine")
	}
	before, after := Replay(anchor, raw[:i]), Replay(anchor, raw[:i+1])
	if lastOutcome(after, i) != ReasonDecode {
		t.Fatalf("run 21 %d = %q, want decode", i, lastOutcome(after, i))
	}
	after.Size, after.Rejected = before.Size, before.Rejected
	a, _ := after.MarshalCanonical()
	b, _ := before.MarshalCanonical()
	if !bytes.Equal(a, b) {
		t.Fatal("refusal changed state")
	}
	var id string
	switch i {
	case 45:
		if env["ts"] != false {
			t.Fatal("expected boolean ts")
		}
		env["ts"] = uint64(0)
	case 47:
		if env["v"] != true {
			t.Fatal("expected boolean v")
		}
		env["v"] = uint64(1)
	case 49, 51, 53:
		req := decode(env["body"].(map[string]any)["request"].([]byte))
		signature := req["sig"].([]byte)
		delete(req, "sig")
		if !ed25519.Verify(publicOf(t, "sundial"), append([]byte(enrollreq.PreimagePrefix), encode(req)...), signature) {
			t.Fatal("hostile request signature is not genuine")
		}
		id = req["device_id"].(string)
		if _, ok := before.Devices[id]; ok {
			t.Fatal("request id must be fresh")
		}
		for _, device := range before.Devices {
			if device.Status == "active" && device.WgPk == hexOf(req["wg_pk"].([]byte)) {
				t.Fatal("request key must be unused")
			}
		}
		field := "ts"
		if i == 49 {
			field = "v"
		}
		if i == 53 {
			if _, ok := req[field]; ok {
				t.Fatal("ts must be absent")
			}
		} else if req[field] != (i == 49) {
			t.Fatal("expected boolean request field")
		}
		repair := uint64(0)
		if i == 49 {
			repair = 1
		}
		req[field] = repair
		req["sig"] = ed25519.Sign(privateKey(t, "sundial"), append([]byte(enrollreq.PreimagePrefix), encode(req)...))
		env["body"].(map[string]any)["request"] = encode(req)
	case 55:
		body := env["body"].(map[string]any)
		if len(body) != 0 {
			t.Fatal("text must be absent")
		}
		body["text"] = ""
	}
	env["sigs"] = []any{map[string]any{"kid": entry.Kid(publicOf(t, "signer1")), "role": "signer", "sig": ed25519.Sign(privateKey(t, "signer1"), append([]byte(entry.PreimagePrefix), encode(env)...))}}
	repaired := encode(env)
	if !bytes.Equal(repaired, raw[i+1]) {
		t.Fatal("repair changed more than the named field and signatures")
	}
	for _, prefix := range [][][]byte{raw[:i], raw[:i+1]} {
		result := Replay(anchor, append(append([][]byte{}, prefix...), repaired))
		if got := lastOutcome(result, len(prefix)); got != "" {
			t.Fatalf("repair = %q", got)
		}
		if id != "" && (result.Devices[id].Status != "active" || result.Devices[id].Version != uint64(len(prefix))) {
			t.Fatal("repair did not enroll its device")
		}
	}
	t.Log("field-only repair accepted at both prefixes")
}
