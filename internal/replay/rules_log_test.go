package replay

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/onembyte/norn/internal/cbor"
	"github.com/onembyte/norn/internal/enrollreq"
	"github.com/onembyte/norn/internal/entry"
	"github.com/onembyte/norn/internal/note"
	"github.com/onembyte/norn/internal/policy"
)

// These outcomes are the rules in §4.0, §4.3, §4.4 and §5.1, independent of
// the manifest. The repairs retain the original content wherever possible.
func TestEveryRuleCaseMatchesAndEachRefusalRepairs(t *testing.T) {
	names := []string{"00-genesis", "01-enroll-nas", "02-enroll-laptop", "03-revoke-nas-by-laptop", "04-revoke-nas-by-self", "05-signer-add-without-prev", "06-signer-add-prev-zero", "07-note-without-ts", "08-note-with-ts", "09-enroll-empty-label-value", "10-policy-preannounces-log-key", "11-log-key-preannounced", "12-copy-enroll-unsorted-sigs", "13-copy-enroll-sorted-sigs", "14-root-threshold-full", "15-root-remove-unknown-before-invariant", "16-root-remove-known-at-full-threshold", "17-root-threshold-repaired", "18-root-remove-known", "19-root-restore-known", "20-note-uppercase-kid", "21-note-without-surplus-kid", "22-enroll-by-roots", "23-enroll-with-signer", "24-enroll-expires-zero", "25-enroll-without-expires", "26-policy-trailing-space", "27-params-by-signers", "28-enroll-envelope-device-sig", "29-enroll-unknown-body-key", "30-note-long-hex-kid", "31-revoke-uppercase-device-id", "32-rotate-uppercase-device-id", "33-policy-log-key-was-witness", "34-params-staleness-zero", "35-params-checkpoint-interval-zero", "36-params-mmd-zero"}
	codes := []string{"", "", "", ReasonThreshold, "", ReasonStaleState, "", ReasonDecode, "", "", "", "", ReasonDecode, ReasonDupEntry, "", ReasonUnknownKey, ReasonRootInvariant, "", "", "", ReasonDecode, "", ReasonThreshold, "", ReasonDecode, "", "", ReasonThreshold, ReasonNoDeviceSig, ReasonDecode, ReasonDecode, ReasonDecode, ReasonDecode, "", "", "", ""}
	dir := vectorRoot() + "/log-rules"
	anchor, raw, m := loadCase(t, dir)
	if len(raw) != len(names) {
		t.Fatalf("got %d entries, want %d", len(raw), len(names))
	}
	read := func(path string) []byte {
		t.Helper()
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	var metadata struct {
		Anchor map[string]string
		Codes  map[string]string
		Rules  map[string]struct{ Section, Says string }
	}
	if err := json.Unmarshal(read(dir+"/manifest.json"), &metadata); err != nil {
		t.Fatal(err)
	}
	if len(metadata.Anchor) != 4 || len(metadata.Rules) != len(names) {
		t.Fatal("anchor or rules incomplete")
	}
	spec := string(read("../../SPEC.md"))
	final := Replay(anchor, raw)
	refusals := 0
	for i, name := range names {
		t.Run(name, func(t *testing.T) {
			if m.Entries[i].Name != name || m.Entries[i].Index != i || m.Entries[i].Reason != codes[i] {
				t.Fatal("manifest differs from stated answer")
			}
			rule, ok := metadata.Rules[name]
			heading := "## "
			if strings.Contains(rule.Section, ".") {
				heading = "### "
			}
			_, section, found := strings.Cut(spec, heading+rule.Section+" ")
			section, _, _ = strings.Cut(section, "\n##")
			onLine := false
			for _, line := range strings.Split(section, "\n") {
				onLine = onLine || strings.Contains(line, rule.Says)
			}
			if !ok || !found || rule.Says == "" || !onLine {
				t.Fatal("rule does not cite one raw normative line")
			}
			if got := lastOutcome(final, i); got != codes[i] {
				t.Fatalf("Go = %q, want %q", got, codes[i])
			}
			t.Logf("Go = %q", codes[i])
			if codes[i] == "" {
				return
			}
			refusals++
			if metadata.Codes[name] != codes[i] || string(read(dir+"/"+name+".reason")) != codes[i]+"\n" {
				t.Fatal("code or reason differs")
			}
			before, after := Replay(anchor, raw[:i]), Replay(anchor, raw[:i+1])
			after.Size, after.Rejected = before.Size, before.Rejected
			a, err := after.MarshalCanonical()
			if err != nil {
				t.Fatal(err)
			}
			b, err := before.MarshalCanonical()
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(a, b) {
				t.Fatal("refusal changed state")
			}
			check := func(prefix [][]byte, value []byte, want string) {
				t.Helper()
				result := Replay(anchor, append(append([][]byte(nil), prefix...), value))
				if got := lastOutcome(result, len(prefix)); got != want {
					t.Fatalf("repair Go = %q, want %q", got, want)
				}
			}
			value, err := cbor.Decode(raw[i])
			if err != nil {
				t.Fatal(err)
			}
			env := value.(map[string]any)
			sign := func(keys []string, role string) []byte {
				t.Helper()
				env["sigs"] = []any{}
				encoded, err := cbor.Encode(env)
				if err != nil {
					t.Fatal(err)
				}
				e, err := entry.Decode(encoded)
				if err != nil {
					t.Fatal(err)
				}
				for _, key := range keys {
					if err := entry.Sign(e, privateKey(t, key), role); err != nil {
						t.Fatal(err)
					}
				}
				encoded, err = entry.Encode(e)
				if err != nil {
					t.Fatal(err)
				}
				return encoded
			}
			paired := func(value []byte, index int) {
				t.Helper()
				if !bytes.Equal(value, raw[index]) {
					t.Fatal("repair changes more than its named fault")
				}
			}
			switch i {
			case 3:
				paired(sign([]string{"nas"}, "device"), 4)
				check(raw[:i], raw[4], "")
			case 5:
				if _, ok := env["prev"]; ok {
					t.Fatal("prev should be absent")
				}
				env["prev"] = uint64(0)
				paired(sign([]string{"root1", "root2"}, "root"), 6)
				check(raw[:i], raw[6], "")
			case 7:
				if _, ok := env["ts"]; ok {
					t.Fatal("ts should be absent")
				}
				value, err := cbor.Decode(raw[8])
				if err != nil {
					t.Fatal(err)
				}
				env["ts"] = value.(map[string]any)["ts"]
				paired(sign([]string{"signer1"}, "signer"), 8)
				check(raw[:i], raw[8], "")
			case 12:
				sigs := env["sigs"].([]any)
				if len(sigs) != 2 {
					t.Fatal("copy needs two signatures")
				}
				sigs[0], sigs[1] = sigs[1], sigs[0]
				encoded, err := cbor.Encode(env)
				if err != nil {
					t.Fatal(err)
				}
				paired(encoded, 1)
				paired(raw[13], 1)
				check(raw[:i], raw[13], ReasonDupEntry)
				check(raw[:1], raw[13], "")
			case 13:
				check(raw[:1], raw[i], "")
			case 15:
				env["body"].(map[string]any)["kid"] = entry.Kid(publicOf(t, "root3"))
				paired(sign([]string{"root1", "root2", "root3"}, "root"), 16)
				check(raw[:i], raw[16], ReasonRootInvariant)
				check(raw[:18], raw[18], "")
			case 16:
				check(raw[:18], raw[18], "")
			case 20:
				sigs := env["sigs"].([]any)
				if len(sigs) != 2 {
					t.Fatal("expected signer and surplus element")
				}
				kid := entry.Kid(publicOf(t, "signer1"))
				var kept []any
				for _, sig := range sigs {
					sm := sig.(map[string]any)
					if sm["kid"] == kid {
						kept = append(kept, sig)
					} else if sm["kid"] != strings.ToUpper(kid) || sm["kid"] == kid {
						t.Fatal("surplus kid must be the signer's hex in uppercase")
					}
				}
				if len(kept) != 1 {
					t.Fatal("missing genuine signer")
				}
				env["sigs"] = kept
				encoded, err := cbor.Encode(env)
				if err != nil {
					t.Fatal(err)
				}
				paired(encoded, 21)
				check(raw[:i], raw[21], "")
			case 22:
				before := Replay(anchor, raw[:i])
				sigs := env["sigs"].([]any)
				if len(before.Roots) != 3 || len(sigs) != 3 {
					t.Fatal("expected three current roots")
				}
				for _, sig := range sigs {
					sm := sig.(map[string]any)
					if sm["role"] != "root" || before.Roots[sm["kid"].(string)] == "" {
						t.Fatal("not signed only by current roots")
					}
				}
				req, err := enrollreq.Decode(env["body"].(map[string]any)["request"].([]byte))
				if err != nil {
					t.Fatal(err)
				}
				if !enrollreq.Verify(req) {
					t.Fatal("request signature does not verify")
				}
				if _, ok := before.Devices[req.DeviceID]; ok {
					t.Fatal("request needs a fresh device")
				}
				e, err := entry.Decode(raw[i])
				if err != nil {
					t.Fatal(err)
				}
				if err := entry.Sign(e, privateKey(t, "signer1"), "signer"); err != nil {
					t.Fatal(err)
				}
				encoded, err := entry.Encode(e)
				if err != nil {
					t.Fatal(err)
				}
				paired(encoded, 23)
				check(raw[:i], raw[23], "")
			case 24:
				body := env["body"].(map[string]any)
				value, err := cbor.Decode(body["request"].([]byte))
				if err != nil {
					t.Fatal(err)
				}
				req := value.(map[string]any)
				if req["expires"] != uint64(0) || req["ts"].(uint64) == 0 {
					t.Fatal("expected explicit expires 0 after a positive ts")
				}
				delete(req, "expires")
				delete(req, "sig")
				unsigned, err := cbor.Encode(req)
				if err != nil {
					t.Fatal(err)
				}
				req["sig"] = ed25519.Sign(privateKey(t, "sundial"), append([]byte(enrollreq.PreimagePrefix), unsigned...))
				body["request"], err = cbor.Encode(req)
				if err != nil {
					t.Fatal(err)
				}
				paired(sign([]string{"signer1"}, "signer"), 25)
				check(raw[:i], raw[25], "")
			case 27, 28:
				e, err := entry.Decode(raw[i])
				if err != nil {
					t.Fatal(err)
				}
				r := &replayer{verify: realVerify}
				if r.countRole(before, e, "signer") < before.SignerThr {
					t.Fatal("entry needs a valid current signer quorum")
				}
				if i == 27 {
					if len(e.Sigs) != 2 || r.countRole(before, e, "root") != 0 {
						t.Fatal("governance must carry only the two signer signatures")
					}
					for _, key := range []string{"root1", "root2"} {
						if err := entry.Sign(e, privateKey(t, key), "root"); err != nil {
							t.Fatal(err)
						}
					}
				} else {
					req, err := enrollreq.Decode(e.Body["request"].([]byte))
					if err != nil {
						t.Fatal(err)
					}
					if enrollreq.Verify(req) || !r.deviceSigned(e, req.DevicePK) {
						t.Fatal("request must be broken beside valid envelope consent")
					}
					if err := enrollreq.Sign(req, privateKey(t, "spare")); err != nil {
						t.Fatal(err)
					}
					e.Body["request"], err = enrollreq.Encode(req)
					if err != nil {
						t.Fatal(err)
					}
					e.Sigs = nil
					if err := entry.Sign(e, privateKey(t, "spare"), "device"); err != nil {
						t.Fatal(err)
					}
					if err := entry.Sign(e, privateKey(t, "signer1"), "signer"); err != nil {
						t.Fatal(err)
					}
				}
				encoded, err := entry.Encode(e)
				if err != nil {
					t.Fatal(err)
				}
				check(raw[:i], encoded, "")
				t.Log("only the missing roots or embedded signature repaired; entry applies")
			case 29:
				body := env["body"].(map[string]any)
				req, err := enrollreq.Decode(body["request"].([]byte))
				if err != nil || !enrollreq.Verify(req) || len(body) != 2 || body["x"] == nil {
					t.Fatal("expected sound request plus x")
				}
				delete(body, "x")
				check(raw[:i], sign([]string{"signer1"}, "signer"), "")
			case 30:
				sigs := env["sigs"].([]any)
				if len(sigs) != 2 {
					t.Fatal("expected genuine signer and surplus kid")
				}
				kept := []any{}
				for _, sig := range sigs {
					kid := sig.(map[string]any)["kid"].(string)
					if len(kid) == 17 {
						if strings.Trim(kid, "0123456789abcdef") != "" {
							t.Fatal("surplus kid is not lowercase hex")
						}
					} else if kid == entry.Kid(publicOf(t, "signer1")) {
						kept = append(kept, sig)
					} else {
						t.Fatal("unexpected kid")
					}
				}
				if len(kept) != 1 {
					t.Fatal("missing genuine signer")
				}
				env["sigs"] = kept
				encoded, err := cbor.Encode(env)
				if err != nil {
					t.Fatal(err)
				}
				check(raw[:i], encoded, "")
			case 31, 32:
				body := env["body"].(map[string]any)
				if body["device_id"] != "NAS" {
					t.Fatal("expected uppercase device id")
				}
				body["device_id"] = "unknown-device"
				keys, role := []string{"signer1"}, "signer"
				if i == 32 {
					keys, role = []string{"nas"}, "device"
				}
				check(raw[:i], sign(keys, role), ReasonUnknownDevice)
				body["device_id"] = "laptop"
				env["prev"] = before.Devices["laptop"].Version
				if i == 32 {
					keys = []string{"laptop"}
				}
				check(raw[:i], sign(keys, role), "")
			default:
				t.Fatal("refusal has no repair")
			}
		})
	}
	if len(metadata.Codes) != refusals {
		t.Fatal("codes has extra or missing refusals")
	}
	beforePolicy := Replay(anchor, raw[:33])
	pi := publicOf(t, "witness-pi")
	witnesses := func(text string) bool {
		for _, line := range strings.Split(text, "\n") {
			parts := strings.Fields(line)
			if len(parts) >= 3 && parts[0] == "witness" {
				key, err := note.ParseVerifierKey(parts[2])
				if err != nil {
					t.Fatal(err)
				}
				if bytes.Equal(key.Public, pi) {
					return true
				}
			}
		}
		return false
	}
	e, err := entry.Decode(raw[33])
	if err != nil {
		t.Fatal(err)
	}
	text := e.Body["text"].(string)
	if !witnesses(beforePolicy.Policy) || witnesses(text) {
		t.Fatal("pi must move from witness to log only")
	}
	if _, err := policy.Parse(text); err != nil {
		t.Fatal(err)
	}
	publics := map[string]bool{}
	foundPi := false
	for _, line := range strings.Split(text, "\n") {
		parts := strings.Fields(line)
		if len(parts) == 0 || (parts[0] != "log" && parts[0] != "witness") {
			continue
		}
		keyText := parts[1]
		if parts[0] == "witness" {
			keyText = parts[2]
		}
		key, err := note.ParseVerifierKey(keyText)
		if err != nil {
			t.Fatal(err)
		}
		if publics[string(key.Public)] {
			t.Fatal("new policy repeats a public key")
		}
		publics[string(key.Public)] = true
		if parts[0] == "log" && bytes.Equal(key.Public, pi) {
			foundPi = true
		}
	}
	if !foundPi || final.Policy != text || final.Versions["policy"] != 33 {
		t.Fatal("replacement policy not stored")
	}
	for offset, key := range []string{"staleness", "checkpoint_interval", "mmd"} {
		i := 34 + offset
		e, err := entry.Decode(raw[i])
		if err != nil {
			t.Fatal(err)
		}
		st := Replay(anchor, raw[:i+1])
		prev := uint64(i - 1)
		if i == 34 {
			prev = 0
		}
		if len(e.Body) != 1 || e.Body[key] != uint64(0) || e.Prev == nil || *e.Prev != prev || st.Params[key] != uint64(0) || st.Versions["params"] != uint64(i) || st.Policy != text || final.Params[key] != uint64(0) {
			t.Fatalf("zero parameter %s or version not stored", key)
		}
	}
	got, err := final.MarshalCanonical()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, read(dir+"/state.json")) {
		t.Fatal("rule state differs from state.json")
	}
}
