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

// The expected answers come from §5.1, independently of the manifest. Each
// paired fault is repaired separately and together against the shipped prefix.
func TestEveryOrderCaseMatchesAndExposesOnlyItsNamedFaults(t *testing.T) {
	cases := map[string][2]string{
		"02-rotate-incoming-only":                  {ReasonNoDeviceSig, ""},
		"04-rotate-threshold-before-prev":          {ReasonThreshold, ReasonStaleState},
		"05-enroll-threshold-before-prev":          {ReasonThreshold, ReasonStaleState},
		"06-enroll-prev-before-dup-id":             {ReasonStaleState, ReasonDupID},
		"07-revoke-threshold-before-prev":          {ReasonThreshold, ReasonStaleState},
		"08-signer-add-after-before-threshold":     {ReasonAfter, ReasonThreshold},
		"09-params-body-before-prev":               {ReasonDecode, ReasonStaleState},
		"10-policy-parse-before-prev":              {ReasonDecode, ReasonStaleState},
		"11-policy-prev-before-dup-key":            {ReasonStaleState, ReasonDupKey},
		"12-signer-remove-prev-before-unknown-key": {ReasonStaleState, ReasonUnknownKey},
		"13-signer-thr-prev-before-bad-thr":        {ReasonStaleState, ReasonBadThr},
		"14-log-key-prev-before-dup-key":           {ReasonStaleState, ReasonDupKey},
		"15-policy-log-identity":                   {ReasonDecode, ""},
		"16-signer-add-body-before-prev":           {ReasonDecode, ReasonStaleState},
		"17-root-add-body-before-prev":             {ReasonDecode, ReasonStaleState},
		"18-signer-remove-body-before-prev":        {ReasonDecode, ReasonStaleState},
		"19-root-remove-body-before-prev":          {ReasonDecode, ReasonStaleState},
		"20-signer-thr-body-before-prev":           {ReasonDecode, ReasonStaleState},
		"21-root-thr-body-before-prev":             {ReasonDecode, ReasonStaleState},
		"22-log-key-fields-before-prev":            {ReasonDecode, ReasonStaleState},
		"23-root-remove-prev-before-unknown-key":   {ReasonStaleState, ReasonUnknownKey},
		"24-enroll-body-before-request-signature":  {ReasonDecode, ReasonNoDeviceSig},
		"25-enroll-body-before-threshold":          {ReasonDecode, ReasonThreshold},
		"26-enroll-body-before-prev":               {ReasonDecode, ReasonStaleState},
		"27-enroll-body-before-dup-id":             {ReasonDecode, ReasonDupID},
		"28-enroll-body-before-dup-wg":             {ReasonDecode, ReasonDupWg},
		"29-log-key-body-before-prev":              {ReasonDecode, ReasonStaleState},
		"30-log-key-body-before-witness-key":       {ReasonDecode, ReasonDupKey},
		"31-log-key-body-before-active-log-key":    {ReasonDecode, ReasonDupKey},
		"32-policy-body-before-prev":               {ReasonDecode, ReasonStaleState},
		"33-policy-body-before-dup-key":            {ReasonDecode, ReasonDupKey},
		"34-policy-cap-before-prev":                {ReasonDecode, ReasonStaleState},
		"35-policy-cap-before-dup-key":             {ReasonDecode, ReasonDupKey},
		"36-revoke-body-before-not-active":         {ReasonDecode, ReasonNotActive},
		"37-rotate-body-before-not-active":         {ReasonDecode, ReasonNotActive},
		"38-envelope-invalid-note":                 {ReasonDecode, ""},
		"40-log-key-point-before-prev":             {ReasonDecode, ReasonStaleState},
		"41-log-key-point-repaired-stale-prev":     {ReasonStaleState, ""},
		"39-byte-copy-before-envelope":             {ReasonDupEntry, ""},
	}
	dir := vectorRoot() + "/log-order"
	anchor, raw, m := loadCase(t, dir)
	if len(raw) != 44 {
		t.Fatalf("got %d entries, want 44", len(raw))
	}
	metadataBytes, err := os.ReadFile(dir + "/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	var metadata struct {
		Codes map[string]string
		Rules map[string]struct{ Section, Says string }
	}
	if err := json.Unmarshal(metadataBytes, &metadata); err != nil {
		t.Fatal(err)
	}
	if len(metadata.Codes) != len(cases) || len(metadata.Rules) != len(cases) {
		t.Fatal("order codes or rules incomplete")
	}
	specBytes, err := os.ReadFile("../../SPEC.md")
	if err != nil {
		t.Fatal(err)
	}
	for name, codes := range cases {
		rule := metadata.Rules[name]
		heading := "### "
		if !strings.Contains(rule.Section, ".") {
			heading = "## "
		}
		_, section, found := strings.Cut(string(specBytes), heading+rule.Section+" ")
		section, _, _ = strings.Cut(section, "\n##")
		onLine := false
		for _, line := range strings.Split(section, "\n") {
			onLine = onLine || strings.Contains(line, rule.Says)
		}
		if metadata.Codes[name] != codes[0] || !found || rule.Says == "" || !onLine {
			t.Fatalf("%s has wrong code or raw SPEC citation", name)
		}
	}
	final := Replay(anchor, raw)
	want, err := os.ReadFile(dir + "/state.json")
	if err != nil {
		t.Fatal(err)
	}
	got, err := final.MarshalCanonical()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Error("order state differs from state.json")
	}
	negatives := 0
	for _, it := range m.Entries {
		t.Run(it.Name, func(t *testing.T) {
			got := lastOutcome(final, it.Index)
			t.Logf("Go outcome = %q", got)
			if got != it.Reason {
				t.Fatalf("got %q, want %q", got, it.Reason)
			}
			if it.Reason == "" {
				return
			}
			negatives++
			codes, ok := cases[it.Name]
			if !ok || codes[0] != it.Reason {
				t.Fatal("manifest differs from the stated answer")
			}
			reason, err := os.ReadFile(dir + "/" + it.Name + ".reason")
			if err != nil || string(reason) != codes[0]+"\n" {
				t.Fatal("reason file differs")
			}
			if it.Name >= "40-" {
				checkRunTwentyOrder(t, anchor, raw, it.Index)
				return
			}
			if it.Name >= "24-" {
				checkRunNineteenOrder(t, anchor, raw, it.Index, it.Name, codes)
				return
			}
			before := Replay(anchor, raw[:it.Index])
			decode := func() *entry.Envelope {
				e, err := entry.Decode(raw[it.Index])
				if err != nil {
					t.Fatal(err)
				}
				return e
			}
			previous := func(e *entry.Envelope) {
				id, _ := e.Body["device_id"].(string)
				if e.T == "enroll" {
					req, err := enrollreq.Decode(e.Body["request"].([]byte))
					if err != nil {
						t.Fatal(err)
					}
					id = req.DeviceID
				}
				e.Prev = before.Previous(e.T, id)
			}
			sign := func(e *entry.Envelope, key, role string) {
				if err := entry.Sign(e, privateKey(t, key), role); err != nil {
					t.Fatal(err)
				}
			}
			repair := func(e *entry.Envelope, fault string) {
				switch fault {
				case ReasonStaleState:
					previous(e)
				case ReasonThreshold:
					if e.T == "signer_add" {
						sign(e, "root1", "root")
						sign(e, "root2", "root")
					} else {
						sign(e, "signer1", "signer")
					}
				case ReasonAfter:
					n := uint64(it.Index)
					e.After = &n
				case ReasonNoDeviceSig:
					sign(e, "nas", "device")
				case ReasonDecode:
					if e.T == "signer_add" {
						e.Body["pk"] = publicOf(t, "signer3")
					} else if e.T == "root_add" {
						e.Body["pk"] = publicOf(t, "spare")
					} else if e.T == "signer_remove" {
						e.Body["kid"] = entry.Kid(publicOf(t, "signer1"))
					} else if e.T == "root_remove" {
						e.Body["kid"] = entry.Kid(publicOf(t, "root3"))
					} else if e.T == "signer_thr" || e.T == "root_thr" {
						e.Body["thr"] = uint64(1)
					} else if e.T == "log_key" {
						e.Body["pk"] = publicOf(t, "logkey2")
					} else if e.T == "params" {
						e.Body = map[string]any{"mmd": uint64(46)}
					} else if it.Name == "15-policy-log-identity" {
						e.Body["text"] = "log " + note.VerifierKey("norn-log", publicOf(t, "logkey")) + "\nquorum none\n"
					} else {
						e.Body["text"] = "quorum none\n"
					}
				case ReasonDupID:
					req, err := enrollreq.Decode(e.Body["request"].([]byte))
					if err != nil {
						t.Fatal(err)
					}
					req.DeviceID = "spare"
					if err := enrollreq.Sign(req, privateKey(t, "nas")); err != nil {
						t.Fatal(err)
					}
					encoded, err := enrollreq.Encode(req)
					if err != nil {
						t.Fatal(err)
					}
					e.Body["request"] = encoded
					// A repaired predecessor moves to the new id's domain;
					// the deliberately stale predecessor remains stale.
					if e.Prev != nil && *e.Prev == before.Devices["nas"].Version {
						previous(e)
					}
				case ReasonDupKey:
					if e.T == "policy" {
						e.Body["text"] = "quorum none\n"
					} else {
						e.Body["pk"] = publicOf(t, "logkey2")
					}
				case ReasonUnknownKey:
					key := "signer1"
					if e.T == "root_remove" {
						key = "root3"
					}
					e.Body["kid"] = entry.Kid(publicOf(t, key))
				case ReasonBadThr:
					e.Body["thr"] = uint64(1)
				default:
					t.Fatal("missing repair " + fault)
				}
			}
			check := func(e *entry.Envelope, want string) {
				signatures := e.Sigs
				e.Sigs = nil
				for _, sig := range signatures {
					found := false
					for _, name := range []string{"nas", "spare", "signer1", "root1", "root2"} {
						if entry.Kid(privateKey(t, name).Public().(ed25519.PublicKey)) == sig.Kid {
							sign(e, name, sig.Role)
							found = true
							break
						}
					}
					if !found {
						t.Fatal("unknown fixture signature")
					}
				}
				result := Replay(anchor, appended(t, raw[:it.Index], e))
				if got := lastOutcome(result, it.Index); got != want {
					t.Fatalf("repair: got %q, want %q", got, want)
				}
				t.Logf("repair outcome = %q", want)
				if want != "" {
					result.Size, result.Rejected = before.Size, before.Rejected
					got, err := result.MarshalCanonical()
					if err != nil {
						t.Fatal(err)
					}
					want, err := before.MarshalCanonical()
					if err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(got, want) {
						t.Error("rejection changed state")
					}
				}
			}
			check(decode(), codes[0])
			e := decode()
			repair(e, codes[0])
			check(e, codes[1])
			if codes[1] != "" {
				repair(e, codes[1])
				check(e, "")
				e = decode()
				repair(e, codes[1])
				check(e, codes[0])
			}
		})
	}
	if negatives != len(cases) {
		t.Fatalf("got %d refusals, want %d", negatives, len(cases))
	}
}

// The new pairs isolate closedness, the text cap and refused-byte ordering.
func checkRunNineteenOrder(t *testing.T, anchor Anchor, raw [][]byte, i int, name string, codes [2]string) {
	t.Helper()
	before := Replay(anchor, raw[:i])
	decode := func() map[string]any {
		value, err := cbor.Decode(raw[i])
		if err != nil {
			t.Fatal(err)
		}
		return value.(map[string]any)
	}
	check := func(env map[string]any, want string) {
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
		keys, role := []string{"signer1", "nas"}, "signer"
		if e.T == "policy" || e.T == "log_key" {
			keys, role = []string{"root1", "root2"}, "root"
		}
		if strings.HasPrefix(name, "25-") && want != "" {
			keys = nil
		}
		for _, key := range keys {
			r := role
			if key == "nas" {
				r = "device"
			}
			if err := entry.Sign(e, privateKey(t, key), r); err != nil {
				t.Fatal(err)
			}
		}
		result := Replay(anchor, appended(t, raw[:i], e))
		if got := lastOutcome(result, i); got != want {
			t.Fatalf("%s repair = %q, want %q", name, got, want)
		}
		t.Logf("repair outcome = %q", want)
		if want != "" {
			result.Size, result.Rejected = before.Size, before.Rejected
			got, err := result.MarshalCanonical()
			if err != nil {
				t.Fatal(err)
			}
			expected, err := before.MarshalCanonical()
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, expected) {
				t.Fatal("refusal changed state")
			}
		}
	}
	if strings.HasPrefix(name, "38-") || strings.HasPrefix(name, "39-") {
		predecessor := i
		if strings.HasPrefix(name, "39-") {
			predecessor--
		}
		if !bytes.Equal(raw[predecessor], raw[predecessor+1]) || decode()["v"] != uint64(2) {
			t.Fatal("expected exact copy of a decodable v2 envelope")
		}
		if lastOutcome(Replay(anchor, raw[:predecessor+1]), predecessor) != ReasonDecode || lastOutcome(Replay(anchor, raw[:predecessor+2]), predecessor+1) != ReasonDupEntry {
			t.Fatal("byte copy must precede envelope validation")
		}
		env := decode()
		env["v"] = uint64(1)
		check(env, "")
		return
	}
	original := decode()
	body := original["body"].(map[string]any)
	if original["after"] != uint64(i) {
		t.Fatal("case must be rebuilt at its own prefix")
	}
	if strings.Contains(name, "cap-before") {
		text := body["text"].(string)
		if len(text) != 4097 {
			t.Fatal("expected 4097-byte text")
		}
		if _, err := policy.Parse(text); err != nil {
			t.Fatal(err)
		}
	} else if _, ok := body["x"]; !ok {
		t.Fatal("missing isolated extra body key")
	}
	kind := original["t"].(string)
	if kind == "rotate" || kind == "revoke" {
		if before.Devices[body["device_id"].(string)].Status != "revoked" {
			t.Fatal("target must be known and revoked")
		}
	}
	repairFirst := func(env map[string]any) {
		body := env["body"].(map[string]any)
		if strings.Contains(name, "cap-before") {
			text := body["text"].(string)
			if !strings.HasSuffix(text, "x\n") {
				t.Fatal("expected comment padding")
			}
			body["text"] = text[:len(text)-2] + "\n"
		} else {
			delete(body, "x")
		}
	}
	repairSecond := func(env map[string]any) {
		body := env["body"].(map[string]any)
		switch codes[1] {
		case ReasonStaleState:
			id, _ := body["device_id"].(string)
			if kind == "enroll" {
				req, err := enrollreq.Decode(body["request"].([]byte))
				if err != nil {
					t.Fatal(err)
				}
				id = req.DeviceID
			}
			delete(env, "prev")
			if prev := before.Previous(kind, id); prev != nil {
				env["prev"] = *prev
			}
		case ReasonThreshold:
			// The final check signs the repaired threshold case with signer1.
		case ReasonNoDeviceSig, ReasonDupID, ReasonDupWg:
			req, err := enrollreq.Decode(body["request"].([]byte))
			if err != nil {
				t.Fatal(err)
			}
			if codes[1] == ReasonDupID {
				req.DeviceID = "order-repair"
				delete(env, "prev")
			}
			if codes[1] == ReasonDupWg {
				req.WGPK = bytes.Repeat([]byte{0x5a}, 32)
			}
			key := "spare"
			if bytes.Equal(req.DevicePK, publicOf(t, "nas")) {
				key = "nas"
			}
			if bytes.Equal(req.DevicePK, publicOf(t, "laptop")) {
				key = "laptop"
			}
			if err := enrollreq.Sign(req, privateKey(t, key)); err != nil {
				t.Fatal(err)
			}
			body["request"], err = enrollreq.Encode(req)
			if err != nil {
				t.Fatal(err)
			}
		case ReasonDupKey:
			if kind == "log_key" {
				body["pk"] = publicOf(t, "logkey2")
			} else {
				old := note.CosignerVerifierKey("order-witness", publicOf(t, "logkey"))
				text := body["text"].(string)
				if !strings.Contains(text, old) {
					t.Fatal("missing conflicting witness key")
				}
				body["text"] = strings.Replace(text, old, note.CosignerVerifierKey("order-witness", publicOf(t, "spare")), 1)
			}
		case ReasonNotActive:
			body["device_id"] = "nas"
			env["prev"] = before.Devices["nas"].Version
		default:
			t.Fatal("missing second repair")
		}
	}
	env := decode()
	repairFirst(env)
	check(env, codes[1])
	repairSecond(env)
	check(env, "")
	env = decode()
	repairSecond(env)
	if codes[1] == ReasonThreshold {
		// Closedness still precedes a now-sufficient signer count.
		encoded, err := cbor.Encode(env)
		if err != nil {
			t.Fatal(err)
		}
		e, err := entry.Decode(encoded)
		if err != nil {
			t.Fatal(err)
		}
		if err := entry.Sign(e, privateKey(t, "signer1"), "signer"); err != nil {
			t.Fatal(err)
		}
		if lastOutcome(Replay(anchor, appended(t, raw[:i], e)), i) != codes[0] {
			t.Fatal("second-only repair changed the first fault")
		}
	} else {
		check(env, codes[0])
	}
}
