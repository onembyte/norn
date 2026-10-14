package replay

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"testing"

	"github.com/onembyte/norn/internal/enrollreq"
	"github.com/onembyte/norn/internal/entry"
	"github.com/onembyte/norn/internal/note"
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
	}
	dir := vectorRoot() + "/log-order"
	anchor, raw, m := loadCase(t, dir)
	if len(raw) != 16 {
		t.Fatalf("got %d entries, want 16", len(raw))
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
					if e.T == "params" {
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
					e.Body["kid"] = entry.Kid(publicOf(t, "signer1"))
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
