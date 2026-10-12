package replay

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"strings"
	"testing"

	"github.com/onembyte/norn/internal/enrollreq"
	"github.com/onembyte/norn/internal/entry"
	"github.com/onembyte/norn/internal/note"
	"github.com/onembyte/norn/internal/state"
)

func casSetup(t *testing.T, typ string) (*state.State, *entry.Envelope, *replayer) {
	t.Helper()
	st := state.New(make([]byte, 16))
	st.Versions = map[string]uint64{"signers": 3, "roots": 3, "params": 3, "policy": 3, "log_key": 3}
	root := privateKey(t, "root1")
	signer := privateKey(t, "signer1")
	device := privateKey(t, "nas")
	st.Roots[entry.Kid(root.Public().(ed25519.PublicKey))] = hexOf(root.Public().(ed25519.PublicKey))
	st.Signers[entry.Kid(signer.Public().(ed25519.PublicKey))] = hexOf(signer.Public().(ed25519.PublicKey))
	st.RootThr, st.SignerThr = 1, 1
	st.Devices["nas"] = state.Device{DevicePk: hexOf(device.Public().(ed25519.PublicKey)), WgPk: hexOf(bytes.Repeat([]byte{2}, 32)), Status: state.StatusActive, Version: 3, Labels: map[string]string{}}
	st.ActiveWg[st.Devices["nas"].WgPk] = "nas"
	n := uint64(3)
	e := &entry.Envelope{V: 1, T: typ, Net: st.Net, TS: 10, Prev: &n, Body: map[string]any{}}
	switch typ {
	case "enroll":
		req := &enrollreq.Request{V: 1, Net: st.Net, DeviceID: "nas", DevicePK: device.Public().(ed25519.PublicKey), WGPK: bytes.Repeat([]byte{4}, 32), TS: 1}
		if err := enrollreq.Sign(req, device); err != nil {
			t.Fatal(err)
		}
		raw, err := enrollreq.Encode(req)
		if err != nil {
			t.Fatal(err)
		}
		e.Body["request"] = raw
		d := st.Devices["nas"]
		d.Status = state.StatusRevoked
		st.Devices["nas"] = d
		delete(st.ActiveWg, d.WgPk)
	case "rotate":
		e.Body = map[string]any{"device_id": "nas", "wg_pk": bytes.Repeat([]byte{4}, 32)}
	case "revoke":
		e.Body = map[string]any{"device_id": "nas"}
	case "signer_add", "root_add":
		e.Body["pk"] = publicOf(t, "root2")
	case "signer_remove":
		e.Body["kid"] = entry.Kid(signer.Public().(ed25519.PublicKey))
	case "root_remove":
		st.Roots[entry.Kid(publicOf(t, "root2"))] = hexOf(publicOf(t, "root2"))
		e.Body["kid"] = entry.Kid(publicOf(t, "root2"))
	case "root_thr", "signer_thr":
		e.Body["thr"] = uint64(1)
	case "params":
		e.Body["mmd"] = uint64(23)
	case "policy":
		e.Body["text"] = "quorum none\n"
	case "log_key":
		e.Body = map[string]any{"pk": publicOf(t, "root2"), "overlap": uint64(60)}
	case "note":
		e.Body["text"] = "x"
	}
	signCAS(t, e, root, signer, device)
	return st, e, &replayer{verify: realVerify, seen: map[string]bool{}}
}

func signCAS(t *testing.T, e *entry.Envelope, keys ...ed25519.PrivateKey) {
	t.Helper()
	e.Sigs = nil
	for i, k := range keys {
		if err := entry.Sign(e, k, []string{"root", "signer", "device"}[i]); err != nil {
			t.Fatal(err)
		}
	}
}

func TestEveryStateChangingHandlerChecksPresenceAndStalenessAndAdvancesOnlyOnAcceptance(t *testing.T) {
	for _, typ := range []string{"enroll", "rotate", "revoke", "signer_add", "root_add", "signer_remove", "root_remove", "signer_thr", "root_thr", "params", "policy", "log_key"} {
		t.Run(typ, func(t *testing.T) {
			for _, prev := range []*uint64{nil, new(uint64)} {
				st, e, r := casSetup(t, typ)
				e.Prev = prev
				signCAS(t, e, privateKey(t, "root1"), privateKey(t, "signer1"), privateKey(t, "nas"))
				before, _ := st.MarshalCanonical()
				err := handlers[typ](r, st, e, 9)
				code, _ := reasonOf(err)
				if code != ReasonStaleState {
					t.Errorf("prev %v: got %q, want stale-state", prev, code)
				}
				after, _ := st.MarshalCanonical()
				if !bytes.Equal(before, after) {
					t.Error("rejection changed state")
				}
			}
			st, e, r := casSetup(t, typ)
			if err := handlers[typ](r, st, e, 9); err != nil {
				t.Fatal(err)
			}
			object := typ
			switch typ {
			case "enroll", "rotate", "revoke":
				if st.Devices["nas"].Version != 9 {
					t.Error("device version did not advance")
				}
				return
			case "signer_add", "signer_remove", "signer_thr":
				object = "signers"
			case "root_add", "root_remove", "root_thr":
				object = "roots"
			}
			if st.Versions[object] != 9 {
				t.Error("object version did not advance")
			}
		})
	}
}

func TestEnrollPresenceTracksRevokedRecordsAndNoteRejectsPrev(t *testing.T) {
	st, e, r := casSetup(t, "enroll")
	delete(st.Devices, "nas")
	if err := hEnroll(r, st, e, 9); err == nil {
		t.Error("never-named enroll carrying prev accepted")
	}
	e.Prev = nil
	signCAS(t, e, privateKey(t, "root1"), privateKey(t, "signer1"), privateKey(t, "nas"))
	if err := hEnroll(r, st, e, 9); err != nil {
		t.Fatal(err)
	}
	st, e, r = casSetup(t, "note")
	if err := hNote(r, st, e, 9); err == nil {
		t.Error("note carrying prev accepted")
	}
}

func TestLogAndWitnessInvariantComparesPublicKeysInBothDirections(t *testing.T) {
	for _, source := range []string{"anchor", "learned"} {
		t.Run(source, func(t *testing.T) {
			st, e, r := casSetup(t, "policy")
			pk := publicOf(t, "root2")
			r.anchor.LogKey = note.VerifierKey("log", pk)
			if source == "learned" {
				r.anchor.LogKey = note.VerifierKey("log", publicOf(t, "root3"))
				st.LogKeys = []state.LogKey{{Pk: hexOf(pk)}}
			}
			e.Body["text"] = "witness w " + note.CosignerVerifierKey("different-name", pk) + "\nquorum w\n"
			err := hPolicy(r, st, e, 9)
			code, _ := reasonOf(err)
			if code != ReasonDupKey {
				t.Errorf("policy: got %q, want dup-key", code)
			}
			e.Body["text"] = "quorum none\n"
			if err := hPolicy(r, st, e, 9); err != nil {
				t.Fatal(err)
			}
			st, e, r = casSetup(t, "log_key")
			text := "witness w " + note.CosignerVerifierKey("different-name", pk) + "\nquorum w\n"
			r.anchor.Policy = text
			if source == "learned" {
				st.Policy = text
				r.anchor.Policy = "quorum none\n"
			}
			err = hLogKey(r, st, e, 9)
			code, _ = reasonOf(err)
			if code != ReasonDupKey {
				t.Errorf("log_key: got %q, want dup-key", code)
			}
			e.Body["pk"] = publicOf(t, "root3")
			if err := hLogKey(r, st, e, 9); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRotateNeedsOneSignaturePerDistinctDeviceKey(t *testing.T) {
	st, e, r := casSetup(t, "rotate")
	e.Body["device_pk"] = publicOf(t, "nas")
	e.Sigs = nil
	if err := entry.Sign(e, privateKey(t, "nas"), "device"); err != nil {
		t.Fatal(err)
	}
	if err := hRotate(r, st, e, 9); err != nil {
		t.Fatal(err)
	}
	if st.Devices["nas"].WgPk != hexOf(e.Body["wg_pk"].([]byte)) {
		t.Error("wireguard key did not change")
	}
}

func TestGenesisWithPrevAbortsEvenWhenItsHashAndSignatureMatch(t *testing.T) {
	anchor, items, _ := loadCase(t, vectorRoot()+"/log")
	env, err := entry.Decode(items[0])
	if err != nil {
		t.Fatal(err)
	}
	n := uint64(0)
	env.Prev = &n
	env.Sigs = nil
	for _, name := range []string{"root1", "root2"} {
		if err := entry.Sign(env, privateKey(t, name), "root"); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := entry.Encode(env)
	if err != nil {
		t.Fatal(err)
	}
	anchor.GenesisHash = entry.LeafHash(raw)
	st := Replay(anchor, [][]byte{raw})
	if st.Size != 0 || len(st.Rejected) != 1 || st.Rejected[0].Reason != ReasonBadGenesis {
		t.Fatalf("genesis with prev accepted: %+v", st)
	}
}

func TestTheCASLogReplaysToItsManifestAndState(t *testing.T) {
	t.Run("log-edges", checkEdgeLog)
	dir := vectorRoot() + "/log-cas"
	anchor, items, m := loadCase(t, dir)
	st := Replay(anchor, items)
	for _, e := range m.Entries {
		if got := lastOutcome(st, e.Index); got != e.Reason {
			t.Errorf("%s: got %q, want %q", e.Name, got, e.Reason)
		}
	}
	want, err := os.ReadFile(dir + "/state.json")
	if err != nil {
		t.Fatal(err)
	}
	got, err := st.MarshalCanonical()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Error("CAS state differs from state.json")
	}
	final := st.Devices["nas"]
	if final.Version != 32 || final.DevicePk != hexOf(publicOf(t, "nas")) {
		t.Errorf("same-key rotate was not accepted: %+v", final)
	}
}

func TestEveryCASNegativeAcceptsAfterItsFaultsAreRepaired(t *testing.T) {
	anchor, items, m := loadCase(t, vectorRoot()+"/log-cas")
	for _, it := range m.Entries {
		if it.Reason == "" {
			continue
		}
		t.Run(it.Name, func(t *testing.T) {
			before := Replay(anchor, items[:it.Index])
			e, err := entry.Decode(items[it.Index])
			if err != nil {
				t.Fatal(err)
			}
			id, _ := e.Body["device_id"].(string)
			if e.T == "enroll" {
				req, err := enrollreq.Decode(e.Body["request"].([]byte))
				if err != nil {
					t.Fatal(err)
				}
				id = req.DeviceID
			}
			e.Prev = before.Previous(e.T, id)
			switch it.Reason {
			case ReasonDupKey:
				if e.T == "log_key" {
					e.Body["pk"] = publicOf(t, "stranger")
				} else {
					e.Body["text"] = "witness w " + note.CosignerVerifierKey("repaired", publicOf(t, "stranger")) + "\nquorum w\n"
				}
			}
			if strings.Contains(it.Name, "stale-before-dup-key") {
				e.Body["pk"] = publicOf(t, "root4")
			}
			if strings.Contains(it.Name, "stale-before-dup-wg") {
				e.Body["wg_pk"] = bytes.Repeat([]byte{4}, 32)
			}
			e.Sigs = nil
			if e.T == "enroll" || e.T == "revoke" || e.T == "note" {
				if err := entry.Sign(e, privateKey(t, "signer1"), "signer"); err != nil {
					t.Fatal(err)
				}
			} else if e.T == "rotate" {
				if err := entry.Sign(e, privateKey(t, "nas"), "device"); err != nil {
					t.Fatal(err)
				}
				if _, ok := e.Body["device_pk"]; ok {
					if err := entry.Sign(e, privateKey(t, "spare"), "device"); err != nil {
						t.Fatal(err)
					}
				}
			} else {
				for _, name := range []string{"root1", "root2"} {
					if err := entry.Sign(e, privateKey(t, name), "root"); err != nil {
						t.Fatal(err)
					}
				}
			}
			after := Replay(anchor, appended(t, items[:it.Index], e))
			if got := lastOutcome(after, it.Index); got != "" {
				t.Fatalf("repaired entry rejected %s", got)
			}
		})
	}
}

// Each precedence case has two faults. Repair either alone to expose the other,
// then the preceding test repairs both and observes acceptance.
func TestCASPrecedenceCasesExposeBothFaultsSeparately(t *testing.T) {
	anchor, items, m := loadCase(t, vectorRoot()+"/log-cas")
	second := map[string]string{"25-threshold-before-stale": ReasonThreshold, "28-current-signature-before-stale": ReasonNoDeviceSig, "29-stale-before-incoming-proof": ReasonNoDeviceSig, "30-stale-before-dup-key": ReasonDupKey, "31-stale-before-dup-wg": ReasonDupWg}
	resign := func(e *entry.Envelope) {
		signatures := e.Sigs
		e.Sigs = nil
		for _, s := range signatures {
			for _, name := range []string{"root1", "root2", "signer1", "nas", "spare"} {
				k := privateKey(t, name)
				if entry.Kid(k.Public().(ed25519.PublicKey)) == s.Kid {
					if err := entry.Sign(e, k, s.Role); err != nil {
						t.Fatal(err)
					}
					break
				}
			}
		}
	}
	for _, it := range m.Entries {
		want, ok := second[it.Name]
		if !ok {
			continue
		}
		t.Run(it.Name, func(t *testing.T) {
			before := Replay(anchor, items[:it.Index])
			e, err := entry.Decode(items[it.Index])
			if err != nil {
				t.Fatal(err)
			}
			id, _ := e.Body["device_id"].(string)
			e.Prev = before.Previous(e.T, id)
			resign(e)
			if got := lastOutcome(Replay(anchor, appended(t, items[:it.Index], e)), it.Index); got != want {
				t.Fatalf("repairing prev: got %q, want %q", got, want)
			}
			e, err = entry.Decode(items[it.Index])
			if err != nil {
				t.Fatal(err)
			}
			switch it.Name {
			case "25-threshold-before-stale":
				err = entry.Sign(e, privateKey(t, "root2"), "root")
			case "28-current-signature-before-stale":
				err = entry.Sign(e, privateKey(t, "nas"), "device")
			case "29-stale-before-incoming-proof":
				err = entry.Sign(e, privateKey(t, "spare"), "device")
			case "30-stale-before-dup-key":
				e.Body["pk"] = publicOf(t, "root4")
				resign(e)
			case "31-stale-before-dup-wg":
				e.Body["wg_pk"] = bytes.Repeat([]byte{4}, 32)
				resign(e)
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := lastOutcome(Replay(anchor, appended(t, items[:it.Index], e)), it.Index); got != ReasonStaleState {
				t.Fatalf("repairing other fault: got %q, want stale-state", got)
			}
		})
	}
}
