package replay

import (
	"bytes"
	"crypto/sha512"
	"encoding/hex"
	"filippo.io/edwards25519"
	"github.com/onembyte/norn/internal/ed25519v1"
	"github.com/onembyte/norn/internal/note"
	"github.com/onembyte/norn/internal/policy"
	"os"
	"path/filepath"
	"testing"

	"github.com/onembyte/norn/internal/cbor"
	"github.com/onembyte/norn/internal/entry"
)

// These logs isolate key admission without changing the served fixture's state.
func TestTheAdmissionLogReplaysToItsManifestAndState(t *testing.T) {
	dir := filepath.Join(vectorRoot(), "log-admission")
	anchor, entries, m := loadCase(t, dir)
	if len(entries) != 9 {
		t.Fatalf("%d entries; want nine entries, including enrollment, two new refusals and a final honest policy", len(entries))
	}
	st := Replay(anchor, entries)
	reasons := map[int]string{}
	for _, r := range st.Rejected {
		reasons[int(r.Index)] = r.Reason
	}
	for _, e := range m.Entries {
		if reasons[e.Index] != e.Reason {
			t.Errorf("%s: got %q, want %q", e.Name, reasons[e.Index], e.Reason)
		}
	}
	if len(reasons) != 5 || len(st.Signers) != 3 {
		t.Errorf("want five refusals and three signers; got %+v", st)
	}
	want, err := os.ReadFile(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := st.MarshalCanonical()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("admission state differs from state.json: %s", got)
	}
	// The final honest policy makes stopping after a refusal observable.
	final, err := entry.Decode(entries[8])
	if err != nil {
		t.Fatal(err)
	}
	if st.Policy != final.Body["text"] {
		t.Error("final honest policy was not applied")
	}
	device := st.Devices["pi-cam"]
	if device.DevicePk != hex.EncodeToString(publicOf(t, "pi-cam")) || device.Status != "active" {
		t.Error("refused rotate changed the enrolled device")
	}
	// Governance entries still have the honest root quorum.
	for i := 1; i < len(entries); i++ {
		env, err := entry.Decode(entries[i])
		if err != nil {
			t.Fatal(err)
		}
		if env.T == "enroll" || env.T == "rotate" {
			continue
		}
		valid := 0
		for _, sig := range env.Sigs {
			if pk, ok := st.Roots[sig.Kid]; ok {
				public, err := hex.DecodeString(pk)
				if err != nil {
					t.Fatal(err)
				}
				verified, err := entry.Verify(env, sig, public)
				if err == nil && verified {
					valid++
				}
			}
		}
		if valid < 2 {
			t.Fatalf("entry %d has only %d valid root signatures", i, valid)
		}
	}
}

func TestTheEd25519GenesisEdgesAbortOnlyForTheirKeys(t *testing.T) {
	for _, name := range []string{"23-root-order-eight", "24-root-noncanonical"} {
		t.Run(name, func(t *testing.T) {
			anchor, raw, _ := loadCase(t, filepath.Join(vectorRoot(), "genesis", name))
			value, err := cbor.Decode(raw[0])
			if err != nil {
				t.Fatal(err)
			}
			env := value.(map[string]any)
			body := env["body"].(map[string]any)
			roots := body["roots"].([]any)
			if len(roots) != 4 {
				t.Fatalf("want three honest roots plus the edge key, got %d", len(roots))
			}
			decoded, err := entry.Decode(raw[0])
			if err != nil {
				t.Fatal(err)
			}
			valid := 0
			for _, sig := range decoded.Sigs {
				for _, root := range roots[:3] {
					pk := root.([]byte)
					verified, err := entry.Verify(decoded, sig, pk)
					if entry.Kid(pk) == sig.Kid && err == nil && verified {
						valid++
					}
				}
			}
			if valid != 2 {
				t.Fatalf("want two honest root signatures, got %d", valid)
			}
			st := Replay(anchor, raw)
			if st.Size != 0 || len(st.Rejected) != 1 || st.Rejected[0].Reason != ReasonBadGenesis {
				t.Fatalf("edge genesis admitted: %+v", st)
			}
		})
	}
}

// A mixed-order incoming key must separate the two equations, not merely forge.
func TestTheIncomingRotateKeyPassesOnlyTheCofactoredEquation(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(vectorRoot(), "log-admission", "06-rotate-mixed-order.cbor"))
	if err != nil {
		t.Fatal(err)
	}
	env, err := entry.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	public := env.Body["device_pk"].([]byte)
	if !bytes.Equal(public, notValidPoints(t, publicOf(t, "spare"))["mixed-order"]) {
		t.Fatal("incoming key is not the honest key plus the order-8 point")
	}
	message, err := entry.Preimage(env)
	if err != nil {
		t.Fatal(err)
	}
	var sig []byte
	currentVerified := false
	for _, candidate := range env.Sigs {
		if candidate.Kid == entry.Kid(public) {
			sig = candidate.Sig
		}
		if candidate.Kid == entry.Kid(publicOf(t, "pi-cam")) {
			currentVerified, err = entry.Verify(env, candidate, publicOf(t, "pi-cam"))
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	if !currentVerified || len(sig) != 64 {
		t.Fatal("rotate lacks current or incoming proof of possession")
	}
	a, err := new(edwards25519.Point).SetBytes(public)
	if err != nil {
		t.Fatal(err)
	}
	r, err := new(edwards25519.Point).SetBytes(sig[:32])
	if err != nil {
		t.Fatal(err)
	}
	scalar, err := edwards25519.NewScalar().SetCanonicalBytes(sig[32:])
	if err != nil {
		t.Fatal(err)
	}
	hash := sha512.New()
	hash.Write(sig[:32])
	hash.Write(public)
	hash.Write(message)
	k, err := edwards25519.NewScalar().SetUniformBytes(hash.Sum(nil))
	if err != nil {
		t.Fatal(err)
	}
	difference := new(edwards25519.Point).VarTimeDoubleScalarBaseMult(k, new(edwards25519.Point).Negate(a), scalar)
	difference.Subtract(difference, r)
	identity := edwards25519.NewIdentityPoint()
	if difference.Equal(identity) == 1 {
		t.Fatal("cofactorless equation holds; the vector no longer separates verifiers")
	}
	for i := 0; i < 3; i++ {
		difference.Add(difference, difference)
	}
	if difference.Equal(identity) != 1 {
		t.Fatal("cofactored equation fails; this is merely a forgery")
	}
	if ed25519v1.ValidPoint(public) || !ed25519v1.ValidPoint(sig[:32]) || ed25519v1.Verify(public, message, sig) {
		t.Fatal("incoming key must fail §3.1 item 1, with an honest R and canonical S")
	}
}

// The witness key has an honestly computed id and the correct algorithm.
func TestThePolicyAdmissionVectorFailsOnlyForItsSmallOrderWitness(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(vectorRoot(), "log-admission", "07-policy-small-order.cbor"))
	if err != nil {
		t.Fatal(err)
	}
	env, err := entry.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	small := notValidPoints(t, publicOf(t, "spare"))["small-order"]
	key := note.VerifierKeyFor("norn-witness/pi", small, note.AlgCosignature)
	text := "witness pi " + key + "\nquorum pi\n"
	if env.Body["text"] != text {
		t.Fatal("policy vector differs from a well-formed small-order witness policy")
	}
	if _, err := note.ParseVerifierKey(key); err != nil {
		t.Fatal(err)
	}
	if _, err := policy.Parse(text); err == nil {
		t.Fatal("small-order witness was admitted")
	}
	repaired := "witness pi " + note.VerifierKeyFor("norn-witness/pi", publicOf(t, "witness-pi"), note.AlgCosignature) + "\nquorum pi\n"
	if _, err := policy.Parse(repaired); err != nil {
		t.Fatalf("honest replacement: %v", err)
	}
}
