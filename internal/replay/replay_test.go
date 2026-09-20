package replay

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/onembyte/norn/internal/entry"
)

// Written from SPEC.md §5. The manifest is the oracle: every (index, reason)
// must match, and the resulting state must equal state.json byte for byte.

type manifest struct {
	Anchor struct {
		Net         string `json:"net"`
		GenesisHash string `json:"genesis_hash"`
	} `json:"anchor"`
	Entries []struct {
		Index  int    `json:"index"`
		Name   string `json:"name"`
		Reason string `json:"reason"`
	} `json:"entries"`
}

func vectorRoot() string { return filepath.Join("..", "..", "testdata", "vectors") }

func loadCase(t *testing.T, dir string) (Anchor, [][]byte, manifest) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	net, err := hex.DecodeString(m.Anchor.Net)
	if err != nil {
		t.Fatal(err)
	}
	genesis, err := hex.DecodeString(m.Anchor.GenesisHash)
	if err != nil {
		t.Fatal(err)
	}
	entries := make([][]byte, 0, len(m.Entries))
	for _, e := range m.Entries {
		b, err := os.ReadFile(filepath.Join(dir, e.Name+".cbor"))
		if err != nil {
			t.Fatal(err)
		}
		entries = append(entries, b)
	}
	return Anchor{Net: net, GenesisHash: genesis}, entries, m
}

func TestEveryOutcomeInTheLogManifestMatches(t *testing.T) {
	dir := filepath.Join(vectorRoot(), "log")
	anchor, entries, m := loadCase(t, dir)
	st := Replay(anchor, entries)

	got := map[int]string{}
	for _, r := range st.Rejected {
		got[int(r.Index)] = r.Reason
	}
	for _, e := range m.Entries {
		want := e.Reason
		if got[e.Index] != want {
			t.Errorf("entry %d (%s): got reason %q, want %q",
				e.Index, e.Name, got[e.Index], want)
		}
	}
	if len(got) != countRejections(m) {
		t.Errorf("produced %d rejections, the manifest expects %d", len(got), countRejections(m))
	}
	if int(st.Size) != len(entries) {
		t.Errorf("size = %d, want %d", st.Size, len(entries))
	}
}

func countRejections(m manifest) int {
	var n int
	for _, e := range m.Entries {
		if e.Reason != "" {
			n++
		}
	}
	return n
}

func TestReplayedStateEqualsStateJSONByteForByte(t *testing.T) {
	anchor, entries, _ := loadCase(t, filepath.Join(vectorRoot(), "log"))
	st := Replay(anchor, entries)
	got, err := st.MarshalCanonical()
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(filepath.Join(vectorRoot(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("replayed state differs from state.json (%d vs %d bytes)", len(got), len(want))
		for i := 0; i < len(got) && i < len(want); i++ {
			if got[i] != want[i] {
				lo := max(0, i-60)
				t.Errorf("first difference at byte %d\n got: %s\nwant: %s",
					i, got[lo:min(len(got), i+60)], want[lo:min(len(want), i+60)])
				break
			}
		}
	}
}

func TestEveryGenesisCaseAbortsAndMatchesItsState(t *testing.T) {
	dirs, err := filepath.Glob(filepath.Join(vectorRoot(), "genesis", "*"))
	if err != nil {
		t.Fatal(err)
	}
	var checked int
	for _, dir := range dirs {
		info, err := os.Stat(dir)
		if err != nil || !info.IsDir() {
			continue
		}
		anchor, entries, _ := loadCase(t, dir)
		st := Replay(anchor, entries)
		if len(st.Rejected) != 1 || st.Rejected[0].Reason != "bad-genesis" {
			t.Errorf("%s: expected exactly one bad-genesis rejection, got %+v", dir, st.Rejected)
			continue
		}
		if st.Size != 0 {
			t.Errorf("%s: an aborted replay has size 0, got %d", dir, st.Size)
		}
		got, err := st.MarshalCanonical()
		if err != nil {
			t.Fatal(err)
		}
		want, err := os.ReadFile(filepath.Join(dir, "state.json"))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s: state differs from its state.json", dir)
		}
		checked++
	}
	if checked < 12 {
		t.Errorf("only %d genesis cases checked, expected at least 12", checked)
	}
}

// The guarantee D-043 exists for: verification must be load-bearing.
func TestASignatureBlindReplayDoesNotReproduceTheManifest(t *testing.T) {
	anchor, entries, m := loadCase(t, filepath.Join(vectorRoot(), "log"))
	honest := Replay(anchor, entries)
	blind := replayWith(anchor, entries, func(pk, msg, sig []byte) bool { return true })

	if len(blind.Rejected) == len(honest.Rejected) {
		t.Fatal("stubbing signature verification changed nothing; the suite does not " +
			"distinguish a valid signature from a forged one")
	}
	missed := map[int]string{}
	for _, r := range honest.Rejected {
		missed[int(r.Index)] = r.Reason
	}
	for _, r := range blind.Rejected {
		delete(missed, int(r.Index))
	}
	if len(missed) == 0 {
		t.Error("expected the forged-signature vectors to be admitted by a blind replay")
	}
	for index := range missed {
		var name string
		for _, e := range m.Entries {
			if e.Index == index {
				name = e.Name
			}
		}
		t.Logf("blind replay admits %d (%s)", index, name)
	}
}

func TestEmptyLogYieldsTheZeroState(t *testing.T) {
	st := Replay(Anchor{Net: bytes.Repeat([]byte{1}, 16), GenesisHash: make([]byte, 32)}, nil)
	if st.Size != 0 || len(st.Rejected) != 0 {
		t.Errorf("an empty log has size 0 and no rejections, got size=%d rejected=%v",
			st.Size, st.Rejected)
	}
	if len(st.Devices) != 0 || len(st.Roots) != 0 {
		t.Error("an empty log leaves the zero state")
	}
}

// The Phase 1 gate names six rejections that must be exercised. Checking that
// by hand found two with no vector at all -- including "signer revoked in an
// earlier entry", which is the entire point of signer_remove. This keeps the
// gate honest from now on.
func TestTheGatesNamedRejectionsAreAllExercised(t *testing.T) {
	dir := filepath.Join(vectorRoot(), "log")
	anchor, entries, m := loadCase(t, dir)
	st := Replay(anchor, entries)

	reasonAt := map[int]string{}
	for _, r := range st.Rejected {
		reasonAt[int(r.Index)] = r.Reason
	}
	nameAt := map[int]string{}
	for _, e := range m.Entries {
		nameAt[e.Index] = e.Name
	}

	cases := []struct{ gateName, vectorSuffix, reason string }{
		{"wrong signer", "bad-stranger-signer", ReasonThreshold},
		{"below threshold", "bad-one-of-two-signers", ReasonThreshold},
		{"signer revoked earlier", "bad-removed-signer", ReasonThreshold},
		{"duplicate device id", "bad-dup-id", ReasonDupID},
		{"rotate without the required signature", "bad-rotate-no-new-key-sig", ReasonNoDeviceSig},
		{"entry referencing an unknown device", "bad-unknown-device", ReasonUnknownDevice},
	}
	for _, c := range cases {
		var found bool
		for index, name := range nameAt {
			if !strings.HasSuffix(name, c.vectorSuffix) {
				continue
			}
			found = true
			if reasonAt[index] != c.reason {
				t.Errorf("%s (%s): reason %q, want %q",
					c.gateName, name, reasonAt[index], c.reason)
			}
		}
		if !found {
			t.Errorf("%s: no vector named *-%s", c.gateName, c.vectorSuffix)
		}
	}
}

// --- Cold-model gate run 5, defect G8 -----------------------------------
//
// D-032 requires a `rotate` that installs a new `device_pk` to carry a
// signature by that incoming key: proof that whoever proposed it holds it.
// The vector named for that rule carried no device signature at all, so it was
// refused three checks earlier, at the *current* key. Run 5 deleted the D-032
// check entirely and passed 597/597.
//
// The fixture turns `rotate_needs_signer` on at index 29, so under that
// setting an implementation missing this check lets two signers install an
// attacker-chosen identity key on a device with no proof the attacker holds
// it, which is the whole of what D-032 exists to prevent.

func publicKey(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(vectorRoot(), "keys.json"))
	if err != nil {
		t.Fatal(err)
	}
	var keys struct {
		Ed25519 map[string]struct {
			Public string `json:"public"`
		} `json:"ed25519"`
	}
	if err := json.Unmarshal(raw, &keys); err != nil {
		t.Fatal(err)
	}
	public, err := hex.DecodeString(keys.Ed25519[name].Public)
	if err != nil || len(public) != ed25519.PublicKeySize {
		t.Fatalf("keys.json has no usable %s public key", name)
	}
	return public
}

func deviceSignedBy(t *testing.T, env *entry.Envelope, public []byte) bool {
	t.Helper()
	kid := entry.Kid(public)
	for _, sig := range env.Sigs {
		if sig.Role != "device" || sig.Kid != kid {
			continue
		}
		ok, err := entry.Verify(env, sig, public)
		if err != nil {
			t.Fatal(err)
		}
		if ok {
			return true
		}
	}
	return false
}

func TestTheRotateVectorReachesTheProofOfPossessionRule(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(vectorRoot(), "log", "46-bad-rotate-no-new-key-sig.cbor"))
	if err != nil {
		t.Fatal(err)
	}
	env, err := entry.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if env.T != "rotate" {
		t.Fatalf("entry 46 is a %q, not a rotate", env.T)
	}
	incoming, present := env.Body["device_pk"]
	if !present {
		t.Fatal("entry 46 installs no new device_pk, so it cannot test D-032 at all")
	}
	_ = incoming

	// It must get *past* the current-key check, or it never reaches D-032.
	if !deviceSignedBy(t, env, publicKey(t, "printer")) {
		t.Error("entry 46 carries no valid signature by the device's current key, so it is " +
			"refused at the current-key check and the rule it is named for is never reached")
	}
	// And it must fail exactly there.
	if deviceSignedBy(t, env, publicKey(t, "printer-id2")) {
		t.Error("entry 46 is signed by the incoming key, so it satisfies D-032 and tests nothing")
	}
}

// The control: the positive rotate carries both, which is what D-032 asks for.
func TestTheAcceptedRotateCarriesBothDeviceSignatures(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(vectorRoot(), "log", "40-rotate-device-key-only.cbor"))
	if err != nil {
		t.Fatal(err)
	}
	env, err := entry.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"nas", "nas-id2"} {
		if !deviceSignedBy(t, env, publicKey(t, name)) {
			t.Errorf("the accepted rotate is not signed by %s", name)
		}
	}
}
