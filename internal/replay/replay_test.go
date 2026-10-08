package replay

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/onembyte/norn/internal/cbor"
	"github.com/onembyte/norn/internal/enrollreq"
	"github.com/onembyte/norn/internal/entry"
	"github.com/onembyte/norn/internal/policy"
	"github.com/onembyte/norn/internal/state"
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

func TestMalformedReservedHintsSurviveEnrollmentReplay(t *testing.T) {
	anchor, entries, manifest := loadCase(t, filepath.Join(vectorRoot(), "log"))
	enrollIndex := -1
	for i, item := range manifest.Entries {
		if item.Name == "51-enroll-unicode-labels" {
			enrollIndex = i
			break
		}
	}
	if enrollIndex < 0 {
		t.Fatal("the malformed-hints enrollment is missing from the log manifest")
	}
	st := Replay(anchor, entries[:enrollIndex+1])
	device, ok := st.Devices["escaped"]
	if !ok {
		t.Fatal("the malformed-hints enrollment was not accepted")
	}
	if device.Status != state.StatusActive {
		t.Fatalf("device status = %q, want active", device.Status)
	}
	for key, want := range map[string]string{"ip": "not-a-cidr", "endpoint": "not-an-endpoint"} {
		if got := device.Labels[key]; got != want {
			t.Errorf("replayed labels[%q] = %q, want %q", key, got, want)
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

// Cold gate run 13, D17. `genesis/` holds the ways entry 0 MUST abort, and a
// bound has two sides: `genesis-good/` holds geneses a reader MUST accept,
// one single-entry log each. Its first is a `name` exactly at §4.0's 64-byte
// cap, which a reader whose cap was 63 refused -- aborting the whole network
// -- and no vector said so.
func TestEveryAcceptedGenesisReplaysToItsState(t *testing.T) {
	dirs, err := filepath.Glob(filepath.Join(vectorRoot(), "genesis-good", "*"))
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
		if len(st.Rejected) != 0 || st.Size != 1 {
			t.Errorf("%s: a genesis §4.0 permits must replay to size 1 with nothing rejected, "+
				"got size %d and %+v", dir, st.Size, st.Rejected)
			continue
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
	if checked == 0 {
		t.Error("no accepted genesis case: every genesis vector is a refusal")
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

// --- Cold-model gate run 5, defect G10 ----------------------------------
//
// §5.1 says "The order is normative: several vectors are simultaneously wrong
// in more than one way, so the first matching step decides the reason code."
// For four of its precedence pairs no such vector existed, and run 5 swapped
// each order in turn and passed 597/597. Only the governance step-7-before-8
// case was genuinely pinned.
//
// A precedence vector is worth nothing unless it is wrong in *both* ways, so
// each is checked for the second fault as well as for the reason it produces.

// entryNamed finds a case by the part of its name that identifies it. The
// index prefix moves whenever an entry is inserted earlier in the fixture --
// which happened the first time one was, and broke four tests at once.
func entryNamed(t *testing.T, m manifest, suffix string) (int, string) {
	t.Helper()
	for i, e := range m.Entries {
		if strings.HasSuffix(e.Name, suffix) {
			return i, e.Reason
		}
	}
	t.Fatalf("the fixture has no entry ending %q", suffix)
	return 0, ""
}

// fullName is the shipped file name for a case, index prefix and all.
func fullName(t *testing.T, m manifest, suffix string) string {
	t.Helper()
	for _, e := range m.Entries {
		if strings.HasSuffix(e.Name, suffix) {
			return e.Name
		}
	}
	t.Fatalf("the fixture has no entry ending %q", suffix)
	return ""
}

func rawEntry(t *testing.T, name string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(vectorRoot(), "log", name+".cbor"))
	if err != nil {
		t.Fatal(err)
	}
	// Deliberately not entry.Decode: the envelope check is one of the rules
	// under test, so these bytes are read as plain CBOR.
	value, err := cbor.Decode(raw)
	if err != nil {
		t.Fatalf("%s is not decodable CBOR, so it cannot isolate a later rule: %v", name, err)
	}
	m, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("%s is not a CBOR map", name)
	}
	return m
}

func TestThePrecedenceVectorsAreWrongInTwoWays(t *testing.T) {
	_, _, m := loadCase(t, filepath.Join(vectorRoot(), "log"))

	cases := []struct {
		name        string
		reason      string
		alsoWrong   string
		secondFault func(t *testing.T, env map[string]any)
	}{{
		name: "bad-precedence-decode-before-unknown-type", reason: "decode",
		alsoWrong: "carries a type §4.3 does not define",
		secondFault: func(t *testing.T, env map[string]any) {
			if kind, _ := env["t"].(string); kind == "note" || kind == "enroll" {
				t.Errorf("t is %q, which §4.3 defines: step 4 would not have fired", kind)
			}
		},
	}, {
		name: "bad-precedence-after-before-threshold", reason: "after",
		alsoWrong: "has no valid signature to count",
		secondFault: func(t *testing.T, env map[string]any) {
			sigs, _ := env["sigs"].([]any)
			if len(sigs) != 0 {
				t.Errorf("%d signatures: step 7 would have been satisfied", len(sigs))
			}
		},
	}, {
		name: "bad-precedence-threshold-before-dup-id", reason: "threshold",
		alsoWrong: "enrols a device_id that is already active",
		secondFault: func(t *testing.T, env map[string]any) {
			sigs, _ := env["sigs"].([]any)
			if len(sigs) >= 2 {
				t.Errorf("%d signatures meets signer_thr, so step 7 would not fire", len(sigs))
			}
		},
	}, {
		name: "bad-precedence-threshold-before-dup-wg", reason: "threshold",
		alsoWrong: "takes a WireGuard key active for another device",
		secondFault: func(t *testing.T, env map[string]any) {
			sigs, _ := env["sigs"].([]any)
			if len(sigs) < 1 {
				t.Error("no signatures at all: this would fail the device-signature check first")
			}
			// The fault the later rule would have reported has to be real. The
			// first version of this vector took `nas`'s *original* key, which
			// `nas` rotated away from at entry 35, so it was wrong in only one
			// way and pinned nothing -- and this check was not here to say so.
			body, _ := env["body"].(map[string]any)
			wg, _ := body["wg_pk"].([]byte)
			owner, taken := activeWg(t)[hex.EncodeToString(wg)]
			if !taken {
				t.Error("the new WireGuard key is not active for anybody, so `dup-wg` " +
					"would never have fired and the order is not pinned")
			} else if owner == "printer" {
				t.Error("the key already belongs to this device, which `dup-wg` permits")
			}
		},
	}, {
		// Run 13, D4: the five pairs no entry had reached.
		name: "bad-precedence-unknown-type-before-after", reason: "unknown-type",
		alsoWrong: "names an `after` past its own index",
		secondFault: func(t *testing.T, env map[string]any) {
			afterPastIndex(t, m, env, "bad-precedence-unknown-type-before-after")
		},
	}, {
		name: "bad-precedence-dup-genesis-before-after", reason: "dup-genesis",
		alsoWrong: "names an `after` past its own index",
		secondFault: func(t *testing.T, env map[string]any) {
			afterPastIndex(t, m, env, "bad-precedence-dup-genesis-before-after")
		},
	}, {
		name: "bad-precedence-note-threshold-before-body", reason: "threshold",
		alsoWrong: "carries a `text` over the 4096-byte cap",
		secondFault: func(t *testing.T, env map[string]any) {
			body, _ := env["body"].(map[string]any)
			if text, _ := body["text"].(string); len(text) <= maxText {
				t.Errorf("a %d-byte text is within the cap: the body check would pass", len(text))
			}
		},
	}, {
		name: "bad-precedence-revoke-not-active-before-threshold", reason: "not-active",
		alsoWrong: "carries no signature, so nothing authorises it",
		secondFault: func(t *testing.T, env map[string]any) {
			if sigs, _ := env["sigs"].([]any); len(sigs) != 0 {
				t.Errorf("%d signatures: the device itself might authorise it", len(sigs))
			}
		},
	}, {
		name: "bad-precedence-net-before-threshold", reason: "decode",
		alsoWrong: "carries no root signature, so step 7 would refuse it",
		secondFault: func(t *testing.T, env map[string]any) {
			if kind, _ := env["t"].(string); !governance[kind] {
				t.Errorf("t is %q, which step 7 does not judge", kind)
			}
			if sigs, _ := env["sigs"].([]any); len(sigs) != 0 {
				t.Errorf("%d signatures: step 7 might be satisfied", len(sigs))
			}
		},
	}}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, reason := entryNamed(t, m, c.name)
			if reason != c.reason {
				t.Errorf("reason is %q, want %q -- the earlier step must decide", reason, c.reason)
			}
			c.secondFault(t, rawEntry(t, fullName(t, m, c.name)))
			t.Logf("also %s, which a swapped order would have reported instead", c.alsoWrong)
		})
	}
}

// afterPastIndex fails unless the entry's `after` is past its own index, the
// fault step 6 would report.
func afterPastIndex(t *testing.T, m manifest, env map[string]any, name string) {
	t.Helper()
	index, _ := entryNamed(t, m, name)
	if after, ok := env["after"].(uint64); !ok || after <= uint64(index) {
		t.Errorf("after is %v at index %d: step 6 would not fire", env["after"], index)
	}
}

// activeWg is the fixture's final WireGuard-key ownership, keyed by hex.
func activeWg(t *testing.T) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(vectorRoot(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	var st struct {
		ActiveWg map[string]string `json:"active_wg"`
	}
	if err := json.Unmarshal(raw, &st); err != nil {
		t.Fatal(err)
	}
	return st.ActiveWg
}

// Cold-model gate run 5, defect G13. §4.3 gives `revoke` three *independent*
// authorisations -- signer quorum, root quorum, or the device itself -- and
// the fixture's `revoke-by-roots` met the root quorum outright, so pooling all
// the signatures into one count gave the same answer everywhere.
// `NORN_REVOKE_COMBINE` passed 597/597.
func TestTheRevokeVectorSeparatesThreeQuorumsFromOne(t *testing.T) {
	_, _, m := loadCase(t, filepath.Join(vectorRoot(), "log"))
	const name = "bad-revoke-neither-quorum"

	var found bool
	for _, e := range m.Entries {
		if !strings.Contains(e.Name, name) {
			continue
		}
		found = true
		if e.Reason != "threshold" {
			t.Errorf("%s is refused %q, want threshold", e.Name, e.Reason)
		}
		env, err := entry.Decode(rawNamed(t, e.Name))
		if err != nil {
			t.Fatal(err)
		}
		var signers, roots int
		for _, sig := range env.Sigs {
			switch sig.Role {
			case "signer":
				signers++
			case "root":
				roots++
			}
		}
		// Under three independent rules this is short on every one of them.
		// Pooled into a single count it reaches the root threshold, which is
		// the reading the suite could not previously rule out.
		if signers == 0 || roots == 0 {
			t.Errorf("%d signers and %d roots: the vector must carry some of each, or "+
				"pooling them changes nothing", signers, roots)
		}
		if signers+roots < 3 {
			t.Errorf("%d signatures in total; pooled they must reach a quorum, or the "+
				"two readings still agree", signers+roots)
		}
	}
	if !found {
		t.Fatalf("the fixture has no %s entry", name)
	}
}

func rawNamed(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(vectorRoot(), "log", name+".cbor"))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// Cold-model gate run 6, defect H2. §4.5 says a `policy` entry "supersedes"
// the trust file's policy inside the log, and §5.1's rule for that entry
// checked only that its body was closed and its text under 4096 bytes -- never
// that the text was a policy at all. The fixture therefore published
// `49-policy-escaping`'s canonical-JSON torture string as the network's
// policy, and an implementer following §4.5 literally could not verify this
// network's own checkpoint.
//
// Whatever an in-log policy is *for* -- a question still open, see BUILD-LOG
// -- a `policy` entry whose text is not a policy is malformed. That is true
// under every reading, so it is settled here.
func TestTheStatesPolicyIsAPolicy(t *testing.T) {
	anchor, entries, _ := loadCase(t, filepath.Join(vectorRoot(), "log"))
	st := Replay(anchor, entries)
	if st.Policy == "" {
		t.Fatal("the fixture records no policy, so nothing here is tested")
	}
	if _, err := policy.Parse(st.Policy); err != nil {
		t.Errorf("the policy this log publishes does not parse as `tlog-policy`: %v\n"+
			"A node that honoured §4.5 would be unable to verify this network.", err)
	}
}

// Cold-model gate run 6, defect H4. §4.0 said an entry with `sigs: []` is
// refused `no-device-sig` for `enroll` and `rotate`, "whose first step-8 check
// is the device signature". For `enroll` that is wrong: the envelope carries
// no signature, but the *request* inside it is still intact and correctly
// signed by the device, so the device-signature check passes and the entry is
// refused `threshold` for having no signers.
//
// The only empty-`sigs` vector was a `note`, so nothing in the suite
// contradicted a reader who believed §4.0 -- and reason codes land in
// `state.rejected`, which §5.3 requires byte-identical, so one wrong sentence
// splits `state.json` on the same log bytes.
func TestAnUnsignedEnrollIsRefusedForItsSignerCount(t *testing.T) {
	_, _, m := loadCase(t, filepath.Join(vectorRoot(), "log"))
	_, reason := entryNamed(t, m, "bad-enroll-empty-sigs")
	if reason != "threshold" {
		t.Errorf("an enroll with no envelope signatures is refused %q; §5.1's order "+
			"gives `threshold`, because the embedded request is still signed", reason)
	}
}

// Cold-model gate run 6, defect H6. The encoding profile never said a decoder
// must reject bytes after the CBOR item, and `allow-trailing` passed every
// vector. The attack is not a parsing curiosity: append one byte to a
// governance entry and it keeps its signatures -- the preimage is the decoded
// envelope, not the raw bytes -- while its `entry_hash` changes, so `dup-entry`
// does not fire and a lenient decoder **applies it twice**. Run 6 grew
// `state.log_keys` from two to three that way.
func TestAGovernanceEntryCannotBeReplayedByAppendingAByte(t *testing.T) {
	_, _, m := loadCase(t, filepath.Join(vectorRoot(), "log"))
	index, reason := entryNamed(t, m, "bad-trailing-byte")
	if reason != "decode" {
		t.Errorf("an entry with a byte after it is refused %q, want decode", reason)
	}

	// It must be a *duplicate* of an entry the log already applied, or it
	// tests trailing bytes and not the doubling they enable.
	raw, err := os.ReadFile(filepath.Join(vectorRoot(), "log",
		fullName(t, m, "bad-trailing-byte")+".cbor"))
	if err != nil {
		t.Fatal(err)
	}
	trimmed := raw[:len(raw)-1]
	var twin string
	for _, e := range m.Entries {
		body, err := os.ReadFile(filepath.Join(vectorRoot(), "log", e.Name+".cbor"))
		if err == nil && e.Reason == "" && string(body) == string(trimmed) {
			twin = e.Name
		}
	}
	if twin == "" {
		t.Error("stripping the trailing byte does not yield an accepted entry, so the " +
			"vector does not show that the byte is what makes a replay possible")
	} else {
		t.Logf("entry %d is %s with one byte appended", index, twin)
	}
}

// Cold-model gate run 6, the replay-layer half of "rules the prose pins and no
// vector does". Each of these passed 285/285 as a variant, and each splits
// `state.rejected`, which §5.3 requires byte-identical.
func TestTheReplayRulesRunSixLeftUnpinned(t *testing.T) {
	_, _, m := loadCase(t, filepath.Join(vectorRoot(), "log"))

	for _, c := range []struct{ suffix, reason, why string }{
		// §4.4's floor is `after > index`, and the fixture's values were 999,
		// 5091 and 5 at indices 10, 91 and 75 -- never at or beside the
		// boundary, so rejecting only above `index+1` passed everything.
		{"after-at-its-own-index", "", "`after` equal to the index is a floor met exactly"},
		{"bad-after-by-one", "after", "one past the index is the smallest violation there is"},
		// §5.1 requires an enroll's request `net` to equal the entry's. The
		// only net negative patched the *envelope*.
		{"bad-request-net", "decode", "the request names another network than the entry"},
		// §5.1's enroll order puts `dup-id` before `dup-wg`.
		{"bad-dup-id-and-wg", "dup-id", "wrong in both ways; the earlier rule decides"},
		// §5.2 requires a `device` signature's `kid` to resolve, not merely to
		// verify against some key.
		{"bad-device-sig-wrong-kid", "no-device-sig", "the signature verifies and its kid names another key"},
	} {
		t.Run(c.suffix, func(t *testing.T) {
			_, reason := entryNamed(t, m, c.suffix)
			if reason != c.reason {
				want := c.reason
				if want == "" {
					want = "accepted"
				}
				t.Errorf("reason is %q, want %q -- %s", reason, want, c.why)
			}
		})
	}
}

// --- Cold-model gate run 7, defect J9 -----------------------------------
//
// The four vectors above cover §5.1's *numbered* steps. Three more orderings
// live inside the `enroll` and `rotate` rules, whose tables §5.1 also calls
// normative ("Each rule's checks run in the order written"), and run 7 swapped
// each of them and still passed 241/241.
//
// The first is the ordering §4.0 goes out of its way to explain a second time
// -- "An unsigned `enroll` is `threshold` and not `no-device-sig`: the
// embedded request is still signed by the device, so the device-signature
// check passes and the signer count is what fails" -- and the vector that
// paragraph names, `bad-enroll-empty-sigs`, carries a *valid* request
// signature, so it cannot tell the two orders apart. The rule was explained
// twice and pinned zero times.

// embeddedRequest is the enrolment request an `enroll` carries, read as plain
// CBOR: the net comparison and the signature check are the rules under test,
// so neither may be applied on the way in.
func embeddedRequest(t *testing.T, env *entry.Envelope) *enrollreq.Request {
	t.Helper()
	raw, ok := env.Body["request"].([]byte)
	if !ok {
		t.Fatal("the enroll body carries no request byte string")
	}
	request, err := enrollreq.Decode(raw)
	if err != nil {
		t.Fatalf("the embedded request does not decode, so the entry dies before "+
			"either rule under test: %v", err)
	}
	return request
}

func envNamed(t *testing.T, m manifest, suffix string) *entry.Envelope {
	t.Helper()
	env, err := entry.Decode(rawNamed(t, fullName(t, m, suffix)))
	if err != nil {
		t.Fatalf("%s does not decode: %v", suffix, err)
	}
	return env
}

func TestTheInnerRulePrecedenceVectorsAreWrongInTwoWays(t *testing.T) {
	_, _, m := loadCase(t, filepath.Join(vectorRoot(), "log"))

	t.Run("enroll: the request signature precedes the signer count", func(t *testing.T) {
		const name = "bad-enroll-unsigned-request-no-signers"
		if _, reason := entryNamed(t, m, name); reason != "no-device-sig" {
			t.Errorf("reason is %q, want no-device-sig", reason)
		}
		env := envNamed(t, m, name)
		request := embeddedRequest(t, env)
		if !bytes.Equal(request.Net, env.Net) {
			t.Error("the request's net differs from the entry's, so `decode` fires first")
		}
		if enrollreq.Verify(request) {
			t.Error("the request's signature verifies, so `no-device-sig` never fires")
		}
		if len(env.Sigs) != 0 {
			t.Errorf("%d signatures: `threshold` would not fire, so the order is "+
				"not pinned", len(env.Sigs))
		}
	})

	t.Run("enroll: the request's net precedes its signature", func(t *testing.T) {
		const name = "bad-enroll-request-net-and-sig"
		if _, reason := entryNamed(t, m, name); reason != "decode" {
			t.Errorf("reason is %q, want decode", reason)
		}
		env := envNamed(t, m, name)
		request := embeddedRequest(t, env)
		if bytes.Equal(request.Net, env.Net) {
			t.Error("the request's net matches the entry's, so `decode` never fires")
		}
		if enrollreq.Verify(request) {
			t.Error("the request's signature verifies, so a swapped order would " +
				"report the same reason and the vector pins nothing")
		}
	})

	t.Run("rotate: dup-wg precedes the incoming key's signature", func(t *testing.T) {
		const name = "bad-rotate-dupwg-and-no-new-key-sig"
		if _, reason := entryNamed(t, m, name); reason != "dup-wg" {
			t.Errorf("reason is %q, want dup-wg", reason)
		}
		env := envNamed(t, m, name)
		deviceID, _ := env.Body["device_id"].(string)
		incoming, ok := env.Body["device_pk"].([]byte)
		if !ok {
			t.Fatal("the body carries no device_pk, so the proof-of-possession " +
				"check is never reached and the order is not pinned")
		}
		if deviceSignedBy(t, env, incoming) {
			t.Error("the incoming key signed: the later check would not fire")
		}
		// Everything before `dup-wg` has to pass, or an earlier rule decides.
		current := devicesOf(t)[deviceID]
		currentPK, err := hex.DecodeString(current.DevicePK)
		if err != nil {
			t.Fatal(err)
		}
		if !deviceSignedBy(t, env, currentPK) {
			t.Error("the device's current key did not sign, so the entry is " +
				"`no-device-sig` for the earlier reason")
		}
		wg, _ := env.Body["wg_pk"].([]byte)
		switch owner, taken := activeWg(t)[hex.EncodeToString(wg)]; {
		case !taken:
			t.Error("the new WireGuard key is active for nobody, so `dup-wg` never fires")
		case owner == deviceID:
			t.Error("the key already belongs to this device, which `dup-wg` permits")
		}
	})
}

type deviceRecord struct {
	DevicePK string `json:"device_pk"`
	WgPK     string `json:"wg_pk"`
	Status   string `json:"status"`
}

func devicesOf(t *testing.T) map[string]deviceRecord {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(vectorRoot(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	var st struct {
		Devices map[string]deviceRecord `json:"devices"`
	}
	if err := json.Unmarshal(raw, &st); err != nil {
		t.Fatal(err)
	}
	return st.Devices
}

// --- Cold-model gate run 7, defect J10 ----------------------------------
//
// §5.1 step 1 states two properties and the suite exercised neither:
// `entry_hash` is recorded *before* the entry is decoded, and entry 0's is
// recorded too. `85-bad-repeat-of-rejected` copies an entry that decodes
// cleanly, and `13-bad-dup-entry` copies entry 1 rather than entry 0, so
// `seen-after-decode` and `no-genesis-seen` both passed the whole suite.
//
// The divergence is not cosmetic: a log carrying two identical undecodable
// entries yields `decode, decode` under one reading and `decode, dup-entry`
// under the other -- different `rejected` arrays, which §5.3 makes a
// byte-identical MUST.

func TestTheSeenSetIsRecordedBeforeDecodingAndAtGenesis(t *testing.T) {
	_, entries, m := loadCase(t, filepath.Join(vectorRoot(), "log"))

	t.Run("a copy of an entry that never decoded", func(t *testing.T) {
		index, reason := entryNamed(t, m, "bad-repeat-of-undecodable")
		if reason != "dup-entry" {
			t.Errorf("reason is %q, want dup-entry", reason)
		}
		original := indexOfCopy(t, entries, index)
		if original < 0 {
			t.Fatal("no earlier entry has these bytes, so nothing is a duplicate of anything")
		}
		if _, err := entry.Decode(entries[original]); err == nil {
			t.Error("the copied entry decodes, so recording the hash after decoding " +
				"would reach the same answer and the vector pins nothing")
		}
		if got := m.Entries[original].Reason; got != "decode" {
			t.Errorf("the copied entry is refused %q, want decode -- step 2", got)
		}
	})

	t.Run("a copy of the genesis entry", func(t *testing.T) {
		index, reason := entryNamed(t, m, "bad-repeat-of-genesis")
		if reason != "dup-entry" {
			t.Errorf("reason is %q, want dup-entry -- step 1 precedes step 5", reason)
		}
		if !bytes.Equal(entries[index], entries[0]) {
			t.Fatal("not a byte copy of entry 0, so `dup-genesis` is all it could ever be")
		}
		env, err := entry.Decode(entries[0])
		if err != nil || env.T != "genesis" {
			t.Fatal("entry 0 is not a decodable genesis")
		}
	})
}

// indexOfCopy is the first earlier entry with exactly these bytes, or -1.
func indexOfCopy(t *testing.T, entries [][]byte, index int) int {
	t.Helper()
	for i := 0; i < index; i++ {
		if bytes.Equal(entries[i], entries[index]) {
			return i
		}
	}
	return -1
}

// --- Cold-model gate run 7, defect J5 -----------------------------------
//
// §5.1's `params` rule is "non-empty, only §4.5 keys, each of the right type",
// and only the non-empty half was vectored: `68-bad-unknown-body-key` is a
// *note*, and no `genesis` in the suite carries a `params` map with a bad key
// at all. `allow-unknown-param` and `params-loose-type` both passed.
//
// This is the widest divergence in the replay machine. Two implementations
// that disagree end up with different `params`, so a different `staleness`, so
// a different freshness verdict -- and at genesis one aborts to the zero state
// while the other replays the whole log.

func TestTheParamsKeyAndTypeRulesAreVectored(t *testing.T) {
	_, _, m := loadCase(t, filepath.Join(vectorRoot(), "log"))
	known := map[string]bool{"checkpoint_interval": true, "staleness": true,
		"mmd": true, "rotate_needs_signer": true}

	t.Run("an unknown key", func(t *testing.T) {
		const name = "bad-params-unknown-key"
		if _, reason := entryNamed(t, m, name); reason != "decode" {
			t.Errorf("reason is %q, want decode", reason)
		}
		body := bodyOf(t, rawEntry(t, fullName(t, m, name)))
		if len(body) == 0 {
			t.Fatal("an empty body is refused by the non-empty rule instead")
		}
		var stranger bool
		for key := range body {
			if !known[key] {
				stranger = true
			}
		}
		if !stranger {
			t.Error("every key is a §4.5 key, so the unknown-key rule never fires")
		}
	})

	t.Run("a §4.5 key of the wrong type", func(t *testing.T) {
		const name = "bad-params-wrong-type"
		if _, reason := entryNamed(t, m, name); reason != "decode" {
			t.Errorf("reason is %q, want decode", reason)
		}
		body := bodyOf(t, rawEntry(t, fullName(t, m, name)))
		if len(body) == 0 {
			t.Fatal("an empty body is refused by the non-empty rule instead")
		}
		for key, value := range body {
			if !known[key] {
				t.Fatalf("%q is not a §4.5 key: the unknown-key rule fires first", key)
			}
			// A bool where a uint belongs is the trap: CBOR `true` is one byte
			// and every loose decoder in the world turns it into 1.
			if key == "rotate_needs_signer" {
				if _, isBool := value.(bool); isBool {
					t.Error("a bool in the one bool-typed field is the right type")
				}
				continue
			}
			if _, isBool := value.(bool); !isBool {
				t.Errorf("%q holds %T; a bool is what a loose uint check lets through", key, value)
			}
		}
	})

	t.Run("an unknown key in the genesis body", func(t *testing.T) {
		names := genesisCaseNames(t)
		var found string
		for _, name := range names {
			if strings.HasSuffix(name, "params-unknown-key") {
				found = name
			}
		}
		if found == "" {
			t.Fatal("no genesis case carries a params map with an unknown key: " +
				"§5.1 entry-0 step 6's params clause is unvectored, and the two " +
				"readings differ by the whole log")
		}
	})
}

func bodyOf(t *testing.T, env map[string]any) map[string]any {
	t.Helper()
	body, ok := env["body"].(map[string]any)
	if !ok {
		t.Fatal("the entry has no CBOR map body")
	}
	return body
}

func genesisCaseNames(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(vectorRoot(), "genesis", "cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Cases []string `json:"cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	return doc.Cases
}

// --- Cold-model gate run 7, defect J12 ----------------------------------
//
// The long tail of "refused-but-not-pinned": rules the prose states, that some
// *other* rule happens to refuse first, so removing them changes nothing any
// vector can see. None is alarming alone; together they are thirteen places
// where a second implementer is free to differ.
//
// These six live in the replay layer. Two of them the Python reference was
// getting wrong -- it never capped `revoke`'s `reason` and never bounded the
// genesis `name` -- which is what an unpinned rule looks like from the inside:
// the two implementations had already drifted and every test on both sides
// still passed.

func TestTheFieldRuleTailIsVectored(t *testing.T) {
	_, _, m := loadCase(t, filepath.Join(vectorRoot(), "log"))

	// §4.0: a `kid` in a `signer_remove`/`root_remove` **body** must match
	// `^[0-9a-f]{16}$` → `decode`. The document flags this exact distinction
	// ("that distinction matters because the two produce different reason
	// codes") and the only `bad-kid-format` vector puts the bad kid in `sigs`,
	// so the body half was stated and never exercised.
	t.Run("a malformed kid in the body", func(t *testing.T) {
		const name = "bad-kid-format-in-body"
		if _, reason := entryNamed(t, m, name); reason != "decode" {
			t.Errorf("reason is %q, want decode -- a malformed kid is a schema "+
				"violation, not an unresolvable one", reason)
		}
		body := bodyOf(t, rawEntry(t, fullName(t, m, name)))
		kid, _ := body["kid"].(string)
		if regexp.MustCompile(`^[0-9a-f]{16}$`).MatchString(kid) {
			t.Errorf("kid %q is well formed, so `unknown-key` is what fires", kid)
		}
	})

	// §5.2: a signature is valid only if its `kid` names a key the entry may be
	// signed by **in that role**. `bad-role-mismatch` pins the root/signer
	// direction; nothing pinned the device one, so `device-sig-any-role` --
	// which accepts a device signature under any declared role -- passed.
	t.Run("a device signature declared under another role", func(t *testing.T) {
		const name = "bad-device-sig-wrong-role"
		if _, reason := entryNamed(t, m, name); reason != "no-device-sig" {
			t.Errorf("reason is %q, want no-device-sig", reason)
		}
		env := envNamed(t, m, name)
		id, _ := env.Body["device_id"].(string)
		current, err := hex.DecodeString(devicesOf(t)[id].DevicePK)
		if err != nil {
			t.Fatal(err)
		}
		if deviceSignedBy(t, env, current) {
			t.Fatal("a signature under role `device` is present, so the rule never fires")
		}
		// The device's key did sign -- under the wrong role. Without that the
		// entry is just unsigned and pins nothing about roles.
		if !signedUnderAnyRole(t, env, current) {
			t.Error("the device's key did not sign at all, so this is an ordinary " +
				"missing signature rather than a misdeclared role")
		}
	})

	// §4.0: `revoke`'s `reason` is 0-256 bytes. `bad-text-too-long` covers
	// `note` and `policy`, whose cap is 4096 and a different rule.
	t.Run("an over-long revoke reason", func(t *testing.T) {
		const name = "bad-revoke-reason-too-long"
		if _, reason := entryNamed(t, m, name); reason != "decode" {
			t.Errorf("reason is %q, want decode", reason)
		}
		body := bodyOf(t, rawEntry(t, fullName(t, m, name)))
		text, _ := body["reason"].(string)
		if len(text) <= 256 {
			t.Errorf("the reason is %d bytes, which the cap permits", len(text))
		}
	})

	// §4.3: nothing constrains the embedded request's `ts` against the entry's.
	// A reader who adds the obvious check diverges, and until this entry every
	// request in the fixture was older than the entry carrying it, so nothing
	// could say so. The vector is a *positive* one: it must be accepted.
	t.Run("a request newer than the entry that carries it", func(t *testing.T) {
		const name = "enroll-request-from-the-future"
		if _, reason := entryNamed(t, m, name); reason != "" {
			t.Fatalf("the entry is refused %q; the rule under test is that it is "+
				"accepted", reason)
		}
		env := envNamed(t, m, name)
		if got := embeddedRequest(t, env).TS; got <= env.TS {
			t.Errorf("the request's ts is %d and the entry's is %d; only a request "+
				"newer than its entry separates the two readings", got, env.TS)
		}
	})
}

// signedUnderAnyRole reports whether this key signed the entry at all,
// whatever role the signature declares itself to be.
func signedUnderAnyRole(t *testing.T, env *entry.Envelope, public []byte) bool {
	t.Helper()
	for _, sig := range env.Sigs {
		if sig.Kid != entry.Kid(public) {
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

// §4.0 bounds the genesis `name` at 1-64 bytes, and `genesis/` had no case at
// either end: `no-name-len` passed. Both halves ship, because a decoder
// enforcing only the cap and one enforcing only the floor are different bugs.
func TestTheGenesisNameBoundsAreVectored(t *testing.T) {
	names := genesisCaseNames(t)
	// Run 13, D17: 66 bytes and empty are both far from the cap. One byte
	// past it is refused here, and the cap itself is accepted in
	// `genesis-good/`.
	for _, want := range []string{"name-too-long", "name-empty", "name-one-past-the-cap"} {
		var found bool
		for _, name := range names {
			if strings.HasSuffix(name, want) {
				found = true
			}
		}
		if !found {
			t.Errorf("no genesis case for %s: §4.0's `name` bound is unpinned at that end", want)
		}
	}
	if _, err := os.Stat(filepath.Join(vectorRoot(), "genesis-good", "01-name-at-the-cap")); err != nil {
		t.Errorf("no accepted genesis with a name at the cap: %v", err)
	}
}

// §5.3: genesis `params` is **overlaid** on the §4.5 defaults, not substituted
// for them. The fixture's genesis set all four keys, so overlay and replace
// produced the same state and `genesis-params-replace` passed. The fixture now
// sets a strict subset, which makes the difference a field of `state.json`.
func TestTheGenesisParamsAreOverlaidOnTheDefaults(t *testing.T) {
	_, entries, _ := loadCase(t, filepath.Join(vectorRoot(), "log"))
	env, err := entry.Decode(entries[0])
	if err != nil {
		t.Fatal(err)
	}
	set, _ := env.Body["params"].(map[string]any)
	if len(set) == 0 {
		t.Fatal("the genesis sets no params at all, so a replace would be the zero map " +
			"and the fixture would be testing something else")
	}

	raw, err := os.ReadFile(filepath.Join(vectorRoot(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	var st struct {
		Params map[string]any `json:"params"`
	}
	if err := json.Unmarshal(raw, &st); err != nil {
		t.Fatal(err)
	}
	defaults := state.DefaultParams()
	var inherited []string
	for key := range defaults {
		if _, fromGenesis := set[key]; !fromGenesis {
			if _, present := st.Params[key]; !present {
				t.Errorf("%q is in neither the genesis body nor the state, so the "+
					"defaults were not applied at all", key)
				continue
			}
			inherited = append(inherited, key)
		}
	}
	if len(inherited) == 0 {
		t.Error("the genesis body sets every §4.5 key, so a replace and an overlay " +
			"reach the same state and the rule is unpinned")
	}
}

// Cold-model gate run 8, defect D19. §5.1: "Replay of an **empty** list of
// entries yields the zero state of §5.3 with `size` 0 and `rejected` empty:
// there is nothing to reject." Every log in the suite had at least one entry,
// so `empty-log-is-bad-genesis` -- which treats no genesis as a missing one --
// reproduced everything.
//
// The two readings differ by a whole field: one reports `rejected: []`, the
// other `[{0, bad-genesis}]`, and §5.3 makes that byte-identical between
// implementations.
func TestAnEmptyLogReplaysToTheZeroStateWithNothingRejected(t *testing.T) {
	dir := filepath.Join(vectorRoot(), "log-empty")
	anchor, entries, _ := loadCase(t, dir)
	if len(entries) != 0 {
		t.Fatalf("%d entries; the case is a log with none", len(entries))
	}
	want, err := os.ReadFile(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := Replay(anchor, entries).MarshalCanonical()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("an empty log does not replay to the shipped zero state.\n got: %s\nwant: %s",
			got, want)
	}
}
