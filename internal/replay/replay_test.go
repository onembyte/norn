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

	"github.com/onembyte/norn/internal/cbor"
	"github.com/onembyte/norn/internal/entry"
	"github.com/onembyte/norn/internal/policy"
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
