package replay

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"path/filepath"
	"reflect"
	"testing"

	"filippo.io/edwards25519"

	"github.com/onembyte/norn/internal/cbor"
	"github.com/onembyte/norn/internal/enrollreq"
	"github.com/onembyte/norn/internal/entry"
	"github.com/onembyte/norn/internal/state"
)

// notValidPoints are SPEC §3.1 item 1's two kinds of 32 bytes that decode to a
// point of the curve and are still not a key: a point of order 8, and an
// honest key with that point added -- a mixed-order key, whose prime-order
// part is somebody's real key and on which the two verification equations
// part.
func notValidPoints(t *testing.T, honest []byte) map[string][]byte {
	t.Helper()
	small, err := hex.DecodeString("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05")
	if err != nil {
		t.Fatal(err)
	}
	torsion, err := new(edwards25519.Point).SetBytes(small)
	if err != nil {
		t.Fatal(err)
	}
	a, err := new(edwards25519.Point).SetBytes(honest)
	if err != nil {
		t.Fatal(err)
	}
	return map[string][]byte{
		"small-order": small,
		"mixed-order": new(edwards25519.Point).Add(a, torsion).Bytes(),
	}
}

func publicOf(t *testing.T, name string) []byte {
	t.Helper()
	return privateKey(t, name).Public().(ed25519.PublicKey)
}

// signAs signs env with every fixture key that holds role in st.
func signAs(t *testing.T, env *entry.Envelope, st *state.State, role string, names ...string) {
	t.Helper()
	held := st.Roots
	if role == "signer" {
		held = st.Signers
	}
	for _, name := range names {
		key := privateKey(t, name)
		if _, ok := held[entry.Kid(key.Public().(ed25519.PublicKey))]; ok {
			if err := entry.Sign(env, key, role); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func appended(t *testing.T, entries [][]byte, env *entry.Envelope) [][]byte {
	t.Helper()
	raw, err := entry.Encode(env)
	if err != nil {
		t.Fatal(err)
	}
	return append(append([][]byte(nil), entries...), raw)
}

// lastOutcome is what replay made of the final entry: its rejection reason,
// or "" when it was accepted.
func lastOutcome(st *state.State, index int) string {
	for _, r := range st.Rejected {
		if r.Index == uint64(index) {
			return r.Reason
		}
	}
	return ""
}

// §3.1 item 2: a root_add, signer_add or log_key entry naming a key that is
// not a valid point is refused as `decode` -- after the root quorum, like
// every governance body check (§5.2) -- and changes nothing. The same entry
// with an honest key is accepted, so the refusal is the key's.
func TestAGovernanceEntryAdmitsOnlyAValidPoint(t *testing.T) {
	anchor, entries, _ := loadCase(t, filepath.Join(vectorRoot(), "log"))
	before := Replay(anchor, entries)
	honest := publicOf(t, "spare")
	keys := notValidPoints(t, honest)
	keys["honest"] = honest
	for _, typ := range []string{"root_add", "signer_add", "log_key"} {
		for kind, key := range keys {
			body := map[string]any{"pk": key}
			if typ == "log_key" {
				body["overlap"] = uint64(0)
			}
			env := &entry.Envelope{V: entry.Version, T: typ, Net: anchor.Net, TS: 1_760_700_000, Body: body}
			signAs(t, env, before, "root", "root1", "root2", "root3", "root4")
			after := Replay(anchor, appended(t, entries, env))
			got := lastOutcome(after, len(entries))
			if kind == "honest" {
				if got != "" {
					t.Errorf("%s of an honest key was rejected %q; the test shows nothing", typ, got)
				}
				continue
			}
			if got != ReasonDecode {
				t.Errorf("%s of a %s key: %q, want %q", typ, kind, got, ReasonDecode)
			}
			if !reflect.DeepEqual(after.Roots, before.Roots) || !reflect.DeepEqual(after.Signers, before.Signers) ||
				!reflect.DeepEqual(after.LogKeys, before.LogKeys) {
				t.Errorf("a rejected %s of a %s key changed the key sets", typ, kind)
			}
		}
	}
}

// §3.1 item 2 and §5.1's entry 0: a genesis whose roots or signers hold a key
// that is not a valid point aborts replay as `bad-genesis`, like every entry-0
// failure. The same genesis with only honest keys replays.
func TestAGenesisAdmitsOnlyValidPoints(t *testing.T) {
	root, signer := privateKey(t, "root1"), publicOf(t, "signer1")
	rootPub := root.Public().(ed25519.PublicKey)
	net := bytes.Repeat([]byte{3}, entry.NetLen)
	replayGenesis := func(roots, signers []any) *state.State {
		env := &entry.Envelope{V: entry.Version, T: "genesis", Net: net, TS: 1_760_000_000,
			Body: map[string]any{"name": "admission", "roots": roots, "signers": signers,
				"root_thr": uint64(1), "signer_thr": uint64(1)}}
		if err := entry.Sign(env, root, "root"); err != nil {
			t.Fatal(err)
		}
		raw, err := entry.Encode(env)
		if err != nil {
			t.Fatal(err)
		}
		return Replay(Anchor{Net: net, GenesisHash: entry.LeafHash(raw)}, [][]byte{raw})
	}
	if st := replayGenesis([]any{[]byte(rootPub)}, []any{signer}); len(st.Rejected) != 0 || st.Size != 1 {
		t.Fatalf("the honest genesis did not replay: %+v; the test shows nothing", st.Rejected)
	}
	for kind, bad := range notValidPoints(t, signer) {
		for field, st := range map[string]*state.State{
			"roots":   replayGenesis([]any{[]byte(rootPub), bad}, []any{signer}),
			"signers": replayGenesis([]any{[]byte(rootPub)}, []any{signer, bad}),
		} {
			if len(st.Rejected) != 1 || st.Rejected[0].Reason != ReasonBadGenesis || st.Size != 0 {
				t.Errorf("a %s key in the genesis %s: %+v, size %d; want one bad-genesis and size 0",
					kind, field, st.Rejected, st.Size)
			}
		}
	}
}

// §3.1 item 2 and §5.2's enroll row: a request whose device_pk is not a valid
// point does not decode under §16.1, so the entry carrying it is `decode` --
// not `no-device-sig`, which is what the signature check alone made it
// (023r-c-ii). The honest request beside it enrolls.
func TestAnEnrollmentOfAKeyThatIsNotAValidPointIsDecode(t *testing.T) {
	anchor, entries, _ := loadCase(t, filepath.Join(vectorRoot(), "log"))
	before := Replay(anchor, entries)
	device := privateKey(t, "spare")
	devicePub := device.Public().(ed25519.PublicKey)
	request, err := enrollreq.New(anchor.Net, "admission-test", devicePub,
		bytes.Repeat([]byte{0x5a}, 32), 1_760_700_000, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := enrollreq.Sign(request, device); err != nil {
		t.Fatal(err)
	}
	honest, err := enrollreq.Encode(request)
	if err != nil {
		t.Fatal(err)
	}
	requests := map[string][]byte{"honest": honest}
	for kind, bad := range notValidPoints(t, devicePub) {
		decoded, err := cbor.Decode(honest)
		if err != nil {
			t.Fatal(err)
		}
		fields := decoded.(map[string]any)
		fields["device_pk"] = bad
		if requests[kind], err = cbor.Encode(fields); err != nil {
			t.Fatal(err)
		}
	}
	for kind, raw := range requests {
		env := &entry.Envelope{V: entry.Version, T: "enroll", Net: anchor.Net, TS: 1_760_700_000,
			Body: map[string]any{"request": raw}}
		signAs(t, env, before, "signer", "signer1", "signer2", "signer3")
		got := lastOutcome(Replay(anchor, appended(t, entries, env)), len(entries))
		want := ReasonDecode
		if kind == "honest" {
			want = ""
		}
		if got != want {
			t.Errorf("an enrollment of a %s device_pk: %q, want %q", kind, got, want)
		}
	}
}
