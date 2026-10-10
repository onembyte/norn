package proof

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/onembyte/norn/internal/cbor"
	"github.com/onembyte/norn/internal/cosign"
	"github.com/onembyte/norn/internal/note"
	"github.com/onembyte/norn/internal/refusal"
	"github.com/onembyte/norn/internal/tlog"
)

// --- 6.5l-vi-b-ii-c: the bundle check names its refusals (D-061) --------
//
// §10.1's second table: `bundle` for what Decode refuses, then the loop's
// checkpoint codes (`note` to `quorum`), then `inclusion`, then `binding`.
// Each case below differs from a valid, witnessed bundle in one thing, so the
// step it is named for is the first to fail; the precedence cases differ in
// two, and the earlier step must decide.
//
// Every refusal is still ErrProof -- the codes are added, never substituted --
// and what is wrong with the anchor rather than the bundle carries no code.

const witnessName = "norn-witness/w"

func witness() ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("norn/proof-test/witness"))
	return ed25519.NewKeyFromSeed(seed[:])
}

// witnessed is a valid bundle for index 7 of a 40-entry log, its checkpoint
// signed by the log and cosigned by the one witness the anchor's policy
// requires -- so a missing or forged cosignature is a refusal here, as it is
// under a real trust file.
type witnessed struct {
	entries [][]byte
	tree    *tlog.Tree
	key     ed25519.PrivateKey
	origin  string
	bundle  *Bundle
	anchor  Anchor
}

func newWitnessed(t *testing.T) *witnessed {
	t.Helper()
	entries, tree, key, origin := build(t, 40)
	w := &witnessed{entries: entries, tree: tree, key: key, origin: origin}
	p, err := tree.InclusionProof(7)
	if err != nil {
		t.Fatal(err)
	}
	if w.bundle, err = Build(deviceName, 7, entries[7], p, w.head(t, tree.Checkpoint(origin).Marshal())); err != nil {
		t.Fatal(err)
	}
	logKey := vkeyFor(origin, key)[0]
	public := witness().Public().(ed25519.PublicKey)
	w.anchor = Anchor{Origin: origin, LogKeys: []string{logKey}, Policy: "log " + logKey + "\n" +
		"witness " + witnessName + " " + note.CosignerVerifierKey(witnessName, public) + "\n" +
		"quorum " + witnessName + "\n"}
	return w
}

// head signs a body as the log and has the witness cosign it.
func (w *witnessed) head(t *testing.T, body string) string {
	t.Helper()
	return cosignAs(t, signAs(t, body, w.origin, w.key))
}

func signAs(t *testing.T, body, name string, key ed25519.PrivateKey) string {
	t.Helper()
	signed, err := note.Sign(body, name, key)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func cosignAs(t *testing.T, signed string) string {
	t.Helper()
	out, err := cosign.Append([]cosign.Signer{{Name: witnessName, Key: witness()}},
		cosign.At(time.Unix(1_760_000_000, 0)))(signed)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// forgeTheCosignature flips the last byte of the checkpoint's last line, the
// witness's, leaving its key id -- and so the witness it claims to be -- intact.
func forgeTheCosignature(t *testing.T, signed string) string {
	t.Helper()
	lines := strings.Split(strings.TrimSuffix(signed, "\n"), "\n")
	last := lines[len(lines)-1]
	cut := strings.LastIndex(last, " ") + 1
	raw, err := base64.StdEncoding.DecodeString(last[cut:])
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-1] ^= 0x01
	lines[len(lines)-1] = last[:cut] + base64.StdEncoding.EncodeToString(raw)
	return strings.Join(lines, "\n") + "\n"
}

type checkCase struct {
	name  string
	want  refusal.Code
	spoil func(t *testing.T, w *witnessed)
}

var checkRefusals = []checkCase{
	{"no signature line at all", refusal.Note, func(t *testing.T, w *witnessed) {
		w.bundle.Checkpoint = w.tree.Checkpoint(w.origin).Marshal()
	}},
	{"a key the anchor does not trust", refusal.LogSignature, func(t *testing.T, w *witnessed) {
		other := ed25519.NewKeyFromSeed(append(make([]byte, 31), 9))
		w.bundle.Checkpoint = cosignAs(t, signAs(t, w.tree.Checkpoint(w.origin).Marshal(), w.origin, other))
	}},
	{"a fourth body line, properly signed", refusal.Checkpoint, func(t *testing.T, w *witnessed) {
		w.bundle.Checkpoint = w.head(t, w.tree.Checkpoint(w.origin).Marshal()+"extension\n")
	}},
	{"the body names another log", refusal.Origin, func(t *testing.T, w *witnessed) {
		w.anchor.Origin = "norn/elsewhere"
	}},
	{"the witness's line does not verify", refusal.Cosignature, func(t *testing.T, w *witnessed) {
		w.bundle.Checkpoint = forgeTheCosignature(t, w.bundle.Checkpoint)
	}},
	{"nobody cosigned", refusal.Quorum, func(t *testing.T, w *witnessed) {
		w.bundle.Checkpoint = signAs(t, w.tree.Checkpoint(w.origin).Marshal(), w.origin, w.key)
	}},
	{"the index is outside the tree", refusal.Inclusion, func(t *testing.T, w *witnessed) {
		w.bundle.Index = 40
	}},
	{"the proof does not chain to the root", refusal.Inclusion, func(t *testing.T, w *witnessed) {
		w.bundle.Proof[0][0] ^= 0x01
	}},
	{"another entry under this entry's proof", refusal.Inclusion, func(t *testing.T, w *witnessed) {
		w.bundle.Entry = w.entries[8]
	}},
	{"the entry is about another device", refusal.Binding, func(t *testing.T, w *witnessed) {
		w.bundle.Device = "someone-else"
	}},
	// The entry is in the log -- the proof is genuine -- and is not an entry
	// at all. Rejected entries stay in a log, so this is reachable, and what
	// it fails is the binding: it is about no device, so not about this one.
	{"the proven entry does not decode", refusal.Binding, func(t *testing.T, w *witnessed) {
		entries := append([][]byte{[]byte("not an entry")}, w.entries[1:]...)
		tree, err := tlog.Build(entries)
		if err != nil {
			t.Fatal(err)
		}
		p, err := tree.InclusionProof(0)
		if err != nil {
			t.Fatal(err)
		}
		w.bundle.Index, w.bundle.Entry, w.bundle.Proof = 0, entries[0], p
		w.bundle.Checkpoint = w.head(t, tree.Checkpoint(w.origin).Marshal())
	}},
}

// Two faults; §10.1's earlier step decides.
var checkPrecedence = []checkCase{
	// The right key under another origin's name, and an anchor pinning that
	// other origin: a reader that compared origins first answers `origin`.
	// Cold gate run 11 found this ordering pinned only by a `says` string.
	{"log-signature before origin", refusal.LogSignature, func(t *testing.T, w *witnessed) {
		w.bundle.Checkpoint = cosignAs(t, signAs(t, w.tree.Checkpoint(w.origin).Marshal(), "norn/elsewhere", w.key))
		w.anchor.Origin = "norn/elsewhere"
	}},
	{"origin before cosignature", refusal.Origin, func(t *testing.T, w *witnessed) {
		w.bundle.Checkpoint = forgeTheCosignature(t, w.bundle.Checkpoint)
		w.anchor.Origin = "norn/elsewhere"
	}},
	{"quorum before inclusion", refusal.Quorum, func(t *testing.T, w *witnessed) {
		w.bundle.Checkpoint = signAs(t, w.tree.Checkpoint(w.origin).Marshal(), w.origin, w.key)
		w.bundle.Proof[0][0] ^= 0x01
	}},
	{"inclusion before binding", refusal.Inclusion, func(t *testing.T, w *witnessed) {
		w.bundle.Proof[0][0] ^= 0x01
		w.bundle.Device = "someone-else"
	}},
}

func TestEveryCheckRefusalCarriesItsSection10_1Code(t *testing.T) {
	if err := newWitnessed(t).bundle.Check(newWitnessed(t).anchor); err != nil {
		t.Fatalf("the unspoiled bundle does not check out: %v", err)
	}
	covered := map[refusal.Code]bool{}
	for _, c := range append(checkRefusals, checkPrecedence...) {
		t.Run(c.name, func(t *testing.T) {
			w := newWitnessed(t)
			c.spoil(t, w)
			err := w.bundle.Check(w.anchor)
			if err == nil {
				t.Fatal("accepted")
			}
			if got, _ := refusal.CodeOf(err); got != c.want {
				t.Errorf("refused as %q, want %q: %v", got, c.want, err)
			}
			if !errors.Is(err, ErrProof) {
				t.Errorf("no longer ErrProof: %v", err)
			}
		})
		covered[c.want] = true
	}
	// Every code a bundle's Check can give, by §10.1's second table.
	for _, code := range []refusal.Code{refusal.Note, refusal.LogSignature, refusal.Checkpoint,
		refusal.Origin, refusal.Cosignature, refusal.Quorum, refusal.Inclusion, refusal.Binding} {
		if !covered[code] {
			t.Errorf("no case reaches %q", code)
		}
	}
}

// Decode is §10.1's bundle step 1: whatever it refuses is `bundle`.
func TestEveryDecodeRefusalIsABundleRefusal(t *testing.T) {
	valid := func(t *testing.T) map[string]any {
		w := newWitnessed(t)
		raw, err := w.bundle.Encode()
		if err != nil {
			t.Fatal(err)
		}
		value, err := cbor.Decode(raw)
		if err != nil {
			t.Fatal(err)
		}
		return value.(map[string]any)
	}
	encode := func(t *testing.T, v any) []byte {
		raw, err := cbor.Encode(v)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	cases := map[string]func(t *testing.T) []byte{
		"not CBOR":           func(t *testing.T) []byte { return []byte{0xff} },
		"not a map":          func(t *testing.T) []byte { return encode(t, uint64(1)) },
		"an unknown key":     func(t *testing.T) []byte { m := valid(t); m["extra"] = uint64(1); return encode(t, m) },
		"a missing key":      func(t *testing.T) []byte { m := valid(t); delete(m, "device"); return encode(t, m) },
		"an unknown version": func(t *testing.T) []byte { m := valid(t); m["v"] = uint64(2); return encode(t, m) },
		"an empty device":    func(t *testing.T) []byte { m := valid(t); m["device"] = ""; return encode(t, m) },
		"a short proof hash": func(t *testing.T) []byte {
			m := valid(t)
			m["proof"] = []any{make([]byte, 31)}
			return encode(t, m)
		},
	}
	// The decoder's own error survives too: before codes, Decode returned it
	// as it was, and a caller may have tested for it.
	if _, err := Decode([]byte{0xff}); !errors.Is(err, cbor.ErrProfile) {
		t.Errorf("Decode lost the decoder's error, cbor.ErrProfile: %v", err)
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Decode(raw(t))
			if err == nil {
				t.Fatal("decoded")
			}
			if got, _ := refusal.CodeOf(err); got != refusal.Bundle {
				t.Errorf("refused as %q, want %q: %v", got, refusal.Bundle, err)
			}
			if !errors.Is(err, ErrProof) {
				t.Errorf("no longer ErrProof: %v", err)
			}
		})
	}
}

// What is wrong with the anchor is the reader's configuration, not the
// bundle: still ErrProof, and no code.
func TestABundleAnchorFaultCarriesNoCode(t *testing.T) {
	for name, spoil := range map[string]func(a *Anchor){
		"a log key that does not parse": func(a *Anchor) { a.LogKeys = []string{"not a key"} },
		"a policy that does not parse":  func(a *Anchor) { a.Policy = "quorum\n" },
		"a witness given a note key": func(a *Anchor) {
			public := witness().Public().(ed25519.PublicKey)
			a.Policy = "log " + a.LogKeys[0] + "\nwitness " + witnessName + " " +
				note.VerifierKey(witnessName, public) + "\nquorum " + witnessName + "\n"
		},
	} {
		t.Run(name, func(t *testing.T) {
			w := newWitnessed(t)
			spoil(&w.anchor)
			err := w.bundle.Check(w.anchor)
			if err == nil {
				t.Fatal("accepted")
			}
			if code, ok := refusal.CodeOf(err); ok {
				t.Errorf("reported as the bundle's %q: %v", code, err)
			}
			if !errors.Is(err, ErrProof) {
				t.Errorf("no longer ErrProof: %v", err)
			}
		})
	}
}

func TestBundleWitnessesSharingANoteNameKeepTheirOwnLabels(t *testing.T) {
	const name = "norn-witness/shared"
	seed := sha256.Sum256([]byte("norn/proof-test/second-witness"))
	second := ed25519.NewKeyFromSeed(seed[:])
	for _, tc := range []struct {
		name string
		keys []ed25519.PrivateKey
		tail string
		want bool
	}{
		{"both meet two", []ed25519.PrivateKey{witness(), second}, "group g 2 a b\nquorum g\n", true},
		{"b alone is short of two", []ed25519.PrivateKey{second}, "group g 2 a b\nquorum g\n", false},
		{"b cannot stand for a", []ed25519.PrivateKey{second}, "quorum a\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newWitnessed(t)
			w.anchor.Policy = fmt.Sprintf("witness a %s\nwitness b %s\n%s",
				note.CosignerVerifierKey(name, witness().Public().(ed25519.PublicKey)),
				note.CosignerVerifierKey(name, second.Public().(ed25519.PublicKey)), tc.tail)
			signed := signAs(t, w.tree.Checkpoint(w.origin).Marshal(), w.origin, w.key)
			var signers []cosign.Signer
			for _, key := range tc.keys {
				signers = append(signers, cosign.Signer{Name: name, Key: key})
			}
			var err error
			w.bundle.Checkpoint, err = cosign.Append(signers, cosign.At(time.Unix(1_760_000_000, 0)))(signed)
			if err != nil {
				t.Fatal(err)
			}
			err = w.bundle.Check(w.anchor)
			if tc.want {
				if err != nil {
					t.Fatalf("a and b were refused: %v", err)
				}
			} else if code, _ := refusal.CodeOf(err); code != refusal.Quorum {
				t.Fatalf("bundle refusal = %q (%v), want quorum", code, err)
			}
		})
	}
}
