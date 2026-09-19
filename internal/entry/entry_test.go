package entry

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Written from SPEC.md §3, §4.0-§4.2. The 16 entry mirrors are the oracle:
// each carries the entry hash, leaf hash, preimage hash and byte length that
// this package must reproduce, and the keys that must verify its signatures.

type mirror struct {
	EntryHash      string `json:"entry_hash"`
	LeafHash       string `json:"leaf_hash"`
	PreimageSHA256 string `json:"preimage_sha256"`
	Size           int    `json:"size"`
}

type keyFile struct {
	Ed25519 map[string]struct {
		Seed   string `json:"seed"`
		Public string `json:"public"`
		Kid    string `json:"kid"`
	} `json:"ed25519"`
}

func vectorRoot() string { return filepath.Join("..", "..", "testdata", "vectors") }

func loadKeys(t *testing.T) keyFile {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(vectorRoot(), "keys.json"))
	if err != nil {
		t.Fatal(err)
	}
	var k keyFile
	if err := json.Unmarshal(raw, &k); err != nil {
		t.Fatal(err)
	}
	return k
}

func TestKidIsFirstEightBytesOfSHA256(t *testing.T) {
	for name, k := range loadKeys(t).Ed25519 {
		pk, err := hex.DecodeString(k.Public)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(pk)
		if want, got := k.Kid, Kid(pk); got != want {
			t.Errorf("%s: Kid = %s, want %s", name, got, want)
		}
		if got := hex.EncodeToString(sum[:8]); got != k.Kid {
			t.Errorf("%s: keys.json kid %s does not match SHA-256(pk)[:8] %s", name, k.Kid, got)
		}
	}
}

func TestSeedsDeriveTheirPublicKeys(t *testing.T) {
	for name, k := range loadKeys(t).Ed25519 {
		seed, _ := hex.DecodeString(k.Seed)
		want, _ := hex.DecodeString(k.Public)
		got := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
		if !bytes.Equal(got, want) {
			t.Errorf("%s: seed does not derive the recorded public key", name)
		}
	}
}

// Every entry in the catalogue must decode, re-encode byte-exact from the
// typed model, and reproduce all four hashes its mirror records.
func TestCatalogueEntriesMatchTheirMirrors(t *testing.T) {
	matches, err := filepath.Glob(filepath.Join(vectorRoot(), "entries", "*.cbor"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 16 {
		t.Fatalf("expected 16 catalogue entries, found %d", len(matches))
	}
	for _, path := range matches {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		env, err := Decode(raw)
		if err != nil {
			t.Errorf("%s: %v", path, err)
			continue
		}
		again, err := Encode(env)
		if err != nil {
			t.Errorf("%s: re-encode: %v", path, err)
			continue
		}
		if !bytes.Equal(raw, again) {
			t.Errorf("%s: re-encode from the typed model differs from the file", path)
		}

		var m mirror
		mirrorRaw, err := os.ReadFile(path[:len(path)-len(".cbor")] + ".json")
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(mirrorRaw, &m); err != nil {
			t.Fatal(err)
		}
		if got := hex.EncodeToString(EntryHash(raw)); got != m.EntryHash {
			t.Errorf("%s: entry hash %s, want %s", path, got, m.EntryHash)
		}
		if got := hex.EncodeToString(LeafHash(raw)); got != m.LeafHash {
			t.Errorf("%s: leaf hash %s, want %s", path, got, m.LeafHash)
		}
		pre, err := Preimage(env)
		if err != nil {
			t.Errorf("%s: preimage: %v", path, err)
			continue
		}
		sum := sha256.Sum256(pre)
		if got := hex.EncodeToString(sum[:]); got != m.PreimageSHA256 {
			t.Errorf("%s: preimage hash %s, want %s", path, got, m.PreimageSHA256)
		}
		if len(raw) != m.Size {
			t.Errorf("%s: size %d, want %d", path, len(raw), m.Size)
		}
	}
}

func TestEverySignatureInTheCatalogueVerifies(t *testing.T) {
	keys := loadKeys(t)
	byKid := map[string]ed25519.PublicKey{}
	for _, k := range keys.Ed25519 {
		pk, _ := hex.DecodeString(k.Public)
		byKid[k.Kid] = pk
	}

	matches, _ := filepath.Glob(filepath.Join(vectorRoot(), "entries", "*.cbor"))
	var verified int
	for _, path := range matches {
		raw, _ := os.ReadFile(path)
		env, err := Decode(raw)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if len(env.Sigs) == 0 {
			t.Errorf("%s: catalogue entries should be signed", path)
		}
		for _, sig := range env.Sigs {
			pk, ok := byKid[sig.Kid]
			if !ok {
				t.Errorf("%s: signature kid %s is not in keys.json", path, sig.Kid)
				continue
			}
			ok, err := Verify(env, sig, pk)
			if err != nil {
				t.Errorf("%s: %v", path, err)
				continue
			}
			if !ok {
				t.Errorf("%s: signature by %s does not verify", path, sig.Kid)
			}
			verified++
		}
	}
	if verified < 30 {
		t.Errorf("only %d signatures verified; expected the whole catalogue", verified)
	}
}

func TestPreimageIsPrefixedAndOmitsSigs(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(vectorRoot(), "entries", "15-note.cbor"))
	if err != nil {
		t.Skip("15-note not present")
	}
	env, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	pre, err := Preimage(env)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(pre, []byte(PreimagePrefix)) {
		t.Errorf("preimage does not start with %q", PreimagePrefix)
	}
	if bytes.Contains(pre[len(PreimagePrefix):], []byte("sigs")) {
		t.Error("preimage must not contain the sigs key")
	}
}

func TestSigningThenVerifyingRoundTrips(t *testing.T) {
	seed := bytes.Repeat([]byte{7}, 32)
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)

	env := &Envelope{V: 1, T: "note", Net: bytes.Repeat([]byte{1}, 16), TS: 1,
		Body: map[string]any{"text": "hello"}}
	if err := Sign(env, priv, "signer"); err != nil {
		t.Fatal(err)
	}
	if len(env.Sigs) != 1 || env.Sigs[0].Kid != Kid(pub) {
		t.Fatalf("unexpected signatures: %+v", env.Sigs)
	}
	ok, err := Verify(env, env.Sigs[0], pub)
	if err != nil || !ok {
		t.Fatalf("own signature must verify: ok=%v err=%v", ok, err)
	}
	env.Body["text"] = "tampered"
	ok, _ = Verify(env, env.Sigs[0], pub)
	if ok {
		t.Error("a tampered entry must not verify")
	}
}

func TestDecodeRejectsAnUnknownType(t *testing.T) {
	env := &Envelope{V: 1, T: "bogus", Net: bytes.Repeat([]byte{1}, 16), TS: 1,
		Body: map[string]any{}}
	if _, err := Encode(env); err == nil {
		t.Error("an unknown entry type should not encode")
	}
}

// The envelope-schema negatives in the log must be rejected here, by this
// package, rather than surviving to replay. Each names the rule it violates.
func TestSchemaNegativesAreRejectedAtDecode(t *testing.T) {
	cases := []string{
		"bad-unknown-envelope-key", // §4.1 closed schema
		"bad-missing-sigs",         // sigs is mandatory
		"bad-kid-format",           // kid field constraint
		"bad-unknown-role",         // role is a closed enum
		"bad-sig-length",           // sig is exactly 64 bytes
		"bad-unsorted-sigs",        // schema rule, not a codec rule (D-048)
	}
	for _, suffix := range cases {
		matches, err := filepath.Glob(filepath.Join(vectorRoot(), "log", "*-"+suffix+".cbor"))
		if err != nil {
			t.Fatal(err)
		}
		if len(matches) != 1 {
			t.Errorf("%s: expected exactly one vector, found %d", suffix, len(matches))
			continue
		}
		raw, err := os.ReadFile(matches[0])
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Decode(raw); err == nil {
			t.Errorf("%s: decoded successfully; the rule it names is unenforced", suffix)
		}
	}
}

// A forged signature must be well-formed at this layer -- it is replay's job to
// refuse to count it, not the decoder's. Getting this wrong would turn a
// `threshold` vector into a `decode` one.
func TestAForgedSignatureStillDecodes(t *testing.T) {
	matches, _ := filepath.Glob(filepath.Join(vectorRoot(), "log", "*-bad-forged-signer-sig.cbor"))
	if len(matches) != 1 {
		t.Skip("forged-signature vector not present")
	}
	raw, err := os.ReadFile(matches[0])
	if err != nil {
		t.Fatal(err)
	}
	env, err := Decode(raw)
	if err != nil {
		t.Fatalf("a forged signature must still be syntactically valid: %v", err)
	}
	keys := loadKeys(t)
	var verified bool
	for _, k := range keys.Ed25519 {
		if k.Kid != env.Sigs[0].Kid {
			continue
		}
		pk, _ := hex.DecodeString(k.Public)
		verified, _ = Verify(env, env.Sigs[0], pk)
	}
	if verified {
		t.Error("the forged signature verifies, so the vector proves nothing")
	}
}
