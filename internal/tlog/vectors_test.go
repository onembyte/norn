package tlog

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/onembyte/norn/internal/cbor"
	"github.com/onembyte/norn/internal/note"
)

// Cold-model gate run 5, defect G2. Until `04-forged-log-signature` shipped,
// every checkpoint in the suite was valid, and a verifier that skipped §10's
// first step -- "verify log signature" -- reproduced the whole manifest. The
// refusals that did exist were all reachable without cryptography: a missing
// signature line, a key id nobody trusts, a note for another origin.

func vectorRoot() string { return filepath.Join("..", "..", "testdata", "vectors") }

func read(t *testing.T, parts ...string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(append([]string{vectorRoot()}, parts...)...))
	if err != nil {
		t.Fatalf("the vector that makes log-signature verification load-bearing is missing: %v", err)
	}
	return string(raw)
}

func logVerifierKey(t *testing.T, origin string) string {
	t.Helper()
	var keys struct {
		Ed25519 map[string]struct {
			Seed string `json:"seed"`
		} `json:"ed25519"`
	}
	if err := json.Unmarshal([]byte(read(t, "keys.json")), &keys); err != nil {
		t.Fatal(err)
	}
	seed, err := hex.DecodeString(keys.Ed25519["logkey"].Seed)
	if err != nil || len(seed) != ed25519.SeedSize {
		t.Fatal("keys.json has no usable logkey seed")
	}
	return note.VerifierKey(origin, ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey))
}

func originOf(signed string) string {
	line, _, _ := strings.Cut(signed, "\n")
	return line
}

func TestTheForgedCheckpointDiffersOnlyInItsSignature(t *testing.T) {
	honest := read(t, "served", "checkpoint")
	forged := read(t, "checkpoints-bad", "04-forged-log-signature.checkpoint")
	origin := originOf(honest)
	keys := []string{logVerifierKey(t, origin)}

	// The control: the honest checkpoint verifies.
	if _, err := Verify(honest, keys); err != nil {
		t.Fatalf("the served checkpoint does not verify: %v", err)
	}

	// The claim: the forged one does not, and nothing else distinguishes them.
	if _, err := Verify(forged, keys); err == nil {
		t.Fatal("a checkpoint whose log signature was tampered with verified")
	}
	honestBody, honestSigs, err := note.Split(honest)
	if err != nil {
		t.Fatal(err)
	}
	forgedBody, forgedSigs, err := note.Split(forged)
	if err != nil {
		t.Fatalf("the forged checkpoint does not even parse, so it tests parsing, not signing: %v", err)
	}
	if honestBody != forgedBody {
		t.Error("the two checkpoints claim different trees; refusing the forged one would " +
			"prove nothing about signature checking")
	}
	if originOf(forged) != origin {
		t.Error("the forged checkpoint names another origin, which a verifier can refuse " +
			"without cryptography")
	}

	// Same signer, same key id: only the signature bytes differ.
	honestSig := signatureBy(honestSigs, origin)
	forgedSig := signatureBy(forgedSigs, origin)
	if honestSig == nil || forgedSig == nil {
		t.Fatal("one of the checkpoints carries no signature line from the log")
	}
	if string(honestSig.KeyID) != string(forgedSig.KeyID) {
		t.Error("the forged line carries a different key id, so a verifier that only compares " +
			"key ids would already refuse it")
	}
	if string(honestSig.Sig) == string(forgedSig.Sig) {
		t.Error("the signature bytes are identical; nothing was forged")
	}
}

func signatureBy(sigs []note.Signature, name string) *note.Signature {
	for i := range sigs {
		if sigs[i].Name == name {
			return &sigs[i]
		}
	}
	return nil
}

// The limit a decoder enforces and the limit the log can serve are the same
// number, or a spec-valid entry exists that cannot be published. §4.0 said
// 65536 and §6's uint16 bundles top out at 65535, so that entry existed.
func TestTheProfileLimitIsWhatABundleCanCarry(t *testing.T) {
	if cbor.MaxEntryBytes != MaxBundleEntryBytes {
		t.Errorf("a decoder accepts entries up to %d bytes but a bundle can frame only %d: "+
			"an entry between the two is valid and unservable",
			cbor.MaxEntryBytes, MaxBundleEntryBytes)
	}
}

// Cold-model gate run 12, defect D8. `24` is the log's own line with one
// padding bit set: a decoder that ignores padding bits reads the honest 68
// bytes, so the head verified and had two byte forms. The claim is that the
// line decodes leniently to exactly the honest payload, and that §7's framing
// refuses it before any signature is checked.
func TestThePadBitCheckpointDecodesToTheHonestSignature(t *testing.T) {
	honest := read(t, "served", "checkpoint")
	padded := read(t, "checkpoints-bad", "24-signature-non-canonical-pad-bits.checkpoint")
	origin := originOf(honest)

	_, honestSigs, err := note.Split(honest)
	if err != nil {
		t.Fatal(err)
	}
	want := signatureBy(honestSigs, origin)
	if want == nil {
		t.Fatal("the served checkpoint carries no line from the log")
	}
	var lenient []byte
	var lines int
	for _, line := range strings.Split(strings.TrimRight(padded, "\n"), "\n") {
		blob, ok := strings.CutPrefix(line, note.SigPrefix+origin+" ")
		if !ok {
			continue
		}
		lines++
		raw, err := base64.StdEncoding.DecodeString(blob)
		if err != nil {
			t.Fatalf("a lenient decoder refuses the line, so the case is not about padding bits: %v", err)
		}
		if base64.StdEncoding.EncodeToString(raw) == blob {
			t.Fatal("the line is its payload's own encoding; nothing is non-canonical")
		}
		lenient = raw
	}
	if lines != 1 {
		t.Fatalf("%d lines from the log; the case rewrites exactly one", lines)
	}
	if !bytes.Equal(lenient, append(append([]byte{}, want.KeyID...), want.Sig...)) {
		t.Fatal("leniently decoded, the line is not the honest payload, so refusing it proves nothing about padding bits")
	}
	if _, _, err := note.Split(padded); err == nil ||
		!strings.Contains(err.Error(), "not the encoding of its payload") {
		t.Errorf("§7 holds a line to its exact encoding; got %v", err)
	}
}
