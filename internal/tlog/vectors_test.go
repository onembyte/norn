package tlog

import (
	"crypto/ed25519"
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
