package cosign

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	tdnote "github.com/transparency-dev/formats/note"
	sumdb "golang.org/x/mod/sumdb/note"

	"github.com/onembyte/norn/internal/note"
	"github.com/onembyte/norn/internal/refusal"
)

const origin = "norn/cosign-test"

func key(t *testing.T, name string) ed25519.PrivateKey {
	t.Helper()
	seed := sha256.Sum256([]byte("norn/cosign-test/" + name))
	return ed25519.NewKeyFromSeed(seed[:])
}

func public(t *testing.T, k ed25519.PrivateKey) ed25519.PublicKey {
	t.Helper()
	return k.Public().(ed25519.PublicKey)
}

// a checkpoint signed by the log, as norn-log serves one.
func signedCheckpoint(t *testing.T) (signed, body string) {
	t.Helper()
	body = origin + "\n90\nqxJq/1kPLQIyoVrLFJ7BQGF0vrVCJBEHkJmPZRJmOms=\n"
	logKey := key(t, "log")
	signed, err := note.Sign(body, origin, logKey)
	if err != nil {
		t.Fatal(err)
	}
	return signed, body
}

func logVerifier(t *testing.T) string {
	t.Helper()
	return note.VerifierKey(origin, public(t, key(t, "log")))
}

func witnessVerifier(t *testing.T, name string) string {
	t.Helper()
	return note.CosignerVerifierKey(name, public(t, key(t, name)))
}

// The one that matters: a cosignature produced by the package a real witness
// uses must verify here, and one produced here must verify there. Until 4.1a
// Norn could not have accepted either -- it encoded witness keys with
// algorithm 0x01 and refused any signature line longer than 68 bytes.
func TestAgreesWithTheEcosystem(t *testing.T) {
	signed, body := signedCheckpoint(t)
	name := "norn-witness/pi"

	// Their key, their signer, our verifier -- and our rendering of their
	// public key has to be the one their own verifier accepts, or the two
	// encodings have drifted.
	skey, theirVkey, err := sumdb.GenerateKey(rand.Reader, name)
	if err != nil {
		t.Fatal(err)
	}
	ourRendering := note.CosignerVerifierKey(name, publicFromVkey(t, theirVkey))
	if _, err := tdnote.NewVerifierForCosignatureV1(ourRendering); err != nil {
		t.Fatalf("the ecosystem rejects Norn's rendering of a witness key: %v", err)
	}

	signer, err := tdnote.NewSignerForCosignatureV1(skey)
	if err != nil {
		t.Fatal(err)
	}
	theirs, err := sumdb.Sign(&sumdb.Note{Text: body}, signer)
	if err != nil {
		t.Fatal(err)
	}
	// A log appends what a witness returns, so graft their line onto the
	// log-signed checkpoint exactly as norn-log will.
	got, err := Verify(signed+lastLine(t, string(theirs))+"\n", []string{ourRendering})
	if err != nil {
		t.Fatalf("a cosignature from the ecosystem's own signer does not verify: %v", err)
	}
	if len(got) != 1 || got[0].Name != name {
		t.Fatalf("cosignatures = %+v", got)
	}
	if got[0].Time.IsZero() {
		t.Error("a cosignature must carry the witness's time; it is the only clock there is")
	}

	// Our key, our signer, their verifier.
	ours := key(t, name)
	ourVkey := note.CosignerVerifierKey(name, public(t, ours))
	ourLine, err := Sign(body, name, ours, time.Unix(1_800_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := tdnote.NewVerifierForCosignatureV1(ourVkey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sumdb.Open([]byte(signed+ourLine+"\n"), sumdb.VerifierList(verifier)); err != nil {
		t.Fatalf("the ecosystem rejects a cosignature Norn made: %v", err)
	}
}

// publicFromVkey recovers the key bytes from a verifier key string.
func publicFromVkey(t *testing.T, vkey string) ed25519.PublicKey {
	t.Helper()
	parts := strings.SplitN(vkey, "+", 3)
	if len(parts) != 3 {
		t.Fatalf("not a verifier key: %q", vkey)
	}
	raw, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil || len(raw) != ed25519.PublicKeySize+1 {
		t.Fatalf("key data: %v", err)
	}
	return ed25519.PublicKey(raw[1:])
}

// lastLine returns the final signature line of a signed note.
func lastLine(t *testing.T, signed string) string {
	t.Helper()
	lines := strings.Split(strings.TrimRight(signed, "\n"), "\n")
	return lines[len(lines)-1]
}

// forgeKeyID relabels a signature line with another key's id, which is how a
// forged cosignature would arrive: the right name, the right shape, the wrong
// signature.
func forgeKeyID(t *testing.T, line, name string, public ed25519.PublicKey) string {
	t.Helper()
	_, blob, ok := strings.Cut(strings.TrimPrefix(line, note.SigPrefix), " ")
	if !ok {
		t.Fatalf("not a signature line: %q", line)
	}
	raw, err := base64.StdEncoding.DecodeString(blob)
	if err != nil {
		t.Fatal(err)
	}
	copy(raw[:4], note.KeyIDFor(name, public, note.AlgCosignature))
	return note.SignatureLine(name, raw)
}

// A cosigned checkpoint must still verify under the log key alone: the log's
// signature is what says this is the log, and the cosignatures are extra.
func TestACosignedCheckpointStillVerifiesUnderTheLogKey(t *testing.T) {
	signed, body := signedCheckpoint(t)
	name := "norn-witness/pi"
	line, err := Sign(body, name, key(t, name), time.Unix(1_800_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	cosigned := signed + line + "\n"

	text, err := note.Verify(cosigned, []string{logVerifier(t)})
	if err != nil {
		t.Fatalf("a cosigned checkpoint stopped verifying under the log key: %v", err)
	}
	if text != body {
		t.Error("the note body changed")
	}
}

func TestVerifyReturnsEveryTrustedWitness(t *testing.T) {
	signed, body := signedCheckpoint(t)
	var keys []string
	cosigned := signed
	for _, name := range []string{"norn-witness/pi", "norn-witness/vps"} {
		line, err := Sign(body, name, key(t, name), time.Unix(1_800_000_000, 0))
		if err != nil {
			t.Fatal(err)
		}
		cosigned += line + "\n"
		keys = append(keys, witnessVerifier(t, name))
	}

	got, err := Verify(cosigned, keys)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("cosignatures = %+v, want two", got)
	}
}

// A witness this network has never heard of is not an error: its line is
// somebody else's business.
func TestAnUnknownWitnessIsIgnored(t *testing.T) {
	signed, body := signedCheckpoint(t)
	line, err := Sign(body, "norn-witness/stranger", key(t, "norn-witness/stranger"),
		time.Unix(1_800_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}

	got, err := Verify(signed+line+"\n", []string{witnessVerifier(t, "norn-witness/pi")})
	if err != nil {
		t.Fatalf("an unknown witness should be ignored, not fatal: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("cosignatures = %+v, want none from this network's witnesses", got)
	}
}

// A forged cosignature must be an error, not a shrug: it is a line claiming a
// witness this network trusts said something it did not.
func TestAForgedCosignatureIsRefused(t *testing.T) {
	signed, body := signedCheckpoint(t)
	name := "norn-witness/pi"
	line, err := Sign(body, name, key(t, "impostor"), time.Unix(1_800_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	// Re-label the impostor's line with the real witness's key id.
	forged := forgeKeyID(t, line, name, public(t, key(t, name)))

	if _, err := Verify(signed+forged+"\n", []string{witnessVerifier(t, name)}); err == nil {
		t.Fatal("a cosignature that does not verify was accepted")
	}
}

// A witness key given as a plain note key is the mistake this checkpoint
// exists to fix, so it is named rather than quietly ignored.
func TestANoteKeyIsNotAWitnessKey(t *testing.T) {
	signed, _ := signedCheckpoint(t)
	plain := note.VerifierKey("norn-witness/pi", public(t, key(t, "norn-witness/pi")))

	_, err := Verify(signed, []string{plain})
	if err == nil {
		t.Fatal("a plain Ed25519 key was accepted as a witness key")
	}
	if !strings.Contains(err.Error(), "cosignature key") {
		t.Errorf("the error should say what is wrong: %v", err)
	}
}

// A log holding witness keys locally -- the fixture generator, a single-host
// lab -- appends one cosignature per witness to the head it just signed. That
// loop is the same everywhere it appears, so it lives here rather than being
// rewritten in each caller.
func TestAppendCosignsForEveryWitness(t *testing.T) {
	signed, _ := signedCheckpoint(t)
	names := []string{"norn-witness/pi", "norn-witness/vps"}

	var signers []Signer
	var keys []string
	for _, name := range names {
		signers = append(signers, Signer{Name: name, Key: key(t, name)})
		keys = append(keys, witnessVerifier(t, name))
	}

	cosigned, err := Append(signers, At(time.Unix(1_800_000_000, 0)))(signed)
	if err != nil {
		t.Fatal(err)
	}

	got, err := Verify(cosigned, keys)
	if err != nil {
		t.Fatalf("what Append produced does not verify: %v", err)
	}
	if len(got) != len(names) {
		t.Fatalf("cosignatures = %d, want %d", len(got), len(names))
	}
	// The log's own signature must survive untouched: cosigning adds lines,
	// it does not re-sign.
	if _, err := note.Verify(cosigned, []string{logVerifier(t)}); err != nil {
		t.Errorf("Append disturbed the log's signature: %v", err)
	}
	for _, c := range got {
		if !c.Time.Equal(time.Unix(1_800_000_000, 0)) {
			t.Errorf("%s cosigned at %v, want the instant asked for", c.Name, c.Time)
		}
	}
}

// SEC-027. §7: once a line's name and key id match a trusted key, its payload
// is exactly that key's length. A line under a listed witness's name and key
// id carrying 68 bytes -- a note signature's length, not a cosignature's --
// was skipped as "not a cosignature", so beside enough good lines the head
// was accepted. It is a line claiming that witness said something it did not
// say in any form a witness speaks, and §10.1 refuses it as `cosignature`, as
// the log side refuses the other length under its key (checkpoints-bad/24).
func TestAMatchedWitnessLineOfTheOtherLengthIsRefused(t *testing.T) {
	signed, body := signedCheckpoint(t)
	var keys []string
	cosigned := signed
	for _, name := range []string{"norn-witness/pi", "norn-witness/vps"} {
		line, err := Sign(body, name, key(t, name), time.Unix(1_800_000_000, 0))
		if err != nil {
			t.Fatal(err)
		}
		cosigned += line + "\n"
		keys = append(keys, witnessVerifier(t, name))
	}
	name := "norn-witness/pi"
	id := note.KeyIDFor(name, public(t, key(t, name)), note.AlgCosignature)
	short := note.SignatureLine(name, append(append([]byte(nil), id...), make([]byte, ed25519.SignatureSize)...))

	got, err := Verify(cosigned+short+"\n", keys)
	if err == nil {
		t.Fatalf("a 68-byte line under a listed witness's name and key id was skipped; got %+v", got)
	}
	if code, _ := refusal.CodeOf(err); code != refusal.Cosignature {
		t.Errorf("refused as %q, want %q: %v", code, refusal.Cosignature, err)
	}
}
