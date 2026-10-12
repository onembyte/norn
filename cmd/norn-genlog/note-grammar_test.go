package main

import (
	"crypto/ed25519"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	cosignpkg "github.com/onembyte/norn/internal/cosign"
	"github.com/onembyte/norn/internal/note"
)

func TestTheCarriageReturnVectorChangesOnlyOneSignedBodyByteAndSignsItExactly(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "vectors")
	dir := t.TempDir()
	if err := os.CopyFS(dir, os.DirFS(root)); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "checkpoints-bad", "44-carriage-return-in-signed-text.checkpoint")
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	honest, err := os.ReadFile(filepath.Join(root, "served", "checkpoint"))
	if err != nil {
		t.Fatal(err)
	}
	signers, err := witnessSigners(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeNoteGrammarCheckpoints(dir, string(honest), signers); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	body := mustBody(string(raw))
	if strings.Count(string(raw), "\r") != 1 || body != strings.TrimSuffix(mustBody(string(honest)), "\n")+"\r\n" {
		t.Fatal("the signed body must differ from the honest body by exactly one CR before the root LF")
	}
	// Frame the normalized temporary string only to extract the payloads; every
	// signature must verify over the original bytes, including the CR.
	_, sigs, err := note.Split(strings.ReplaceAll(string(raw), "\r", ""))
	if err != nil || len(sigs) != 4 {
		t.Fatalf("the vector must retain four signature lines: %v", err)
	}
	key, err := seedKey(root, "logkey")
	if err != nil {
		t.Fatal(err)
	}
	origin := strings.SplitN(body, "\n", 2)[0]
	if sigs[0].Name != origin || string(sigs[0].KeyID) != string(note.KeyID(origin, key.Public().(ed25519.PublicKey))) || !ed25519.Verify(key.Public().(ed25519.PublicKey), []byte(body), sigs[0].Sig) {
		t.Fatal("the log must sign the exact CR-bearing body")
	}
	for i, signer := range signers {
		sig := sigs[i+1]
		at := time.Unix(CosignedAt+int64(i*CosignSpread), 0)
		if sig.Name != signer.Name || string(sig.KeyID) != string(note.KeyIDFor(signer.Name, signer.Key.Public().(ed25519.PublicKey), note.AlgCosignature)) || !sig.IsCosignature() || binary.BigEndian.Uint64(sig.Sig[:8]) != uint64(at.Unix()) || !ed25519.Verify(signer.Key.Public().(ed25519.PublicKey), cosignpkg.Message(at, body), sig.Sig[8:]) {
			t.Fatalf("witness %s must cosign the exact body at its fixture timestamp", signer.Name)
		}
	}
}
