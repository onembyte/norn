package tlog_test

import (
	"crypto/ed25519"
	"strings"
	"testing"

	tdlog "github.com/transparency-dev/formats/log"
	upstreamnote "golang.org/x/mod/sumdb/note"

	"github.com/onembyte/norn/internal/note"
	"github.com/onembyte/norn/internal/tlog"
)

// PLAN.md ground rule 3, tested: if the transparency ecosystem cannot read a
// Norn checkpoint unchanged, the design is wrong.
//
// github.com/transparency-dev/formats/log is the package witnesses use to
// parse and verify checkpoints -- 6 modules, against 80 for the full witness
// binary, whose HTTP handler and storage are the witness's business rather
// than Norn's format. What is proven here is the part that is Norn's: that a
// checkpoint we sign is a valid tlog-checkpoint the ecosystem's own parser
// accepts, with the origin, size and root it reads back matching ours.

func signedCheckpoint(t *testing.T, origin string, size int64) (string, string, tlog.Checkpoint) {
	t.Helper()
	entries := make([][]byte, 0, size)
	for i := int64(0); i < size; i++ {
		entries = append(entries, []byte{byte(i), byte(i >> 8)})
	}
	tree, err := tlog.Build(entries)
	if err != nil {
		t.Fatal(err)
	}
	cp := tree.Checkpoint(origin)

	seed := make([]byte, 32)
	seed[0] = 7
	key := ed25519.NewKeyFromSeed(seed)
	signed, err := cp.Sign(key)
	if err != nil {
		t.Fatal(err)
	}
	return signed, note.VerifierKey(origin, key.Public().(ed25519.PublicKey)), cp
}

func TestTheEcosystemParsesOurSignedCheckpoint(t *testing.T) {
	origin := "norn/nzxxe3rnorsxg5domv2c2mbqge"
	signed, vkey, cp := signedCheckpoint(t, origin, 91)

	v, err := upstreamnote.NewVerifier(vkey)
	if err != nil {
		t.Fatalf("upstream rejects our checkpoint verifier key: %v", err)
	}
	parsed, _, _, err := tdlog.ParseCheckpoint([]byte(signed), origin, v)
	if err != nil {
		t.Fatalf("transparency-dev/formats cannot parse our checkpoint: %v", err)
	}
	if parsed.Origin != cp.Origin {
		t.Errorf("origin: got %q, want %q", parsed.Origin, cp.Origin)
	}
	if int64(parsed.Size) != cp.Size {
		t.Errorf("size: got %d, want %d", parsed.Size, cp.Size)
	}
	if string(parsed.Hash) != string(cp.Root[:]) {
		t.Errorf("root hash disagreement:\n got %x\nwant %x", parsed.Hash, cp.Root)
	}
}

func TestTheEcosystemRejectsACheckpointSignedByTheWrongKey(t *testing.T) {
	origin := "norn/nzxxe3rnorsxg5domv2c2mbqge"
	signed, _, _ := signedCheckpoint(t, origin, 10)

	other := ed25519.NewKeyFromSeed(append(make([]byte, 31), 9))
	vkey := note.VerifierKey(origin, other.Public().(ed25519.PublicKey))
	v, err := upstreamnote.NewVerifier(vkey)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := tdlog.ParseCheckpoint([]byte(signed), origin, v); err == nil {
		t.Error("a checkpoint signed by an untrusted key must be rejected")
	}
}

func TestTheEcosystemRejectsAnOriginMismatch(t *testing.T) {
	signed, vkey, _ := signedCheckpoint(t, "norn/one", 10)
	v, err := upstreamnote.NewVerifier(vkey)
	if err != nil {
		t.Fatal(err)
	}
	// A witness is configured with the origin it expects; a checkpoint for a
	// different log must not be accepted just because the signature is valid.
	if _, _, _, err := tdlog.ParseCheckpoint([]byte(signed), "norn/two", v); err == nil {
		t.Error("an origin mismatch must be rejected")
	}
}

func TestOurVerifierAcceptsWhatWeSign(t *testing.T) {
	origin := "norn/roundtrip"
	signed, vkey, cp := signedCheckpoint(t, origin, 42)
	got, err := tlog.Verify(signed, []string{vkey})
	if err != nil {
		t.Fatal(err)
	}
	if got != cp {
		t.Errorf("round trip lost information: %+v vs %+v", got, cp)
	}
}

func TestATamperedSizeBreaksTheSignature(t *testing.T) {
	origin := "norn/tamper"
	signed, vkey, _ := signedCheckpoint(t, origin, 42)
	tampered := strings.Replace(signed, "\n42\n", "\n43\n", 1)
	if tampered == signed {
		t.Fatal("the size line was not found to tamper with")
	}
	if _, err := tlog.Verify(tampered, []string{vkey}); err == nil {
		t.Error("altering the size must break the signature")
	}
	v, _ := upstreamnote.NewVerifier(vkey)
	if _, _, _, err := tdlog.ParseCheckpoint([]byte(tampered), origin, v); err == nil {
		t.Error("the ecosystem must reject it too")
	}
}
