package cosign

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/onembyte/norn/internal/note"
)

// Cold-model gate run 5, defect G2. A forged cosignature is the only
// construction that tells a verifier apart from one that counts lines: every
// other refusal in the suite -- too few, none, a stranger -- is reachable
// without ever calling Ed25519. Run 5's `NORN_COSIG_BLIND` variant passed all
// 597 checks because this vector did not exist.

func vectorRoot() string { return filepath.Join("..", "..", "testdata", "vectors") }

func witnessKeys(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(vectorRoot(), "keys.json"))
	if err != nil {
		t.Fatal(err)
	}
	var keys struct {
		Ed25519 map[string]struct {
			Seed string `json:"seed"`
		} `json:"ed25519"`
	}
	if err := json.Unmarshal(raw, &keys); err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, name := range []string{"pi", "vps", "friend"} {
		seed, err := hex.DecodeString(keys.Ed25519["witness-"+name].Seed)
		if err != nil || len(seed) != ed25519.SeedSize {
			t.Fatalf("keys.json has no usable witness-%s seed", name)
		}
		public := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
		out = append(out, note.CosignerVerifierKey("norn-witness/"+name, public))
	}
	return out
}

func countCosignatureLines(signed string) int {
	var n int
	for _, line := range strings.Split(signed, "\n") {
		if strings.HasPrefix(line, "— norn-witness/") {
			n++
		}
	}
	return n
}

func TestTheForgedCosignatureIsCountedButNotVerified(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(vectorRoot(), "checkpoints-bad", "08-forged-cosignature.checkpoint"))
	if err != nil {
		t.Fatalf("the vector that makes cosignature verification load-bearing is missing: %v", err)
	}
	signed := string(raw)

	// What a verifier that counts lines sees: two witnesses the policy names.
	if got := countCosignatureLines(signed); got != 2 {
		t.Fatalf("the vector carries %d cosignature lines, want 2 -- it no longer meets a "+
			"threshold of two by counting alone", got)
	}
	// What a verifier that checks signatures sees: a refusal. §10 is strict
	// here -- "every cosignature by a witness the policy names must verify" --
	// so a line that does not verify condemns the checkpoint rather than
	// merely failing to count towards the quorum.
	valid, err := Verify(signed, witnessKeys(t))
	if err == nil {
		t.Fatalf("a checkpoint carrying a forged cosignature verified, yielding %d cosignatures; "+
			"§10 requires it to be refused", len(valid))
	}
	if !strings.Contains(err.Error(), "norn-witness/vps") {
		t.Errorf("the refusal should name the witness whose line does not verify: %v", err)
	}
	if len(valid) != 0 {
		t.Errorf("a refused checkpoint still yielded %d cosignatures", len(valid))
	}
}

// The distinction the vector exists to make, stated as a test: the forged
// checkpoint and the honest one are separated by signature verification and by
// nothing else a verifier might do instead.
func TestCountingLinesCannotTellTheTwoApart(t *testing.T) {
	honest, err := os.ReadFile(filepath.Join(vectorRoot(), "served", "checkpoint"))
	if err != nil {
		t.Fatal(err)
	}
	forged, err := os.ReadFile(filepath.Join(vectorRoot(), "checkpoints-bad", "08-forged-cosignature.checkpoint"))
	if err != nil {
		t.Fatal(err)
	}
	honestBody, _, err := note.Split(string(honest))
	if err != nil {
		t.Fatal(err)
	}
	forgedBody, _, err := note.Split(string(forged))
	if err != nil {
		t.Fatal(err)
	}
	if honestBody != forgedBody {
		t.Error("the two checkpoints disagree about the tree, so refusing the forged one " +
			"proves nothing about signature checking")
	}
	if countCosignatureLines(string(forged)) < 2 {
		t.Error("the forged checkpoint carries too few cosignature lines to meet the " +
			"threshold by counting")
	}
}

// The control. Without it, a Verify that refused everything would look the same.
func TestTheServedCheckpointsCosignaturesAllVerify(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(vectorRoot(), "served", "checkpoint"))
	if err != nil {
		t.Fatal(err)
	}
	valid, err := Verify(string(raw), witnessKeys(t))
	if err != nil {
		t.Fatalf("the served checkpoint's cosignatures do not verify: %v", err)
	}
	if len(valid) != 3 {
		t.Errorf("%d of 3 cosignatures verified on the honest checkpoint", len(valid))
	}
}
