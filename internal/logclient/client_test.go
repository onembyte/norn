package logclient

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/onembyte/norn/internal/cosign"
	"github.com/onembyte/norn/internal/note"
	"github.com/onembyte/norn/internal/replay"
	"github.com/onembyte/norn/internal/state"
	"github.com/onembyte/norn/internal/tlog"
	"github.com/onembyte/norn/internal/tlogstore"
)

// The verifier loop of SPEC §10, end to end: take the fixture's own entries,
// write them into a real served tile directory, read them back through the
// same interface a node would use, and require the state that comes out to be
// state.json byte for byte.
//
// Until now replay was fed entries from a list. This is the first test where
// they arrive the way they actually will: as tiles and bundles on a disk
// someone else controls.

func vectorRoot() string { return filepath.Join("..", "..", "testdata", "vectors") }

type manifest struct {
	Anchor struct {
		Net         string `json:"net"`
		GenesisHash string `json:"genesis_hash"`
	} `json:"anchor"`
	Entries []struct {
		Name string `json:"name"`
	} `json:"entries"`
}

func loadFixture(t *testing.T) (replay.Anchor, [][]byte) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(vectorRoot(), "log", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	net, _ := hex.DecodeString(m.Anchor.Net)
	genesis, _ := hex.DecodeString(m.Anchor.GenesisHash)
	entries := make([][]byte, 0, len(m.Entries))
	for _, e := range m.Entries {
		b, err := os.ReadFile(filepath.Join(vectorRoot(), "log", e.Name+".cbor"))
		if err != nil {
			t.Fatal(err)
		}
		entries = append(entries, b)
	}
	return replay.Anchor{Net: net, GenesisHash: genesis}, entries
}

// logKey is the key this test's log signs its checkpoints with. It is derived,
// not random, so a failure is reproducible.
func logKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	seed := sha256.Sum256([]byte("norn/logclient-test/log-key"))
	return ed25519.NewKeyFromSeed(seed[:])
}

func verifierKey(t *testing.T, key ed25519.PrivateKey, origin string) string {
	t.Helper()
	return note.VerifierKey(origin, key.Public().(ed25519.PublicKey))
}

// servedLog writes the fixture into a tile directory and returns its path.
func servedLog(t *testing.T) (string, Anchor) {
	t.Helper()
	inner, entries := loadFixture(t)
	dir := t.TempDir()
	key := logKey(t)
	// A log with a witness, because a verifier checks the quorum: every test
	// below that expects a *healthy* log needs one that a correctly
	// configured node would actually accept.
	store, err := tlogstore.Open(dir, "norn/test", key, tlogstore.WithCosigner(
		tlogstore.CosignerFunc(cosign.Append(witnesses(t), cosign.At(cosignedAt)))))
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range entries {
		if _, err := store.Append(raw); err != nil {
			t.Fatal(err)
		}
	}
	return dir, Anchor{Anchor: inner, LogKeys: []string{verifierKey(t, key, "norn/test")},
		Policy: policyOver(t, "norn/test", witnessNames, 2)}
}

// This package's logs are cosigned by three witnesses, of which the policy
// requires two -- the same shape as the shipped fixture, so the quorum tests
// exercise a real threshold rather than a one-witness special case.
var witnessNames = []string{"pi", "vps", "friend"}

const cosignedAtUnix = 1_760_003_600

var cosignedAt = time.Unix(cosignedAtUnix, 0)

func witnessKey(t *testing.T, name string) ed25519.PrivateKey {
	t.Helper()
	seed := sha256.Sum256([]byte("norn/logclient-test/witness/" + name))
	return ed25519.NewKeyFromSeed(seed[:])
}

func witnesses(t *testing.T) []cosign.Signer {
	t.Helper()
	var out []cosign.Signer
	for _, name := range witnessNames {
		out = append(out, cosign.Signer{Name: "norn-witness/" + name, Key: witnessKey(t, name)})
	}
	return out
}

// policyOver writes the policy an anchor carries: the log, every witness, and
// a threshold group over them.
func policyOver(t *testing.T, origin string, names []string, threshold int) string {
	t.Helper()
	var b strings.Builder
	fmt.Fprintf(&b, "log %s\n", verifierKey(t, logKey(t), origin))
	for _, name := range names {
		public := witnessKey(t, name).Public().(ed25519.PublicKey)
		fmt.Fprintf(&b, "witness norn-witness/%s %s\n", name,
			note.CosignerVerifierKey("norn-witness/"+name, public))
	}
	fmt.Fprintf(&b, "group all %d", threshold)
	for _, name := range names {
		fmt.Fprintf(&b, " norn-witness/%s", name)
	}
	b.WriteString("\nquorum all\n")
	return b.String()
}

func TestVerifyOverAServedDirectoryReproducesStateJSON(t *testing.T) {
	dir, anchor := servedLog(t)

	result, err := Verify(Dir(dir), anchor)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	got, err := result.State.MarshalCanonical()
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(filepath.Join(vectorRoot(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("state from a served log differs from state.json (%d vs %d bytes)",
			len(got), len(want))
	}
	_, entries := loadFixture(t)
	if result.Checkpoint.Size != int64(len(entries)) {
		t.Errorf("checkpoint size %d, want %d", result.Checkpoint.Size, len(entries))
	}
	if int(result.State.Size) != len(entries) {
		t.Errorf("replayed size %d, want %d", result.State.Size, len(entries))
	}
}

func TestVerifyChecksTheHeadAgainstTheEntries(t *testing.T) {
	dir, anchor := servedLog(t)

	// A log operator who serves a checkpoint that does not describe the
	// entries it also serves must be caught -- that is the whole point of the
	// tree head being in the checkpoint.
	cpPath := filepath.Join(dir, "checkpoint")
	raw, err := os.ReadFile(cpPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(raw, []byte("\n"))
	lines[2] = []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	if err := os.WriteFile(cpPath, bytes.Join(lines, []byte("\n")), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(Dir(dir), anchor); err == nil {
		t.Error("a checkpoint whose root does not match the entries must be refused")
	}
}

func TestVerifyRefusesATamperedEntry(t *testing.T) {
	dir, anchor := servedLog(t)

	// Flip one byte inside a served entry bundle. The entries no longer hash
	// to the head the checkpoint advertises, so the verifier must refuse
	// rather than replay whatever it was handed.
	bundle := filepath.Join(dir, "tile", "entries", "000")
	raw, err := os.ReadFile(bundle)
	if err != nil {
		matches, _ := filepath.Glob(filepath.Join(dir, "tile", "entries", "000.p", "*"))
		if len(matches) == 0 {
			t.Fatal("no entry bundle found to tamper with")
		}
		bundle = matches[0]
		if raw, err = os.ReadFile(bundle); err != nil {
			t.Fatal(err)
		}
	}
	raw[len(raw)/2] ^= 0x01
	if err := os.WriteFile(bundle, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(Dir(dir), anchor); err == nil {
		t.Error("a tampered entry bundle must be refused")
	}
}

func TestVerifyRefusesAWrongAnchor(t *testing.T) {
	dir, anchor := servedLog(t)
	anchor.GenesisHash = make([]byte, 32)

	result, err := Verify(Dir(dir), anchor)
	if err != nil {
		return // refusing outright is also correct
	}
	// If it returns a state, that state must be the aborted one -- never a
	// populated state built on a genesis the anchor does not pin.
	if len(result.State.Rejected) != 1 || result.State.Rejected[0].Reason != "bad-genesis" {
		t.Errorf("a wrong anchor must abort, got %+v", result.State.Rejected)
	}
	if len(result.State.Devices) != 0 {
		t.Error("a wrong anchor must not yield devices")
	}
}

func TestVerifyRefusesAMissingBundle(t *testing.T) {
	dir, anchor := servedLog(t)
	_ = os.RemoveAll(filepath.Join(dir, "tile", "entries"))
	if _, err := Verify(Dir(dir), anchor); err == nil {
		t.Error("a log that advertises entries it cannot serve must be refused")
	}
}

func TestSurvivingARestartStillVerifies(t *testing.T) {
	dir, anchor := servedLog(t)
	before, err := Verify(Dir(dir), anchor)
	if err != nil {
		t.Fatal(err)
	}
	// Reopen the store, append nothing, and verify again: a restart must
	// neither lose entries nor reorder them. It is reopened with the same
	// witnesses it had, because that is what restarting a log does -- and a
	// restart that dropped them would republish an uncosigned head, which is
	// its own hazard and the reason norn-log says so on startup.
	if _, err := tlogstore.Open(dir, "norn/test", logKey(t), tlogstore.WithCosigner(
		tlogstore.CosignerFunc(cosign.Append(witnesses(t), cosign.At(cosignedAt))))); err != nil {
		t.Fatal(err)
	}
	after, err := Verify(Dir(dir), anchor)
	if err != nil {
		t.Fatalf("verify after restart: %v", err)
	}
	if after.Checkpoint != before.Checkpoint {
		t.Errorf("restart changed the checkpoint: %+v -> %+v", before.Checkpoint, after.Checkpoint)
	}
	beforeJSON, _ := before.State.MarshalCanonical()
	afterJSON, _ := after.State.MarshalCanonical()
	if !bytes.Equal(beforeJSON, afterJSON) {
		t.Error("restart changed the replayed state")
	}
}

// These four cases are the defect this file exists to keep fixed.
//
// Until 2.9e-i the verifier never looked at `norn.trust.log_key`: it parsed an
// unsigned `checkpoint` file and proved only that the served entries hashed to
// the head *in that same file*. Internally consistent, signed by nobody. §10
// step 2 says "verify log signature", and nothing did.

func TestAnUnsignedCheckpointIsRefused(t *testing.T) {
	dir, anchor := servedLog(t)
	cp, err := os.ReadFile(filepath.Join(dir, "checkpoint"))
	if err != nil {
		t.Fatal(err)
	}
	// The old format: the note's text with its signature lines removed.
	text, _, err := note.Split(string(cp))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "checkpoint"), []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(Dir(dir), anchor); err == nil {
		t.Fatal("verified a checkpoint nobody signed")
	}
}

func TestACheckpointSignedByAnotherKeyIsRefused(t *testing.T) {
	dir, anchor := servedLog(t)

	seed := sha256.Sum256([]byte("norn/logclient-test/impostor"))
	impostor := ed25519.NewKeyFromSeed(seed[:])
	cp, err := os.ReadFile(filepath.Join(dir, "checkpoint"))
	if err != nil {
		t.Fatal(err)
	}
	text, _, err := note.Split(string(cp))
	if err != nil {
		t.Fatal(err)
	}
	forged, err := note.Sign(text, "norn/test", impostor)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "checkpoint"), []byte(forged), 0o644); err != nil {
		t.Fatal(err)
	}

	// The tree is untouched, so every entry still hashes to this exact head:
	// only the signature separates this log from the real one.
	if _, err := Verify(Dir(dir), anchor); err == nil {
		t.Fatal("verified a head signed by a key the anchor does not trust")
	}
}

func TestACheckpointForAnotherOriginIsRefused(t *testing.T) {
	dir, anchor := servedLog(t)
	key := logKey(t)
	cp, err := os.ReadFile(filepath.Join(dir, "checkpoint"))
	if err != nil {
		t.Fatal(err)
	}
	text, _, err := note.Split(string(cp))
	if err != nil {
		t.Fatal(err)
	}
	// The right key, signing the right bytes, under the wrong name. §9.1 binds
	// the note name to the origin precisely so this fails.
	elsewhere, err := note.Sign(text, "norn/elsewhere", key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "checkpoint"), []byte(elsewhere), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(Dir(dir), anchor); err == nil {
		t.Fatal("verified a checkpoint signed under another origin's name")
	}
}

func TestAnAnchorWithoutALogKeyIsRefused(t *testing.T) {
	dir, anchor := servedLog(t)
	anchor.LogKeys = nil
	_, err := Verify(Dir(dir), anchor)
	if err == nil {
		t.Fatal("verified with nothing to check the signature against")
	}
	if !strings.Contains(err.Error(), "log key") {
		t.Errorf("the error should say what is missing: %v", err)
	}
}

// An anchor missing its genesis pin is a caller mistake that reads like a
// healthy empty network: every entry is refused `bad-genesis`, replay aborts,
// and the result is a state with no devices and no error. It cost an afternoon
// in 2.9e-ii, so it is now a refusal.
func TestAnAnchorWithoutAGenesisPinIsRefused(t *testing.T) {
	dir, anchor := servedLog(t)
	anchor.GenesisHash = nil
	_, err := Verify(Dir(dir), anchor)
	if err == nil {
		t.Fatal("verified against an anchor that pins no genesis entry")
	}
	if !strings.Contains(err.Error(), "genesis") {
		t.Errorf("the error should name what is missing: %v", err)
	}
}

// The Phase 2 gate says: flip one byte in a tile, and the verifier refuses.
// Until 2.10 it did not — the verifier never fetched a hash tile at all, so a
// log could serve corrupt tiles and the one program guaranteed to be looking
// said nothing. Every monitor and witness fetching proofs from that log would
// have got wrong hashes.
func TestAFlippedByteInAHashTileIsRefused(t *testing.T) {
	dir, anchor := servedLog(t)

	var tilePath string
	err := filepath.WalkDir(filepath.Join(dir, "tile"), func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && !strings.Contains(p, "entries") && tilePath == "" {
			tilePath = p
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if tilePath == "" {
		t.Fatal("the served log has no hash tiles")
	}

	raw, err := os.ReadFile(tilePath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(Dir(dir), anchor); err != nil {
		t.Fatalf("the untouched log must verify first: %v", err)
	}

	flipped := append([]byte(nil), raw...)
	flipped[10] ^= 0xff
	if err := os.WriteFile(tilePath, flipped, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(Dir(dir), anchor); err == nil {
		t.Fatal("a corrupted hash tile was accepted")
	}
}

func TestAMissingHashTileIsRefused(t *testing.T) {
	dir, anchor := servedLog(t)
	var tilePath string
	_ = filepath.WalkDir(filepath.Join(dir, "tile"), func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && !strings.Contains(p, "entries") && tilePath == "" {
			tilePath = p
		}
		return nil
	})
	if tilePath == "" {
		t.Fatal("the served log has no hash tiles")
	}
	if err := os.Remove(tilePath); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(Dir(dir), anchor); err == nil {
		t.Fatal("a log missing a tile tlog-tiles requires was accepted")
	}
}

// The writer and the verifier must agree about what a tile contains, which is
// why the computation lives in one place.
func TestTheStoreServesExactlyTheTilesTheTreeImplies(t *testing.T) {
	dir, anchor := servedLog(t)
	result, err := Verify(Dir(dir), anchor)
	if err != nil {
		t.Fatal(err)
	}
	tree, err := tlog.Build(result.Served)
	if err != nil {
		t.Fatal(err)
	}
	tiles, err := tree.Tiles()
	if err != nil {
		t.Fatal(err)
	}
	if len(tiles) == 0 {
		t.Fatal("a 90-entry log implies at least one tile")
	}
	for _, tile := range tiles {
		served, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(tile.Path())))
		if err != nil {
			t.Errorf("%s: %v", tile.Path(), err)
			continue
		}
		if !bytes.Equal(served, tile.Data) {
			t.Errorf("%s differs from what the tree implies", tile.Path())
		}
	}
}

// SPEC §10 step 3 -- the step this project carried unimplemented from 2.9e
// until 4.1c. A checkpoint the log signed is only half of what a node is
// allowed to believe: GOSSIP.md part 1 makes witnesses the guard against the
// log itself, so a head no quorum of witnesses has cosigned must be refused
// however well-formed it is.

// cosignedLog builds a served log whose checkpoint carries cosignatures from
// exactly the named witnesses, and an anchor requiring `threshold` of them.
func cosignedLog(t *testing.T, cosigners []string, threshold int) (string, Anchor) {
	t.Helper()
	inner, entries := loadFixture(t)
	dir := t.TempDir()
	key := logKey(t)
	var signers []cosign.Signer
	for _, name := range cosigners {
		signers = append(signers, cosign.Signer{
			Name: "norn-witness/" + name, Key: witnessKey(t, name)})
	}
	var opts []tlogstore.Option
	if len(signers) > 0 {
		opts = append(opts, tlogstore.WithCosigner(
			tlogstore.CosignerFunc(cosign.Append(signers, cosign.At(cosignedAt)))))
	}
	store, err := tlogstore.Open(dir, "norn/test", key, opts...)
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range entries[:10] {
		if _, err := store.Append(raw); err != nil {
			t.Fatal(err)
		}
	}
	return dir, Anchor{Anchor: inner, LogKeys: []string{verifierKey(t, key, "norn/test")},
		Policy: policyOver(t, "norn/test", witnessNames, threshold)}
}

func TestAQuorumOfWitnessesIsAccepted(t *testing.T) {
	dir, anchor := cosignedLog(t, []string{"pi", "vps"}, 2)

	result, err := Verify(Dir(dir), anchor)
	if err != nil {
		t.Fatalf("a checkpoint two of three witnesses cosigned was refused: %v", err)
	}
	if len(result.Cosignatures) != 2 {
		t.Fatalf("cosignatures = %+v, want the two that signed", result.Cosignatures)
	}
	// The result must carry *which* witnesses, not just how many: 4.2 reads
	// the freshness clock off these, and a count would not survive that.
	for _, c := range result.Cosignatures {
		if c.Time.Unix() != cosignedAtUnix {
			t.Errorf("%s cosigned at %v, want the fixture's instant", c.Name, c.Time)
		}
	}
}

func TestOneCosignatureShortIsRefused(t *testing.T) {
	dir, anchor := cosignedLog(t, []string{"pi"}, 2)

	if _, err := Verify(Dir(dir), anchor); err == nil {
		t.Fatal("a checkpoint one witness short of the quorum was accepted")
	} else if !strings.Contains(err.Error(), "witness policy") {
		t.Errorf("the error should name the quorum as the reason: %v", err)
	}
}

// A log that no witness has seen is the case the quorum exists for: it is
// exactly what a log serving a private fork produces.
func TestAnUncosignedCheckpointIsRefused(t *testing.T) {
	dir, anchor := cosignedLog(t, nil, 2)

	if _, err := Verify(Dir(dir), anchor); err == nil {
		t.Fatal("a checkpoint no witness cosigned was accepted")
	}
}

// Cosignatures from witnesses this network has not named cannot make up the
// numbers -- otherwise a forking log would simply bring its own witnesses.
func TestUnnamedWitnessesDoNotCountTowardTheQuorum(t *testing.T) {
	dir, anchor := cosignedLog(t, []string{"pi", "stranger", "interloper"}, 2)

	if _, err := Verify(Dir(dir), anchor); err == nil {
		t.Fatal("witnesses the policy never named were counted toward the quorum")
	}
}

// A forged cosignature is worse than a missing one: it claims a witness this
// network trusts said something it did not, so it is an error rather than a
// line that simply fails to count.
func TestAForgedCosignatureIsRefused(t *testing.T) {
	dir, anchor := cosignedLog(t, []string{"pi", "vps"}, 2)

	path := filepath.Join(dir, "checkpoint")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Flip a byte inside the last cosignature's signature, leaving its key id
	// -- and so the witness it claims to be -- intact.
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	last := lines[len(lines)-1]
	blob := last[strings.LastIndex(last, " ")+1:]
	decoded, err := base64.StdEncoding.DecodeString(blob)
	if err != nil {
		t.Fatal(err)
	}
	decoded[len(decoded)-1] ^= 0x01
	lines[len(lines)-1] = last[:strings.LastIndex(last, " ")+1] +
		base64.StdEncoding.EncodeToString(decoded)
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := Verify(Dir(dir), anchor); err == nil {
		t.Fatal("a forged cosignature was accepted")
	}
}

// `quorum none` is in the grammar, and it means what it says: a network may
// decide it wants no corroboration. Refusing to honour that would be Norn
// overriding the operator's own policy.
func TestQuorumNoneAcceptsAnUncosignedCheckpoint(t *testing.T) {
	dir, anchor := cosignedLog(t, nil, 2)
	anchor.Policy = "log norn/test " + verifierKey(t, logKey(t), "norn/test") + "\nquorum none\n"

	result, err := Verify(Dir(dir), anchor)
	if err != nil {
		t.Fatalf("`quorum none` must accept an uncosigned checkpoint: %v", err)
	}
	if len(result.Cosignatures) != 0 {
		t.Errorf("cosignatures = %+v, want none", result.Cosignatures)
	}
}

// The checkpoint's witness time: the instant the policy vouches for, which is
// the only clock a node trusts (A11, GOSSIP part 5). The verifier is where the
// policy and the cosignatures meet, so it is where that instant is read.
func TestVerifyReportsTheWitnessTime(t *testing.T) {
	// Three witnesses, two required, cosigning at three different instants.
	dir, anchor := cosignedLogAt(t, map[string]int64{
		"pi": cosignedAtUnix, "vps": cosignedAtUnix - 60, "friend": cosignedAtUnix - 600,
	}, 2)

	result, err := Verify(Dir(dir), anchor)
	if err != nil {
		t.Fatal(err)
	}
	if result.QuorumTime == nil {
		t.Fatal("a cosigned checkpoint must carry a witness time")
	}
	// Two of three: the newest instant at which two have signed. The newest
	// cosignature alone is one witness, and one witness is not a quorum.
	if got := result.QuorumTime.Unix(); got != cosignedAtUnix-60 {
		t.Errorf("quorum time = %d, want %d", got, cosignedAtUnix-60)
	}
}

// A network that asked for no corroboration has no witness clock, and the
// result says so by carrying no time rather than by inventing one.
func TestQuorumNoneReportsNoWitnessTime(t *testing.T) {
	dir, anchor := cosignedLog(t, nil, 2)
	anchor.Policy = "log norn/test " + verifierKey(t, logKey(t), "norn/test") + "\nquorum none\n"

	result, err := Verify(Dir(dir), anchor)
	if err != nil {
		t.Fatal(err)
	}
	if result.QuorumTime != nil {
		t.Errorf("quorum time = %v, want none", result.QuorumTime)
	}
}

// cosignedLogAt is cosignedLog with a different instant per witness.
func cosignedLogAt(t *testing.T, when map[string]int64, threshold int) (string, Anchor) {
	t.Helper()
	inner, entries := loadFixture(t)
	dir := t.TempDir()
	key := logKey(t)
	cosigners := func(signed string) (string, error) {
		out := signed
		for _, name := range witnessNames {
			at, ok := when[name]
			if !ok {
				continue
			}
			one := cosign.Append(
				[]cosign.Signer{{Name: "norn-witness/" + name, Key: witnessKey(t, name)}},
				cosign.At(time.Unix(at, 0)))
			var err error
			if out, err = one(out); err != nil {
				return "", err
			}
		}
		return out, nil
	}
	store, err := tlogstore.Open(dir, "norn/test", key,
		tlogstore.WithCosigner(tlogstore.CosignerFunc(cosigners)))
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range entries[:10] {
		if _, err := store.Append(raw); err != nil {
			t.Fatal(err)
		}
	}
	return dir, Anchor{Anchor: inner, LogKeys: []string{verifierKey(t, key, "norn/test")},
		Policy: policyOver(t, "norn/test", witnessNames, threshold)}
}

// SPEC §10, the step after the signature and the quorum:
//
//	if stored_cp exists:
//	    require cp.size >= stored_cp.size
//	    verify consistency proof stored_cp → cp; on failure → FORK (§11)
//
// Without it, a log -- or, once gossip exists, any peer -- can serve an older
// checkpoint that is perfectly signed and perfectly cosigned, and a node will
// replay it and roll its own peer table backwards. A device revoked at entry
// 80 becomes active again by handing the node the log as it stood at entry 70.
// Every signature checks out, because it is the *same log*, earlier.
func TestACheckpointOlderThanTheStoredOneIsRefused(t *testing.T) {
	dir, anchor := cosignedLog(t, []string{"pi", "vps"}, 2)

	current, err := Verify(Dir(dir), anchor)
	if err != nil {
		t.Fatal(err)
	}
	// The node now holds this head, and is offered the same log ten entries
	// shorter -- signed and cosigned exactly as correctly.
	older, olderAnchor := cosignedLogOfSize(t, 5, []string{"pi", "vps"}, 2)
	olderAnchor.Stored = &current.Checkpoint

	if _, err := Verify(Dir(older), olderAnchor); err == nil {
		t.Fatal("a node accepted a checkpoint older than the one it already held; " +
			"a revoked device would come back")
	} else if !strings.Contains(err.Error(), "does not shrink") {
		t.Errorf("the refusal should say the log went backwards: %v", err)
	}
}

// The same size and the same root is not a rollback: it is the ordinary case
// of nothing having changed since the last poll.
func TestTheSameCheckpointIsAcceptedAgain(t *testing.T) {
	dir, anchor := cosignedLog(t, []string{"pi", "vps"}, 2)
	current, err := Verify(Dir(dir), anchor)
	if err != nil {
		t.Fatal(err)
	}

	anchor.Stored = &current.Checkpoint
	if _, err := Verify(Dir(dir), anchor); err != nil {
		t.Fatalf("re-verifying the head a node already holds failed: %v", err)
	}
}

// Growing is what a log does.
func TestAGrownLogIsAccepted(t *testing.T) {
	small, anchor := cosignedLogOfSize(t, 5, []string{"pi", "vps"}, 2)
	held, err := Verify(Dir(small), anchor)
	if err != nil {
		t.Fatal(err)
	}

	bigger, biggerAnchor := cosignedLogOfSize(t, 20, []string{"pi", "vps"}, 2)
	biggerAnchor.Stored = &held.Checkpoint
	if _, err := Verify(Dir(bigger), biggerAnchor); err != nil {
		t.Fatalf("a log that grew was refused: %v", err)
	}
}

// A log the same size or larger whose earlier history differs is a **fork**:
// the node held a head this log cannot have produced. This is the case §11
// exists for, and it must be refused loudly rather than replayed.
func TestALogThatRewroteItsHistoryIsRefused(t *testing.T) {
	dir, anchor := cosignedLogOfSize(t, 20, []string{"pi", "vps"}, 2)
	held, err := Verify(Dir(dir), anchor)
	if err != nil {
		t.Fatal(err)
	}

	// A head of the same size whose root is not this log's root at that size.
	forked := held.Checkpoint
	forked.Root[0] ^= 0x01
	anchor.Stored = &forked

	if _, err := Verify(Dir(dir), anchor); err == nil {
		t.Fatal("a log inconsistent with the head this node held was accepted")
	} else if !strings.Contains(err.Error(), "FORK") {
		t.Errorf("the refusal should raise a fork: %v", err)
	}
}

// cosignedLogOfSize builds a cosigned log of the first `n` fixture entries.
func cosignedLogOfSize(t *testing.T, n int, cosigners []string, threshold int) (string, Anchor) {
	t.Helper()
	inner, entries := loadFixture(t)
	dir := t.TempDir()
	key := logKey(t)
	var signers []cosign.Signer
	for _, name := range cosigners {
		signers = append(signers, cosign.Signer{
			Name: "norn-witness/" + name, Key: witnessKey(t, name)})
	}
	store, err := tlogstore.Open(dir, "norn/test", key, tlogstore.WithCosigner(
		tlogstore.CosignerFunc(cosign.Append(signers, cosign.At(cosignedAt)))))
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range entries[:n] {
		if _, err := store.Append(raw); err != nil {
			t.Fatal(err)
		}
	}
	return dir, Anchor{Anchor: inner, LogKeys: []string{verifierKey(t, key, "norn/test")},
		Policy: policyOver(t, "norn/test", witnessNames, threshold)}
}

// --- D-020, implemented: log-key rotation with an overlap window ---------
//
// Cold gate run 6 (H3) found that which keys may sign a checkpoint, and from
// when, was in no document: §15 deferred it to `ENROLLMENT.md`, which does not
// ship, and §5.3 named "the index from which the key becomes valid" without
// defining it. Nothing in this repository read `state.log_keys` at all.
//
// The rule, and the reason it is not circular: a node accepts a checkpoint
// under the trust file's key, replays the log that checkpoint commits to, and
// *thereby* learns any key the roots have published. A node that has accepted
// nothing has only the trust file's key. Rotation cannot bootstrap itself,
// which is what stops a stolen log key from naming its successor -- a
// `log_key` entry needs the root quorum (§4.3).

func TestARotatedKeyIsAcceptedOnlyAfterItsRotationIsReplayed(t *testing.T) {
	dir, anchor := servedLog(t)

	// The node bootstraps on the trust file's key and learns what the log
	// published.
	result, err := Verify(Dir(dir), anchor)
	if err != nil {
		t.Fatal(err)
	}
	learned := KeysFrom("norn/test", result.State)
	if len(learned) == 0 {
		t.Fatal("the fixture log publishes no log_key entry, so nothing here is tested")
	}

	// Re-sign the head with the rotated key the log published.
	rotated := rotatedKey(t, result.State)
	signed, err := resignCheckpoint(t, dir, "norn/test", rotated)
	if err != nil {
		t.Fatal(err)
	}
	served := servedWithHead(t, dir, signed)

	// A node holding only the trust file refuses it: it has never seen the
	// rotation, so this key is a stranger's.
	if _, err := Verify(Dir(served), anchor); err == nil {
		t.Error("a checkpoint signed by a key this node has never seen was accepted; " +
			"rotation would then bootstrap itself")
	}

	// A node that replayed the rotation accepts it.
	informed := anchor
	informed.LogKeys = append(append([]string(nil), anchor.LogKeys...), learned...)
	if _, err := Verify(Dir(served), informed); err != nil {
		t.Errorf("a node that replayed the rotation refused the key the roots published: %v", err)
	}
}

// rotatedKey is the private half of the first key the fixture's roots publish,
// read from `keys.json` by matching the public key the state records.
func rotatedKey(t *testing.T, st *state.State) ed25519.PrivateKey {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(vectorRoot(), "keys.json"))
	if err != nil {
		t.Fatal(err)
	}
	var keys struct {
		Ed25519 map[string]struct{ Seed, Public string } `json:"ed25519"`
	}
	if err := json.Unmarshal(raw, &keys); err != nil {
		t.Fatal(err)
	}
	want := st.LogKeys[0].Pk
	for _, k := range keys.Ed25519 {
		if k.Public != want {
			continue
		}
		seed, err := hex.DecodeString(k.Seed)
		if err != nil || len(seed) != ed25519.SeedSize {
			t.Fatalf("keys.json has no usable seed for %s", want)
		}
		return ed25519.NewKeyFromSeed(seed)
	}
	t.Fatalf("keys.json holds no private key for the published %s", want)
	return nil
}

// resignCheckpoint re-signs the served head under another key, cosigned as
// usual, so the only thing different about it is who signed it.
func resignCheckpoint(t *testing.T, dir, origin string, key ed25519.PrivateKey) (string, error) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "checkpoint"))
	if err != nil {
		return "", err
	}
	body, _, err := note.Split(string(raw))
	if err != nil {
		return "", err
	}
	signed, err := note.Sign(body, origin, key)
	if err != nil {
		return "", err
	}
	return cosign.Append(witnesses(t), cosign.At(cosignedAt))(signed)
}

// servedWithHead copies a served log and puts another head on it.
func servedWithHead(t *testing.T, from, head string) string {
	t.Helper()
	to := t.TempDir()
	err := filepath.Walk(from, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(from, path)
		if err != nil {
			return err
		}
		target := filepath.Join(to, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, body, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(to, "checkpoint"), []byte(head), 0o644); err != nil {
		t.Fatal(err)
	}
	return to
}
