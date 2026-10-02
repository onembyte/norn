package logclient

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/onembyte/norn/internal/cosign"
	"github.com/onembyte/norn/internal/note"
	"github.com/onembyte/norn/internal/refusal"
	"github.com/onembyte/norn/internal/tlog"
)

// --- 6.5l-vi-b-ii-b: the loop names its refusals (D-061) ---------------
//
// Every place Verify refuses a log is one of §10.1's steps, and the refusal
// carries that step's code. Each case below is built so that its step is the
// FIRST to fail: a negative that some earlier step also refuses proves
// nothing about the step it is named for (D-044). Before codes, one of this
// package's own tests was exactly that: TestVerifyChecksTheHeadAgainstTheEntries
// edited the root line of a signed head, which is a signature refusal, and
// passed because all it asked for was an error.
//
// The codes are added to the errors, never substituted: every case is still
// ErrLog, and a fork is still a *ForkError to errors.As, which is how the
// agent decides to write evidence.

type refusalCase struct {
	name  string
	want  refusal.Code
	build func(t *testing.T) (string, Anchor)
}

var loopRefusals = []refusalCase{
	{"the checkpoint is not served", refusal.Unserved, func(t *testing.T) (string, Anchor) {
		dir, anchor := servedLog(t)
		remove(t, filepath.Join(dir, "checkpoint"))
		return dir, anchor
	}},
	{"no signature line at all", refusal.Note, func(t *testing.T) (string, Anchor) {
		dir, anchor := servedLog(t)
		write(t, filepath.Join(dir, "checkpoint"), bodyOf(t, dir))
		return dir, anchor
	}},
	{"a key the anchor does not trust", refusal.LogSignature, func(t *testing.T) (string, Anchor) {
		dir, anchor := servedLog(t)
		seed := sha256.Sum256([]byte("norn/logclient-test/impostor"))
		write(t, filepath.Join(dir, "checkpoint"),
			signAndCosign(t, bodyOf(t, dir), "norn/test", ed25519.NewKeyFromSeed(seed[:])))
		return dir, anchor
	}},
	// §10.1: the signature decides before the origin. The right key under
	// another origin's name is a signature this anchor does not trust, and
	// the anchor below *also* pins an origin the body does not name -- so a
	// verifier that compared origins first would answer `origin`.
	{"the right key under another origin's name", refusal.LogSignature, func(t *testing.T) (string, Anchor) {
		dir, anchor := servedLog(t)
		write(t, filepath.Join(dir, "checkpoint"),
			signAndCosign(t, bodyOf(t, dir), "norn/elsewhere", logKey(t)))
		anchor.Origin = "norn/elsewhere"
		return dir, anchor
	}},
	{"a fourth body line, properly signed", refusal.Checkpoint, func(t *testing.T) (string, Anchor) {
		dir, anchor := servedLog(t)
		write(t, filepath.Join(dir, "checkpoint"),
			signAndCosign(t, bodyOf(t, dir)+"extension\n", "norn/test", logKey(t)))
		return dir, anchor
	}},
	{"the body names another log", refusal.Origin, func(t *testing.T) (string, Anchor) {
		dir, anchor := servedLog(t)
		anchor.Origin = "norn/elsewhere"
		return dir, anchor
	}},
	// Three witnesses cosign and two are required, so the quorum is met
	// without the forged line: only the per-line rule refuses this head.
	{"a listed witness's line does not verify", refusal.Cosignature, func(t *testing.T) (string, Anchor) {
		dir, anchor := servedLog(t)
		forgeLastCosignature(t, dir)
		return dir, anchor
	}},
	{"one cosignature short", refusal.Quorum, func(t *testing.T) (string, Anchor) {
		return cosignedLog(t, []string{"pi"}, 2)
	}},
	{"an entry bundle that does not frame", refusal.Entries, func(t *testing.T) (string, Anchor) {
		dir, anchor := servedLog(t)
		path := entryBundle(t, dir)
		raw := []byte(readFile(t, path))
		write(t, path, string(raw[:len(raw)-1]))
		return dir, anchor
	}},
	// The bundle frames and holds one entry fewer than the checkpoint's size
	// implies. §10.1 step 8: "do not add up to that size". A verifier that
	// counts across bundles goes looking for a next one the size never
	// implied, and refuses `unserved` -- which is what this package did.
	{"an entry bundle one entry short", refusal.Entries, func(t *testing.T) (string, Anchor) {
		dir, anchor := servedLog(t)
		path := entryBundle(t, dir)
		entries, err := tlog.DecodeBundle([]byte(readFile(t, path)))
		if err != nil {
			t.Fatal(err)
		}
		short, err := tlog.EncodeBundle(entries[:len(entries)-1])
		if err != nil {
			t.Fatal(err)
		}
		write(t, path, string(short))
		return dir, anchor
	}},
	{"an entry bundle is not served", refusal.Unserved, func(t *testing.T) (string, Anchor) {
		dir, anchor := servedLog(t)
		remove(t, entryBundle(t, dir))
		return dir, anchor
	}},
	// The served tiles are the honest log's, so this is also a tiles fault:
	// §10.1 checks the head first.
	{"a changed byte inside an entry", refusal.Head, func(t *testing.T) (string, Anchor) {
		dir, anchor := servedLog(t)
		changeAnEntry(t, dir)
		return dir, anchor
	}},
	{"this node's head disagrees with the served branch", refusal.Fork, func(t *testing.T) (string, Anchor) {
		dir, anchor := cosignedLogOfSize(t, 20, []string{"pi", "vps"}, 2)
		forked := checkpointIn(t, dir, "checkpoint", anchor)
		forked.Root[0] ^= 0x01
		anchor.Stored = &forked
		return dir, anchor
	}},
	{"a shorter log, and this node cannot speak for the smaller size", refusal.Rollback, func(t *testing.T) (string, Anchor) {
		bigger, biggerAnchor := cosignedLogOfSize(t, 10, []string{"pi", "vps"}, 2)
		held := checkpointIn(t, bigger, "checkpoint", biggerAnchor)
		dir, anchor := cosignedLogOfSize(t, 5, []string{"pi", "vps"}, 2)
		anchor.Stored = &held
		return dir, anchor
	}},
	{"a shorter log whose branch agrees with this node's", refusal.Rollback, func(t *testing.T) (string, Anchor) {
		bigger, biggerAnchor := cosignedLogOfSize(t, 10, []string{"pi", "vps"}, 2)
		result, err := Verify(Dir(bigger), biggerAnchor)
		if err != nil {
			t.Fatal(err)
		}
		dir, anchor := cosignedLogOfSize(t, 5, []string{"pi", "vps"}, 2)
		anchor.Stored, anchor.Held = &result.Checkpoint, result.Tree
		return dir, anchor
	}},
	{"a hash tile is not served", refusal.Unserved, func(t *testing.T) (string, Anchor) {
		dir, anchor := servedLog(t)
		remove(t, hashTile(t, dir))
		return dir, anchor
	}},
	{"a hash tile disagrees with the rebuilt tree", refusal.Tiles, func(t *testing.T) (string, Anchor) {
		dir, anchor := servedLog(t)
		path := hashTile(t, dir)
		raw := []byte(readFile(t, path))
		raw[10] ^= 0xff
		write(t, path, string(raw))
		return dir, anchor
	}},
}

// Two faults, and §10.1's earlier step decides. A verifier that ran its
// checks in another order would refuse every one of these logs too -- with the
// later step's code -- so without codes none of these orderings could be seen.
var precedence = []refusalCase{
	{"origin before cosignature: the body names another log and a line is forged", refusal.Origin,
		func(t *testing.T) (string, Anchor) {
			dir, anchor := servedLog(t)
			forgeLastCosignature(t, dir)
			anchor.Origin = "norn/elsewhere"
			return dir, anchor
		}},
	{"cosignature before quorum: the only witness's line is forged", refusal.Cosignature,
		func(t *testing.T) (string, Anchor) {
			dir, anchor := cosignedLog(t, []string{"pi"}, 2)
			forgeLastCosignature(t, dir)
			return dir, anchor
		}},
	{"quorum before entries: one witness short, and a bundle that does not frame", refusal.Quorum,
		func(t *testing.T) (string, Anchor) {
			dir, anchor := cosignedLog(t, []string{"pi"}, 2)
			path := entryBundle(t, dir)
			raw := []byte(readFile(t, path))
			write(t, path, string(raw[:len(raw)-1]))
			return dir, anchor
		}},
	// §10.1's argued case. The fork comparison uses the root the served
	// branch has *recomputed from the served entries*; when those do not even
	// hash to the head they came with, a disagreement would accuse a log of
	// signing two histories when it served one broken one.
	{"head before fork: the entries are corrupt and this node held another head", refusal.Head,
		func(t *testing.T) (string, Anchor) {
			dir, anchor := cosignedLogOfSize(t, 20, []string{"pi", "vps"}, 2)
			held := checkpointIn(t, dir, "checkpoint", anchor)
			changeAnEntry(t, dir)
			anchor.Stored = &held
			return dir, anchor
		}},
	{"rollback before tiles: a shorter log with a corrupt tile", refusal.Rollback,
		func(t *testing.T) (string, Anchor) {
			bigger, biggerAnchor := cosignedLogOfSize(t, 10, []string{"pi", "vps"}, 2)
			held := checkpointIn(t, bigger, "checkpoint", biggerAnchor)
			dir, anchor := cosignedLogOfSize(t, 5, []string{"pi", "vps"}, 2)
			path := hashTile(t, dir)
			raw := []byte(readFile(t, path))
			raw[10] ^= 0xff
			write(t, path, string(raw))
			anchor.Stored = &held
			return dir, anchor
		}},
}

func TestEveryRefusalCarriesItsSection10_1Code(t *testing.T) {
	covered := map[refusal.Code]bool{}
	for _, c := range loopRefusals {
		t.Run(c.name, func(t *testing.T) {
			dir, anchor := c.build(t)
			_, err := Verify(Dir(dir), anchor)
			if err == nil {
				t.Fatal("accepted")
			}
			if got, _ := refusal.CodeOf(err); got != c.want {
				t.Errorf("refused as %q, want %q: %v", got, c.want, err)
			}
			if !errors.Is(err, ErrLog) {
				t.Errorf("no longer ErrLog: %v", err)
			}
			var fork *ForkError
			if isFork := errors.As(err, &fork); isFork != (c.want == refusal.Fork) {
				t.Errorf("errors.As(*ForkError) = %v for a %q refusal", isFork, c.want)
			}
		})
		covered[c.want] = true
	}
	// Every one of the loop's twelve codes has a case, so a step cannot lose
	// its code without one of them failing.
	for _, code := range refusal.All()[:12] {
		if !covered[code] {
			t.Errorf("no case here reaches §10.1's %q", code)
		}
	}
}

func TestTheEarlierStepDecides(t *testing.T) {
	for _, c := range precedence {
		t.Run(c.name, func(t *testing.T) {
			dir, anchor := c.build(t)
			_, err := Verify(Dir(dir), anchor)
			if got, _ := refusal.CodeOf(err); got != c.want {
				t.Errorf("refused as %q, want %q: %v", got, c.want, err)
			}
		})
	}
}

// What is wrong with the anchor is the caller's configuration, not the log's:
// it is still ErrLog -- the log cannot be used -- and it carries no code,
// because §10.1's codes describe what was served.
func TestAnAnchorFaultCarriesNoCode(t *testing.T) {
	plainWitness := func(t *testing.T) string {
		public := witnessKey(t, "pi").Public().(ed25519.PublicKey)
		return "log norn/test " + verifierKey(t, logKey(t), "norn/test") + "\n" +
			"witness pi " + note.VerifierKey("norn-witness/pi", public) + "\nquorum pi\n"
	}
	for name, spoil := range map[string]func(t *testing.T, a *Anchor){
		"no log key":                    func(t *testing.T, a *Anchor) { a.LogKeys = nil },
		"a log key that does not parse": func(t *testing.T, a *Anchor) { a.LogKeys = []string{"not a key"} },
		"no genesis pin":                func(t *testing.T, a *Anchor) { a.GenesisHash = nil },
		"no policy":                     func(t *testing.T, a *Anchor) { a.Policy = "" },
		"a policy that does not parse":  func(t *testing.T, a *Anchor) { a.Policy = "quorum\n" },
		"a witness given a note key":    func(t *testing.T, a *Anchor) { a.Policy = plainWitness(t) },
	} {
		t.Run(name, func(t *testing.T) {
			dir, anchor := servedLog(t)
			spoil(t, &anchor)
			_, err := Verify(Dir(dir), anchor)
			if err == nil {
				t.Fatal("accepted")
			}
			if code, ok := refusal.CodeOf(err); ok {
				t.Errorf("reported as the log's %q: %v", code, err)
			}
			if !errors.Is(err, ErrLog) {
				t.Errorf("no longer ErrLog: %v", err)
			}
		})
	}
}

func remove(t *testing.T, path string) {
	t.Helper()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
}

func write(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// bodyOf is the served checkpoint's signed text.
func bodyOf(t *testing.T, dir string) string {
	t.Helper()
	body, _, err := note.Split(readFile(t, filepath.Join(dir, "checkpoint")))
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// signAndCosign signs a body as a log would, and has every test witness
// cosign it, so the only thing wrong with the head is what the case put there.
func signAndCosign(t *testing.T, body, name string, key ed25519.PrivateKey) string {
	t.Helper()
	signed, err := note.Sign(body, name, key)
	if err != nil {
		t.Fatal(err)
	}
	cosigned, err := cosign.Append(witnesses(t), cosign.At(cosignedAt))(signed)
	if err != nil {
		t.Fatal(err)
	}
	return cosigned
}

// forgeLastCosignature flips the last byte of the checkpoint's last line --
// a cosignature, in every log this package builds -- leaving its key id, and
// so the witness it claims to be, intact.
func forgeLastCosignature(t *testing.T, dir string) {
	t.Helper()
	path := filepath.Join(dir, "checkpoint")
	lines := strings.Split(strings.TrimSuffix(readFile(t, path), "\n"), "\n")
	last := lines[len(lines)-1]
	cut := strings.LastIndex(last, " ") + 1
	raw, err := base64.StdEncoding.DecodeString(last[cut:])
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-1] ^= 0x01
	lines[len(lines)-1] = last[:cut] + base64.StdEncoding.EncodeToString(raw)
	write(t, path, strings.Join(lines, "\n")+"\n")
}

// changeAnEntry flips the last byte of the last entry, which leaves every
// length prefix -- and so the framing -- untouched.
func changeAnEntry(t *testing.T, dir string) {
	t.Helper()
	path := entryBundle(t, dir)
	raw := []byte(readFile(t, path))
	raw[len(raw)-1] ^= 0x01
	write(t, path, string(raw))
}

// entryBundle is the one entry bundle a fixture-sized log serves.
func entryBundle(t *testing.T, dir string) string {
	t.Helper()
	return onlyFile(t, filepath.Join(dir, "tile", "entries"))
}

// hashTile is the first level-0 hash tile.
func hashTile(t *testing.T, dir string) string {
	t.Helper()
	return onlyFile(t, filepath.Join(dir, "tile", "0"))
}

func onlyFile(t *testing.T, root string) string {
	t.Helper()
	var found string
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && found == "" {
			found = p
		}
		return err
	})
	if err != nil || found == "" {
		t.Fatalf("nothing served under %s: %v", root, err)
	}
	return found
}

// --- 6.5l-vi-b-ii-d: checkpoints-bad/ names its codes -------------------
//
// The suite's own harness: each file served in place of served/checkpoint,
// over the honest tiles, under trust.cbor -- exactly as cases.json tells a
// second implementer to serve it -- and refused with the code cases.json
// names. Before codes this could only ask "refused?", and two orderings were
// invisible: a reader that compares origins before checking the signature
// refuses 03-wrong-origin too, as `origin`; a reader that looks for a trusted
// signature before framing the note refuses 01-unsigned too, as
// `log-signature`.

func TestEveryBadCheckpointIsRefusedWithItsCode(t *testing.T) {
	var manifest struct {
		Cases []string                `json:"cases"`
		Codes map[string]refusal.Code `json:"codes"`
	}
	raw := readFile(t, filepath.Join(vectorRoot(), "checkpoints-bad", "cases.json"))
	if err := json.Unmarshal([]byte(raw), &manifest); err != nil {
		t.Fatal(err)
	}
	if len(manifest.Codes) != len(manifest.Cases) {
		t.Fatalf("%d cases and %d codes: every case names the §10.1 code it is refused with",
			len(manifest.Cases), len(manifest.Codes))
	}
	anchor := shippedLogAnchor(t)
	honest := filepath.Join(vectorRoot(), "served")
	for _, name := range manifest.Cases {
		t.Run(name, func(t *testing.T) {
			want, ok := manifest.Codes[name]
			if !ok || !refusal.Known(want) {
				t.Fatalf("names %q, which is not a §10.1 code", want)
			}
			checkpoint := readFile(t, filepath.Join(vectorRoot(), "checkpoints-bad", name+".checkpoint"))
			_, err := Verify(Dir(servedWith(t, honest, checkpoint)), anchor)
			if err == nil {
				t.Fatal("accepted")
			}
			if got, _ := refusal.CodeOf(err); got != want {
				t.Errorf("refused as %q, and cases.json says %q: %v", got, want, err)
			}
		})
	}
}

// --- 6.5l-vi-b-ii-e: served-bad/ names its codes ------------------------
//
// A served log is a directory, so each case replaces or removes paths in an
// honest copy of served/ (cases.json says which), and the result is refused
// with the code `codes` names.

type servedNegative struct {
	Name   string
	Path   string
	File   string
	Remove bool
	Files  []struct{ Path, File string } `json:"files"`
}

func servedNegatives(t *testing.T) ([]servedNegative, map[string]refusal.Code) {
	t.Helper()
	var manifest struct {
		Cases []servedNegative        `json:"cases"`
		Codes map[string]refusal.Code `json:"codes"`
	}
	raw := readFile(t, filepath.Join(vectorRoot(), "served-bad", "cases.json"))
	if err := json.Unmarshal([]byte(raw), &manifest); err != nil {
		t.Fatal(err)
	}
	return manifest.Cases, manifest.Codes
}

// apply builds the served directory a case describes.
func (c servedNegative) apply(t *testing.T) string {
	t.Helper()
	honest := filepath.Join(vectorRoot(), "served")
	dir := servedWith(t, honest, readFile(t, filepath.Join(honest, "checkpoint")))
	replace := func(path, file string) {
		at := filepath.Join(dir, filepath.FromSlash(path))
		if _, err := os.Stat(at); err != nil {
			t.Fatalf("the case replaces %s, which the honest log does not serve", path)
		}
		write(t, at, readFile(t, filepath.Join(vectorRoot(), "served-bad", file)))
	}
	switch {
	case c.Remove:
		remove(t, filepath.Join(dir, filepath.FromSlash(c.Path)))
	case len(c.Files) > 0:
		for _, f := range c.Files {
			replace(f.Path, f.File)
		}
	default:
		replace(c.Path, c.File)
	}
	return dir
}

func TestEveryServedNegativeIsRefusedWithItsCode(t *testing.T) {
	cases, codes := servedNegatives(t)
	if len(codes) != len(cases) {
		t.Fatalf("%d cases and %d codes: every case names the §10.1 code it is refused with",
			len(cases), len(codes))
	}
	anchor := shippedLogAnchor(t)
	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			want, ok := codes[c.Name]
			if !ok || !refusal.Known(want) {
				t.Fatalf("names %q, which is not a §10.1 code", want)
			}
			_, err := Verify(Dir(c.apply(t)), anchor)
			if err == nil {
				t.Fatal("accepted")
			}
			if got, _ := refusal.CodeOf(err); got != want {
				t.Errorf("refused as %q, and cases.json says %q: %v", got, want, err)
			}
		})
	}
}

// §10.1 checks the head before the tiles. The ordering is a vector only if
// some served log fails BOTH -- its entries do not hash to the signed head,
// and its served tiles disagree with the tree those entries build -- and is
// coded `head`: a reader that checks tiles first refuses that same log as
// `tiles`, and one that never rebuilds the tree has nothing else to say.
func TestTheHeadBeforeTilesOrderHasAVector(t *testing.T) {
	cases, codes := servedNegatives(t)
	for _, c := range cases {
		if codes[c.Name] != refusal.Head || c.Remove {
			continue
		}
		dir := c.apply(t)
		cp := checkpointIn(t, dir, "checkpoint", shippedLogAnchor(t))
		entries, err := fetchEntries(Dir(dir), cp.Size)
		if err != nil {
			t.Fatalf("%s: %v", c.Name, err)
		}
		tree, err := tlog.Build(entries)
		if err != nil {
			t.Fatal(err)
		}
		if tree.Head() == cp.Root {
			t.Errorf("%s is coded `head` and its entries hash to the signed root", c.Name)
			continue
		}
		if checkTiles(Dir(dir), tree) != nil {
			return // the tiles disagree too: a tiles-first reader says `tiles` here
		}
	}
	t.Error("no served-bad case is coded `head` while its tiles also disagree, so a " +
		"reader that checks tiles before the head passes every file here")
}
