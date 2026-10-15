package logclient

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/onembyte/norn/internal/cosign"
	"github.com/onembyte/norn/internal/note"
	"github.com/onembyte/norn/internal/refusal"
	"github.com/onembyte/norn/internal/tlog"
)

// Repairs are made only in temporary served copies. Each ordering case must
// expose the other fault independently, and reach acceptance with both fixed.
func runFourteenAnswer(t *testing.T, dir string, anchor Anchor, want string) *Result {
	t.Helper()
	result, err := Verify(Dir(dir), anchor)
	got := "accept"
	if err != nil {
		code, _ := refusal.CodeOf(err)
		got = string(code)
	}
	if got != want {
		t.Fatalf("Go answers %q (%v), SPEC states %q", got, err, want)
	}
	return result
}

func runFourteenSign(t *testing.T, body, name string, cosigned bool) string {
	t.Helper()
	seed := sha256.Sum256([]byte("norn/testvector/v1\nlogkey"))
	head, err := note.Sign(body, name, ed25519.NewKeyFromSeed(seed[:]))
	if err != nil {
		t.Fatal(err)
	}
	if cosigned {
		for i, witness := range []string{"pi", "vps", "friend"} {
			seed := sha256.Sum256([]byte("norn/testvector/v1\nwitness-" + witness))
			line, err := cosign.Sign(body, "norn-witness/"+witness, ed25519.NewKeyFromSeed(seed[:]), time.Unix(1_760_003_600+int64(i*7), 0))
			if err != nil {
				t.Fatal(err)
			}
			head += line + "\n"
		}
	}
	return head
}

func checkRunFourteenCheckpointPairs(t *testing.T) {
	anchor := shippedLogAnchor(t)
	honest := filepath.Join(vectorRoot(), "served")
	base := readFile(t, filepath.Join(honest, "checkpoint"))
	for _, c := range []struct{ name, code string }{
		{"34-four-lines-and-wrong-origin", "checkpoint"},
		{"35-wrong-origin-and-forged-pi", "origin"},
		{"36-no-quorum-and-size-163", "quorum"},
		{"37-crlf", "note"},
	} {
		t.Run(c.name, func(t *testing.T) {
			head := readFile(t, filepath.Join(vectorRoot(), "checkpoints-bad", c.name+".checkpoint"))
			serve := func(head, want string) { runFourteenAnswer(t, servedWith(t, honest, head), anchor, want) }
			serve(head, c.code)
			if c.code == "note" {
				if strings.ReplaceAll(head, "\r\n", "\n") != base {
					t.Fatal("CRLF is not the sole change")
				}
				serve(base, "accept")
				return
			}
			body, _, err := note.Split(head)
			if err != nil {
				t.Fatal(err)
			}
			lines := strings.Split(strings.TrimSuffix(body, "\n"), "\n")
			switch c.code {
			case "checkpoint":
				if len(lines) != 4 || lines[0] == anchor.Origin {
					t.Fatal("both body faults are required")
				}
				serve(runFourteenSign(t, strings.Join(lines[:3], "\n")+"\n", anchor.Origin, true), "origin")
				lines[0] = anchor.Origin
				serve(runFourteenSign(t, strings.Join(lines, "\n")+"\n", anchor.Origin, true), "checkpoint")
			case "origin":
				// Restoring the signed text and all honest signatures except pi
				// preserves the forged pi line as a standalone cosignature fault.
				var badPi string
				for _, line := range strings.Split(head, "\n") {
					if strings.HasPrefix(line, "— norn-witness/pi ") {
						badPi = line
					}
				}
				if badPi == "" {
					t.Fatal("missing forged pi")
				}
				fixed := strings.Split(base, "\n")
				for i, line := range fixed {
					if strings.HasPrefix(line, "— norn-witness/pi ") {
						fixed[i] = badPi
					}
				}
				serve(strings.Join(fixed, "\n"), "cosignature")
				serve(runFourteenSign(t, body, anchor.Origin, true), "origin")
			case "quorum":
				if lines[1] != "163" {
					t.Fatal("must request one beyond served")
				}
				serve(runFourteenSign(t, body, anchor.Origin, true), "unserved")
				baseBody, _, err := note.Split(base)
				if err != nil {
					t.Fatal(err)
				}
				serve(runFourteenSign(t, baseBody, anchor.Origin, false), "quorum")
			}
			serve(base, "accept")
		})
	}
}

func checkRunFourteenServed(t *testing.T) {
	anchor := shippedLogAnchor(t)
	t.Run("zero-length entry", func(t *testing.T) {
		dir := filepath.Join(vectorRoot(), "served-empty-entry")
		var manifest struct {
			Codes       map[string]string
			ReplayCodes map[string]string `json:"replay_codes"`
		}
		if err := json.Unmarshal([]byte(readFile(t, filepath.Join(dir, "cases.json"))), &manifest); err != nil {
			t.Fatal(err)
		}
		if manifest.Codes["zero-length-entry"] != "accept" || manifest.ReplayCodes["2"] != "decode" {
			t.Fatal("manifest must state both answers")
		}
		result := runFourteenAnswer(t, dir, anchor, "accept")
		if len(result.Served) != 4 || len(result.Served[2]) != 0 || len(result.Served[1]) == 0 || len(result.Served[3]) == 0 {
			t.Fatal("empty frame must lie among real entries")
		}
		if len(result.State.Rejected) != 1 || result.State.Rejected[0].Index != 2 || result.State.Rejected[0].Reason != "decode" {
			t.Fatalf("empty entry replay: %+v", result.State.Rejected)
		}
		state, err := result.State.MarshalCanonical()
		if err != nil {
			t.Fatal(err)
		}
		if string(state) != readFile(t, filepath.Join(dir, "state.json")) {
			t.Fatal("replayed state differs")
		}
	})
	t.Run("full bundles and tiles have no trailing bytes", func(t *testing.T) {
		dir := filepath.Join(vectorRoot(), "served-large-bad")
		var manifest struct {
			ServeOver string `json:"serve_over"`
			Cases     []servedNegative
			Codes     map[string]string
		}
		if err := json.Unmarshal([]byte(readFile(t, filepath.Join(dir, "cases.json"))), &manifest); err != nil {
			t.Fatal(err)
		}
		if manifest.ServeOver != "served-large" || len(manifest.Cases) != 3 {
			t.Fatal("must cover both full paths and the level-1 tile over served-large")
		}
		for _, c := range manifest.Cases {
			t.Run(c.Name, func(t *testing.T) {
				honest := filepath.Join(vectorRoot(), manifest.ServeOver)
				copy := servedWith(t, honest, readFile(t, filepath.Join(honest, "checkpoint")))
				want := map[string]string{"full-entry-bundle-trailing-bytes": "entries", "full-hash-tile-trailing-bytes": "tiles", "level-one-byte-changed": "tiles"}[c.Name]
				if want == "" || manifest.Codes[c.Name] != want {
					t.Fatalf("%s is coded %q, SPEC states %q", c.Name, manifest.Codes[c.Name], want)
				}
				original := readFile(t, filepath.Join(honest, c.Path))
				bad := readFile(t, filepath.Join(dir, c.File))
				if c.Name == "level-one-byte-changed" {
					if c.Path != "tile/1/000.p/1" || len(bad) != len(original) || len(bad) != 32 {
						t.Fatal("must mutate the width-1 level-1 tile")
					}
					different := 0
					for i := range original {
						if original[i] != bad[i] {
							different++
						}
					}
					if different != 1 {
						t.Fatal("only one tile byte may differ")
					}
				} else {
					if len(bad) <= len(original) || !strings.HasPrefix(bad, original) {
						t.Fatal("only trailing bytes may differ")
					}
					if c.Path != "tile/entries/000" && c.Path != "tile/0/000" {
						t.Fatal("must mutate full width-256 paths")
					}
				}
				write(t, filepath.Join(copy, c.Path), bad)
				runFourteenAnswer(t, copy, anchor, manifest.Codes[c.Name])
				write(t, filepath.Join(copy, c.Path), original)
				runFourteenAnswer(t, copy, anchor, "accept")
			})
		}
	})
	for _, name := range []string{"other-genesis-missing-tile", "other-genesis-tampered-tile"} {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(vectorRoot(), "detect", name)
			readFile(t, filepath.Join(dir, "checkpoint"))
			runFourteenAnswer(t, dir, anchor, "genesis")
			cp := checkpointIn(t, dir, "checkpoint", anchor)
			entries, err := fetchEntries(Dir(dir), cp.Size)
			if err != nil {
				t.Fatal(err)
			}
			tree, err := tlog.Build(entries)
			if err != nil {
				t.Fatal(err)
			}
			want := "tiles"
			if strings.Contains(name, "missing") {
				want = "unserved"
			}
			if err := checkTiles(Dir(dir), tree, nil); err == nil {
				t.Fatal("the tile fault is absent")
			} else if code, _ := refusal.CodeOf(err); string(code) != want {
				t.Fatalf("tile fault is %s: %v", code, err)
			}
			copy := servedWith(t, dir, readFile(t, filepath.Join(dir, "checkpoint")))
			tiles, err := tree.Tiles()
			if err != nil {
				t.Fatal(err)
			}
			for _, tile := range tiles {
				if err := os.MkdirAll(filepath.Dir(filepath.Join(copy, tile.Path())), 0o755); err != nil {
					t.Fatal(err)
				}
				write(t, filepath.Join(copy, tile.Path()), string(tile.Data))
			}
			runFourteenAnswer(t, copy, anchor, "genesis")
			// Restore the anchored genesis and rebuild the bytes bound to it.
			fixture := runFourteenAnswer(t, filepath.Join(vectorRoot(), "served"), anchor, "accept")
			entries[0] = fixture.Served[0]
			goodTree, err := tlog.Build(entries)
			if err != nil {
				t.Fatal(err)
			}
			head := runFourteenSign(t, (tlog.Checkpoint{Origin: anchor.Origin, Size: cp.Size, Root: goodTree.Head()}).Marshal(), anchor.Origin, true)
			write(t, filepath.Join(copy, "checkpoint"), head)
			bundle, err := tlog.EncodeBundle(entries)
			if err != nil {
				t.Fatal(err)
			}
			write(t, filepath.Join(copy, tlog.EntryBundlePath(0, len(entries))), string(bundle))
			// Keep the broken tile while repairing entry 0, then repair the tile.
			if want == "unserved" {
				remove(t, filepath.Join(copy, tlog.TilePath(0, 0, len(entries))))
			} else {
				data := bytes.Clone(mustRunFourteenTile(t, goodTree))
				data[0] ^= 1
				write(t, filepath.Join(copy, tlog.TilePath(0, 0, len(entries))), string(data))
			}
			runFourteenAnswer(t, copy, anchor, want)
			write(t, filepath.Join(copy, tlog.TilePath(0, 0, len(entries))), string(mustRunFourteenTile(t, goodTree)))
			runFourteenAnswer(t, copy, anchor, "accept")
		})
	}
}

func mustRunFourteenTile(t *testing.T, tree *tlog.Tree) []byte {
	t.Helper()
	tiles, err := tree.Tiles()
	if err != nil || len(tiles) != 1 {
		t.Fatalf("small tree tiles: %v", err)
	}
	return tiles[0].Data
}

func checkRunFourteenLearnedKeys(t *testing.T) {
	fresh := shippedLogAnchor(t)
	honest := filepath.Join(vectorRoot(), "served")
	held := runFourteenAnswer(t, honest, fresh, "accept")
	informed := fresh
	informed.LogKeys = append(append([]string(nil), fresh.LogKeys...), KeysFrom(fresh.Origin, held.State)...)
	if published := PolicyFrom(held.State); published != "" {
		informed.Policy = published
	}
	for _, c := range []struct{ dir, want string }{{"served-rotated-wrong-name", "log-signature"}, {"served-rotated-earlier", "accept"}} {
		t.Run(c.dir, func(t *testing.T) {
			dir := filepath.Join(vectorRoot(), c.dir)
			var manifest struct {
				Fresh, Informed string
				SinceIndex      int64 `json:"since_index"`
			}
			if err := json.Unmarshal([]byte(readFile(t, filepath.Join(dir, "cases.json"))), &manifest); err != nil {
				t.Fatal(err)
			}
			if manifest.Fresh != "log-signature" || manifest.Informed != c.want || manifest.SinceIndex != 27 {
				t.Fatalf("wrong learned-key answers: %+v", manifest)
			}
			serve := dir
			if c.want == "log-signature" {
				serve = servedWith(t, honest, readFile(t, filepath.Join(dir, "checkpoint")))
			}
			runFourteenAnswer(t, serve, fresh, manifest.Fresh)
			result := runFourteenAnswer(t, serve, informed, manifest.Informed)
			if c.want == "accept" {
				head := readFile(t, filepath.Join(dir, "checkpoint"))
				if _, err := note.Verify(head, KeysFrom(fresh.Origin, held.State)[:1]); err != nil {
					t.Fatalf("the earlier head must use the key published at index 27: %v", err)
				}
			}
			if result != nil && result.Checkpoint.Size != 20 {
				t.Fatal("earlier head must be size 20")
			}
			if c.want == "log-signature" {
				runFourteenAnswer(t, servedWith(t, honest, readFile(t, filepath.Join(vectorRoot(), "served-rotated", "checkpoint"))), informed, "accept")
			}
		})
	}
}
