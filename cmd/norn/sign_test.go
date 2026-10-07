package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/onembyte/norn/internal/entry"
	"github.com/onembyte/norn/internal/keyfile"
	"github.com/onembyte/norn/internal/replay"
	"github.com/onembyte/norn/internal/state"
	"github.com/onembyte/norn/internal/trust"
)

// The test that decides whether `norn sign` works: a request made by `norn
// enroll` is signed by two signers and then **replayed into the fixture log**,
// which must accept it and show the device active. Anything less checks that
// the command runs, not that it produces a usable entry.

func fixtureKey(t *testing.T, name string) ed25519.PrivateKey {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(vectors(), "keys.json"))
	if err != nil {
		t.Fatal(err)
	}
	var keys struct {
		Ed25519 map[string]struct{ Seed string } `json:"ed25519"`
	}
	if err := json.Unmarshal(raw, &keys); err != nil {
		t.Fatal(err)
	}
	seed, err := hex.DecodeString(keys.Ed25519[name].Seed)
	if err != nil || len(seed) != ed25519.SeedSize {
		t.Fatalf("no usable seed for %q", name)
	}
	return ed25519.NewKeyFromSeed(seed)
}

// signerKeyFile writes a fixture signer's key in the tier-0 format.
func signerKeyFile(t *testing.T, dir, name string) string {
	t.Helper()
	path := filepath.Join(dir, name+".key")
	if err := keyfile.Write(path, fixtureKey(t, name), name); err != nil {
		t.Fatal(err)
	}
	return path
}

func fixtureLog(t *testing.T) ([][]byte, replay.Anchor) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(vectors(), "log", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Anchor struct {
			Net         string `json:"net"`
			GenesisHash string `json:"genesis_hash"`
		} `json:"anchor"`
		Entries []struct{ Name string } `json:"entries"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	var entries [][]byte
	for _, e := range manifest.Entries {
		b, err := os.ReadFile(filepath.Join(vectors(), "log", e.Name+".cbor"))
		if err != nil {
			t.Fatal(err)
		}
		entries = append(entries, b)
	}
	net, _ := hex.DecodeString(manifest.Anchor.Net)
	genesis, _ := hex.DecodeString(manifest.Anchor.GenesisHash)
	return entries, replay.Anchor{Net: net, GenesisHash: genesis}
}

func fixtureNetOrigin(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(vectors(), "trust.cbor"))
	if err != nil {
		t.Fatal(err)
	}
	anchor, err := trust.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return anchor.Origin
}

func run(t *testing.T, bin string, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	var out, errBuf strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &errBuf
	err = cmd.Run()
	return out.String(), errBuf.String(), err
}

// The whole enrolment path, end to end, ending in the log's own verdict.
func TestSignedEntryIsAcceptedByReplay(t *testing.T) {
	bin := nornBinary(t)
	dir := t.TempDir()
	trustFile := filepath.Join(vectors(), "trust.cbor")
	entries, anchor := fixtureLog(t)

	// 1. The device asks.
	requestText, stderr, err := enrollRun(t, bin, "-name", "signed-device",
		"-net", fixtureNetOrigin(t), "-key", filepath.Join(dir, "device.key"), "-gen")
	if err != nil {
		t.Fatalf("enroll: %v\n%s", err, stderr)
	}
	requestPath := filepath.Join(dir, "request.txt")
	if err := os.WriteFile(requestPath, []byte(requestText), 0o600); err != nil {
		t.Fatal(err)
	}

	// 2. The first signer signs. signer_thr is 2 at the end of the fixture, so
	//    one signature must not be enough -- the log has to say so itself.
	entryPath := filepath.Join(dir, "entry.cbor")
	_, stderr, err = run(t, bin, "sign", "-trust", trustFile, "-key", signerKeyFile(t, dir, "signer1"),
		"-after", "90", "-yes", "-o", entryPath, requestPath)
	if err != nil {
		t.Fatalf("first sign: %v\n%s", err, stderr)
	}

	once, err := os.ReadFile(entryPath)
	if err != nil {
		t.Fatal(err)
	}
	st := replay.Replay(anchor, append(append([][]byte{}, entries...), once))
	if last := st.Rejected[len(st.Rejected)-1]; last.Reason != replay.ReasonThreshold ||
		last.Index != uint64(len(entries)) {
		t.Fatalf("one signature should be refused `threshold`, got %+v", last)
	}

	// 3. The second signer appends to the same entry, which must not disturb
	//    the preimage the first signature covers.
	both := filepath.Join(dir, "entry2.cbor")
	_, stderr, err = run(t, bin, "sign", "-trust", trustFile, "-key", signerKeyFile(t, dir, "signer3"),
		"-yes", "-o", both, entryPath)
	if err != nil {
		t.Fatalf("second sign: %v\n%s", err, stderr)
	}

	final, err := os.ReadFile(both)
	if err != nil {
		t.Fatal(err)
	}
	env, err := entry.Decode(final)
	if err != nil {
		t.Fatalf("the twice-signed entry does not decode: %v", err)
	}
	if len(env.Sigs) != 2 {
		t.Fatalf("got %d signatures, want 2", len(env.Sigs))
	}

	st = replay.Replay(anchor, append(append([][]byte{}, entries...), final))
	device, ok := st.Devices["signed-device"]
	if !ok {
		t.Fatalf("the twice-signed entry was not accepted; last rejection %+v",
			st.Rejected[len(st.Rejected)-1])
	}
	if device.Status != state.StatusActive {
		t.Errorf("status = %s, want active", device.Status)
	}
	if device.SinceIndex != uint64(len(entries)) {
		t.Errorf("since_index = %d, want %d", device.SinceIndex, len(entries))
	}
}

// Appending a signature must leave every earlier signature valid, which is only
// true because the preimage excludes `sigs` (§4.2).
func TestAppendingASignatureKeepsTheFirstOneValid(t *testing.T) {
	bin := nornBinary(t)
	dir := t.TempDir()
	trustFile := filepath.Join(vectors(), "trust.cbor")

	requestText, _, err := enrollRun(t, bin, "-name", "two-sigs", "-net", fixtureNetOrigin(t),
		"-key", filepath.Join(dir, "device.key"), "-gen")
	if err != nil {
		t.Fatal(err)
	}
	requestPath := filepath.Join(dir, "r.txt")
	if err := os.WriteFile(requestPath, []byte(requestText), 0o600); err != nil {
		t.Fatal(err)
	}

	first := filepath.Join(dir, "one.cbor")
	if _, stderr, err := run(t, bin, "sign", "-trust", trustFile,
		"-key", signerKeyFile(t, dir, "signer1"), "-after", "90", "-yes",
		"-o", first, requestPath); err != nil {
		t.Fatalf("%v\n%s", err, stderr)
	}
	second := filepath.Join(dir, "two.cbor")
	if _, stderr, err := run(t, bin, "sign", "-trust", trustFile,
		"-key", signerKeyFile(t, dir, "signer3"), "-yes", "-o", second, first); err != nil {
		t.Fatalf("%v\n%s", err, stderr)
	}

	raw, err := os.ReadFile(second)
	if err != nil {
		t.Fatal(err)
	}
	env, err := entry.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	publics := map[string]ed25519.PublicKey{}
	for _, name := range []string{"signer1", "signer3"} {
		key := fixtureKey(t, name).Public().(ed25519.PublicKey)
		publics[entry.Kid(key)] = key
	}
	kids := make([]string, 0, len(env.Sigs))
	for _, sig := range env.Sigs {
		public, ok := publics[sig.Kid]
		if !ok {
			t.Fatalf("unexpected signature by %s", sig.Kid)
		}
		valid, err := entry.Verify(env, sig, public)
		if err != nil || !valid {
			t.Errorf("signature by %s stopped verifying: %v", sig.Kid, err)
		}
		kids = append(kids, sig.Kid)
	}
	if !sort.StringsAreSorted(kids) {
		t.Errorf("signatures are not sorted by kid: %v", kids)
	}
}

func TestSignRefusals(t *testing.T) {
	bin := nornBinary(t)
	dir := t.TempDir()
	trustFile := filepath.Join(vectors(), "trust.cbor")
	key := signerKeyFile(t, dir, "signer1")
	root := signerKeyFile(t, dir, "root1")

	requestText, _, err := enrollRun(t, bin, "-name", "refusals", "-net", fixtureNetOrigin(t),
		"-key", filepath.Join(dir, "device.key"), "-gen")
	if err != nil {
		t.Fatal(err)
	}
	good := filepath.Join(dir, "good.txt")
	if err := os.WriteFile(good, []byte(requestText), 0o600); err != nil {
		t.Fatal(err)
	}

	// A request whose signature has been tampered with: one character of the
	// bech32m payload changed, which the checksum catches, and a re-checksummed
	// body, which only Ed25519 catches.
	corrupt := filepath.Join(dir, "corrupt.txt")
	text := strings.TrimSpace(requestText)
	swapped := "q"
	if text[20] == 'q' {
		swapped = "p"
	}
	if err := os.WriteFile(corrupt, []byte(text[:20]+swapped+text[21:]), 0o600); err != nil {
		t.Fatal(err)
	}

	// A separate directory: `-gen` refuses to replace an existing wg.key, which
	// is the right rule and makes one enrolment per directory.
	elsewhere := t.TempDir()
	foreign := filepath.Join(dir, "foreign.txt")
	foreignText, _, err := enrollRun(t, bin, "-name", "elsewhere",
		"-net", "norn/n5xw6zdmnrxxq33vojqxezlbnq",
		"-key", filepath.Join(elsewhere, "other.key"), "-gen")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(foreign, []byte(foreignText), 0o600); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		why  string
		args []string
		says string
	}{
		{"no trust file", []string{"sign", "-key", key, "-yes", good}, "-trust is required"},
		{"no input", []string{"sign", "-trust", trustFile, "-key", key, "-yes"}, "exactly one"},
		{"a corrupted request", []string{"sign", "-trust", trustFile, "-key", key,
			"-after", "90", "-yes", corrupt}, "does not"},
		{"another network's request", []string{"sign", "-trust", trustFile, "-key", key,
			"-after", "90", "-yes", foreign}, "another network"},
		{"no way to learn the log size", []string{"sign", "-trust", trustFile, "-key", key,
			"-log", filepath.Join(dir, "absent"), "-yes", good}, "-after"},
		// §16.3: `--yes` MUST NOT exist for the root role. The key here is a
		// real root's, so on a broken build this case does not merely mislabel
		// an entry — it mints a scripted root authorization, the exact thing
		// the rule exists to prevent.
		{"--yes for the root role", []string{"sign", "-trust", trustFile, "-key", root,
			"-after", "90", "-yes", "-role", "root", good}, "never exercised by a script"},
	}
	for _, c := range cases {
		t.Run(c.why, func(t *testing.T) {
			stdout, stderr, err := run(t, bin, c.args...)
			if err == nil {
				t.Fatalf("accepted: %s", c.why)
			}
			if !strings.Contains(stderr, c.says) {
				t.Errorf("stderr should mention %q:\n%s", c.says, stderr)
			}
			if stdout != "" {
				t.Errorf("a refused run wrote an entry to stdout")
			}
		})
	}
}

// UX rule 1: what you sign is what you see.
func TestSignSummaryShowsEverythingTheSignatureCovers(t *testing.T) {
	bin := nornBinary(t)
	dir := t.TempDir()

	requestText, _, err := enrollRun(t, bin, "-name", "shown", "-net", fixtureNetOrigin(t),
		"-key", filepath.Join(dir, "device.key"), "-gen",
		"-label", "ip=10.9.0.31/32", "-expires", "30d")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "r.txt")
	if err := os.WriteFile(path, []byte(requestText), 0o600); err != nil {
		t.Fatal(err)
	}

	_, stderr, err := run(t, bin, "sign", "-trust", filepath.Join(vectors(), "trust.cbor"),
		"-key", signerKeyFile(t, dir, "signer1"), "-after", "90", "-yes",
		"-o", filepath.Join(dir, "e.cbor"), path)
	if err != nil {
		t.Fatalf("%v\n%s", err, stderr)
	}
	for _, want := range []string{"shown", "ip=10.9.0.31/32", "expires", "after      90",
		"entry hash", "wireguard", "device key", "signing as"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("the summary omits %q:\n%s", want, stderr)
		}
	}
}

// Signing through a real ssh-agent, which §16.3 makes the default for signers
// and the only option for a hardware root. This closes the
// loop: a key file Norn wrote, loaded by ssh-add, used by norn sign, producing
// an entry the log accepts.
func TestSignThroughARealAgent(t *testing.T) {
	for _, tool := range []string{"ssh-agent", "ssh-add"} {
		if _, err := exec.LookPath(tool); err != nil {
			if os.Getenv("NORN_REQUIRE_SSH_AGENT") != "" {
				t.Fatalf("NORN_REQUIRE_SSH_AGENT is set but %s is missing", tool)
			}
			t.Skipf("%s is not installed", tool)
		}
	}

	bin := nornBinary(t)
	work := t.TempDir()
	short, err := os.MkdirTemp("", "na") // a socket path inside the platform limit
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(short)
	socket := filepath.Join(short, "agent")

	agent := exec.Command("ssh-agent", "-D", "-a", socket)
	if err := agent.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = agent.Process.Kill()
		_, _ = agent.Process.Wait()
	}()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(socket); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("ssh-agent never created its socket")
		}
		time.Sleep(10 * time.Millisecond)
	}

	key := signerKeyFile(t, work, "signer1")
	add := exec.Command("ssh-add", key)
	add.Env = append(os.Environ(), "SSH_AUTH_SOCK="+socket)
	if out, err := add.CombinedOutput(); err != nil {
		t.Fatalf("ssh-add: %v: %s", err, out)
	}

	requestText, _, err := enrollRun(t, bin, "-name", "agent-signed", "-net", fixtureNetOrigin(t),
		"-key", filepath.Join(work, "device.key"), "-gen")
	if err != nil {
		t.Fatal(err)
	}
	requestPath := filepath.Join(work, "r.txt")
	if err := os.WriteFile(requestPath, []byte(requestText), 0o600); err != nil {
		t.Fatal(err)
	}

	// No -key: the agent holds exactly one Ed25519 key, so it is unambiguous.
	entryPath := filepath.Join(work, "e.cbor")
	cmd := exec.Command(bin, "sign", "-trust", filepath.Join(vectors(), "trust.cbor"),
		"-after", "90", "-yes", "-o", entryPath, requestPath)
	cmd.Env = append(os.Environ(), "SSH_AUTH_SOCK="+socket)
	var errBuf strings.Builder
	cmd.Stderr = &errBuf
	if err := cmd.Run(); err != nil {
		t.Fatalf("sign through the agent: %v\n%s", err, errBuf.String())
	}

	raw, err := os.ReadFile(entryPath)
	if err != nil {
		t.Fatal(err)
	}
	env, err := entry.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	public := fixtureKey(t, "signer1").Public().(ed25519.PublicKey)
	if len(env.Sigs) != 1 || env.Sigs[0].Kid != entry.Kid(public) {
		t.Fatalf("sigs = %+v", env.Sigs)
	}
	valid, err := entry.Verify(env, env.Sigs[0], public)
	if err != nil || !valid {
		t.Fatalf("the agent's signature does not verify in the entry: %v", err)
	}
}
