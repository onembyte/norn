package sshagent_test

import (
	"crypto"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/onembyte/norn/internal/entry"
	"github.com/onembyte/norn/internal/sshagent"
)

// This file is the reason the client may be hand-written at all. A fake agent
// proves only that this package agrees with a fake this package's author also
// wrote; OpenSSH's ssh-agent is the implementation every other agent is
// compatible with, so passing here is agreement with the ecosystem.
//
// Set NORN_REQUIRE_SSH_AGENT=1 (CI does) to turn "not installed" into a
// failure, so the test cannot quietly stop running everywhere at once.

const requireEnv = "NORN_REQUIRE_SSH_AGENT"

func needTools(t *testing.T) {
	t.Helper()
	for _, tool := range []string{"ssh-agent", "ssh-keygen", "ssh-add"} {
		if _, err := exec.LookPath(tool); err != nil {
			if os.Getenv(requireEnv) != "" {
				t.Fatalf("%s is set but %s is not installed", requireEnv, tool)
			}
			t.Skipf("%s is not installed; set %s to make this a failure", tool, requireEnv)
		}
	}
}

// startAgent runs a real ssh-agent in the foreground and loads one freshly
// generated Ed25519 key into it. It returns the socket and the public key as
// ssh-keygen wrote it.
func startAgent(t *testing.T) (socket string, public ed25519.PublicKey, comment string) {
	t.Helper()
	needTools(t)

	// Unix socket paths are short; a long TMPDIR would fail to bind.
	dir, err := os.MkdirTemp("", "na")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	socket = filepath.Join(dir, "agent")
	agent := exec.Command("ssh-agent", "-D", "-a", socket)
	agent.Stderr = os.Stderr
	if err := agent.Start(); err != nil {
		t.Fatalf("starting ssh-agent: %v", err)
	}
	t.Cleanup(func() {
		_ = agent.Process.Kill()
		_, _ = agent.Process.Wait()
	})

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

	comment = "norn-test-key"
	key := filepath.Join(dir, "id")
	gen := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", comment, "-f", key)
	if out, err := gen.CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen: %v: %s", err, out)
	}

	add := exec.Command("ssh-add", key)
	add.Env = append(os.Environ(), sshagent.SocketEnv+"="+socket)
	if out, err := add.CombinedOutput(); err != nil {
		t.Fatalf("ssh-add: %v: %s", err, out)
	}

	return socket, readPublicKey(t, key+".pub"), comment
}

// readPublicKey parses "ssh-ed25519 <base64 blob> <comment>" without help from
// the package under test: the blob's own encoding is what is being checked.
func readPublicKey(t *testing.T, path string) ed25519.PublicKey {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Fields(string(raw))
	if len(parts) < 2 || parts[0] != sshagent.KeyType {
		t.Fatalf("unexpected public key file: %q", raw)
	}
	blob, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	// blob = string("ssh-ed25519") || string(pk); the key is the last 32 bytes.
	if len(blob) != 4+len(sshagent.KeyType)+4+ed25519.PublicKeySize {
		t.Fatalf("blob is %d bytes", len(blob))
	}
	return ed25519.PublicKey(blob[len(blob)-ed25519.PublicKeySize:])
}

func TestRealAgentListsTheKeyItWasGiven(t *testing.T) {
	socket, public, comment := startAgent(t)

	client, err := sshagent.Dial(socket)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	keys, err := client.Keys()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 {
		t.Fatalf("got %d keys, want 1", len(keys))
	}
	if !keys[0].Public.Equal(public) {
		t.Errorf("key = %x, want %x", keys[0].Public, public)
	}
	if keys[0].Comment != comment {
		t.Errorf("comment = %q, want %q", keys[0].Comment, comment)
	}
}

func TestRealAgentSignsAnEntry(t *testing.T) {
	socket, public, _ := startAgent(t)

	client, err := sshagent.Dial(socket)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	signer, err := client.Signer(public)
	if err != nil {
		t.Fatal(err)
	}

	// The whole point of the seam: an entry cannot tell an agent-held key from
	// a key in memory, and the result is an ordinary §4.2 signature.
	env := &entry.Envelope{
		V: entry.Version, T: "note", Net: make([]byte, entry.NetLen), TS: 1,
		Body: map[string]any{"text": "signed by a real ssh-agent"},
	}
	if err := entry.Sign(env, signer, "signer"); err != nil {
		t.Fatalf("entry.Sign through an agent: %v", err)
	}
	if len(env.Sigs) != 1 || env.Sigs[0].Kid != entry.Kid(public) {
		t.Fatalf("sigs = %+v", env.Sigs)
	}
	ok, err := entry.Verify(env, env.Sigs[0], public)
	if err != nil || !ok {
		t.Fatalf("the agent's signature does not verify as an entry signature: %v", err)
	}

	// And the bytes are a plain Ed25519 signature over the preimage, which is
	// what makes an agent usable at all (`ENROLLMENT.md` part 1).
	pre, err := entry.Preimage(env)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(public, pre, env.Sigs[0].Sig) {
		t.Error("not a plain Ed25519 signature over the preimage")
	}
}

func TestRealAgentRefusesAKeyItDoesNotHold(t *testing.T) {
	socket, _, _ := startAgent(t)
	other, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	client, err := sshagent.Dial(socket)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	if _, err := client.Signer(other); err == nil {
		t.Fatal("got a signer for a key the agent never saw")
	}
}

func TestOpenUsesTheEnvironment(t *testing.T) {
	socket, public, _ := startAgent(t)
	t.Setenv(sshagent.SocketEnv, socket)

	client, err := sshagent.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	signer, err := client.Signer(public)
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("norn/entry/v1\nvia the environment")
	sig, err := signer.Sign(nil, message, crypto.Hash(0))
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(public, message, sig) {
		t.Fatal("signature does not verify")
	}
	if errors.Is(err, sshagent.ErrNoAgent) {
		t.Fatal("unreachable")
	}
}
