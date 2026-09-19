package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/onembyte/norn/internal/enrollreq"
	"github.com/onembyte/norn/internal/entry"
	"github.com/onembyte/norn/internal/keyfile"
	"github.com/onembyte/norn/internal/logserver"
	"github.com/onembyte/norn/internal/tlogstore"
	"github.com/onembyte/norn/internal/trust"
)

func vectors() string { return filepath.Join("..", "..", "testdata", "vectors") }

func build(t *testing.T, pkg, name string) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), name)
	out, err := exec.Command("go", "build", "-o", bin, pkg).CombinedOutput()
	if err != nil {
		t.Fatalf("building %s: %v\n%s", pkg, err, out)
	}
	return bin
}

func seed(t *testing.T, name string) ed25519.PrivateKey {
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
	s, err := hex.DecodeString(keys.Ed25519[name].Seed)
	if err != nil || len(s) != ed25519.SeedSize {
		t.Fatalf("no seed for %q", name)
	}
	return ed25519.NewKeyFromSeed(s)
}

func anchorOf(t *testing.T) *trust.Trust {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(vectors(), "trust.cbor"))
	if err != nil {
		t.Fatal(err)
	}
	a, err := trust.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// seededLog builds a log directory holding the fixture's entries, signed by the
// key the vectors' trust file actually names.
func seededLog(t *testing.T) (dir string, entries [][]byte, anchor *trust.Trust) {
	t.Helper()
	anchor = anchorOf(t)
	dir = t.TempDir()
	store, err := tlogstore.Open(dir, anchor.Origin, seed(t, "logkey"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(vectors(), "log", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Entries []struct{ Name string } `json:"entries"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	for _, e := range manifest.Entries {
		b, err := os.ReadFile(filepath.Join(vectors(), "log", e.Name+".cbor"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.Append(b); err != nil {
			t.Fatal(err)
		}
		entries = append(entries, b)
	}
	return dir, entries, anchor
}

func freePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

// A log a signer can submit to and a verifier can read, over HTTP, as two
// separate processes -- which is what the lab will actually run.
func TestNornLogServesAndAccepts(t *testing.T) {
	logBin := build(t, ".", "norn-log")
	nornBin := build(t, "../norn", "norn")
	dir, entries, anchor := seededLog(t)

	keyPath := filepath.Join(t.TempDir(), "log.key")
	if err := keyfile.Write(keyPath, seed(t, "logkey"), "norn log key"); err != nil {
		t.Fatal(err)
	}
	addr := freePort(t)

	server := exec.Command(logBin, "-dir", dir, "-key", keyPath,
		"-trust", filepath.Join(vectors(), "trust.cbor"), "-listen", addr)
	server.Stderr = os.Stderr
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = server.Process.Kill()
		_, _ = server.Process.Wait()
	})

	base := "http://" + addr
	deadline := time.Now().Add(10 * time.Second)
	for {
		if resp, err := http.Get(base + "/checkpoint"); err == nil {
			resp.Body.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("norn-log never came up")
		}
		time.Sleep(20 * time.Millisecond)
	}

	// Build a submittable enrolment for this network.
	devicePub, devicePriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	wg := make([]byte, 32)
	wg[0] = 7
	request, err := enrollreq.New(anchor.Net, "over-http", devicePub, wg, 1_760_200_000, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := enrollreq.Sign(request, devicePriv); err != nil {
		t.Fatal(err)
	}
	body, err := enrollreq.Encode(request)
	if err != nil {
		t.Fatal(err)
	}
	after := uint64(len(entries))
	env := &entry.Envelope{V: entry.Version, T: "enroll", Net: anchor.Net,
		TS: 1_760_200_000, After: &after, Body: map[string]any{"request": body}}
	for _, name := range []string{"signer1", "signer3"} {
		if err := entry.Sign(env, seed(t, name), "signer"); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := entry.Encode(env)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := http.Post(base+logserver.AddPath, logserver.ContentType, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("submit: status %d", resp.StatusCode)
	}

	// And `norn verify`, a different binary, reads the result over HTTP.
	out, err := exec.Command(nornBin, "verify", "-trust",
		filepath.Join(vectors(), "trust.cbor"), "-log", base).CombinedOutput()
	if err != nil {
		t.Fatalf("norn verify: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "over-http") {
		t.Errorf("the submitted device is not in the verifier's view:\n%s", out)
	}
	if !strings.Contains(string(out), fmt.Sprintf("%d entries", len(entries)+1)) {
		t.Errorf("the log did not grow by one:\n%s", out)
	}
}

// §9.1 binds the log key's note name to the origin. A key the network's trust
// file does not name would sign checkpoints nobody there can verify, so it is
// refused at startup rather than at the first submission.
func TestNornLogRefusesTheWrongKey(t *testing.T) {
	logBin := build(t, ".", "norn-log")
	dir, _, _ := seededLog(t)

	keyPath := filepath.Join(t.TempDir(), "wrong.key")
	if err := keyfile.Write(keyPath, seed(t, "signer1"), "not the log key"); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(logBin, "-dir", dir, "-key", keyPath,
		"-trust", filepath.Join(vectors(), "trust.cbor"),
		"-listen", freePort(t)).CombinedOutput()
	if err == nil {
		t.Fatal("started with a key the trust file does not name")
	}
	if !strings.Contains(string(out), "not the log key in") {
		t.Errorf("the error should say what is wrong:\n%s", out)
	}
}

func TestNornLogNeedsItsFlags(t *testing.T) {
	logBin := build(t, ".", "norn-log")
	for _, missing := range []string{"-dir", "-key", "-trust"} {
		args := []string{"-dir", t.TempDir(), "-key", "k", "-trust", "t"}
		for i, a := range args {
			if a == missing {
				args = append(args[:i], args[i+2:]...)
				break
			}
		}
		out, err := exec.Command(logBin, args...).CombinedOutput()
		if err == nil {
			t.Errorf("started without %s", missing)
		}
		if !strings.Contains(string(out), missing+" is required") {
			t.Errorf("the error should name %s:\n%s", missing, out)
		}
	}
}
