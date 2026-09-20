package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/onembyte/norn/internal/entry"
	"github.com/onembyte/norn/internal/keyfile"
	"github.com/onembyte/norn/internal/note"
	"github.com/onembyte/norn/internal/tlogstore"
	"github.com/onembyte/norn/internal/trust"
)

// A running log to submit to: the real `norn-log`, not a double.
func runningLog(t *testing.T) (base string, anchor *trust.Trust) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(vectors(), "trust.cbor"))
	if err != nil {
		t.Fatal(err)
	}
	anchor, err = trust.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	logkey := fixtureKey(t, "logkey")
	store, err := tlogstore.Open(dir, anchor.Origin, logkey)
	if err != nil {
		t.Fatal(err)
	}
	entries, _ := fixtureLog(t)
	for _, e := range entries {
		if _, err := store.Append(e); err != nil {
			t.Fatal(err)
		}
	}

	keyPath := filepath.Join(t.TempDir(), "log.key")
	if err := keyfile.Write(keyPath, logkey, "log"); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	listener.Close()

	bin := filepath.Join(t.TempDir(), "norn-log")
	if out, err := exec.Command("go", "build", "-o", bin, "../norn-log").CombinedOutput(); err != nil {
		t.Fatalf("building norn-log: %v\n%s", err, out)
	}
	// The fixture's policy needs two of three witnesses, so the log must be
	// able to produce their cosignatures or no verifier will read it.
	server := exec.Command(bin, "-dir", dir, "-key", keyPath,
		"-trust", filepath.Join(vectors(), "trust.cbor"), "-listen", addr,
		"-self-witness", "pi="+witnessKeyFile(t, "pi"),
		"-self-witness", "vps="+witnessKeyFile(t, "vps"))
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = server.Process.Kill()
		_, _ = server.Process.Wait()
	})

	base = "http://" + addr
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
	return base, anchor
}

// The whole of Phase 2 in one test: a device asks, two signers agree, the log
// accepts, and a verifier -- a different process, reading over HTTP -- sees the
// device active. Four binaries' worth of protocol, end to end.
func TestEnrollSignSubmitVerify(t *testing.T) {
	bin := nornBinary(t)
	base, _ := runningLog(t)
	dir := t.TempDir()
	trustFile := filepath.Join(vectors(), "trust.cbor")

	requestText, stderr, err := enrollRun(t, bin, "-name", "end-to-end",
		"-net", fixtureNetOrigin(t), "-key", filepath.Join(dir, "device.key"), "-gen")
	if err != nil {
		t.Fatalf("enroll: %v\n%s", err, stderr)
	}
	requestPath := filepath.Join(dir, "request.txt")
	if err := os.WriteFile(requestPath, []byte(requestText), 0o600); err != nil {
		t.Fatal(err)
	}

	entryPath := filepath.Join(dir, "entry.cbor")
	if _, stderr, err := run(t, bin, "sign", "-trust", trustFile, "-log", base,
		"-key", signerKeyFile(t, dir, "signer1"), "-yes", "-o", entryPath,
		requestPath); err != nil {
		t.Fatalf("first sign: %v\n%s", err, stderr)
	}
	signedPath := filepath.Join(dir, "entry2.cbor")
	if _, stderr, err := run(t, bin, "sign", "-trust", trustFile, "-log", base,
		"-key", signerKeyFile(t, dir, "signer3"), "-yes", "-o", signedPath,
		entryPath); err != nil {
		t.Fatalf("second sign: %v\n%s", err, stderr)
	}

	_, stderr, err = run(t, bin, "submit", "-trust", trustFile, "-log", base,
		"-wait", signedPath)
	if err != nil {
		t.Fatalf("submit: %v\n%s", err, stderr)
	}
	if !strings.Contains(stderr, "Included at index") {
		t.Errorf("submit should report inclusion:\n%s", stderr)
	}

	// The receipt was kept, and it is a note about *this* entry.
	stored, err := os.ReadFile(signedPath + ".receipt")
	if err != nil {
		t.Fatalf("the receipt was not kept: %v", err)
	}
	raw, err := os.ReadFile(signedPath)
	if err != nil {
		t.Fatal(err)
	}
	text, err := note.Verify(string(stored), []string{trustLogKey(t)})
	if err != nil {
		t.Fatalf("the kept receipt does not verify: %v", err)
	}
	want, err := note.ReceiptText(fixtureNetOrigin(t), entry.LeafHash(raw), 0)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Split(text, "\n")[2] != strings.Split(want, "\n")[2] {
		t.Error("the kept receipt is about a different leaf")
	}

	// And an independent verifier sees the device.
	out, err := exec.Command(bin, "verify", "-trust", trustFile, "-log", base).CombinedOutput()
	if err != nil {
		t.Fatalf("verify: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "end-to-end") {
		t.Errorf("the verifier does not see the device:\n%s", out)
	}
}

func trustLogKey(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(vectors(), "trust.cbor"))
	if err != nil {
		t.Fatal(err)
	}
	anchor, err := trust.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return anchor.LogKey
}

func TestSubmitRefusesAnEntryTheLogRejects(t *testing.T) {
	bin := nornBinary(t)
	base, anchor := runningLog(t)
	dir := t.TempDir()
	trustFile := filepath.Join(vectors(), "trust.cbor")

	// `nas` is already active in the fixture, so this is `dup-id`.
	requestText, _, err := enrollRun(t, bin, "-name", "nas", "-net", anchor.Origin,
		"-key", filepath.Join(dir, "device.key"), "-gen")
	if err != nil {
		t.Fatal(err)
	}
	requestPath := filepath.Join(dir, "r.txt")
	if err := os.WriteFile(requestPath, []byte(requestText), 0o600); err != nil {
		t.Fatal(err)
	}
	entryPath := filepath.Join(dir, "e.cbor")
	for _, signer := range []string{"signer1", "signer3"} {
		in, out := requestPath, entryPath
		if signer == "signer3" {
			in, out = entryPath, entryPath+"2"
		}
		if _, stderr, err := run(t, bin, "sign", "-trust", trustFile, "-log", base,
			"-key", signerKeyFile(t, dir, signer), "-yes", "-o", out, in); err != nil {
			t.Fatalf("sign with %s: %v\n%s", signer, err, stderr)
		}
	}

	_, stderr, err := run(t, bin, "submit", "-trust", trustFile, "-log", base, entryPath+"2")
	if err == nil {
		t.Fatal("submitted an entry the log rejects")
	}
	if !strings.Contains(stderr, "dup-id") || !strings.Contains(stderr, "advisory") {
		t.Errorf("the reason and its advisory status belong in the message:\n%s", stderr)
	}
}

// A log can hand back a receipt that verifies and still means nothing useful.
// These are the answers `norn submit` must not accept.
func TestSubmitRefusesAnUnusableReceipt(t *testing.T) {
	bin := nornBinary(t)
	dir := t.TempDir()
	trustFile := filepath.Join(vectors(), "trust.cbor")
	anchorOrigin := fixtureNetOrigin(t)
	logkey := fixtureKey(t, "logkey")

	entries, _ := fixtureLog(t)
	entryPath := filepath.Join(dir, "e.cbor")
	if err := os.WriteFile(entryPath, entries[1], 0o600); err != nil {
		t.Fatal(err)
	}
	leaf := entry.LeafHash(entries[1])

	receiptFor := func(t *testing.T, leaf []byte, deadline uint64, origin string) string {
		t.Helper()
		text, err := note.ReceiptText(origin, leaf, deadline)
		if err != nil {
			t.Fatal(err)
		}
		signed, err := note.Sign(text, anchorOrigin, logkey)
		if err != nil {
			t.Fatal(err)
		}
		return signed
	}

	other := entry.LeafHash(entries[2])
	cases := []struct {
		why  string
		body string
		says string
	}{
		{"about another entry", receiptFor(t, other, uint64(time.Now().Unix())+60, anchorOrigin),
			"different entry"},
		{"already expired", receiptFor(t, leaf, uint64(time.Now().Unix())-1, anchorOrigin),
			"already passed"},
		{"for another log", receiptFor(t, leaf, uint64(time.Now().Unix())+60, "norn/elsewhere"),
			"receipt"},
		{"not a note at all", "thanks!", "receipt"},
	}
	for _, c := range cases {
		t.Run(c.why, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(c.body))
			}))
			defer server.Close()

			_, stderr, err := run(t, bin, "submit", "-trust", trustFile,
				"-log", server.URL, entryPath)
			if err == nil {
				t.Fatalf("accepted a receipt that is %s", c.why)
			}
			if !strings.Contains(stderr, c.says) {
				t.Errorf("the error should mention %q:\n%s", c.says, stderr)
			}
			if _, err := os.Stat(entryPath + ".receipt"); err == nil {
				t.Error("an unusable receipt was kept as if it were evidence")
			}
		})
	}
}

func TestSubmitRefusals(t *testing.T) {
	bin := nornBinary(t)
	dir := t.TempDir()
	trustFile := filepath.Join(vectors(), "trust.cbor")

	junk := filepath.Join(dir, "junk.cbor")
	if err := os.WriteFile(junk, []byte("not an entry"), 0o600); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		why  string
		args []string
		says string
	}{
		{"no trust file", []string{"submit", junk}, "-trust is required"},
		{"no entry", []string{"submit", "-trust", trustFile}, "exactly one"},
		{"a file that is not an entry", []string{"submit", "-trust", trustFile,
			"-log", "http://127.0.0.1:1", junk}, "not a well-formed entry"},
	}
	for _, c := range cases {
		t.Run(c.why, func(t *testing.T) {
			if _, stderr, err := run(t, bin, c.args...); err == nil {
				t.Fatalf("accepted: %s", c.why)
			} else if !strings.Contains(stderr, c.says) {
				t.Errorf("stderr should mention %q:\n%s", c.says, stderr)
			}
		})
	}
}

// witnessKeyFile writes one of the fixture's witness keys where norn-log can
// read it, and returns the path.
func witnessKeyFile(t *testing.T, name string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name+".key")
	if err := keyfile.Write(path, fixtureKey(t, "witness-"+name), "norn witness key"); err != nil {
		t.Fatal(err)
	}
	return path
}
