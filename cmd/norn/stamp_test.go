package main

import (
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// `norn stamp` is the producing half of the anchoring gate line: it obtains a
// proof and writes it where `norn verify --anchored` looks.

func TestStampWritesAProofVerifyCanRead(t *testing.T) {
	bin := nornBinary(t)
	response, err := os.ReadFile(filepath.Join(vectors(), "anchors", "calendar-response.bin"))
	if err != nil {
		t.Fatal(err)
	}
	calendar := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/digest" || r.Method != http.MethodPost {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write(response)
	}))
	defer calendar.Close()

	out := t.TempDir()
	trustFile := filepath.Join(vectors(), "trust.cbor")
	served := filepath.Join(vectors(), "served")

	stdout, stderr, err := run(t, bin, "stamp", "-trust", trustFile, "-log", served,
		"-out", out, "-calendars", calendar.URL)
	if err != nil {
		t.Fatalf("stamp: %v\n%s", err, stderr)
	}
	if !strings.Contains(stdout, servedSize(t)+".ots") {
		t.Errorf("the path written should be reported:\n%s", stdout)
	}
	// It must be honest that a fresh stamp is not yet evidence.
	if !strings.Contains(stdout, "Bitcoin block") {
		t.Errorf("the output should say what has and has not happened yet:\n%s", stdout)
	}

	// The two halves meet: what `stamp` wrote, `verify --anchored` reads.
	anchored := t.TempDir()
	copyDir(t, served, anchored)
	proof, err := os.ReadFile(filepath.Join(out, "anchors", servedSize(t)+".ots"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(anchored, "anchors"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(anchored, "anchors", servedSize(t)+".ots"), proof, 0o644); err != nil {
		t.Fatal(err)
	}
	report, stderr, err := run(t, bin, "verify", "-trust", trustFile, "-log", anchored, "-anchored")
	if err != nil {
		t.Fatalf("verify -anchored on a freshly stamped log: %v\n%s", err, stderr)
	}
	if !strings.Contains(report, "not yet anchored") {
		t.Errorf("a pending stamp should read as not yet anchored:\n%s", report)
	}
}

// A log that does not verify is not stamped. A timestamp over a checkpoint
// this network refuses would be a timestamp on somebody else's document.
func TestStampRefusesALogThatDoesNotVerify(t *testing.T) {
	bin := nornBinary(t)
	broken := t.TempDir()
	copyDir(t, filepath.Join(vectors(), "served"), broken)
	// Remove the cosignatures: a head no quorum vouched for.
	raw, err := os.ReadFile(filepath.Join(broken, "checkpoint"))
	if err != nil {
		t.Fatal(err)
	}
	var kept []string
	for _, line := range strings.Split(string(raw), "\n") {
		if !strings.Contains(line, "norn-witness/") {
			kept = append(kept, line)
		}
	}
	if err := os.WriteFile(filepath.Join(broken, "checkpoint"),
		[]byte(strings.Join(kept, "\n")), 0o644); err != nil {
		t.Fatal(err)
	}

	_, stderr, err := run(t, bin, "stamp", "-trust", filepath.Join(vectors(), "trust.cbor"),
		"-log", broken, "-out", t.TempDir(), "-calendars", "http://127.0.0.1:1")
	if err == nil {
		t.Fatal("a log that does not verify was stamped")
	}
	if !strings.Contains(stderr, "does not verify") {
		t.Errorf("the reason should be plain:\n%s", stderr)
	}
}

// The digest is over the checkpoint body, not the signed note -- so a stamp
// keeps matching as witnesses cosign.
func TestTheStampedDigestIsTheBody(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(vectors(), "served", "checkpoint"))
	if err != nil {
		t.Fatal(err)
	}
	body, _, _ := strings.Cut(string(raw), "\n\n")
	want := sha256.Sum256([]byte(body + "\n\n"))

	// The committed vector was built over exactly this, by the reference
	// implementation -- so if the rule here ever drifts, that file stops
	// matching and this test says which.
	proof, err := os.ReadFile(anchorProof(t))
	if err != nil {
		t.Fatal(err)
	}
	// The digest sits right after the magic, the version and the hash-op tag.
	const headerLen = 31 + 1 + 1
	if got := proof[headerLen : headerLen+32]; string(got) != string(want[:]) {
		t.Errorf("the vector is over %x…, this build stamps %x…", got[:8], want[:8])
	}
}

func copyDir(t *testing.T, from, to string) {
	t.Helper()
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
}
