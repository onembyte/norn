package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/onembyte/norn/internal/cosign"
	"github.com/onembyte/norn/internal/enrollreq"
	"github.com/onembyte/norn/internal/entry"
	"github.com/onembyte/norn/internal/keyfile"
	"github.com/onembyte/norn/internal/logserver"
	"github.com/onembyte/norn/internal/note"
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

	// The fixture's policy needs two of three witnesses (§10 step 3), so the
	// log has to be able to obtain cosignatures or nothing will accept its
	// head. Here it holds two witness keys itself -- GOSSIP part 3's "same
	// host as the log" row, independent from nothing, which is why a real
	// deployment pushes to witnesses elsewhere instead (4.3).
	server := exec.Command(logBin, "-dir", dir, "-key", keyPath,
		"-trust", filepath.Join(vectors(), "trust.cbor"), "-listen", addr,
		"-self-witness", "pi="+witnessKeyFile(t, "pi"),
		"-self-witness", "vps="+witnessKeyFile(t, "vps"))
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

// witnessKeyFile writes one of the fixture's witness keys where norn-log can
// read it, and returns the path.
func witnessKeyFile(t *testing.T, name string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name+".key")
	if err := keyfile.Write(path, seed(t, "witness-"+name), "norn witness key"); err != nil {
		t.Fatal(err)
	}
	return path
}

// A self-witness key that is not the one the trust file names would produce
// cosignatures no node on this network counts -- a log that looks healthy to
// its operator and is refused by every verifier. Catch it at startup.
func TestASelfWitnessKeyMustMatchTheTrustFile(t *testing.T) {
	logBin := build(t, ".", "norn-log")
	dir, _, _ := seededLog(t)
	keyPath := filepath.Join(t.TempDir(), "log.key")
	if err := keyfile.Write(keyPath, seed(t, "logkey"), "norn log key"); err != nil {
		t.Fatal(err)
	}

	// The right witness name, the wrong key.
	wrong := filepath.Join(t.TempDir(), "wrong.key")
	if err := keyfile.Write(wrong, seed(t, "witness-friend"), "norn witness key"); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(logBin, "-dir", dir, "-key", keyPath,
		"-trust", filepath.Join(vectors(), "trust.cbor"), "-listen", freePort(t),
		"-self-witness", "pi="+wrong).CombinedOutput()
	if err == nil {
		t.Fatal("norn-log started with a witness key the trust file does not name")
	}
	if !strings.Contains(string(out), "witness pi") {
		t.Errorf("the error should name the witness: %s", out)
	}
}

// A witness name the policy never mentions is the same mistake wearing a
// different hat: the cosignatures would be ignored by everyone.
func TestASelfWitnessMustBeNamedByThePolicy(t *testing.T) {
	logBin := build(t, ".", "norn-log")
	dir, _, _ := seededLog(t)
	keyPath := filepath.Join(t.TempDir(), "log.key")
	if err := keyfile.Write(keyPath, seed(t, "logkey"), "norn log key"); err != nil {
		t.Fatal(err)
	}

	out, err := exec.Command(logBin, "-dir", dir, "-key", keyPath,
		"-trust", filepath.Join(vectors(), "trust.cbor"), "-listen", freePort(t),
		"-self-witness", "nobody="+witnessKeyFile(t, "pi")).CombinedOutput()
	if err == nil {
		t.Fatal("norn-log started as a witness this network has never heard of")
	}
	if !strings.Contains(string(out), "nobody") {
		t.Errorf("the error should name the witness: %s", out)
	}
}

// The end of the self-witness crutch: a real `norn-log`, a real HTTP witness,
// and a checkpoint that carries a cosignature the log did not make itself.
//
// The witness here is a stub rather than `transparency-dev/witness` -- that is
// 4.4, and the point of keeping them separate is that this test proves the
// *log* asks correctly, while that one proves an implementation nobody here
// wrote is happy with what it asked.
func TestTheLogCollectsACosignatureOverHTTP(t *testing.T) {
	logBin := build(t, ".", "norn-log")
	dir, _, anchor := seededLog(t)

	// A witness at a real address, holding the fixture's `pi` key.
	witnessKey := seed(t, "witness-pi")
	var asked int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/add-checkpoint") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		asked++
		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_, checkpoint, ok := strings.Cut(string(body), "\n\n")
		if !ok {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		text, _, err := note.Split(checkpoint)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		line, err := cosign.Sign(text, "norn-witness/pi", witnessKey, time.Unix(1_760_003_600, 0))
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte(line + "\n"))
	}))
	defer server.Close()

	// A trust file whose `pi` witness points at that address.
	trustFile := witnessedTrust(t, anchor, server.URL)

	keyPath := filepath.Join(t.TempDir(), "log.key")
	if err := keyfile.Write(keyPath, seed(t, "logkey"), "norn log key"); err != nil {
		t.Fatal(err)
	}
	addr := freePort(t)
	proc := exec.Command(logBin, "-dir", dir, "-key", keyPath,
		"-trust", trustFile, "-listen", addr)
	proc.Stderr = os.Stderr
	if err := proc.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = proc.Process.Kill()
		_, _ = proc.Process.Wait()
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

	// The log asks its witnesses in the background -- 2.9 made the first
	// refresh asynchronous precisely so that a witness which is slow or down
	// cannot stop the log from starting. So the port opening does not mean the
	// first round has finished, and asserting on the first fetch made this
	// test fail under parallel load and pass on its own, four times.
	//
	// Poll for the cosignature rather than assuming it has arrived. The
	// assertion is unchanged; only the moment it is made is.
	public := witnessKey.Public().(ed25519.PublicKey)
	witnessVKey := note.CosignerVerifierKey("norn-witness/pi", public)
	var served []byte
	deadline = time.Now().Add(10 * time.Second)
	for {
		resp, err := http.Get(base + "/checkpoint")
		if err == nil {
			served, _ = io.ReadAll(resp.Body)
			resp.Body.Close()
			if got, err := cosign.Verify(string(served), []string{witnessVKey}); err == nil &&
				len(got) == 1 {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("the served checkpoint never carried a cosignature from the "+
				"witness; the log asked it %d time(s). Last head:\n%s", asked, served)
		}
		time.Sleep(20 * time.Millisecond)
	}

	if asked == 0 {
		t.Fatal("the log never asked its witness")
	}
}

// witnessedTrust rewrites the fixture's anchor so its `pi` witness lives at
// `url`, and writes it where norn-log can read it.
func witnessedTrust(t *testing.T, anchor *trust.Trust, url string) string {
	t.Helper()
	doc := *anchor
	doc.Witnesses = append([]trust.Witness(nil), anchor.Witnesses...)
	for i := range doc.Witnesses {
		if doc.Witnesses[i].Name == "pi" {
			doc.Witnesses[i].URL = url
			doc.Witnesses[i].HasURL = true
		} else {
			doc.Witnesses[i].URL = ""
			doc.Witnesses[i].HasURL = false
		}
	}
	raw, err := doc.Encode()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "norn.trust")
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// A log with nothing to add still has to keep asking. Witness time is what
// every node measures freshness against (GOSSIP part 5), so cosignatures from
// an hour ago make the whole network `degraded` with nothing actually wrong.
// SPEC §4.5's `checkpoint_interval` is the promise: at most T_c between
// checkpoints.
func TestAQuietLogKeepsRefreshingItsCosignatures(t *testing.T) {
	logBin := build(t, ".", "norn-log")
	dir, _, anchor := seededLog(t)

	witnessKey := seed(t, "witness-pi")
	var mu sync.Mutex
	var asked int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_, checkpoint, ok := strings.Cut(string(body), "\n\n")
		if !ok {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		text, _, err := note.Split(checkpoint)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		mu.Lock()
		asked++
		at := time.Unix(1_760_003_600+int64(asked), 0)
		mu.Unlock()
		line, err := cosign.Sign(text, "norn-witness/pi", witnessKey, at)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte(line + "\n"))
	}))
	defer server.Close()

	keyPath := filepath.Join(t.TempDir(), "log.key")
	if err := keyfile.Write(keyPath, seed(t, "logkey"), "norn log key"); err != nil {
		t.Fatal(err)
	}
	addr := freePort(t)
	proc := exec.Command(logBin, "-dir", dir, "-key", keyPath,
		"-trust", witnessedTrust(t, anchor, server.URL), "-listen", addr,
		"-checkpoint-interval", "300ms")
	proc.Stderr = os.Stderr
	if err := proc.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = proc.Process.Kill()
		_, _ = proc.Process.Wait()
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

	// Nothing is submitted; the log is idle.
	first := cosignedAtOf(t, base)
	deadline = time.Now().Add(5 * time.Second)
	for {
		if later := cosignedAtOf(t, base); later > first {
			return // the witness time on the served head moved forward
		}
		if time.Now().After(deadline) {
			mu.Lock()
			count := asked
			mu.Unlock()
			t.Fatalf("an idle log never refreshed its cosignatures (%d asks); every "+
				"node on this network would degrade for no reason", count)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// cosignedAtOf reads the witness time off the currently served checkpoint.
func cosignedAtOf(t *testing.T, base string) int64 {
	t.Helper()
	resp, err := http.Get(base + "/checkpoint")
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0
	}
	public := seed(t, "witness-pi").Public().(ed25519.PublicKey)
	got, err := cosign.Verify(string(raw),
		[]string{note.CosignerVerifierKey("norn-witness/pi", public)})
	if err != nil || len(got) == 0 {
		return 0
	}
	return got[0].Time.Unix()
}
