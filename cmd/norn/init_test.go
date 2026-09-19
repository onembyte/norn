package main

import (
	"encoding/hex"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/onembyte/norn/internal/entry"
	"github.com/onembyte/norn/internal/keyfile"
	"github.com/onembyte/norn/internal/replay"
	"github.com/onembyte/norn/internal/trust"
)

// A whole network, from nothing: no fixture, no vectors, no keys that existed
// before the test started. If this passes, Norn can be adopted rather than
// merely inspected.
func TestBootstrapANetworkAndEnrolADevice(t *testing.T) {
	bin := nornBinary(t)
	logBin := filepath.Join(t.TempDir(), "norn-log")
	if out, err := exec.Command("go", "build", "-o", logBin, "../norn-log").CombinedOutput(); err != nil {
		t.Fatalf("building norn-log: %v\n%s", err, out)
	}

	work := t.TempDir()
	keys := filepath.Join(work, "keys")
	logDir := filepath.Join(work, "log")
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		t.Fatal(err)
	}
	addr := freeAddr(t)
	logURL := "http://" + addr

	// 1. The ceremony. Two roots of three sign; the third exists only as a
	//    public key, the way a paper root would.
	if err := os.MkdirAll(keys, 0o700); err != nil {
		t.Fatal(err)
	}
	paperRoot, _, err := keyfile.Generate()
	if err != nil {
		t.Fatal(err)
	}
	thirdRoot := hex.EncodeToString(paperRoot)

	_, stderr, err := run(t, bin, "init",
		"-name", "bootstrap-lab", "-out", work,
		"-root", filepath.Join(keys, "root1.key"),
		"-root", filepath.Join(keys, "root2.key"),
		"-root-pub", thirdRoot,
		"-root-thr", "2",
		"-signer", filepath.Join(keys, "signer1.key"), "-signer-thr", "1",
		"-log-key", filepath.Join(keys, "log.key"), "-log-url", logURL,
		"-witness", "pi="+filepath.Join(keys, "witness-pi.key"))
	if err != nil {
		t.Fatalf("init: %v\n%s", err, stderr)
	}
	if !strings.Contains(stderr, "FINGERPRINT") {
		t.Errorf("the ceremony must show the fingerprint to compare:\n%s", stderr)
	}

	trustFile := filepath.Join(work, "norn.trust")
	anchor := readAnchor(t, trustFile)
	if anchor.Name != "bootstrap-lab" {
		t.Fatalf("name = %q", anchor.Name)
	}

	// 2. The log, started on an empty directory with that trust file.
	server := exec.Command(logBin, "-dir", logDir, "-key", filepath.Join(keys, "log.key"),
		"-trust", trustFile, "-listen", addr)
	server.Stderr = os.Stderr
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = server.Process.Kill()
		_, _ = server.Process.Wait()
	})
	waitForLog(t, logURL)

	// 3. The genesis entry is entry 0, submitted like any other.
	if _, stderr, err := run(t, bin, "submit", "-trust", trustFile, "-log", logURL,
		"-wait", filepath.Join(work, "genesis.cbor")); err != nil {
		t.Fatalf("submitting genesis: %v\n%s", err, stderr)
	}

	// 4. A device asks to join a network that did not exist five seconds ago.
	device := filepath.Join(work, "device")
	if err := os.MkdirAll(device, 0o700); err != nil {
		t.Fatal(err)
	}
	requestText, stderr, err := enrollRun(t, bin, "-name", "first-device",
		"-trust", trustFile, "-key", filepath.Join(device, "device.key"), "-gen")
	if err != nil {
		t.Fatalf("enroll: %v\n%s", err, stderr)
	}
	requestPath := filepath.Join(work, "request.txt")
	if err := os.WriteFile(requestPath, []byte(requestText), 0o600); err != nil {
		t.Fatal(err)
	}

	// 5. The network's only signer signs it -- signer_thr is 1 here.
	entryPath := filepath.Join(work, "enroll.cbor")
	if _, stderr, err := run(t, bin, "sign", "-trust", trustFile, "-log", logURL,
		"-key", filepath.Join(keys, "signer1.key"), "-yes", "-o", entryPath,
		requestPath); err != nil {
		t.Fatalf("sign: %v\n%s", err, stderr)
	}
	if _, stderr, err := run(t, bin, "submit", "-trust", trustFile, "-log", logURL,
		"-wait", entryPath); err != nil {
		t.Fatalf("submit: %v\n%s", err, stderr)
	}

	// 6. And a verifier, holding only the trust file, sees the device.
	out, err := exec.Command(bin, "verify", "-trust", trustFile, "-log", logURL).CombinedOutput()
	if err != nil {
		t.Fatalf("verify: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "first-device") {
		t.Errorf("the device is not in the verifier's view:\n%s", out)
	}
	if !strings.Contains(string(out), "2 entries") {
		t.Errorf("the log should hold genesis and the enrolment:\n%s", out)
	}
	if !strings.Contains(string(out), anchor.Name) {
		t.Errorf("the summary should name the network:\n%s", out)
	}
}

// The ceremony must refuse to build a network that cannot work, and say so
// before writing anything.
func TestInitRefusals(t *testing.T) {
	bin := nornBinary(t)

	cases := []struct {
		why  string
		args func(dir string) []string
		says string
	}{
		{"no name", func(d string) []string {
			return []string{"init", "-out", d, "-log-key", filepath.Join(d, "l.key"),
				"-log-url", "http://x", "-root", filepath.Join(d, "r.key")}
		}, "-name"},
		{"no log url", func(d string) []string {
			return []string{"init", "-name", "n", "-out", d, "-log-key", filepath.Join(d, "l.key")}
		}, "-log-url"},
		{"no roots", func(d string) []string {
			return []string{"init", "-name", "n", "-out", d, "-log-key", filepath.Join(d, "l.key"),
				"-log-url", "http://x", "-signer", filepath.Join(d, "s.key"),
				"-witness", "pi=" + filepath.Join(d, "w.key")}
		}, "root"},
		{"no signers", func(d string) []string {
			return []string{"init", "-name", "n", "-out", d, "-log-key", filepath.Join(d, "l.key"),
				"-log-url", "http://x", "-root", filepath.Join(d, "r.key"),
				"-witness", "pi=" + filepath.Join(d, "w.key")}
		}, "signer"},
		{"no witnesses", func(d string) []string {
			return []string{"init", "-name", "n", "-out", d, "-log-key", filepath.Join(d, "l.key"),
				"-log-url", "http://x", "-root", filepath.Join(d, "r.key"),
				"-signer", filepath.Join(d, "s.key")}
		}, "witness"},
		{"a root threshold nobody can meet", func(d string) []string {
			return []string{"init", "-name", "n", "-out", d, "-log-key", filepath.Join(d, "l.key"),
				"-log-url", "http://x", "-root", filepath.Join(d, "r.key"), "-root-thr", "3",
				"-signer", filepath.Join(d, "s.key"), "-witness", "pi=" + filepath.Join(d, "w.key")}
		}, "root_thr"},
		{"a malformed witness", func(d string) []string {
			return []string{"init", "-name", "n", "-out", d, "-log-key", filepath.Join(d, "l.key"),
				"-log-url", "http://x", "-root", filepath.Join(d, "r.key"),
				"-signer", filepath.Join(d, "s.key"), "-witness", "nokey"}
		}, "name=hex"},
	}
	for _, c := range cases {
		t.Run(c.why, func(t *testing.T) {
			dir := t.TempDir()
			_, stderr, err := run(t, bin, c.args(dir)...)
			if err == nil {
				t.Fatalf("built a network with %s", c.why)
			}
			if !strings.Contains(stderr, c.says) {
				t.Errorf("the error should mention %q:\n%s", c.says, stderr)
			}
			if _, err := os.Stat(filepath.Join(dir, "norn.trust")); err == nil {
				t.Error("a refused ceremony still wrote a trust file")
			}
		})
	}
}

// Running init twice in one directory would strand every node holding the
// first trust file.
func TestInitRefusesToOverwriteANetwork(t *testing.T) {
	bin := nornBinary(t)
	dir := t.TempDir()
	args := []string{"init", "-name", "once", "-out", dir,
		"-root", filepath.Join(dir, "r.key"), "-signer", filepath.Join(dir, "s.key"),
		"-log-key", filepath.Join(dir, "l.key"), "-log-url", "http://x",
		"-witness", "pi=" + filepath.Join(dir, "w.key")}

	if _, stderr, err := run(t, bin, args...); err != nil {
		t.Fatalf("first init: %v\n%s", err, stderr)
	}
	first, err := os.ReadFile(filepath.Join(dir, "norn.trust"))
	if err != nil {
		t.Fatal(err)
	}

	_, stderr, err := run(t, bin, args...)
	if err == nil {
		t.Fatal("initialised a second network over the first")
	}
	if !strings.Contains(stderr, "already exists") {
		t.Errorf("the error should say why:\n%s", stderr)
	}
	second, err := os.ReadFile(filepath.Join(dir, "norn.trust"))
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatal("the original trust file was changed anyway")
	}
}

// The genesis entry init writes must replay under the trust file it writes.
// They are two files that have to agree, and nothing else checks it for them.
func TestGenesisAndTrustFileAgree(t *testing.T) {
	bin := nornBinary(t)
	dir := t.TempDir()
	if _, stderr, err := run(t, bin, "init", "-name", "agreement", "-out", dir,
		"-root", filepath.Join(dir, "r.key"), "-signer", filepath.Join(dir, "s.key"),
		"-log-key", filepath.Join(dir, "l.key"), "-log-url", "http://x",
		"-witness", "pi="+filepath.Join(dir, "w.key")); err != nil {
		t.Fatalf("init: %v\n%s", err, stderr)
	}

	anchor := readAnchor(t, filepath.Join(dir, "norn.trust"))
	raw, err := os.ReadFile(filepath.Join(dir, "genesis.cbor"))
	if err != nil {
		t.Fatal(err)
	}
	if string(anchor.GenesisHash) != string(entry.LeafHash(raw)) {
		t.Fatal("genesis_hash is not the leaf hash of genesis.cbor")
	}
	st := replay.Replay(replay.Anchor{Net: anchor.Net, GenesisHash: anchor.GenesisHash},
		[][]byte{raw})
	if len(st.Rejected) != 0 {
		t.Fatalf("the genesis does not replay under its own trust file: %+v", st.Rejected)
	}
	if _, err := os.Stat(filepath.Join(dir, "norn.trust.toml")); err != nil {
		t.Errorf("the human rendering (§9.2) was not written: %v", err)
	}
}

func readAnchor(t *testing.T, path string) *trust.Trust {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	anchor, err := trust.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := anchor.Validate(); err != nil {
		t.Fatalf("init wrote a trust file that is not a usable anchor: %v", err)
	}
	return anchor
}

func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

func waitForLog(t *testing.T, base string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if resp, err := http.Get(base + "/checkpoint"); err == nil {
			resp.Body.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("norn-log never came up")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
