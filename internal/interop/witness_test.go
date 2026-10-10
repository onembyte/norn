// Package interop holds the tests that check Norn against implementations
// nobody here wrote.
//
// Everything else in this project can be green while being consistently wrong:
// a writer and a reader that disagree with the world in the same way agree
// with each other perfectly. 4.1a is the cautionary tale -- Norn encoded
// witness keys under the wrong algorithm byte in *both* implementations, and
// its own cross-check passed because it was handing sumdb the wrong key kind
// on both sides. Only bytes produced by somebody else settle those questions.
package interop

import (
	"crypto/ed25519"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/onembyte/norn/internal/cosign"
	"github.com/onembyte/norn/internal/note"
	"github.com/onembyte/norn/internal/trust"
)

// requireEnv turns "the witness is not built" from a skip into a failure, so
// this test cannot quietly stop running everywhere at once.
const requireEnv = "NORN_REQUIRE_WITNESS"

// witnessBin is where `make witness` puts the binaries; NORN_WITNESS_BIN and
// NORN_WITNESS_KEYGEN override.
func witnessBin(t *testing.T, name, envVar string) string {
	t.Helper()
	if path := os.Getenv(envVar); path != "" {
		return path
	}
	path := filepath.Join("..", "..", "build", name)
	if _, err := os.Stat(path); err != nil {
		if os.Getenv(requireEnv) != "" {
			t.Fatalf("%s is set but %s is not built: %v", requireEnv, name, err)
		}
		t.Skipf("%s is not built (run `make witness`); set %s to make this a failure",
			name, requireEnv)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		t.Fatal(err)
	}
	return abs
}

// TestAnUnmodifiedWitnessCosignsANornCheckpoint is the claim the whole design
// rests on, and the one nothing else in this repository can establish.
//
// A log can sign anything it likes, including two histories for two different
// nodes; what it cannot do is get independent witnesses to cosign both at the
// same size. That argument is worth nothing unless a witness somebody else
// wrote will actually cosign what Norn publishes -- so this drives the real
// `transparency-dev/witness`, unmodified, at a pinned commit, with no Norn
// code in it and none of its code in Norn's go.mod.
func TestAnUnmodifiedWitnessCosignsANornCheckpoint(t *testing.T) {
	omniwitness := witnessBin(t, "omniwitness", "NORN_WITNESS_BIN")
	generateKeys := witnessBin(t, "generate_keys", "NORN_WITNESS_KEYGEN")

	work := t.TempDir()
	keys := filepath.Join(work, "keys")
	logDir := filepath.Join(work, "log")
	for _, dir := range []string{keys, logDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}

	// 1. The witness makes its own identity, with its own tool. Norn never
	//    sees the private key, and the public one arrives in exactly the form
	//    a witness operator publishes.
	out, err := exec.Command(generateKeys, "-origin", "norn-witness/interop", "-print").Output()
	if err != nil {
		t.Fatalf("generate_keys: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) != 2 {
		t.Fatalf("generate_keys printed %d lines, want the private then the public key", len(lines))
	}
	witnessSec, witnessVkey := lines[0], lines[1]

	// The first assertion, before anything is even running: their rendering of
	// a witness key is the one Norn expects. 4.1a's defect lived here.
	verifier, err := note.ParseVerifierKey(witnessVkey)
	if err != nil {
		t.Fatalf("Norn cannot parse a key the witness ecosystem published: %v", err)
	}
	if !verifier.IsCosigner() {
		t.Fatalf("the witness published algorithm %#x, Norn expects a cosignature key",
			verifier.Alg)
	}
	if got := note.CosignerVerifierKey(verifier.Name, ed25519.PublicKey(verifier.Public)); got != witnessVkey {
		t.Fatalf("Norn re-renders their key differently:\n got %q\nwant %q", got, witnessVkey)
	}

	// 2. A Norn network that requires that witness, created by `norn init`
	//    from the published key -- no hand-editing, no hex conversion.
	nornBin := build(t, "norn")
	logURL := "http://" + freePort(t)
	witnessURL := "http://" + freePort(t)
	if out, err := exec.Command(nornBin, "init", "-name", "interop", "-out", work,
		"-root", filepath.Join(keys, "root1.key"), "-root-thr", "1",
		"-signer", filepath.Join(keys, "signer1.key"), "-signer-thr", "1",
		"-log-key", filepath.Join(keys, "log.key"), "-log-url", logURL,
		"-witness", "interop="+witnessVkey,
		"-witness-url", "interop="+witnessURL,
	).CombinedOutput(); err != nil {
		t.Fatalf("norn init: %v\n%s", err, out)
	}
	anchor := readTrust(t, filepath.Join(work, "norn.trust"))

	// 3. The witness, told about this log the way any witness operator would
	//    be told: origin, public key, address.
	secPath := filepath.Join(work, "witness.sec")
	if err := os.WriteFile(secPath, []byte(witnessSec+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	logsYAML := filepath.Join(work, "logs.yaml")
	if err := os.WriteFile(logsYAML, []byte(fmt.Sprintf(
		"Logs:\n  - Origin: %s\n    PublicKey: %s\n    URL: %s\n",
		anchor.Origin, anchor.LogKey, logURL)), 0o600); err != nil {
		t.Fatal(err)
	}
	start(t, omniwitness, "--listen", strings.TrimPrefix(witnessURL, "http://"),
		"--metrics_listen", "", "--private_key_path", secPath,
		"--additional_logs", logsYAML)
	waitFor(t, witnessURL+"/add-checkpoint")

	// 4. The log, which knows where its witness is because the trust file says
	//    so, and pushes to it over tlog-witness.
	logBin := build(t, "norn-log")
	start(t, logBin, "-dir", logDir, "-key", filepath.Join(keys, "log.key"),
		"-trust", filepath.Join(work, "norn.trust"),
		"-listen", strings.TrimPrefix(logURL, "http://"),
		"-checkpoint-interval", "500ms")
	waitFor(t, logURL+"/checkpoint")

	// The genesis is entry 0, submitted like any other. A log that has not
	// published it is no network's log yet, and §10.1 refuses it as `genesis`
	// (D-074 (g)); the log batches its checkpoints, so this also waits through
	// an empty head, which `submit -wait` must read as not included yet.
	if out, err := exec.Command(nornBin, "submit", "-trust", filepath.Join(work, "norn.trust"),
		"-log", logURL, "-wait", filepath.Join(work, "genesis.cbor")).CombinedOutput(); err != nil {
		t.Fatalf("submitting the genesis: %v\n%s", err, out)
	}

	// 5. Wait for a cosignature signed by a key this process never held.
	deadline := time.Now().Add(20 * time.Second)
	var served string
	for {
		served = fetch(t, logURL+"/checkpoint")
		if got, err := cosign.Verify(served, []string{witnessVkey}); err == nil && len(got) == 1 {
			if got[0].Time.IsZero() {
				t.Error("the cosignature carries no witness time")
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no witness cosignature appeared on the checkpoint:\n%s", served)
		}
		time.Sleep(100 * time.Millisecond)
	}

	// 6. And Norn's own verifier accepts it -- quorum and all. This is the
	//    line that makes the previous five worth anything.
	if out, err := exec.Command(nornBin, "verify",
		"-trust", filepath.Join(work, "norn.trust"), "-log", logURL).CombinedOutput(); err != nil {
		t.Fatalf("norn verify refused a checkpoint a real witness cosigned: %v\n%s", err, out)
	}

	// 7. The negative half: with the witness's line removed, the same
	//    checkpoint must be refused. Otherwise step 6 proved only that
	//    verification succeeds, not that the cosignature was why.
	stripped := filepath.Join(work, "stripped")
	copyTree(t, logDir, stripped)
	var kept []string
	for _, line := range strings.Split(strings.TrimRight(served, "\n"), "\n") {
		if !strings.Contains(line, verifier.Name) {
			kept = append(kept, line)
		}
	}
	if err := os.WriteFile(filepath.Join(stripped, "checkpoint"),
		[]byte(strings.Join(kept, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err = exec.Command(nornBin, "verify",
		"-trust", filepath.Join(work, "norn.trust"), "-log", stripped).CombinedOutput()
	if err == nil {
		t.Fatal("a checkpoint with the witness's cosignature removed was accepted")
	}
	if !strings.Contains(string(out), "witness policy") {
		t.Errorf("the refusal should name the quorum:\n%s", out)
	}
}

// --- helpers ---------------------------------------------------------------

func build(t *testing.T, cmd string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), cmd)
	if out, err := exec.Command("go", "build", "-o", path, "../../cmd/"+cmd).CombinedOutput(); err != nil {
		t.Fatalf("building %s: %v\n%s", cmd, err, out)
	}
	return path
}

func start(t *testing.T, bin string, args ...string) {
	t.Helper()
	proc := exec.Command(bin, args...)
	proc.Stderr = os.Stderr
	if err := proc.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = proc.Process.Kill()
		_, _ = proc.Process.Wait()
	})
}

func freePort(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	return listener.Addr().String()
}

// waitFor blocks until something answers at `url`, whatever it answers.
func waitFor(t *testing.T, url string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		resp, err := http.Get(url)
		if err == nil {
			resp.Body.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("nothing came up at %s", url)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func fetch(t *testing.T, url string) string {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	raw := make([]byte, 1<<16)
	n, _ := resp.Body.Read(raw)
	return string(raw[:n])
}

func readTrust(t *testing.T, path string) *trust.Trust {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := trust.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

func copyTree(t *testing.T, from, to string) {
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
