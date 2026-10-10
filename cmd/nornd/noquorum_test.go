package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/onembyte/norn/internal/peertable"
	"github.com/onembyte/norn/internal/trust"
)

// noQuorumTrust writes the shipped trust file with its quorum line set to
// `none`, and returns its path.
func noQuorumTrust(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(vectors(), "trust.cbor"))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := trust.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, line := range strings.Split(doc.Policy, "\n") {
		if strings.HasPrefix(line, "quorum ") {
			line = "quorum none"
		}
		lines = append(lines, line)
	}
	doc.Policy = strings.Join(lines, "\n")
	encoded, err := doc.Encode()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "norn.trust")
	if err := os.WriteFile(path, encoded, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// §13.2 (D-072 (e)), through the daemon: the flag and the setting both reach
// the agent. An owner node on a `quorum none` trust file is refused and told
// what to set; with `-allow-no-quorum`, or `allow_no_quorum = true` in
// nornd.toml, it runs a cycle. A setting that parsed and never reached the
// agent would say one thing and do another.
func TestAllowNoQuorumReachesTheAgent(t *testing.T) {
	previous := openDevice
	openDevice = func(string) (peertable.Device, error) { return peertable.NewFake(), nil }
	t.Cleanup(func() { openDevice = previous })

	trustPath := noQuorumTrust(t)
	args := func(extra ...string) []string {
		return append([]string{"-iface", "norn-test0", "-trust", trustPath, "-mode", "owner",
			"-log", filepath.Join(vectors(), "served"), "-run-dir", t.TempDir(),
			"-state-dir", t.TempDir(), "-gossip-port", "0", "-once"}, extra...)
	}
	err := run(args())
	if err == nil || !strings.Contains(err.Error(), "allow_no_quorum") {
		t.Fatalf("an owner node started on quorum none, or did not say what to set: %v", err)
	}
	if err := run(args("-allow-no-quorum")); err != nil {
		t.Errorf("with -allow-no-quorum: %v", err)
	}
	config := write(t, "allow_no_quorum = true\n")
	if err := run(args("-config", config)); err != nil {
		t.Errorf("with allow_no_quorum = true in nornd.toml: %v", err)
	}
}
