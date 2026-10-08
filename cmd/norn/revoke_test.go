package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/onembyte/norn/internal/entry"
	"github.com/onembyte/norn/internal/replay"
	"github.com/onembyte/norn/internal/state"
	"github.com/onembyte/norn/internal/wgkey"
)

func revokeArgs(key string) []string {
	return []string{"revoke", "-trust", filepath.Join(vectors(), "trust.cbor"),
		"-log", filepath.Join(vectors(), "served"), "-device", "nas", "-key", key}
}

func decodeRevocation(t *testing.T, raw []byte) *entry.Envelope {
	t.Helper()
	env, err := entry.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if env.T != "revoke" || env.Body["device_id"] != "nas" {
		t.Fatalf("not a revocation of nas: %+v", env)
	}
	return env
}

func requireRevoked(t *testing.T, raw []byte) {
	t.Helper()
	entries, anchor := fixtureLog(t)
	st := replay.Replay(anchor, append(entries, raw))
	d := st.Devices["nas"]
	if d.Status != state.StatusRevoked || d.SinceIndex != uint64(len(entries)) {
		t.Fatalf("revocation did not apply: %+v; last rejection %+v", d, st.Rejected[len(st.Rejected)-1])
	}
	if _, present := st.ActiveWg[d.WgPk]; present {
		t.Fatal("the revoked device remains in active_wg")
	}
}

// The fixture requires two signers. The command must produce a partial entry
// another operator can finish, and the result must actually change replay.
func TestRevokeIsAcceptedByReplay(t *testing.T) {
	bin, dir := nornBinary(t), t.TempDir()
	first := filepath.Join(dir, "first.cbor")
	args := append(revokeArgs(signerKeyFile(t, dir, "signer1")), "-reason", "stolen", "-yes", "-o", first)
	if _, stderr, err := run(t, bin, args...); err != nil {
		t.Fatalf("first revoke: %v\n%s", err, stderr)
	}
	once, err := os.ReadFile(first)
	if err != nil {
		t.Fatal(err)
	}
	env := decodeRevocation(t, once)
	entries, anchor := fixtureLog(t)
	if env.After == nil || *env.After != uint64(len(entries)) || env.Body["reason"] != "stolen" {
		t.Fatalf("wrong guard or reason: %+v", env)
	}
	st := replay.Replay(anchor, append(append([][]byte{}, entries...), once))
	if last := st.Rejected[len(st.Rejected)-1]; last.Index != uint64(len(entries)) || last.Reason != replay.ReasonThreshold {
		t.Fatalf("one signer should fail threshold: %+v", last)
	}
	args = append(revokeArgs(signerKeyFile(t, dir, "signer3")), "-yes", "-in", first)
	both, stderr, err := run(t, bin, args...)
	if err != nil {
		t.Fatalf("second revoke: %v\n%s", err, stderr)
	}
	final := decodeRevocation(t, []byte(both))
	before, _ := entry.Preimage(env)
	after, _ := entry.Preimage(final)
	if !bytes.Equal(before, after) || len(final.Sigs) != 2 {
		t.Fatal("extending changed the preimage or lost a signature")
	}
	for _, name := range []string{"signer1", "signer3"} {
		public := fixtureKey(t, name).Public().(ed25519.PublicKey)
		found := false
		for _, sig := range final.Sigs {
			if sig.Kid == entry.Kid(public) {
				valid, err := entry.Verify(final, sig, public)
				if err != nil || !valid || sig.Role != "signer" {
					t.Fatalf("signature by %s is unusable: %v", name, err)
				}
				found = true
			}
		}
		if !found {
			t.Fatalf("missing signature by %s", name)
		}
	}
	requireRevoked(t, []byte(both))
}

func TestRevokeByTheDeviceIsAcceptedByReplay(t *testing.T) {
	bin, dir := nornBinary(t), t.TempDir()
	// The fixture rotated nas's identity key; self-revocation needs that
	// current key, just as nornd's key file would after the rotation.
	args := append(revokeArgs(signerKeyFile(t, dir, "nas-id2")), "-role", "device", "-yes")
	raw, stderr, err := run(t, bin, args...)
	if err != nil {
		t.Fatalf("self-revoke: %v\n%s", err, stderr)
	}
	env := decodeRevocation(t, []byte(raw))
	if _, present := env.Body["reason"]; present {
		t.Fatal("an empty reason must be omitted")
	}
	if len(env.Sigs) != 1 || env.Sigs[0].Role != "device" {
		t.Fatalf("wrong self-revocation signature: %+v", env.Sigs)
	}
	requireRevoked(t, []byte(raw))
}

func TestRevokeRefusals(t *testing.T) {
	bin, dir := nornBinary(t), t.TempDir()
	key := signerKeyFile(t, dir, "signer1")
	cases := []struct {
		name  string
		flags []string
		says  string
	}{
		{"unknown device", []string{"-device", "missing"}, "unknown device"},
		{"already revoked", []string{"-device", "laptop"}, "revoked"},
		{"not a signer", []string{"-key", signerKeyFile(t, dir, "stranger")}, "not a signer"},
		{"not a root", []string{"-role", "root", "-yes=false"}, "not a root"},
		{"not this device", []string{"-role", "device"}, "does not match"},
		{"superseded device key", []string{"-role", "device", "-key", signerKeyFile(t, dir, "nas")}, "does not match"},
		{"scripted root", []string{"-role", "root", "-key", signerKeyFile(t, dir, "root1")}, "never exercised by a script"},
		{"long reason", []string{"-reason", strings.Repeat("x", 257)}, "256 bytes"},
		{"long UTF-8 reason", []string{"-reason", strings.Repeat("é", 129)}, "256 bytes"},
		{"unknown role", []string{"-role", "observer"}, "signer, root or device"},
		{"missing trust", []string{"-trust", ""}, "-trust is required"},
		{"missing device", []string{"-device", ""}, "-device is required"},
		{"unreachable log", []string{"-log", filepath.Join(dir, "absent")}, "-after N"},
		{"unreachable log with after", []string{"-log", filepath.Join(dir, "absent"), "-after", "90"}, "could not verify the device and signing role"},
		{"unreachable log without guard", []string{"-log", filepath.Join(dir, "absent"), "-no-after"}, "could not verify the device and signing role"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			args := append(revokeArgs(key), "-yes")
			stdout, stderr, err := run(t, bin, append(args, c.flags...)...)
			if err == nil {
				t.Fatalf("accepted: %s", c.name)
			}
			if !strings.Contains(stderr, c.says) || strings.Contains(stderr, "Sign this entry?") {
				t.Errorf("want refusal mentioning %q before confirmation:\n%s", c.says, stderr)
			}
			if stdout != "" {
				t.Error("a refused run emitted an entry")
			}
		})
	}
}

func TestRevokeByRootQuorumRequiresConfirmationAndReplays(t *testing.T) {
	bin, dir := nornBinary(t), t.TempDir()
	path := filepath.Join(dir, "roots.cbor")
	for i, name := range []string{"root1", "root2", "root3"} {
		args := append(revokeArgs(signerKeyFile(t, dir, name)), "-role", "root", "-o", path)
		if i != 0 {
			args = append(args, "-in", path)
		}
		cmd := exec.Command(bin, args...)
		cmd.Stdin = strings.NewReader("yes\n")
		output, err := cmd.CombinedOutput()
		if err != nil || !strings.Contains(string(output), "Sign this entry?") {
			t.Fatalf("root must confirm: %v\n%s", err, output)
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	env := decodeRevocation(t, raw)
	if len(env.Sigs) != 3 {
		t.Fatalf("want three root signatures, got %d", len(env.Sigs))
	}
	for _, sig := range env.Sigs {
		if sig.Role != "root" {
			t.Fatalf("root signature has role %q", sig.Role)
		}
	}
	requireRevoked(t, raw)
}

func TestRevokeRefusesToExtendAnEntryThatDoesNotMatch(t *testing.T) {
	bin, dir := nornBinary(t), t.TempDir()
	key := signerKeyFile(t, dir, "signer1")
	raw, stderr, err := run(t, bin, append(revokeArgs(key), "-yes", "-reason", "lost")...)
	if err != nil {
		t.Fatalf("%v\n%s", err, stderr)
	}
	cases := []struct {
		name   string
		change func(*entry.Envelope)
		flags  []string
		says   string
	}{
		{"different type", func(e *entry.Envelope) { e.T = "note" }, nil, "signs `revoke`"},
		{"different network", func(e *entry.Envelope) { e.Net[0] ^= 1 }, nil, "another network"},
		{"different device", func(e *entry.Envelope) { e.Body["device_id"] = "pi-cam" }, nil, "does not match -device"},
		{"unknown field", func(e *entry.Envelope) { e.Body["extra"] = "hidden" }, nil, "unknown field"},
		{"long embedded reason", func(e *entry.Envelope) { e.Body["reason"] = strings.Repeat("x", 257) }, nil, "256 bytes"},
		{"different reason flag", func(e *entry.Envelope) {}, []string{"-reason", "stolen"}, "does not match -reason"},
		{"explicit empty reason", func(e *entry.Envelope) {}, []string{"-reason", ""}, "does not match -reason"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			env := decodeRevocation(t, []byte(raw))
			c.change(env)
			changed, err := entry.Encode(env)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "entry.cbor")
			if err := os.WriteFile(path, changed, 0o600); err != nil {
				t.Fatal(err)
			}
			args := append(revokeArgs(key), c.flags...)
			stdout, stderr, err := run(t, bin, append(args, "-in", path)...)
			if err == nil || stdout != "" || !strings.Contains(stderr, c.says) || strings.Contains(stderr, "Sign this entry?") {
				t.Fatalf("want refusal %q before confirmation: %v\n%s", c.says, err, stderr)
			}
		})
	}
}

func TestRevokeSummaryPrecedesConfirmation(t *testing.T) {
	bin, dir := nornBinary(t), t.TempDir()
	args := append(revokeArgs(signerKeyFile(t, dir, "signer1")), "-reason", "device stolen")
	cmd := exec.Command(bin, args...)
	cmd.Stdin = strings.NewReader("no\n")
	var out, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &stderr
	if err := cmd.Run(); err == nil || out.Len() != 0 {
		t.Fatal("declining confirmation must not emit an entry")
	}
	text := stderr.String()
	prompt := strings.Index(text, "Sign this entry?")
	entries, anchor := fixtureLog(t)
	d := replay.Replay(anchor, entries).Devices["nas"]
	wg, _ := hex.DecodeString(d.WgPk)
	for _, want := range []string{"REVOKE", "nas", "device stolen", wgkey.Format(wg), "signer", kidOf(t, "signer1"), "after      " + strconv.Itoa(len(entries)), "entry hash"} {
		at := strings.Index(text, want)
		if at < 0 || prompt < 0 || at >= prompt {
			t.Errorf("summary must show %q before confirmation:\n%s", want, text)
		}
	}
}

func TestRevokeOrderingGuardChoicesArePreserved(t *testing.T) {
	bin, dir := nornBinary(t), t.TempDir()
	first, second := signerKeyFile(t, dir, "signer1"), signerKeyFile(t, dir, "signer3")
	for _, noAfter := range []bool{false, true} {
		args := append(revokeArgs(first), "-yes", "-reason", strings.Repeat("é", 128))
		if noAfter {
			args = append(args, "-no-after")
		} else {
			args = append(args, "-after", "90")
		}
		raw, stderr, err := run(t, bin, args...)
		if err != nil {
			t.Fatalf("%v\n%s", err, stderr)
		}
		env := decodeRevocation(t, []byte(raw))
		if noAfter && env.After != nil || !noAfter && (env.After == nil || *env.After != 90) {
			t.Fatalf("wrong after: %+v", env.After)
		}
		if noAfter && !strings.Contains(stderr, "no ordering guard") {
			t.Fatal("unguarded entry needs an explicit warning")
		}
		// Stdin follows sign's '-' convention. New guard flags cannot change
		// an entry another signer has already approved.
		cmd := exec.Command(bin, append(revokeArgs(second), "-yes", "-after", "123", "-in", "-")...)
		cmd.Stdin = strings.NewReader(raw)
		var out, errBuf bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &errBuf
		if err := cmd.Run(); err != nil {
			t.Fatalf("stdin extension: %v\n%s", err, errBuf.String())
		}
		final := decodeRevocation(t, out.Bytes())
		before, _ := entry.Preimage(env)
		after, _ := entry.Preimage(final)
		if !bytes.Equal(before, after) {
			t.Fatal("extension changed the signed guard")
		}
	}
}

func TestRevokeRefusesATamperedEntryBeforeConfirmation(t *testing.T) {
	bin, dir := nornBinary(t), t.TempDir()
	raw, stderr, err := run(t, bin, append(revokeArgs(signerKeyFile(t, dir, "signer1")), "-yes")...)
	if err != nil {
		t.Fatalf("%v\n%s", err, stderr)
	}
	env := decodeRevocation(t, []byte(raw))
	env.Body["reason"] = "changed after the first signer approved"
	changed, err := entry.Encode(env)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "tampered.cbor")
	if err := os.WriteFile(path, changed, 0o600); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, err := run(t, bin, append(revokeArgs(signerKeyFile(t, dir, "signer3")), "-in", path)...)
	if err == nil || stdout != "" || !strings.Contains(stderr, "does not verify") || strings.Contains(stderr, "Sign this entry?") {
		t.Fatalf("tampered preimage was not refused before confirmation: %v\n%s", err, stderr)
	}
}
