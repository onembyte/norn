package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
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

func rotateArgs(key string) []string {
	return []string{"rotate", "-trust", filepath.Join(vectors(), "trust.cbor"),
		"-log", filepath.Join(vectors(), "served"), "-device", "nas", "-key", key}
}

func rotationState(t *testing.T) *state.State {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(vectors(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	st, err := state.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func rotationWG(t *testing.T) []byte {
	t.Helper()
	_, public, err := wgkey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return public
}

func decodeRotation(t *testing.T, raw []byte) *entry.Envelope {
	t.Helper()
	env, err := entry.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if env.T != "rotate" || env.Body["device_id"] != "nas" {
		t.Fatalf("not a rotation of nas: %+v", env)
	}
	return env
}

// Read the quorum from the fixture so a partial is completed with exactly the
// signers the observed state requires, preserving everything the device signed.
func extendRotation(t *testing.T, bin, dir string, raw []byte) []byte {
	t.Helper()
	st := rotationState(t)
	original, err := entry.Preimage(decodeRotation(t, raw))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "rotation.cbor")
	var count uint64
	for _, name := range []string{"signer1", "signer3"} {
		if count >= st.SignerThr {
			break
		}
		if _, ok := st.Signers[kidOf(t, name)]; !ok {
			continue
		}
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		args := append(rotateArgs(signerKeyFile(t, dir, name)), "-role", "signer", "-yes", path)
		stdout, stderr, err := run(t, bin, args...)
		if err != nil {
			t.Fatalf("extend rotation: %v\n%s", err, stderr)
		}
		raw = []byte(stdout)
		env := decodeRotation(t, raw)
		preimage, err := entry.Preimage(env)
		if err != nil || !bytes.Equal(original, preimage) {
			t.Fatal("extension changed the preimage")
		}
		count++
	}
	if count != st.SignerThr {
		t.Fatal("fixture has insufficient known signer keys")
	}
	return raw
}

func requireRotated(t *testing.T, raw, wg []byte, devicePK string) {
	t.Helper()
	entries, anchor := fixtureLog(t)
	st := replay.Replay(anchor, append(entries, raw))
	d := st.Devices["nas"]
	if d.WgPk != hex.EncodeToString(wg) || d.DevicePk != devicePK || d.Status != state.StatusActive {
		t.Fatalf("rotation did not apply: %+v; last rejection %+v", d, st.Rejected[len(st.Rejected)-1])
	}
	if st.ActiveWg[d.WgPk] != "nas" {
		t.Fatal("new key missing from active_wg")
	}
	old := rotationState(t).Devices["nas"].WgPk
	if old != d.WgPk {
		if _, present := st.ActiveWg[old]; present {
			t.Fatal("old key remains in active_wg")
		}
	}
}

func TestRotateIsAcceptedByReplayAfterSignerExtension(t *testing.T) {
	bin, dir := nornBinary(t), t.TempDir()
	st, wg := rotationState(t), rotationWG(t)
	if st.Params["rotate_needs_signer"] != true {
		t.Fatal("fixture must require signers")
	}
	first := filepath.Join(dir, "first.cbor")
	args := append(rotateArgs(signerKeyFile(t, dir, "nas-id2")), "-wg-pub", wgkey.Format(wg), "-yes", "-o", first)
	stdout, stderr, err := run(t, bin, args...)
	if err != nil {
		t.Fatalf("first rotate: %v\n%s", err, stderr)
	}
	if stdout != "" {
		t.Fatal("-o also wrote to stdout")
	}
	raw, err := os.ReadFile(first)
	if err != nil {
		t.Fatal(err)
	}
	env := decodeRotation(t, raw)
	entries, anchor := fixtureLog(t)
	if env.After == nil || *env.After != uint64(len(entries)) {
		t.Fatal("missing observed ordering guard")
	}
	if len(env.Sigs) != 1 || env.Sigs[0].Role != "device" {
		t.Fatal("missing device signature")
	}
	if _, present := env.Body["device_pk"]; present {
		t.Fatal("WG-only rotation includes device_pk")
	}
	partial := replay.Replay(anchor, append(entries, raw))
	if last := partial.Rejected[len(partial.Rejected)-1]; last.Index != uint64(len(entries)) || last.Reason != replay.ReasonThreshold {
		t.Fatalf("device alone must fail threshold: %+v", last)
	}
	final := extendRotation(t, bin, dir, raw)
	requireRotated(t, final, wg, st.Devices["nas"].DevicePk)
	if len(decodeRotation(t, final).Sigs) != int(st.SignerThr)+1 {
		t.Fatal("extension lost a signature")
	}
}

func TestRotateProvesPossessionOfTheIncomingIdentityKey(t *testing.T) {
	bin := nornBinary(t)
	for _, identityOnly := range []bool{false, true} {
		t.Run(fmt.Sprintf("identity only %t", identityOnly), func(t *testing.T) {
			dir := t.TempDir()
			wg := rotationWG(t)
			if identityOnly {
				wg, _ = hex.DecodeString(rotationState(t).Devices["nas"].WgPk)
			}
			incoming := fixtureKey(t, "stranger").Public().(ed25519.PublicKey)
			args := append(rotateArgs(signerKeyFile(t, dir, "nas-id2")), "-wg-pub", wgkey.Format(wg), "-new-key", signerKeyFile(t, dir, "stranger"), "-yes")
			raw, stderr, err := run(t, bin, args...)
			if err != nil {
				t.Fatalf("identity rotation: %v\n%s", err, stderr)
			}
			final := extendRotation(t, bin, dir, []byte(raw))
			// Replay must install the incoming key; a current-key-only signature
			// would pass the threshold but fail no-device-sig at this point.
			requireRotated(t, final, wg, hex.EncodeToString(incoming))
			env := decodeRotation(t, []byte(raw))
			if len(env.Sigs) != 2 {
				t.Fatalf("want two device signatures, got %d", len(env.Sigs))
			}
			for _, name := range []string{"nas-id2", "stranger"} {
				public := fixtureKey(t, name).Public().(ed25519.PublicKey)
				found := false
				for _, sig := range env.Sigs {
					if sig.Kid != entry.Kid(public) {
						continue
					}
					valid, err := entry.Verify(env, sig, public)
					if err != nil || !valid || sig.Role != "device" {
						t.Fatalf("unusable device signature: %s", name)
					}
					found = true
				}
				if !found {
					t.Fatalf("missing signature by %s", name)
				}
			}
		})
	}
}

func TestRotateRefusalsPrecedeConfirmation(t *testing.T) {
	bin, dir := nornBinary(t), t.TempDir()
	key := signerKeyFile(t, dir, "nas-id2")
	old, _ := hex.DecodeString(rotationState(t).Devices["nas"].WgPk)
	other, _ := hex.DecodeString(rotationState(t).Devices["pi-cam"].WgPk)
	stranger := signerKeyFile(t, dir, "stranger")
	cases := []struct {
		name  string
		flags []string
		says  string
	}{
		{"unknown device", []string{"-device", "missing"}, "unknown device"},
		{"revoked device", []string{"-device", "laptop"}, "revoked"},
		{"superseded device key", []string{"-key", signerKeyFile(t, dir, "nas")}, "does not match"},
		{"stranger key", []string{"-key", stranger}, "does not match"},
		{"not a signer", []string{"-role", "signer"}, "not a signer"},
		{"duplicate WG key", []string{"-wg-pub", wgkey.Format(other)}, "dup-wg"},
		{"no change", []string{"-wg-pub", wgkey.Format(old)}, "changes nothing"},
		{"malformed WG key", []string{"-wg-pub", "bad-key"}, "wgkey"},
		{"new identity as signer", []string{"-new-key", stranger, "-role", "signer"}, "-new-key"},
		{"root role", []string{"-role", "root"}, "device or signer"},
		{"missing WG key", []string{"-wg-pub", ""}, "exactly one"},
		{"both WG flags", []string{"-wg-key", "unused"}, "exactly one"},
		{"missing trust", []string{"-trust", ""}, "-trust is required"},
		{"missing device", []string{"-device", ""}, "-device is required"},
		{"unreadable log", []string{"-log", filepath.Join(dir, "absent")}, "-after N"},
		{"unreadable log with after", []string{"-log", filepath.Join(dir, "absent"), "-after", "90"}, "could not verify the device and signing role"},
		{"unreadable log without guard", []string{"-log", filepath.Join(dir, "absent"), "-no-after"}, "could not verify the device and signing role"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			args := append(rotateArgs(key), "-wg-pub", wgkey.Format(rotationWG(t)))
			stdout, stderr, err := run(t, bin, append(args, c.flags...)...)
			if err == nil || stdout != "" || !strings.Contains(stderr, c.says) || strings.Contains(stderr, "Sign this entry?") {
				t.Fatalf("want refusal %q before confirmation: %v\n%s", c.says, err, stderr)
			}
		})
	}
}

func TestRotateRefusesToExtendAnEntryThatDoesNotMatch(t *testing.T) {
	bin, dir := nornBinary(t), t.TempDir()
	device := signerKeyFile(t, dir, "nas-id2")
	signer := signerKeyFile(t, dir, "signer1")
	raw, stderr, err := run(t, bin, append(rotateArgs(device), "-wg-pub", wgkey.Format(rotationWG(t)), "-yes")...)
	if err != nil {
		t.Fatalf("%v\n%s", err, stderr)
	}
	cases := []struct {
		name   string
		change func(*entry.Envelope)
		flags  []string
		says   string
	}{
		{"different type", func(e *entry.Envelope) { e.T = "note" }, nil, "signs `rotate`"},
		{"different network", func(e *entry.Envelope) { e.Net[0] ^= 1 }, nil, "another network"},
		{"different device", func(e *entry.Envelope) { e.Body["device_id"] = "pi-cam" }, nil, "does not match -device"},
		{"unknown field", func(e *entry.Envelope) { e.Body["extra"] = "hidden" }, nil, "unknown field"},
		{"missing WG key", func(e *entry.Envelope) { delete(e.Body, "wg_pk") }, nil, "wg_pk"},
		{"bad identity key", func(e *entry.Envelope) { e.Body["device_pk"] = []byte{1} }, nil, "device_pk"},
		{"disagreeing WG flag", func(e *entry.Envelope) {}, []string{"-wg-pub", wgkey.Format(rotationWG(t))}, "does not match"},
		{"empty WG flag", func(e *entry.Envelope) {}, []string{"-wg-pub", ""}, "exactly one"},
		{"new key while extending", func(e *entry.Envelope) {}, []string{"-role", "device", "-key", device, "-new-key", signer}, "-new-key"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			env := decodeRotation(t, []byte(raw))
			c.change(env)
			changed, err := entry.Encode(env)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "entry.cbor")
			if err := os.WriteFile(path, changed, 0o600); err != nil {
				t.Fatal(err)
			}
			args := append(rotateArgs(signer), "-role", "signer", "-in", path)
			stdout, stderr, err := run(t, bin, append(args, c.flags...)...)
			if err == nil || stdout != "" || !strings.Contains(stderr, c.says) || strings.Contains(stderr, "Sign this entry?") {
				t.Fatalf("want refusal %q before confirmation: %v\n%s", c.says, err, stderr)
			}
		})
	}
}

func TestRotateRefusesATamperedEntryBeforeConfirmation(t *testing.T) {
	bin, dir := nornBinary(t), t.TempDir()
	raw, stderr, err := run(t, bin, append(rotateArgs(signerKeyFile(t, dir, "nas-id2")), "-wg-pub", wgkey.Format(rotationWG(t)), "-new-key", signerKeyFile(t, dir, "stranger"), "-yes")...)
	if err != nil {
		t.Fatalf("%v\n%s", err, stderr)
	}
	signer := signerKeyFile(t, dir, "signer3")
	for _, damaged := range []string{"body", "nas-id2", "stranger", "signer1", "root role", "unrelated device", "unrelated signer"} {
		t.Run(damaged, func(t *testing.T) {
			env := decodeRotation(t, []byte(raw))
			if err := entry.Sign(env, fixtureKey(t, "signer1"), "signer"); err != nil {
				t.Fatal(err)
			}
			says := "does not verify"
			switch damaged {
			case "body":
				env.Body["wg_pk"] = rotationWG(t)
			case "root role", "unrelated device", "unrelated signer":
				role := "device"
				says = "does not match"
				if damaged == "root role" {
					role, says = "root", "device or signer"
				} else if damaged == "unrelated signer" {
					role, says = "signer", "not a signer"
				}
				if err := entry.Sign(env, fixtureKey(t, "root1"), role); err != nil {
					t.Fatal(err)
				}
			default:
				for i := range env.Sigs {
					if env.Sigs[i].Kid == kidOf(t, damaged) {
						env.Sigs[i].Sig[0] ^= 1
					}
				}
			}
			changed, err := entry.Encode(env)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "tampered.cbor")
			if err := os.WriteFile(path, changed, 0o600); err != nil {
				t.Fatal(err)
			}
			stdout, stderr, err := run(t, bin, append(rotateArgs(signer), "-role", "signer", "-in", path)...)
			if err == nil || stdout != "" || !strings.Contains(stderr, says) || strings.Contains(stderr, "Sign this entry?") {
				t.Fatalf("tampered entry was not refused before confirmation (%s): %v\n%s", says, err, stderr)
			}
		})
	}
}

func TestRotateSummaryPrecedesConfirmation(t *testing.T) {
	bin, dir := nornBinary(t), t.TempDir()
	wg := rotationWG(t)
	args := append(rotateArgs(signerKeyFile(t, dir, "nas-id2")), "-wg-pub", wgkey.Format(wg), "-new-key", signerKeyFile(t, dir, "stranger"))
	cmd := exec.Command(bin, args...)
	cmd.Stdin = strings.NewReader("no\n")
	var out, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &stderr
	if err := cmd.Run(); err == nil || out.Len() != 0 {
		t.Fatal("declining confirmation must not emit an entry")
	}
	text := stderr.String()
	prompt := strings.Index(text, "Sign this entry?")
	st := rotationState(t)
	old, _ := hex.DecodeString(st.Devices["nas"].WgPk)
	for _, want := range []string{"ROTATE", "nas", wgkey.Format(old), wgkey.Format(wg), st.Devices["nas"].DevicePk,
		hex.EncodeToString(fixtureKey(t, "stranger").Public().(ed25519.PublicKey)), "role device", kidOf(t, "nas-id2"), kidOf(t, "stranger"),
		"rotate_needs_signer", "on", fmt.Sprintf("%d signer", st.SignerThr), "after      " + strconv.FormatUint(st.Size, 10), "entry hash"} {
		at := strings.Index(text, want)
		if at < 0 || prompt < 0 || at >= prompt {
			t.Errorf("summary must show %q before confirmation:\n%s", want, text)
		}
	}
}

func TestRotateOrderingGuardChoicesArePreserved(t *testing.T) {
	bin, dir := nornBinary(t), t.TempDir()
	device, signer := signerKeyFile(t, dir, "nas-id2"), signerKeyFile(t, dir, "signer1")
	for _, noAfter := range []bool{false, true} {
		args := append(rotateArgs(device), "-wg-pub", wgkey.Format(rotationWG(t)), "-yes")
		if noAfter {
			args = append(args, "-no-after")
		} else {
			args = append(args, "-after", "90")
		}
		raw, stderr, err := run(t, bin, args...)
		if err != nil {
			t.Fatalf("%v\n%s", err, stderr)
		}
		env := decodeRotation(t, []byte(raw))
		if noAfter && env.After != nil || !noAfter && (env.After == nil || *env.After != 90) {
			t.Fatal("wrong after")
		}
		if noAfter && !strings.Contains(stderr, "no ordering guard") {
			t.Fatal("missing warning")
		}
		cmd := exec.Command(bin, append(rotateArgs(signer), "-role", "signer", "-yes", "-after", "123", "-in", "-")...)
		cmd.Stdin = strings.NewReader(raw)
		var out, errBuf bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &errBuf
		if err := cmd.Run(); err != nil {
			t.Fatalf("stdin extension: %v\n%s", err, errBuf.String())
		}
		before, _ := entry.Preimage(env)
		after, _ := entry.Preimage(decodeRotation(t, out.Bytes()))
		if !bytes.Equal(before, after) {
			t.Fatal("extension changed the signed guard")
		}
	}
}

func TestRotateReadsButNeverWritesOrPrintsTheWireGuardPrivateKey(t *testing.T) {
	bin, dir := nornBinary(t), t.TempDir()
	private, wg, err := wgkey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "wg.key")
	original := []byte(wgkey.Format(private) + "\n")
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}
	device, signer := signerKeyFile(t, dir, "nas-id2"), signerKeyFile(t, dir, "signer1")
	before, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	raw, stderr, err := run(t, bin, append(rotateArgs(device), "-wg-key", path, "-yes")...)
	if err != nil {
		t.Fatalf("%v\n%s", err, stderr)
	}
	env := decodeRotation(t, []byte(raw))
	if !bytes.Equal(env.Body["wg_pk"].([]byte), wg) {
		t.Fatal("wrong derived public key")
	}
	if strings.Contains(stderr+raw, wgkey.Format(private)) || bytes.Contains([]byte(raw), private) {
		t.Fatal("private key was printed")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(original, after) {
		t.Fatal("private key was rewritten")
	}
	files, err := os.ReadDir(dir)
	if err != nil || len(files) != len(before) {
		t.Fatal("rotation created an unsolicited file")
	}
	input := filepath.Join(dir, "rotation.cbor")
	if err := os.WriteFile(input, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	args := append(rotateArgs(signer), "-role", "signer", "-in", input, "-wg-key", path, "-yes")
	if _, stderr, err := run(t, bin, args...); err != nil {
		t.Fatalf("matching WG file refused: %v\n%s", err, stderr)
	}
	wrong := filepath.Join(dir, "other.key")
	other, _, err := wgkey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(wrong, []byte(wgkey.Format(other)), 0o600); err != nil {
		t.Fatal(err)
	}
	args = append(rotateArgs(signer), "-role", "signer", "-in", input, "-wg-key", wrong)
	stdout, stderr, err := run(t, bin, args...)
	if err == nil || stdout != "" || !strings.Contains(stderr, "does not match") || strings.Contains(stderr, "Sign this entry?") {
		t.Fatalf("disagreeing WG file accepted: %v\n%s", err, stderr)
	}
}
