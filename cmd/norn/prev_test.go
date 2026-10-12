package main

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/onembyte/norn/internal/enrollreq"
	"github.com/onembyte/norn/internal/entry"
	"github.com/onembyte/norn/internal/state"
	"github.com/onembyte/norn/internal/wgkey"
)

func TestFreshEnrollmentCarriesTheObservedRevokedRecordVersion(t *testing.T) {
	anchor, err := loadAnchor(filepath.Join(vectors(), "trust.cbor"))
	if err != nil {
		t.Fatal(err)
	}
	req := &enrollreq.Request{V: 1, Net: anchor.Net, DeviceID: "again", DevicePK: fixtureKey(t, "nas").Public().(ed25519.PublicKey), WGPK: rotationWG(t), TS: 1}
	if err := enrollreq.Sign(req, fixtureKey(t, "nas")); err != nil {
		t.Fatal(err)
	}
	text, err := enrollreq.Text(req)
	if err != nil {
		t.Fatal(err)
	}
	st := state.New(anchor.Net)
	st.Devices["again"] = state.Device{Status: state.StatusRevoked, Version: 12}
	env, _, _, err := buildOrExtend([]byte(text), anchor, observation{Size: 20, State: st}, -1, false)
	if err != nil {
		t.Fatal(err)
	}
	if env.Prev == nil || *env.Prev != 12 {
		t.Fatalf("enroll prev=%v, want 12", env.Prev)
	}
}

func TestFreshCommandsCarryObservedPrevAndAllowAnExplicitOverride(t *testing.T) {
	bin, dir := nornBinary(t), t.TempDir()
	st := rotationState(t)
	key := signerKeyFile(t, dir, "nas-id2")
	rootKey := signerKeyFile(t, dir, "root1")
	for _, override := range []bool{false, true} {
		args := append(rotateArgs(key), "-wg-pub", wgkey.Format(rotationWG(t)), "-yes")
		if override {
			args = append(args, "-prev", "17")
		}
		out, stderr, err := run(t, bin, args...)
		if err != nil {
			t.Fatalf("rotate: %v\n%s", err, stderr)
		}
		env, err := entry.Decode([]byte(out))
		if err != nil {
			t.Fatal(err)
		}
		want := st.Devices["nas"].Version
		if override {
			want = 17
		}
		if env.Prev == nil || *env.Prev != want {
			t.Errorf("rotate prev=%v, want %d", env.Prev, want)
		}
		args = append(governArgs(rootKey, "signer_add"), "-pk-hex", governancePublic(t, "root2"))
		// root2 is already a root; use a device key entering the signer set.
		args[len(args)-1] = governancePublic(t, "printer")
		if override {
			args = append(args, "-prev", "17")
		}
		out, stderr, err = runGovern(t, bin, "yes\n", args...)
		if err != nil {
			t.Fatalf("govern: %v\n%s", err, stderr)
		}
		env, err = entry.Decode([]byte(out))
		if err != nil {
			t.Fatal(err)
		}
		want = st.Versions["signers"]
		if override {
			want = 17
		}
		if env.Prev == nil || *env.Prev != want {
			t.Errorf("signer_add prev=%v, want %d", env.Prev, want)
		}
	}
}

func TestEnrollmentPrevOverrideAndExtensionPreserveSignedContent(t *testing.T) {
	bin, dir := nornBinary(t), t.TempDir()
	anchor, err := loadAnchor(filepath.Join(vectors(), "trust.cbor"))
	if err != nil {
		t.Fatal(err)
	}
	request := &enrollreq.Request{V: 1, Net: anchor.Net, DeviceID: "new-cas", DevicePK: fixtureKey(t, "nas").Public().(ed25519.PublicKey), WGPK: rotationWG(t), TS: 1}
	if err := enrollreq.Sign(request, fixtureKey(t, "nas")); err != nil {
		t.Fatal(err)
	}
	text, err := enrollreq.Text(request)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "request.txt")
	if err := os.WriteFile(path, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	base := []string{"sign", "-trust", filepath.Join(vectors(), "trust.cbor"), "-log", filepath.Join(vectors(), "served"), "-key", signerKeyFile(t, dir, "signer1"), "-yes"}
	out, stderr, err := run(t, bin, append(base, "-prev", "17", path)...)
	if err != nil {
		t.Fatalf("sign: %v\n%s", err, stderr)
	}
	env, err := entry.Decode([]byte(out))
	if err != nil {
		t.Fatal(err)
	}
	if env.Prev == nil || *env.Prev != 17 {
		t.Fatal("sign did not carry explicit prev")
	}
	signed := governanceFile(t, []byte(out))
	_, stderr, err = run(t, bin, append(base, "-prev", "18", signed)...)
	if err == nil || !strings.Contains(stderr, "the entry's prev guard does not match the given flag; existing signed fields cannot be changed") {
		t.Fatalf("extension changed prev: %v\n%s", err, stderr)
	}
}

func TestRotateCanKeepTheCurrentIdentityKeyWithOneDeviceSignature(t *testing.T) {
	bin, dir := nornBinary(t), t.TempDir()
	key := signerKeyFile(t, dir, "nas-id2")
	wg := rotationWG(t)
	out, stderr, err := run(t, bin, append(rotateArgs(key), "-wg-pub", wgkey.Format(wg), "-new-key", key, "-yes")...)
	if err != nil {
		t.Fatalf("same-key rotation: %v\n%s", err, stderr)
	}
	env, err := entry.Decode([]byte(out))
	if err != nil {
		t.Fatal(err)
	}
	if len(env.Sigs) != 1 {
		t.Fatalf("got %d device signatures, want one", len(env.Sigs))
	}
	complete := extendRotation(t, bin, dir, []byte(out))
	requireRotated(t, complete, wg, rotationState(t).Devices["nas"].DevicePk)
}
