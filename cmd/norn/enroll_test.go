package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/onembyte/norn/internal/enrollreq"
	"github.com/onembyte/norn/internal/keyfile"
	"github.com/onembyte/norn/internal/wgkey"
)

// `norn enroll` runs on a device nobody is watching, and what it prints has to
// be usable by a signer who trusts nothing about it yet. So these tests check
// the request that comes out, not just the exit code.

const testNet = "norn/n5xw6zdmnrxxq33vojqxezlbnq" // an arbitrary 16-byte net

func enrollRun(t *testing.T, bin string, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	cmd := exec.Command(bin, append([]string{"enroll"}, args...)...)
	var out, errBuf strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &errBuf
	err = cmd.Run()
	return out.String(), errBuf.String(), err
}

func decodeRequest(t *testing.T, stdout string) *enrollreq.Request {
	t.Helper()
	text := strings.TrimSpace(stdout)
	request, err := enrollreq.DecodeText(text)
	if err != nil {
		t.Fatalf("stdout is not a request: %v\n%q", err, text)
	}
	if err := enrollreq.Check(request, request.Net); err != nil {
		t.Fatalf("the printed request does not verify: %v", err)
	}
	return request
}

func TestEnrollCreatesAKeyAndPrintsAVerifiableRequest(t *testing.T) {
	bin := nornBinary(t)
	dir := t.TempDir()
	key := filepath.Join(dir, "device.key")

	stdout, stderr, err := enrollRun(t, bin, "-name", "pi-cam", "-net", testNet,
		"-key", key, "-gen")
	if err != nil {
		t.Fatalf("enroll: %v\n%s", err, stderr)
	}

	request := decodeRequest(t, stdout)
	if request.DeviceID != "pi-cam" {
		t.Errorf("device_id = %q", request.DeviceID)
	}

	// The device key must exist, be private, and be the one that signed.
	info, err := os.Stat(key)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("device key mode = %o", mode)
	}
	private, _, err := keyfile.Read(key)
	if err != nil {
		t.Fatal(err)
	}
	if !private.Public().(ed25519.PublicKey).Equal(ed25519.PublicKey(request.DevicePK)) {
		t.Error("the request was signed by a key other than the one on disk")
	}

	// -gen must have left a WireGuard key beside it, matching the request.
	wgPrivate, err := wgkey.ReadPrivate(filepath.Join(dir, "wg.key"))
	if err != nil {
		t.Fatalf("-gen did not leave a usable WireGuard key: %v", err)
	}
	public, err := wgkey.Public(wgPrivate)
	if err != nil {
		t.Fatal(err)
	}
	if string(public) != string(request.WGPK) {
		t.Error("the request does not carry the generated WireGuard key")
	}

	if !strings.Contains(stderr, "ENROLLMENT REQUEST for pi-cam") {
		t.Errorf("no human summary on stderr:\n%s", stderr)
	}

	// The QR carries the uppercase form, because QR alphanumeric mode has no
	// lowercase (SPEC §16.2). A signer scanning it must get the same request,
	// or the camera path quietly does not work.
	scanned, err := enrollreq.DecodeText(strings.ToUpper(strings.TrimSpace(stdout)))
	if err != nil {
		t.Fatalf("the uppercase form a scanner produces does not decode: %v", err)
	}
	if string(scanned.Sig) != string(request.Sig) {
		t.Error("the scanned request differs from the printed one")
	}
	// stdout is the request and nothing else, so `> request.txt` is usable.
	if strings.Count(strings.TrimSpace(stdout), "\n") != 0 {
		t.Errorf("stdout carries more than the request:\n%q", stdout)
	}
}

func TestEnrollReusesAnExistingDeviceKey(t *testing.T) {
	bin := nornBinary(t)
	dir := t.TempDir()
	key := filepath.Join(dir, "device.key")

	first, _, err := enrollRun(t, bin, "-name", "pi-cam", "-net", testNet, "-key", key, "-gen")
	if err != nil {
		t.Fatal(err)
	}
	before := decodeRequest(t, first)

	second, stderr, err := enrollRun(t, bin, "-name", "pi-cam", "-net", testNet,
		"-key", key, "-wg-pub", wgkey.Format(before.WGPK))
	if err != nil {
		t.Fatalf("second run: %v\n%s", err, stderr)
	}
	after := decodeRequest(t, second)

	if string(before.DevicePK) != string(after.DevicePK) {
		t.Error("the device identity changed between runs")
	}
	if !strings.Contains(stderr, "existing") {
		t.Errorf("the summary should say the key was reused:\n%s", stderr)
	}
}

func TestEnrollTakesTheWireGuardKeyFromAFile(t *testing.T) {
	bin := nornBinary(t)
	dir := t.TempDir()
	wgPath := filepath.Join(dir, "wg0.key")

	private, public, err := wgkey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(wgPath, []byte(wgkey.Format(private)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	stdout, stderr, err := enrollRun(t, bin, "-name", "nas", "-net", testNet,
		"-key", filepath.Join(dir, "device.key"), "-wg-key", wgPath)
	if err != nil {
		t.Fatalf("enroll: %v\n%s", err, stderr)
	}
	if got := decodeRequest(t, stdout); string(got.WGPK) != string(public) {
		t.Error("the request does not carry the public half of the given key")
	}
}

func TestEnrollLabelsAndExpiry(t *testing.T) {
	bin := nornBinary(t)
	dir := t.TempDir()

	before := time.Now()
	stdout, stderr, err := enrollRun(t, bin, "-name", "contractor", "-net", testNet,
		"-key", filepath.Join(dir, "device.key"), "-gen",
		"-label", "ip=10.9.0.14/32", "-label", "owner=franco", "-expires", "30d")
	if err != nil {
		t.Fatalf("enroll: %v\n%s", err, stderr)
	}

	request := decodeRequest(t, stdout)
	if request.Labels["ip"] != "10.9.0.14/32" || request.Labels["owner"] != "franco" {
		t.Errorf("labels = %v", request.Labels)
	}
	if request.Expires == nil {
		t.Fatal("no expiry in the request")
	}
	want := before.Add(30 * 24 * time.Hour).Unix()
	if delta := int64(*request.Expires) - want; delta < -60 || delta > 60 {
		t.Errorf("expires is %d seconds off 30 days", delta)
	}
	if *request.Expires <= request.TS {
		t.Error("expires is not after ts")
	}
}

func TestEnrollRefusals(t *testing.T) {
	bin := nornBinary(t)
	cases := []struct {
		why  string
		args []string
		says string
	}{
		{"no name", []string{"-net", testNet, "-gen"}, "-name is required"},
		{"no network", []string{"-name", "pi-cam", "-gen"}, "-net or -trust is required"},
		{"no wireguard key", []string{"-name", "pi-cam", "-net", testNet}, "exactly one of"},
		{"two wireguard sources", []string{"-name", "pi-cam", "-net", testNet, "-gen",
			"-wg-pub", wgkey.Format(make([]byte, 32))}, "exactly one of"},
		{"bad device_id", []string{"-name", "Pi-Cam", "-net", testNet, "-gen"}, "device_id"},
		{"bad label", []string{"-name", "pi-cam", "-net", testNet, "-gen", "-label", "nope"}, "key=value"},
		{"bad duration", []string{"-name", "pi-cam", "-net", testNet, "-gen", "-expires", "soon"}, "not a duration"},
		{"bad net", []string{"-name", "pi-cam", "-net", "norn/!!!", "-gen"}, "-net"},
	}
	for _, c := range cases {
		t.Run(c.why, func(t *testing.T) {
			dir := t.TempDir()
			args := append([]string{"-key", filepath.Join(dir, "device.key")}, c.args...)
			stdout, stderr, err := enrollRun(t, bin, args...)
			if err == nil {
				t.Fatalf("accepted a run with %s", c.why)
			}
			if !strings.Contains(stderr, c.says) {
				t.Errorf("the error should mention %q, got:\n%s", c.says, stderr)
			}
			if strings.TrimSpace(stdout) != "" {
				t.Errorf("a failed run printed a request:\n%s", stdout)
			}
		})
	}
}

func TestEnrollRefusesConflictingNetworks(t *testing.T) {
	bin := nornBinary(t)
	dir := t.TempDir()
	trustFile := filepath.Join(vectors(), "trust.cbor")
	if _, err := os.Stat(trustFile); err != nil {
		t.Skip("trust vector not present")
	}

	_, stderr, err := enrollRun(t, bin, "-name", "pi-cam", "-gen",
		"-key", filepath.Join(dir, "device.key"),
		"-trust", trustFile, "-net", testNet)
	if err == nil {
		t.Fatal("accepted a trust file and a -net that disagree")
	}
	if !strings.Contains(stderr, "different networks") {
		t.Errorf("stderr should say why:\n%s", stderr)
	}
}

// A device that already has a trust file -- one being re-enrolled after a
// revoke -- should not have to retype its network.
func TestEnrollTakesTheNetworkFromATrustFile(t *testing.T) {
	bin := nornBinary(t)
	dir := t.TempDir()
	trustFile := filepath.Join(vectors(), "trust.cbor")
	raw, err := os.ReadFile(trustFile)
	if err != nil {
		t.Skip("trust vector not present")
	}

	stdout, stderr, err := enrollRun(t, bin, "-name", "pi-cam", "-gen",
		"-key", filepath.Join(dir, "device.key"), "-trust", trustFile)
	if err != nil {
		t.Fatalf("enroll: %v\n%s", err, stderr)
	}
	request := decodeRequest(t, stdout)
	if !strings.Contains(hex.EncodeToString(raw), hex.EncodeToString(request.Net)) {
		t.Error("the request's net is not the trust file's")
	}
}
