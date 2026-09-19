package enrollreq

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The vectors are the reference implementation's, not this one's: SPEC §12's
// two provenances put requests on the reference side, so agreement here is
// agreement with an implementation that shares no code with this package.

func vectorRoot() string { return filepath.Join("..", "..", "testdata", "vectors") }

type mirror struct {
	Request struct {
		V         uint64            `json:"v"`
		Net       string            `json:"net"`
		DeviceID  string            `json:"device_id"`
		DevicePK  string            `json:"device_pk"`
		WGPK      string            `json:"wg_pk"`
		TS        uint64            `json:"ts"`
		Labels    map[string]string `json:"labels"`
		Expires   *uint64           `json:"expires"`
		Signature string            `json:"sig"`
	} `json:"request"`
	PreimageSHA256 string `json:"preimage_sha256"`
	Text           string `json:"text"`
	Size           int    `json:"size"`
}

func readCases(t *testing.T, dir string, into any) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(vectorRoot(), dir, "cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, into); err != nil {
		t.Fatal(err)
	}
}

func TestPositiveVectors(t *testing.T) {
	var index struct {
		Cases []string `json:"cases"`
	}
	readCases(t, "requests", &index)
	if len(index.Cases) == 0 {
		t.Fatal("no request vectors")
	}

	for _, name := range index.Cases {
		t.Run(name, func(t *testing.T) {
			base := filepath.Join(vectorRoot(), "requests", name)
			raw, err := os.ReadFile(base + ".cbor")
			if err != nil {
				t.Fatal(err)
			}
			text, err := os.ReadFile(base + ".txt")
			if err != nil {
				t.Fatal(err)
			}
			mirrorRaw, err := os.ReadFile(base + ".json")
			if err != nil {
				t.Fatal(err)
			}
			var want mirror
			if err := json.Unmarshal(mirrorRaw, &want); err != nil {
				t.Fatal(err)
			}

			req, err := Decode(raw)
			if err != nil {
				t.Fatalf("Decode: %v", err)
			}

			// Re-encoding must be byte-identical: a request is signed, so a
			// second encoding of the same meaning is a second signed object.
			got, err := Encode(req)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, raw) {
				t.Errorf("re-encode differs:\n got %x\nwant %x", got, raw)
			}
			if len(raw) != want.Size {
				t.Errorf("size = %d, want %d", len(raw), want.Size)
			}

			preimage, err := Preimage(req)
			if err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(preimage)
			if hex.EncodeToString(sum[:]) != want.PreimageSHA256 {
				t.Errorf("preimage hash = %x, want %s", sum, want.PreimageSHA256)
			}
			if !strings.HasPrefix(string(preimage), PreimagePrefix) {
				t.Error("the preimage is not domain-separated")
			}

			if !Verify(req) {
				t.Error("the vector's own signature does not verify")
			}
			if err := Check(req, req.Net); err != nil {
				t.Errorf("Check: %v", err)
			}

			// Text form, both directions, and the uppercase QR form.
			wantText := strings.TrimSuffix(string(text), "\n")
			gotText, err := Text(req)
			if err != nil {
				t.Fatal(err)
			}
			if gotText != wantText || gotText != want.Text {
				t.Errorf("text = %q, want %q", gotText, wantText)
			}
			for _, form := range []string{wantText, strings.ToUpper(wantText)} {
				back, err := DecodeText(form)
				if err != nil {
					t.Fatalf("DecodeText: %v", err)
				}
				again, err := Encode(back)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(again, raw) {
					t.Error("the text form decoded to different bytes")
				}
			}

			// The fields themselves, against the mirror.
			if req.DeviceID != want.Request.DeviceID || req.TS != want.Request.TS || req.V != want.Request.V {
				t.Errorf("scalar fields differ: %+v", req)
			}
			for _, pair := range []struct {
				got  []byte
				want string
				name string
			}{
				{req.Net, want.Request.Net, "net"},
				{req.DevicePK, want.Request.DevicePK, "device_pk"},
				{req.WGPK, want.Request.WGPK, "wg_pk"},
				{req.Sig, want.Request.Signature, "sig"},
			} {
				if hex.EncodeToString(pair.got) != pair.want {
					t.Errorf("%s = %x, want %s", pair.name, pair.got, pair.want)
				}
			}
			if len(req.Labels) != len(want.Request.Labels) {
				t.Errorf("labels = %v, want %v", req.Labels, want.Request.Labels)
			}
			for k, v := range want.Request.Labels {
				if req.Labels[k] != v {
					t.Errorf("label %q = %q, want %q", k, req.Labels[k], v)
				}
			}
			switch {
			case want.Request.Expires == nil && req.Expires != nil:
				t.Error("expires present where the vector has none")
			case want.Request.Expires != nil && (req.Expires == nil || *req.Expires != *want.Request.Expires):
				t.Errorf("expires = %v, want %d", req.Expires, *want.Request.Expires)
			}
		})
	}
}

func TestNegativeVectors(t *testing.T) {
	var index struct {
		Cases []struct{ Name, Why string } `json:"cases"`
	}
	readCases(t, "requests-bad", &index)
	if len(index.Cases) == 0 {
		t.Fatal("no negative request vectors")
	}

	for _, c := range index.Cases {
		t.Run(c.Name, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(vectorRoot(), "requests-bad", c.Name+".txt"))
			if err != nil {
				t.Fatal(err)
			}
			text := strings.TrimSuffix(string(raw), "\n")

			req, err := DecodeText(text)
			if err == nil {
				err = Check(req, req.Net)
			}
			if err == nil {
				t.Fatalf("accepted a request that is %s", c.Why)
			}
		})
	}
}

// Without this, a package that never calls Ed25519 passes the whole negative
// directory -- which is exactly what gate run 4 found in the entry vectors.
func TestForgedSignatureIsStructurallyPerfect(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(vectorRoot(), "requests-bad", "forged-signature.txt"))
	if err != nil {
		t.Fatal(err)
	}
	req, err := DecodeText(strings.TrimSuffix(string(raw), "\n"))
	if err != nil {
		t.Fatalf("the forged case must decode cleanly, or it tests nothing: %v", err)
	}
	if len(req.Sig) != ed25519.SignatureSize {
		t.Fatal("the forged case is not a well-formed signature")
	}
	if Verify(req) {
		t.Fatal("a signature by another key verified")
	}
}
