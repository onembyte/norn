package enrollreq

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/onembyte/norn/internal/bech32m"
	"github.com/onembyte/norn/internal/cbor"
)

// Cold-model gate run 5, defects G3 and G4. A negative that is refused for
// some rule other than the one it is named for does not pin that rule: run 5
// disabled the §4.0 map-key cap and §16.1's `expires > ts` outright and still
// passed 597/597, because both vectors were patched after signing and so died
// at Ed25519 instead.
//
// §4.0 states the construction rule these violated: either the patch
// canonicalises away and the original signature still verifies, or the request
// is re-signed over the patched preimage. The check below is the second half.

func vectorRoot() string { return filepath.Join("..", "..", "testdata", "vectors") }

// signatureCoversItsOwnBytes reports whether the request's `sig` verifies over
// the preimage of the bytes as they actually ship -- which is what makes the
// file's *only* fault the rule it names.
func signatureCoversItsOwnBytes(t *testing.T, name string) bool {
	t.Helper()
	text, err := os.ReadFile(filepath.Join(vectorRoot(), "requests-bad", name+".txt"))
	if err != nil {
		t.Fatal(err)
	}
	_, raw, err := bech32m.Decode(strings.TrimSpace(string(text)))
	if err != nil {
		t.Fatalf("%s is not decodable bech32m, so it tests the wrapper: %v", name, err)
	}
	value, err := cbor.Decode(raw)
	if err != nil {
		t.Skipf("%s is outside the CBOR profile, so its signature cannot be checked "+
			"with a strict decoder; the generator asserts it instead: %v", name, err)
	}
	m, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("%s is not a CBOR map", name)
	}
	sig, _ := m["sig"].([]byte)
	pk, _ := m["device_pk"].([]byte)
	if len(sig) != ed25519.SignatureSize || len(pk) != ed25519.PublicKeySize {
		t.Fatalf("%s carries no usable sig/device_pk", name)
	}
	body := map[string]any{}
	for k, v := range m {
		if k != "sig" {
			body[k] = v
		}
	}
	encoded, err := cbor.Encode(body)
	if err != nil {
		t.Fatalf("re-encoding %s: %v", name, err)
	}
	return ed25519.Verify(pk, append([]byte(PreimagePrefix), encoded...), sig)
}

func TestARuleNegativeIsRefusedByItsOwnRule(t *testing.T) {
	// Each of these names a rule; each must be the *only* thing wrong.
	for _, c := range []struct{ name, rule string }{
		{"expires-at-ts", "expires must be after ts"},
		{"oversize-label-key", "map key must be 1-23 bytes"},
	} {
		t.Run(c.name, func(t *testing.T) {
			text, err := os.ReadFile(filepath.Join(vectorRoot(), "requests-bad", c.name+".txt"))
			if err != nil {
				t.Fatal(err)
			}
			_, err = DecodeText(strings.TrimSpace(string(text)))
			if err == nil {
				t.Fatal("accepted a request that must be refused")
			}
			if !strings.Contains(err.Error(), c.rule) {
				t.Errorf("refused for the wrong reason.\n  got:  %v\n  want: %s", err, c.rule)
			}
			if !signatureCoversItsOwnBytes(t, c.name) {
				t.Error("the signature does not cover the bytes that ship, so a verifier " +
					"missing this rule still refuses the file and the rule is not pinned")
			}
		})
	}
}

// The control: a case that is *about* the signature must still fail to verify.
func TestTheForgedRequestStillDoesNotVerify(t *testing.T) {
	if signatureCoversItsOwnBytes(t, "forged-signature") {
		t.Error("forged-signature verifies, so nothing in the suite forces a request " +
			"verifier to call Ed25519")
	}
}

// Cold-model gate run 6, defect H10 -- and the class behind it.
//
// Run 5 reported two request negatives refused by their own broken signature
// rather than by the rule they name. 6.5c fixed those two. Run 6 found two
// more, and checking the whole directory afterwards found eleven of fifteen.
// 6.5b's own log says a fix should "close the class, not the instance", and one
// checkpoint later I fixed the instances.
//
// So the property is enforced over the directory, not a list. Every case
// declares whether its signature is valid; the declaration is checked against
// the file; and only a case that is *about* the signature may declare it
// broken. A new negative cannot be added without answering the question.

func TestEveryRequestNegativeDeclaresItsSignatureHonestly(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(vectorRoot(), "requests-bad", "cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Cases []struct {
			Name      string `json:"name"`
			Why       string `json:"why"`
			Signature string `json:"signature"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Cases) < 20 {
		t.Fatalf("%d cases; the directory has more than that", len(doc.Cases))
	}

	for _, c := range doc.Cases {
		t.Run(c.Name, func(t *testing.T) {
			switch c.Signature {
			case "valid", "broken":
			default:
				t.Fatalf("declares signature %q; a negative must say whether its "+
					"signature covers its own bytes, or nobody can tell which rule "+
					"refuses it", c.Signature)
			}

			// Only a case about the signature may have a broken one. Anything
			// else is refused by Ed25519 before its own rule is reached, which
			// is the defect this test exists for.
			if c.Signature == "broken" {
				// Two kinds of case may carry a broken signature: one that is
				// *about* the signature, and one whose fault is the key the
				// signature would verify under. A 31-byte `device_pk` cannot
				// verify anything, so that rule cannot be pinned independently
				// by any construction -- §12.1 says so rather than pretending.
				about := strings.Contains(c.Name, "sig") || strings.Contains(c.Why, "sign") ||
					strings.Contains(c.Why, "unsigned") ||
					strings.Contains(c.Name, "device-pk")
				if !about {
					t.Errorf("%s is not about the signature (%q) and carries a broken one, "+
						"so it is refused by Ed25519 and the rule it names is never reached",
						c.Name, c.Why)
				}
				return
			}
			// A case whose fault is the bech32m wrapper carries the valid
			// request inside it; nothing outside the wrapper can read the
			// signature, and the generator computes the declaration from the
			// bytes it wrote.
			text, err := os.ReadFile(filepath.Join(vectorRoot(), "requests-bad", c.Name+".txt"))
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := bech32m.Decode(strings.TrimSpace(string(text))); err != nil {
				t.Skipf("the wrapper is this case's fault: %v", err)
			}
			if !signatureCoversItsOwnBytes(t, c.Name) {
				t.Error("declares a valid signature and does not have one")
			}
		})
	}
}

// The directory's whole purpose, which nothing was checking.
//
// `trust-bad/` has had a loop asserting every case is refused since Phase 0.
// `requests-bad/` never did: individual tests named individual files, so a
// rule could be switched off and the only signal was a case nobody had thought
// to name. Found by a mutation that removed §16.2's padding rules and passed.
func TestEveryRequestNegativeIsRefused(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(vectorRoot(), "requests-bad", "cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Cases []struct{ Name, Why string } `json:"cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	net := shippedNet(t)

	for _, c := range doc.Cases {
		t.Run(c.Name, func(t *testing.T) {
			body, err := os.ReadFile(filepath.Join(vectorRoot(), "requests-bad", c.Name+".txt"))
			if err != nil {
				t.Fatal(err)
			}
			request, err := DecodeText(strings.TrimSpace(string(body)))
			if err != nil {
				return
			}
			if err := Check(request, net); err == nil {
				t.Errorf("accepted a request that must be refused (%s)", c.Why)
			}
		})
	}
}

func TestExcessPaddingVectorHasOnlyPaddingFault(t *testing.T) {
	baseText, err := os.ReadFile(filepath.Join(vectorRoot(), "requests", "req-padding-base.txt"))
	if err != nil {
		t.Fatal(err)
	}
	base, err := DecodeText(strings.TrimSpace(string(baseText)))
	if err != nil {
		t.Fatalf("padding control request is invalid: %v", err)
	}
	if err := Check(base, shippedNet(t)); err != nil {
		t.Fatalf("padding control signature does not verify: %v", err)
	}
	baseBytes, err := Encode(base)
	if err != nil {
		t.Fatal(err)
	}
	if remainder := (8 * len(baseBytes)) % 5; remainder != 0 && remainder != 3 && remainder != 4 {
		t.Fatalf("padding control is %d bytes, so 8L mod 5 is %d; want 0, 3 or 4",
			len(baseBytes), remainder)
	}

	badText, err := os.ReadFile(filepath.Join(vectorRoot(), "requests-bad", "excess-padding.txt"))
	if err != nil {
		t.Fatal(err)
	}
	baseHRP, baseGroups, err := bech32m.DecodeRaw(strings.TrimSpace(string(baseText)))
	if err != nil {
		t.Fatal(err)
	}
	badHRP, badGroups, err := bech32m.DecodeRaw(strings.TrimSpace(string(badText)))
	if err != nil {
		t.Fatalf("excess-padding checksum is invalid: %v", err)
	}
	if badHRP != baseHRP || len(badGroups) != len(baseGroups)+1 ||
		!bytes.Equal(badGroups[:len(baseGroups)], baseGroups) || badGroups[len(badGroups)-1] != 0 {
		t.Fatal("excess-padding must append exactly one zero 5-bit group to its valid control")
	}
	if _, _, err := bech32m.Decode(strings.TrimSpace(string(badText))); err == nil ||
		!strings.Contains(err.Error(), "too much padding") {
		t.Fatalf("excess-padding was not refused by the padding rule: %v", err)
	}
}

func TestOversizeLabelVectorIsOneBytePastTheCap(t *testing.T) {
	baseText, err := os.ReadFile(filepath.Join(vectorRoot(), "requests", "req-label-at-cap.txt"))
	if err != nil {
		t.Fatal(err)
	}
	base, err := DecodeText(strings.TrimSpace(string(baseText)))
	if err != nil {
		t.Fatalf("the 256-byte label control is invalid: %v", err)
	}
	if err := Check(base, shippedNet(t)); err != nil {
		t.Fatalf("the 256-byte label control signature does not verify: %v", err)
	}
	if got := len([]byte(base.Labels["ip"])); got != 256 {
		t.Fatalf("accepted label is %d UTF-8 bytes, want exactly 256", got)
	}
	if got := len([]rune(base.Labels["ip"])); got != 128 {
		t.Fatalf("accepted label is %d code points, want 128", got)
	}

	text, err := os.ReadFile(filepath.Join(vectorRoot(), "requests-bad", "oversize-label.txt"))
	if err != nil {
		t.Fatal(err)
	}
	_, raw, err := bech32m.Decode(strings.TrimSpace(string(text)))
	if err != nil {
		t.Fatalf("oversize-label is not a valid bech32m wrapper: %v", err)
	}
	value, err := cbor.Decode(raw)
	if err != nil {
		t.Fatalf("oversize-label is not valid CBOR: %v", err)
	}
	request, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("request is %T, want map[string]any", value)
	}
	labels, ok := request["labels"].(map[string]any)
	if !ok {
		t.Fatalf("labels is %T, want map[string]any", request["labels"])
	}
	label, ok := labels["ip"].(string)
	if !ok {
		t.Fatalf("labels.ip is %T, want string", labels["ip"])
	}
	if got := len([]byte(label)); got != 257 {
		t.Fatalf("oversize-label is %d UTF-8 bytes, want exactly 257", got)
	}
	if got := len([]rune(label)); got != 129 {
		t.Fatalf("oversize-label is %d code points, want 129", got)
	}
	if !signatureCoversItsOwnBytes(t, "oversize-label") {
		t.Fatal("oversize-label signature does not cover its own bytes")
	}
	if _, err := DecodeText(strings.TrimSpace(string(text))); err == nil ||
		!strings.Contains(err.Error(), "longer than 256 bytes") {
		t.Fatalf("257-byte label was not refused by the value cap: %v", err)
	}
}

func shippedNet(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(vectorRoot(), "keys.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Net string `json:"net"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	out := make([]byte, len(doc.Net)/2)
	for i := range out {
		var b int
		if _, err := fmt.Sscanf(doc.Net[2*i:2*i+2], "%02x", &b); err != nil {
			t.Fatal(err)
		}
		out[i] = byte(b)
	}
	return out
}

// --- Cold-model gate run 7, defect J6 -----------------------------------
//
// `requests/` shipped four positive cases and **nothing read them** -- not a
// Go test, not a Python one. So §16.2's one positive obligation ("the
// canonical form is lowercase; an all-uppercase form MUST also be accepted,
// because QR alphanumeric mode has no lowercase letters") was vectored by
// nothing, and run 7's `bech32-reject-upper` variant passed the whole suite.
//
// The enrolment flow the design exists for is a device printing a QR code and
// a signer scanning it. An implementation that refuses the uppercase form
// cannot take part in it, and until this test the suite said nothing.

type requestCase struct {
	Name          string `json:"name"`
	Form          string `json:"form"`
	SameRequestAs string `json:"same_request_as"`
}

func positiveRequestCases(t *testing.T) []requestCase {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(vectorRoot(), "requests", "cases.json"))
	if err != nil {
		t.Fatalf("the positive request vectors are missing: %v", err)
	}
	var doc struct {
		Cases []requestCase `json:"cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Cases) == 0 {
		t.Fatal("no positive request cases")
	}
	return doc.Cases
}

func TestEveryPositiveRequestVectorIsAccepted(t *testing.T) {
	net := shippedNet(t)
	for _, c := range positiveRequestCases(t) {
		t.Run(c.Name, func(t *testing.T) {
			dir := filepath.Join(vectorRoot(), "requests")
			text, err := os.ReadFile(filepath.Join(dir, c.Name+".txt"))
			if err != nil {
				t.Fatal(err)
			}
			trimmed := strings.TrimSuffix(string(text), "\n")

			request, err := DecodeText(trimmed)
			if err != nil {
				t.Fatalf("a request a signer MUST accept did not decode: %v", err)
			}
			if err := Check(request, net); err != nil {
				t.Fatalf("a request a signer MUST accept was refused: %v", err)
			}
			if !Verify(request) {
				t.Fatal("the shipped signature does not verify")
			}

			// The three files are one case in three forms; a reader that
			// takes any one of them must land on the same request.
			wire, err := os.ReadFile(filepath.Join(dir, c.Name+".cbor"))
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := Encode(request)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(encoded, wire) {
				t.Errorf("the text form and the .cbor are different requests")
			}
			// Canonical JSON (§14.1) carries byte strings as hex.
			var meta struct {
				PreimageSHA256 string `json:"preimage_sha256"`
				Text           string `json:"text"`
				Size           int    `json:"size"`
			}
			blob, err := os.ReadFile(filepath.Join(dir, c.Name+".json"))
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(blob, &meta); err != nil {
				t.Fatal(err)
			}
			if meta.Text != trimmed {
				t.Errorf("the .json records a different text form than the .txt ships")
			}
			if meta.Size != len(wire) {
				t.Errorf("the .json says %d bytes, the .cbor is %d", meta.Size, len(wire))
			}
			preimage, err := Preimage(request)
			if err != nil {
				t.Fatal(err)
			}
			if sum := sha256.Sum256(preimage); hex.EncodeToString(sum[:]) != meta.PreimageSHA256 {
				t.Errorf("the signature preimage is not the one the .json publishes")
			}

			switch c.Form {
			case "canonical":
				if trimmed != strings.ToLower(trimmed) {
					t.Error("§16.2 makes lowercase the canonical form")
				}
			case "uppercase":
				if trimmed != strings.ToUpper(trimmed) {
					t.Error("an uppercase case whose text is not all-uppercase pins nothing")
				}
				twin, err := os.ReadFile(filepath.Join(dir, c.SameRequestAs+".txt"))
				if err != nil {
					t.Fatalf("the case names %q as its twin: %v", c.SameRequestAs, err)
				}
				if want := strings.ToUpper(strings.TrimSuffix(string(twin), "\n")); trimmed != want {
					t.Error("the uppercase case is not the same string as its lowercase twin")
				}
			default:
				t.Fatalf("unknown form %q", c.Form)
			}
		})
	}
}

func TestReservedHintRequestVectorKeepsMalformedValuesOpaque(t *testing.T) {
	var found bool
	for _, c := range positiveRequestCases(t) {
		if c.Name == "req-reserved-hints" && c.Form == "canonical" {
			found = true
		}
	}
	if !found {
		t.Fatal("no positive request vector pins malformed reserved hints")
	}

	path := filepath.Join(vectorRoot(), "requests", "req-reserved-hints.txt")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	request, err := DecodeText(strings.TrimSuffix(string(raw), "\n"))
	if err != nil {
		t.Fatalf("malformed advisory hints must not invalidate a request: %v", err)
	}
	if err := Check(request, shippedNet(t)); err != nil {
		t.Fatalf("malformed advisory hints must not invalidate a request: %v", err)
	}
	if !Verify(request) {
		t.Fatal("the malformed-hints request must carry a valid device signature")
	}
	for key, want := range map[string]string{"ip": "not-a-cidr", "endpoint": "not-an-endpoint"} {
		if got := request.Labels[key]; got != want {
			t.Errorf("labels[%q] = %q, want %q", key, got, want)
		}
	}
}

// The uppercase obligation is a MUST with no negative to hide behind: if the
// suite carries no uppercase case, an implementation that refuses one is
// indistinguishable from a correct one.
func TestTheSuiteCarriesAnUppercaseRequest(t *testing.T) {
	for _, c := range positiveRequestCases(t) {
		if c.Form == "uppercase" {
			return
		}
	}
	t.Fatal("no uppercase request vector: §16.2's one positive MUST is unpinned")
}
