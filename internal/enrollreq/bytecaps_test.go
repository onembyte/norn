package enrollreq

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/onembyte/norn/internal/bech32m"
	"github.com/onembyte/norn/internal/cbor"
)

// --- Cold-model gate run 11, defect D6 ----------------------------------
//
// §4.0 caps a label value at 256 bytes of UTF-8. `oversize-label` was 257
// ASCII bytes and no value sat at 256, so a reader counting characters, or
// refusing 256, passed. `req-label-at-the-cap` is the positive; the negative
// is the same request with the value's last `x` made `Ж`, and re-signed.
func TestTheLabelValueCapCountsBytesNotCharacters(t *testing.T) {
	read := func(dir, name string) (map[string]any, string) {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join(vectorRoot(), dir, name+".txt"))
		if err != nil {
			t.Fatal(err)
		}
		text := strings.TrimSpace(string(raw))
		// Decoded as plain CBOR: the negative exists to fail the field rules.
		_, payload, err := bech32m.Decode(text)
		if err != nil {
			t.Fatal(err)
		}
		value, err := cbor.Decode(payload)
		if err != nil {
			t.Fatal(err)
		}
		return value.(map[string]any), text
	}
	pos, posText := read("requests", "req-label-at-the-cap")
	neg, negText := read("requests-bad", "oversize-label")

	// The shape: one label value, one byte, and nothing else but the signature.
	pl, _ := pos["labels"].(map[string]any)
	nl, _ := neg["labels"].(map[string]any)
	if len(pl) != 1 || len(nl) != 1 {
		t.Fatalf("%d and %d labels; the pair carries one each", len(pl), len(nl))
	}
	var p, n string
	for k := range pl {
		p, _ = pl[k].(string)
		n, _ = nl[k].(string)
	}
	if len(p) != 256 || len(n) != 257 {
		t.Fatalf("%d and %d bytes; the pair must sit at 256 and one past it", len(p), len(n))
	}
	if utf8.RuneCountInString(p) != utf8.RuneCountInString(n) ||
		len(utf16.Encode([]rune(p))) != len(utf16.Encode([]rune(n))) {
		t.Fatal("the two values differ in characters, so a reader counting them can tell them apart")
	}
	// Measured as encoded (§4.0): normalised first, the positive is over the cap.
	// `é` (U+00E9) is the motif's one decomposable letter: two bytes as sent,
	// three once decomposed, counted here without an x/text dependency.
	if n := len(p) + strings.Count(p, "\u00e9"); n <= 256 {
		t.Errorf("the positive is %d bytes under NFD, within the cap", n)
	}
	for _, m := range []map[string]any{pos, neg} {
		delete(m, "labels")
		delete(m, "sig")
	}
	if !reflect.DeepEqual(pos, neg) {
		t.Fatal("the two requests differ in more than the label value and the signature")
	}
	if !signatureCoversItsOwnBytes(t, "oversize-label") {
		t.Fatal("oversize-label's signature does not cover its bytes, so Ed25519 refuses it first")
	}

	// Then the verdicts.
	net := shippedNet(t)
	check := func(text string) error {
		r, err := DecodeText(text)
		if err == nil {
			err = Check(r, net)
		}
		return err
	}
	if err := check(posText); err != nil {
		t.Errorf("req-label-at-the-cap is refused: %v; its value sits exactly at the cap", err)
	}
	if err := check(negText); err == nil || !strings.Contains(err.Error(), "longer than 256 bytes") {
		t.Errorf("oversize-label: got %v, want the label-value cap", err)
	}
}
