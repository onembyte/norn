package receipt

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/onembyte/norn/internal/note"
)

func TestAnOverlongReceiptLeafFailsBeforeBindingAndRepairsOnlyItsSuffix(t *testing.T) {
	const root = "../../testdata/vectors"
	const name = "leaf-33-bytes.note"
	read := func(path string) []byte {
		t.Helper()
		b, e := os.ReadFile(root + "/" + path)
		if e != nil {
			t.Fatal(e)
		}
		return b
	}
	var m struct {
		Cases []struct{ Name string }
		Codes map[string]string
		Rules map[string]struct{ Section, Says string }
	}
	if e := json.Unmarshal(read("receipt-bad/cases.json"), &m); e != nil {
		t.Fatal(e)
	}
	count := 0
	for _, c := range m.Cases {
		if c.Name == name {
			count++
		}
	}
	if count != 1 || m.Codes[name] != "leaf-hash" || m.Rules[name].Section != "7" || m.Rules[name].Says != "The leaf hash MUST be standard base64 and decode to exactly 32 bytes" {
		t.Fatal("overlong leaf case or rule missing")
	}
	keys := anchorLogKey(t, root)
	leaf, org, _ := receiptFacts(t, root)
	raw := read("receipt-bad/" + name)
	_, err := Check(string(raw), keys, org, nil, time.Time{})
	if code, ok := CodeOf(err); !ok || code != Code("leaf-hash") {
		t.Fatalf("code=%q, want leaf-hash: %v", code, err)
	}
	text, err := note.Verify(string(raw), keys)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	long, err := base64.StdEncoding.Strict().DecodeString(lines[2])
	if err != nil || len(long) != 33 || base64.StdEncoding.EncodeToString(long) != lines[2] || !bytes.Equal(long, append(append([]byte{}, leaf...), 0)) {
		t.Fatal("expected canonical genesis leaf plus one zero byte")
	}
	lines[2] = base64.StdEncoding.EncodeToString(long[:32])
	seed := sha256.Sum256([]byte("norn/testvector/v1\nlogkey"))
	repair, err := note.Sign(strings.Join(lines, "\n")+"\n", org, ed25519.NewKeyFromSeed(seed[:]))
	if err != nil {
		t.Fatal(err)
	}
	if repair != string(read("receipt.note")) {
		t.Fatal("suffix-only repair differs from genesis receipt")
	}
	if _, err := Check(repair, keys, org, leaf, time.Time{}); err != nil {
		t.Fatal(err)
	}
	t.Log("suffix-only repair accepted against genesis leaf")
}
