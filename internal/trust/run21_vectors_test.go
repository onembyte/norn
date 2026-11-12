package trust

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/onembyte/norn/internal/cbor"
)

func TestSwappedWitnessNamesKeepTheSetsButBreakTheirAssociation(t *testing.T) {
	const root = "../../testdata/vectors/"
	const name = "61-witness-names-swapped"
	read := func(path string) []byte {
		t.Helper()
		b, e := os.ReadFile(root + path)
		if e != nil {
			t.Fatal(e)
		}
		return b
	}
	var m struct {
		Cases []string
		Rules map[string]struct{ Section, Says string }
	}
	if err := json.Unmarshal(read("trust-bad/cases.json"), &m); err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, n := range m.Cases {
		if n == name {
			count++
		}
	}
	if count != 1 || m.Rules[name].Section != "9.1" || m.Rules[name].Says != "The `witness` directive is matched on **its own `<name>`**" {
		t.Fatal("swapped-name case or rule missing")
	}
	raw := read("trust-bad/" + name + ".cbor")
	v, e := cbor.Decode(raw)
	if e != nil {
		t.Fatal(e)
	}
	doc := v.(map[string]any)
	array := map[string]string{}
	for _, v := range doc["witnesses"].([]any) {
		w := v.(map[string]any)
		array[w["name"].(string)] = w["key"].(string)
	}
	named := map[string]string{}
	for _, l := range strings.Split(doc["policy"].(string), "\n") {
		p := strings.Fields(l)
		if len(p) >= 3 && p[0] == "witness" {
			named[p[1]] = p[2]
		}
	}
	if len(array) != 3 || len(named) != 3 || named["pi"] != array["vps"] || named["vps"] != array["pi"] || named["friend"] != array["friend"] {
		t.Fatal("expected the same names and keys with pi/vps swapped")
	}
	tr, e := Parse(raw)
	if e == nil {
		e = tr.Validate()
	}
	if e == nil {
		t.Fatal("swapped directive names accepted")
	}
	text := doc["policy"].(string)
	text = strings.Replace(text, "witness vps ", "witness TEMP ", 1)
	text = strings.Replace(text, "witness pi ", "witness vps ", 1)
	doc["policy"] = strings.Replace(text, "witness TEMP ", "witness pi ", 1)
	repair, e := cbor.Encode(doc)
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(repair, read("trust.cbor")) {
		t.Fatal("repair changed more than the swap")
	}
	tr, e = Parse(repair)
	if e == nil {
		e = tr.Validate()
	}
	if e != nil {
		t.Fatal(e)
	}
	t.Log("swap-only repair accepted and equals trust.cbor")
	// Keep the earlier key-only story beside the association fault: repairing
	// pi's array key alone still recovers the ordinary accepted anchor.
	old, err := cbor.Decode(read("trust-bad/42-witness-key-mismatch.cbor"))
	if err != nil {
		t.Fatal(err)
	}
	prior := old.(map[string]any)
	bad := prior["witnesses"].([]any)[0].(map[string]any)
	honest, err := cbor.Decode(read("trust.cbor"))
	if err != nil {
		t.Fatal(err)
	}
	good := honest.(map[string]any)["witnesses"].([]any)[0].(map[string]any)
	if bad["name"] != good["name"] || bad["key"] == good["key"] {
		t.Fatal("42 must change only the key")
	}
	bad["key"] = good["key"]
	fixed, err := cbor.Encode(prior)
	if err != nil || !bytes.Equal(fixed, read("trust.cbor")) {
		t.Fatal("42 key-only repair changed another member", err)
	}
	tr, err = Parse(fixed)
	if err == nil {
		err = tr.Validate()
	}
	if err != nil {
		t.Fatal(err)
	}

}
