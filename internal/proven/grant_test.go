package proven

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// D-073. In WireGuard a peer's allowed-ips is its authority to source those
// addresses, and nothing proved them: the key came from the log and the
// routes from an untrusted provider. The enrollment's `ip` label is now the
// grant -- parsed as a whole, masked, sorted -- and `proven/cases.json`
// carries every active device's, so a second implementation computes the
// same bound a node will enforce (§4.0, §13.1).
func TestEveryActiveDeviceHasItsGrantInTheFixture(t *testing.T) {
	result, _ := verified(t)
	raw, err := os.ReadFile(filepath.Join(vectorRoot(), "proven", "cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Grants map[string][]string `json:"grants"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Grants) == 0 {
		t.Fatal("proven/cases.json carries no grants: the §4.0 grant is unvectored")
	}
	for _, id := range Devices(result.State, EvaluationTime(result)) {
		want, ok := doc.Grants[id]
		if !ok {
			t.Errorf("%s is active and has no grant entry", id)
			continue
		}
		if got := Grant(result.State.Devices[id].Labels); strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("%s: grant = %v, the fixture says %v", id, got, want)
		}
	}
	// The two that separate the readings: host addresses on wider prefixes
	// are masked and sorted, and a label with one unparseable prefix is no
	// grant rather than the prefixes that did parse.
	if g := doc.Grants["router"]; strings.Join(g, ",") != "10.9.1.0/24,fd00::/64" {
		t.Errorf("router's grant is %v; a grant is masked and sorted as text", g)
	}
	if g, ok := doc.Grants["badgrant"]; !ok || len(g) != 0 {
		t.Errorf("badgrant's grant is %v; a label that does not parse as a whole is no grant", g)
	}
}
