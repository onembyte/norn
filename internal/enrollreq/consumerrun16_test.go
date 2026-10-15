package enrollreq

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRequestConsumersPinTheirNetworkWithASoundTwin(t *testing.T) {
	root := filepath.Join(vectorRoot(), "heads-run16")
	for _, name := range []string{"request-this-network", "request-other-network"} {
		t.Run(name, func(t *testing.T) {
			read := func(path string) []byte {
				t.Helper()
				raw, err := os.ReadFile(filepath.Join(root, path))
				if err != nil {
					t.Fatal(err)
				}
				return raw
			}
			var m struct {
				Requests struct {
					ConsumerNet string `json:"consumer_net"`
					Cases       []struct {
						Name, File, Says string
						Accept           bool
					}
				}
			}
			if err := json.Unmarshal(read("cases.json"), &m); err != nil {
				t.Fatal(err)
			}
			net, err := hex.DecodeString(m.Requests.ConsumerNet)
			if err != nil || !bytes.Equal(net, shippedNet(t)) {
				t.Fatal("manifest must carry the consumer's network")
			}
			if len(m.Requests.Cases) != 2 {
				t.Fatal("manifest must list both request cases")
			}
			found := false
			for _, c := range m.Requests.Cases {
				if c.Name != name {
					continue
				}
				if found {
					t.Fatal("duplicate request case")
				}
				found = true
				r, err := Decode(read(c.File))
				if err != nil {
					t.Fatal(err)
				}
				if err := Check(r, nil); err != nil {
					t.Fatal("request must verify without a consumer network", err)
				}
				want := name == "request-this-network"
				if c.Accept != want || c.Says == "" {
					t.Fatal("manifest must state the fixed semantic answer")
				}
				err = Check(r, net)
				if want && err != nil {
					t.Fatal(err)
				}
				if !want && (err == nil || !strings.Contains(err.Error(), "another network")) {
					t.Fatalf("Go answers %v, SPEC states refusal for another network", err)
				}
				if err := Check(r, r.Net); err != nil {
					t.Fatal("the request's own consumer must accept", err)
				}
			}
			if !found {
				t.Fatal("missing " + name)
			}
		})
	}
}
