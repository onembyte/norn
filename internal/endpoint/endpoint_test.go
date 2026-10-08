package endpoint

import (
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/onembyte/norn/internal/peertable"
)

func device(t *testing.T, id string, b byte, labels map[string]string) Device {
	t.Helper()
	var key peertable.Key
	for i := range key {
		key[i] = b
	}
	return Device{ID: id, Key: key, Labels: labels}
}

// The property the whole package exists for: a provider cannot add a peer.
// Not "is checked and rejected" -- cannot express one, because Hints has no
// key field and Desired walks the proven set, never the provider's.
func TestAProviderCannotAddAPeer(t *testing.T) {
	proven := []Device{device(t, "pi-cam", 1, nil)}
	provider := Static{Peers: map[string]Hints{
		"pi-cam":   {AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.9.0.1/32")}},
		"ghost":    {AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.9.0.9/32")}},
		"attacker": {AllowedIPs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}},
	}}

	peers, report := Desired(proven, provider)
	if len(peers) != 1 || peers[0].Key != proven[0].Key {
		t.Fatalf("peers = %+v, want only the proven device", peers)
	}
	if len(report.Unproven) != 2 {
		t.Errorf("unproven = %v, want the two the log does not prove", report.Unproven)
	}
	// And they are named, because a control plane quietly trying to add peers
	// is exactly the event worth seeing.
	if strings.Join(report.Unproven, ",") != "attacker,ghost" {
		t.Errorf("unproven = %v", report.Unproven)
	}
}

func TestStaticDecoratesAProvenDevice(t *testing.T) {
	proven := []Device{device(t, "nas", 2, nil)}
	provider := Static{Peers: map[string]Hints{"nas": {
		AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.9.0.2/32")},
		Endpoint:   netip.MustParseAddrPort("192.0.2.2:51820"),
		Keepalive:  25 * time.Second,
	}}}

	peers, report := Desired(proven, provider)
	if len(peers) != 1 {
		t.Fatalf("peers = %+v", peers)
	}
	if peers[0].Endpoint.String() != "192.0.2.2:51820" || peers[0].Keepalive != 25*time.Second {
		t.Errorf("hints were not applied: %+v", peers[0])
	}
	if !report.Empty() {
		t.Errorf("report = %+v, want nothing to say", report)
	}
}

// A proven device nobody configured is still proven. Dropping it would be
// enforcement removing a peer the log vouches for.
func TestAProvenDeviceWithNoHintsIsStillInstalled(t *testing.T) {
	proven := []Device{device(t, "unconfigured", 3, nil)}

	peers, report := Desired(proven, None{})
	if len(peers) != 1 || peers[0].Key != proven[0].Key {
		t.Fatalf("a proven device was dropped: %+v", peers)
	}
	if len(peers[0].AllowedIPs) != 0 {
		t.Errorf("routes appeared from nowhere: %+v", peers[0])
	}
	if len(report.Unrouted) != 1 || report.Unrouted[0] != "unconfigured" {
		t.Errorf("unrouted = %v; a device with no routes must be reported", report.Unrouted)
	}
}

func TestLabelsReadIPAndIgnoreAllowedIPs(t *testing.T) {
	for _, label := range []string{"ip", "allowed_ips"} {
		t.Run(label, func(t *testing.T) {
			labels := &Labels{}
			hints, found := labels.Hints(device(t, "laptop", 5, map[string]string{
				label: "10.9.0.5/32,fd00::5/128",
			}))
			if label == "allowed_ips" {
				if found || len(hints.AllowedIPs) != 0 {
					t.Errorf("allowed_ips label produced hints: %+v, found = %v", hints, found)
				}
				return
			}
			want := []netip.Prefix{
				netip.MustParsePrefix("10.9.0.5/32"),
				netip.MustParsePrefix("fd00::5/128"),
			}
			if !found || len(hints.AllowedIPs) != len(want) {
				t.Fatalf("ip label allowed-ips = %v, found = %v; want %v", hints.AllowedIPs, found, want)
			}
			for i, prefix := range want {
				if hints.AllowedIPs[i] != prefix {
					t.Errorf("allowed-ips[%d] = %v, want %v", i, hints.AllowedIPs[i], prefix)
				}
			}
		})
	}
}

func TestLabelsCarryHints(t *testing.T) {
	proven := []Device{device(t, "laptop", 4, map[string]string{
		LabelIP:        "10.9.0.4/32, fd00::4/128",
		LabelEndpoint:  "198.51.100.4:51820",
		LabelKeepalive: "25",
	})}

	labels := &Labels{}
	peers, report := Desired(proven, labels)
	if len(peers[0].AllowedIPs) != 2 {
		t.Errorf("allowed-ips = %+v", peers[0].AllowedIPs)
	}
	if peers[0].Endpoint.String() != "198.51.100.4:51820" {
		t.Errorf("endpoint = %v", peers[0].Endpoint)
	}
	if peers[0].Keepalive != 25*time.Second {
		t.Errorf("keepalive = %v", peers[0].Keepalive)
	}
	if !report.Empty() {
		t.Errorf("report = %+v", report)
	}
	if len(labels.Malformed) != 0 {
		t.Errorf("malformed = %v", labels.Malformed)
	}
}

// A typo in a signed label must not evict a peer the log proves.
func TestAMalformedLabelIsReportedNotFatal(t *testing.T) {
	proven := []Device{device(t, "typo", 5, map[string]string{
		LabelIP:        "10.9.0.5/32",
		LabelEndpoint:  "not-an-endpoint",
		LabelKeepalive: "soon",
	})}

	labels := &Labels{}
	peers, _ := Desired(proven, labels)
	if len(peers) != 1 {
		t.Fatalf("the device was dropped over a typo: %+v", peers)
	}
	if len(peers[0].AllowedIPs) != 1 {
		t.Errorf("the routes that did parse were lost: %+v", peers[0])
	}
	if peers[0].Endpoint.IsValid() {
		t.Error("a malformed endpoint was used anyway")
	}
	if len(labels.Malformed) != 2 {
		t.Errorf("malformed = %v, want the endpoint and the keepalive", labels.Malformed)
	}
}

// Labels travel with the device, so this provider can never speak about a
// device the log has not proven.
func TestLabelsKnowsNothingItWasNotGiven(t *testing.T) {
	if len((&Labels{}).Knows()) != 0 {
		t.Error("the labels provider claimed to know devices of its own")
	}
}

func TestFirstPrefersTheEarlierProvider(t *testing.T) {
	proven := []Device{
		device(t, "pinned", 6, map[string]string{LabelIP: "10.9.0.66/32"}),
		device(t, "by-label", 7, map[string]string{LabelIP: "10.9.0.7/32"}),
	}
	static := Static{Peers: map[string]Hints{"pinned": {
		AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.9.0.6/32")}}}}

	peers, _ := Desired(proven, First{static, &Labels{}})
	byKey := peertable.ByKey(peers)
	if got := byKey[proven[0].Key].AllowedIPs[0].String(); got != "10.9.0.6/32" {
		t.Errorf("the pinned device took its label instead of the config: %s", got)
	}
	if got := byKey[proven[1].Key].AllowedIPs[0].String(); got != "10.9.0.7/32" {
		t.Errorf("the unpinned device did not fall through to its label: %s", got)
	}
}

func TestFirstReportsEveryProviderSUnprovenOpinions(t *testing.T) {
	proven := []Device{device(t, "real", 8, nil)}
	a := Static{Peers: map[string]Hints{"ghost-a": {}}}
	b := Static{Peers: map[string]Hints{"ghost-b": {}, "ghost-a": {}}}

	_, report := Desired(proven, First{a, b})
	if strings.Join(report.Unproven, ",") != "ghost-a,ghost-b" {
		t.Errorf("unproven = %v, want each named once", report.Unproven)
	}
}

func TestParsePrefixes(t *testing.T) {
	got, err := ParsePrefixes(" 10.9.0.1/32 ,fd00::1/128 ")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %+v", got)
	}
	for _, bad := range []string{"", "10.9.0.1", "not a cidr", "10.9.0.0/33"} {
		if _, err := ParsePrefixes(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

// Desired returns peers in a stable order: the reconciler compares them, and
// an operator reads them.
func TestDesiredIsOrdered(t *testing.T) {
	proven := []Device{device(t, "c", 3, nil), device(t, "a", 1, nil), device(t, "b", 2, nil)}
	peers, _ := Desired(proven, None{})
	for i := 1; i < len(peers); i++ {
		if peers[i-1].Key.String() > peers[i].Key.String() {
			t.Fatal("Desired did not order its peers")
		}
	}
}

func TestLoadFile(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/hints.json"
	if err := os.WriteFile(path, []byte(`{"peers":{
		"pi-cam":{"allowed_ips":["10.9.0.1/32"],"endpoint":"192.0.2.1:51820","keepalive":25},
		"nas":{"allowed_ips":["10.9.0.2/32","fd00::2/128"]}}}`), 0o644); err != nil {
		t.Fatal(err)
	}

	provider, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	proven := []Device{device(t, "pi-cam", 1, nil), device(t, "nas", 2, nil)}
	peers, report := Desired(proven, provider)
	if len(peers) != 2 {
		t.Fatalf("peers = %+v", peers)
	}
	if !report.Empty() {
		t.Errorf("report = %+v", report)
	}
	byKey := peertable.ByKey(peers)
	if got := byKey[proven[0].Key]; got.Endpoint.String() != "192.0.2.1:51820" ||
		got.Keepalive != 25*time.Second {
		t.Errorf("pi-cam = %+v", got)
	}
	if got := byKey[proven[1].Key]; len(got.AllowedIPs) != 2 {
		t.Errorf("nas = %+v", got)
	}
}

// A file written by another daemon is untrusted input like any other.
func TestLoadFileRejections(t *testing.T) {
	dir := t.TempDir()
	cases := map[string]string{
		"not json":           `not json`,
		"unknown field":      `{"peers":{"a":{"public_key":"AAAA"}}}`,
		"bad cidr":           `{"peers":{"a":{"allowed_ips":["10.9.0.1"]}}}`,
		"bad endpoint":       `{"peers":{"a":{"endpoint":"nowhere"}}}`,
		"negative keepalive": `{"peers":{"a":{"keepalive":-1}}}`,
	}
	for why, body := range cases {
		t.Run(why, func(t *testing.T) {
			path := dir + "/" + strings.ReplaceAll(why, " ", "-") + ".json"
			if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadFile(path); err == nil {
				t.Errorf("accepted a hints file that is %s", why)
			}
		})
	}
	if _, err := LoadFile(dir + "/absent.json"); err == nil {
		t.Error("accepted a hints file that is not there")
	}
}

// The escape hatch must not become a way in: a hints file naming a device the
// log does not prove adds nothing.
func TestAHintsFileCannotAddAPeerEither(t *testing.T) {
	path := t.TempDir() + "/hints.json"
	if err := os.WriteFile(path, []byte(
		`{"peers":{"intruder":{"allowed_ips":["0.0.0.0/0"]}}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	provider, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	peers, report := Desired([]Device{device(t, "real", 1, nil)}, provider)
	if len(peers) != 1 || peers[0].Key != device(t, "real", 1, nil).Key {
		t.Fatalf("peers = %+v", peers)
	}
	if len(report.Unproven) != 1 || report.Unproven[0] != "intruder" {
		t.Errorf("unproven = %v", report.Unproven)
	}
}

// SEC-035 (row 035-ii). Two proven devices whose allowed-ips overlap is a
// provider fault, not a routing choice: WireGuard sends a packet to the peer
// with the most specific prefix, so the wider device silently loses the
// narrower one's addresses -- or, for equal prefixes, whichever was written
// last wins. Neither device gets the overlapping prefix; both stay in the
// desired set, because the log proves them; and the report says so.
func TestDesiredRefusesOverlappingAllowedIPsAmongProvenDevices(t *testing.T) {
	devices := []Device{device(t, "subnet", 1, nil), device(t, "host", 2, nil)}
	provider := Static{Peers: map[string]Hints{
		"subnet": {AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.9.0.0/24")}},
		"host":   {AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.9.0.2/32")}},
	}}
	peers, report := Desired(devices, provider)
	if len(peers) != 2 {
		t.Fatal("proven identities must remain in the desired set")
	}
	for _, peer := range peers {
		if len(peer.AllowedIPs) != 0 {
			t.Errorf("overlapping routes were installed for a proven device: %v", peer.AllowedIPs)
		}
	}
	if len(report.Overlapping) != 1 {
		t.Fatalf("overlaps reported = %v, want one naming both devices", report.Overlapping)
	}
	for _, want := range []string{"subnet", "10.9.0.0/24", "host", "10.9.0.2/32"} {
		if !strings.Contains(report.Overlapping[0], want) {
			t.Errorf("the overlap report should name %q: %q", want, report.Overlapping[0])
		}
	}
	if report.Empty() {
		t.Error("a report carrying an overlap is not empty")
	}
}

// Only the overlapping prefix is withheld. A device's other routes are its
// own, and disjoint devices are untouched.
func TestOnlyTheOverlappingPrefixIsWithheld(t *testing.T) {
	devices := []Device{device(t, "a", 1, nil), device(t, "b", 2, nil), device(t, "c", 3, nil)}
	provider := Static{Peers: map[string]Hints{
		"a": {AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.9.0.1/32"), netip.MustParsePrefix("10.8.0.0/24")}},
		"b": {AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.9.0.1/32")}},
		"c": {AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.7.0.1/32")}},
	}}
	peers, report := Desired(devices, provider)
	routes := map[byte][]netip.Prefix{}
	for _, peer := range peers {
		routes[peer.Key[0]] = peer.AllowedIPs
	}
	if len(routes[1]) != 1 || routes[1][0] != netip.MustParsePrefix("10.8.0.0/24") {
		t.Errorf("a kept %v; want only its non-overlapping 10.8.0.0/24", routes[1])
	}
	if len(routes[2]) != 0 {
		t.Errorf("b kept the overlapping %v", routes[2])
	}
	if len(routes[3]) != 1 {
		t.Errorf("c, which overlaps nobody, lost its route: %v", routes[3])
	}
	if len(report.Overlapping) != 1 {
		t.Errorf("overlaps reported = %v, want the one equal pair", report.Overlapping)
	}
}
