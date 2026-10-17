package docclaims

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// NetBird 0.81 (2026-10-15) added a certificate posture check, and a reader
// who knows it will ask whether the comparison's NetBird column is stale. It
// is not: the management server issues and judges the challenge, so a
// compromised one is not bound by it. The README, PRIOR-ART.md §5 and the
// review packet each say so, with NetBird's own sources, so the column cannot
// look like it ignored the feature (row 6.5n-nb).
func TestTheNetBirdColumnNotesItsCertificatePostureCheck(t *testing.T) {
	read := func(name string) string {
		raw, err := os.ReadFile(filepath.Join(root(t), name))
		if err != nil {
			t.Fatal(err)
		}
		return strings.Join(strings.Fields(string(raw)), " ")
	}
	const release = "https://github.com/netbirdio/netbird/releases/tag/v0.81.0"
	const docs = "https://docs.netbird.io/manage/access-control/posture-checks/device-certificates"
	readme := read("README.md")
	_, comparison, _ := strings.Cut(readme, "## How Norn compares")
	comparison, _, _ = strings.Cut(comparison, " ## ")
	priorArt := read("PRIOR-ART.md")
	_, section5, _ := strings.Cut(priorArt, "## 5. Mesh VPNs")
	section5, _, _ = strings.Cut(section5, " ## ")
	packet := read("REVIEW-COMPARISON.md")
	_, row1, _ := strings.Cut(packet, "## Can the control plane add a device you never approved?")
	row1, _, _ = strings.Cut(row1, " ## ")
	for _, c := range []struct{ where, body string }{
		{"README.md's comparison", comparison},
		{"PRIOR-ART.md §5", section5},
		{"REVIEW-COMPARISON.md's first row", row1},
	} {
		for _, want := range []string{
			"NetBird 0.81",
			"certificate posture check",
			"The management server issues and judges that challenge",
			"does not tie the certificate to a user or a hostname",
			release,
		} {
			if !strings.Contains(c.body, want) {
				t.Errorf("%s does not say %q", c.where, want)
			}
		}
	}
	if !strings.Contains(section5, docs) || !strings.Contains(row1, docs) {
		t.Error("PRIOR-ART.md §5 and the review packet must cite NetBird's posture-check documentation")
	}
}
