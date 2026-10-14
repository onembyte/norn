package specdoc

import (
	"strings"
	"testing"
)

// D-078 (4) and cold gate run 15's L7 and L8. §16.1 said a consumer verifies
// a request's structure and signature before showing it, and nothing about
// its network. §5.1 named `log/101` as the step-6-before-step-7 vector, and it
// is a `note`: a reader swapping the two steps for governance entries only
// passed it, and `log-order/08` holds the governance pair.
func TestD078ARequestForAnotherNetworkIsRefusedAndL8IsCited(t *testing.T) {
	doc := load(t)
	for _, tc := range []struct{ section, want string }{
		{"16.1", "A consumer MUST also refuse a request whose `net` is not the network it serves, before showing it (D-078)"},
		{"5.1", "`log/101-bad-precedence-after-before-threshold` (step 6 before step 7, for a `note`; `log-order/08-signer-add-after-before-threshold` holds the same pair for a governance entry)"},
	} {
		s, ok := doc.Section(tc.section)
		if !ok {
			t.Fatalf("§%s is missing", tc.section)
		}
		if !strings.Contains(strings.Join(strings.Fields(s.Body), " "), tc.want) {
			t.Errorf("§%s lacks %q", tc.section, tc.want)
		}
	}
}
