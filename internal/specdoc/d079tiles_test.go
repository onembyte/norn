package specdoc

import (
	"strings"
	"testing"
)

// D-079 (3), row 6.5l-xiv-g. A log may delete a partial tile once the full
// one exists, so a verifier that cannot fetch the partial path may use the
// first W hashes or entries of the full one; `unserved` only when neither is
// served. Stated in §6 where the paths are, and in §10.1 where the code is.
func TestTheFullTileFallbackIsStated(t *testing.T) {
	doc := load(t)
	norm := func(s string) string { return strings.Join(strings.Fields(s), " ") }
	for _, c := range []struct{ name, section, want string }{
		{"§6 lets a verifier use the full tile", "6",
			"a verifier that cannot fetch `tile/<L>/<N>.p/<W>` MAY fetch `tile/<L>/<N>` and use its first `W` hashes, and likewise the full entry bundle for a missing `tile/entries/<N>.p/<W>`"},
		{"§6 still compares what it uses", "6",
			"what it uses is compared with the tree it rebuilt exactly as the partial path would have been"},
		{"§10.1 says unserved means neither path", "10.1",
			"`unserved` only when neither the partial path nor the full one is served (D-079)"},
	} {
		t.Run(c.name, func(t *testing.T) {
			s, ok := doc.Section(c.section)
			if !ok {
				t.Fatalf("§%s is missing", c.section)
			}
			if !strings.Contains(norm(s.Body), norm(c.want)) {
				t.Errorf("§%s is missing %q", c.section, c.want)
			}
		})
	}
}
