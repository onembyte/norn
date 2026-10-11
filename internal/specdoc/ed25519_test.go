package specdoc

import (
	"strings"
	"testing"
)

// D-072 (c). RFC 8032 permits two verification equations and says nothing a
// verifier must do about non-canonical encodings or small-order points, so
// two libraries can disagree about one signature -- and a transparency log is
// two verifiers agreeing about the state. §3 now names one predicate,
// NORN-ED25519-v1, under which every library gives the same answer. The Go
// code, the reference and the vectors are built to these sentences, and the
// CCTV outcome table (023r-b) cites them.
func TestKeysDefineOneEd25519Predicate(t *testing.T) {
	doc := load(t)
	keys, ok := doc.Section("3")
	if !ok {
		t.Fatal("§3 is missing")
	}
	if !strings.Contains(strings.Join(strings.Fields(keys.Body), " "), "verified under §3.1's NORN-ED25519-v1") {
		t.Error("§3 does not send every signature to §3.1's predicate")
	}
	predicate, ok := doc.Section("3.1")
	if !ok {
		t.Fatal("§3.1 is missing")
	}
	text := strings.Join(strings.Fields(predicate.Body), " ")
	for _, phrase := range []string{
		"the canonical encoding (RFC 8032 §5.1.3) of a point of order exactly `L`",
		"not the identity and has no component of order 2, 4 or 8",
		"`S`, read as a little-endian integer, MUST be less than `L`",
		"[S]B = R + [k]A",
		"the cofactored and the cofactorless equations agree",
		"PureEdDSA",
		"wherever a key is admitted",
		"refused as `decode`",
		"rejects every vector in the C2SP CCTV Ed25519 set that carries a flag",
		"accepts the one vector that carries none (number 305)",
		"`low_order_component_A` and `low_order_component_R`",
		"MUST NOT accept what this predicate refuses, whatever its library accepts",
	} {
		if !strings.Contains(text, phrase) {
			t.Errorf("§3 does not define NORN-ED25519-v1: missing %q", phrase)
		}
	}
}

// D-075 names the two remaining admission points and their body-step reason.
func TestEveryKeyEnteringVerifierStateIsAdmittedAsAValidPoint(t *testing.T) {
	doc := load(t)
	for section, phrases := range map[string][]string{
		"3.1": {"One rule throughout: every key that enters a verifier's state is a valid point where it enters (D-075)."},
		"5.1": {"body well-formed and closed, its `device_pk` when present a valid point (§3.1) (`decode`)", "`text` MUST parse as `c2sp.org/tlog-policy`, every verifier key it carries a valid point (§3.1) (`decode`)"},
	} {
		part, ok := doc.Section(section)
		if !ok {
			t.Fatalf("missing §%s", section)
		}
		text := strings.Join(strings.Fields(part.Body), " ")
		for _, phrase := range phrases {
			if !strings.Contains(text, phrase) {
				t.Errorf("§%s missing %q", section, phrase)
			}
		}
	}
}
