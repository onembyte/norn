package specdoc

import (
	"strings"
	"testing"
)

// D-077 (3) and (6): every entry that changes state is a compare-and-swap on
// the object it changes, and the log's keys and the witnesses' keys stay
// disjoint. Keep the deciding sentences where a reader learns each rule, and
// keep the sentence they replace out.
func TestD077BindsEveryStateChangeToItsPredecessorAndKeepsLogAndWitnessKeysApart(t *testing.T) {
	doc := load(t)
	for _, tc := range []struct{ section, want, stale string }{
		{"4.1", "\"prev\": <uint>,                 # OPTIONAL — version of the object this entry changes (§4.4)", ""},
		{"4.1", "correct `t, v, ts, net, body, prev, sigs, after`", "correct `t, v, ts, net, body, sigs, after`"},
		{"4.0", "`after` and `prev` are the only optional keys (§4.4)", "only `after` is optional"},
		{"4.4", "Every entry that changes state is an authenticated compare-and-swap on the **object** it changes", ""},
		{"4.4", "replay refuses the entry as `stale-state` (§5.1, §5.2) unless `prev` is exactly the object's current version", ""},
		{"4.4", "a signature binds the transition's target and nothing about its source", ""},
		{"5", "| `log_key` | text | `norn.trust.log_key` |", ""},
		{"5.1", "5. `after`, if present, MUST be 0, and `prev` MUST be absent → else **abort** (`bad-genesis`).", "5. `after`, if present, MUST be 0 → else **abort** (`bad-genesis`)."},
		{"5.1", "`prev` is the record's `version` (`stale-state`) · new `wg_pk` not active **for another device** (`dup-wg`)", "new `wg_pk` not active **for another device** (`dup-wg`) · if the body carries `device_pk`, a valid `device` signature by **that** key as well (`no-device-sig`) |"},
		{"5.1", "Every accepted entry that changes state sets the version of the object it changed to its own index", ""},
		{"5.2", "| `stale-state` | `prev` is not the current version of the object the entry changes (§4.4)", ""},
		{"5.2", "a key entering a role whose set must stay disjoint from another", "| `dup-key` | `signer_add`/`root_add` of a `pk` whose `kid` already exists in either role |"},
		{"5.2", "one valid signature for each *distinct* key among the two", "is by construction not in the state before the entry"},
		{"5.3", "| `version` | uint | index of the last accepted entry naming this `device_id`", ""},
		{"5.3", "| `versions` | map of five uints: `signers`, `roots`, `params`, `policy`, `log_key` |", ""},
		{"9.1", "active log keys and active witness keys are disjoint at every state", ""},
	} {
		t.Run(tc.section+"/"+tc.want, func(t *testing.T) {
			section, ok := doc.Section(tc.section)
			if !ok {
				t.Fatalf("§%s is missing", tc.section)
			}
			body := strings.Join(strings.Fields(section.Body), " ")
			if !strings.Contains(body, strings.Join(strings.Fields(tc.want), " ")) {
				t.Errorf("§%s lacks D-077 passage %q", tc.section, tc.want)
			}
			if tc.stale != "" && strings.Contains(body, strings.Join(strings.Fields(tc.stale), " ")) {
				t.Errorf("§%s retains replaced passage %q", tc.section, tc.stale)
			}
		})
	}
}
