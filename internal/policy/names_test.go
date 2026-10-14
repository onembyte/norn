package policy_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/onembyte/norn/internal/note"
	. "github.com/onembyte/norn/internal/policy"
)

// D-078 (2), cold gate run 15's M1. A witness or group name follows §7's
// key-name grammar -- one or more bytes 0x21-0x7E, '+' excluded -- and is at
// most 64 bytes, in every policy. The grammar never said, both implementations
// took `zürich`, and a reader applying the key-name sentence refused it: a
// refused `policy` entry leaves two readers with different quorums.
func TestAPolicyNameFollowsTheKeyNameGrammar(t *testing.T) {
	key := testVKey("norn-witness/pi", note.AlgCosignature)
	witness := func(name string) string { return fmt.Sprintf("witness %s %s\nquorum %s\n", name, key, name) }
	group := func(name string) string {
		return fmt.Sprintf("witness member %s\ngroup %s 1 member\nquorum %s\n", key, name, name)
	}
	for _, name := range []string{"pi", "a", "norn-witness/pi", "!~", strings.Repeat("a", 64)} {
		for kind, text := range map[string]string{"witness": witness(name), "group": group(name)} {
			if _, err := Parse(text); err != nil {
				t.Errorf("a %s named %q is refused: %v", kind, name, err)
			}
		}
	}
	for _, name := range []string{"zürich", "a+b", strings.Repeat("a", 65), "pi "} {
		for kind, text := range map[string]string{"witness": witness(name), "group": group(name)} {
			if _, err := Parse(text); err == nil {
				t.Errorf("a %s named %q is accepted", kind, name)
			}
		}
	}
}
