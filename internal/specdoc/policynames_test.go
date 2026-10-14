package specdoc

import (
	"strings"
	"testing"
)

// D-078 (2), cold gate run 15's M1: §9.1's restated grammar said a name is
// defined once and never which bytes it may hold. Keep the rule where a
// reader learns the grammar, and in the trust file's `witnesses` row.
func TestD078APolicyNameHasAGrammar(t *testing.T) {
	doc := load(t)
	s, ok := doc.Section("9.1")
	if !ok {
		t.Fatal("§9.1 is missing")
	}
	body := strings.Join(strings.Fields(s.Body), " ")
	for _, want := range []string{
		"A witness or group name follows §7's key-name grammar — one or more bytes `0x21`–`0x7E`, `+` excluded — and is at most 64 bytes, in every policy: a trust file's and a `policy` entry's alike (D-078)",
		"**a witness `name` is 1–64 bytes** of the policy grammar's name rule below, and unique within the file",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("§9.1 lacks %q", want)
		}
	}
}
