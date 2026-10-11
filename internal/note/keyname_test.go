package note

import (
	"crypto/ed25519"
	"strings"
	"testing"
)

// D-074 (f). A key name is one or more ASCII bytes from 0x21 to 0x7E, '+'
// excluded, and the key id is lowercase hex. It was a whitespace predicate,
// and the Unicode tables behind Go's unicode.IsSpace and Python's
// str.isspace disagree -- Python counts U+001C to U+001F as space, Go does
// not -- so one trust file loaded in one implementation and not the other.
// A grammar has no tables to disagree about.
func TestAKeyNameIsASCIIByGrammarAndTheIDIsLowercase(t *testing.T) {
	public := ed25519.NewKeyFromSeed(make([]byte, 32)).Public().(ed25519.PublicKey)
	for _, name := range []string{"pi", "norn-witness/pi", "norn/nzxxe3rnorsxg5domv2c2mbqge", "!~"} {
		if _, err := ParseVerifierKey(VerifierKey(name, public)); err != nil {
			t.Errorf("%q is ASCII 0x21-0x7E and was refused: %v", name, err)
		}
	}
	for _, name := range []string{
		"a\x1cb",     // the separator Python calls space and Go does not
		"a b",        // no-break space
		"a b",        // em space
		"café",       // a letter outside ASCII
		"a\tb",       // a control character
		"a\x7fb",     // DEL
		"tab\u0085x", // next line
	} {
		if _, err := ParseVerifierKey(VerifierKey(name, public)); err == nil {
			t.Errorf("%q is outside the ASCII key-name grammar and was accepted", name)
		}
	}
	vkey := VerifierKey("pi", public)
	parts := strings.SplitN(vkey, "+", 3)
	if strings.ToUpper(parts[1]) == parts[1] {
		t.Fatal("this key's id has no letter, so its case cannot be tested")
	}
	upper := parts[0] + "+" + strings.ToUpper(parts[1]) + "+" + parts[2]
	if _, err := ParseVerifierKey(upper); err == nil {
		t.Error("a key id in uppercase hex was accepted; §7 says lowercase")
	}
}
