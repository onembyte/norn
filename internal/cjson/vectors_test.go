package cjson

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Cold-model gate run 5, defect G13. §14.1 says object keys sort "bytewise
// over the UTF-8 encoding". No object key in the suite was outside the basic
// multilingual plane, so UTF-16 code-unit order -- what a JavaScript
// implementation gets for free -- agreed with UTF-8 order on every file, and
// `NORN_JSON_UTF16SORT` passed 597/597.
//
// The two orders disagree only across U+E000: an astral character encodes in
// UTF-16 as a surrogate pair beginning 0xD800, which sorts *below* U+E000,
// while in UTF-8 it begins 0xF0 and sorts *above* U+E000's 0xEE. One key of
// each is enough to tell the two apart, and the suite now carries both.

func TestTheSuiteDistinguishesUTF8OrderFromUTF16(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "vectors", "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)

	const astral = "\U0001F512" // U+1F512, UTF-8 f0 9f 94 92, UTF-16 d83d dd12
	const privateUse = ""      // UTF-8 ee 80 80, UTF-16 e000

	iAstral := strings.Index(text, astral)
	iPrivate := strings.Index(text, privateUse)
	if iAstral < 0 || iPrivate < 0 {
		t.Fatal("state.json carries no key pair that separates UTF-8 bytewise order " +
			"from UTF-16 code-unit order, so a verifier sorting either way passes")
	}
	// UTF-8 bytewise: 0xEE < 0xF0, so the private-use key comes first.
	// UTF-16: 0xD83D < 0xE000, so the astral key would come first instead.
	if iPrivate > iAstral {
		t.Error("the astral key is serialised first, which is UTF-16 code-unit order; " +
			"§14.1 requires bytewise order over the UTF-8 encoding")
	}
}
