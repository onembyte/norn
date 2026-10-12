package note

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
)

// A stranger's name is framing, even when no trusted key could match it.
func TestSplitRefusesMalformedStrangerNames(t *testing.T) {
	for _, name := range []string{"", "a\tb", "a\u00a0b", "a+b", "a\x00b"} {
		t.Run(fmt.Sprintf("%q", name), func(t *testing.T) {
			signed := "hello\n\n" + SignatureLine(name, make([]byte, 68)) + "\n"
			// Tab is refused by both the whole-note control rule and the
			// name property, so test the name rule independently as well.
			if name != "a\x00b" && validSignatureName(name) {
				t.Error("the malformed name passes the signature-name rule")
			}
			if _, _, err := Split(signed); !errors.Is(err, ErrNote) {
				t.Errorf("malformed stranger name framed: %v", err)
			}
			repaired := strings.Replace(signed, SigPrefix+name+" ", SigPrefix+"stranger ", 1)
			if _, _, err := Split(repaired); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSplitRefusesControlBytesAnywhereInTheNote(t *testing.T) {
	for c := byte(0); c < 0x20; c++ {
		if c == '\n' {
			continue
		}
		for _, place := range []string{"text", "name", "payload"} {
			t.Run(fmt.Sprintf("%s/U+%04X", place, c), func(t *testing.T) {
				text, name, blob := "hello", "stranger", strings.TrimPrefix(SignatureLine("stranger", make([]byte, 68)), SigPrefix+"stranger ")
				switch place {
				case "text":
					text += string(c)
				case "name":
					name += string(c)
				case "payload":
					blob = blob[:4] + string(c) + blob[4:]
				}
				if _, _, err := Split(text + "\n\n" + SigPrefix + name + " " + blob + "\n"); !errors.Is(err, ErrNote) {
					t.Errorf("control byte framed: %v", err)
				}
			})
		}
	}
}

func TestSignatureNameWhitespaceIsTheWrittenSet(t *testing.T) {
	if !validSignatureName("a\x1cb") || !validSignatureName("a\u180eb") {
		t.Error("U+001C and U+180E are outside the written name property")
	}

	spaces := []rune{'\u0009', '\u000a', '\u000b', '\u000c', '\u000d', '\u0020', '\u0085', '\u00a0', '\u1680', '\u2000', '\u2001', '\u2002', '\u2003', '\u2004', '\u2005', '\u2006', '\u2007', '\u2008', '\u2009', '\u200a', '\u2028', '\u2029', '\u202f', '\u205f', '\u3000'}
	for _, c := range spaces {
		t.Run(fmt.Sprintf("U+%04X", c), func(t *testing.T) {
			if _, _, err := Split("hello\n\n" + SignatureLine("a"+string(c)+"b", make([]byte, 68)) + "\n"); err == nil {
				t.Error("white-space name framed")
			}
		})
	}
	for _, name := range []string{"witness.example/zürich", "a\u180eb", "a\u200bb", "a\u007fb"} {
		if _, _, err := Split("hello\n\n" + SignatureLine(name, make([]byte, 68)) + "\n"); err != nil {
			t.Fatalf("valid name %q refused: %v", name, err)
		}
	}
	// Go's current Unicode table agrees with the written property; provenance
	// still matters because the protocol cannot change with the runtime table.
	raw, err := os.ReadFile("note.go")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "unicode.IsSpace(") {
		t.Error("the signature-name rule consults a runtime Unicode table")
	}
}
