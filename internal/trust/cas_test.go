package trust

import (
	"testing"

	"github.com/onembyte/norn/internal/note"
)

func TestAWitnessCannotHoldTheLogPublicKeyEvenWithoutAPolicyLogLine(t *testing.T) {
	good := loadGood(t)
	log, err := note.ParseVerifierKey(good.LogKey)
	if err != nil {
		t.Fatal(err)
	}
	bad := *good
	key := note.CosignerVerifierKey("other-name", log.Public)
	bad.Witnesses = []Witness{{Name: "w", Key: key}}
	bad.Policy = "witness w " + key + "\nquorum w\n"
	if err := bad.Validate(); err == nil {
		t.Fatal("log acting as its own witness accepted")
	}
	key = good.Witnesses[0].Key
	bad.Witnesses[0].Key = key
	bad.Policy = "witness w " + key + "\nquorum w\n"
	if err := bad.Validate(); err != nil {
		t.Fatal(err)
	}
}
