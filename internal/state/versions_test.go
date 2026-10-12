package state

import (
	"bytes"
	"testing"
)

func TestVersionsAndDeviceVersionHaveTheirCanonicalFormAndCloneIndependently(t *testing.T) {
	s := New(make([]byte, 16))
	s.Devices["a"] = Device{Version: 7, Labels: map[string]string{}}
	raw, err := s.MarshalCanonical()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"versions":{"log_key":0,"params":0,"policy":0,"roots":0,"signers":0}`, `"version":7`} {
		if !bytes.Contains(raw, []byte(want)) {
			t.Errorf("canonical state lacks %s", want)
		}
	}
	if len(s.Versions) != 5 {
		t.Fatalf("zero state has %d versions, want five", len(s.Versions))
	}
	s.Versions["signers"] = 6
	clone := s.Clone()
	if clone.Versions["signers"] != 6 {
		t.Fatal("clone did not copy versions")
	}
	clone.Versions["signers"] = 8
	if s.Versions["signers"] != 6 {
		t.Error("clone aliases versions")
	}
	parsed, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	again, _ := parsed.MarshalCanonical()
	if !bytes.Equal(raw, again) {
		t.Error("versions fail to round trip")
	}
}
