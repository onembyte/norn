package entry

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// Everything so far re-encodes entries that were DECODED from the suite, which
// exercises the encoder only along a path the decoder already vouched for. This
// builds entries from their semantic values instead -- the fields, the keys,
// the signatures -- and requires the bytes to match the shipped vector.
//
// That is the cross-implementation check that matters: two implementations
// given the same inputs must produce the same bytes, not merely agree about
// bytes one of them was handed.

type mirrorDoc struct {
	Entry map[string]any `json:"entry"`
}

func TestEntriesRebuiltFromTheirValuesMatchTheShippedBytes(t *testing.T) {
	keys := loadKeys(t)
	seeds := map[string]ed25519.PrivateKey{}
	for _, k := range keys.Ed25519 {
		seed, err := hex.DecodeString(k.Seed)
		if err != nil {
			t.Fatal(err)
		}
		seeds[k.Kid] = ed25519.NewKeyFromSeed(seed)
	}

	matches, err := filepath.Glob(filepath.Join(vectorRoot(), "entries", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 16 {
		t.Fatalf("expected 16 mirrors, found %d", len(matches))
	}

	for _, mirrorPath := range matches {
		raw, err := os.ReadFile(mirrorPath)
		if err != nil {
			t.Fatal(err)
		}
		var doc mirrorDoc
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		want, err := os.ReadFile(mirrorPath[:len(mirrorPath)-len(".json")] + ".cbor")
		if err != nil {
			t.Fatal(err)
		}

		env, signers, err := rebuild(doc.Entry)
		if err != nil {
			t.Errorf("%s: %v", filepath.Base(mirrorPath), err)
			continue
		}
		// Sign in kid order, exactly as an independent signer would, rather
		// than copying the signature bytes out of the vector.
		sort.Strings(signers)
		for _, spec := range signers {
			kid, role := spec[:16], spec[17:]
			key, ok := seeds[kid]
			if !ok {
				t.Errorf("%s: no seed for kid %s", filepath.Base(mirrorPath), kid)
				continue
			}
			if err := Sign(env, key, role); err != nil {
				t.Errorf("%s: %v", filepath.Base(mirrorPath), err)
			}
		}
		got, err := Encode(env)
		if err != nil {
			t.Errorf("%s: %v", filepath.Base(mirrorPath), err)
			continue
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s: rebuilt entry differs from the shipped bytes\n got %x\nwant %x",
				filepath.Base(mirrorPath), got, want)
		}
	}
}

// rebuild turns a mirror's canonical-JSON view back into an Envelope, and
// returns the "kid:role" specs of the signatures to recreate.
func rebuild(m map[string]any) (*Envelope, []string, error) {
	env := &Envelope{V: Version}
	t, _ := m["t"].(string)
	env.T = t
	netHex, _ := m["net"].(string)
	net, err := hex.DecodeString(netHex)
	if err != nil {
		return nil, nil, err
	}
	env.Net = net
	ts, ok := m["ts"].(float64)
	if !ok {
		return nil, nil, errMissing("ts")
	}
	env.TS = uint64(ts)
	if after, present := m["after"].(float64); present {
		v := uint64(after)
		env.After = &v
	}
	body, ok := m["body"].(map[string]any)
	if !ok {
		return nil, nil, errMissing("body")
	}
	converted, err := convertBody(env.T, body)
	if err != nil {
		return nil, nil, err
	}
	env.Body = converted

	var specs []string
	sigs, _ := m["sigs"].([]any)
	for _, item := range sigs {
		sm, ok := item.(map[string]any)
		if !ok {
			return nil, nil, errMissing("sigs entry")
		}
		kid, _ := sm["kid"].(string)
		role, _ := sm["role"].(string)
		specs = append(specs, kid+":"+role)
	}
	return env, specs, nil
}

type missingField string

func (m missingField) Error() string { return "missing or malformed field: " + string(m) }

func errMissing(field string) error { return missingField(field) }

// byteFields names the body fields that are byte strings, so a hex string in
// the mirror becomes bytes again rather than staying text.
var byteFields = map[string]bool{
	"device_pk": true, "wg_pk": true, "pk": true, "net": true,
}

func convertBody(entryType string, body map[string]any) (map[string]any, error) {
	out := make(map[string]any, len(body))
	for key, value := range body {
		switch v := value.(type) {
		case string:
			if byteFields[key] {
				decoded, err := hex.DecodeString(v)
				if err != nil {
					return nil, err
				}
				out[key] = decoded
				continue
			}
			out[key] = v
		case float64:
			out[key] = uint64(v)
		case bool:
			out[key] = v
		case []any:
			list := make([]any, 0, len(v))
			for _, item := range v {
				text, ok := item.(string)
				if !ok {
					return nil, errMissing(key)
				}
				decoded, err := hex.DecodeString(text)
				if err != nil {
					return nil, err
				}
				list = append(list, decoded)
			}
			out[key] = list
		case map[string]any:
			nested, err := convertBody(entryType, v)
			if err != nil {
				return nil, err
			}
			out[key] = nested
		default:
			return nil, errMissing(key)
		}
	}
	return out, nil
}
