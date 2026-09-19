package entry

import "github.com/onembyte/norn/internal/cbor"

// envelopeKeys is the closed schema of §4.1: exactly these, and `after` alone
// is optional.
var (
	envelopeKeys  = map[string]bool{"v": true, "t": true, "net": true, "ts": true, "after": true, "body": true, "sigs": true}
	requiredKeys  = []string{"v", "t", "net", "ts", "body", "sigs"}
	signatureKeys = map[string]bool{"kid": true, "role": true, "sig": true}
)

// Decode parses one entry. It enforces the envelope schema but not the per-type
// body rules, which belong to replay: an entry can be well-formed and still
// take no effect.
func Decode(raw []byte) (*Envelope, error) {
	value, err := cbor.Decode(raw)
	if err != nil {
		return nil, err
	}
	m, ok := value.(map[string]any)
	if !ok {
		return nil, schemaErrorf("entry must be a map")
	}
	for key := range m {
		if !envelopeKeys[key] {
			return nil, schemaErrorf("unknown envelope key %q", key)
		}
	}
	for _, key := range requiredKeys {
		if _, ok := m[key]; !ok {
			return nil, schemaErrorf("missing envelope key %q", key)
		}
	}

	env := &Envelope{}
	if env.V, ok = m["v"].(uint64); !ok || env.V != Version {
		return nil, schemaErrorf("v must be %d", Version)
	}
	if env.T, ok = m["t"].(string); !ok {
		return nil, schemaErrorf("t must be a text string")
	}
	if env.Net, ok = m["net"].([]byte); !ok || len(env.Net) != NetLen {
		return nil, schemaErrorf("net must be %d bytes", NetLen)
	}
	if env.TS, ok = m["ts"].(uint64); !ok {
		return nil, schemaErrorf("ts must be an unsigned integer")
	}
	if raw, present := m["after"]; present {
		after, ok := raw.(uint64)
		if !ok {
			return nil, schemaErrorf("after must be an unsigned integer")
		}
		env.After = &after
	}
	if env.Body, ok = m["body"].(map[string]any); !ok {
		return nil, schemaErrorf("body must be a map")
	}

	list, ok := m["sigs"].([]any)
	if !ok {
		return nil, schemaErrorf("sigs must be an array")
	}
	var previous string
	for _, item := range list {
		sm, ok := item.(map[string]any)
		if !ok {
			return nil, schemaErrorf("each signature must be a map")
		}
		for key := range sm {
			if !signatureKeys[key] {
				return nil, schemaErrorf("unknown signature key %q", key)
			}
		}
		if len(sm) != len(signatureKeys) {
			return nil, schemaErrorf("a signature needs exactly kid, role and sig")
		}
		sig := Signature{}
		if sig.Kid, ok = sm["kid"].(string); !ok || !validKid(sig.Kid) {
			return nil, schemaErrorf("kid must be 16 lowercase hex characters")
		}
		if sig.Role, ok = sm["role"].(string); !ok || !Roles[sig.Role] {
			return nil, schemaErrorf("role must be root, signer or device")
		}
		if sig.Sig, ok = sm["sig"].([]byte); !ok || len(sig.Sig) != SigLen {
			return nil, schemaErrorf("sig must be %d bytes", SigLen)
		}
		// CBOR canonicalises map keys, not array order, so sigs ordering is a
		// schema rule checked here rather than by the codec (D-048).
		if previous != "" && sig.Kid <= previous {
			return nil, schemaErrorf("sigs must be sorted by kid with no repeats")
		}
		previous = sig.Kid
		env.Sigs = append(env.Sigs, sig)
	}
	return env, nil
}

func validKid(s string) bool {
	if len(s) != 16 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
