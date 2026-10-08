package replay

import (
	"bytes"
	"encoding/hex"

	"github.com/onembyte/norn/internal/entry"
	"github.com/onembyte/norn/internal/state"
)

// applyGenesis runs the entry-0 procedure of §5.1. Any failure aborts replay:
// a log whose entry 0 is unusable has nothing to verify later entries against,
// so the caller discards the state and records a single bad-genesis rejection.
//
// Genesis signatures are counted against the roots and threshold in its OWN
// body -- there is no earlier state to resolve them against. That bootstrap is
// the one place where signature checking cannot consult existing state.
func (r *replayer) applyGenesis(st *state.State, raw []byte) error {
	r.remember(raw)

	env, err := entry.Decode(raw)
	if err != nil {
		return err
	}
	if env.T != "genesis" || !bytes.Equal(env.Net, r.anchor.Net) {
		return rejectWith(ReasonBadGenesis)
	}
	if !bytes.Equal(entry.LeafHash(raw), r.anchor.GenesisHash) {
		return rejectWith(ReasonBadGenesis)
	}
	if env.After != nil && *env.After != 0 {
		return rejectWith(ReasonBadGenesis)
	}
	if err := checkBody("genesis", env.Body); err != nil {
		return rejectWith(ReasonBadGenesis)
	}

	name, ok := env.Body["name"].(string)
	if !ok || len(name) < 1 || len(name) > maxName {
		return rejectWith(ReasonBadGenesis)
	}
	roots, err := keyList(env.Body, "roots")
	if err != nil {
		return err
	}
	signers, err := keyList(env.Body, "signers")
	if err != nil {
		return err
	}
	rootThr, ok := env.Body["root_thr"].(uint64)
	if !ok || rootThr < 1 || rootThr > uint64(len(roots)) {
		return rejectWith(ReasonBadGenesis)
	}
	signerThr, ok := env.Body["signer_thr"].(uint64)
	if !ok || signerThr < 1 || signerThr > uint64(len(signers)) {
		return rejectWith(ReasonBadGenesis)
	}
	for kid := range roots {
		if _, clash := signers[kid]; clash {
			return rejectWith(ReasonBadGenesis) // a key may hold only one role
		}
	}

	// Bootstrap: count root signatures against the body's own root set.
	valid := map[string]bool{}
	for _, sig := range env.Sigs {
		if sig.Role != "root" || valid[sig.Kid] {
			continue
		}
		encoded, present := roots[sig.Kid]
		if !present {
			continue
		}
		public, err := hex.DecodeString(encoded)
		if err != nil {
			continue
		}
		if r.signatureValid(env, sig, public) {
			valid[sig.Kid] = true
		}
	}
	if uint64(len(valid)) < rootThr {
		return rejectWith(ReasonBadGenesis)
	}

	st.Name = name
	st.Roots = roots
	st.Signers = signers
	st.RootThr = rootThr
	st.SignerThr = signerThr
	if raw, present := env.Body["params"]; present {
		params, ok := raw.(map[string]any)
		if !ok || len(params) == 0 {
			return rejectWith(ReasonBadGenesis)
		}
		for key, value := range params {
			// Typed, like a `params` entry. Only the *keys* were checked here,
			// so a bool `staleness` reached the state and every freshness
			// decision silently fell back to the §4.5 default -- and the two
			// paths into `params` disagreed (cold gate run 8, D20).
			if _, known := state.DefaultParams()[key]; !known {
				return rejectWith(ReasonBadGenesis)
			}
			typed, ok := checkParam(key, value)
			if !ok {
				return rejectWith(ReasonBadGenesis)
			}
			st.Params[key] = typed
		}
	}
	return nil
}

// keyList reads a genesis key array, rejecting duplicates and wrong lengths.
func keyList(body map[string]any, field string) (map[string]string, error) {
	raw, ok := body[field].([]any)
	if !ok || len(raw) == 0 {
		return nil, rejectWith(ReasonBadGenesis)
	}
	out := make(map[string]string, len(raw))
	for _, item := range raw {
		public, ok := item.([]byte)
		if !ok || len(public) != entry.KeyLen {
			return nil, rejectWith(ReasonBadGenesis)
		}
		kid := entry.Kid(public)
		if _, dup := out[kid]; dup {
			return nil, rejectWith(ReasonBadGenesis)
		}
		out[kid] = hex.EncodeToString(public)
	}
	return out, nil
}
