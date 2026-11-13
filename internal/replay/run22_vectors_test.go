package replay

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/onembyte/norn/internal/cbor"
	"github.com/onembyte/norn/internal/enrollreq"
	"github.com/onembyte/norn/internal/entry"
)

type run22Rule struct{ Section, Says string }

func run22Read(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func run22Decode(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	v, err := cbor.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	return v.(map[string]any)
}

func run22Encode(t *testing.T, v any) []byte {
	t.Helper()
	b, err := cbor.Encode(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Use raw maps here because the typed decoder correctly refuses boolean prev.
// Authenticating the hostile bytes keeps that refusal separate from quorum.
func run22Authenticate(t *testing.T, env map[string]any, role string, holders ...string) {
	t.Helper()
	sigs := env["sigs"].([]any)
	delete(env, "sigs")
	defer func() { env["sigs"] = sigs }()
	message := append([]byte(entry.PreimagePrefix), run22Encode(t, env)...)
	want := map[string][]byte{}
	for _, n := range holders {
		want[entry.Kid(publicOf(t, n))] = publicOf(t, n)
	}
	if len(sigs) != len(want) {
		t.Fatal("wrong fixture quorum")
	}
	for _, s := range sigs {
		sig := s.(map[string]any)
		pk, ok := want[sig["kid"].(string)]
		if !ok || sig["role"] != role || !ed25519.Verify(pk, message, sig["sig"].([]byte)) {
			t.Fatal("hostile signature is not genuine in its declared role")
		}
		delete(want, sig["kid"].(string))
	}
}

func run22Sign(t *testing.T, env map[string]any, role string, holders ...string) []byte {
	t.Helper()
	delete(env, "sigs")
	message := append([]byte(entry.PreimagePrefix), run22Encode(t, env)...)
	sigs := []any{}
	for _, n := range holders {
		sigs = append(sigs, map[string]any{"kid": entry.Kid(publicOf(t, n)), "role": role,
			"sig": ed25519.Sign(privateKey(t, n), message)})
	}
	sort.Slice(sigs, func(i, j int) bool {
		return sigs[i].(map[string]any)["kid"].(string) < sigs[j].(map[string]any)["kid"].(string)
	})
	env["sigs"] = sigs
	return run22Encode(t, env)
}

func TestTheRunTwentyTwoReplayStoriesHaveTheirSignedRepairs(t *testing.T) {
	for _, story := range []struct {
		name  string
		names []string
		rule  run22Rule
	}{
		{"policy-names-differ-in-case", []string{"00-genesis", "01-policy-pi-PI"}, run22Rule{"9.1", "Nothing here is case-folded"}},
		{"signer-add-prev-bool", []string{"00-genesis", "01-signer-add-prev-false", "02-signer-add-prev-zero"}, run22Rule{"5.1", "`ts`, `after` and `prev` uint"}},
		{"enroll-empty-device-id", []string{"00-genesis", "01-enroll-empty-device-id", "02-enroll-sundial"}, run22Rule{"2", "UTF-8 string, 1–64 bytes"}},
	} {
		t.Run(story.name, func(t *testing.T) {
			dir := filepath.Join(vectorRoot(), "log-run22", story.name)
			anchor, raw, m := loadCase(t, dir)
			var meta struct {
				Codes map[string]string
				Rules map[string]run22Rule
			}
			if err := json.Unmarshal(run22Read(t, filepath.Join(dir, "manifest.json")), &meta); err != nil {
				t.Fatal(err)
			}
			if len(raw) != len(story.names) || len(meta.Codes) != len(raw)-1 || len(meta.Rules) != len(raw) {
				t.Fatal("wrong story cardinality")
			}
			baseAnchor, fixture, _ := loadCase(t, filepath.Join(vectorRoot(), "log"))
			if !bytes.Equal(raw[0], fixture[0]) || !bytes.Equal(anchor.GenesisHash, entry.LeafHash(raw[0])) || !bytes.Equal(anchor.Net, baseAnchor.Net) || anchor.LogKey != baseAnchor.LogKey || anchor.Policy != baseAnchor.Policy {
				t.Fatal("wrong genesis or pin")
			}
			if meta.Rules["00-genesis"] != (run22Rule{"5.1", "Otherwise the state is initialised from the body"}) {
				t.Fatal("missing initialization rule")
			}
			final := Replay(anchor, raw)
			got, err := final.MarshalCanonical()
			if err != nil || !bytes.Equal(got, run22Read(t, filepath.Join(dir, "state.json"))) {
				t.Fatal("canonical state differs", err)
			}
			if int(final.Size) != len(raw) || len(final.Rejected) != len(raw)-2 {
				t.Fatal("wrong final size or refusals")
			}
			for i, n := range story.names {
				want := ""
				if i == 1 && len(raw) == 3 {
					want = ReasonDecode
				}
				if m.Entries[i].Index != i || m.Entries[i].Name != n || m.Entries[i].Reason != want || lastOutcome(final, i) != want {
					t.Fatal("manifest outcome differs", n)
				}
				if i == 0 {
					continue
				}
				code := want
				if code == "" {
					code = "accept"
				}
				if meta.Codes[n] != code || meta.Rules[n] != story.rule {
					t.Fatal("missing code or rule", n)
				}
				if want != "" && string(run22Read(t, filepath.Join(dir, n+".reason"))) != want+"\n" {
					t.Fatal("wrong reason bytes")
				}
			}
			env := run22Decode(t, raw[1])
			role, holders := "root", []string{"root1", "root2", "root3"}
			if story.name == "enroll-empty-device-id" {
				role, holders = "signer", []string{"signer1", "signer2"}
			}
			run22Authenticate(t, env, role, holders...)
			if len(raw) == 2 {
				text := string(run22Read(t, filepath.Join(vectorRoot(), "policies", "names-differ-in-case.txt")))
				if env["prev"] != uint64(0) || env["body"].(map[string]any)["text"] != text || final.Policy != text || final.Versions["policy"] != 1 {
					t.Fatal("case-distinct policy was not applied verbatim")
				}
				env["body"].(map[string]any)["text"] = strings.ReplaceAll(text, "PI", "upper")
				fixed := run22Sign(t, env, role, holders...)
				repaired := Replay(anchor, [][]byte{raw[0], fixed})
				if len(repaired.Rejected) != 0 || repaired.Policy != env["body"].(map[string]any)["text"] {
					t.Fatal("short-name-only repair refused")
				}
				t.Log("short-name-only repair accepted with renewed root signatures")
				return
			}
			before, refused := Replay(anchor, raw[:1]), Replay(anchor, raw[:2])
			if lastOutcome(refused, 1) != ReasonDecode {
				t.Fatal("hostile field was not decode")
			}
			refused.Size, refused.Rejected = before.Size, before.Rejected
			a, _ := before.MarshalCanonical()
			b, _ := refused.MarshalCanonical()
			if !bytes.Equal(a, b) {
				t.Fatal("refusal changed state")
			}
			if story.name == "signer-add-prev-bool" {
				if env["prev"] != false || !reflect.DeepEqual(env["body"], map[string]any{"pk": publicOf(t, "signer3")}) {
					t.Fatal("wrong prev or incoming signer")
				}
				env["prev"] = uint64(0)
				if len(final.Signers) != 3 || final.Versions["signers"] != 2 {
					t.Fatal("repair did not add signer3")
				}
			} else {
				req := run22Decode(t, env["body"].(map[string]any)["request"].([]byte))
				sig := req["sig"].([]byte)
				delete(req, "sig")
				if req["device_id"] != "" || !bytes.Equal(req["device_pk"].([]byte), publicOf(t, "sundial")) || !ed25519.Verify(publicOf(t, "sundial"), append([]byte(enrollreq.PreimagePrefix), run22Encode(t, req)...), sig) {
					t.Fatal("empty-ID request is not genuine")
				}
				req["device_id"] = "sundial"
				req["sig"] = ed25519.Sign(privateKey(t, "sundial"), append([]byte(enrollreq.PreimagePrefix), run22Encode(t, req)...))
				env["body"].(map[string]any)["request"] = run22Encode(t, req)
				if final.Devices["sundial"].Status != "active" || final.Devices["sundial"].Version != 2 {
					t.Fatal("repair did not enroll sundial")
				}
			}
			fixed := run22Sign(t, env, role, holders...)
			if !bytes.Equal(fixed, raw[2]) {
				t.Fatal("repair changed more than its field and signatures")
			}
			for _, prefix := range [][][]byte{raw[:1], raw[:2]} {
				if got := lastOutcome(Replay(anchor, append(append([][]byte{}, prefix...), fixed)), len(prefix)); got != "" {
					t.Fatal("repair refused", got)
				}
			}
			t.Log("field-only repair accepted at both prefixes")
		})
	}
}
