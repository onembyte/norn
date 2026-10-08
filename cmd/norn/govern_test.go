package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/onembyte/norn/internal/entry"
	"github.com/onembyte/norn/internal/policy"
	"github.com/onembyte/norn/internal/replay"
	"github.com/onembyte/norn/internal/sshwire"
	"github.com/onembyte/norn/internal/state"
)

var governanceTypes = []string{"signer_add", "signer_remove", "signer_thr", "root_add", "root_remove", "root_thr", "log_key", "policy", "params", "note"}

func governArgs(key, typ string) []string {
	return []string{"govern", "-trust", filepath.Join(vectors(), "trust.cbor"), "-log", filepath.Join(vectors(), "served"), "-t", typ, "-key", key}
}

func runGovern(t *testing.T, bin, input string, args ...string) (string, string, error) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Stdin = strings.NewReader(input)
	var out, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &stderr
	err := cmd.Run()
	return out.String(), stderr.String(), err
}

func governanceEntry(t *testing.T, raw []byte) *entry.Envelope {
	t.Helper()
	env, err := entry.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func governanceFile(t *testing.T, raw []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "entry.cbor")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func governancePublic(t *testing.T, name string) string {
	t.Helper()
	return hex.EncodeToString(fixtureKey(t, name).Public().(ed25519.PublicKey))
}

// Each partial is replayed separately: appending an undersigned partial and
// then its completion would intentionally hit D-070's duplicate-content rule.
func governanceQuorum(t *testing.T, bin, typ string, flags ...string) []byte {
	t.Helper()
	dir := t.TempDir()
	var raw []byte
	var preimage []byte
	st := rotationState(t)
	if st.RootThr != 3 || len(st.Roots) != 3 {
		t.Fatal("fixture must have three roots and root_thr 3")
	}
	for i, name := range []string{"root1", "root2", "root3"} {
		args := governArgs(signerKeyFile(t, dir, name), typ)
		if i == 0 {
			args = append(args, flags...)
		} else {
			path := governanceFile(t, raw)
			if i == 1 {
				args = append(args, "-in", path)
			} else {
				args = append(args, path)
			}
		}
		stdout, stderr, err := runGovern(t, bin, "yes\n", args...)
		if err != nil {
			t.Fatalf("root %d: %v\n%s", i+1, err, stderr)
		}
		if !strings.Contains(stderr, "Sign this entry?") {
			t.Fatal("root approval did not prompt")
		}
		raw = []byte(stdout)
		env := governanceEntry(t, raw)
		got, err := entry.Preimage(env)
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			preimage = got
		} else if !bytes.Equal(preimage, got) {
			t.Fatal("extension changed the preimage")
		}
		if len(env.Sigs) != i+1 {
			t.Fatal("extension lost a signature")
		}
		entries, anchor := fixtureLog(t)
		if env.After == nil || *env.After != uint64(len(entries)) {
			t.Fatal("missing observed ordering guard")
		}
		result := replay.Replay(anchor, append(entries, raw))
		last := result.Rejected[len(result.Rejected)-1]
		if i < 2 && typ != "note" {
			if last.Index != uint64(len(entries)) || last.Reason != replay.ReasonThreshold {
				t.Fatalf("partial should fail threshold: %+v", last)
			}
		} else if last.Index == uint64(len(entries)) {
			t.Fatalf("completed entry rejected: %+v", last)
		}
	}
	return raw
}

func TestGovernSignerAddIsAcceptedOnlyWithTheRootQuorum(t *testing.T) {
	raw := governanceQuorum(t, nornBinary(t), "signer_add", "-pk-hex", governancePublic(t, "stranger"))
	entries, anchor := fixtureLog(t)
	st := replay.Replay(anchor, append(entries, raw))
	if st.Signers[kidOf(t, "stranger")] != governancePublic(t, "stranger") {
		t.Fatal("new signer missing")
	}
}

func TestGovernBodiesReplayWithTheirSpecifiedEffects(t *testing.T) {
	bin := nornBinary(t)
	anchor, err := loadAnchor(filepath.Join(vectors(), "trust.cbor"))
	if err != nil {
		t.Fatal(err)
	}
	policyFile := filepath.Join(t.TempDir(), "policy.txt")
	if err := os.WriteFile(policyFile, []byte(anchor.Policy), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		typ   string
		flags []string
		check func(*testing.T, *state.State)
	}{
		{"signer_thr", []string{"-thr", "1"}, func(t *testing.T, s *state.State) {
			if s.SignerThr != 1 {
				t.Fatal("threshold unchanged")
			}
		}},
		{"root_thr", []string{"-thr", "2"}, func(t *testing.T, s *state.State) {
			if s.RootThr != 2 {
				t.Fatal("threshold unchanged")
			}
		}},
		{"root_add", []string{"-pk-hex", governancePublic(t, "stranger")}, func(t *testing.T, s *state.State) {
			if s.Roots[kidOf(t, "stranger")] == "" {
				t.Fatal("root missing")
			}
		}},
		{"signer_remove", []string{"-kid", kidOf(t, "signer1")}, func(t *testing.T, s *state.State) {
			if s.Signers[kidOf(t, "signer1")] != "" {
				t.Fatal("signer remains")
			}
		}},
		{"log_key", []string{"-pk-hex", governancePublic(t, "stranger"), "-overlap", "2592000"}, func(t *testing.T, s *state.State) {
			last := s.LogKeys[len(s.LogKeys)-1]
			if last.Pk != governancePublic(t, "stranger") || last.Overlap != 2592000 {
				t.Fatalf("wrong log key: %+v", last)
			}
		}},
		{"params", []string{"-set", "staleness=900", "-set", "rotate_needs_signer=false"}, func(t *testing.T, s *state.State) {
			raw, err := s.MarshalCanonical()
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := state.Parse(raw)
			if err != nil {
				t.Fatal(err)
			}
			if parsed.Params["staleness"] != uint64(900) || parsed.Params["rotate_needs_signer"] != false {
				t.Fatalf("wrong params in state.json: %s", raw)
			}
		}},
		{"policy", []string{"-policy", policyFile}, func(t *testing.T, s *state.State) {
			if s.Policy != anchor.Policy {
				t.Fatal("policy was not retained verbatim")
			}
		}},
		{"note", []string{"-text", "approved\nmaintenance"}, func(t *testing.T, s *state.State) {
			before := rotationState(t)
			before.Size = s.Size
			want, _ := before.MarshalCanonical()
			got, _ := s.MarshalCanonical()
			if !bytes.Equal(want, got) {
				t.Fatal("note changed state")
			}
		}},
	}
	for _, c := range cases {
		t.Run(c.typ, func(t *testing.T) {
			raw := governanceQuorum(t, bin, c.typ, c.flags...)
			entries, anchor := fixtureLog(t)
			c.check(t, replay.Replay(anchor, append(entries, raw)))
		})
	}
}

func TestGovernRefusalsPrecedeConfirmation(t *testing.T) {
	bin, dir := nornBinary(t), t.TempDir()
	root, stranger := signerKeyFile(t, dir, "root1"), signerKeyFile(t, dir, "stranger")
	badPolicy := filepath.Join(dir, "bad-policy")
	if err := os.WriteFile(badPolicy, []byte("this is not a policy\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, typ string
		flags     []string
		says      string
	}{
		{"not a root", "note", []string{"-text", "hello", "-key", stranger}, "not a root"},
		{"root invariant", "root_remove", []string{"-kid", kidOf(t, "root1")}, "root-invariant"},
		{"signer threshold zero", "signer_thr", []string{"-thr", "0"}, "bad-thr"},
		{"signer threshold high", "signer_thr", []string{"-thr", "3"}, "bad-thr"},
		{"root threshold zero", "root_thr", []string{"-thr", "0"}, "bad-thr"},
		{"root threshold high", "root_thr", []string{"-thr", "4"}, "bad-thr"},
		{"duplicate root", "signer_add", []string{"-pk-hex", governancePublic(t, "root1")}, "dup-key"},
		{"duplicate signer", "root_add", []string{"-pk-hex", governancePublic(t, "signer1")}, "dup-key"},
		{"unknown root", "root_remove", []string{"-kid", kidOf(t, "stranger")}, "unknown-key"},
		{"unknown signer", "signer_remove", []string{"-kid", kidOf(t, "root1")}, "unknown-key"},
		{"unparseable policy", "policy", []string{"-policy", badPolicy}, "policy"},
		{"bool for uint", "params", []string{"-set", "mmd=true"}, "uint"},
		{"uint for bool", "params", []string{"-set", "rotate_needs_signer=1"}, "bool"},
		{"unknown param", "params", []string{"-set", "witness_policy=none"}, "unknown"},
		{"empty params", "params", nil, "non-empty"},
		{"missing threshold", "signer_thr", nil, "thr"},
		{"missing overlap", "log_key", []string{"-pk-hex", governancePublic(t, "stranger")}, "overlap"},
		{"long note", "note", []string{"-text", strings.Repeat("é", 2049)}, "4096"},
		{"wrong flag", "note", []string{"-text", "hello", "-thr", "1"}, "-thr"},
		{"wrong role", "note", []string{"-text", "hello", "-role", "signer"}, "root"},
		{"unknown type", "enroll", nil, "type"},
		{"unreadable log", "note", []string{"-text", "hello", "-log", filepath.Join(dir, "missing")}, "-after N"},
		{"unreadable with after", "note", []string{"-text", "hello", "-log", filepath.Join(dir, "missing"), "-after", "90"}, "log is unreadable"},
		{"unreadable without guard", "note", []string{"-text", "hello", "-log", filepath.Join(dir, "missing"), "-no-after"}, "log is unreadable"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, stderr, err := runGovern(t, bin, "yes\n", append(governArgs(root, c.typ), c.flags...)...)
			if err == nil || out != "" || !strings.Contains(stderr, c.says) || strings.Contains(stderr, "Sign this entry?") || strings.Contains(stderr, "SIGN A NEW") {
				t.Fatalf("want %q before summary and confirmation: %v\n%s", c.says, err, stderr)
			}
		})
	}
}

func TestGovernRefusesYesBeforeReadingAnything(t *testing.T) {
	bin := nornBinary(t)
	for _, typ := range governanceTypes {
		t.Run(typ, func(t *testing.T) {
			out, stderr, err := run(t, bin, "govern", "-t", typ, "-yes", "-trust", "missing", "-key", "missing", "-in", "-")
			if err == nil || out != "" || !strings.Contains(stderr, "never exercised by a script") || strings.Contains(stderr, "Sign this entry?") {
				t.Fatalf("scripted root not refused first: %v\n%s", err, stderr)
			}
		})
	}
}

func TestGovernRefusesTamperedSignaturesBeforeConfirmation(t *testing.T) {
	bin, dir := nornBinary(t), t.TempDir()
	root := signerKeyFile(t, dir, "root1")
	raw, stderr, err := runGovern(t, bin, "yes\n", append(governArgs(root, "note"), "-text", "original")...)
	if err != nil {
		t.Fatalf("%v\n%s", err, stderr)
	}
	for _, damage := range []string{"body", "own signature", "other signature", "non-root", "wrong role"} {
		t.Run(damage, func(t *testing.T) {
			env := governanceEntry(t, []byte(raw))
			says := "does not verify"
			switch damage {
			case "body":
				env.Body["text"] = "tampered"
			case "own signature":
				env.Sigs[0].Sig[0] ^= 1
			case "other signature":
				if err := entry.Sign(env, fixtureKey(t, "root2"), "root"); err != nil {
					t.Fatal(err)
				}
				for i := range env.Sigs {
					if env.Sigs[i].Kid == kidOf(t, "root2") {
						env.Sigs[i].Sig[0] ^= 1
					}
				}
			case "non-root", "wrong role":
				name, role := "stranger", "root"
				says = "not a root"
				if damage == "wrong role" {
					name, role, says = "root2", "signer", "role"
				}
				if err := entry.Sign(env, fixtureKey(t, name), role); err != nil {
					t.Fatal(err)
				}
			}
			changed, err := entry.Encode(env)
			if err != nil {
				t.Fatal(err)
			}
			out, stderr, err := runGovern(t, bin, "yes\n", append(governArgs(root, "note"), "-in", governanceFile(t, changed))...)
			if err == nil || out != "" || !strings.Contains(stderr, says) || strings.Contains(stderr, "Sign this entry?") {
				t.Fatalf("tamper not refused before confirmation: %v\n%s", err, stderr)
			}
		})
	}
}

func TestGovernExtensionFlagsMustAgreeWithTheSignedBody(t *testing.T) {
	bin, dir := nornBinary(t), t.TempDir()
	root := signerKeyFile(t, dir, "root1")
	anchor, err := loadAnchor(filepath.Join(vectors(), "trust.cbor"))
	if err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(dir, "policy")
	if err := os.WriteFile(policyPath, []byte(anchor.Policy), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		typ               string
		initial, mismatch []string
	}{
		{"signer_add", []string{"-pk-hex", governancePublic(t, "stranger")}, []string{"-pk-hex", governancePublic(t, "nas")}},
		{"signer_remove", []string{"-kid", kidOf(t, "signer1")}, []string{"-kid", kidOf(t, "signer3")}},
		{"root_thr", []string{"-thr", "2"}, []string{"-thr", "3"}},
		{"log_key", []string{"-pk-hex", governancePublic(t, "stranger"), "-overlap", "60"}, []string{"-overlap", "0"}},
		{"params", []string{"-set", "mmd=90", "-set", "staleness=900"}, []string{"-set", "mmd=60"}},
		{"note", []string{"-text", "original"}, []string{"-text", ""}},
		{"policy", []string{"-policy", policyPath}, []string{"-policy", governanceFile(t, []byte("quorum none\n"))}},
	}
	for _, c := range cases {
		t.Run(c.typ, func(t *testing.T) {
			raw, stderr, err := runGovern(t, bin, "yes\n", append(governArgs(root, c.typ), c.initial...)...)
			if err != nil {
				t.Fatalf("%v\n%s", err, stderr)
			}
			path := governanceFile(t, []byte(raw))
			args := append(governArgs(root, c.typ), "-in", path)
			out, stderr, err := runGovern(t, bin, "yes\n", append(args, c.mismatch...)...)
			if err == nil || out != "" || !strings.Contains(stderr, "does not match") || strings.Contains(stderr, "Sign this entry?") {
				t.Fatalf("mismatch not refused: %v\n%s", err, stderr)
			}
			out, stderr, err = runGovern(t, bin, "yes\n", append(args, c.initial...)...)
			if err != nil {
				t.Fatalf("matching flags refused: %v\n%s", err, stderr)
			}
			before, _ := entry.Preimage(governanceEntry(t, []byte(raw)))
			after, _ := entry.Preimage(governanceEntry(t, []byte(out)))
			if !bytes.Equal(before, after) {
				t.Fatal("matching flags changed preimage")
			}
		})
	}
}

func TestGovernRefusesForeignOrMalformedEntriesBeforeConfirmation(t *testing.T) {
	bin, dir := nornBinary(t), t.TempDir()
	root := signerKeyFile(t, dir, "root1")
	raw, stderr, err := runGovern(t, bin, "yes\n", append(governArgs(root, "note"), "-text", "original")...)
	if err != nil {
		t.Fatalf("%v\n%s", err, stderr)
	}
	cases := []struct {
		name, says string
		mutate     func(*entry.Envelope)
	}{
		{"type", "this invocation signs `note` entries", func(e *entry.Envelope) { e.T = "policy" }},
		{"network", "another network", func(e *entry.Envelope) { e.Net[0] ^= 1 }},
		{"extra field", "unknown field", func(e *entry.Envelope) { e.Body["hidden"] = "anything" }},
		{"missing field", "text", func(e *entry.Envelope) { delete(e.Body, "text") }},
		{"bad text", "text", func(e *entry.Envelope) { e.Body["text"] = uint64(1) }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			env := governanceEntry(t, []byte(raw))
			c.mutate(env)
			changed, err := entry.Encode(env)
			if err != nil {
				t.Fatal(err)
			}
			// Stdin must be decoded and checked just like a named input file.
			out, stderr, err := runGovern(t, bin, string(changed), append(governArgs(root, "note"), "-in", "-")...)
			if err == nil || out != "" || !strings.Contains(stderr, c.says) || strings.Contains(stderr, "Sign this entry?") {
				t.Fatalf("foreign input accepted: %v\n%s", err, stderr)
			}
		})
	}
}

func TestGovernSummaryShowsEveryFieldBeforeConfirmation(t *testing.T) {
	bin, dir := nornBinary(t), t.TempDir()
	root := signerKeyFile(t, dir, "root1")
	anchor, err := loadAnchor(filepath.Join(vectors(), "trust.cbor"))
	if err != nil {
		t.Fatal(err)
	}
	p, err := policy.Parse(anchor.Policy)
	if err != nil {
		t.Fatal(err)
	}
	policyWants := []string{strconv.Quote(anchor.Policy), "quorum " + p.Quorum()}
	for _, w := range p.Witnesses {
		policyWants = append(policyWants, strconv.Quote(w.Name))
	}
	cases := []struct {
		typ          string
		flags, wants []string
	}{
		{"signer_add", []string{"-pk-hex", governancePublic(t, "stranger")}, []string{kidOf(t, "stranger"), governancePublic(t, "stranger")}},
		{"signer_thr", []string{"-thr", "1"}, []string{"1 of 2"}},
		{"log_key", []string{"-pk-hex", governancePublic(t, "stranger"), "-overlap", "60"}, []string{kidOf(t, "stranger"), governancePublic(t, "stranger"), "60 seconds"}},
		{"params", []string{"-set", "mmd=90", "-set", "rotate_needs_signer=false"}, []string{"mmd=90", "rotate_needs_signer=false"}},
		{"policy", []string{"-policy", governanceFile(t, []byte(anchor.Policy))}, policyWants},
		{"note", []string{"-text", "hello\n\x1b[2J"}, []string{strconv.Quote("hello\n\x1b[2J"), "needs 1 root"}},
	}
	for _, c := range cases {
		t.Run(c.typ, func(t *testing.T) {
			out, stderr, err := runGovern(t, bin, "no\n", append(governArgs(root, c.typ), c.flags...)...)
			if err == nil || out != "" {
				t.Fatal("declining must not emit an entry")
			}
			prompt := strings.Index(stderr, "Sign this entry?")
			wants := append(c.wants, c.typ, "root_thr 3", "has 0", "3 of 3", "after      "+strconv.FormatUint(rotationState(t).Size, 10), "entry hash", kidOf(t, "root1"))
			for _, want := range wants {
				at := strings.Index(stderr, want)
				if at < 0 || prompt < 0 || at >= prompt {
					t.Errorf("missing %q before prompt:\n%s", want, stderr)
				}
			}
		})
	}
}

func TestGovernReadsPublicAndPrivateKeyFilesWithoutChangingThem(t *testing.T) {
	bin, dir := nornBinary(t), t.TempDir()
	root := signerKeyFile(t, dir, "root1")
	private := signerKeyFile(t, dir, "stranger")
	public := fixtureKey(t, "stranger").Public().(ed25519.PublicKey)
	blob := sshwire.AppendString(nil, []byte("ssh-ed25519"))
	blob = sshwire.AppendString(blob, public)
	pubPath := filepath.Join(dir, "stranger.pub")
	if err := os.WriteFile(pubPath, []byte("ssh-ed25519 "+base64.StdEncoding.EncodeToString(blob)+" comment\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{private, pubPath} {
		t.Run(filepath.Base(path), func(t *testing.T) {
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			raw, stderr, err := runGovern(t, bin, "yes\n", append(governArgs(root, "signer_add"), "-pk", path)...)
			if err != nil {
				t.Fatalf("%v\n%s", err, stderr)
			}
			if !bytes.Equal(governanceEntry(t, []byte(raw)).Body["pk"].([]byte), public) {
				t.Fatal("wrong public half")
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("key file changed")
			}
			if strings.Contains(stderr, "PRIVATE KEY") {
				t.Fatal("private key printed")
			}
		})
	}
}

func TestGovernOrderingGuardAndFileOutputArePreserved(t *testing.T) {
	bin, dir := nornBinary(t), t.TempDir()
	root, second := signerKeyFile(t, dir, "root1"), signerKeyFile(t, dir, "root2")
	for _, guard := range [][]string{{"-after", "90"}, {"-no-after"}} {
		t.Run(fmt.Sprint(guard), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "entry")
			args := append(governArgs(root, "note"), "-text", "ordering", "-o", path)
			out, stderr, err := runGovern(t, bin, "yes\n", append(args, guard...)...)
			if err != nil || out != "" {
				t.Fatalf("file output: %v\n%s", err, stderr)
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			env := governanceEntry(t, raw)
			if guard[0] == "-after" {
				if env.After == nil || *env.After != 90 {
					t.Fatal("wrong guard")
				}
			} else if env.After != nil || !strings.Contains(stderr, "no ordering guard") {
				t.Fatal("missing guard warning")
			}
			out, stderr, err = runGovern(t, bin, "yes\n", append(governArgs(second, "note"), "-in", path)...)
			if err != nil {
				t.Fatalf("extension: %v\n%s", err, stderr)
			}
			before, _ := entry.Preimage(env)
			after, _ := entry.Preimage(governanceEntry(t, []byte(out)))
			if !bytes.Equal(before, after) {
				t.Fatal("extension changed guard")
			}
		})
	}
}
