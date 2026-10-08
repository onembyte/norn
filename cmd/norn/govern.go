package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/onembyte/norn/internal/entry"
	"github.com/onembyte/norn/internal/fields"
	"github.com/onembyte/norn/internal/keyfile"
	"github.com/onembyte/norn/internal/policy"
	"github.com/onembyte/norn/internal/sshwire"
	"github.com/onembyte/norn/internal/state"
	"github.com/onembyte/norn/internal/trust"
)

func governCmd(args []string) error {
	fs := newFlagSet("govern")
	trustPath := fs.String("trust", "", "path to norn.trust (required)")
	typ := fs.String("t", "", "governance type: signer_add/remove/thr, root_add/remove/thr, log_key, policy, params or note")
	pkPath := fs.String("pk", "", "an OpenSSH public or private key file; use its public half")
	pkHex := fs.String("pk-hex", "", "the public key, hex")
	kid := fs.String("kid", "", "the key id to remove")
	thr := fs.Uint64("thr", 0, "the new threshold")
	overlap := fs.Uint64("overlap", 0, "seconds the log must keep signing with the old key")
	policyPath := fs.String("policy", "", "verbatim tlog-policy text file")
	text := fs.String("text", "", "note text (at most 4096 bytes)")
	var sets repeated
	fs.Var(&sets, "set", "a parameter key=value; repeat for more than one")
	keyPath := fs.String("key", "", "an OpenSSH private key file to sign with")
	agentKid := fs.String("agent-kid", "", "sign with this `kid` from the ssh-agent")
	role := fs.String("role", "root", "the role to sign as: root only")
	logLocation := fs.String("log", "", "log URL or directory; defaults to the anchor's log_urls")
	after := fs.Int64("after", -1, "the log size this signature assumes (§4.4)")
	noAfter := fs.Bool("no-after", false, "sign without an `after` guard, and say why in the summary")
	in := fs.String("in", "", "an existing entry to extend (or - for stdin; confirmation then uses the terminal)")
	out := fs.String("o", "", "write the entry here instead of stdout")
	yes := fs.Bool("yes", false, "not allowed: root authority always requires confirmation")
	if err := fs.Parse(args); err != nil {
		return err
	}
	// Refuse scripted root authority before reading a trust file, key or entry.
	if *yes {
		return errors.New("--yes cannot be used for governance: a root's authority is never exercised by a script")
	}
	if *role != "root" {
		return errors.New("-role must be root for governance")
	}
	if *trustPath == "" {
		return errors.New("-trust is required: signing means deciding for a network, and the anchor is what names it")
	}
	bodyFields := governBodyFields(*typ)
	if bodyFields == nil {
		return fmt.Errorf("unknown governance type %q; use signer_add, signer_remove, signer_thr, root_add, root_remove, root_thr, log_key, policy, params or note", *typ)
	}
	if fs.NArg() > 1 || (fs.NArg() == 1 && *in != "") {
		return errors.New("give at most one existing entry, using -in FILE or a positional file (or - for stdin)")
	}
	if fs.NArg() == 1 {
		*in = fs.Arg(0)
	}
	given := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { given[f.Name] = true })
	if given["after"] && *after < 0 {
		return errors.New("-after must be a non-negative log size")
	}
	if given["after"] && *noAfter {
		return errors.New("give -after or -no-after, not both")
	}
	flagFields := map[string]string{"pk": "pk", "pk-hex": "pk", "kid": "kid", "thr": "thr", "overlap": "overlap", "policy": "text", "text": "text", "set": "params"}
	for name, field := range flagFields {
		if !given[name] {
			continue
		}
		allowed := bodyFields[field] || name == "set" && *typ == "params"
		if name == "policy" {
			allowed = *typ == "policy"
		}
		if name == "text" {
			allowed = *typ == "note"
		}
		if !allowed {
			return fmt.Errorf("-%s is not a flag for %s", name, *typ)
		}
	}
	if given["pk"] && given["pk-hex"] {
		return errors.New("give exactly one of -pk or -pk-hex")
	}

	anchor, err := loadAnchor(*trustPath)
	if err != nil {
		return err
	}
	signer, keySource, err := openSigner(*keyPath, *agentKid)
	if err != nil {
		return err
	}
	public, ok := signer.Public().(ed25519.PublicKey)
	if !ok {
		return errors.New("the signing key is not Ed25519")
	}
	fresh := *in == ""
	observed, logErr := observedSize(anchor, *logLocation)
	if logErr != nil {
		if fresh && *after < 0 && !*noAfter {
			return fmt.Errorf("could not read the log to learn its size (%w).\n"+
				"Pass -after N with the size you observed, or -no-after to sign without "+
				"the §4.4 ordering guard; governance still requires a verified log to check the body and signing role", logErr)
		}
		return fmt.Errorf("could not verify the body and signing role because the log is unreadable: %w", logErr)
	}
	if err := checkGovernRoot(observed.State, public); err != nil {
		return err
	}

	// This map contains only explicit flags. On extension each is a constraint,
	// never a replacement for a field that another root has already approved.
	proposed := map[string]any{}
	if given["pk"] || given["pk-hex"] {
		pk, err := governPublicKey(*pkPath, *pkHex, given["pk"])
		if err != nil {
			return err
		}
		proposed["pk"] = pk
	}
	if given["kid"] {
		proposed["kid"] = *kid
	}
	if given["thr"] {
		proposed["thr"] = *thr
	}
	if given["overlap"] {
		proposed["overlap"] = *overlap
	}
	if given["text"] {
		proposed["text"] = *text
	}
	if given["policy"] {
		raw, err := os.ReadFile(*policyPath)
		if err != nil {
			return fmt.Errorf("reading the policy: %w", err)
		}
		proposed["text"] = string(raw)
	}
	for _, setting := range sets {
		name, value, ok := strings.Cut(setting, "=")
		if !ok {
			return fmt.Errorf("-set %q must be key=value", setting)
		}
		parsed, err := governParam(name, value)
		if err != nil {
			return err
		}
		if previous, exists := proposed[name]; exists && previous != parsed {
			return fmt.Errorf("conflicting values for parameter %q", name)
		}
		proposed[name] = parsed
	}
	var env *entry.Envelope
	if fresh {
		env = &entry.Envelope{V: entry.Version, T: *typ, Net: anchor.Net, TS: uint64(time.Now().Unix()), Body: proposed}
		switch {
		case *after >= 0:
			value := uint64(*after)
			env.After = &value
		case !*noAfter:
			value := observed.Size
			env.After = &value
		}
	} else {
		input, err := readInput(*in)
		if err != nil {
			return err
		}
		env, err = entry.Decode(input)
		if err != nil {
			return fmt.Errorf("the input is not an entry: %w", err)
		}
		if env.T != *typ {
			return fmt.Errorf("this invocation signs `%s` entries, not %q", *typ, env.T)
		}
		if !bytes.Equal(env.Net, anchor.Net) {
			return errors.New("the entry is for another network")
		}
		for field, value := range proposed {
			if !reflect.DeepEqual(env.Body[field], value) {
				return fmt.Errorf("the entry's %s does not match the given flag; existing signed fields cannot be changed", field)
			}
		}
		if given["after"] && (env.After == nil || *env.After != uint64(*after)) || *noAfter && env.After != nil {
			return errors.New("the entry's after guard does not match the given flag; existing signed fields cannot be changed")
		}
	}
	// These are CLI pre-checks, not replay. D-046 still makes replay count the
	// root quorum before checking a governance body, including malformed ones.
	if err := checkGovernBody(env, observed.State); err != nil {
		return err
	}
	if err := checkGovernSignatures(env, observed.State); err != nil {
		return err
	}
	printGovernSummary(env, anchor, observed.State, entry.Kid(public), keySource, fresh)
	if err := confirmGovern(*in); err != nil {
		return err
	}
	if err := entry.Sign(env, signer, "root"); err != nil {
		return err
	}
	if err := checkSelfSigned(env, signer); err != nil {
		return err
	}
	if err := checkGovernSignatures(env, observed.State); err != nil {
		return err
	}
	raw, err := entry.Encode(env)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "\nSigned. %d root signature(s); needs %d.\nExtend with `norn govern -t %s -in FILE`; submit a completed entry with `norn submit`.\n", len(env.Sigs), governRequired(env, observed.State), env.T)
	return writeEntry(raw, *out)
}

func governBodyFields(typ string) map[string]bool {
	switch typ {
	case "signer_add", "root_add":
		return map[string]bool{"pk": true}
	case "signer_remove", "root_remove":
		return map[string]bool{"kid": true}
	case "signer_thr", "root_thr":
		return map[string]bool{"thr": true}
	case "log_key":
		return map[string]bool{"pk": true, "overlap": true}
	case "policy", "note":
		return map[string]bool{"text": true}
	case "params":
		return map[string]bool{"checkpoint_interval": true, "staleness": true, "mmd": true, "rotate_needs_signer": true}
	}
	return nil
}

func governParam(name, value string) (any, error) {
	switch name {
	case "rotate_needs_signer":
		if value != "true" && value != "false" {
			return nil, fmt.Errorf("parameter %q must be a bool (true or false)", name)
		}
		return value == "true", nil
	case "checkpoint_interval", "staleness", "mmd":
		n, err := strconv.ParseUint(value, 10, 63)
		if err != nil {
			return nil, fmt.Errorf("parameter %q must be a uint: %w", name, err)
		}
		return n, nil
	default:
		return nil, fmt.Errorf("unknown parameter %q: §4.5 names checkpoint_interval, staleness, mmd and rotate_needs_signer", name)
	}
}

func governPublicKey(path, encoded string, fromFile bool) ([]byte, error) {
	if !fromFile {
		public, err := publicFromHex(encoded)
		return []byte(public), err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if bytes.HasPrefix(raw, []byte("-----BEGIN OPENSSH PRIVATE KEY-----")) {
		private, _, err := keyfile.Read(path)
		if err != nil {
			return nil, err
		}
		return []byte(private.Public().(ed25519.PublicKey)), nil
	}
	// The SSH public blob is length-prefixed, not just its last 32 bytes: both
	// algorithm declarations and the absence of trailing data must agree.
	parts := strings.Fields(string(raw))
	if len(parts) < 2 || parts[0] != "ssh-ed25519" {
		return nil, errors.New("-pk must name an OpenSSH Ed25519 public or private key file")
	}
	blob, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("public key: %w", err)
	}
	algorithm, rest, err := sshwire.String(blob)
	if err != nil || string(algorithm) != "ssh-ed25519" {
		return nil, errors.New("the public key blob is not ssh-ed25519")
	}
	public, rest, err := sshwire.String(rest)
	if err != nil || len(rest) != 0 {
		return nil, errors.New("the public key blob is malformed")
	}
	return fields.PublicKey(public, "pk")
}

func checkGovernRoot(st *state.State, public ed25519.PublicKey) error {
	observed, err := revokeRoleKey(st, state.Device{}, "root", entry.Kid(public))
	if err != nil {
		return err
	}
	if !bytes.Equal(public, observed) {
		return errors.New("the signing key does not match the observed root public key")
	}
	return nil
}

func checkGovernSignatures(env *entry.Envelope, st *state.State) error {
	for _, sig := range env.Sigs {
		if sig.Role != "root" {
			return fmt.Errorf("governance cannot be extended with signature role %q: use root", sig.Role)
		}
		public, err := revokeRoleKey(st, state.Device{}, "root", sig.Kid)
		if err != nil {
			return err
		}
		valid, err := entry.Verify(env, sig, public)
		if err != nil {
			return err
		}
		if !valid {
			return fmt.Errorf("the existing signature by %s does not verify over this entry", sig.Kid)
		}
	}
	return nil
}

func checkGovernBody(env *entry.Envelope, st *state.State) error {
	allowed := governBodyFields(env.T)
	for field := range env.Body {
		if !allowed[field] {
			return fmt.Errorf("the %s body contains unknown field %q", env.T, field)
		}
	}
	if env.T != "params" {
		for field := range allowed {
			if _, ok := env.Body[field]; !ok {
				return fmt.Errorf("the %s body requires %s", env.T, field)
			}
		}
	}
	switch env.T {
	case "signer_add", "root_add", "log_key":
		pk, err := fields.PublicKey(env.Body["pk"], "pk")
		if err != nil {
			return err
		}
		if env.T == "log_key" {
			_, err := fields.Uint(env.Body["overlap"], "overlap")
			return err
		}
		kid := entry.Kid(pk)
		if st.Roots[kid] != "" || st.Signers[kid] != "" {
			return fmt.Errorf("key %s is already a root or signer in the observed log: dup-key", kid)
		}
	case "signer_remove", "root_remove":
		kid, ok := env.Body["kid"].(string)
		decoded, err := hex.DecodeString(kid)
		if !ok || err != nil || len(decoded) != 8 || strings.ToLower(kid) != kid {
			return errors.New("kid must be 16 lowercase hex characters")
		}
		set, role := st.Signers, "signer"
		if env.T == "root_remove" {
			set, role = st.Roots, "root"
		}
		if set[kid] == "" {
			return fmt.Errorf("key %s is not a %s in the observed log: unknown-key", kid, role)
		}
		if env.T == "root_remove" && uint64(len(st.Roots)-1) < st.RootThr {
			return fmt.Errorf("removing root %s would leave %d roots, fewer than root_thr %d: root-invariant", kid, len(st.Roots)-1, st.RootThr)
		}
	case "signer_thr", "root_thr":
		thr, err := fields.Uint(env.Body["thr"], "thr")
		if err != nil {
			return err
		}
		size := len(st.Signers)
		if env.T == "root_thr" {
			size = len(st.Roots)
		}
		if thr < 1 || thr > uint64(size) {
			return fmt.Errorf("%s value %d is outside 1 … %d in the observed log: bad-thr", env.T, thr, size)
		}
	case "policy", "note":
		text, err := fields.Text(env.Body["text"], 4096, "text")
		if err != nil {
			return err
		}
		if env.T == "policy" {
			if _, err := policy.Parse(text); err != nil {
				return fmt.Errorf("the policy does not parse: %w", err)
			}
		}
	case "params":
		if len(env.Body) == 0 {
			return errors.New("params must be a non-empty partial §4.5 map; give -set key=value")
		}
		for name, value := range env.Body {
			if name == "rotate_needs_signer" {
				if _, ok := value.(bool); !ok {
					return fmt.Errorf("parameter %q must be a bool", name)
				}
			} else if _, err := fields.Uint(value, name); err != nil {
				return err
			}
		}
	}
	return nil
}

// A pipe holding CBOR is exhausted by readInput. Confirmation must come from
// the controlling terminal in that case, never from bytes inside the entry.
func confirmGovern(input string) error {
	if input != "-" {
		return confirm()
	}
	terminal, err := os.Open("/dev/tty")
	if err != nil {
		return fmt.Errorf("confirmation for -in - requires a terminal; save the entry and use -in FILE: %w", err)
	}
	defer terminal.Close()
	previous := os.Stdin
	os.Stdin = terminal
	defer func() { os.Stdin = previous }()
	return confirm()
}

func governRequired(env *entry.Envelope, st *state.State) uint64 {
	// §4.3 permits a note with any one signer or root, independently of root_thr.
	if env.T == "note" {
		return 1
	}
	return st.RootThr
}

func printGovernSummary(env *entry.Envelope, anchor *trust.Trust, st *state.State, kid, source string, fresh bool) {
	w := os.Stderr
	action := "APPEND A SIGNATURE TO"
	if fresh {
		action = "SIGN A NEW"
	}
	fmt.Fprintf(w, "%s %s ENTRY\n", action, env.T)
	fmt.Fprintf(w, "  network    %q (%x)\n", anchor.Name, env.Net)
	if fp, err := anchor.Fingerprint(); err == nil {
		fmt.Fprintf(w, "  anchor     %s\n", fp)
	}
	fmt.Fprintf(w, "  version    %d\n  timestamp  %d\n", env.V, env.TS)
	switch env.T {
	case "signer_add", "root_add", "log_key":
		pk := env.Body["pk"].([]byte)
		fmt.Fprintf(w, "  new public key %s (%x)\n", entry.Kid(pk), pk)
		if env.T == "log_key" {
			fmt.Fprintf(w, "  old log key signing overlap %d seconds\n", env.Body["overlap"])
		}
	case "signer_remove", "root_remove":
		kid := env.Body["kid"].(string)
		pk := st.Signers[kid]
		if env.T == "root_remove" {
			pk = st.Roots[kid]
		}
		fmt.Fprintf(w, "  remove key %s (%s)\n", kid, pk)
	case "signer_thr", "root_thr":
		role, size := "signers", len(st.Signers)
		if env.T == "root_thr" {
			role, size = "roots", len(st.Roots)
		}
		fmt.Fprintf(w, "  new threshold %d of %d %s\n", env.Body["thr"], size, role)
	case "policy":
		text := env.Body["text"].(string)
		p, _ := policy.Parse(text)
		fmt.Fprintf(w, "  policy text %q\n  quorum line %q\n", text, "quorum "+p.Quorum())
		for _, witness := range p.Witnesses {
			fmt.Fprintf(w, "  witness    %q\n", witness.Name)
		}
	case "note":
		fmt.Fprintf(w, "  text       %q\n", env.Body["text"])
	case "params":
		names := make([]string, 0, len(env.Body))
		for name := range env.Body {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			fmt.Fprintf(w, "  parameter  %s=%v\n", name, env.Body[name])
		}
	}
	// Free text is quoted so a terminal control cannot conceal signed content.
	fmt.Fprintf(w, "  signing as %s  role root  (%q)\n", kid, source)
	fmt.Fprintf(w, "  root_thr %d (%d of %d roots); entry needs %d root signature(s), has %d\n", st.RootThr, st.RootThr, len(st.Roots), governRequired(env, st), len(env.Sigs))
	if env.After != nil {
		fmt.Fprintf(w, "  after      %d\n", *env.After)
	} else {
		fmt.Fprintln(w, "  after      (none — no ordering guard; the log may place this entry anywhere)")
	}
	if raw, err := entry.Encode(env); err == nil {
		fmt.Fprintf(w, "  entry hash %x\n", entry.EntryHash(raw))
	}
}
