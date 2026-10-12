package main

import (
	"bufio"
	"crypto"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/onembyte/norn/internal/enrollreq"
	"github.com/onembyte/norn/internal/entry"
	"github.com/onembyte/norn/internal/keyfile"
	"github.com/onembyte/norn/internal/logclient"
	"github.com/onembyte/norn/internal/sshagent"
	"github.com/onembyte/norn/internal/state"
	"github.com/onembyte/norn/internal/trust"
	"github.com/onembyte/norn/internal/wgkey"
)

func signCmd(args []string) error {
	fs := newFlagSet("sign")
	trustPath := fs.String("trust", "", "path to norn.trust (required)")
	keyPath := fs.String("key", "", "an OpenSSH private key file to sign with")
	agentKid := fs.String("agent-kid", "", "sign with this `kid` from the ssh-agent")
	logLocation := fs.String("log", "", "log URL or directory; defaults to the anchor's log_urls")
	after := fs.Int64("after", -1, "the log size this signature assumes (§4.4)")
	prev := fs.Int64("prev", -1, "the object version this signature assumes (§4.4)")
	noAfter := fs.Bool("no-after", false, "sign without an `after` guard, and say why in the summary")
	role := fs.String("role", "signer", "the role to sign as: signer or root")
	out := fs.String("o", "", "write the entry here instead of stdout")
	yes := fs.Bool("yes", false, "do not ask for confirmation")
	if err := fs.Parse(args); err != nil {
		return err
	}
	prevGiven := false
	fs.Visit(func(f *flag.Flag) { prevGiven = prevGiven || f.Name == "prev" })
	if prevGiven && *prev < 0 {
		return errors.New("-prev must be a non-negative object version")
	}

	// §16.3: `--yes` MUST NOT exist for the root role. A root's authority is
	// the one thing in this protocol that cannot be scripted away, because a
	// script that can mint it is indistinguishable from a stolen signer with
	// better manners. Refused before anything is read, so the combination
	// costs nothing to try and nothing to automate.
	if *yes && *role == "root" {
		return errors.New("--yes cannot be combined with --role root: a root's " +
			"authority is never exercised by a script")
	}
	if *trustPath == "" {
		fs.Usage()
		return errors.New("-trust is required: signing means deciding for a network, " +
			"and the anchor is what names it")
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return errors.New("give exactly one request or partially signed entry (or - for stdin)")
	}

	anchor, err := loadAnchor(*trustPath)
	if err != nil {
		return err
	}
	input, err := readInput(fs.Arg(0))
	if err != nil {
		return err
	}
	signer, keySource, err := openSigner(*keyPath, *agentKid)
	if err != nil {
		return err
	}

	// The log is advisory here (§6: operator validation is non-binding), but a
	// signer who can see it learns two useful things: the size to guard a *new*
	// entry with, and whether the entry is going to be refused for a reason
	// they could fix now rather than after submitting.
	size, logErr := observedSize(anchor, *logLocation)
	var observed *state.State
	if logErr == nil {
		observed = size.State
	}

	// An entry that already carries signatures has its `after` fixed: changing
	// it would change the preimage and invalidate every signature already on
	// it. So the log size is only needed when building a new entry.
	if isRequest(input) && *after < 0 && !*noAfter && logErr != nil {
		return fmt.Errorf("could not read the log to learn its size (%w).\n"+
			"Pass -after N with the size you observed, or -no-after to sign without "+
			"the §4.4 ordering guard", logErr)
	}

	env, request, fresh, err := buildOrExtend(input, anchor, size, *after, *noAfter)
	if err != nil {
		return err
	}

	if err := applyPrevFlag(env, fresh, *prev, prevGiven); err != nil {
		return err
	}

	printSignSummary(env, request, anchor, observed, signer, keySource, *noAfter, fresh)
	if !*yes {
		if err := confirm(); err != nil {
			return err
		}
	}

	if err := entry.Sign(env, signer, *role); err != nil {
		return err
	}
	raw, err := entry.Encode(env)
	if err != nil {
		return err
	}
	// Never emit an entry this command cannot itself verify.
	if err := checkSelfSigned(env, signer); err != nil {
		return err
	}
	reportProgress(env, observed)
	return writeEntry(raw, *out)
}

type observation struct {
	Size  uint64
	State *state.State
}

func observedSize(anchor *trust.Trust, location string) (observation, error) {
	if location == "" {
		if len(anchor.LogURLs) == 0 {
			return observation{}, errors.New("the anchor lists no log_urls")
		}
		location = anchor.LogURLs[0]
	}
	fetcher, err := logclient.Open(location)
	if err != nil {
		return observation{}, err
	}
	result, err := logclient.Verify(fetcher, anchorFor(anchor))
	if err != nil {
		return observation{}, err
	}
	return observation{Size: uint64(result.Checkpoint.Size), State: result.State}, nil
}

// buildOrExtend turns a request into a fresh entry, or takes an entry that
// already carries signatures and leaves it byte-identical so that appending
// one more signature is all this run does.
func buildOrExtend(input []byte, anchor *trust.Trust, observed observation,
	afterFlag int64, noAfter bool) (*entry.Envelope, *enrollreq.Request, bool, error) {

	if isRequest(input) {
		request, err := enrollreq.DecodeText(strings.TrimSpace(string(input)))
		if err != nil {
			return nil, nil, false, fmt.Errorf("the request does not decode: %w", err)
		}
		// §16.1: verify before anything is shown to a human.
		if err := enrollreq.Check(request, anchor.Net); err != nil {
			return nil, nil, false, fmt.Errorf("the request does not check out: %w", err)
		}
		body := map[string]any{"request": mustEncode(request)}
		env := &entry.Envelope{
			V: entry.Version, T: "enroll", Net: anchor.Net,
			TS: uint64(time.Now().Unix()), Body: body,
		}
		switch {
		case afterFlag >= 0:
			value := uint64(afterFlag)
			env.After = &value
		case !noAfter:
			value := observed.Size
			env.After = &value
		}
		if observed.State != nil {
			env.Prev = observed.State.Previous("enroll", request.DeviceID)
		}
		return env, request, true, nil
	}

	env, err := entry.Decode(input)
	if err != nil {
		return nil, nil, false, fmt.Errorf("the input is neither a bech32m request nor an entry: %w", err)
	}
	if env.T != "enroll" {
		return nil, nil, false, fmt.Errorf("this command signs `enroll` entries, not %q", env.T)
	}
	raw, ok := env.Body["request"].([]byte)
	if !ok {
		return nil, nil, false, errors.New("the entry carries no request (§4.3)")
	}
	request, err := enrollreq.Decode(raw)
	if err != nil {
		return nil, nil, false, fmt.Errorf("the embedded request does not decode: %w", err)
	}
	if err := enrollreq.Check(request, anchor.Net); err != nil {
		return nil, nil, false, fmt.Errorf("the embedded request does not check out: %w", err)
	}
	return env, request, false, nil
}

// isRequest reports whether the input is a bech32m request rather than an
// entry. The two are told apart by shape, not by a flag: a signer pastes or
// scans whatever they were handed and should not have to say which it is.
func isRequest(input []byte) bool {
	text := strings.TrimSpace(string(input))
	return strings.HasPrefix(strings.ToLower(text), enrollreq.HRP+"1")
}

func mustEncode(request *enrollreq.Request) []byte {
	raw, err := enrollreq.Encode(request)
	if err != nil {
		panic(err) // the request was decoded and checked moments ago
	}
	return raw
}

// checkSelfSigned re-verifies what was just produced. A signature this command
// cannot verify is a bug here, and it must not reach a log.
func checkSelfSigned(env *entry.Envelope, signer crypto.Signer) error {
	public, ok := signer.Public().(ed25519.PublicKey)
	if !ok {
		return errors.New("the signing key is not Ed25519")
	}
	for _, sig := range env.Sigs {
		if sig.Kid != entry.Kid(public) {
			continue
		}
		valid, err := entry.Verify(env, sig, public)
		if err != nil {
			return err
		}
		if !valid {
			return errors.New("the signature this command just made does not verify")
		}
		return nil
	}
	return errors.New("the signature this command just made is not in the entry")
}

// openSigner resolves the signing key and says where it came from, because the
// summary has to name it: "what you sign is what you see" includes *which key*.
func openSigner(keyPath, agentKid string) (crypto.Signer, string, error) {
	if keyPath != "" && agentKid != "" {
		return nil, "", errors.New("give -key or -agent-kid, not both")
	}
	if keyPath != "" {
		key, comment, err := keyfile.Read(keyPath)
		source := keyPath
		if comment != "" {
			source = fmt.Sprintf("%s — %s", keyPath, comment)
		}
		return key, source, err
	}

	client, err := sshagent.Open()
	if err != nil {
		return nil, "", fmt.Errorf("%w. Use -key to sign with a key file instead", err)
	}
	keys, err := client.Keys()
	if err != nil {
		return nil, "", err
	}
	pick := func(key sshagent.Key) (crypto.Signer, string, error) {
		signer, err := client.Signer(key.Public)
		source := "ssh-agent"
		if key.Comment != "" {
			source = "ssh-agent — " + key.Comment
		}
		return signer, source, err
	}
	if agentKid != "" {
		for _, key := range keys {
			if entry.Kid(key.Public) == agentKid {
				return pick(key)
			}
		}
		return nil, "", fmt.Errorf("the agent holds no key with kid %s", agentKid)
	}
	switch len(keys) {
	case 0:
		return nil, "", errors.New("the agent holds no Ed25519 keys")
	case 1:
		return pick(keys[0])
	default:
		var names []string
		for _, key := range keys {
			names = append(names, fmt.Sprintf("  %s  %s", entry.Kid(key.Public), key.Comment))
		}
		return nil, "", fmt.Errorf("the agent holds %d keys; choose one with -agent-kid:\n%s",
			len(keys), strings.Join(names, "\n"))
	}
}

func readInput(path string) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(path)
}

// loadAnchor reads a trust file and refuses one that is not a usable anchor,
// the same way `norn verify` does: there is no flag to skip this.
func loadAnchor(path string) (*trust.Trust, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading the trust file: %w", err)
	}
	anchor, err := trust.Parse(raw)
	if err != nil {
		return nil, err
	}
	if err := anchor.Validate(); err != nil {
		return nil, fmt.Errorf("the trust file is not a usable anchor: %w", err)
	}
	return anchor, nil
}

func writeEntry(raw []byte, path string) error {
	if path != "" {
		return os.WriteFile(path, raw, 0o644)
	}
	if isTerminal(os.Stdout) {
		return errors.New("an entry is CBOR, not text: give -o FILE or redirect stdout")
	}
	_, err := os.Stdout.Write(raw)
	return err
}

func confirm() error {
	fmt.Fprint(os.Stderr, "\nSign this entry? [y/N] ")
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		return fmt.Errorf("reading the answer: %w", err)
	}
	if answer := strings.ToLower(strings.TrimSpace(line)); answer != "y" && answer != "yes" {
		return errors.New("not signed")
	}
	return nil
}

// printSignSummary is §16.1's what-you-sign-is-what-you-see rule: every
// field the signature will cover appears here, including the ones the
// signer cannot change.
func printSignSummary(env *entry.Envelope, request *enrollreq.Request, anchor *trust.Trust,
	observed *state.State, signer crypto.Signer, keySource string, noAfter, fresh bool) {

	w := os.Stderr
	action := "APPEND A SIGNATURE TO"
	if fresh {
		action = "SIGN A NEW"
	}
	fmt.Fprintf(w, "%s ENROLL ENTRY\n", action)
	fmt.Fprintf(w, "  network    %s\n", anchor.Name)
	if fp, err := anchor.Fingerprint(); err == nil {
		fmt.Fprintf(w, "  anchor     %s\n", fp)
	}
	fmt.Fprintf(w, "  device     %s\n", request.DeviceID)
	fmt.Fprintf(w, "  device key %s\n", entry.Kid(request.DevicePK))
	fmt.Fprintf(w, "  wireguard  %s\n", wgkey.Format(request.WGPK))
	for _, key := range sortedKeys(request.Labels) {
		fmt.Fprintf(w, "  label      %s=%s\n", key, request.Labels[key])
	}
	if request.Expires != nil {
		fmt.Fprintf(w, "  expires    %s\n", time.Unix(int64(*request.Expires), 0).Format(time.RFC3339))
	}
	if env.After != nil {
		fmt.Fprintf(w, "  after      %d\n", *env.After)
	} else if noAfter {
		fmt.Fprintf(w, "  after      (none — no ordering guard; the log may place this entry anywhere)\n")
	}
	if public, ok := signer.Public().(ed25519.PublicKey); ok {
		fmt.Fprintf(w, "  signing as %s  (%s)\n", entry.Kid(public), keySource)
	}
	printPrevSummary(w, env)
	if raw, err := entry.Encode(env); err == nil {
		fmt.Fprintf(w, "  entry hash %s\n", hex.EncodeToString(entry.EntryHash(raw)))
	}

	// Advisory warnings: the log's own view, which §6 says nobody may rely on.
	if observed != nil {
		if d, ok := observed.Devices[request.DeviceID]; ok && d.Status == state.StatusActive {
			fmt.Fprintf(w, "\n  ! %s is already active in the log; this entry would be "+
				"refused `dup-id`\n", request.DeviceID)
		}
		if id, taken := observed.ActiveWg[hex.EncodeToString(request.WGPK)]; taken {
			fmt.Fprintf(w, "\n  ! that WireGuard key is already active for %s; this entry "+
				"would be refused `dup-wg`\n", id)
		}
	}
}

// reportProgress says whether the entry is ready to submit, because a signer
// who stops one signature short has done nothing at all.
func reportProgress(env *entry.Envelope, observed *state.State) {
	if observed == nil {
		fmt.Fprintf(os.Stderr, "\nSigned. %d signature(s); the log was not reachable, so "+
			"whether that meets `signer_thr` is unknown here.\n", len(env.Sigs))
		return
	}
	var valid int
	for _, sig := range env.Sigs {
		if _, ok := observed.Signers[sig.Kid]; ok && sig.Role == "signer" {
			valid++
		}
	}
	switch {
	case uint64(valid) >= observed.SignerThr:
		fmt.Fprintf(os.Stderr, "\nSigned: %d of %d signer signatures. Ready for `norn submit`.\n",
			valid, observed.SignerThr)
	default:
		fmt.Fprintf(os.Stderr, "\nSigned: %d of %d signer signatures. Run `norn sign` again "+
			"with another signer key before submitting.\n", valid, observed.SignerThr)
	}
}
