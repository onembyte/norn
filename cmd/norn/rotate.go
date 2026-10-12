package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/onembyte/norn/internal/entry"
	"github.com/onembyte/norn/internal/fields"
	"github.com/onembyte/norn/internal/state"
	"github.com/onembyte/norn/internal/trust"
	"github.com/onembyte/norn/internal/wgkey"
)

func rotateCmd(args []string) error {
	fs := newFlagSet("rotate")
	trustPath := fs.String("trust", "", "path to norn.trust (required)")
	deviceID := fs.String("device", "", "the device id to rotate (required)")
	wgPath := fs.String("wg-key", "", "a WireGuard private key file to rotate to the public half of")
	wgPublic := fs.String("wg-pub", "", "the new WireGuard public key, base64")
	newKeyPath := fs.String("new-key", "", "the incoming identity key, an OpenSSH private key file")
	keyPath := fs.String("key", "", "an OpenSSH private key file to sign with")
	agentKid := fs.String("agent-kid", "", "sign with this `kid` from the ssh-agent")
	role := fs.String("role", "device", "the role to sign as: device or signer")
	logLocation := fs.String("log", "", "log URL or directory; defaults to the anchor's log_urls")
	after := fs.Int64("after", -1, "the log size this signature assumes (§4.4)")
	prev := fs.Int64("prev", -1, "the object version this signature assumes (§4.4)")
	noAfter := fs.Bool("no-after", false, "sign without an `after` guard, and say why in the summary")
	in := fs.String("in", "", "an existing rotate entry to extend (or - for stdin)")
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

	if *trustPath == "" {
		return errors.New("-trust is required: signing means deciding for a network, and the anchor is what names it")
	}
	if *deviceID == "" {
		return errors.New("-device is required: name the device to rotate")
	}
	if *role != "device" && *role != "signer" {
		return errors.New("-role must be device or signer")
	}
	if _, err := fields.DeviceID(*deviceID); err != nil {
		return err
	}
	if fs.NArg() > 1 || (fs.NArg() == 1 && *in != "") {
		return errors.New("give at most one existing entry, using -in FILE or a positional file (or - for stdin)")
	}
	if fs.NArg() == 1 {
		*in = fs.Arg(0)
	}
	if *newKeyPath != "" && (*role != "device" || *in != "") {
		return errors.New("-new-key is only allowed for a new entry signed with -role device, not when extending")
	}
	fresh := *in == ""
	wgGiven := *wgPath != "" || *wgPublic != ""
	// An explicitly empty flag on an extension is still an input to check,
	// not permission to silently use the key already in the body.
	emptyWGFlag := false
	fs.Visit(func(f *flag.Flag) {
		if (f.Name == "wg-key" || f.Name == "wg-pub") && f.Value.String() == "" {
			emptyWGFlag = true
		}
	})
	if emptyWGFlag || (fresh && !wgGiven) || (*wgPath != "" && *wgPublic != "") {
		return errors.New("give exactly one of -wg-key (a private key file) or -wg-pub (a public key) for a new entry")
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
	observed, logErr := observedSize(anchor, *logLocation)
	if logErr != nil {
		if fresh && *after < 0 && !*noAfter {
			return fmt.Errorf("could not read the log to learn its size (%w).\n"+
				"Pass -after N with the size you observed, or -no-after to sign without "+
				"the §4.4 ordering guard; rotation still requires a verified log to check the device and signing role", logErr)
		}
		return fmt.Errorf("could not verify the device and signing role because the log is unreadable: %w", logErr)
	}
	d, known := observed.State.Devices[*deviceID]
	if !known {
		return fmt.Errorf("unknown device %q: it is not in the observed log", *deviceID)
	}
	if d.Status != state.StatusActive {
		return fmt.Errorf("device %q is %s in the observed log, not active", *deviceID, d.Status)
	}
	// Only the current device key may initiate a rotation or extend it as the
	// device. The incoming key is valid only for its proof of possession below.
	roleKey, err := rotateRoleKey(observed.State, d, nil, *role, entry.Kid(public))
	if err != nil {
		return err
	}
	if !bytes.Equal(public, roleKey) {
		return fmt.Errorf("key %s does not match the observed %s public key", entry.Kid(public), *role)
	}

	var wg []byte
	if wgGiven {
		wg, err = rotateWireGuardKey(*wgPath, *wgPublic)
		if err != nil {
			return err
		}
	}
	var incoming ed25519.PrivateKey
	incomingSource := ""
	if *newKeyPath != "" {
		next, source, err := openSigner(*newKeyPath, "")
		if err != nil {
			return err
		}
		incoming, ok = next.(ed25519.PrivateKey)
		if !ok {
			return errors.New("the incoming identity key is not an Ed25519 private key")
		}
		incomingSource = source
	}
	var env *entry.Envelope
	if fresh {
		body := map[string]any{"device_id": *deviceID, "wg_pk": wg}
		if incoming != nil {
			body["device_pk"] = []byte(incoming.Public().(ed25519.PublicKey))
		}
		env = &entry.Envelope{V: entry.Version, T: "rotate", Net: anchor.Net,
			TS: uint64(time.Now().Unix()), Body: body}
		env.Prev = observed.State.Previous(env.T, *deviceID)
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
		if env.T != "rotate" {
			return fmt.Errorf("this command signs `rotate` entries, not %q", env.T)
		}
		if !bytes.Equal(env.Net, anchor.Net) {
			return errors.New("the entry is for another network")
		}
		// Fields another signer approved cannot be silently replaced by flags.
		for key := range env.Body {
			if key != "device_id" && key != "wg_pk" && key != "device_pk" {
				return fmt.Errorf("the rotate body contains unknown field %q", key)
			}
		}
		if env.Body["device_id"] != *deviceID {
			return errors.New("the entry's device_id does not match -device")
		}
		bodyWG, err := fields.PublicKey(env.Body["wg_pk"], "wg_pk")
		if err != nil {
			return err
		}
		if wgGiven && !bytes.Equal(wg, bodyWG) {
			return errors.New("the entry's wg_pk does not match -wg-pub or -wg-key; existing signed fields cannot be changed")
		}
		wg = bodyWG
	}
	if err := applyPrevFlag(env, fresh, *prev, prevGiven); err != nil {
		return err
	}

	var incomingPublic []byte
	if value, present := env.Body["device_pk"]; present {
		incomingPublic, err = fields.PublicKey(value, "device_pk")
		if err != nil {
			return err
		}
	}
	// These are CLI refusals, not new replay rules. A signer should learn why
	// the proposed change is unusable before being asked to approve it.
	if owner, active := observed.State.ActiveWg[hex.EncodeToString(wg)]; active && owner != *deviceID {
		return fmt.Errorf("the new WireGuard key is already active for device %q: dup-wg", owner)
	}
	if hex.EncodeToString(wg) == d.WgPk && incomingPublic == nil {
		return errors.New("the rotation changes nothing: the WireGuard key is unchanged and there is no new device_pk")
	}

	// Verify before the summary, then again after signing. Adding a signature
	// must neither bless a tampered input nor invalidate a previous approval.
	if err := checkRotateSignatures(env, observed.State, d); err != nil {
		return err
	}
	printRotateSummary(env, anchor, observed.State, d, entry.Kid(public), *role, keySource, incomingSource, fresh)
	if !*yes {
		if err := confirm(); err != nil {
			return err
		}
	}
	if err := entry.Sign(env, signer, *role); err != nil {
		return err
	}
	if err := checkSelfSigned(env, signer); err != nil {
		return err
	}
	// D-032 requires possession of both identity keys, on the same preimage.
	if incoming != nil {
		if err := entry.Sign(env, incoming, "device"); err != nil {
			return err
		}
		if err := checkSelfSigned(env, incoming); err != nil {
			return err
		}
	}
	if err := checkRotateSignatures(env, observed.State, d); err != nil {
		return err
	}
	raw, err := entry.Encode(env)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "\nSigned. %d signature(s); rotation needs the current device key and any incoming identity key, plus %d signer signature(s).\n"+
		"Extend with `norn rotate -role signer -in FILE`; submit a completed entry with `norn submit`.\n",
		len(env.Sigs), rotateSignerThreshold(observed.State))
	return writeEntry(raw, *out)
}

// Rotation reads the same WireGuard formats as enrollment, but has no key
// generation path: installing the private key remains the device's job.
func rotateWireGuardKey(path, public string) ([]byte, error) {
	if public != "" {
		return wgkey.Parse(public)
	}
	private, err := wgkey.ReadPrivate(path)
	if err != nil {
		return nil, err
	}
	return wgkey.Public(private)
}

// A device signature resolves only to this device's current identity or the
// incoming identity named in the body. Signers resolve against the log state.
func rotateRoleKey(st *state.State, d state.Device, incoming []byte, role, kid string) ([]byte, error) {
	var encoded string
	switch role {
	case "signer":
		encoded = st.Signers[kid]
	case "device":
		if len(incoming) == ed25519.PublicKeySize && entry.Kid(incoming) == kid {
			return incoming, nil
		}
		encoded = d.DevicePk
	default:
		return nil, fmt.Errorf("rotation cannot be signed with role %q: use device or signer", role)
	}
	public, err := hex.DecodeString(encoded)
	if err != nil || len(public) != ed25519.PublicKeySize || entry.Kid(public) != kid {
		if role == "device" {
			return nil, fmt.Errorf("key %s does not match the device's current device_pk %s or its incoming identity key", kid, d.DevicePk)
		}
		return nil, fmt.Errorf("key %s is not a signer in the observed log", kid)
	}
	return public, nil
}

func checkRotateSignatures(env *entry.Envelope, st *state.State, d state.Device) error {
	incoming, _ := env.Body["device_pk"].([]byte)
	for _, sig := range env.Sigs {
		public, err := rotateRoleKey(st, d, incoming, sig.Role, sig.Kid)
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

func rotateSignerThreshold(st *state.State) uint64 {
	if st.Params["rotate_needs_signer"] == true {
		return st.SignerThr
	}
	return 0
}

func printRotateSummary(env *entry.Envelope, anchor *trust.Trust, st *state.State, d state.Device,
	kid, role, keySource, incomingSource string, fresh bool) {
	w := os.Stderr
	action := "APPEND A SIGNATURE TO"
	if fresh {
		action = "SIGN A NEW"
	}
	fmt.Fprintf(w, "%s ROTATE ENTRY\n", action)
	// Names and key comments are free text; quoting keeps control characters
	// from forging or hiding the fields the operator is about to approve.
	fmt.Fprintf(w, "  network    %q (%x)\n", anchor.Name, env.Net)
	if fp, err := anchor.Fingerprint(); err == nil {
		fmt.Fprintf(w, "  anchor     %s\n", fp)
	}
	fmt.Fprintf(w, "  version    %d\n  timestamp  %d\n", env.V, env.TS)
	fmt.Fprintf(w, "  device     %q\n", env.Body["device_id"])
	fmt.Fprintf(w, "  current device key %s\n", d.DevicePk)
	oldWG, _ := hex.DecodeString(d.WgPk)
	fmt.Fprintf(w, "  current wireguard  %s\n", wgkey.Format(oldWG))
	fmt.Fprintf(w, "  new wireguard      %s\n", wgkey.Format(env.Body["wg_pk"].([]byte)))
	if incoming, ok := env.Body["device_pk"].([]byte); ok {
		fmt.Fprintf(w, "  incoming device key %x\n", incoming)
		if incomingSource != "" {
			fmt.Fprintf(w, "  signing as %s  role device  (%q; incoming identity)\n", entry.Kid(incoming), incomingSource)
		}
	}
	fmt.Fprintf(w, "  signing as %s  role %s  (%q)\n", kid, role, keySource)
	required := rotateSignerThreshold(st)
	setting := "off"
	if st.Params["rotate_needs_signer"] == true {
		setting = "on"
	}
	fmt.Fprintf(w, "  rotate_needs_signer %s; needs %d signer signature(s)\n", setting, required)
	if env.After != nil {
		fmt.Fprintf(w, "  after      %d\n", *env.After)
	} else {
		fmt.Fprintln(w, "  after      (none — no ordering guard; the log may place this entry anywhere)")
	}
	printPrevSummary(w, env)
	if raw, err := entry.Encode(env); err == nil {
		fmt.Fprintf(w, "  entry hash %x\n", entry.EntryHash(raw))
	}
}
