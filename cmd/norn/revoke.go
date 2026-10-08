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

// SPEC §4.0 caps reason in bytes, as internal/replay's maxReason does.
const maxRevokeReason = 256

func revokeCmd(args []string) error {
	fs := newFlagSet("revoke")
	trustPath := fs.String("trust", "", "path to norn.trust (required)")
	deviceID := fs.String("device", "", "the device id to revoke (required)")
	reason := fs.String("reason", "", "why the device is being revoked (at most 256 bytes)")
	keyPath := fs.String("key", "", "an OpenSSH private key file to sign with")
	agentKid := fs.String("agent-kid", "", "sign with this `kid` from the ssh-agent")
	role := fs.String("role", "signer", "the role to sign as: signer, root or device")
	logLocation := fs.String("log", "", "log URL or directory; defaults to the anchor's log_urls")
	after := fs.Int64("after", -1, "the log size this signature assumes (§4.4)")
	noAfter := fs.Bool("no-after", false, "sign without an `after` guard, and say why in the summary")
	in := fs.String("in", "", "an existing revoke entry to extend (or - for stdin)")
	out := fs.String("o", "", "write the entry here instead of stdout")
	yes := fs.Bool("yes", false, "do not ask for confirmation")
	if err := fs.Parse(args); err != nil {
		return err
	}
	// As with sign, refuse scripted root authority before reading any input.
	if *yes && *role == "root" {
		return errors.New("--yes cannot be combined with --role root: a root's " +
			"authority is never exercised by a script")
	}
	if *trustPath == "" {
		return errors.New("-trust is required: signing means deciding for a network, and the anchor is what names it")
	}
	if *deviceID == "" {
		return errors.New("-device is required: name the device to revoke")
	}
	if !entry.Roles[*role] {
		return errors.New("-role must be signer, root or device")
	}
	if _, err := fields.DeviceID(*deviceID); err != nil {
		return err
	}
	if _, err := fields.Text(*reason, maxRevokeReason, "reason"); err != nil {
		return err
	}
	if fs.NArg() > 1 || (fs.NArg() == 1 && *in != "") {
		return errors.New("give at most one existing entry, using -in FILE or a positional file (or - for stdin)")
	}
	if fs.NArg() == 1 {
		*in = fs.Arg(0)
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
		if *in == "" && *after < 0 && !*noAfter {
			return fmt.Errorf("could not read the log to learn its size (%w).\n"+
				"Pass -after N with the size you observed, or -no-after to sign without "+
				"the §4.4 ordering guard; revocation still requires a verified log to check the device and signing role", logErr)
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
	roleKey, err := revokeRoleKey(observed.State, d, *role, entry.Kid(public))
	if err != nil {
		return err
	}
	if !bytes.Equal(public, roleKey) {
		return fmt.Errorf("key %s does not match the observed %s public key", entry.Kid(public), *role)
	}

	fresh := *in == ""
	var env *entry.Envelope
	if fresh {
		body := map[string]any{"device_id": *deviceID}
		if *reason != "" {
			body["reason"] = *reason
		}
		env = &entry.Envelope{V: entry.Version, T: "revoke", Net: anchor.Net,
			TS: uint64(time.Now().Unix()), Body: body}
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
		if env.T != "revoke" {
			return fmt.Errorf("this command signs `revoke` entries, not %q", env.T)
		}
		if !bytes.Equal(env.Net, anchor.Net) {
			return errors.New("the entry is for another network")
		}
		// The body is closed, and flags cannot silently replace fields another
		// signer approved. Even an explicit empty reason must agree with it.
		for key := range env.Body {
			if key != "device_id" && key != "reason" {
				return fmt.Errorf("the revoke body contains unknown field %q", key)
			}
		}
		if env.Body["device_id"] != *deviceID {
			return errors.New("the entry's device_id does not match -device")
		}
		entryReason := ""
		if value, present := env.Body["reason"]; present {
			entryReason, err = fields.Text(value, maxRevokeReason, "reason")
			if err != nil {
				return err
			}
		}
		reasonGiven := false
		fs.Visit(func(f *flag.Flag) { reasonGiven = reasonGiven || f.Name == "reason" })
		if reasonGiven && *reason != entryReason {
			return errors.New("the entry's reason does not match -reason; existing signed fields cannot be changed")
		}
		*reason = entryReason
	}

	// Verify before the summary, then again after signing. Adding a signature
	// must neither bless a tampered input nor invalidate a previous approval.
	if err := checkRevokeSignatures(env, observed.State, d); err != nil {
		return err
	}
	printRevokeSummary(env, anchor, d, *reason, entry.Kid(public), *role, keySource, fresh)
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
	if err := checkRevokeSignatures(env, observed.State, d); err != nil {
		return err
	}
	raw, err := entry.Encode(env)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "\nSigned. %d signature(s); revocation needs %d signers, %d roots, or the device itself.\n"+
		"Extend with `norn revoke -in FILE`; submit a completed entry with `norn submit`.\n",
		len(env.Sigs), observed.State.SignerThr, observed.State.RootThr)
	return writeEntry(raw, *out)
}

// Resolve against the verified state, so a key cannot merely claim a role in
// its signature element. A device key is scoped to this one device.
func revokeRoleKey(st *state.State, d state.Device, role, kid string) ([]byte, error) {
	var encoded string
	switch role {
	case "signer":
		encoded = st.Signers[kid]
	case "root":
		encoded = st.Roots[kid]
	case "device":
		encoded = d.DevicePk
	}
	public, err := hex.DecodeString(encoded)
	if err != nil || len(public) != ed25519.PublicKeySize || entry.Kid(public) != kid {
		if role == "device" {
			return nil, fmt.Errorf("key %s does not match the device's device_pk %s in the observed log", kid, d.DevicePk)
		}
		return nil, fmt.Errorf("key %s is not a %s in the observed log", kid, role)
	}
	return public, nil
}

func checkRevokeSignatures(env *entry.Envelope, st *state.State, d state.Device) error {
	for _, sig := range env.Sigs {
		public, err := revokeRoleKey(st, d, sig.Role, sig.Kid)
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

func printRevokeSummary(env *entry.Envelope, anchor *trust.Trust, d state.Device,
	reason, kid, role, keySource string, fresh bool) {
	w := os.Stderr
	action := "APPEND A SIGNATURE TO"
	if fresh {
		action = "SIGN A NEW"
	}
	fmt.Fprintf(w, "%s REVOKE ENTRY\n", action)
	fmt.Fprintf(w, "  network    %s (%x)\n", anchor.Name, env.Net)
	if fp, err := anchor.Fingerprint(); err == nil {
		fmt.Fprintf(w, "  anchor     %s\n", fp)
	}
	fmt.Fprintf(w, "  version    %d\n  timestamp  %d\n", env.V, env.TS)
	fmt.Fprintf(w, "  device     %s\n", env.Body["device_id"])
	fmt.Fprintf(w, "  device key %s\n", d.DevicePk)
	wg, _ := hex.DecodeString(d.WgPk)
	fmt.Fprintf(w, "  wireguard  %s\n", wgkey.Format(wg))
	// Quote the reason so control characters cannot hide or forge the summary.
	fmt.Fprintf(w, "  reason     %q\n", reason)
	fmt.Fprintf(w, "  signing as %s  role %s  (%s)\n", kid, role, keySource)
	if env.After != nil {
		fmt.Fprintf(w, "  after      %d\n", *env.After)
	} else {
		fmt.Fprintln(w, "  after      (none — no ordering guard; the log may place this entry anywhere)")
	}
	if raw, err := entry.Encode(env); err == nil {
		fmt.Fprintf(w, "  entry hash %x\n", entry.EntryHash(raw))
	}
}
