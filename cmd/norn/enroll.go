package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/onembyte/norn/internal/enrollreq"
	"github.com/onembyte/norn/internal/entry"
	"github.com/onembyte/norn/internal/keyfile"
	"github.com/onembyte/norn/internal/qrterm"
	"github.com/onembyte/norn/internal/trust"
	"github.com/onembyte/norn/internal/wgkey"
)

// DefaultKeyDir is where a device keeps its identity (`ENROLLMENT.md` part 3).
const DefaultKeyDir = "/var/lib/norn"

func enrollCmd(args []string) error {
	fs := newFlagSet("enroll")
	name := fs.String("name", "", "device_id to request (required)")
	net := fs.String("net", "", "the network's origin (norn/…) or its 32 hex digits")
	trustPath := fs.String("trust", "", "a norn.trust to take the network from")
	keyPath := fs.String("key", filepath.Join(DefaultKeyDir, "device.key"),
		"the device identity key; created if absent")
	wgPath := fs.String("wg-key", "", "a WireGuard private key file to enrol the public half of")
	wgPublic := fs.String("wg-pub", "", "a WireGuard public key, base64")
	gen := fs.Bool("gen", false, "generate a WireGuard key beside the device key")
	expires := fs.String("expires", "", "how long the enrolment should last, e.g. 30d")
	qr := fs.Bool("qr", false, "print the QR even when the output is not a terminal")
	noQR := fs.Bool("no-qr", false, "never print the QR")
	chosen := labels{}
	fs.Var(chosen, "label", "a `key=value` label; may be repeated")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *name == "" {
		fs.Usage()
		return fmt.Errorf("-name is required: a request has to say which device it is for")
	}

	netID, err := resolveNet(*net, *trustPath)
	if err != nil {
		return err
	}
	device, created, err := deviceKey(*keyPath)
	if err != nil {
		return err
	}
	wgPub, wgSource, err := wireguardKey(*wgPath, *wgPublic, *gen, *keyPath)
	if err != nil {
		return err
	}

	now := time.Now().Unix()
	var expiry *uint64
	if *expires != "" {
		span, err := parseSpan(*expires)
		if err != nil {
			return err
		}
		at := uint64(time.Now().Add(span).Unix())
		expiry = &at
	}

	request, err := enrollreq.New(netID, *name,
		device.Public().(ed25519.PublicKey), wgPub, uint64(now), chosen, expiry)
	if err != nil {
		return err
	}
	if err := enrollreq.Sign(request, device); err != nil {
		return err
	}
	// Check our own work before a human is asked to act on it: a request that
	// does not verify is a bug here, and it must not leave the machine.
	if err := enrollreq.Check(request, netID); err != nil {
		return fmt.Errorf("the request this command just built does not verify: %w", err)
	}

	text, err := enrollreq.Text(request)
	if err != nil {
		return err
	}

	// The request goes to stdout and nothing else does, so `norn enroll … >
	// request.txt` gives exactly the request. Everything for a human is on
	// stderr, where it cannot corrupt that file.
	printRequestSummary(request, *keyPath, created, wgSource, text)
	if !*noQR && (*qr || isTerminal(os.Stderr)) {
		drawing, err := qrterm.Encode(strings.ToUpper(text))
		if err != nil {
			return err
		}
		fmt.Fprint(os.Stderr, "\n", drawing)
	}
	fmt.Println(text)
	return nil
}

func resolveNet(origin, trustPath string) ([]byte, error) {
	var fromTrust, fromFlag []byte
	if trustPath != "" {
		raw, err := os.ReadFile(trustPath)
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
		fromTrust = anchor.Net
	}
	if origin != "" {
		var err error
		if strings.HasPrefix(origin, "norn/") {
			fromFlag, err = trust.NetFromOrigin(origin)
		} else {
			fromFlag, err = hex.DecodeString(origin)
			if err == nil && len(fromFlag) != 16 {
				err = fmt.Errorf("a net_id is 16 bytes, got %d", len(fromFlag))
			}
		}
		if err != nil {
			return nil, fmt.Errorf("-net: %w", err)
		}
	}

	switch {
	case fromTrust == nil && fromFlag == nil:
		return nil, fmt.Errorf("-net or -trust is required: a request names the network " +
			"it is for, and a device enrolling for the first time has no trust file yet")
	case fromTrust != nil && fromFlag != nil && string(fromTrust) != string(fromFlag):
		return nil, fmt.Errorf("-net and -trust name different networks; refusing to guess")
	case fromTrust != nil:
		return fromTrust, nil
	default:
		return fromFlag, nil
	}
}

// deviceKey loads the device identity, creating it on first use.
func deviceKey(path string) (ed25519.PrivateKey, bool, error) {
	if _, err := os.Stat(path); err == nil {
		key, _, err := keyfile.Read(path)
		return key, false, err
	} else if !os.IsNotExist(err) {
		return nil, false, fmt.Errorf("reading the device key: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, false, fmt.Errorf("creating %s: %w", filepath.Dir(path), err)
	}
	_, key, err := keyfile.Generate()
	if err != nil {
		return nil, false, err
	}
	if err := keyfile.Write(path, key, "norn device key"); err != nil {
		return nil, false, err
	}
	return key, true, nil
}

// wireguardKey resolves the public key to enrol, and says where it came from.
func wireguardKey(path, public string, gen bool, keyPath string) ([]byte, string, error) {
	given := 0
	for _, set := range []bool{path != "", public != "", gen} {
		if set {
			given++
		}
	}
	if given != 1 {
		return nil, "", fmt.Errorf("give exactly one of -wg-key (a private key file), " +
			"-wg-pub (a public key) or -gen (make a new pair)")
	}

	switch {
	case public != "":
		key, err := wgkey.Parse(public)
		if err != nil {
			return nil, "", err
		}
		return key, "-wg-pub", nil
	case path != "":
		private, err := wgkey.ReadPrivate(path)
		if err != nil {
			return nil, "", err
		}
		key, err := wgkey.Public(private)
		if err != nil {
			return nil, "", err
		}
		return key, path, nil
	default:
		target := filepath.Join(filepath.Dir(keyPath), "wg.key")
		private, key, err := wgkey.Generate()
		if err != nil {
			return nil, "", err
		}
		if err := wgkey.WritePrivate(target, private); err != nil {
			return nil, "", err
		}
		return key, "created " + target, nil
	}
}

func printRequestSummary(request *enrollreq.Request, keyPath string, created bool,
	wgSource, text string) {
	out := os.Stderr
	fmt.Fprintf(out, "ENROLLMENT REQUEST for %s\n", request.DeviceID)
	origin, err := trust.OriginFor(request.Net)
	if err == nil {
		fmt.Fprintf(out, "  network    %s\n", origin)
	}
	state := "existing"
	if created {
		state = "created"
	}
	fmt.Fprintf(out, "  device key %s  (%s, %s)\n",
		entry.Kid(request.DevicePK), keyPath, state)
	fmt.Fprintf(out, "  wireguard  %s  (%s)\n", wgkey.Format(request.WGPK), wgSource)
	for _, key := range sortedKeys(request.Labels) {
		fmt.Fprintf(out, "  label      %s=%s\n", key, request.Labels[key])
	}
	if request.Expires != nil {
		at := time.Unix(int64(*request.Expires), 0)
		fmt.Fprintf(out, "  expires    %s\n", at.Format(time.RFC3339))
	}
	fmt.Fprintf(out, "\nGive this to a signer. It proves possession of the device key;\n"+
		"the WireGuard key is X25519 and cannot sign, so nothing here proves\n"+
		"the device holds it (SPEC §16.1).\n")
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for key := range m {
		out = append(out, key)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// isTerminal reports whether f is a character device, so the QR is drawn for a
// person and never into a pipe or a file.
func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}
