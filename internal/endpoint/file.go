package endpoint

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"time"
)

// MaxFileBytes caps a hints file. It is written by another daemon, which makes
// it untrusted input like everything else that arrives from outside.
const MaxFileBytes = 8 << 20

// fileDocument is the on-disk shape of a hints file.
//
// Keyed by `device_id`, not by public key, and that is deliberate: identity in
// Norn comes from the log, so an adapter for a control plane has to map its
// own idea of a peer onto a device the log proves. That mapping is the
// adapter's problem, and doing it in the adapter is what keeps the control
// plane out of the business of naming keys.
type fileDocument struct {
	Peers map[string]struct {
		AllowedIPs []string `json:"allowed_ips"`
		Endpoint   string   `json:"endpoint"`
		Keepalive  int      `json:"keepalive"`
	} `json:"peers"`
}

// LoadFile reads a hints file written by another daemon.
//
// It returns a Static, so a caller re-reads it whenever it likes and nothing
// here holds a file handle or a cache: the file is somebody else's to change.
func LoadFile(path string) (Static, error) {
	info, err := os.Stat(path)
	if err != nil {
		return Static{}, fmt.Errorf("endpoint: %w", err)
	}
	if info.Size() > MaxFileBytes {
		return Static{}, fmt.Errorf("endpoint: %s is %d bytes, over the %d cap",
			path, info.Size(), MaxFileBytes)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return Static{}, fmt.Errorf("endpoint: %w", err)
	}

	var doc fileDocument
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&doc); err != nil {
		return Static{}, fmt.Errorf("endpoint: %s: %w", path, err)
	}

	peers := make(map[string]Hints, len(doc.Peers))
	for id, entry := range doc.Peers {
		var hints Hints
		for _, cidr := range entry.AllowedIPs {
			prefix, err := netip.ParsePrefix(cidr)
			if err != nil {
				return Static{}, fmt.Errorf("endpoint: %s: %s: %q is not a CIDR", path, id, cidr)
			}
			hints.AllowedIPs = append(hints.AllowedIPs, prefix)
		}
		if entry.Endpoint != "" {
			addr, err := netip.ParseAddrPort(entry.Endpoint)
			if err != nil {
				return Static{}, fmt.Errorf("endpoint: %s: %s: %q is not host:port", path, id, entry.Endpoint)
			}
			hints.Endpoint = addr
		}
		if entry.Keepalive < 0 {
			return Static{}, fmt.Errorf("endpoint: %s: %s: a negative keepalive", path, id)
		}
		hints.Keepalive = time.Duration(entry.Keepalive) * time.Second
		peers[id] = hints
	}
	return Static{Peers: peers}, nil
}
