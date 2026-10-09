// Package tslocal reads tailscaled's LocalAPI without linking tailscale.com.
package tslocal

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/onembyte/norn/internal/peertable"
)

// DefaultSocket is tailscaled's usual Unix socket on Linux.
const DefaultSocket = "/var/run/tailscale/tailscaled.sock"

// notifyPeerWireGuardState is ipn.NotifyPeerWireGuardState (1 << 9).
// U6 must validate this option and the JSON contract against a real tailscaled.
const notifyPeerWireGuardState = 512

// ErrReadOnly explains why this source cannot be used to enforce.
var ErrReadOnly = errors.New("tslocal: observe only (D-014): tailscaled has no UAPI; eviction would require patching tailscaled")

// Device relies on GET /localapi/v0/status: Self.PublicKey, the keys of
// Peer, and each Peer[key].PublicKey. All keys must be nodekey:<64 hex digits>,
// and the map key must equal the entry's PublicKey. No routing or endpoint
// fields are read, so returned peers describe key membership only.
//
// GET /localapi/v0/watch-ipn-bus?mask=512 requests NotifyPeerWireGuardState.
// Its body is a stream of JSON notification objects. No notification fields
// are interpreted: every object invalidates the status snapshot, and the
// reader fetches status to identify added, changed or removed keys. This avoids
// treating incremental notification payloads as a complete peer table. Neither
// endpoint nor this mask/JSON contract has been validated against tailscaled
// here; that is user row U6, including the timing of status after notification.
type Device struct {
	client *http.Client
	socket string
}

// New permits a test transport so observing needs no listening socket.
// A nil transport dials only the configured Unix socket, never TCP or a proxy.
func New(socket string, transport http.RoundTripper) *Device {
	if socket == "" {
		socket = DefaultSocket
	}
	if transport == nil {
		transport = &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "unix", socket)
		}, ResponseHeaderTimeout: 5 * time.Second}
	}
	return &Device{client: &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, socket: socket}
}

// Open refuses an unavailable or malformed status before the daemon starts.
func Open(socket string) (*Device, error) {
	d := New(socket, nil)
	if _, err := d.status(); err != nil {
		d.client.CloseIdleConnections()
		return nil, err
	}
	return d, nil
}

// Close releases idle HTTP connections. The watch is owned by its context.
func (d *Device) Close() error { d.client.CloseIdleConnections(); return nil }

func (d *Device) get(ctx context.Context, path string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://local-tailscaled.sock"+path, nil)
	if err != nil {
		return nil, err
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("tslocal: %s via %s: %w", path, d.socket, err)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("tslocal: %s via %s: HTTP %s", path, d.socket, resp.Status)
	}
	return resp, nil
}

type peerStatus struct{ PublicKey string }
type status struct {
	Self *peerStatus
	Peer map[string]*peerStatus
}

func (d *Device) status() (*status, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := d.get(ctx, "/localapi/v0/status")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var st status
	dec := json.NewDecoder(io.LimitReader(resp.Body, 16<<20))
	if err := dec.Decode(&st); err != nil {
		return nil, fmt.Errorf("tslocal: decoding status: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, errors.New("tslocal: status has trailing or oversized JSON")
	}
	if st.Self == nil {
		return nil, errors.New("tslocal: status lacks Self.PublicKey")
	}
	if _, err := ParseNodeKey(st.Self.PublicKey); err != nil {
		return nil, fmt.Errorf("tslocal: Self.PublicKey: %w", err)
	}
	for text, peer := range st.Peer {
		if _, err := ParseNodeKey(text); err != nil {
			return nil, err
		}
		if peer == nil || peer.PublicKey != text {
			return nil, fmt.Errorf("tslocal: Peer[%q].PublicKey is missing or inconsistent", text)
		}
	}
	return &st, nil
}

// ParseNodeKey refuses anything other than tailscaled's full node public key.
func ParseNodeKey(text string) (peertable.Key, error) {
	if !strings.HasPrefix(text, "nodekey:") || len(text) != 8+2*peertable.KeyLen {
		return peertable.Key{}, fmt.Errorf("tslocal: malformed node public key %q", text)
	}
	raw, err := hex.DecodeString(text[8:])
	if err != nil {
		return peertable.Key{}, fmt.Errorf("tslocal: malformed node public key %q: %w", text, err)
	}
	return peertable.KeyFromBytes(raw)
}

// OwnKey reads the local key so the agent does not expect itself as a peer.
func (d *Device) OwnKey() (peertable.Key, error) {
	st, err := d.status()
	if err != nil {
		return peertable.Key{}, err
	}
	return ParseNodeKey(st.Self.PublicKey)
}

// Peers reads the authoritative current snapshot, including removals. Polling
// remains useful for recovery if a peer changed before the watch opened.
func (d *Device) Peers() ([]peertable.Peer, error) {
	st, err := d.status()
	if err != nil {
		return nil, err
	}
	out := make([]peertable.Peer, 0, len(st.Peer))
	for text := range st.Peer {
		key, err := ParseNodeKey(text)
		if err != nil {
			return nil, err
		}
		out = append(out, peertable.Peer{Key: key})
	}
	return peertable.Sorted(out), nil
}

// The write methods always refuse, including empty requests. A mistaken mode
// must not succeed just because it happened to have nothing to change.
func (d *Device) Replace([]peertable.Peer) error         { return ErrReadOnly }
func (d *Device) Remove([]peertable.Key) error           { return ErrReadOnly }
func (d *Device) UpdateEndpoints([]peertable.Peer) error { return ErrReadOnly }

// Watch reports nil for each notification and an error if the stream fails.
// Its buffered wakeup may coalesce notifications; status supplies the current
// set, not a history of peers that disappeared before a status read.
func (d *Device) Watch(ctx context.Context) (<-chan error, error) {
	resp, err := d.get(ctx, fmt.Sprintf("/localapi/v0/watch-ipn-bus?mask=%d", notifyPeerWireGuardState))
	if err != nil {
		return nil, err
	}
	events := make(chan error, 1)
	go func() {
		defer close(events)
		defer resp.Body.Close()
		dec := json.NewDecoder(resp.Body)
		for {
			var notification map[string]json.RawMessage
			err := dec.Decode(&notification)
			if err == nil && notification == nil {
				err = errors.New("notification is not a JSON object")
			}
			if err != nil {
				if ctx.Err() == nil {
					select {
					case events <- fmt.Errorf("tslocal: IPN bus via %s: %w", d.socket, err):
					case <-ctx.Done():
					}
				}
				return
			}
			select {
			case events <- nil:
			default:
			}
		}
	}()
	return events, nil
}

var _ peertable.Device = (*Device)(nil)
