// Package tlogstore writes a Norn log as a static tlog-tiles directory.
//
// It writes the layout rather than adopting Tessera, which would pull 135
// modules including Google Cloud Spanner and Storage into a project whose
// pitch is that it runs on a NAS and a Pi; see D-049 for the measurement and
// the upgrade trigger. Ground rule 3 is untouched by that choice: it requires
// the *formats* to interoperate, which 2.6 tests directly by having an
// unmodified witness cosign one of these checkpoints.
//
// Durability is write-to-temp-then-rename. The checkpoint is written last, so
// a crash mid-append leaves a directory whose checkpoint describes a prefix of
// what is on disk -- never the reverse, which would advertise entries a reader
// cannot fetch.
package tlogstore

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	upstream "golang.org/x/mod/sumdb/tlog"

	"github.com/onembyte/norn/internal/tlog"
)

// ErrStore reports a corrupt or unreadable log directory.
var ErrStore = errors.New("log store error")

func storeErrorf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrStore, fmt.Sprintf(format, args...))
}

// A Cosigner turns a log-signed checkpoint into a cosigned one -- SPEC §6,
// `c2sp.org/tlog-cosignature`. A log that serves an uncosigned head serves one
// that §10 step 3 makes every correctly-configured verifier refuse, so the
// store treats corroboration as part of publishing rather than as something
// that happens afterwards.
//
// The store deliberately does not know *how*: a real log asks its witnesses
// over `c2sp.org/tlog-witness` (4.3), a test holds the witness keys itself.
// Keeping that behind an interface is what lets the HTTP client arrive later
// without the store learning about HTTP.
type Cosigner interface {
	// Cosign returns the signed note with cosignature lines appended. It must
	// not alter the body or the log's own signature.
	Cosign(signed string) (string, error)
}

// CosignerFunc adapts a function to Cosigner.
type CosignerFunc func(signed string) (string, error)

func (f CosignerFunc) Cosign(signed string) (string, error) { return f(signed) }

// Store is an append-only log on disk, served as static files.
type Store struct {
	dir      string
	origin   string
	key      ed25519.PrivateKey
	tree     *tlog.Tree
	bundle   [][]byte // entries of the tile currently being filled
	cosigner Cosigner
}

// An Option configures a store at open time.
type Option func(*Store)

// WithCosigner attaches the cosigner every published checkpoint passes
// through. A store without one publishes a bare log-signed head, which is
// correct only for a network whose policy asks for no corroboration.
//
// It is an open-time option rather than a setter because the store republishes
// its head on open: a log that gains a witness must serve a corroborated
// checkpoint immediately, not from its next append onwards.
func WithCosigner(c Cosigner) Option {
	return func(s *Store) { s.cosigner = c }
}

// Open opens or creates a log directory and recovers its state.
//
// The key signs every checkpoint this store publishes. SPEC §6 says the
// checkpoint *is* a signed note, so a store without a key could only publish
// something no verifier is allowed to believe -- and an unsigned file sitting
// at `checkpoint` is worse than none, because a verifier that forgot to check
// would read it happily.
func Open(dir, origin string, key ed25519.PrivateKey, opts ...Option) (*Store, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, storeErrorf("a log needs its signing key to publish checkpoints (§6)")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	s := &Store{dir: dir, origin: origin, key: key, tree: &tlog.Tree{}}
	for _, opt := range opts {
		opt(s)
	}
	if err := s.recover(); err != nil {
		return nil, err
	}
	// Republish the head under this store's current configuration. The file on
	// disk was written by whatever was running last, which may have had no
	// witness, a different one, or an older key.
	if err := s.publishCheckpoint(); err != nil {
		return nil, err
	}
	return s, nil
}

// Republish writes the current head again, passing it through the cosigner.
//
// Two things need this. A log wires its witness client *after* opening the
// store -- the client needs consistency proofs from the tree the store holds,
// so one of the two has to be built first -- and without a second publish the
// head opened with would stay uncosigned until the next append. And a quiet
// log has to refresh its cosignatures anyway: witness time is what every node
// measures freshness against (`GOSSIP.md` part 5), so a log that stops asking
// makes the whole network degrade without anything being wrong.
func (s *Store) Republish() error { return s.publishCheckpoint() }

// publishCheckpoint writes the current head as the file a verifier reads.
func (s *Store) publishCheckpoint() error {
	signed, err := s.SignedCheckpoint()
	if err != nil {
		return err
	}
	return s.writeFile("checkpoint", []byte(signed))
}

// SignedCheckpoint is the current head as the note §6 requires: signed by the
// log, and cosigned by the witnesses if this log has any.
func (s *Store) SignedCheckpoint() (string, error) {
	signed, err := s.Checkpoint().Sign(s.key)
	if err != nil || s.cosigner == nil {
		return signed, err
	}
	cosigned, err := s.cosigner.Cosign(signed)
	if err != nil {
		// A cosigner that fails is a cosigner that is broken, not a witness
		// that is down: `witness.Submitter` returns the head with whatever it
		// collected and reports the rest, because `GOSSIP.md`'s T6 says a
		// witness outage must not stop the log. So an error reaching here
		// means the signing itself failed, and publishing a head that claims
		// corroboration it does not have would be worse than not publishing.
		return "", storeErrorf("cosigning the head failed: %v", err)
	}
	return cosigned, nil
}

// recover rebuilds the tree from the entry bundles on disk. The bundles are the
// authoritative record: tiles and the checkpoint are derived, so a torn write
// to either is repaired simply by writing them again.
func (s *Store) recover() error {
	for index := int64(0); ; index++ {
		entries, err := s.readBundle(index)
		if err != nil {
			return err
		}
		if len(entries) == 0 {
			return nil
		}
		for _, raw := range entries {
			if err := s.tree.Append(raw); err != nil {
				return err
			}
		}
		if len(entries) < tlog.TileWidth {
			s.bundle = entries // a partial bundle: keep filling it
			return nil
		}
	}
}

func (s *Store) readBundle(index int64) ([][]byte, error) {
	base := filepath.Join(s.dir, filepath.FromSlash(tlog.EntryBundlePath(index, tlog.TileWidth)))

	raw, err := os.ReadFile(base)
	if err == nil {
		return decodeBundle(raw)
	}
	if !os.IsNotExist(err) {
		return nil, err
	}
	// A partial bundle carries its width in the path, and the width is not
	// known until the file is found -- so look, rather than guess.
	matches, err := filepath.Glob(base + ".p" + string(filepath.Separator) + "*")
	if err != nil || len(matches) == 0 {
		return nil, nil
	}
	raw, err = os.ReadFile(matches[0])
	if err != nil {
		return nil, err
	}
	return decodeBundle(raw)
}

// Bundles are sequences of big-endian uint16 length-prefixed entries (§6).
func encodeBundle(entries [][]byte) []byte {
	var out []byte
	for _, raw := range entries {
		var header [2]byte
		binary.BigEndian.PutUint16(header[:], uint16(len(raw)))
		out = append(out, header[:]...)
		out = append(out, raw...)
	}
	return out
}

func decodeBundle(raw []byte) ([][]byte, error) {
	var out [][]byte
	for len(raw) > 0 {
		if len(raw) < 2 {
			return nil, storeErrorf("truncated entry bundle")
		}
		n := int(binary.BigEndian.Uint16(raw[:2]))
		if len(raw) < 2+n {
			return nil, storeErrorf("entry bundle claims %d bytes but has %d", n, len(raw)-2)
		}
		out = append(out, raw[2:2+n])
		raw = raw[2+n:]
	}
	return out, nil
}

// Size is the number of entries in the log.
func (s *Store) Size() int64 { return s.tree.Size() }

// Checkpoint is the current tree head.
func (s *Store) Checkpoint() tlog.Checkpoint { return s.tree.Checkpoint(s.origin) }

// Append adds one entry and republishes the files it affects, returning the
// index it was given.
func (s *Store) Append(raw []byte) (int64, error) {
	if len(raw) > 0xffff {
		return 0, storeErrorf("entry exceeds the uint16 length prefix")
	}
	index := s.tree.Size()
	if err := s.tree.Append(raw); err != nil {
		return 0, err
	}
	s.bundle = append(s.bundle, raw)

	bundleIndex := index / tlog.TileWidth
	if err := s.writeFile(tlog.EntryBundlePath(bundleIndex, len(s.bundle)),
		encodeBundle(s.bundle)); err != nil {
		return 0, err
	}
	if len(s.bundle) == tlog.TileWidth {
		// The full bundle supersedes every partial version of itself.
		_ = os.RemoveAll(filepath.Join(s.dir,
			filepath.FromSlash(tlog.EntryBundlePath(bundleIndex, tlog.TileWidth))+".p"))
		s.bundle = nil // the next entry starts a new bundle
	}
	if err := s.writeTiles(); err != nil {
		return 0, err
	}
	// The checkpoint goes last: a crash before it leaves a log whose
	// advertised size is behind what is on disk, never ahead of it.
	if err := s.publishCheckpoint(); err != nil {
		return 0, err
	}
	return index, nil
}

// writeTiles republishes every tile the current size touches. At Norn's scale
// this is a handful of files; a log large enough for that to matter is a log
// large enough for Tessera (D-049).
// writeTiles republishes every tile the current size touches, using the same
// computation the verifier checks them with (tlog.Tree.Tiles).
func (s *Store) writeTiles() error {
	tiles, err := s.tree.Tiles()
	if err != nil {
		return err
	}
	for _, tile := range tiles {
		if err := s.writeFile(tile.Path(), tile.Data); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) writeFile(rel string, data []byte) error {
	path := filepath.Join(s.dir, filepath.FromSlash(rel))
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if filepath.Base(dir) != "" && filepath.Ext(filepath.Dir(rel)) == ".p" {
		stale, _ := filepath.Glob(filepath.Join(dir, "*"))
		for _, old := range stale {
			if old != path {
				_ = os.Remove(old)
			}
		}
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// Entry returns the entry at an index, read back from the served bundles.
func (s *Store) Entry(index int64) ([]byte, error) {
	entries, err := s.readBundle(index / tlog.TileWidth)
	if err != nil {
		return nil, err
	}
	offset := int(index % tlog.TileWidth)
	if offset >= len(entries) {
		return nil, storeErrorf("no entry at index %d", index)
	}
	return entries[offset], nil
}

// InclusionProof proves an entry is in the log at its current size.
func (s *Store) InclusionProof(index int64) (upstream.RecordProof, error) {
	return s.tree.InclusionProof(index)
}

// ConsistencyProof proves the log at an earlier size is a prefix of this one.
func (s *Store) ConsistencyProof(older int64) (upstream.TreeProof, error) {
	return s.tree.ConsistencyProof(older)
}

// Cosigners runs several cosigners in order, each adding to what the last
// produced. A log that both holds a witness key locally and asks others over
// the network needs all of them on the checkpoint; two separate WithCosigner
// options would mean the second silently replaced the first.
func Cosigners(all ...Cosigner) Cosigner {
	return CosignerFunc(func(signed string) (string, error) {
		out := signed
		for _, one := range all {
			next, err := one.Cosign(out)
			if err != nil {
				return "", err
			}
			out = next
		}
		return out, nil
	})
}
