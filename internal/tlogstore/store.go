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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"

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
		return tlog.DecodeBundle(raw)
	}
	if !os.IsNotExist(err) {
		return nil, err
	}
	// A partial bundle carries its width in the path, and the width is not
	// known until the file is found -- so look, rather than guess. What a
	// crash can leave in that directory decides how to look (SEC-011): a
	// temporary file, dot-prefixed, is never a bundle; two widths side by
	// side mean the crash fell between writing the new one and removing the
	// old, and the log is the wider; and a name is only a claim, so a file
	// counts only if it decodes to exactly the width its name gives. Reading
	// the first glob match took an empty temporary for the bundle and
	// reopened a five-entry log at size zero.
	names, err := os.ReadDir(base + ".p")
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var widths []int
	for _, name := range names {
		if strings.HasPrefix(name.Name(), ".") || name.IsDir() {
			continue
		}
		width, err := strconv.Atoi(name.Name())
		if err != nil || width < 1 || width >= tlog.TileWidth {
			continue
		}
		widths = append(widths, width)
	}
	sort.Sort(sort.Reverse(sort.IntSlice(widths)))
	for _, width := range widths {
		raw, err := os.ReadFile(filepath.Join(base+".p", strconv.Itoa(width)))
		if err != nil {
			return nil, err
		}
		entries, err := tlog.DecodeBundle(raw)
		if err != nil || len(entries) != width {
			continue // torn, or a name lying about its width
		}
		return entries, nil
	}
	if len(widths) > 0 {
		return nil, storeErrorf("%s.p holds no bundle that decodes to its name's width; "+
			"the log's tail is damaged and must be restored before this log serves", base)
	}
	return nil, nil
}

// Bundles are sequences of big-endian uint16 length-prefixed entries (§6).
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
	framed, err := tlog.EncodeBundle(s.bundle)
	if err != nil {
		return 0, err
	}
	if err := s.writeFile(tlog.EntryBundlePath(bundleIndex, len(s.bundle)), framed); err != nil {
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
		if tile.Width == tlog.TileWidth {
			// A full path supersedes the partial-width directory for this tile.
			// Without removing it, a log that crosses 256 leaves serves both
			// tile/0/000.p/255 and tile/0/000, leaving an obsolete path beside
			// the canonical one (D12).
			partial := filepath.Join(s.dir,
				filepath.FromSlash(tlog.TilePath(tile.Level, tile.Index, tlog.TileWidth))+".p")
			if err := os.RemoveAll(partial); err != nil {
				return fmt.Errorf("remove superseded partial tile %s: %w", partial, err)
			}
		}
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
	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	// Only now, with the new partial in place, do the older widths go: a
	// crash between the two steps leaves the log longer than it should look,
	// never shorter, and readBundle picks the wider (SEC-011). Removing first
	// left an empty directory, which reopened the log at the last full
	// bundle -- size zero for any log under 256 entries.
	if filepath.Ext(filepath.Dir(rel)) == ".p" {
		stale, _ := filepath.Glob(filepath.Join(dir, "*"))
		for _, old := range stale {
			if old != path {
				_ = os.Remove(old)
			}
		}
	}
	return syncDir(dir)
}

// syncDir flushes a directory's entries, so a rename survives a power cut.
// Windows cannot open a directory for writing and orders its metadata
// itself, so there it is skipped, as internal/durable does.
func syncDir(dir string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
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
