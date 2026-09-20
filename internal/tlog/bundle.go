package tlog

import (
	"encoding/binary"
	"fmt"
)

// EncodeBundle frames entries as `tlog-tiles` entry-bundle bytes: each entry
// preceded by its length as a big-endian uint16.
func EncodeBundle(entries [][]byte) ([]byte, error) {
	var out []byte
	for i, raw := range entries {
		// The length header is 16 bits, so an entry of 65536 bytes or more
		// cannot be framed. Truncating it to `uint16` writes a header of zero
		// and produces a bundle that decodes as a different log, which is the
		// one outcome worse than refusing to serve: SPEC §4.0's
		// MAX_ENTRY_BYTES is 65535 for exactly this reason.
		if len(raw) > MaxBundleEntryBytes {
			return nil, fmt.Errorf("tlog: entry %d is %d bytes; an entry bundle cannot "+
				"frame more than %d", i, len(raw), MaxBundleEntryBytes)
		}
		var header [2]byte
		binary.BigEndian.PutUint16(header[:], uint16(len(raw)))
		out = append(out, header[:]...)
		out = append(out, raw...)
	}
	return out, nil
}

// MaxBundleEntryBytes is the largest entry a `tlog-tiles` entry bundle can
// carry: the most a uint16 length prefix can describe (SPEC §4.0, §6).
const MaxBundleEntryBytes = 65535

// DecodeBundle reads entry-bundle bytes back.
//
// One implementation, used by the log that writes bundles, the verifier that
// reads them and the node that mirrors them. Two decoders that disagree about
// a malformed bundle disagree about what the log contains, which is the one
// thing every part of this system has to agree on.
func DecodeBundle(raw []byte) ([][]byte, error) {
	var out [][]byte
	for len(raw) > 0 {
		if len(raw) < 2 {
			return nil, fmt.Errorf("truncated entry bundle")
		}
		n := int(binary.BigEndian.Uint16(raw[:2]))
		if len(raw) < 2+n {
			return nil, fmt.Errorf("entry bundle claims %d bytes but has %d", n, len(raw)-2)
		}
		out = append(out, raw[2:2+n])
		raw = raw[2+n:]
	}
	return out, nil
}
