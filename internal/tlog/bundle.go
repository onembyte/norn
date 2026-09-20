package tlog

import (
	"encoding/binary"
	"fmt"
)

// EncodeBundle frames entries as `tlog-tiles` entry-bundle bytes: each entry
// preceded by its length as a big-endian uint16.
func EncodeBundle(entries [][]byte) []byte {
	var out []byte
	for _, raw := range entries {
		var header [2]byte
		binary.BigEndian.PutUint16(header[:], uint16(len(raw)))
		out = append(out, header[:]...)
		out = append(out, raw...)
	}
	return out
}

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
