// Package sshwire is the SSH data-type encoding of RFC 4251 §5: length-prefixed
// strings and 32-bit integers, big-endian.
//
// It exists because two unrelated things in Norn speak it -- the agent protocol
// and the OpenSSH private-key file -- and because every length in it arrives
// from somewhere Norn does not control. A length prefix must never become a
// slice bound without a check, which is easy to get right once and easy to
// forget twice.
package sshwire

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// AppendString appends a length-prefixed string.
func AppendString(to, value []byte) []byte {
	to = binary.BigEndian.AppendUint32(to, uint32(len(value)))
	return append(to, value...)
}

// AppendUint32 appends a big-endian 32-bit integer.
func AppendUint32(to []byte, value uint32) []byte {
	return binary.BigEndian.AppendUint32(to, value)
}

// String splits one length-prefixed string off the front of b.
func String(b []byte) (value, rest []byte, err error) {
	if len(b) < 4 {
		return nil, nil, errors.New("sshwire: truncated length")
	}
	length := binary.BigEndian.Uint32(b[:4])
	if uint64(length) > uint64(len(b)-4) {
		return nil, nil, fmt.Errorf("sshwire: length %d runs past the end of %d bytes",
			length, len(b)-4)
	}
	return b[4 : 4+length], b[4+length:], nil
}

// Uint32 splits one big-endian 32-bit integer off the front of b.
func Uint32(b []byte) (value uint32, rest []byte, err error) {
	if len(b) < 4 {
		return 0, nil, errors.New("sshwire: truncated uint32")
	}
	return binary.BigEndian.Uint32(b[:4]), b[4:], nil
}
