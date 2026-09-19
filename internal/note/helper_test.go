package note_test

import "crypto/ed25519"

// ed25519From is a tiny helper so the interop tests read cleanly.
func ed25519From(seed []byte) ed25519.PrivateKey { return ed25519.NewKeyFromSeed(seed) }
