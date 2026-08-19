package mtclient

import "crypto/rand"

// cryptoRead fills b with cryptographically random bytes. Wrapped so the rest
// of the package reads clearly and so a test can substitute a deterministic
// source if one is ever needed.
func cryptoRead(b []byte) (int, error) { return rand.Read(b) }
