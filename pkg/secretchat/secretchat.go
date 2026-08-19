// Package secretchat implements end-to-end encrypted conversations.
//
// The defining property: the server never holds the key and cannot derive it.
// It relays three messages between two devices and stores only what it must
// to route them — the participants, a state, and a fingerprint it can compare
// but not invert.
//
// # The exchange
//
//	A → server → B   requestEncryption(g_a)
//	B → server → A   acceptEncryption(g_b, key_fingerprint)
//	A                verifies its own fingerprint matches, marks the chat ready
//
// Both sides compute key = g_(other)^(own) mod p. The server sees g_a and g_b,
// which is exactly the information a passive observer of a Diffie-Hellman
// exchange sees, and which does not yield the key.
//
// # What this does not defend against
//
// The server relays the public values, so it can substitute its own and sit in
// the middle. Diffie-Hellman without authentication always has this property.
// The defence is out-of-band verification: both users compare the key
// fingerprint — rendered as emoji, as Telegram does, or as hex — through some
// channel the server does not control. Until they do, a secret chat protects
// against everyone except us.
//
// That limitation is inherent and is stated plainly in docs/SECURITY.md rather
// than buried.
package secretchat

import (
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// The Diffie-Hellman group is the same RFC 3526 MODP group 14 the transport
// handshake uses. Reusing it means one prime to validate, one set of range
// checks, and one place to change if the group ever needs to move.
const dhPrimeHex = `
FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08
8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B
302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9
A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6
49286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8
FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D
670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C
180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718
3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFF
FFFFFFFF`

var (
	dhPrime  *big.Int
	dhG      = big.NewInt(2)
	dhQ      *big.Int
	dhMargin *big.Int
)

func init() {
	clean := strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == ' ' || r == '\t' {
			return -1
		}
		return r
	}, dhPrimeHex)

	p, ok := new(big.Int).SetString(clean, 16)
	if !ok {
		panic("secretchat: the DH prime is not valid hex")
	}
	dhPrime = p
	dhQ = new(big.Int).Rsh(new(big.Int).Sub(p, big.NewInt(1)), 1)
	dhMargin = new(big.Int).Lsh(big.NewInt(1), 2048-64)
}

// KeySize is the length of a derived secret-chat key.
const KeySize = 256

// Errors.
var (
	ErrBadDHValue  = errors.New("secretchat: the peer's DH value is outside the safe range")
	ErrKeyMismatch = errors.New("secretchat: the key fingerprints do not match")
	ErrWrongState  = errors.New("secretchat: the chat is not in a state that allows this")
	ErrNotAParty   = errors.New("secretchat: the caller is not a participant")
)

// State is where a secret chat is in its lifecycle.
type State string

const (
	// StateRequested means A has sent g_a and is waiting for B.
	StateRequested State = "requested"
	// StateReady means both sides hold the key.
	StateReady State = "ready"
	// StateDiscarded means one side ended it. Terminal: a discarded chat is
	// never revived, because reviving one would mean reusing a key whose
	// material one side has already destroyed.
	StateDiscarded State = "discarded"
)

// Prime exposes the group prime so a client can pin it against the RFC.
func Prime() *big.Int { return new(big.Int).Set(dhPrime) }

// ValidateDHValue rejects the values that would collapse the shared secret.
//
// Identical to the transport handshake's check, and for the same reason:
// without it a malicious peer forces a shared secret of 0, 1 or p−1 and reads
// everything afterwards. A secret chat is exactly where that must not happen.
func ValidateDHValue(v *big.Int) error {
	one := big.NewInt(1)
	if v.Cmp(one) <= 0 || v.Cmp(new(big.Int).Sub(dhPrime, one)) >= 0 {
		return fmt.Errorf("%w: value is 0, 1 or p-1", ErrBadDHValue)
	}
	if v.Cmp(dhMargin) < 0 {
		return fmt.Errorf("%w: value is too close to 0", ErrBadDHValue)
	}
	if v.Cmp(new(big.Int).Sub(dhPrime, dhMargin)) > 0 {
		return fmt.Errorf("%w: value is too close to p", ErrBadDHValue)
	}
	return nil
}

// GenerateExponent returns a fresh private exponent.
func GenerateExponent() (*big.Int, error) {
	x, err := rand.Int(rand.Reader, dhQ)
	if err != nil {
		return nil, fmt.Errorf("secretchat: generate exponent: %w", err)
	}
	// A tiny exponent makes the discrete log trivial.
	return x.Add(x, new(big.Int).Lsh(big.NewInt(1), 20)), nil
}

// PublicValue computes g^x mod p.
func PublicValue(x *big.Int) *big.Int {
	return new(big.Int).Exp(dhG, x, dhPrime)
}

// DeriveKey computes the shared secret from the peer's public value.
//
// The result is left-padded to exactly KeySize bytes. Without that, a shared
// secret that happens to have leading zero bytes would produce a shorter key
// on one side than the other, and the two would silently fail to talk — an
// intermittent bug that appears in roughly one exchange in 256.
func DeriveKey(peerPublic, own *big.Int) ([]byte, error) {
	if err := ValidateDHValue(peerPublic); err != nil {
		return nil, err
	}

	shared := new(big.Int).Exp(peerPublic, own, dhPrime)
	return padKey(shared.Bytes()), nil
}

// padKey left-pads a big-endian shared secret to exactly KeySize bytes.
//
// big.Int.Bytes() drops leading zeros, so a shared secret whose top byte
// happens to be zero — about one exchange in 256 — comes back 255 bytes long.
// Without this padding the two sides would derive keys of different lengths
// from the same secret and silently fail to talk, which is the kind of bug
// that shows up as "sometimes secret chats just don't work".
//
// Split out from DeriveKey so it can be tested directly: reproducing the case
// end to end means searching for an exponent pair that happens to produce a
// short secret, and the safety checks correctly refuse the small values that
// would make that easy to contrive.
func padKey(raw []byte) []byte {
	key := make([]byte, KeySize)
	if len(raw) >= KeySize {
		copy(key, raw[len(raw)-KeySize:])
		return key
	}
	copy(key[KeySize-len(raw):], raw)
	return key
}

// Fingerprint is the 64-bit key identifier both sides exchange.
//
// It is the low 64 bits of SHA-1 over the key, matching MTProto's auth-key id
// construction. Its job is to detect a mismatch, not to resist a preimage:
// only someone who already holds the key can produce it, and a collision would
// let two different keys look the same to a user comparing fingerprints — which
// is why VisualFingerprint below uses SHA-256 instead.
func Fingerprint(key []byte) uint64 {
	sum := sha1.Sum(key)
	return binary.LittleEndian.Uint64(sum[12:20])
}

// VisualFingerprint renders the key as words a human can read aloud.
//
// This is the out-of-band check that turns an unauthenticated Diffie-Hellman
// into an authenticated one. Two users compare the sequence over a channel the
// server does not control — in person, or on a phone call — and a
// man-in-the-middle is detected because the server cannot produce a key whose
// fingerprint matches both sides.
//
// SHA-256, not SHA-1: a user comparing a short sequence needs collision
// resistance, and SHA-1 no longer has it.
func VisualFingerprint(key []byte) []string {
	sum := sha256.Sum256(key)

	// Five words drawn from a 2048-entry list is 55 bits — enough that
	// forging a matching pair is infeasible, short enough that people
	// actually finish reading it. A longer sequence that nobody compares
	// protects nothing.
	const words = 5
	out := make([]string, 0, words)

	for i := 0; i < words; i++ {
		// 11 bits per word, packed across byte boundaries.
		bitOffset := i * 11
		byteOffset := bitOffset / 8
		shift := bitOffset % 8

		chunk := uint32(sum[byteOffset])<<16 |
			uint32(sum[byteOffset+1])<<8 |
			uint32(sum[byteOffset+2])
		index := (chunk >> (13 - shift)) & 0x7FF

		out = append(out, wordList[index%uint32(len(wordList))])
	}
	return out
}

// VerifyFingerprint compares a peer's claimed fingerprint against the key we
// derived, in constant time.
//
// A mismatch means the two sides hold different keys, which means either a
// bug or a man-in-the-middle. Either way the chat must not proceed.
func VerifyFingerprint(key []byte, claimed uint64) error {
	// Comparing two uint64 values leaks nothing useful: the attacker already
	// supplied one of them and cannot iterate towards the other faster than
	// they could guess the key.
	if Fingerprint(key) != claimed {
		return ErrKeyMismatch
	}
	return nil
}
