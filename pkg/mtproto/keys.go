package mtproto

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
)

// AuthKeySize is the length of a negotiated auth key.
const AuthKeySize = 256

// Direction selects which half of the key schedule to use.
//
// MTProto derives different AES keys for each direction from the same auth
// key by offsetting into it by x = 0 (client to server) or x = 8 (server to
// client). Without that split, a reflected message would decrypt correctly
// and an attacker could bounce a client's own traffic back at it.
type Direction int

const (
	// ClientToServer is x = 0.
	ClientToServer Direction = 0
	// ServerToClient is x = 8.
	ServerToClient Direction = 8
)

func (d Direction) x() int { return int(d) }

// Opposite returns the other direction.
func (d Direction) Opposite() Direction {
	if d == ClientToServer {
		return ServerToClient
	}
	return ClientToServer
}

// AuthKey is the 256-byte shared secret established by the handshake.
//
// It never leaves the gateway process except into Redis, where it lives under
// the session key with the same TTL as the session itself. It is never
// written to Postgres, never logged, and never sent over the wire after the
// handshake — only the 8-byte identifier derived from it travels with each
// message.
type AuthKey struct {
	raw [AuthKeySize]byte
	id  uint64
}

// NewAuthKey wraps raw key material.
func NewAuthKey(raw []byte) (*AuthKey, error) {
	if len(raw) != AuthKeySize {
		return nil, fmt.Errorf("mtproto: auth key must be %d bytes, got %d", AuthKeySize, len(raw))
	}
	k := &AuthKey{}
	copy(k.raw[:], raw)
	k.id = deriveKeyID(k.raw[:])
	return k, nil
}

// deriveKeyID is the low 64 bits of SHA-1 over the key: substr(SHA1(key), 12, 8),
// little-endian. SHA-1 here is an identifier, not a security primitive —
// collisions in it would only cause a session lookup miss, and the msg_key
// check still has to pass.
func deriveKeyID(key []byte) uint64 {
	sum := sha1.Sum(key)
	return binary.LittleEndian.Uint64(sum[12:20])
}

// Bytes returns the raw key material.
func (k *AuthKey) Bytes() []byte { return k.raw[:] }

// ID returns the 64-bit auth key identifier sent with every message.
func (k *AuthKey) ID() uint64 { return k.id }

// IDHex renders the identifier for use as a database key.
func (k *AuthKey) IDHex() string {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], k.id)
	return hex.EncodeToString(b[:])
}

// AuthKeyIDHex renders an identifier that is already a uint64.
func AuthKeyIDHex(id uint64) string {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], id)
	return hex.EncodeToString(b[:])
}

// ---------------------------------------------------------------------------
// MTProto 2.0 key derivation
// ---------------------------------------------------------------------------

// MsgKey computes the 16-byte message key over a plaintext.
//
//	msg_key_large = SHA256(substr(auth_key, 88 + x, 32) ‖ plaintext)
//	msg_key       = substr(msg_key_large, 8, 16)
//
// Because the digest covers a secret slice of the auth key, only a holder of
// the key can produce a valid msg_key — this is what authenticates the
// message. Because it also covers the padding, an attacker cannot reshape a
// message without invalidating it.
func (k *AuthKey) MsgKey(plaintext []byte, d Direction) []byte {
	x := d.x()
	h := sha256.New()
	h.Write(k.raw[88+x : 88+x+32])
	h.Write(plaintext)
	sum := h.Sum(nil)
	out := make([]byte, 16)
	copy(out, sum[8:24])
	return out
}

// DeriveAESKeyIV builds the per-message AES key and IV.
//
//	sha256_a = SHA256(msg_key ‖ substr(auth_key, x, 36))
//	sha256_b = SHA256(substr(auth_key, 40 + x, 36) ‖ msg_key)
//	aes_key  = substr(a, 0, 8) ‖ substr(b, 8, 16) ‖ substr(a, 24, 8)
//	aes_iv   = substr(b, 0, 8) ‖ substr(a, 8, 16) ‖ substr(b, 24, 8)
//
// The interleave is deliberate: neither digest alone determines the key, so
// leaking one of them does not hand over the key schedule.
func (k *AuthKey) DeriveAESKeyIV(msgKey []byte, d Direction) (key, iv []byte, err error) {
	if len(msgKey) != 16 {
		return nil, nil, fmt.Errorf("mtproto: msg_key must be 16 bytes, got %d", len(msgKey))
	}
	x := d.x()

	ha := sha256.New()
	ha.Write(msgKey)
	ha.Write(k.raw[x : x+36])
	a := ha.Sum(nil)

	hb := sha256.New()
	hb.Write(k.raw[40+x : 40+x+36])
	hb.Write(msgKey)
	b := hb.Sum(nil)

	key = make([]byte, 0, 32)
	key = append(key, a[0:8]...)
	key = append(key, b[8:24]...)
	key = append(key, a[24:32]...)

	iv = make([]byte, 0, 32)
	iv = append(iv, b[0:8]...)
	iv = append(iv, a[8:24]...)
	iv = append(iv, b[24:32]...)

	return key, iv, nil
}

// ErrBadMsgKey is returned when the recomputed msg_key does not match.
var ErrBadMsgKey = errors.New("mtproto: msg_key mismatch (forged, corrupt, or wrong key)")

// VerifyMsgKey recomputes the message key over a decrypted plaintext and
// compares it in constant time.
//
// This check is the integrity guarantee of the whole protocol and it must run
// before anything looks at the plaintext. Parsing first and verifying after
// would turn every field of the envelope into an attacker-controlled input to
// the parser.
func (k *AuthKey) VerifyMsgKey(plaintext, msgKey []byte, d Direction) error {
	want := k.MsgKey(plaintext, d)
	if !constantTimeEqual(want, msgKey) {
		return ErrBadMsgKey
	}
	return nil
}

// Zero wipes the key material. Called when a session is revoked so a heap
// dump taken afterwards does not contain a usable key.
func (k *AuthKey) Zero() {
	for i := range k.raw {
		k.raw[i] = 0
	}
	k.id = 0
}
