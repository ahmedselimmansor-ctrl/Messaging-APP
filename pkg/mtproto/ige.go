package mtproto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"errors"
	"fmt"
)

// IGE (Infinite Garble Extension) is the block cipher mode MTProto uses.
//
// Each ciphertext block depends on the previous ciphertext block *and* the
// previous plaintext block:
//
//	encrypt: y[i] = E(x[i] ⊕ y[i-1]) ⊕ x[i-1]
//	decrypt: x[i] = D(y[i] ⊕ x[i-1]) ⊕ y[i-1]
//
// with y[-1] and x[-1] taken from the first and second halves of the 32-byte
// IV respectively.
//
// IGE is not authenticated on its own. In MTProto the authentication comes
// from msg_key: the receiver recomputes it over the decrypted plaintext and
// compares, which is an encrypt-and-MAC construction over a key derived from
// the same secret. That is why VerifyMsgKey below must use a constant-time
// comparison and must run before the plaintext is parsed.

var (
	// ErrBlockSize is returned when data is not a multiple of the AES block.
	ErrBlockSize = errors.New("mtproto: data length must be a multiple of 16")
	// ErrIVSize is returned when the IV is not 32 bytes.
	ErrIVSize = errors.New("mtproto: IGE IV must be 32 bytes")
)

const (
	blockSize = aes.BlockSize // 16
	igeIVSize = 2 * blockSize // 32
)

// IGEEncrypt encrypts src into a new slice using AES-IGE.
//
// key must be 32 bytes (AES-256), iv 32 bytes, and src a multiple of 16.
func IGEEncrypt(key, iv, src []byte) ([]byte, error) {
	block, err := newBlock(key, iv, src)
	if err != nil {
		return nil, err
	}

	dst := make([]byte, len(src))

	// prevCipher plays the role of y[i-1]; prevPlain the role of x[i-1].
	prevCipher := make([]byte, blockSize)
	prevPlain := make([]byte, blockSize)
	copy(prevCipher, iv[:blockSize])
	copy(prevPlain, iv[blockSize:])

	buf := make([]byte, blockSize)

	for i := 0; i < len(src); i += blockSize {
		plain := src[i : i+blockSize]
		out := dst[i : i+blockSize]

		xorBytes(buf, plain, prevCipher)
		block.Encrypt(out, buf)
		xorBytes(out, out, prevPlain)

		copy(prevCipher, out)
		copy(prevPlain, plain)
	}
	return dst, nil
}

// IGEDecrypt decrypts src into a new slice using AES-IGE.
func IGEDecrypt(key, iv, src []byte) ([]byte, error) {
	block, err := newBlock(key, iv, src)
	if err != nil {
		return nil, err
	}

	dst := make([]byte, len(src))

	prevCipher := make([]byte, blockSize)
	prevPlain := make([]byte, blockSize)
	copy(prevCipher, iv[:blockSize])
	copy(prevPlain, iv[blockSize:])

	buf := make([]byte, blockSize)

	for i := 0; i < len(src); i += blockSize {
		ciph := src[i : i+blockSize]
		out := dst[i : i+blockSize]

		xorBytes(buf, ciph, prevPlain)
		block.Decrypt(out, buf)
		xorBytes(out, out, prevCipher)

		copy(prevCipher, ciph)
		copy(prevPlain, out)
	}
	return dst, nil
}

func newBlock(key, iv, src []byte) (cipher.Block, error) {
	if len(iv) != igeIVSize {
		return nil, fmt.Errorf("%w: got %d", ErrIVSize, len(iv))
	}
	if len(src) == 0 || len(src)%blockSize != 0 {
		return nil, fmt.Errorf("%w: got %d", ErrBlockSize, len(src))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("mtproto: aes cipher: %w", err)
	}
	return block, nil
}

// xorBytes writes a ⊕ b into dst. All three must be blockSize long.
func xorBytes(dst, a, b []byte) {
	_ = dst[blockSize-1]
	_ = a[blockSize-1]
	_ = b[blockSize-1]
	for i := 0; i < blockSize; i++ {
		dst[i] = a[i] ^ b[i]
	}
}

// constantTimeEqual compares two byte slices without leaking their contents
// through timing. Used for msg_key and nonce-hash verification, where a
// byte-by-byte compare would let an attacker forge a value one byte at a time.
func constantTimeEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}
