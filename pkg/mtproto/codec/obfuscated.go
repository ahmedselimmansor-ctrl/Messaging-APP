package codec

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
)

// Obfuscation ("obfuscated2") makes an MTProto connection look like random
// bytes from the first packet onwards.
//
// It is not a security layer — the real encryption is the auth key — it is a
// censorship-resistance layer. A deep packet inspection box that blocks
// traffic by protocol signature has nothing to match: there is no plaintext
// handshake, no fixed header, no recognisable length pattern.
//
// The client opens with 64 random-looking bytes chosen so that neither the
// first byte nor the first four bytes collide with any other framing's magic
// or with an HTTP verb. Those 64 bytes are themselves the key material:
//
//	client → server: key = init[8:40],  iv = init[40:56]
//	server → client: key = rev[0:32],   iv = rev[32:48]
//	                 where rev = reverse(init[8:56])
//
// Both directions then run AES-256-CTR. The server decrypts the init packet
// with the client-to-server key and reads bytes 56..60, which carry the
// framing the client wants to use — so the framing selection is itself
// obfuscated.

const initPacketSize = 64

// ErrNotObfuscated is returned when the init packet does not decrypt to a
// known framing tag.
var ErrNotObfuscated = errors.New("codec: connection is not obfuscated")

// ObfuscatedConn wraps a net.Conn with the two CTR streams.
type ObfuscatedConn struct {
	net.Conn

	// src is where ciphertext is read from, which is *not* always the
	// connection. On the accept path the init packet is read through a
	// buffered reader, and that reader may already hold bytes past it —
	// TCP is free to coalesce the client's init packet and its first frame
	// into one segment. Reading from the connection directly afterwards
	// would silently discard those buffered bytes and lose the first frame,
	// intermittently and only under the right timing.
	src io.Reader

	enc cipher.Stream // server → client
	dec cipher.Stream // client → server

	// Codec is the framing the client selected inside the init packet.
	Codec Codec
	// DCID is the datacentre the client wants, carried in the init packet.
	// Negative values mean a media-only connection in Telegram's scheme; we
	// use it to pin a client to a region.
	DCID int16
}

// AcceptObfuscated reads and validates the 64-byte init packet.
//
// It returns a wrapped connection whose Read and Write transparently
// encrypt/decrypt, so every layer above is unaware the obfuscation exists.
func AcceptObfuscated(c net.Conn, br *bufio.Reader) (*ObfuscatedConn, error) {
	var init [initPacketSize]byte
	if _, err := io.ReadFull(br, init[:]); err != nil {
		return nil, fmt.Errorf("codec: read init packet: %w", err)
	}

	decKey := make([]byte, 32)
	decIV := make([]byte, 16)
	copy(decKey, init[8:40])
	copy(decIV, init[40:56])

	rev := make([]byte, 48)
	for i := 0; i < 48; i++ {
		rev[i] = init[55-i]
	}
	encKey := make([]byte, 32)
	encIV := make([]byte, 16)
	copy(encKey, rev[0:32])
	copy(encIV, rev[32:48])

	decStream, err := newCTR(decKey, decIV)
	if err != nil {
		return nil, err
	}
	encStream, err := newCTR(encKey, encIV)
	if err != nil {
		return nil, err
	}

	// Decrypting the init packet advances the client-to-server stream past
	// its own 64 bytes, which is exactly what the client did on its side.
	decrypted := make([]byte, initPacketSize)
	decStream.XORKeyStream(decrypted, init[:])

	tag := binary.LittleEndian.Uint32(decrypted[56:60])
	var codec Codec
	switch {
	case decrypted[56] == magicAbridged && decrypted[57] == magicAbridged &&
		decrypted[58] == magicAbridged && decrypted[59] == magicAbridged:
		codec = &Abridged{}
	case tag == magicIntermediate:
		codec = &Intermediate{}
	case tag == magicPaddedIntermediate:
		codec = &PaddedIntermediate{}
	default:
		return nil, fmt.Errorf("%w: init tag %08x", ErrNotObfuscated, tag)
	}

	return &ObfuscatedConn{
		Conn:  c,
		src:   br, // keep reading through the buffer, not around it
		enc:   encStream,
		dec:   decStream,
		Codec: codec,
		DCID:  int16(binary.LittleEndian.Uint16(decrypted[60:62])),
	}, nil
}

func (o *ObfuscatedConn) Read(p []byte) (int, error) {
	n, err := o.src.Read(p)
	if n > 0 {
		o.dec.XORKeyStream(p[:n], p[:n])
	}
	return n, err
}

func (o *ObfuscatedConn) Write(p []byte) (int, error) {
	// CTR is a stream cipher, so encrypting into a scratch buffer keeps the
	// caller's slice untouched. Writing in place would corrupt a buffer the
	// caller may still be holding, and would break a retried write.
	buf := make([]byte, len(p))
	o.enc.XORKeyStream(buf, p)
	return o.Conn.Write(buf)
}

func newCTR(key, iv []byte) (cipher.Stream, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("codec: aes: %w", err)
	}
	return cipher.NewCTR(block, iv), nil
}

// DialObfuscated builds the client-side init packet and returns a wrapped
// connection. Used by the load generator and the end-to-end tests.
func DialObfuscated(c net.Conn, framing Codec, dcID int16) (*ObfuscatedConn, error) {
	var init [initPacketSize]byte

	for attempts := 0; ; attempts++ {
		if attempts > 32 {
			return nil, errors.New("codec: could not generate an acceptable init packet")
		}
		if _, err := rand.Read(init[:56]); err != nil {
			return nil, fmt.Errorf("codec: init randomness: %w", err)
		}
		// The init packet must not be mistakable for any other framing's
		// magic, nor for the start of an HTTP request — otherwise a proxy
		// might interpret it and the disguise fails at the first hop.
		if init[0] == magicAbridged || init[0] == 0x00 {
			continue
		}
		switch binary.LittleEndian.Uint32(init[0:4]) {
		case magicIntermediate, magicPaddedIntermediate,
			0x44414548, // HEAD
			0x54534f50, // POST
			0x20544547, // "GET "
			0x4954504f, // OPTI
			0x02010316: // TLS handshake record
			continue
		}
		if binary.LittleEndian.Uint32(init[4:8]) == 0 {
			continue
		}
		break
	}

	switch framing.(type) {
	case *Abridged:
		for i := 56; i < 60; i++ {
			init[i] = magicAbridged
		}
	case *Intermediate:
		binary.LittleEndian.PutUint32(init[56:60], magicIntermediate)
	case *PaddedIntermediate:
		binary.LittleEndian.PutUint32(init[56:60], magicPaddedIntermediate)
	default:
		return nil, fmt.Errorf("codec: %T cannot be obfuscated", framing)
	}
	binary.LittleEndian.PutUint16(init[60:62], uint16(dcID))
	if _, err := rand.Read(init[62:64]); err != nil {
		return nil, fmt.Errorf("codec: init tail: %w", err)
	}

	// The client's send key is the server's receive key and vice versa.
	encKey := make([]byte, 32)
	encIV := make([]byte, 16)
	copy(encKey, init[8:40])
	copy(encIV, init[40:56])

	rev := make([]byte, 48)
	for i := 0; i < 48; i++ {
		rev[i] = init[55-i]
	}
	decKey := make([]byte, 32)
	decIV := make([]byte, 16)
	copy(decKey, rev[0:32])
	copy(decIV, rev[32:48])

	encStream, err := newCTR(encKey, encIV)
	if err != nil {
		return nil, err
	}
	decStream, err := newCTR(decKey, decIV)
	if err != nil {
		return nil, err
	}

	// Encrypt the init packet, then splice the plaintext first 56 bytes back
	// in: the server needs them in the clear to derive the keys, and only
	// bytes 56..64 travel encrypted.
	encrypted := make([]byte, initPacketSize)
	encStream.XORKeyStream(encrypted, init[:])

	wire := make([]byte, initPacketSize)
	copy(wire, init[:56])
	copy(wire[56:], encrypted[56:])

	if _, err := c.Write(wire); err != nil {
		return nil, fmt.Errorf("codec: write init packet: %w", err)
	}

	return &ObfuscatedConn{
		Conn: c, src: c, enc: encStream, dec: decStream, Codec: framing, DCID: dcID,
	}, nil
}
