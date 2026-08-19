package mtproto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// ClientHandshake is the client half of the auth-key negotiation.
//
// It lives in the server repository on purpose: it is what the load generator
// and the end-to-end tests drive, and keeping both halves next to each other
// is what makes it possible to test the handshake for real rather than mock
// it. The Kotlin and TypeScript clients implement the same six steps.
type ClientHandshake struct {
	serverPub *rsa.PublicKey
	fp        uint64

	nonce       [16]byte
	serverNonce [16]byte
	newNonce    [32]byte

	b  *big.Int // client's secret exponent
	gA *big.Int // server's public value
}

// NewClientHandshake starts a negotiation against a pinned server key.
//
// The client must pin the key. Without pinning, an attacker who can intercept
// the connection simply substitutes their own RSA key, learns new_nonce, and
// reads the entire DH exchange — the handshake protects against passive
// observers, the pin protects against active ones.
func NewClientHandshake(serverPublicKeyPEM string) (*ClientHandshake, error) {
	initDH()

	block, _ := pem.Decode([]byte(strings.TrimSpace(serverPublicKeyPEM)))
	if block == nil {
		return nil, errors.New("mtproto: server public key is not valid PEM")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("mtproto: parse server public key: %w", err)
	}
	pub, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("mtproto: expected an RSA public key, got %T", parsed)
	}

	return &ClientHandshake{serverPub: pub, fp: rsaFingerprint(pub)}, nil
}

// Start produces req_pq.
func (c *ClientHandshake) Start() (ReqPQ, error) {
	if _, err := rand.Read(c.nonce[:]); err != nil {
		return ReqPQ{}, fmt.Errorf("mtproto: client nonce: %w", err)
	}
	return ReqPQ{Nonce: c.nonce}, nil
}

// OnResPQ factors the semiprime and produces req_dh_params.
func (c *ClientHandshake) OnResPQ(res ResPQ) (ReqDHParams, error) {
	if res.Nonce != c.nonce {
		return ReqDHParams{}, ErrNonceMismatch
	}
	c.serverNonce = res.ServerNonce

	known := false
	for _, fp := range res.RSAFingerprints {
		if fp == c.fp {
			known = true
			break
		}
	}
	if !known {
		return ReqDHParams{}, fmt.Errorf("%w: server offered %v, we pinned %d",
			ErrUnknownRSAKey, res.RSAFingerprints, c.fp)
	}

	p, q, err := FactorPQ(res.PQ)
	if err != nil {
		return ReqDHParams{}, err
	}
	if _, err := rand.Read(c.newNonce[:]); err != nil {
		return ReqDHParams{}, fmt.Errorf("mtproto: new nonce: %w", err)
	}

	inner, err := PQInnerData{
		PQ: res.PQ, P: p, Q: q,
		Nonce: c.nonce, ServerNonce: c.serverNonce, NewNonce: c.newNonce,
	}.MarshalBinary()
	if err != nil {
		return ReqDHParams{}, err
	}
	sealed, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, c.serverPub, inner, nil)
	if err != nil {
		return ReqDHParams{}, fmt.Errorf("mtproto: RSA-encrypt inner data: %w", err)
	}

	return ReqDHParams{
		Nonce: c.nonce, ServerNonce: c.serverNonce,
		P: p, Q: q, RSAFingerprint: c.fp, EncryptedData: sealed,
	}, nil
}

// OnServerDHParams validates the group, generates the client exponent and
// produces set_client_dh_params.
func (c *ClientHandshake) OnServerDHParams(res ServerDHParams) (SetClientDHParams, error) {
	if res.Nonce != c.nonce || res.ServerNonce != c.serverNonce {
		return SetClientDHParams{}, ErrNonceMismatch
	}

	key, iv := tmpAESKeyIV(c.newNonce, c.serverNonce)
	plain, err := igeOpen(key, iv, res.EncryptedAnswer)
	if err != nil {
		return SetClientDHParams{}, err
	}
	var inner ServerDHInnerData
	if err := decodeInner(plain, &inner); err != nil {
		return SetClientDHParams{}, err
	}
	if inner.Nonce != c.nonce || inner.ServerNonce != c.serverNonce {
		return SetClientDHParams{}, ErrNonceMismatch
	}

	// Verify the server handed us the group we expect. A server that quietly
	// substitutes a weak or composite prime could recover the shared secret,
	// so this check is not optional.
	if got := new(big.Int).SetBytes(inner.DHPrime); got.Cmp(dhPrime) != 0 {
		return SetClientDHParams{}, fmt.Errorf("%w: server proposed a different DH prime", ErrBadDHValue)
	}
	if inner.G != 2 {
		return SetClientDHParams{}, fmt.Errorf("%w: unexpected generator %d", ErrBadDHValue, inner.G)
	}

	gA := new(big.Int).SetBytes(inner.GA)
	if err := validateDHValue(gA); err != nil {
		return SetClientDHParams{}, err
	}
	c.gA = gA

	b, err := rand.Int(rand.Reader, dhPrimeQ)
	if err != nil {
		return SetClientDHParams{}, fmt.Errorf("mtproto: generate exponent: %w", err)
	}
	b.Add(b, big.NewInt(1<<20))
	c.b = b

	gB := new(big.Int).Exp(dhG, b, dhPrime)
	innerOut, err := encodeInner(ClientDHInnerData{
		Nonce: c.nonce, ServerNonce: c.serverNonce, RetryID: 0, GB: gB.Bytes(),
	})
	if err != nil {
		return SetClientDHParams{}, err
	}
	sealed, err := igeSeal(key, iv, innerOut)
	if err != nil {
		return SetClientDHParams{}, err
	}

	return SetClientDHParams{
		Nonce: c.nonce, ServerNonce: c.serverNonce, EncryptedData: sealed,
	}, nil
}

// OnDHGenOK derives the auth key and verifies the server proved the same one.
func (c *ClientHandshake) OnDHGenOK(res DHGenOK) (*AuthKey, error) {
	if res.Nonce != c.nonce || res.ServerNonce != c.serverNonce {
		return nil, ErrNonceMismatch
	}
	if c.gA == nil || c.b == nil {
		return nil, ErrHandshakeState
	}

	shared := new(big.Int).Exp(c.gA, c.b, dhPrime)
	key, err := NewAuthKey(leftPad(shared.Bytes(), AuthKeySize))
	if err != nil {
		return nil, err
	}

	want := newNonceHash(c.newNonce, 1, key)
	if !constantTimeEqual(want[:], res.NewNonceHash[:]) {
		return nil, errors.New("mtproto: new_nonce_hash mismatch; the server derived a different key")
	}
	return key, nil
}
