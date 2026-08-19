package mtproto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"
)

// The auth-key handshake, in five messages:
//
//	1. client → req_pq(nonce)
//	2. server → res_pq(nonce, server_nonce, pq, rsa_fingerprint)
//	3. client → req_dh_params(nonce, server_nonce, p, q,
//	              RSA(inner: pq, p, q, nonce, server_nonce, new_nonce))
//	4. server → server_dh_params(nonce, server_nonce,
//	              AES-IGE(tmp: dh_prime, g, g_a, server_time))
//	5. client → set_client_dh_params(nonce, server_nonce, AES-IGE(tmp: g_b))
//	   server → dh_gen_ok(nonce, server_nonce, new_nonce_hash)
//
// auth_key = g_a^b mod p, computed by the client; the server computes
// g_b^a mod p and both arrive at the same 256-byte secret.
//
// Three properties are worth naming because each one is load-bearing:
//
//   - new_nonce travels RSA-encrypted, so only the holder of the server's
//     private key learns it, and it keys the AES layer that protects the DH
//     exchange. A passive observer sees the DH publics but cannot read the
//     encrypted answers.
//   - The DH exponents are freshly generated per handshake and discarded, so
//     compromising the RSA key later does not reveal past auth keys — the
//     forward secrecy of the negotiation.
//   - The server validates g_b (and the client validates g_a) against small
//     subgroup and boundary values. Skipping that check would let a peer force
//     a shared secret of 0, 1 or p-1 and read everything afterwards.

// DH group: RFC 3526 MODP group 14, a 2048-bit safe prime with g = 2.
//
// Telegram uses its own prime; this one is published, widely reviewed and has
// the same properties (p and (p-1)/2 both prime), so a client can verify it
// against the RFC instead of trusting the server's word.
const rfc3526Group14Hex = `
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
	dhPrime    *big.Int
	dhG        = big.NewInt(2)
	dhPrimeQ   *big.Int // (p-1)/2
	dhInitOnce sync.Once
)

func initDH() {
	dhInitOnce.Do(func() {
		clean := strings.Map(func(r rune) rune {
			if r == '\n' || r == '\r' || r == ' ' || r == '\t' {
				return -1
			}
			return r
		}, rfc3526Group14Hex)
		p, ok := new(big.Int).SetString(clean, 16)
		if !ok {
			panic("mtproto: DH prime is not valid hex")
		}
		dhPrime = p
		dhPrimeQ = new(big.Int).Rsh(new(big.Int).Sub(p, big.NewInt(1)), 1)
	})
}

// DHPrime exposes the group prime so clients can pin it.
func DHPrime() *big.Int { initDH(); return new(big.Int).Set(dhPrime) }

// Handshake errors.
var (
	ErrNonceMismatch    = errors.New("mtproto: nonce mismatch")
	ErrUnknownRSAKey    = errors.New("mtproto: unknown RSA key fingerprint")
	ErrBadDHValue       = errors.New("mtproto: DH value is out of the safe range")
	ErrHandshakeState   = errors.New("mtproto: handshake step out of order")
	ErrHandshakeExpired = errors.New("mtproto: handshake timed out")
)

// ServerKey is the RSA key pair the server proves possession of.
type ServerKey struct {
	priv        *rsa.PrivateKey
	Fingerprint uint64
}

// LoadServerKey parses a PEM-encoded RSA private key from Secret Manager.
func LoadServerKey(pemStr string) (*ServerKey, error) {
	block, _ := pem.Decode([]byte(strings.TrimSpace(pemStr)))
	if block == nil {
		return nil, errors.New("mtproto: server key is not valid PEM")
	}

	var priv *rsa.PrivateKey
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		priv = k
	} else {
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("mtproto: parse server key: %w", err)
		}
		var ok bool
		if priv, ok = parsed.(*rsa.PrivateKey); !ok {
			return nil, fmt.Errorf("mtproto: expected an RSA key, got %T", parsed)
		}
	}
	if priv.N.BitLen() < 2048 {
		return nil, fmt.Errorf("mtproto: server key must be at least 2048 bits, got %d", priv.N.BitLen())
	}

	return &ServerKey{priv: priv, Fingerprint: rsaFingerprint(&priv.PublicKey)}, nil
}

// PublicPEM renders the public half, published so clients can pin it.
func (k *ServerKey) PublicPEM() (string, error) {
	der, err := x509.MarshalPKIXPublicKey(&k.priv.PublicKey)
	if err != nil {
		return "", fmt.Errorf("mtproto: marshal public key: %w", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), nil
}

// rsaFingerprint is the low 64 bits of SHA-1 over the DER public key. It only
// selects which key to use when several are published during a rotation.
func rsaFingerprint(pub *rsa.PublicKey) uint64 {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return 0
	}
	sum := sha1.Sum(der)
	return binary.LittleEndian.Uint64(sum[12:20])
}

// ---------------------------------------------------------------------------
// Server side
// ---------------------------------------------------------------------------

// ServerHandshake holds the state of one in-progress negotiation.
//
// It is per-connection and short-lived. Holding DH state across connections
// would let an attacker start thousands of handshakes and pin server memory,
// so a connection that stalls mid-handshake is dropped with its state.
type ServerHandshake struct {
	key *ServerKey

	nonce       [16]byte
	serverNonce [16]byte
	newNonce    [32]byte

	pq, p, q uint64

	a  *big.Int // server's secret exponent
	gA *big.Int // server's public value
	gB *big.Int // client's public value

	step     int
	deadline time.Time
}

// NewServerHandshake starts a negotiation.
func NewServerHandshake(key *ServerKey, timeout time.Duration) *ServerHandshake {
	initDH()
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	return &ServerHandshake{key: key, deadline: time.Now().Add(timeout)}
}

// ReqPQ handles step 1 and produces res_pq.
func (h *ServerHandshake) ReqPQ(clientNonce [16]byte) (ResPQ, error) {
	if h.step != 0 {
		return ResPQ{}, ErrHandshakeState
	}
	if time.Now().After(h.deadline) {
		return ResPQ{}, ErrHandshakeExpired
	}

	h.nonce = clientNonce
	if _, err := rand.Read(h.serverNonce[:]); err != nil {
		return ResPQ{}, fmt.Errorf("mtproto: server nonce: %w", err)
	}

	pq, p, q, err := GeneratePQ()
	if err != nil {
		return ResPQ{}, err
	}
	h.pq, h.p, h.q = pq, p, q
	h.step = 1

	return ResPQ{
		Nonce:           h.nonce,
		ServerNonce:     h.serverNonce,
		PQ:              pq,
		RSAFingerprints: []uint64{h.key.Fingerprint},
	}, nil
}

// ReqDHParams handles step 3 and produces server_dh_params.
func (h *ServerHandshake) ReqDHParams(req ReqDHParams) (ServerDHParams, error) {
	if h.step != 1 {
		return ServerDHParams{}, ErrHandshakeState
	}
	if time.Now().After(h.deadline) {
		return ServerDHParams{}, ErrHandshakeExpired
	}
	if req.Nonce != h.nonce || req.ServerNonce != h.serverNonce {
		return ServerDHParams{}, ErrNonceMismatch
	}
	if req.RSAFingerprint != h.key.Fingerprint {
		return ServerDHParams{}, ErrUnknownRSAKey
	}
	// The proof of work: refuse to spend a modexp until the factors check out.
	if err := VerifyPQ(h.pq, req.P, req.Q); err != nil {
		return ServerDHParams{}, err
	}

	// OAEP rather than PKCS#1 v1.5: v1.5 padding oracles are a solved problem
	// and there is no compatibility reason to inherit one here.
	inner, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, h.key.priv, req.EncryptedData, nil)
	if err != nil {
		return ServerDHParams{}, fmt.Errorf("mtproto: decrypt inner data: %w", err)
	}
	var pqInner PQInnerData
	if err := pqInner.UnmarshalBinary(inner); err != nil {
		return ServerDHParams{}, err
	}
	if pqInner.Nonce != h.nonce || pqInner.ServerNonce != h.serverNonce {
		return ServerDHParams{}, ErrNonceMismatch
	}
	if pqInner.PQ != h.pq || pqInner.P != req.P || pqInner.Q != req.Q {
		return ServerDHParams{}, fmt.Errorf("mtproto: inner pq data does not match the outer request")
	}
	h.newNonce = pqInner.NewNonce

	// Fresh exponent per handshake; never reused, never stored.
	a, err := rand.Int(rand.Reader, dhPrimeQ)
	if err != nil {
		return ServerDHParams{}, fmt.Errorf("mtproto: generate exponent: %w", err)
	}
	// A tiny exponent would make the discrete log trivial.
	a.Add(a, big.NewInt(1<<20))
	h.a = a
	h.gA = new(big.Int).Exp(dhG, a, dhPrime)

	answer := ServerDHInnerData{
		Nonce:       h.nonce,
		ServerNonce: h.serverNonce,
		G:           2,
		DHPrime:     dhPrime.Bytes(),
		GA:          h.gA.Bytes(),
		ServerTime:  time.Now().Unix(),
	}
	plain, err := encodeInner(answer)
	if err != nil {
		return ServerDHParams{}, err
	}

	tmpKey, tmpIV := tmpAESKeyIV(h.newNonce, h.serverNonce)
	sealed, err := igeSeal(tmpKey, tmpIV, plain)
	if err != nil {
		return ServerDHParams{}, err
	}

	h.step = 2
	return ServerDHParams{
		Nonce:           h.nonce,
		ServerNonce:     h.serverNonce,
		EncryptedAnswer: sealed,
	}, nil
}

// SetClientDHParams handles step 5, derives the auth key and confirms.
func (h *ServerHandshake) SetClientDHParams(req SetClientDHParams) (*AuthKey, DHGenOK, error) {
	if h.step != 2 {
		return nil, DHGenOK{}, ErrHandshakeState
	}
	if time.Now().After(h.deadline) {
		return nil, DHGenOK{}, ErrHandshakeExpired
	}
	if req.Nonce != h.nonce || req.ServerNonce != h.serverNonce {
		return nil, DHGenOK{}, ErrNonceMismatch
	}

	tmpKey, tmpIV := tmpAESKeyIV(h.newNonce, h.serverNonce)
	plain, err := igeOpen(tmpKey, tmpIV, req.EncryptedData)
	if err != nil {
		return nil, DHGenOK{}, err
	}
	var inner ClientDHInnerData
	if err := decodeInner(plain, &inner); err != nil {
		return nil, DHGenOK{}, err
	}
	if inner.Nonce != h.nonce || inner.ServerNonce != h.serverNonce {
		return nil, DHGenOK{}, ErrNonceMismatch
	}

	gB := new(big.Int).SetBytes(inner.GB)
	if err := validateDHValue(gB); err != nil {
		return nil, DHGenOK{}, err
	}
	h.gB = gB

	shared := new(big.Int).Exp(gB, h.a, dhPrime)
	authKeyBytes := leftPad(shared.Bytes(), AuthKeySize)

	key, err := NewAuthKey(authKeyBytes)
	if err != nil {
		return nil, DHGenOK{}, err
	}

	// new_nonce_hash proves to the client that we derived the same key: it
	// covers new_nonce and the auth key's own fingerprint.
	hash := newNonceHash(h.newNonce, 1, key)

	h.step = 3
	return key, DHGenOK{
		Nonce:        h.nonce,
		ServerNonce:  h.serverNonce,
		NewNonceHash: hash,
	}, nil
}

// Done reports whether the handshake completed.
func (h *ServerHandshake) Done() bool { return h.step == 3 }

// ---------------------------------------------------------------------------
// Shared crypto helpers
// ---------------------------------------------------------------------------

// validateDHValue rejects the values that would collapse the shared secret.
//
// 1 < g_b < p-1 is the minimum; MTProto additionally requires the value to
// stay clear of both ends by 2^(2048-64), which rules out the small-subgroup
// and near-boundary tricks that make the discrete log easy.
func validateDHValue(v *big.Int) error {
	initDH()
	one := big.NewInt(1)
	pMinus1 := new(big.Int).Sub(dhPrime, one)

	if v.Cmp(one) <= 0 || v.Cmp(pMinus1) >= 0 {
		return fmt.Errorf("%w: value is 0, 1 or p-1", ErrBadDHValue)
	}

	margin := new(big.Int).Lsh(one, 2048-64)
	if v.Cmp(margin) < 0 {
		return fmt.Errorf("%w: value is too close to 0", ErrBadDHValue)
	}
	if v.Cmp(new(big.Int).Sub(dhPrime, margin)) > 0 {
		return fmt.Errorf("%w: value is too close to p", ErrBadDHValue)
	}
	return nil
}

// tmpAESKeyIV derives the AES key protecting the DH exchange from new_nonce
// and server_nonce, exactly as MTProto specifies.
//
//	key = SHA1(new_nonce ‖ server_nonce) ‖ substr(SHA1(server_nonce ‖ new_nonce), 0, 12)
//	iv  = substr(SHA1(server_nonce ‖ new_nonce), 12, 8) ‖ SHA1(new_nonce ‖ new_nonce) ‖ substr(new_nonce, 0, 4)
func tmpAESKeyIV(newNonce [32]byte, serverNonce [16]byte) (key, iv []byte) {
	ns := sha1.Sum(concat(newNonce[:], serverNonce[:]))
	sn := sha1.Sum(concat(serverNonce[:], newNonce[:]))
	nn := sha1.Sum(concat(newNonce[:], newNonce[:]))

	key = make([]byte, 0, 32)
	key = append(key, ns[:]...)
	key = append(key, sn[0:12]...)

	iv = make([]byte, 0, 32)
	iv = append(iv, sn[12:20]...)
	iv = append(iv, nn[:]...)
	iv = append(iv, newNonce[0:4]...)

	return key, iv
}

// newNonceHash binds new_nonce to the derived auth key so each side can prove
// it computed the same secret without revealing it.
func newNonceHash(newNonce [32]byte, tag byte, key *AuthKey) [16]byte {
	authKeyDigest := sha1.Sum(key.Bytes())
	// The auxiliary hash is the first 8 bytes of SHA1(auth_key).
	buf := make([]byte, 0, 32+1+8)
	buf = append(buf, newNonce[:]...)
	buf = append(buf, tag)
	buf = append(buf, authKeyDigest[0:8]...)

	sum := sha1.Sum(buf)
	var out [16]byte
	copy(out[:], sum[4:20])
	return out
}

// igeSeal encrypts an inner payload with a SHA-1 integrity prefix, matching
// MTProto's inner-data framing: SHA1(data) ‖ data ‖ random padding to 16.
func igeSeal(key, iv, data []byte) ([]byte, error) {
	digest := sha1.Sum(data)
	buf := make([]byte, 0, 20+len(data)+16)
	buf = append(buf, digest[:]...)
	buf = append(buf, data...)

	if pad := (16 - len(buf)%16) % 16; pad > 0 {
		padding := make([]byte, pad)
		if _, err := rand.Read(padding); err != nil {
			return nil, fmt.Errorf("mtproto: inner padding: %w", err)
		}
		buf = append(buf, padding...)
	}
	return IGEEncrypt(key, iv, buf)
}

// igeOpen reverses igeSeal and verifies the integrity prefix.
func igeOpen(key, iv, sealed []byte) ([]byte, error) {
	plain, err := IGEDecrypt(key, iv, sealed)
	if err != nil {
		return nil, err
	}
	if len(plain) < 20 {
		return nil, ErrShortFrame
	}
	digest := plain[:20]
	body := plain[20:]

	// The payload length is unknown because of the padding, so try the
	// candidate lengths from longest to shortest and take the one whose
	// digest matches. Padding is at most 15 bytes, so this is a bounded scan.
	for cut := len(body); cut >= 0 && len(body)-cut <= 16; cut-- {
		sum := sha1.Sum(body[:cut])
		if constantTimeEqual(sum[:], digest) {
			out := make([]byte, cut)
			copy(out, body[:cut])
			return out, nil
		}
	}
	return nil, errors.New("mtproto: inner data integrity check failed")
}

func concat(parts ...[]byte) []byte {
	n := 0
	for _, p := range parts {
		n += len(p)
	}
	out := make([]byte, 0, n)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// leftPad zero-extends a big-endian integer to a fixed width. A shared secret
// with leading zero bytes would otherwise produce a short auth key and the two
// sides would derive different keys.
func leftPad(b []byte, size int) []byte {
	if len(b) >= size {
		return b[len(b)-size:]
	}
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}
