package mtproto

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
)

// Handshake message types.
//
// These are the structures carried in the handshake's plain (auth_key_id = 0)
// messages. Their wire form is a constructor id followed by a JSON body — see
// the package documentation for why the payload is JSON rather than TL.
//
// The RSA- and AES-protected *inner* payloads use the same encoding, wrapped
// by encodeInner/decodeInner.

// ResPQ is step 2: the server's nonce, the proof-of-work semiprime and the
// fingerprints of the RSA keys it will accept.
type ResPQ struct {
	Nonce           [16]byte `json:"nonce"`
	ServerNonce     [16]byte `json:"server_nonce"`
	PQ              uint64   `json:"pq"`
	RSAFingerprints []uint64 `json:"rsa_fingerprints"`
}

// ReqPQ is step 1.
type ReqPQ struct {
	Nonce [16]byte `json:"nonce"`
}

// ReqDHParams is step 3.
type ReqDHParams struct {
	Nonce          [16]byte `json:"nonce"`
	ServerNonce    [16]byte `json:"server_nonce"`
	P              uint64   `json:"p"`
	Q              uint64   `json:"q"`
	RSAFingerprint uint64   `json:"rsa_fingerprint"`
	// EncryptedData is RSA-OAEP(PQInnerData) under the server's public key.
	EncryptedData []byte `json:"encrypted_data"`
}

// PQInnerData is the RSA-protected payload of step 3. Its whole purpose is to
// deliver new_nonce to the server and nobody else.
//
// Unlike every other structure here it has a fixed binary layout rather than a
// JSON body, because it must fit inside one RSA-OAEP block: a 2048-bit key
// with SHA-256 OAEP carries at most 190 bytes, and the JSON rendering of three
// nonces alone exceeds that. The layout is 88 bytes:
//
//	pq(8) ‖ p(8) ‖ q(8) ‖ nonce(16) ‖ server_nonce(16) ‖ new_nonce(32)
type PQInnerData struct {
	PQ          uint64
	P           uint64
	Q           uint64
	Nonce       [16]byte
	ServerNonce [16]byte
	NewNonce    [32]byte
}

// pqInnerDataSize is the fixed wire size of PQInnerData.
const pqInnerDataSize = 8 + 8 + 8 + 16 + 16 + 32

// MarshalBinary renders the fixed layout.
func (d PQInnerData) MarshalBinary() ([]byte, error) {
	out := make([]byte, pqInnerDataSize)
	binary.BigEndian.PutUint64(out[0:8], d.PQ)
	binary.BigEndian.PutUint64(out[8:16], d.P)
	binary.BigEndian.PutUint64(out[16:24], d.Q)
	copy(out[24:40], d.Nonce[:])
	copy(out[40:56], d.ServerNonce[:])
	copy(out[56:88], d.NewNonce[:])
	return out, nil
}

// UnmarshalBinary parses the fixed layout.
func (d *PQInnerData) UnmarshalBinary(b []byte) error {
	if len(b) != pqInnerDataSize {
		return fmt.Errorf("mtproto: pq_inner_data must be %d bytes, got %d", pqInnerDataSize, len(b))
	}
	d.PQ = binary.BigEndian.Uint64(b[0:8])
	d.P = binary.BigEndian.Uint64(b[8:16])
	d.Q = binary.BigEndian.Uint64(b[16:24])
	copy(d.Nonce[:], b[24:40])
	copy(d.ServerNonce[:], b[40:56])
	copy(d.NewNonce[:], b[56:88])
	return nil
}

// ServerDHParams is step 4.
type ServerDHParams struct {
	Nonce       [16]byte `json:"nonce"`
	ServerNonce [16]byte `json:"server_nonce"`
	// EncryptedAnswer is AES-IGE(ServerDHInnerData) under the temporary key.
	EncryptedAnswer []byte `json:"encrypted_answer"`
}

// ServerDHInnerData carries the group and the server's public value.
type ServerDHInnerData struct {
	Nonce       [16]byte `json:"nonce"`
	ServerNonce [16]byte `json:"server_nonce"`
	G           int32    `json:"g"`
	DHPrime     []byte   `json:"dh_prime"`
	GA          []byte   `json:"g_a"`
	ServerTime  int64    `json:"server_time"`
}

// SetClientDHParams is step 5.
type SetClientDHParams struct {
	Nonce         [16]byte `json:"nonce"`
	ServerNonce   [16]byte `json:"server_nonce"`
	EncryptedData []byte   `json:"encrypted_data"`
}

// ClientDHInnerData carries the client's public value.
type ClientDHInnerData struct {
	Nonce       [16]byte `json:"nonce"`
	ServerNonce [16]byte `json:"server_nonce"`
	RetryID     int64    `json:"retry_id"`
	GB          []byte   `json:"g_b"`
}

// DHGenOK is the server's confirmation that both sides derived the same key.
type DHGenOK struct {
	Nonce        [16]byte `json:"nonce"`
	ServerNonce  [16]byte `json:"server_nonce"`
	NewNonceHash [16]byte `json:"new_nonce_hash"`
}

// HandshakeError is returned to the client when a step fails. It carries no
// detail beyond a stable code: telling an attacker *why* their forged
// handshake was rejected turns the server into an oracle.
type HandshakeError struct {
	Code string `json:"code"`
}

func encodeInner(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("mtproto: encode inner data: %w", err)
	}
	return b, nil
}

func decodeInner(b []byte, v any) error {
	if err := json.Unmarshal(b, v); err != nil {
		return fmt.Errorf("mtproto: decode inner data: %w", err)
	}
	return nil
}
