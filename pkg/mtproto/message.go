package mtproto

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"sync/atomic"
	"time"
)

// Envelope sizes.
const (
	authKeyIDSize = 8
	msgKeySize    = 16
	// headerSize is salt(8) + session_id(8) + msg_id(8) + seq_no(4) + length(4).
	headerSize = 32

	minPadding = 12
	maxPadding = 1024

	// MaxMessageSize caps the decrypted body. A client that claims a larger
	// length is either broken or hostile; either way we refuse before
	// allocating.
	MaxMessageSize = 16 << 20 // 16 MiB
)

// Errors returned while parsing.
var (
	ErrShortFrame     = errors.New("mtproto: frame is too short")
	ErrUnknownAuthKey = errors.New("mtproto: unknown auth key id")
	ErrBadLength      = errors.New("mtproto: declared body length is invalid")
	ErrBadPadding     = errors.New("mtproto: padding is out of range")
	ErrBadSession     = errors.New("mtproto: session id mismatch")
	ErrBadSalt        = errors.New("mtproto: server salt mismatch")
	ErrMsgIDTooOld    = errors.New("mtproto: msg_id is outside the accepted time window (too old)")
	ErrMsgIDTooNew    = errors.New("mtproto: msg_id is outside the accepted time window (too far ahead)")
	ErrMsgIDReplay    = errors.New("mtproto: msg_id has already been seen")
	ErrMsgIDParity    = errors.New("mtproto: msg_id parity is wrong for its direction")
)

// Message is a decrypted MTProto message.
type Message struct {
	Salt      int64
	SessionID int64
	MsgID     int64
	SeqNo     int32
	Body      []byte
}

// Time returns the wall-clock time encoded in the msg_id.
func (m *Message) Time() time.Time { return time.Unix(m.MsgID>>32, 0) }

// IsContentRelated reports whether the message counts towards the sequence
// number. Acknowledgements and pings do not; RPC calls do.
func (m *Message) IsContentRelated() bool { return m.SeqNo%2 == 1 }

// Encrypt builds the wire frame for a message.
//
// Layout: auth_key_id(8) ‖ msg_key(16) ‖ AES-IGE(header ‖ body ‖ padding)
func Encrypt(k *AuthKey, m *Message, d Direction) ([]byte, error) {
	if len(m.Body) > MaxMessageSize {
		return nil, fmt.Errorf("mtproto: body of %d bytes exceeds the limit", len(m.Body))
	}

	// Padding is random in length as well as content: a fixed padding would
	// leak the exact body size, and MTProto 2.0 requires 12..1024 bytes taking
	// the total to a 16-byte boundary.
	unpadded := headerSize + len(m.Body)
	pad := minPadding + (16 - (unpadded+minPadding)%16)
	if pad < minPadding {
		pad += 16
	}

	plaintext := make([]byte, 0, unpadded+pad)
	var hdr [headerSize]byte
	binary.LittleEndian.PutUint64(hdr[0:8], uint64(m.Salt))
	binary.LittleEndian.PutUint64(hdr[8:16], uint64(m.SessionID))
	binary.LittleEndian.PutUint64(hdr[16:24], uint64(m.MsgID))
	binary.LittleEndian.PutUint32(hdr[24:28], uint32(m.SeqNo))
	binary.LittleEndian.PutUint32(hdr[28:32], uint32(len(m.Body)))
	plaintext = append(plaintext, hdr[:]...)
	plaintext = append(plaintext, m.Body...)

	padding := make([]byte, pad)
	if _, err := rand.Read(padding); err != nil {
		return nil, fmt.Errorf("mtproto: read padding: %w", err)
	}
	plaintext = append(plaintext, padding...)

	msgKey := k.MsgKey(plaintext, d)
	aesKey, aesIV, err := k.DeriveAESKeyIV(msgKey, d)
	if err != nil {
		return nil, err
	}
	ciphertext, err := IGEEncrypt(aesKey, aesIV, plaintext)
	if err != nil {
		return nil, err
	}

	out := make([]byte, 0, authKeyIDSize+msgKeySize+len(ciphertext))
	var idBuf [8]byte
	binary.LittleEndian.PutUint64(idBuf[:], k.ID())
	out = append(out, idBuf[:]...)
	out = append(out, msgKey...)
	out = append(out, ciphertext...)
	return out, nil
}

// PeekAuthKeyID reads the auth key id from a frame without decrypting it, so
// the gateway can look up the session before it has a key to work with.
//
// An id of zero marks an unencrypted message, which is only legal during the
// handshake.
func PeekAuthKeyID(frame []byte) (uint64, error) {
	if len(frame) < authKeyIDSize {
		return 0, ErrShortFrame
	}
	return binary.LittleEndian.Uint64(frame[:authKeyIDSize]), nil
}

// Decrypt parses and authenticates a wire frame.
func Decrypt(k *AuthKey, frame []byte, d Direction) (*Message, error) {
	if len(frame) < authKeyIDSize+msgKeySize+headerSize+minPadding {
		return nil, ErrShortFrame
	}

	gotID := binary.LittleEndian.Uint64(frame[:authKeyIDSize])
	if gotID != k.ID() {
		return nil, fmt.Errorf("%w: %s", ErrUnknownAuthKey, AuthKeyIDHex(gotID))
	}

	msgKey := frame[authKeyIDSize : authKeyIDSize+msgKeySize]
	ciphertext := frame[authKeyIDSize+msgKeySize:]
	if len(ciphertext)%blockSize != 0 {
		return nil, ErrBlockSize
	}

	aesKey, aesIV, err := k.DeriveAESKeyIV(msgKey, d)
	if err != nil {
		return nil, err
	}
	plaintext, err := IGEDecrypt(aesKey, aesIV, ciphertext)
	if err != nil {
		return nil, err
	}

	// Authenticate before parsing. Everything below this line is trusted only
	// because this check passed.
	if err := k.VerifyMsgKey(plaintext, msgKey, d); err != nil {
		return nil, err
	}

	bodyLen := int(binary.LittleEndian.Uint32(plaintext[28:32]))
	if bodyLen < 0 || bodyLen > MaxMessageSize || headerSize+bodyLen > len(plaintext) {
		return nil, fmt.Errorf("%w: %d in a %d byte plaintext", ErrBadLength, bodyLen, len(plaintext))
	}
	if pad := len(plaintext) - headerSize - bodyLen; pad < minPadding || pad > maxPadding {
		return nil, fmt.Errorf("%w: %d bytes", ErrBadPadding, pad)
	}

	body := make([]byte, bodyLen)
	copy(body, plaintext[headerSize:headerSize+bodyLen])

	return &Message{
		Salt:      int64(binary.LittleEndian.Uint64(plaintext[0:8])),
		SessionID: int64(binary.LittleEndian.Uint64(plaintext[8:16])),
		MsgID:     int64(binary.LittleEndian.Uint64(plaintext[16:24])),
		SeqNo:     int32(binary.LittleEndian.Uint32(plaintext[24:28])),
		Body:      body,
	}, nil
}

// ---------------------------------------------------------------------------
// Unencrypted messages (handshake only)
// ---------------------------------------------------------------------------

// EncodePlain builds an unencrypted frame: auth_key_id(0) ‖ msg_id ‖ len ‖ body.
func EncodePlain(msgID int64, body []byte) []byte {
	out := make([]byte, 20+len(body))
	binary.LittleEndian.PutUint64(out[0:8], 0)
	binary.LittleEndian.PutUint64(out[8:16], uint64(msgID))
	binary.LittleEndian.PutUint32(out[16:20], uint32(len(body)))
	copy(out[20:], body)
	return out
}

// DecodePlain parses an unencrypted frame.
//
// The gateway only accepts these while a connection is still unauthenticated
// and only for handshake constructors; accepting them afterwards would let an
// attacker bypass encryption entirely by simply setting auth_key_id to zero.
func DecodePlain(frame []byte) (msgID int64, body []byte, err error) {
	if len(frame) < 20 {
		return 0, nil, ErrShortFrame
	}
	if id := binary.LittleEndian.Uint64(frame[0:8]); id != 0 {
		return 0, nil, fmt.Errorf("mtproto: not a plain message (auth_key_id=%s)", AuthKeyIDHex(id))
	}
	msgID = int64(binary.LittleEndian.Uint64(frame[8:16]))
	n := int(binary.LittleEndian.Uint32(frame[16:20]))
	if n < 0 || n > MaxMessageSize || 20+n > len(frame) {
		return 0, nil, fmt.Errorf("%w: %d", ErrBadLength, n)
	}
	body = make([]byte, n)
	copy(body, frame[20:20+n])
	return msgID, body, nil
}

// ---------------------------------------------------------------------------
// Message identifiers
// ---------------------------------------------------------------------------

// MsgIDGenerator produces monotonically increasing message identifiers.
//
// The high 32 bits are unix seconds and the low 32 bits are a counter, so a
// msg_id is simultaneously a timestamp, a nonce and an ordering key. The low
// two bits encode the message kind, which is how the peer distinguishes an
// RPC call from a response or a service message without parsing the body.
type MsgIDGenerator struct {
	last atomic.Int64
	// offset absorbs a client whose clock is ahead of ours: the server adopts
	// the client's time base for the session rather than rejecting every
	// message.
	offset atomic.Int64
}

// Message kind encoded in the low two bits of a msg_id.
const (
	// KindFromClient marks a client-originated call: bits 00.
	KindFromClient = 0
	// KindFromServerResponse marks a reply to a client call: bits 01.
	KindFromServerResponse = 1
	// KindFromServerPush marks a server-initiated update: bits 11.
	KindFromServerPush = 3
)

// Next returns the next msg_id with the given kind in its low two bits.
func (g *MsgIDGenerator) Next(kind int) int64 {
	for {
		now := time.Now().Unix() + g.offset.Load()
		candidate := now << 32

		prev := g.last.Load()
		if candidate <= prev {
			// Same second, or the clock went backwards. Step past the last id
			// so the sequence stays strictly increasing.
			candidate = prev + 4
		}
		candidate = candidate&^3 | int64(kind&3)

		if candidate <= prev {
			candidate = (prev+4)&^3 | int64(kind&3)
		}
		if g.last.CompareAndSwap(prev, candidate) {
			return candidate
		}
	}
}

// AdoptPeerTime shifts our time base towards a peer whose clock differs.
func (g *MsgIDGenerator) AdoptPeerTime(peerMsgID int64) {
	peerSeconds := peerMsgID >> 32
	delta := peerSeconds - time.Now().Unix()
	if delta > 0 {
		g.offset.Store(delta)
	}
}

// MsgIDValidator enforces the time window and rejects replays.
//
// MTProto's rule is that a client msg_id must be within roughly 300 seconds
// behind and 30 seconds ahead of server time, and must not repeat within a
// session. That window is what stops an attacker replaying a captured
// "delete my account" call an hour later.
type MsgIDValidator struct {
	// Behind is how far in the past a msg_id may be.
	Behind time.Duration
	// Ahead is how far in the future a msg_id may be. Smaller than Behind
	// because a client legitimately lags (mobile networks) but should never
	// be meaningfully ahead.
	Ahead time.Duration

	mu   sync.Mutex
	seen map[int64]time.Time
	// maxSeen bounds memory: the window is time-limited anyway, so once the
	// map is this large we sweep entries that have aged out.
	maxSeen int
}

// NewMsgIDValidator returns a validator with MTProto's default window.
func NewMsgIDValidator() *MsgIDValidator {
	return &MsgIDValidator{
		Behind:  300 * time.Second,
		Ahead:   30 * time.Second,
		seen:    make(map[int64]time.Time, 256),
		maxSeen: 8192,
	}
}

// Check validates a client-originated msg_id.
func (v *MsgIDValidator) Check(msgID int64) error {
	// Client messages must have even ids; an odd id means the client is
	// echoing a server id back, which no legitimate client does.
	if msgID&1 != 0 {
		return ErrMsgIDParity
	}

	now := time.Now()
	ts := time.Unix(msgID>>32, 0)
	if now.Sub(ts) > v.Behind {
		return fmt.Errorf("%w: %s is %s old", ErrMsgIDTooOld, ts.UTC(), now.Sub(ts))
	}
	if ts.Sub(now) > v.Ahead {
		return fmt.Errorf("%w: %s is %s ahead", ErrMsgIDTooNew, ts.UTC(), ts.Sub(now))
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	if _, dup := v.seen[msgID]; dup {
		return ErrMsgIDReplay
	}
	if len(v.seen) >= v.maxSeen {
		cutoff := now.Add(-v.Behind)
		for id, at := range v.seen {
			if at.Before(cutoff) {
				delete(v.seen, id)
			}
		}
		// If the sweep freed nothing the peer is flooding us with fresh ids;
		// drop the oldest half rather than grow without bound.
		if len(v.seen) >= v.maxSeen {
			n := len(v.seen) / 2
			for id := range v.seen {
				delete(v.seen, id)
				if n--; n <= 0 {
					break
				}
			}
		}
	}
	v.seen[msgID] = now
	return nil
}

// SeqNoCounter tracks the per-session sequence number.
//
// Content-related messages get odd numbers and increment the counter; service
// messages get even numbers and do not. The peer uses the parity to know
// which messages it must acknowledge.
type SeqNoCounter struct{ n atomic.Int32 }

// Next returns the next sequence number.
func (c *SeqNoCounter) Next(contentRelated bool) int32 {
	if !contentRelated {
		return c.n.Load() * 2
	}
	v := c.n.Add(1)
	return v*2 - 1
}

// NewSalt generates a random server salt.
//
// Salts rotate hourly. A message carrying an expired salt is answered with
// bad_server_salt rather than dropped, so a client that was offline across a
// rotation recovers in one round trip instead of re-authenticating.
func NewSalt() (int64, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return 0, fmt.Errorf("mtproto: generate salt: %w", err)
	}
	return n.Int64(), nil
}
