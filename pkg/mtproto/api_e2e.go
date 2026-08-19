package mtproto

import "time"

// Secret chats and call signalling.
//
// Both are relay protocols: the server carries opaque payloads between two
// devices and enforces only who may talk to whom. It cannot read a secret
// chat's messages, and it never sees a byte of call media.

// ---------------------------------------------------------------------------
// Secret chats
// ---------------------------------------------------------------------------

// RequestEncryption starts an end-to-end encrypted conversation.
//
// GA is the initiator's Diffie-Hellman public value, base64-encoded. The
// server relays it and stores it; it is exactly what a passive observer of
// any DH exchange sees, and it does not yield the key.
type RequestEncryption struct {
	PeerID int64 `json:"peer_id"`
	// GA is base64(g^a mod p) with the RFC 3526 group 14 parameters.
	GA string `json:"g_a"`
	// RandomID makes the request idempotent, as with sending a message.
	RandomID int64 `json:"random_id"`
}

// AcceptEncryption completes the exchange from the other side.
type AcceptEncryption struct {
	ChatID int64 `json:"chat_id"`
	// GB is base64(g^b mod p).
	GB string `json:"g_b"`
	// KeyFingerprint lets the initiator confirm both sides derived the same
	// key. It is a hash of the key, not the key.
	KeyFingerprint int64 `json:"key_fingerprint"`
}

// DiscardEncryption ends a secret chat. Terminal — a discarded chat is never
// revived, because reviving one would mean reusing a key whose material one
// side has already destroyed.
type DiscardEncryption struct {
	ChatID int64 `json:"chat_id"`
	// DeleteHistory asks the peer's client to erase its local copy. The
	// server cannot enforce this: it never had the plaintext. It is a request
	// to a client the user already chose to trust.
	DeleteHistory bool `json:"delete_history,omitempty"`
}

// SecretChatState is what the server can say about a secret chat.
type SecretChatState struct {
	ChatID         int64     `json:"chat_id"`
	AdminID        int64     `json:"admin_id"`
	PeerID         int64     `json:"peer_id"`
	State          string    `json:"state"` // requested|ready|discarded
	GA             string    `json:"g_a,omitempty"`
	GB             string    `json:"g_b,omitempty"`
	KeyFingerprint int64     `json:"key_fingerprint,omitempty"`
	TTLSeconds     int       `json:"ttl_seconds"`
	CreatedAt      time.Time `json:"created_at"`
}

// SendEncrypted carries a client-encrypted payload.
//
// Body is ciphertext the server cannot read and does not try to. It is not
// indexed, no push preview is generated from it, and the persister stores it
// as opaque bytes.
type SendEncrypted struct {
	ChatID int64 `json:"chat_id"`
	// Body is base64 ciphertext produced by the client.
	Body string `json:"body"`
	// RandomID deduplicates a retry, as elsewhere.
	RandomID int64 `json:"random_id"`
	// KeyFingerprint identifies which key encrypted this, so a client that
	// has rekeyed knows which one to try.
	KeyFingerprint int64 `json:"key_fingerprint"`
}

// SetSecretTTL sets the self-destruct timer.
//
// Enforced entirely by the clients. The server stores the value so it
// survives a reinstall, and cannot apply it, because it cannot read the
// messages to delete them.
type SetSecretTTL struct {
	ChatID     int64 `json:"chat_id"`
	TTLSeconds int   `json:"ttl_seconds"`
}

// ---------------------------------------------------------------------------
// Calls
// ---------------------------------------------------------------------------

// CallState enumerates a call's lifecycle.
const (
	CallStateRequested = "requested"
	CallStateRinging   = "ringing"
	CallStateActive    = "active"
	CallStateEnded     = "ended"
)

// RequestCall starts an outgoing call.
type RequestCall struct {
	PeerID int64 `json:"peer_id"`
	// Video distinguishes a video call from voice. The protocol is
	// identical; this only tells the callee's UI what to show.
	Video bool `json:"video"`
	// GAHash commits the caller to a DH value without revealing it yet.
	//
	// The commitment matters: without it the callee, who answers second,
	// could choose its own value after seeing the caller's and steer the
	// shared key. Publishing a hash first and the value later removes that
	// freedom.
	GAHash string `json:"g_a_hash"`
	// RandomID deduplicates a retried request.
	RandomID int64 `json:"random_id"`
	// Protocol is what the caller's client supports, so the two can agree
	// before any media flows.
	Protocol CallProtocol `json:"protocol"`
}

// CallProtocol is a client's capability set.
type CallProtocol struct {
	MinLayer        int      `json:"min_layer"`
	MaxLayer        int      `json:"max_layer"`
	UDPP2P          bool     `json:"udp_p2p"`
	UDPReflector    bool     `json:"udp_reflector"`
	LibraryVersions []string `json:"library_versions,omitempty"`
}

// AcceptCall answers an incoming call.
type AcceptCall struct {
	CallID int64 `json:"call_id"`
	// GB is the callee's DH public value, base64.
	GB       string       `json:"g_b"`
	Protocol CallProtocol `json:"protocol"`
}

// ConfirmCall is the caller revealing the value it committed to.
type ConfirmCall struct {
	CallID int64 `json:"call_id"`
	// GA must hash to the GAHash sent in RequestCall, or the callee refuses.
	GA             string `json:"g_a"`
	KeyFingerprint int64  `json:"key_fingerprint"`
}

// DiscardCall ends a call.
type DiscardCall struct {
	CallID   int64  `json:"call_id"`
	Reason   string `json:"reason"` // hangup|busy|missed|disconnect
	Duration int    `json:"duration,omitempty"`
	// Rating and comment feed call-quality telemetry, if the user offers them.
	Rating  int    `json:"rating,omitempty"`
	Comment string `json:"comment,omitempty"`
}

// CallSignal relays one SDP or ICE message.
//
// The server does not parse the payload. It checks only that the sender is a
// party to the call, and forwards.
type CallSignal struct {
	CallID int64 `json:"call_id"`
	// Kind is offer|answer|candidate|end-of-candidates.
	Kind string `json:"kind"`
	// Payload is the opaque SDP or ICE candidate.
	Payload string `json:"payload"`
}

// TURNCredentials are time-limited credentials for the relay.
//
// Long-lived TURN credentials are a standing invitation to use someone else's
// relay bandwidth. These are derived by HMAC over an expiry timestamp, so
// they cannot be minted by anyone without the shared secret and they stop
// working on their own.
type TURNCredentials struct {
	Username string   `json:"username"`
	Password string   `json:"password"`
	URIs     []string `json:"uris"`
	TTL      int      `json:"ttl"`
	// STUNURIs need no credentials: a STUN server only reports the address it
	// sees, which is not worth protecting.
	STUNURIs []string `json:"stun_uris,omitempty"`
}

// CallStateUpdate is what the server pushes as a call progresses.
type CallStateUpdate struct {
	CallID   int64         `json:"call_id"`
	State    string        `json:"state"`
	PeerID   int64         `json:"peer_id"`
	Video    bool          `json:"video,omitempty"`
	GAHash   string        `json:"g_a_hash,omitempty"`
	GA       string        `json:"g_a,omitempty"`
	GB       string        `json:"g_b,omitempty"`
	Reason   string        `json:"reason,omitempty"`
	Protocol *CallProtocol `json:"protocol,omitempty"`
}

// SearchMessages runs a full-text search over the caller's chats.
type SearchMessages struct {
	Query    string `json:"q"`
	ChatID   int64  `json:"chat_id,omitempty"`
	SenderID int64  `json:"sender_id,omitempty"`
	Limit    int    `json:"limit,omitempty"`
	Offset   int    `json:"offset,omitempty"`
}
