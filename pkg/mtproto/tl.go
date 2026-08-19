package mtproto

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
)

// Payload encoding: a 4-byte little-endian constructor id followed by a JSON
// body.
//
// This replaces Telegram's TL. The constructor id is kept because everything
// above it — dispatch, containers, acknowledgements, the update stream —
// keys off "what kind of thing is this?" without needing to parse the body,
// and because it makes the wire self-describing for tooling. Swapping JSON
// for TL, protobuf or CBOR later means changing only Encode/Decode below.

// ConstructorID identifies a method, response or update.
type ConstructorID uint32

// Handshake constructors (sent in plain messages).
const (
	CReqPQ             ConstructorID = 0x60469778
	CResPQ             ConstructorID = 0x05162463
	CReqDHParams       ConstructorID = 0xd712e4be
	CServerDHParams    ConstructorID = 0xd0e8075c
	CSetClientDHParams ConstructorID = 0xf5045f1f
	CDHGenOK           ConstructorID = 0x3bcbf734
	CHandshakeError    ConstructorID = 0x0a1b2c3d
)

// Service constructors (encrypted, not content-related).
const (
	CPing            ConstructorID = 0x7abe77ec
	CPong            ConstructorID = 0x347773c5
	CMsgsAck         ConstructorID = 0x62d6b459
	CBadMsgNotify    ConstructorID = 0xa7eff811
	CBadServerSalt   ConstructorID = 0xedab447b
	CNewSessionReset ConstructorID = 0x9ec20908
	CMsgContainer    ConstructorID = 0x73f1f8dc
	CRPCError        ConstructorID = 0x2144ca19
	CRPCResult       ConstructorID = 0xf35c6d01
	CDestroySession  ConstructorID = 0xe7512126
)

// API constructors (encrypted, content-related).
const (
	CAuthBind        ConstructorID = 0x10000001 // bind an auth key to a JWT session
	CAuthBindResult  ConstructorID = 0x10000002
	CSendMessage     ConstructorID = 0x10000010
	CSendMessageResp ConstructorID = 0x10000011
	CGetHistory      ConstructorID = 0x10000012
	CGetHistoryResp  ConstructorID = 0x10000013
	CGetDifference   ConstructorID = 0x10000014
	CDifferenceResp  ConstructorID = 0x10000015
	CReadHistory     ConstructorID = 0x10000016
	CReadHistoryResp ConstructorID = 0x10000017
	CSetTyping       ConstructorID = 0x10000018
	CGetDialogs      ConstructorID = 0x10000019
	CGetDialogsResp  ConstructorID = 0x1000001a
	CUpdate          ConstructorID = 0x10000030 // server-pushed update
	COK              ConstructorID = 0x10000031
	CSearchMessages  ConstructorID = 0x10000032
	CSearchResp      ConstructorID = 0x10000033
)

// Secret-chat constructors.
//
// The server relays these without understanding them: it forwards two public
// Diffie-Hellman values and never sees a key.
const (
	CRequestEncryption ConstructorID = 0x10000040
	CAcceptEncryption  ConstructorID = 0x10000041
	CDiscardEncryption ConstructorID = 0x10000042
	CSecretChatState   ConstructorID = 0x10000043
	CSendEncrypted     ConstructorID = 0x10000044
	CSetSecretTTL      ConstructorID = 0x10000045
)

// Call-signalling constructors.
//
// Signalling only. The media never touches our servers: it is peer-to-peer,
// or relayed by TURN when a NAT forbids that.
const (
	CRequestCall  ConstructorID = 0x10000050
	CAcceptCall   ConstructorID = 0x10000051
	CDiscardCall  ConstructorID = 0x10000052
	CCallSignal   ConstructorID = 0x10000053 // SDP and ICE relay
	CGetTURNCreds ConstructorID = 0x10000054
	CCallState    ConstructorID = 0x10000055
)

// Errors.
var (
	ErrShortPayload       = errors.New("mtproto: payload is shorter than a constructor id")
	ErrUnknownConstructor = errors.New("mtproto: unknown constructor")
)

// Encode builds a payload from a constructor id and a value.
func Encode(id ConstructorID, v any) ([]byte, error) {
	body, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("mtproto: encode %#x: %w", uint32(id), err)
	}
	out := make([]byte, 4+len(body))
	binary.LittleEndian.PutUint32(out[:4], uint32(id))
	copy(out[4:], body)
	return out, nil
}

// PeekConstructor reads the constructor without decoding the body, so the
// dispatcher can route before it knows the concrete type.
func PeekConstructor(payload []byte) (ConstructorID, error) {
	if len(payload) < 4 {
		return 0, ErrShortPayload
	}
	return ConstructorID(binary.LittleEndian.Uint32(payload[:4])), nil
}

// Decode unmarshals the body into v.
func Decode(payload []byte, v any) error {
	if len(payload) < 4 {
		return ErrShortPayload
	}
	if err := json.Unmarshal(payload[4:], v); err != nil {
		return fmt.Errorf("mtproto: decode body: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Service messages
// ---------------------------------------------------------------------------

// Ping keeps a connection warm and measures round-trip time.
type Ping struct {
	PingID int64 `json:"ping_id"`
	// DisconnectAfter, when non-zero, asks the server to close the connection
	// if no ping arrives within that many seconds. It is how a mobile client
	// tells the server to release resources promptly when the app is
	// backgrounded, instead of waiting for a TCP timeout.
	DisconnectAfter int32 `json:"disconnect_after,omitempty"`
}

// Pong answers a ping.
type Pong struct {
	MsgID  int64 `json:"msg_id"`
	PingID int64 `json:"ping_id"`
	// ServerTime lets the client correct its clock, which matters because
	// msg_id validation depends on the two clocks staying close.
	ServerTime int64 `json:"server_time"`
}

// MsgsAck acknowledges received content messages so the peer can stop
// retransmitting them.
type MsgsAck struct {
	MsgIDs []int64 `json:"msg_ids"`
}

// BadMsgNotification tells a client its msg_id or seq_no was rejected, with
// the reason, so it can correct itself rather than retry blindly.
type BadMsgNotification struct {
	BadMsgID  int64 `json:"bad_msg_id"`
	BadSeqNo  int32 `json:"bad_msg_seqno"`
	ErrorCode int32 `json:"error_code"`
}

// Bad-message error codes.
const (
	BadMsgIDTooLow    int32 = 16 // msg_id too far in the past
	BadMsgIDTooHigh   int32 = 17 // msg_id too far in the future
	BadMsgIDEvenOdd   int32 = 18 // wrong parity
	BadMsgIDDuplicate int32 = 19 // already seen
	BadSeqNoTooLow    int32 = 32
	BadSeqNoTooHigh   int32 = 33
	BadSeqNoEven      int32 = 34
	BadSeqNoOdd       int32 = 35
	BadSaltInvalid    int32 = 48
)

// BadServerSalt carries the correct salt after a rotation.
type BadServerSalt struct {
	BadMsgID  int64 `json:"bad_msg_id"`
	BadSeqNo  int32 `json:"bad_msg_seqno"`
	ErrorCode int32 `json:"error_code"`
	NewSalt   int64 `json:"new_server_salt"`
}

// NewSessionCreated tells the client the server started a new session, so any
// unacknowledged messages must be resent.
type NewSessionCreated struct {
	FirstMsgID int64 `json:"first_msg_id"`
	UniqueID   int64 `json:"unique_id"`
	ServerSalt int64 `json:"server_salt"`
}

// RPCResult wraps a method's return value with the id of the call it answers.
type RPCResult struct {
	ReqMsgID int64           `json:"req_msg_id"`
	Result   json.RawMessage `json:"result"`
}

// RPCError is a method failure.
type RPCError struct {
	ReqMsgID int64  `json:"req_msg_id"`
	Code     int32  `json:"error_code"`
	Message  string `json:"error_message"`
}

func (e *RPCError) Error() string {
	return fmt.Sprintf("mtproto rpc error %d: %s", e.Code, e.Message)
}

// FloodWait renders the flood-control error a client must back off on. The
// suffix is the number of seconds, matching MTProto's FLOOD_WAIT_X convention
// so clients can parse the delay out of the string.
func FloodWait(seconds int) *RPCError {
	return &RPCError{Code: 420, Message: fmt.Sprintf("FLOOD_WAIT_%d", seconds)}
}

// MsgContainer batches several messages into one frame. A phone waking from
// sleep sends its pending acks, a ping and a getDifference together, which is
// one round trip instead of three.
type MsgContainer struct {
	Messages []ContainedMessage `json:"messages"`
}

// ContainedMessage is one element of a container.
type ContainedMessage struct {
	MsgID   int64  `json:"msg_id"`
	SeqNo   int32  `json:"seqno"`
	Payload []byte `json:"payload"`
}

// DestroySession asks the server to forget a session.
type DestroySession struct {
	SessionID int64 `json:"session_id"`
}
