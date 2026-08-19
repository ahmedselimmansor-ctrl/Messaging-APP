package mtproto

import "time"

// The API surface the realtime gateway exposes over MTProto.
//
// It is deliberately narrow. Everything that is latency-critical or
// high-volume — sending, reading, catching up, typing — goes over the
// realtime connection. Everything else (registration, profile edits, media
// upload negotiation, contact import) goes over REST, where request/response
// semantics, caching and the CDN all work in our favour.

// AuthBind attaches an authenticated identity to a negotiated auth key.
//
// The handshake proves the channel is private; it says nothing about *who* is
// on the other end. The client obtains a JWT from the auth service over REST
// and presents it here exactly once, after which the auth key itself carries
// the identity for the lifetime of the session.
type AuthBind struct {
	AccessToken string `json:"access_token"`
	Platform    string `json:"platform"`
	AppVersion  string `json:"app_version"`
	DeviceModel string `json:"device_model"`
	LangCode    string `json:"lang_code,omitempty"`
	// PushToken registers this device for FCM in the same round trip.
	PushToken string `json:"push_token,omitempty"`
}

// AuthBindResult confirms the binding.
type AuthBindResult struct {
	UserID   int64 `json:"user_id"`
	DeviceID int64 `json:"device_id"`
	// ServerSalt and SessionID let the client start encrypting immediately.
	ServerSalt int64 `json:"server_salt"`
	SessionID  int64 `json:"session_id"`
	ServerTime int64 `json:"server_time"`
	// QTS is the client's current position in its update stream, used by
	// GetDifference to resume.
	QTS int64 `json:"qts"`
}

// SendMessage posts a message to a chat.
type SendMessage struct {
	ChatID int64  `json:"chat_id"`
	Type   string `json:"type"` // text|photo|video|voice|file|sticker
	Body   string `json:"body,omitempty"`
	// RandomID makes sends idempotent. A client that retries after a network
	// failure sends the same value and gets the original message back rather
	// than posting a duplicate — the single most visible correctness bug a
	// chat app can have.
	RandomID int64 `json:"random_id"`
	// ReplyToSeq threads the message.
	ReplyToSeq int64 `json:"reply_to_seq,omitempty"`
	// MediaObject is the GCS object path from a completed upload.
	MediaObject string `json:"media_object,omitempty"`
	MediaMime   string `json:"media_mime,omitempty"`
	MediaSize   int64  `json:"media_size,omitempty"`
	// Encrypted marks a secret-chat payload the server must not inspect.
	Encrypted bool `json:"encrypted,omitempty"`
}

// SendMessageResult confirms acceptance.
//
// Seq is assigned before the message is durable, so the client can render it
// immediately in the right place. Durability follows within milliseconds; if
// it fails, the client learns through the update stream, not through this
// call.
type SendMessageResult struct {
	MessageID string `json:"message_id"`
	ChatID    int64  `json:"chat_id"`
	Seq       int64  `json:"seq"`
	Date      int64  `json:"date"`
	// Duplicate is true when RandomID matched an earlier send.
	Duplicate bool `json:"duplicate,omitempty"`
}

// GetHistory pages backwards through a chat.
type GetHistory struct {
	ChatID    int64 `json:"chat_id"`
	BeforeSeq int64 `json:"before_seq,omitempty"` // 0 means "from newest"
	Limit     int   `json:"limit"`
}

// HistoryMessage is one message in a history page.
type HistoryMessage struct {
	MessageID  string     `json:"message_id"`
	ChatID     int64      `json:"chat_id"`
	Seq        int64      `json:"seq"`
	SenderID   int64      `json:"sender_id"`
	Type       string     `json:"type"`
	Body       string     `json:"body,omitempty"`
	Encrypted  bool       `json:"encrypted,omitempty"`
	Media      any        `json:"media,omitempty"`
	ReplyToSeq int64      `json:"reply_to_seq,omitempty"`
	Date       time.Time  `json:"date"`
	EditedAt   *time.Time `json:"edited_at,omitempty"`
	Deleted    bool       `json:"deleted,omitempty"`
}

// GetHistoryResult is a page of history, newest first.
type GetHistoryResult struct {
	Messages []HistoryMessage `json:"messages"`
	// NextBeforeSeq is the cursor for the following page, 0 when exhausted.
	NextBeforeSeq int64 `json:"next_before_seq"`
}

// GetDifference is the catch-up call a client makes on reconnect.
//
// This is what makes a fire-and-forget realtime layer safe: anything the
// client missed while disconnected is recovered from durable storage by
// asking for everything after the last sequence it saw, per chat.
type GetDifference struct {
	// Cursors maps chat_id to the last sequence the client holds.
	Cursors map[int64]int64 `json:"cursors"`
	// Limit bounds the total messages returned across all chats.
	Limit int `json:"limit"`
}

// DifferenceResult carries the missed messages.
type DifferenceResult struct {
	Messages []HistoryMessage `json:"messages"`
	// Truncated tells the client the limit was hit and it must call again.
	Truncated bool `json:"truncated"`
	// NewCursors is the position to resume from next time.
	NewCursors map[int64]int64 `json:"new_cursors"`
}

// ReadHistory advances the read pointer.
type ReadHistory struct {
	ChatID int64 `json:"chat_id"`
	MaxSeq int64 `json:"max_seq"`
}

// ReadHistoryResult returns the resulting unread count.
type ReadHistoryResult struct {
	ChatID      int64 `json:"chat_id"`
	LastReadSeq int64 `json:"last_read_seq"`
	UnreadCount int64 `json:"unread_count"`
}

// SetTyping publishes a typing indicator.
//
// It is deliberately fire-and-forget with a short TTL: typing state is worth
// nothing a few seconds later, so it never touches durable storage and is
// never retried.
type SetTyping struct {
	ChatID int64  `json:"chat_id"`
	Action string `json:"action"` // typing|cancel|recording|uploading
}

// GetDialogs returns the chat list.
type GetDialogs struct {
	IncludeArchived bool `json:"include_archived,omitempty"`
	Limit           int  `json:"limit"`
	Offset          int  `json:"offset"`
}

// DialogEntry is one row of the chat list.
type DialogEntry struct {
	ChatID      int64  `json:"chat_id"`
	Type        string `json:"type"`
	Title       string `json:"title"`
	PeerID      int64  `json:"peer_id,omitempty"`
	MaxSeq      int64  `json:"max_seq"`
	LastReadSeq int64  `json:"last_read_seq"`
	UnreadCount int64  `json:"unread_count"`
	Muted       bool   `json:"muted"`
	Pinned      bool   `json:"pinned"`
	Archived    bool   `json:"archived"`
}

// GetDialogsResult is the chat list page.
type GetDialogsResult struct {
	Dialogs []DialogEntry `json:"dialogs"`
}

// Update is a server-pushed event.
type Update struct {
	Kind   string `json:"kind"`
	ChatID int64  `json:"chat_id,omitempty"`
	Seq    int64  `json:"seq,omitempty"`
	UserID int64  `json:"user_id,omitempty"`
	Date   int64  `json:"date"`
	// Payload is the kind-specific body, e.g. a HistoryMessage for
	// new_message.
	Payload any `json:"payload,omitempty"`
}

// OK is the empty success response.
type OK struct {
	OK bool `json:"ok"`
}
