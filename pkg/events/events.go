// Package events defines the Kafka topic names and the record schemas that
// travel between services.
//
// These structs are the platform's contract. They are versioned by an
// explicit `v` field rather than by topic name so that a rolling deploy can
// have producers and consumers of different versions alive at once: consumers
// must ignore unknown fields and tolerate v < their own.
package events

import (
	"encoding/json"
	"fmt"
	"time"
)

// Topic names. Partition counts and retention live in Terraform
// (deploy/terraform/modules/kafka), not here.
const (
	// TopicMessagesRaw carries every accepted message the instant the chat
	// service durably assigns it a sequence number. Keyed by chat_id so all
	// messages of one chat land on one partition and stay ordered.
	TopicMessagesRaw = "messages.raw"

	// TopicMessagesPersisted is emitted by the persister once the message is
	// committed to Cassandra. Push notifications and search indexing hang off
	// this topic, never off messages.raw, so we never notify a user about a
	// message that a later failure would have lost.
	TopicMessagesPersisted = "messages.persisted"

	// TopicPresenceEvents carries online/offline/typing transitions.
	TopicPresenceEvents = "presence.events"

	// TopicNotificationsPush carries explicit push requests that do not
	// originate from a chat message (calls, system notices).
	TopicNotificationsPush = "notifications.push"

	// TopicMediaProcessing carries uploaded-object references for
	// thumbnailing, transcoding and virus scanning.
	TopicMediaProcessing = "media.processing"

	// TopicMediaProcessed carries the derivatives once they exist, so the
	// chat service can attach them to the message that referenced the
	// original — or withdraw the message when the file turned out to be
	// malware.
	TopicMediaProcessed = "media.processed"

	// TopicUserEvents carries profile/account lifecycle changes.
	TopicUserEvents = "user.events"

	// TopicSearchIndex carries documents to (re)index in Elasticsearch.
	TopicSearchIndex = "search.index"

	// TopicDeadLetter receives records a consumer could not handle after
	// exhausting retries, with the failure reason attached.
	TopicDeadLetter = "platform.dlq"
)

// MessageType enumerates the payload kinds a message can hold.
type MessageType string

const (
	MessageText    MessageType = "text"
	MessagePhoto   MessageType = "photo"
	MessageVideo   MessageType = "video"
	MessageVoice   MessageType = "voice"
	MessageFile    MessageType = "file"
	MessageSticker MessageType = "sticker"
	MessageSystem  MessageType = "system"
)

// MediaRef points at an object in Cloud Storage.
type MediaRef struct {
	Bucket    string `json:"bucket"`
	Object    string `json:"object"`
	MimeType  string `json:"mime_type"`
	SizeBytes int64  `json:"size_bytes"`
	Width     int    `json:"width,omitempty"`
	Height    int    `json:"height,omitempty"`
	// DurationMS applies to video and voice.
	DurationMS int64 `json:"duration_ms,omitempty"`
	// ThumbObject is filled in by the media processing consumer.
	ThumbObject string `json:"thumb_object,omitempty"`
}

// MessageEvent is the record on messages.raw and messages.persisted.
type MessageEvent struct {
	V int `json:"v"`

	MessageID string      `json:"message_id"` // UUIDv4, client-visible
	ChatID    int64       `json:"chat_id"`
	Seq       int64       `json:"seq"` // dense per-chat sequence
	SenderID  int64       `json:"sender_id"`
	Type      MessageType `json:"type"`

	// Body is plaintext for cloud chats. For secret chats it is the opaque
	// client-encrypted blob and the server never sees the contents.
	Body      string    `json:"body,omitempty"`
	Encrypted bool      `json:"encrypted,omitempty"`
	Media     *MediaRef `json:"media,omitempty"`

	ReplyToSeq int64 `json:"reply_to_seq,omitempty"`
	// Recipients is the materialised member list at send time. The persister
	// and the pusher both need it and neither should have to hit Postgres.
	Recipients []int64 `json:"recipients,omitempty"`

	// ClientRandomID is the client-generated dedupe key. Retrying a send with
	// the same value must return the original message, not create a second.
	ClientRandomID int64 `json:"client_random_id,omitempty"`

	CreatedAt time.Time `json:"created_at"`
	// TraceParent carries W3C trace context across the broker so a message's
	// full path stays a single trace.
	TraceParent string `json:"traceparent,omitempty"`
}

// PresenceState enumerates presence transitions.
type PresenceState string

const (
	PresenceOnline  PresenceState = "online"
	PresenceOffline PresenceState = "offline"
	PresenceTyping  PresenceState = "typing"
)

// PresenceEvent is the record on presence.events.
type PresenceEvent struct {
	V         int           `json:"v"`
	UserID    int64         `json:"user_id"`
	DeviceID  int64         `json:"device_id,omitempty"`
	State     PresenceState `json:"state"`
	ChatID    int64         `json:"chat_id,omitempty"` // typing is per-chat
	At        time.Time     `json:"at"`
	ExpiresAt time.Time     `json:"expires_at,omitempty"`
}

// PushRequest is the record on notifications.push.
type PushRequest struct {
	V         int               `json:"v"`
	UserID    int64             `json:"user_id"`
	ChatID    int64             `json:"chat_id,omitempty"`
	MessageID string            `json:"message_id,omitempty"`
	Title     string            `json:"title"`
	Body      string            `json:"body"`
	Badge     int               `json:"badge,omitempty"`
	Data      map[string]string `json:"data,omitempty"`
	// CollapseKey lets FCM replace an undelivered notification for the same
	// chat rather than stacking twenty of them on a phone that was offline.
	CollapseKey string    `json:"collapse_key,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

// MediaVariant is one derivative of an uploaded object.
type MediaVariant struct {
	// Name is the suffix that produced it, e.g. "_s" or "_720p".
	Name      string `json:"name"`
	Object    string `json:"object"`
	MimeType  string `json:"mime_type"`
	Width     int    `json:"width,omitempty"`
	Height    int    `json:"height,omitempty"`
	SizeBytes int64  `json:"size_bytes"`
}

// MediaDerived is everything the processor learned or produced.
type MediaDerived struct {
	Width      int            `json:"width,omitempty"`
	Height     int            `json:"height,omitempty"`
	DurationMS int64          `json:"duration_ms,omitempty"`
	Variants   []MediaVariant `json:"variants,omitempty"`
}

// MediaProcessed is the record on media.processed.
type MediaProcessed struct {
	V        int    `json:"v"`
	UploadID string `json:"upload_id"`
	OwnerID  int64  `json:"owner_id"`
	Object   string `json:"object"`

	Derived MediaDerived `json:"derived,omitempty"`

	// Quarantined means the scanner found malware and the object has been
	// deleted. Any message referencing it must be withdrawn.
	Quarantined bool   `json:"quarantined,omitempty"`
	Threat      string `json:"threat,omitempty"`

	ProcessedAt time.Time `json:"processed_at"`
}

// MediaJob is the record on media.processing.
type MediaJob struct {
	V         int       `json:"v"`
	UploadID  string    `json:"upload_id"`
	OwnerID   int64     `json:"owner_id"`
	Media     MediaRef  `json:"media"`
	Ops       []string  `json:"ops"` // thumbnail|transcode|scan
	CreatedAt time.Time `json:"created_at"`
}

// UserEventKind enumerates account lifecycle changes.
type UserEventKind string

const (
	UserCreated  UserEventKind = "created"
	UserUpdated  UserEventKind = "updated"
	UserDeleted  UserEventKind = "deleted"
	UserBanned   UserEventKind = "banned"
	DeviceAdded  UserEventKind = "device_added"
	DeviceRevoke UserEventKind = "device_revoked"
)

// UserEvent is the record on user.events.
type UserEvent struct {
	V        int               `json:"v"`
	Kind     UserEventKind     `json:"kind"`
	UserID   int64             `json:"user_id"`
	DeviceID int64             `json:"device_id,omitempty"`
	Fields   map[string]string `json:"fields,omitempty"`
	At       time.Time         `json:"at"`
}

// SearchDoc is the record on search.index.
type SearchDoc struct {
	V         int       `json:"v"`
	Index     string    `json:"index"` // messages|users|chats
	DocID     string    `json:"doc_id"`
	Op        string    `json:"op"` // upsert|delete
	ChatID    int64     `json:"chat_id,omitempty"`
	Members   []int64   `json:"members,omitempty"` // ACL filter for message search
	Body      string    `json:"body,omitempty"`
	SenderID  int64     `json:"sender_id,omitempty"`
	Seq       int64     `json:"seq,omitempty"`
	CreatedAt time.Time `json:"created_at,omitempty"`
}

// DeadLetter wraps a record that could not be processed.
type DeadLetter struct {
	V           int             `json:"v"`
	SourceTopic string          `json:"source_topic"`
	Group       string          `json:"group"`
	Partition   int             `json:"partition"`
	Offset      int64           `json:"offset"`
	Key         string          `json:"key"`
	Payload     json.RawMessage `json:"payload"`
	Error       string          `json:"error"`
	Attempts    int             `json:"attempts"`
	FailedAt    time.Time       `json:"failed_at"`
}

// CurrentVersion is stamped on every event this build produces.
const CurrentVersion = 1

// Validate performs the cheap invariant checks a consumer can rely on.
func (m *MessageEvent) Validate() error {
	switch {
	case m.MessageID == "":
		return fmt.Errorf("events: message_id is empty")
	case m.ChatID == 0:
		return fmt.Errorf("events: chat_id is zero")
	case m.Seq <= 0:
		return fmt.Errorf("events: seq must be positive, got %d", m.Seq)
	case m.SenderID == 0:
		return fmt.Errorf("events: sender_id is zero")
	case m.Type == "":
		return fmt.Errorf("events: type is empty")
	case m.Type == MessageText && m.Body == "" && !m.Encrypted:
		return fmt.Errorf("events: text message has empty body")
	case m.Media == nil && (m.Type == MessagePhoto || m.Type == MessageVideo || m.Type == MessageFile || m.Type == MessageVoice):
		return fmt.Errorf("events: %s message has no media reference", m.Type)
	}
	return nil
}
