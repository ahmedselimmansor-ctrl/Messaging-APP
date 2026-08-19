package pgstore

import "time"

// ChatType enumerates conversation kinds.
type ChatType string

const (
	// ChatPrivate is a 1:1 conversation. Its membership is fixed at two and
	// it is deduplicated by a canonical member pair so two users can never
	// end up with two parallel private chats.
	ChatPrivate ChatType = "private"
	// ChatGroup is a many-to-many conversation with a bounded member count.
	ChatGroup ChatType = "group"
	// ChatChannel is broadcast: many readers, few writers.
	ChatChannel ChatType = "channel"
)

// MemberRole enumerates permissions inside a chat.
type MemberRole string

const (
	RoleOwner  MemberRole = "owner"
	RoleAdmin  MemberRole = "admin"
	RoleMember MemberRole = "member"
	// RoleRestricted can read but not post; used for channel subscribers and
	// for moderation.
	RoleRestricted MemberRole = "restricted"
)

// User is an account.
type User struct {
	ID          int64      `json:"id"`
	Phone       string     `json:"phone"` // E.164, unique
	Username    *string    `json:"username,omitempty"`
	DisplayName string     `json:"display_name"`
	AboutText   string     `json:"about,omitempty"`
	AvatarObj   *string    `json:"avatar_object,omitempty"` // GCS object path
	LangCode    string     `json:"lang_code"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	DeletedAt   *time.Time `json:"deleted_at,omitempty"`
	// Banned accounts keep their rows so their message history stays
	// attributable, but every authenticated path rejects them.
	Banned bool `json:"banned"`
}

// Device is one authenticated client session.
//
// A device row is created by the auth handshake and is what an MTProto
// auth_key maps to. Revoking a device invalidates its auth_key without
// touching the account.
type Device struct {
	ID     int64 `json:"id"`
	UserID int64 `json:"user_id"`
	// AuthKeyID is the 64-bit MTProto key identifier, hex-encoded. The key
	// material itself lives only in Redis and is never written to Postgres.
	AuthKeyID   string `json:"auth_key_id"`
	Platform    string `json:"platform"` // android|ios|web|desktop
	AppVersion  string `json:"app_version"`
	DeviceModel string `json:"device_model"`
	// PushToken is the FCM registration token. Null for web sessions that
	// have not granted notification permission.
	PushToken  *string    `json:"push_token,omitempty"`
	LastIP     string     `json:"last_ip"`
	CreatedAt  time.Time  `json:"created_at"`
	LastSeenAt time.Time  `json:"last_seen_at"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
}

// Chat is a conversation.
type Chat struct {
	ID          int64      `json:"id"`
	Type        ChatType   `json:"type"`
	Title       string     `json:"title,omitempty"`
	Username    *string    `json:"username,omitempty"` // public channels only
	PhotoObj    *string    `json:"photo_object,omitempty"`
	Description string     `json:"description,omitempty"`
	CreatedBy   int64      `json:"created_by"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	DeletedAt   *time.Time `json:"deleted_at,omitempty"`
	MemberCount int        `json:"member_count"`
	// HomeRegion is where this chat's sequence allocation and message
	// ordering happen. Fixed at creation and never changed: moving a chat
	// between regions would mean migrating its sequence counter atomically
	// across two Redis clusters, which is not a thing that can be done
	// safely while messages are in flight.
	HomeRegion string `json:"home_region,omitempty"`
	// PairKey deduplicates private chats: the canonical "min:max" of the two
	// member ids, unique-indexed. Null for groups and channels.
	PairKey *string `json:"-"`
}

// Member is a user's participation in a chat.
type Member struct {
	ChatID   int64      `json:"chat_id"`
	UserID   int64      `json:"user_id"`
	Role     MemberRole `json:"role"`
	JoinedAt time.Time  `json:"joined_at"`
	// LastReadSeq drives unread counts. It only ever moves forward.
	LastReadSeq int64 `json:"last_read_seq"`
	// MutedUntil suppresses push notifications without leaving the chat.
	MutedUntil *time.Time `json:"muted_until,omitempty"`
	// Pinned and Archived are per-user client-side organisation.
	Pinned   bool       `json:"pinned"`
	Archived bool       `json:"archived"`
	LeftAt   *time.Time `json:"left_at,omitempty"`
}

// Dialog is the joined view a client renders in its chat list.
type Dialog struct {
	Chat        Chat       `json:"chat"`
	Role        MemberRole `json:"role"`
	LastReadSeq int64      `json:"last_read_seq"`
	MaxSeq      int64      `json:"max_seq"`
	UnreadCount int64      `json:"unread_count"`
	MutedUntil  *time.Time `json:"muted_until,omitempty"`
	Pinned      bool       `json:"pinned"`
	Archived    bool       `json:"archived"`
	// Peer is filled for private chats so the client can show the other
	// party's name without a second round trip.
	Peer *User `json:"peer,omitempty"`
}

// OTPChallenge is a pending phone verification.
type OTPChallenge struct {
	ID         string     `json:"id"`
	Phone      string     `json:"phone"`
	CodeHash   string     `json:"-"` // bcrypt; the plaintext code is never stored
	Attempts   int        `json:"attempts"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  time.Time  `json:"expires_at"`
	ConsumedAt *time.Time `json:"-"`
}

// Contact is a saved address-book entry.
type Contact struct {
	OwnerID   int64     `json:"owner_id"`
	UserID    int64     `json:"user_id"`
	FirstName string    `json:"first_name"`
	LastName  string    `json:"last_name,omitempty"`
	AddedAt   time.Time `json:"added_at"`
}
