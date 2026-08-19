// Package cassandrax owns the Cassandra session and the message repository.
//
// Cassandra holds the message history: it is the only store in the platform
// that must absorb the full write rate of every chat in the system, and it is
// the reason the data model below is shaped around the query, not the entity.
package cassandrax

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/gocql/gocql"
	"github.com/pervagans/messaging-app/pkg/events"
	"github.com/pervagans/messaging-app/pkg/gcsx"
)

// Config describes how to reach the ring.
type Config struct {
	// Hosts are the contact points. In GKE this is the headless Service of
	// the Cassandra StatefulSet: cassandra-0.cassandra.data.svc.cluster.local
	// and friends, or simply "cassandra.data.svc.cluster.local" which resolves
	// to every ready pod.
	Hosts []string
	// Keyspace is created by db/cassandra/schema.cql.
	Keyspace string
	Username string
	Password string
	// LocalDC must match the GKE region so the token-aware policy prefers
	// replicas in the same region and we stop paying cross-region egress on
	// every read.
	LocalDC string
	// Consistency for reads and writes. LOCAL_QUORUM is the only sane choice
	// for a multi-zone ring: it survives one zone loss and still gives
	// read-your-writes within the region.
	Consistency gocql.Consistency
	// NumConns per host. Cassandra multiplexes requests on a connection, so
	// 2-4 is plenty; more just wastes file descriptors on both sides.
	NumConns    int
	Timeout     time.Duration
	ConnTimeout time.Duration
	// PageSize bounds how much of a partition comes back per round trip.
	PageSize int
}

// DefaultConfig returns production-shaped defaults.
func DefaultConfig() Config {
	return Config{
		Keyspace:    "messaging",
		Consistency: gocql.LocalQuorum,
		NumConns:    3,
		Timeout:     3 * time.Second,
		ConnTimeout: 5 * time.Second,
		PageSize:    100,
	}
}

// Session wraps a gocql session.
type Session struct {
	s   *gocql.Session
	cfg Config
}

// Connect opens the session and verifies the keyspace exists.
func Connect(ctx context.Context, cfg Config) (*Session, error) {
	if len(cfg.Hosts) == 0 {
		return nil, errors.New("cassandrax: no hosts configured")
	}

	c := gocql.NewCluster(cfg.Hosts...)
	c.Keyspace = cfg.Keyspace
	c.Consistency = cfg.Consistency
	c.NumConns = cfg.NumConns
	c.Timeout = cfg.Timeout
	c.ConnectTimeout = cfg.ConnTimeout
	c.PageSize = cfg.PageSize
	c.ProtoVersion = 4
	c.CQLVersion = "3.4.5"

	// Token-aware routing sends each query straight to a replica, removing
	// the coordinator hop that otherwise doubles latency and load.
	fallback := gocql.RoundRobinHostPolicy()
	if cfg.LocalDC != "" {
		fallback = gocql.DCAwareRoundRobinPolicy(cfg.LocalDC)
	}
	c.PoolConfig.HostSelectionPolicy = gocql.TokenAwareHostPolicy(fallback)

	// Retry idempotent queries on a different host. Every statement this
	// package issues is an idempotent insert or a plain select, so this is
	// safe; it would not be for counter updates or lightweight transactions.
	c.RetryPolicy = &gocql.ExponentialBackoffRetryPolicy{
		NumRetries: 3,
		Min:        50 * time.Millisecond,
		Max:        500 * time.Millisecond,
	}
	if cfg.Username != "" {
		c.Authenticator = gocql.PasswordAuthenticator{
			Username: cfg.Username,
			Password: cfg.Password,
		}
	}

	s, err := c.CreateSession()
	if err != nil {
		return nil, fmt.Errorf("cassandrax: create session: %w", err)
	}

	sess := &Session{s: s, cfg: cfg}
	if err := sess.Ping(ctx); err != nil {
		s.Close()
		return nil, err
	}
	return sess, nil
}

// speculative races a second replica when the first is slow to answer.
//
// gocql applies this per query rather than per cluster, and it is only safe
// for idempotent statements, so it is attached to reads only. A single node
// in compaction or a GC pause stops being visible to users.
var speculative = &gocql.SimpleSpeculativeExecution{
	NumAttempts:  1,
	TimeoutDelay: 40 * time.Millisecond,
}

// Ping runs a trivial query; used as a readiness check.
func (s *Session) Ping(ctx context.Context) error {
	var now time.Time
	if err := s.s.Query(`SELECT now() FROM system.local`).
		WithContext(ctx).Consistency(gocql.One).Scan(&now); err != nil {
		return fmt.Errorf("cassandrax: ping: %w", err)
	}
	return nil
}

// Raw exposes the underlying session for queries this package does not wrap.
func (s *Session) Raw() *gocql.Session { return s.s }

// Close shuts the session down.
func (s *Session) Close(context.Context) error {
	s.s.Close()
	return nil
}

// ---------------------------------------------------------------------------
// Message repository
// ---------------------------------------------------------------------------

// BucketSize is how many messages share one Cassandra partition.
//
// A chat's history is unbounded, and an unbounded partition is the classic
// way to kill a Cassandra cluster: compaction, repair and reads all degrade
// once a partition passes a few hundred megabytes. Bucketing by sequence
// range keeps every partition bounded and predictable — 10k messages at ~1KB
// each is a ~10MB partition, comfortably inside the healthy range.
const BucketSize int64 = 10_000

// BucketOf returns the partition bucket for a sequence number.
func BucketOf(seq int64) int64 { return seq / BucketSize }

// StoredMessage is a row of messages_by_chat.
type StoredMessage struct {
	ChatID     int64
	Bucket     int64
	Seq        int64
	MessageID  string
	SenderID   int64
	Type       string
	Body       string
	Encrypted  bool
	MediaJSON  string
	ReplyToSeq int64
	CreatedAt  time.Time
	EditedAt   *time.Time
	Deleted    bool
}

// MessageRepo reads and writes chat history.
type MessageRepo struct{ s *Session }

// Messages returns the repository bound to this session.
func (s *Session) Messages() *MessageRepo { return &MessageRepo{s: s} }

// Insert persists one message.
//
// The write touches three tables and they are deliberately not in a batch:
// a multi-partition BATCH in Cassandra is not a transaction, it just moves
// the fan-out to the coordinator and creates a batchlog write plus a hot
// coordinator. Issuing three independent idempotent inserts is faster and the
// consumer's at-least-once retry covers a partial failure.
func (r *MessageRepo) Insert(ctx context.Context, e *events.MessageEvent, mediaJSON string) error {
	bucket := BucketOf(e.Seq)

	if err := r.s.s.Query(`
		INSERT INTO messages_by_chat (
			chat_id, bucket, seq, message_id, sender_id, msg_type,
			body, encrypted, media, reply_to_seq, created_at, deleted
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, false)`,
		e.ChatID, bucket, e.Seq, e.MessageID, e.SenderID, string(e.Type),
		e.Body, e.Encrypted, mediaJSON, e.ReplyToSeq, e.CreatedAt,
	).WithContext(ctx).Idempotent(true).Exec(); err != nil {
		return fmt.Errorf("cassandrax: insert messages_by_chat: %w", err)
	}

	// Lookup by the opaque client-facing id, e.g. for "jump to message".
	if err := r.s.s.Query(`
		INSERT INTO message_by_id (message_id, chat_id, bucket, seq)
		VALUES (?, ?, ?, ?)`,
		e.MessageID, e.ChatID, bucket, e.Seq,
	).WithContext(ctx).Idempotent(true).Exec(); err != nil {
		return fmt.Errorf("cassandrax: insert message_by_id: %w", err)
	}

	// Dedupe index: a client retrying a send with the same random id must get
	// the original message back rather than posting twice. TTL'd because the
	// window a client can retry in is minutes, not forever.
	if e.ClientRandomID != 0 {
		if err := r.s.s.Query(`
			INSERT INTO message_dedupe (chat_id, sender_id, client_random_id, seq, message_id)
			VALUES (?, ?, ?, ?, ?) USING TTL 86400`,
			e.ChatID, e.SenderID, e.ClientRandomID, e.Seq, e.MessageID,
		).WithContext(ctx).Idempotent(true).Exec(); err != nil {
			return fmt.Errorf("cassandrax: insert message_dedupe: %w", err)
		}
	}
	return nil
}

// ErrNotFound is returned when a lookup misses.
var ErrNotFound = errors.New("cassandrax: not found")

// FindByClientRandomID resolves a retry to its original message.
func (r *MessageRepo) FindByClientRandomID(ctx context.Context, chatID, senderID, randomID int64) (seq int64, messageID string, err error) {
	err = r.s.s.Query(`
		SELECT seq, message_id FROM message_dedupe
		WHERE chat_id = ? AND sender_id = ? AND client_random_id = ?`,
		chatID, senderID, randomID,
	).WithContext(ctx).Scan(&seq, &messageID)
	if errors.Is(err, gocql.ErrNotFound) {
		return 0, "", ErrNotFound
	}
	if err != nil {
		return 0, "", fmt.Errorf("cassandrax: dedupe lookup: %w", err)
	}
	return seq, messageID, nil
}

// History returns up to limit messages of a chat with seq strictly below
// beforeSeq, newest first. Passing beforeSeq <= 0 starts from the newest.
//
// Because the clustering order is (seq DESC), a page is a contiguous slice
// of one partition — no filtering, no ALLOW FILTERING, no tombstone scans.
// Pages that straddle a bucket boundary walk backwards into the previous
// bucket, which is why this loops instead of issuing one query.
func (r *MessageRepo) History(ctx context.Context, chatID, beforeSeq int64, limit int) ([]StoredMessage, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	if beforeSeq <= 0 {
		beforeSeq = int64(1) << 62
	}

	out := make([]StoredMessage, 0, limit)
	bucket := BucketOf(beforeSeq)

	// Stop after walking a bounded number of empty buckets so a request
	// against a sparse or deleted chat cannot turn into a full history scan.
	const maxBucketWalk = 8

	for walked := 0; len(out) < limit && bucket >= 0 && walked < maxBucketWalk; walked++ {
		iter := r.s.s.Query(`
			SELECT chat_id, bucket, seq, message_id, sender_id, msg_type,
			       body, encrypted, media, reply_to_seq, created_at, edited_at, deleted
			FROM messages_by_chat
			WHERE chat_id = ? AND bucket = ? AND seq < ?
			ORDER BY seq DESC
			LIMIT ?`,
			chatID, bucket, beforeSeq, limit-len(out),
		).WithContext(ctx).Idempotent(true).SetSpeculativeExecutionPolicy(speculative).Iter()

		var m StoredMessage
		var editedAt time.Time
		for iter.Scan(&m.ChatID, &m.Bucket, &m.Seq, &m.MessageID, &m.SenderID,
			&m.Type, &m.Body, &m.Encrypted, &m.MediaJSON, &m.ReplyToSeq,
			&m.CreatedAt, &editedAt, &m.Deleted) {
			cp := m
			if !editedAt.IsZero() {
				t := editedAt
				cp.EditedAt = &t
			}
			out = append(out, cp)
		}
		if err := iter.Close(); err != nil {
			return nil, fmt.Errorf("cassandrax: history bucket %d: %w", bucket, err)
		}

		bucket--
		// Next bucket starts just past its top sequence.
		beforeSeq = (bucket + 1) * BucketSize
	}
	return out, nil
}

// Range returns messages with fromSeq <= seq <= toSeq in ascending order.
// Used by clients catching up after a reconnect.
func (r *MessageRepo) Range(ctx context.Context, chatID, fromSeq, toSeq int64, limit int) ([]StoredMessage, error) {
	if fromSeq < 1 {
		fromSeq = 1
	}
	if toSeq < fromSeq {
		return nil, nil
	}
	if limit <= 0 || limit > 500 {
		limit = 200
	}

	out := make([]StoredMessage, 0, limit)
	for bucket := BucketOf(fromSeq); bucket <= BucketOf(toSeq) && len(out) < limit; bucket++ {
		iter := r.s.s.Query(`
			SELECT chat_id, bucket, seq, message_id, sender_id, msg_type,
			       body, encrypted, media, reply_to_seq, created_at, edited_at, deleted
			FROM messages_by_chat
			WHERE chat_id = ? AND bucket = ? AND seq >= ? AND seq <= ?
			ORDER BY seq ASC
			LIMIT ?`,
			chatID, bucket, fromSeq, toSeq, limit-len(out),
		).WithContext(ctx).Idempotent(true).SetSpeculativeExecutionPolicy(speculative).Iter()

		var m StoredMessage
		var editedAt time.Time
		for iter.Scan(&m.ChatID, &m.Bucket, &m.Seq, &m.MessageID, &m.SenderID,
			&m.Type, &m.Body, &m.Encrypted, &m.MediaJSON, &m.ReplyToSeq,
			&m.CreatedAt, &editedAt, &m.Deleted) {
			cp := m
			if !editedAt.IsZero() {
				t := editedAt
				cp.EditedAt = &t
			}
			out = append(out, cp)
		}
		if err := iter.Close(); err != nil {
			return nil, fmt.Errorf("cassandrax: range bucket %d: %w", bucket, err)
		}
	}
	return out, nil
}

// GetByID resolves a message by its public UUID.
func (r *MessageRepo) GetByID(ctx context.Context, messageID string) (StoredMessage, error) {
	var chatID, bucket, seq int64
	err := r.s.s.Query(`SELECT chat_id, bucket, seq FROM message_by_id WHERE message_id = ?`, messageID).
		WithContext(ctx).Scan(&chatID, &bucket, &seq)
	if errors.Is(err, gocql.ErrNotFound) {
		return StoredMessage{}, ErrNotFound
	}
	if err != nil {
		return StoredMessage{}, fmt.Errorf("cassandrax: message_by_id: %w", err)
	}

	var m StoredMessage
	var editedAt time.Time
	err = r.s.s.Query(`
		SELECT chat_id, bucket, seq, message_id, sender_id, msg_type,
		       body, encrypted, media, reply_to_seq, created_at, edited_at, deleted
		FROM messages_by_chat WHERE chat_id = ? AND bucket = ? AND seq = ?`,
		chatID, bucket, seq,
	).WithContext(ctx).Scan(&m.ChatID, &m.Bucket, &m.Seq, &m.MessageID, &m.SenderID,
		&m.Type, &m.Body, &m.Encrypted, &m.MediaJSON, &m.ReplyToSeq,
		&m.CreatedAt, &editedAt, &m.Deleted)
	if errors.Is(err, gocql.ErrNotFound) {
		return StoredMessage{}, ErrNotFound
	}
	if err != nil {
		return StoredMessage{}, fmt.Errorf("cassandrax: messages_by_chat: %w", err)
	}
	if !editedAt.IsZero() {
		m.EditedAt = &editedAt
	}
	return m, nil
}

// SoftDelete marks a message deleted and blanks its content.
//
// A real DELETE would create a tombstone that every subsequent read of the
// partition has to skip, and 10k tombstones in a partition is a query that
// times out. Overwriting in place keeps reads cheap; the row is reclaimed by
// the table's TTL policy, not by a tombstone.
func (r *MessageRepo) SoftDelete(ctx context.Context, chatID, seq int64) error {
	if err := r.s.s.Query(`
		UPDATE messages_by_chat SET deleted = true, body = '', media = ''
		WHERE chat_id = ? AND bucket = ? AND seq = ?`,
		chatID, BucketOf(seq), seq,
	).WithContext(ctx).Idempotent(true).Exec(); err != nil {
		return fmt.Errorf("cassandrax: soft delete: %w", err)
	}
	return nil
}

// Edit replaces a message body.
func (r *MessageRepo) Edit(ctx context.Context, chatID, seq int64, body string, at time.Time) error {
	if err := r.s.s.Query(`
		UPDATE messages_by_chat SET body = ?, edited_at = ?
		WHERE chat_id = ? AND bucket = ? AND seq = ?`,
		body, at, chatID, BucketOf(seq), seq,
	).WithContext(ctx).Idempotent(true).Exec(); err != nil {
		return fmt.Errorf("cassandrax: edit: %w", err)
	}
	return nil
}

// MaxSeq returns the highest sequence stored for a chat.
//
// This is the authority used to rebuild the Redis sequence allocator after a
// cache loss; it is a single-partition read of the newest bucket, so it stays
// cheap even for a chat with millions of messages.
func (r *MessageRepo) MaxSeq(ctx context.Context, chatID int64) (int64, error) {
	var maxBucket int64
	err := r.s.s.Query(`
		SELECT bucket FROM messages_by_chat_buckets WHERE chat_id = ? ORDER BY bucket DESC LIMIT 1`,
		chatID).WithContext(ctx).Scan(&maxBucket)
	if errors.Is(err, gocql.ErrNotFound) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("cassandrax: max bucket: %w", err)
	}

	var seq int64
	err = r.s.s.Query(`
		SELECT seq FROM messages_by_chat WHERE chat_id = ? AND bucket = ? ORDER BY seq DESC LIMIT 1`,
		chatID, maxBucket).WithContext(ctx).Scan(&seq)
	if errors.Is(err, gocql.ErrNotFound) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("cassandrax: max seq: %w", err)
	}
	return seq, nil
}

// TouchBucket records that a bucket exists for a chat, so MaxSeq can find the
// newest partition without scanning.
func (r *MessageRepo) TouchBucket(ctx context.Context, chatID, seq int64) error {
	if err := r.s.s.Query(`
		INSERT INTO messages_by_chat_buckets (chat_id, bucket) VALUES (?, ?)`,
		chatID, BucketOf(seq),
	).WithContext(ctx).Idempotent(true).Exec(); err != nil {
		return fmt.Errorf("cassandrax: touch bucket: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Media access control
// ---------------------------------------------------------------------------

// MediaACL records which chat an uploaded object belongs to.
//
// This closes what was a capability-based hole: possession of an object path
// used to be sufficient to fetch it. Paths contain a UUID and are only learned
// from a message the caller can already read, so they are unguessable — but a
// forwarded path granted access to anyone, forever.
//
// Recording the binding at send time and checking membership at download time
// makes the object's access follow the chat's, which is what a user assumes
// is already true.
type MediaACL struct{ s *Session }

// Media returns the media ACL repository.
func (s *Session) Media() *MediaACL { return &MediaACL{s: s} }

// Bind records that an object was shared into a chat.
//
// Called by the persister rather than the chat service: the binding must not
// exist before the message is durable, or an abandoned send would leave an
// object permanently readable by a chat that never received it.
//
// The key is gcsx.ACLKey(object), so every derivative the media processor
// later produces resolves to this same row without needing one of its own.
func (r *MediaACL) Bind(ctx context.Context, object string, chatID int64, messageID string, uploaderID int64) error {
	if object == "" {
		return nil
	}
	if err := r.s.s.Query(`
		INSERT INTO media_acl (acl_key, chat_id, message_id, uploader_id, bound_at)
		VALUES (?, ?, ?, ?, ?)`,
		gcsx.ACLKey(object), chatID, messageID, uploaderID, time.Now().UTC(),
	).WithContext(ctx).Idempotent(true).Exec(); err != nil {
		return fmt.Errorf("cassandrax: bind media acl: %w", err)
	}
	return nil
}

// ChatFor returns the chat an object was shared into.
//
// It accepts an original or any of its derivatives: both map onto the same
// ACL key, so a thumbnail inherits its original's permissions.
//
// ErrNotFound means the object was never attached to a message — an upload
// that was abandoned, or a path someone guessed.
func (r *MediaACL) ChatFor(ctx context.Context, object string) (chatID int64, uploaderID int64, err error) {
	err = r.s.s.Query(
		`SELECT chat_id, uploader_id FROM media_acl WHERE acl_key = ?`, gcsx.ACLKey(object),
	).WithContext(ctx).Idempotent(true).SetSpeculativeExecutionPolicy(speculative).
		Scan(&chatID, &uploaderID)

	if errors.Is(err, gocql.ErrNotFound) {
		return 0, 0, ErrNotFound
	}
	if err != nil {
		return 0, 0, fmt.Errorf("cassandrax: media acl lookup: %w", err)
	}
	return chatID, uploaderID, nil
}

// Unbind removes a binding when a message is deleted, so the object stops
// being readable at the same moment the message does.
func (r *MediaACL) Unbind(ctx context.Context, object string) error {
	if err := r.s.s.Query(`DELETE FROM media_acl WHERE acl_key = ?`, gcsx.ACLKey(object)).
		WithContext(ctx).Idempotent(true).Exec(); err != nil {
		return fmt.Errorf("cassandrax: unbind media acl: %w", err)
	}
	return nil
}
