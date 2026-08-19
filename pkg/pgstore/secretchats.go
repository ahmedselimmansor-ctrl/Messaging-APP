package pgstore

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// SecretChat is the server's view of an end-to-end encrypted conversation.
//
// Note what is absent: there is no key column, and there never will be. The
// server stores the public Diffie-Hellman values it relayed and a fingerprint
// it can compare but not invert. Everything needed to read the messages lives
// only on the two devices.
type SecretChat struct {
	ID int64 `json:"id"`
	// AdminID is the user who initiated. The asymmetry matters for one thing
	// only: on a rekey, the admin is the side that proposes.
	AdminID       int64 `json:"admin_id"`
	AdminDeviceID int64 `json:"admin_device_id"`

	ParticipantID       int64 `json:"participant_id"`
	ParticipantDeviceID int64 `json:"participant_device_id,omitempty"`

	State string `json:"state"`

	// GA and GB are the public values, base64-encoded. A passive observer of
	// any Diffie-Hellman exchange sees these; they do not yield the key.
	GA string `json:"g_a,omitempty"`
	GB string `json:"g_b,omitempty"`

	// KeyFingerprint lets each side confirm the other derived the same key.
	// It is a hash of the key, not the key.
	KeyFingerprint int64 `json:"key_fingerprint,omitempty"`

	// TTLSeconds is the self-destruct timer both clients enforce. The server
	// stores it so a new device of the same user learns the setting, and does
	// not enforce it — it cannot read the messages to delete them, and a
	// client that ignores the timer is a client the user chose to trust.
	TTLSeconds int `json:"ttl_seconds"`

	CreatedAt   time.Time  `json:"created_at"`
	ReadyAt     *time.Time `json:"ready_at,omitempty"`
	DiscardedAt *time.Time `json:"discarded_at,omitempty"`
}

// SecretChats is the secret-chat repository.
type SecretChats struct{ db *DB }

// SecretChatsRepo returns the secret-chat repository.
func (d *DB) SecretChatsRepo() *SecretChats { return &SecretChats{db: d} }

const secretChatColumns = `id, admin_id, admin_device_id, participant_id, participant_device_id,
	state, g_a, g_b, key_fingerprint, ttl_seconds, created_at, ready_at, discarded_at`

func scanSecretChat(row pgx.Row) (SecretChat, error) {
	var c SecretChat
	err := row.Scan(&c.ID, &c.AdminID, &c.AdminDeviceID, &c.ParticipantID, &c.ParticipantDeviceID,
		&c.State, &c.GA, &c.GB, &c.KeyFingerprint, &c.TTLSeconds,
		&c.CreatedAt, &c.ReadyAt, &c.DiscardedAt)
	return c, mapError(err)
}

// Request creates a chat in the requested state, carrying the initiator's
// public value.
func (r *SecretChats) Request(ctx context.Context, id, adminID, adminDeviceID, participantID int64, gA string) (SecretChat, error) {
	return scanSecretChat(r.db.pool.QueryRow(ctx, `
		INSERT INTO secret_chats (id, admin_id, admin_device_id, participant_id, state, g_a)
		VALUES ($1, $2, $3, $4, 'requested', $5)
		RETURNING `+secretChatColumns,
		id, adminID, adminDeviceID, participantID, gA))
}

// Accept records the participant's public value and the agreed fingerprint.
//
// Conditional on the chat still being in the requested state, so two devices
// of the same participant accepting concurrently cannot both win and leave the
// admin unsure which key is live.
func (r *SecretChats) Accept(ctx context.Context, id, participantDeviceID int64, gB string, fingerprint int64) (SecretChat, error) {
	return scanSecretChat(r.db.pool.QueryRow(ctx, `
		UPDATE secret_chats
		SET participant_device_id = $2, g_b = $3, key_fingerprint = $4,
		    state = 'ready', ready_at = now()
		WHERE id = $1 AND state = 'requested'
		RETURNING `+secretChatColumns,
		id, participantDeviceID, gB, fingerprint))
}

// Discard ends a chat. Terminal.
func (r *SecretChats) Discard(ctx context.Context, id, byUserID int64) error {
	tag, err := r.db.pool.Exec(ctx, `
		UPDATE secret_chats
		SET state = 'discarded', discarded_at = now(),
		    -- Drop the public values as well. They are not secret, but there
		    -- is no reason to retain anything about a conversation both sides
		    -- have ended.
		    g_a = '', g_b = ''
		WHERE id = $1 AND (admin_id = $2 OR participant_id = $2) AND state <> 'discarded'`,
		id, byUserID)
	if err != nil {
		return mapError(err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// Get loads a chat, checking the caller is a participant.
func (r *SecretChats) Get(ctx context.Context, id, callerID int64) (SecretChat, error) {
	return scanSecretChat(r.db.pool.QueryRow(ctx,
		`SELECT `+secretChatColumns+` FROM secret_chats
		 WHERE id = $1 AND (admin_id = $2 OR participant_id = $2)`, id, callerID))
}

// ListFor returns a user's live secret chats.
func (r *SecretChats) ListFor(ctx context.Context, userID int64) ([]SecretChat, error) {
	rows, err := r.db.pool.Query(ctx,
		`SELECT `+secretChatColumns+` FROM secret_chats
		 WHERE (admin_id = $1 OR participant_id = $1) AND state <> 'discarded'
		 ORDER BY created_at DESC LIMIT 200`, userID)
	if err != nil {
		return nil, mapError(err)
	}
	defer rows.Close()

	out := make([]SecretChat, 0, 16)
	for rows.Next() {
		c, err := scanSecretChat(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, mapError(rows.Err())
}

// SetTTL updates the self-destruct timer.
func (r *SecretChats) SetTTL(ctx context.Context, id, callerID int64, seconds int) error {
	tag, err := r.db.pool.Exec(ctx, `
		UPDATE secret_chats SET ttl_seconds = $3
		WHERE id = $1 AND (admin_id = $2 OR participant_id = $2) AND state = 'ready'`,
		id, callerID, seconds)
	if err != nil {
		return mapError(err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
