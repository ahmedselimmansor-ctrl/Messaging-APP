package pgstore

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Chats is the conversation repository.
type Chats struct{ db *DB }

// ChatsRepo returns the conversation repository.
func (d *DB) ChatsRepo() *Chats { return &Chats{db: d} }

const chatColumns = `id, chat_type, title, username, photo_object, description,
	created_by, created_at, updated_at, deleted_at, member_count, home_region`

func scanChat(row pgx.Row) (Chat, error) {
	var c Chat
	err := row.Scan(&c.ID, &c.Type, &c.Title, &c.Username, &c.PhotoObj, &c.Description,
		&c.CreatedBy, &c.CreatedAt, &c.UpdatedAt, &c.DeletedAt, &c.MemberCount, &c.HomeRegion)
	return c, mapError(err)
}

// PairKey builds the canonical dedupe key for a private chat.
func PairKey(a, b int64) string {
	if a > b {
		a, b = b, a
	}
	return fmt.Sprintf("%d:%d", a, b)
}

// Get loads a chat.
func (r *Chats) Get(ctx context.Context, chatID int64) (Chat, error) {
	return scanChat(r.db.pool.QueryRow(ctx,
		`SELECT `+chatColumns+` FROM chats WHERE id = $1 AND deleted_at IS NULL`, chatID))
}

// GetMany loads several chats at once.
func (r *Chats) GetMany(ctx context.Context, ids []int64) (map[int64]Chat, error) {
	out := make(map[int64]Chat, len(ids))
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := r.db.pool.Query(ctx,
		`SELECT `+chatColumns+` FROM chats WHERE id = ANY($1) AND deleted_at IS NULL`, ids)
	if err != nil {
		return nil, mapError(err)
	}
	defer rows.Close()
	for rows.Next() {
		c, err := scanChat(rows)
		if err != nil {
			return nil, err
		}
		out[c.ID] = c
	}
	return out, mapError(rows.Err())
}

// CreatePrivate returns the existing 1:1 chat between two users or creates it.
//
// The whole operation is one transaction with an ON CONFLICT on pair_key, so
// two devices of the same user tapping "message" simultaneously converge on a
// single chat instead of racing into two.
func (r *Chats) CreatePrivate(ctx context.Context, chatID, a, b int64, homeRegion string) (Chat, bool, error) {
	if a == b {
		return Chat{}, false, fmt.Errorf("pgstore: cannot create a private chat with oneself")
	}
	key := PairKey(a, b)

	var chat Chat
	created := false
	err := r.db.InTx(ctx, func(tx pgx.Tx) error {
		// Fast path: it already exists.
		err := tx.QueryRow(ctx,
			`SELECT `+chatColumns+` FROM chats WHERE pair_key = $1 AND deleted_at IS NULL`, key).
			Scan(&chat.ID, &chat.Type, &chat.Title, &chat.Username, &chat.PhotoObj,
				&chat.Description, &chat.CreatedBy, &chat.CreatedAt, &chat.UpdatedAt,
				&chat.DeletedAt, &chat.MemberCount, &chat.HomeRegion)
		if err == nil {
			return nil
		}
		if mapped := mapError(err); mapped != ErrNotFound {
			return mapped
		}

		err = tx.QueryRow(ctx, `
			INSERT INTO chats (id, chat_type, created_by, pair_key, member_count, home_region)
			VALUES ($1, 'private', $2, $3, 2, $4)
			ON CONFLICT (pair_key) DO UPDATE SET updated_at = now()
			RETURNING `+chatColumns,
			chatID, a, key, homeRegion).
			Scan(&chat.ID, &chat.Type, &chat.Title, &chat.Username, &chat.PhotoObj,
				&chat.Description, &chat.CreatedBy, &chat.CreatedAt, &chat.UpdatedAt,
				&chat.DeletedAt, &chat.MemberCount, &chat.HomeRegion)
		if err != nil {
			return mapError(err)
		}
		created = chat.ID == chatID

		for _, uid := range []int64{a, b} {
			if _, err := tx.Exec(ctx, `
				INSERT INTO chat_members (chat_id, user_id, role)
				VALUES ($1, $2, 'member')
				ON CONFLICT (chat_id, user_id) DO UPDATE SET left_at = NULL`,
				chat.ID, uid); err != nil {
				return mapError(err)
			}
		}
		return nil
	})
	return chat, created, err
}

// CreateGroup creates a group or channel with its initial roster.
func (r *Chats) CreateGroup(ctx context.Context, chatID int64, kind ChatType, title string, ownerID int64, members []int64, homeRegion string) (Chat, error) {
	if kind != ChatGroup && kind != ChatChannel {
		return Chat{}, fmt.Errorf("pgstore: CreateGroup called with type %q", kind)
	}

	// Deduplicate and guarantee the owner is present exactly once.
	seen := map[int64]bool{ownerID: true}
	roster := []int64{ownerID}
	for _, m := range members {
		if !seen[m] {
			seen[m] = true
			roster = append(roster, m)
		}
	}

	var chat Chat
	err := r.db.InTx(ctx, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `
			INSERT INTO chats (id, chat_type, title, created_by, member_count, home_region)
			VALUES ($1, $2, $3, $4, $5, $6)
			RETURNING `+chatColumns,
			chatID, kind, title, ownerID, len(roster), homeRegion).
			Scan(&chat.ID, &chat.Type, &chat.Title, &chat.Username, &chat.PhotoObj,
				&chat.Description, &chat.CreatedBy, &chat.CreatedAt, &chat.UpdatedAt,
				&chat.DeletedAt, &chat.MemberCount, &chat.HomeRegion)
		if err != nil {
			return mapError(err)
		}

		rows := make([][]any, 0, len(roster))
		for _, uid := range roster {
			role := RoleMember
			if uid == ownerID {
				role = RoleOwner
			}
			rows = append(rows, []any{chatID, uid, string(role)})
		}
		// CopyFrom beats N inserts once a group has more than a handful of
		// members, and group creation from an address book is routinely 50+.
		if _, err := tx.CopyFrom(ctx,
			pgx.Identifier{"chat_members"},
			[]string{"chat_id", "user_id", "role"},
			pgx.CopyFromRows(rows)); err != nil {
			return mapError(err)
		}
		return nil
	})
	return chat, err
}

// UpdateMeta changes title, description or photo.
func (r *Chats) UpdateMeta(ctx context.Context, chatID int64, title, description, photoObj *string) (Chat, error) {
	return scanChat(r.db.pool.QueryRow(ctx, `
		UPDATE chats SET
			title        = COALESCE($2, title),
			description  = COALESCE($3, description),
			photo_object = COALESCE($4, photo_object),
			updated_at   = now()
		WHERE id = $1 AND deleted_at IS NULL
		RETURNING `+chatColumns,
		chatID, title, description, photoObj))
}

// SoftDelete marks a chat deleted.
func (r *Chats) SoftDelete(ctx context.Context, chatID int64) error {
	tag, err := r.db.pool.Exec(ctx,
		`UPDATE chats SET deleted_at = now() WHERE id = $1 AND deleted_at IS NULL`, chatID)
	if err != nil {
		return mapError(err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ---------------------------------------------------------------------------
// Membership
// ---------------------------------------------------------------------------

// Members is the membership repository.
type Members struct{ db *DB }

// MembersRepo returns the membership repository.
func (d *DB) MembersRepo() *Members { return &Members{db: d} }

// IDs returns the active member ids of a chat.
//
// This is the authoritative answer behind the Redis membership cache, and the
// list that gets materialised onto every message event so downstream
// consumers never have to ask again.
func (r *Members) IDs(ctx context.Context, chatID int64) ([]int64, error) {
	rows, err := r.db.pool.Query(ctx,
		`SELECT user_id FROM chat_members WHERE chat_id = $1 AND left_at IS NULL ORDER BY user_id`,
		chatID)
	if err != nil {
		return nil, mapError(err)
	}
	defer rows.Close()

	out := make([]int64, 0, 32)
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, mapError(err)
		}
		out = append(out, id)
	}
	return out, mapError(rows.Err())
}

// Get loads one membership row.
func (r *Members) Get(ctx context.Context, chatID, userID int64) (Member, error) {
	var m Member
	err := r.db.pool.QueryRow(ctx, `
		SELECT chat_id, user_id, role, joined_at, last_read_seq, muted_until, pinned, archived, left_at
		FROM chat_members WHERE chat_id = $1 AND user_id = $2`, chatID, userID).
		Scan(&m.ChatID, &m.UserID, &m.Role, &m.JoinedAt, &m.LastReadSeq,
			&m.MutedUntil, &m.Pinned, &m.Archived, &m.LeftAt)
	return m, mapError(err)
}

// CanPost answers the send-path authorisation question in one query.
//
// It returns membership and posting rights together because the send path
// needs both and a second round trip per message would double the Postgres
// load of the busiest endpoint in the system.
func (r *Members) CanPost(ctx context.Context, chatID, userID int64) (isMember bool, canPost bool, err error) {
	var role MemberRole
	var chatType ChatType
	err = r.db.pool.QueryRow(ctx, `
		SELECT m.role, c.chat_type
		FROM chat_members m
		JOIN chats c ON c.id = m.chat_id AND c.deleted_at IS NULL
		WHERE m.chat_id = $1 AND m.user_id = $2 AND m.left_at IS NULL`,
		chatID, userID).Scan(&role, &chatType)
	if err != nil {
		if mapError(err) == ErrNotFound {
			return false, false, nil
		}
		return false, false, mapError(err)
	}

	switch {
	case role == RoleRestricted:
		canPost = false
	case chatType == ChatChannel:
		// In a channel only owners and admins broadcast.
		canPost = role == RoleOwner || role == RoleAdmin
	default:
		canPost = true
	}
	return true, canPost, nil
}

// Add inserts or reactivates a membership and keeps member_count correct.
func (r *Members) Add(ctx context.Context, chatID, userID int64, role MemberRole) error {
	return r.db.InTx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
			INSERT INTO chat_members (chat_id, user_id, role)
			VALUES ($1, $2, $3)
			ON CONFLICT (chat_id, user_id) DO UPDATE
			SET left_at = NULL, role = EXCLUDED.role
			WHERE chat_members.left_at IS NOT NULL`,
			chatID, userID, string(role))
		if err != nil {
			return mapError(err)
		}
		if tag.RowsAffected() == 0 {
			return nil // already an active member; count unchanged
		}
		_, err = tx.Exec(ctx,
			`UPDATE chats SET member_count = member_count + 1, updated_at = now() WHERE id = $1`,
			chatID)
		return mapError(err)
	})
}

// Remove marks a membership as left.
func (r *Members) Remove(ctx context.Context, chatID, userID int64) error {
	return r.db.InTx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			`UPDATE chat_members SET left_at = now()
			 WHERE chat_id = $1 AND user_id = $2 AND left_at IS NULL`, chatID, userID)
		if err != nil {
			return mapError(err)
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		_, err = tx.Exec(ctx,
			`UPDATE chats SET member_count = GREATEST(0, member_count - 1), updated_at = now()
			 WHERE id = $1`, chatID)
		return mapError(err)
	})
}

// SetRole changes a member's permissions.
func (r *Members) SetRole(ctx context.Context, chatID, userID int64, role MemberRole) error {
	tag, err := r.db.pool.Exec(ctx,
		`UPDATE chat_members SET role = $3 WHERE chat_id = $1 AND user_id = $2 AND left_at IS NULL`,
		chatID, userID, string(role))
	if err != nil {
		return mapError(err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// MarkRead advances the read pointer.
//
// GREATEST keeps the pointer monotonic: two devices reporting out of order
// must not move the unread count backwards.
func (r *Members) MarkRead(ctx context.Context, chatID, userID, seq int64) (int64, error) {
	var newSeq int64
	err := r.db.pool.QueryRow(ctx, `
		UPDATE chat_members SET last_read_seq = GREATEST(last_read_seq, $3)
		WHERE chat_id = $1 AND user_id = $2 AND left_at IS NULL
		RETURNING last_read_seq`, chatID, userID, seq).Scan(&newSeq)
	return newSeq, mapError(err)
}

// SetMuted mutes a chat for one member until the given time (nil unmutes).
func (r *Members) SetMuted(ctx context.Context, chatID, userID int64, until *time.Time) error {
	_, err := r.db.pool.Exec(ctx,
		`UPDATE chat_members SET muted_until = $3 WHERE chat_id = $1 AND user_id = $2`,
		chatID, userID, until)
	return mapError(err)
}

// MutedAmong returns which of the given users have this chat muted. The push
// consumer calls it to avoid waking a phone the user asked to stay quiet.
func (r *Members) MutedAmong(ctx context.Context, chatID int64, userIDs []int64) (map[int64]bool, error) {
	out := make(map[int64]bool, len(userIDs))
	if len(userIDs) == 0 {
		return out, nil
	}
	rows, err := r.db.pool.Query(ctx, `
		SELECT user_id FROM chat_members
		WHERE chat_id = $1 AND user_id = ANY($2)
		  AND muted_until IS NOT NULL AND muted_until > now()`, chatID, userIDs)
	if err != nil {
		return nil, mapError(err)
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, mapError(err)
		}
		out[id] = true
	}
	return out, mapError(rows.Err())
}

// SetFlags toggles the per-user pinned/archived flags.
func (r *Members) SetFlags(ctx context.Context, chatID, userID int64, pinned, archived *bool) error {
	_, err := r.db.pool.Exec(ctx, `
		UPDATE chat_members
		SET pinned = COALESCE($3, pinned), archived = COALESCE($4, archived)
		WHERE chat_id = $1 AND user_id = $2`, chatID, userID, pinned, archived)
	return mapError(err)
}

// Dialogs returns a user's chat list.
//
// max_seq comes from a per-chat counter table that the persister keeps
// current. Reading it here rather than asking Cassandra means the chat list —
// the first screen every client renders on launch — is a single Postgres
// query, not one Cassandra read per chat.
func (r *Members) Dialogs(ctx context.Context, userID int64, includeArchived bool, limit, offset int) ([]Dialog, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := r.db.pool.Query(ctx, `
		SELECT `+prefixed("c", chatColumns)+`,
		       m.role, m.last_read_seq, m.muted_until, m.pinned, m.archived,
		       COALESCE(s.max_seq, 0) AS max_seq
		FROM chat_members m
		JOIN chats c ON c.id = m.chat_id AND c.deleted_at IS NULL
		LEFT JOIN chat_sequences s ON s.chat_id = m.chat_id
		WHERE m.user_id = $1 AND m.left_at IS NULL
		  AND ($2 OR m.archived = false)
		ORDER BY m.pinned DESC, COALESCE(s.updated_at, c.created_at) DESC
		LIMIT $3 OFFSET $4`, userID, includeArchived, limit, offset)
	if err != nil {
		return nil, mapError(err)
	}
	defer rows.Close()

	out := make([]Dialog, 0, limit)
	for rows.Next() {
		var d Dialog
		if err := rows.Scan(
			&d.Chat.ID, &d.Chat.Type, &d.Chat.Title, &d.Chat.Username, &d.Chat.PhotoObj,
			&d.Chat.Description, &d.Chat.CreatedBy, &d.Chat.CreatedAt, &d.Chat.UpdatedAt,
			&d.Chat.DeletedAt, &d.Chat.MemberCount, &d.Chat.HomeRegion,
			&d.Role, &d.LastReadSeq, &d.MutedUntil, &d.Pinned, &d.Archived, &d.MaxSeq,
		); err != nil {
			return nil, mapError(err)
		}
		if d.MaxSeq > d.LastReadSeq {
			d.UnreadCount = d.MaxSeq - d.LastReadSeq
		}
		out = append(out, d)
	}
	return out, mapError(rows.Err())
}

// prefixed qualifies a column list with a table alias.
func prefixed(alias, cols string) string {
	out := ""
	start := 0
	for i := 0; i <= len(cols); i++ {
		if i == len(cols) || cols[i] == ',' {
			field := trimSpace(cols[start:i])
			if out != "" {
				out += ", "
			}
			out += alias + "." + field
			start = i + 1
		}
	}
	return out
}

func trimSpace(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\n' || s[0] == '\t') {
		s = s[1:]
	}
	for len(s) > 0 {
		c := s[len(s)-1]
		if c != ' ' && c != '\n' && c != '\t' {
			break
		}
		s = s[:len(s)-1]
	}
	return s
}

// ---------------------------------------------------------------------------
// Chat sequence mirror
// ---------------------------------------------------------------------------

// Sequences mirrors each chat's highest persisted sequence into Postgres.
type Sequences struct{ db *DB }

// SequencesRepo returns the sequence mirror repository.
func (d *DB) SequencesRepo() *Sequences { return &Sequences{db: d} }

// Advance raises the stored maximum for a chat. It is monotonic, so
// out-of-order consumer retries cannot move it backwards.
func (r *Sequences) Advance(ctx context.Context, chatID, seq int64) error {
	_, err := r.db.pool.Exec(ctx, `
		INSERT INTO chat_sequences (chat_id, max_seq, updated_at)
		VALUES ($1, $2, now())
		ON CONFLICT (chat_id) DO UPDATE
		SET max_seq = GREATEST(chat_sequences.max_seq, EXCLUDED.max_seq),
		    updated_at = now()`, chatID, seq)
	return mapError(err)
}

// Max reads the mirrored maximum.
func (r *Sequences) Max(ctx context.Context, chatID int64) (int64, error) {
	var seq int64
	err := r.db.pool.QueryRow(ctx, `SELECT max_seq FROM chat_sequences WHERE chat_id = $1`, chatID).
		Scan(&seq)
	if mapped := mapError(err); mapped == ErrNotFound {
		return 0, nil
	} else if mapped != nil {
		return 0, mapped
	}
	return seq, nil
}
