package pgstore

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"

	"github.com/jackc/pgx/v5"
)

// Contacts is the address-book repository.
type Contacts struct{ db *DB }

// ContactsRepo returns the address-book repository.
func (d *DB) ContactsRepo() *Contacts { return &Contacts{db: d} }

// PhoneHash is how a client discovers which of its address-book entries are
// already users, without either side handing over a plaintext directory.
//
// The client sends HMAC-SHA256(pepper, E.164) rather than the number itself.
// This is not privacy theatre but it is not strong either, and it is worth
// being precise about what it does and does not buy:
//
//   - It does buy: our request logs, and anything that sees the request body,
//     never contain a plaintext address book.
//   - It does not buy: protection against us. We hold the pepper and every
//     user's number, so we could reverse any hash we receive.
//   - It does not buy: protection against a brute-force by someone who steals
//     the pepper. The phone number space is small enough to enumerate.
//
// Making it genuinely private needs a private set intersection protocol, which
// is a substantial piece of work and is noted in docs/SECURITY.md.
func PhoneHash(pepper []byte, e164 string) string {
	mac := hmac.New(sha256.New, pepper)
	mac.Write([]byte(e164))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// Add saves or updates a contact.
func (r *Contacts) Add(ctx context.Context, ownerID, userID int64, firstName, lastName string) error {
	if ownerID == userID {
		return ErrConflict
	}
	_, err := r.db.pool.Exec(ctx, `
		INSERT INTO contacts (owner_id, user_id, first_name, last_name)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (owner_id, user_id) DO UPDATE
		SET first_name = EXCLUDED.first_name, last_name = EXCLUDED.last_name`,
		ownerID, userID, firstName, lastName)
	return mapError(err)
}

// ImportEntry is one address-book row a client offers.
type ImportEntry struct {
	PhoneHash string `json:"phone_hash"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name,omitempty"`
}

// Import matches hashed phone numbers against registered users.
//
// One query for the whole address book rather than one per entry: a phone
// holds hundreds of contacts, and an N+1 here would be the slowest endpoint in
// the platform by an order of magnitude.
func (r *Contacts) Import(ctx context.Context, ownerID int64, pepper []byte, entries []ImportEntry) ([]User, error) {
	if len(entries) == 0 {
		return nil, nil
	}

	byHash := make(map[string]ImportEntry, len(entries))
	hashes := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.PhoneHash == "" {
			continue
		}
		if _, dup := byHash[e.PhoneHash]; dup {
			continue
		}
		byHash[e.PhoneHash] = e
		hashes = append(hashes, e.PhoneHash)
	}
	if len(hashes) == 0 {
		return nil, nil
	}

	// The hash is computed in SQL from the stored plaintext number, so there
	// is no denormalised hash column to keep in step with a pepper rotation:
	// rotating the pepper simply changes what clients send and what this
	// computes, with no migration.
	rows, err := r.db.pool.Query(ctx, `
		SELECT `+userColumns+`,
		       translate(encode(hmac(phone, $1, 'sha256'), 'base64'), '+/=', '-_') AS phone_hash
		FROM users
		WHERE deleted_at IS NULL
		  AND banned = false
		  AND translate(encode(hmac(phone, $1, 'sha256'), 'base64'), '+/=', '-_') = ANY($2)`,
		pepper, hashes)
	if err != nil {
		return nil, mapError(err)
	}
	defer rows.Close()

	matched := make([]User, 0, 8)
	toInsert := make([][]any, 0, 8)

	for rows.Next() {
		var u User
		var hash string
		if err := rows.Scan(&u.ID, &u.Phone, &u.Username, &u.DisplayName, &u.AboutText,
			&u.AvatarObj, &u.LangCode, &u.CreatedAt, &u.UpdatedAt, &u.DeletedAt, &u.Banned,
			&hash); err != nil {
			return nil, mapError(err)
		}
		if u.ID == ownerID {
			continue // a user's own number is in their own address book
		}

		entry := byHash[hash]
		matched = append(matched, u)
		toInsert = append(toInsert, []any{ownerID, u.ID, entry.FirstName, entry.LastName})
	}
	if err := rows.Err(); err != nil {
		return nil, mapError(err)
	}

	if len(toInsert) > 0 {
		if err := r.db.InTx(ctx, func(tx pgx.Tx) error {
			for _, row := range toInsert {
				if _, err := tx.Exec(ctx, `
					INSERT INTO contacts (owner_id, user_id, first_name, last_name)
					VALUES ($1, $2, $3, $4)
					ON CONFLICT (owner_id, user_id) DO UPDATE
					SET first_name = EXCLUDED.first_name, last_name = EXCLUDED.last_name`,
					row...); err != nil {
					return mapError(err)
				}
			}
			return nil
		}); err != nil {
			return nil, err
		}
	}

	// The phone number is never returned. The caller already knows the numbers
	// it sent; echoing back the ones that matched would confirm which of an
	// arbitrary list are registered, which is exactly the enumeration this
	// endpoint must not become.
	for i := range matched {
		matched[i].Phone = ""
	}
	return matched, nil
}

// List returns a user's saved contacts.
func (r *Contacts) List(ctx context.Context, ownerID int64, limit, offset int) ([]Contact, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	rows, err := r.db.pool.Query(ctx, `
		SELECT c.owner_id, c.user_id, c.first_name, c.last_name, c.added_at
		FROM contacts c
		JOIN users u ON u.id = c.user_id AND u.deleted_at IS NULL
		WHERE c.owner_id = $1
		ORDER BY c.first_name, c.last_name
		LIMIT $2 OFFSET $3`, ownerID, limit, offset)
	if err != nil {
		return nil, mapError(err)
	}
	defer rows.Close()

	out := make([]Contact, 0, limit)
	for rows.Next() {
		var c Contact
		if err := rows.Scan(&c.OwnerID, &c.UserID, &c.FirstName, &c.LastName, &c.AddedAt); err != nil {
			return nil, mapError(err)
		}
		out = append(out, c)
	}
	return out, mapError(rows.Err())
}

// Delete removes a contact.
func (r *Contacts) Delete(ctx context.Context, ownerID, userID int64) error {
	tag, err := r.db.pool.Exec(ctx,
		`DELETE FROM contacts WHERE owner_id = $1 AND user_id = $2`, ownerID, userID)
	if err != nil {
		return mapError(err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// MutualIDs returns the users who have this user in their contacts.
//
// Presence visibility keys off this: someone who has never saved your number
// should not learn when you are online.
func (r *Contacts) MutualIDs(ctx context.Context, userID int64) ([]int64, error) {
	rows, err := r.db.pool.Query(ctx,
		`SELECT owner_id FROM contacts WHERE user_id = $1 LIMIT 5000`, userID)
	if err != nil {
		return nil, mapError(err)
	}
	defer rows.Close()

	out := make([]int64, 0, 64)
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, mapError(err)
		}
		out = append(out, id)
	}
	return out, mapError(rows.Err())
}

// ---------------------------------------------------------------------------
// Blocklist
// ---------------------------------------------------------------------------

// Blocks is the blocklist repository.
type Blocks struct{ db *DB }

// BlocksRepo returns the blocklist repository.
func (d *DB) BlocksRepo() *Blocks { return &Blocks{db: d} }

// Block adds a user to the caller's blocklist.
func (r *Blocks) Block(ctx context.Context, ownerID, blockedID int64) error {
	if ownerID == blockedID {
		return ErrConflict
	}
	_, err := r.db.pool.Exec(ctx, `
		INSERT INTO blocklist (owner_id, blocked_id) VALUES ($1, $2)
		ON CONFLICT (owner_id, blocked_id) DO NOTHING`, ownerID, blockedID)
	return mapError(err)
}

// Unblock removes a block.
func (r *Blocks) Unblock(ctx context.Context, ownerID, blockedID int64) error {
	_, err := r.db.pool.Exec(ctx,
		`DELETE FROM blocklist WHERE owner_id = $1 AND blocked_id = $2`, ownerID, blockedID)
	return mapError(err)
}

// List returns who the caller has blocked.
func (r *Blocks) List(ctx context.Context, ownerID int64) ([]int64, error) {
	rows, err := r.db.pool.Query(ctx,
		`SELECT blocked_id FROM blocklist WHERE owner_id = $1 ORDER BY created_at DESC`, ownerID)
	if err != nil {
		return nil, mapError(err)
	}
	defer rows.Close()

	out := make([]int64, 0, 16)
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, mapError(err)
		}
		out = append(out, id)
	}
	return out, mapError(rows.Err())
}

// IsBlockedBetween reports whether either user has blocked the other.
//
// Symmetric on purpose. A block must stop messages in both directions:
// if it only stopped the blocked user from sending, the blocker could still
// message them, which is not what anyone means by "block".
//
// One query rather than two, because this runs on the send path of every
// private chat.
func (r *Blocks) IsBlockedBetween(ctx context.Context, a, b int64) (bool, error) {
	var exists bool
	err := r.db.pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM blocklist
			WHERE (owner_id = $1 AND blocked_id = $2)
			   OR (owner_id = $2 AND blocked_id = $1)
		)`, a, b).Scan(&exists)
	return exists, mapError(err)
}

// BlockedAmong filters a recipient list down to those who have blocked the
// sender, so a group message can skip them without a query per member.
func (r *Blocks) BlockedAmong(ctx context.Context, senderID int64, candidates []int64) (map[int64]bool, error) {
	out := make(map[int64]bool, 4)
	if len(candidates) == 0 {
		return out, nil
	}
	rows, err := r.db.pool.Query(ctx, `
		SELECT owner_id FROM blocklist
		WHERE blocked_id = $1 AND owner_id = ANY($2)`, senderID, candidates)
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
