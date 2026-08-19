package pgstore

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Users is the account repository.
type Users struct{ db *DB }

// UsersRepo returns the account repository.
func (d *DB) UsersRepo() *Users { return &Users{db: d} }

const userColumns = `id, phone, username, display_name, about_text, avatar_object,
	lang_code, created_at, updated_at, deleted_at, banned`

func scanUser(row pgx.Row) (User, error) {
	var u User
	err := row.Scan(&u.ID, &u.Phone, &u.Username, &u.DisplayName, &u.AboutText,
		&u.AvatarObj, &u.LangCode, &u.CreatedAt, &u.UpdatedAt, &u.DeletedAt, &u.Banned)
	return u, mapError(err)
}

// GetByID loads a user.
func (r *Users) GetByID(ctx context.Context, id int64) (User, error) {
	return scanUser(r.db.pool.QueryRow(ctx,
		`SELECT `+userColumns+` FROM users WHERE id = $1 AND deleted_at IS NULL`, id))
}

// GetByPhone loads a user by E.164 phone number.
func (r *Users) GetByPhone(ctx context.Context, phone string) (User, error) {
	return scanUser(r.db.pool.QueryRow(ctx,
		`SELECT `+userColumns+` FROM users WHERE phone = $1 AND deleted_at IS NULL`, phone))
}

// GetByUsername resolves a public @username.
func (r *Users) GetByUsername(ctx context.Context, username string) (User, error) {
	return scanUser(r.db.pool.QueryRow(ctx,
		`SELECT `+userColumns+` FROM users WHERE lower(username) = lower($1) AND deleted_at IS NULL`,
		username))
}

// GetMany loads several users in one round trip. Used to hydrate a chat list
// or a member roster without an N+1.
func (r *Users) GetMany(ctx context.Context, ids []int64) (map[int64]User, error) {
	out := make(map[int64]User, len(ids))
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := r.db.pool.Query(ctx,
		`SELECT `+userColumns+` FROM users WHERE id = ANY($1) AND deleted_at IS NULL`, ids)
	if err != nil {
		return nil, mapError(err)
	}
	defer rows.Close()

	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out[u.ID] = u
	}
	return out, mapError(rows.Err())
}

// Create inserts a new account.
func (r *Users) Create(ctx context.Context, u User) (User, error) {
	err := r.db.pool.QueryRow(ctx, `
		INSERT INTO users (id, phone, display_name, lang_code)
		VALUES ($1, $2, $3, $4)
		RETURNING `+userColumns,
		u.ID, u.Phone, u.DisplayName, orDefault(u.LangCode, "en"),
	).Scan(&u.ID, &u.Phone, &u.Username, &u.DisplayName, &u.AboutText,
		&u.AvatarObj, &u.LangCode, &u.CreatedAt, &u.UpdatedAt, &u.DeletedAt, &u.Banned)
	return u, mapError(err)
}

// UpdateProfile changes the mutable profile fields. Nil pointers are left
// untouched, so a client can PATCH one field without sending the rest.
func (r *Users) UpdateProfile(ctx context.Context, id int64, displayName, about, avatarObj, langCode *string) (User, error) {
	sets := make([]string, 0, 5)
	args := make([]any, 0, 6)
	arg := func(v any) string {
		args = append(args, v)
		return fmt.Sprintf("$%d", len(args))
	}

	if displayName != nil {
		sets = append(sets, "display_name = "+arg(*displayName))
	}
	if about != nil {
		sets = append(sets, "about_text = "+arg(*about))
	}
	if avatarObj != nil {
		sets = append(sets, "avatar_object = "+arg(*avatarObj))
	}
	if langCode != nil {
		sets = append(sets, "lang_code = "+arg(*langCode))
	}
	if len(sets) == 0 {
		return r.GetByID(ctx, id)
	}
	sets = append(sets, "updated_at = now()")

	q := `UPDATE users SET ` + strings.Join(sets, ", ") +
		` WHERE id = ` + arg(id) + ` AND deleted_at IS NULL RETURNING ` + userColumns
	return scanUser(r.db.pool.QueryRow(ctx, q, args...))
}

// SetUsername claims a public username, or clears it when empty.
func (r *Users) SetUsername(ctx context.Context, id int64, username string) error {
	var value any
	if username != "" {
		value = username
	}
	_, err := r.db.pool.Exec(ctx,
		`UPDATE users SET username = $1, updated_at = now() WHERE id = $2 AND deleted_at IS NULL`,
		value, id)
	return mapError(err)
}

// SoftDelete deactivates an account, freeing the phone number and username
// for reuse while keeping the row so message history stays attributable.
func (r *Users) SoftDelete(ctx context.Context, id int64) error {
	_, err := r.db.pool.Exec(ctx, `
		UPDATE users
		SET deleted_at = now(),
		    phone = 'deleted:' || id::text,
		    username = NULL,
		    display_name = 'Deleted Account',
		    avatar_object = NULL,
		    about_text = ''
		WHERE id = $1 AND deleted_at IS NULL`, id)
	return mapError(err)
}

// SearchByUsername does a prefix search for the "add contact" screen.
func (r *Users) SearchByUsername(ctx context.Context, prefix string, limit int) ([]User, error) {
	if limit <= 0 || limit > 50 {
		limit = 20
	}
	rows, err := r.db.pool.Query(ctx, `
		SELECT `+userColumns+`
		FROM users
		WHERE username IS NOT NULL
		  AND lower(username) LIKE lower($1) || '%'
		  AND deleted_at IS NULL AND banned = false
		ORDER BY length(username), username
		LIMIT $2`, prefix, limit)
	if err != nil {
		return nil, mapError(err)
	}
	defer rows.Close()

	out := make([]User, 0, limit)
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, mapError(rows.Err())
}

// ---------------------------------------------------------------------------
// Devices
// ---------------------------------------------------------------------------

// Devices is the session repository.
type Devices struct{ db *DB }

// DevicesRepo returns the device repository.
func (d *DB) DevicesRepo() *Devices { return &Devices{db: d} }

const deviceColumns = `id, user_id, auth_key_id, platform, app_version, device_model,
	push_token, last_ip, created_at, last_seen_at, revoked_at`

func scanDevice(row pgx.Row) (Device, error) {
	var d Device
	err := row.Scan(&d.ID, &d.UserID, &d.AuthKeyID, &d.Platform, &d.AppVersion,
		&d.DeviceModel, &d.PushToken, &d.LastIP, &d.CreatedAt, &d.LastSeenAt, &d.RevokedAt)
	return d, mapError(err)
}

// Upsert registers or refreshes a device by auth key id.
//
// The auth key is the identity here, not the device model string: a client
// that re-runs the handshake gets a new key and therefore a new device row,
// which is what makes "log out other sessions" meaningful.
func (r *Devices) Upsert(ctx context.Context, d Device) (Device, error) {
	return scanDevice(r.db.pool.QueryRow(ctx, `
		INSERT INTO devices (id, user_id, auth_key_id, platform, app_version, device_model, last_ip)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (auth_key_id) DO UPDATE SET
			last_seen_at = now(),
			last_ip      = EXCLUDED.last_ip,
			app_version  = EXCLUDED.app_version,
			revoked_at   = NULL
		RETURNING `+deviceColumns,
		d.ID, d.UserID, d.AuthKeyID, d.Platform, d.AppVersion, d.DeviceModel, d.LastIP))
}

// GetByAuthKey resolves a session from its MTProto auth key id.
func (r *Devices) GetByAuthKey(ctx context.Context, authKeyID string) (Device, error) {
	return scanDevice(r.db.pool.QueryRow(ctx,
		`SELECT `+deviceColumns+` FROM devices WHERE auth_key_id = $1 AND revoked_at IS NULL`,
		authKeyID))
}

// ListForUser returns the active sessions shown on the "devices" screen.
func (r *Devices) ListForUser(ctx context.Context, userID int64) ([]Device, error) {
	rows, err := r.db.pool.Query(ctx,
		`SELECT `+deviceColumns+` FROM devices
		 WHERE user_id = $1 AND revoked_at IS NULL ORDER BY last_seen_at DESC`, userID)
	if err != nil {
		return nil, mapError(err)
	}
	defer rows.Close()

	out := make([]Device, 0, 8)
	for rows.Next() {
		d, err := scanDevice(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, mapError(rows.Err())
}

// SetPushToken stores the FCM registration token for a device.
func (r *Devices) SetPushToken(ctx context.Context, deviceID int64, token string) error {
	var value any
	if token != "" {
		value = token
	}
	_, err := r.db.pool.Exec(ctx,
		`UPDATE devices SET push_token = $1, last_seen_at = now() WHERE id = $2`, value, deviceID)
	return mapError(err)
}

// PushTargetsFor returns the FCM tokens to notify for a set of users,
// skipping revoked devices and devices with no token.
//
// This is the query the push consumer runs for every message, so it is a
// single ANY() lookup rather than a loop, and it returns the device id
// alongside the token so an FCM "unregistered" response can be traced back to
// exactly which row to clear.
func (r *Devices) PushTargetsFor(ctx context.Context, userIDs []int64) (map[int64][]PushTarget, error) {
	out := make(map[int64][]PushTarget, len(userIDs))
	if len(userIDs) == 0 {
		return out, nil
	}
	rows, err := r.db.pool.Query(ctx, `
		SELECT user_id, id, push_token, platform
		FROM devices
		WHERE user_id = ANY($1) AND revoked_at IS NULL AND push_token IS NOT NULL`, userIDs)
	if err != nil {
		return nil, mapError(err)
	}
	defer rows.Close()

	for rows.Next() {
		var userID int64
		var t PushTarget
		if err := rows.Scan(&userID, &t.DeviceID, &t.Token, &t.Platform); err != nil {
			return nil, mapError(err)
		}
		out[userID] = append(out[userID], t)
	}
	return out, mapError(rows.Err())
}

// PushTarget is one notifiable device.
type PushTarget struct {
	DeviceID int64
	Token    string
	Platform string
}

// Revoke invalidates one session.
func (r *Devices) Revoke(ctx context.Context, userID, deviceID int64) error {
	tag, err := r.db.pool.Exec(ctx,
		`UPDATE devices SET revoked_at = now(), push_token = NULL
		 WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL`, deviceID, userID)
	if err != nil {
		return mapError(err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// RevokeAllExcept logs out every session but the current one.
func (r *Devices) RevokeAllExcept(ctx context.Context, userID, keepDeviceID int64) (int64, error) {
	tag, err := r.db.pool.Exec(ctx,
		`UPDATE devices SET revoked_at = now(), push_token = NULL
		 WHERE user_id = $1 AND id <> $2 AND revoked_at IS NULL`, userID, keepDeviceID)
	if err != nil {
		return 0, mapError(err)
	}
	return tag.RowsAffected(), nil
}

// ClearPushToken drops a token FCM reported as unregistered.
func (r *Devices) ClearPushToken(ctx context.Context, deviceID int64) error {
	_, err := r.db.pool.Exec(ctx, `UPDATE devices SET push_token = NULL WHERE id = $1`, deviceID)
	return mapError(err)
}

// Touch records activity without a full upsert.
func (r *Devices) Touch(ctx context.Context, deviceID int64, ip string) error {
	_, err := r.db.pool.Exec(ctx,
		`UPDATE devices SET last_seen_at = now(), last_ip = $2 WHERE id = $1`, deviceID, ip)
	return mapError(err)
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// ---------------------------------------------------------------------------
// OTP challenges
// ---------------------------------------------------------------------------

// OTP is the phone-verification repository.
type OTP struct{ db *DB }

// OTPRepo returns the OTP repository.
func (d *DB) OTPRepo() *OTP { return &OTP{db: d} }

// Create stores a pending challenge. Only the bcrypt hash of the code is
// written, so a database leak does not hand an attacker live login codes.
func (r *OTP) Create(ctx context.Context, id, phone, codeHash string, ttl time.Duration) (OTPChallenge, error) {
	var c OTPChallenge
	err := r.db.pool.QueryRow(ctx, `
		INSERT INTO otp_challenges (id, phone, code_hash, expires_at)
		VALUES ($1, $2, $3, now() + $4::interval)
		RETURNING id, phone, code_hash, attempts, created_at, expires_at, consumed_at`,
		id, phone, codeHash, fmt.Sprintf("%d seconds", int(ttl.Seconds())),
	).Scan(&c.ID, &c.Phone, &c.CodeHash, &c.Attempts, &c.CreatedAt, &c.ExpiresAt, &c.ConsumedAt)
	return c, mapError(err)
}

// Get loads a live challenge.
func (r *OTP) Get(ctx context.Context, id string) (OTPChallenge, error) {
	var c OTPChallenge
	err := r.db.pool.QueryRow(ctx, `
		SELECT id, phone, code_hash, attempts, created_at, expires_at, consumed_at
		FROM otp_challenges WHERE id = $1`, id,
	).Scan(&c.ID, &c.Phone, &c.CodeHash, &c.Attempts, &c.CreatedAt, &c.ExpiresAt, &c.ConsumedAt)
	return c, mapError(err)
}

// IncrementAttempts records a failed guess and returns the new count.
func (r *OTP) IncrementAttempts(ctx context.Context, id string) (int, error) {
	var n int
	err := r.db.pool.QueryRow(ctx,
		`UPDATE otp_challenges SET attempts = attempts + 1 WHERE id = $1 RETURNING attempts`, id).
		Scan(&n)
	return n, mapError(err)
}

// Consume marks a challenge used. It is conditional on the row still being
// unconsumed, so two concurrent verifications cannot both succeed.
func (r *OTP) Consume(ctx context.Context, id string) error {
	tag, err := r.db.pool.Exec(ctx,
		`UPDATE otp_challenges SET consumed_at = now()
		 WHERE id = $1 AND consumed_at IS NULL AND expires_at > now()`, id)
	if err != nil {
		return mapError(err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// PurgeExpired deletes old challenges. Run from a CronJob.
func (r *OTP) PurgeExpired(ctx context.Context) (int64, error) {
	tag, err := r.db.pool.Exec(ctx,
		`DELETE FROM otp_challenges WHERE expires_at < now() - interval '1 day'`)
	if err != nil {
		return 0, mapError(err)
	}
	return tag.RowsAffected(), nil
}
