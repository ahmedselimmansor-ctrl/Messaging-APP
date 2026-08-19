package redisx

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// Bans is the ban flag on the hot path.
//
// A ban has to be enforced when a banned account tries to send, and the send
// path must not touch Postgres. So the flag is mirrored into Redis when the
// ban is applied, and checked here.
//
// The two enforcement points, and why both exist:
//
//   - Token issuance, in the auth service, reads Postgres. That is the
//     authoritative check and it is on a cold path, so a database read is
//     free. Within one access-token lifetime (15 minutes) a banned account
//     cannot obtain new credentials at all.
//   - The send path checks here. That closes the 15-minute window for the
//     action that actually matters — a banned account continuing to message
//     people while its current token is still valid.
//
// The failure mode is worth stating plainly: absence means "not banned", so a
// Redis flush stops the send-path check from firing. Bans continue to be
// enforced at token issuance throughout, which bounds the exposure at one
// access-token lifetime. Reload() exists to close it faster.
//
// The alternative — treating a Redis outage as "everyone is banned" — fails
// the wrong way. This is the one place where failing open is right, because
// the cost of the alternative is the entire platform going silent.
type Bans struct {
	c   *Client
	ttl time.Duration
}

// Bans returns the ban cache.
//
// The TTL is a backstop, not the mechanism. Entries are removed explicitly on
// unban; the expiry only bounds how long a stale entry could survive a missed
// delete, so it is deliberately long — an accidentally-persistent ban is a
// support ticket, an accidentally-lifted one is an abuser back online.
func (c *Client) Bans(ttl time.Duration) *Bans {
	if ttl == 0 {
		ttl = 24 * time.Hour
	}
	return &Bans{c: c, ttl: ttl}
}

func keyBan(userID int64) string { return fmt.Sprintf("ban:%d", userID) }

// IsBanned reports whether the account is banned.
//
// A Redis error is returned rather than swallowed so the caller decides. The
// send path treats an error as not-banned and logs it, for the reason in the
// type comment.
func (b *Bans) IsBanned(ctx context.Context, userID int64) (bool, error) {
	n, err := b.c.udc.Exists(ctx, keyBan(userID)).Result()
	if err != nil {
		return false, fmt.Errorf("redisx: ban lookup: %w", err)
	}
	return n > 0, nil
}

// Set marks an account banned.
//
// reason is stored for diagnostics only — the authoritative record is the
// Postgres row and the audit entry. It is here so an operator debugging "why
// is this user getting 403s" gets an answer from the cache they are already
// looking at.
func (b *Bans) Set(ctx context.Context, userID int64, reason string) error {
	if err := b.c.udc.Set(ctx, keyBan(userID), reason, b.ttl).Err(); err != nil {
		return fmt.Errorf("redisx: set ban: %w", err)
	}
	return nil
}

// Clear lifts a ban.
func (b *Bans) Clear(ctx context.Context, userID int64) error {
	if err := b.c.udc.Del(ctx, keyBan(userID)).Err(); err != nil && err != redis.Nil {
		return fmt.Errorf("redisx: clear ban: %w", err)
	}
	return nil
}

// Reload repopulates the cache from an authoritative list.
//
// Run after a Redis failover or flush, and periodically as a reconciliation
// pass. Without it the send-path check silently degrades to permitting
// everything, and nothing would ever say so.
//
// It adds rather than replaces: it must not delete a ban applied between
// reading the list and writing it here.
func (b *Bans) Reload(ctx context.Context, banned map[int64]string) error {
	if len(banned) == 0 {
		return nil
	}
	pipe := b.c.udc.Pipeline()
	for id, reason := range banned {
		pipe.Set(ctx, keyBan(id), reason, b.ttl)
	}
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("redisx: reload bans: %w", err)
	}
	return nil
}
