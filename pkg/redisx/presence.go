package redisx

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

// Presence tracks who is connected and where.
//
// Two facts are stored per user and they answer different questions:
//
//   - presence (pres:{uN}): a hash of device_id -> last-seen unix seconds,
//     with a TTL. Answers "is this user online?" for the UI and for the push
//     decision.
//   - routing (route:{uN}): a hash of device_id -> gateway pod identity.
//     Answers "which pod holds this connection?" so a direct delivery can
//     skip the broadcast.
//
// Both are TTL'd rather than explicitly deleted, because the one failure mode
// that matters is a gateway pod dying without running its cleanup: a stale
// "online" entry would suppress push notifications indefinitely. A TTL that
// the gateway must keep refreshing turns that from a permanent bug into a
// bounded, self-healing gap.
type Presence struct {
	c *Client
	// TTL is how long an entry survives without a heartbeat. It must be
	// comfortably longer than the gateway's heartbeat interval so a single
	// missed refresh does not mark a live user offline.
	TTL time.Duration
}

// PresenceOf returns the presence store.
func (c *Client) PresenceOf(ttl time.Duration) *Presence {
	if ttl == 0 {
		ttl = 90 * time.Second
	}
	return &Presence{c: c, TTL: ttl}
}

// DeviceRoute records where one device's connection lives.
type DeviceRoute struct {
	DeviceID int64  `json:"device_id"`
	Pod      string `json:"pod"`      // gateway pod name
	Region   string `json:"region"`   // GCP region, for cross-region routing
	Since    int64  `json:"since"`    // unix seconds
	Platform string `json:"platform"` // android|ios|web|desktop
}

// Online records a connection and refreshes the TTL.
func (p *Presence) Online(ctx context.Context, userID int64, r DeviceRoute) error {
	now := time.Now().Unix()
	r.Since = now
	blob, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("redisx: marshal route: %w", err)
	}

	field := strconv.FormatInt(r.DeviceID, 10)
	pipe := p.c.udc.TxPipeline()
	pipe.HSet(ctx, keyPresence(userID), field, now)
	pipe.Expire(ctx, keyPresence(userID), p.TTL)
	pipe.HSet(ctx, keyRoute(userID), field, blob)
	pipe.Expire(ctx, keyRoute(userID), p.TTL)
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("redisx: set presence: %w", err)
	}
	return nil
}

// Heartbeat extends the TTL for a still-connected device. It is the cheapest
// possible call — two HSETs and two EXPIREs — because every gateway runs it
// for every connection on a fixed interval.
func (p *Presence) Heartbeat(ctx context.Context, userID, deviceID int64) error {
	field := strconv.FormatInt(deviceID, 10)
	pipe := p.c.udc.Pipeline()
	pipe.HSet(ctx, keyPresence(userID), field, time.Now().Unix())
	pipe.Expire(ctx, keyPresence(userID), p.TTL)
	pipe.Expire(ctx, keyRoute(userID), p.TTL)
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("redisx: heartbeat: %w", err)
	}
	return nil
}

// Offline removes one device.
func (p *Presence) Offline(ctx context.Context, userID, deviceID int64) error {
	field := strconv.FormatInt(deviceID, 10)
	pipe := p.c.udc.Pipeline()
	pipe.HDel(ctx, keyPresence(userID), field)
	pipe.HDel(ctx, keyRoute(userID), field)
	if _, err := pipe.Exec(ctx); err != nil && !errors.Is(err, redis.Nil) {
		return fmt.Errorf("redisx: clear presence: %w", err)
	}
	return nil
}

// IsOnline reports whether the user has at least one live device.
func (p *Presence) IsOnline(ctx context.Context, userID int64) (bool, error) {
	n, err := p.c.udc.HLen(ctx, keyPresence(userID)).Result()
	if err != nil {
		return false, fmt.Errorf("redisx: hlen presence: %w", err)
	}
	return n > 0, nil
}

// OnlineMany answers the push decision for a whole recipient list in one
// round trip. The pusher calls this for every message, so an N+1 of HLENs
// would be the single hottest call in the platform.
func (p *Presence) OnlineMany(ctx context.Context, userIDs []int64) (map[int64]bool, error) {
	out := make(map[int64]bool, len(userIDs))
	if len(userIDs) == 0 {
		return out, nil
	}

	pipe := p.c.udc.Pipeline()
	cmds := make(map[int64]*redis.IntCmd, len(userIDs))
	for _, id := range userIDs {
		cmds[id] = pipe.HLen(ctx, keyPresence(id))
	}
	if _, err := pipe.Exec(ctx); err != nil && !errors.Is(err, redis.Nil) {
		return nil, fmt.Errorf("redisx: bulk presence: %w", err)
	}
	for id, cmd := range cmds {
		n, err := cmd.Result()
		if err != nil && !errors.Is(err, redis.Nil) {
			// Treat an unreadable entry as offline: sending a redundant push
			// to an online user is a far smaller failure than silently
			// dropping a notification for an offline one.
			out[id] = false
			continue
		}
		out[id] = n > 0
	}
	return out, nil
}

// LastSeen returns the most recent heartbeat across all of a user's devices.
func (p *Presence) LastSeen(ctx context.Context, userID int64) (time.Time, bool, error) {
	vals, err := p.c.udc.HGetAll(ctx, keyPresence(userID)).Result()
	if err != nil {
		return time.Time{}, false, fmt.Errorf("redisx: hgetall presence: %w", err)
	}
	if len(vals) == 0 {
		return time.Time{}, false, nil
	}
	var newest int64
	for _, v := range vals {
		if ts, err := strconv.ParseInt(v, 10, 64); err == nil && ts > newest {
			newest = ts
		}
	}
	return time.Unix(newest, 0).UTC(), true, nil
}

// Routes returns where each of a user's devices is connected.
func (p *Presence) Routes(ctx context.Context, userID int64) ([]DeviceRoute, error) {
	vals, err := p.c.udc.HGetAll(ctx, keyRoute(userID)).Result()
	if err != nil {
		return nil, fmt.Errorf("redisx: hgetall routes: %w", err)
	}
	out := make([]DeviceRoute, 0, len(vals))
	for _, v := range vals {
		var r DeviceRoute
		if err := json.Unmarshal([]byte(v), &r); err != nil {
			continue // a malformed entry is not worth failing the lookup over
		}
		out = append(out, r)
	}
	return out, nil
}
