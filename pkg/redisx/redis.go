// Package redisx wraps Memorystore for Redis. It carries four workloads that
// share a cluster but not much else:
//
//   - presence: who is online, on which device, until when
//   - routing:  which gateway pod holds a given user's connection
//   - sequence: the per-chat monotonic message counter
//   - fanout:   pub/sub delivery of updates between gateway pods
//
// All four are latency-critical and none of them is the system of record, so
// every path here is written to degrade rather than fail: a Redis outage
// costs realtime delivery and forces a Cassandra fallback, it does not lose
// an accepted message.
package redisx

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// Config describes the Memorystore instance.
type Config struct {
	// Addrs is one address for a standalone instance, or the discovery
	// endpoint list for Memorystore Cluster.
	Addrs []string
	// Cluster selects the cluster client. Memorystore for Redis Cluster
	// requires it; a basic-tier instance must not use it.
	Cluster  bool
	Username string
	Password string
	// TLS is required when the instance has in-transit encryption enabled.
	TLS bool
	DB  int

	PoolSize     int
	MinIdleConns int
	DialTimeout  time.Duration
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
}

// Client is the shared Redis handle.
type Client struct {
	udc redis.UniversalClient
}

// Connect dials Redis and verifies reachability.
func Connect(ctx context.Context, cfg Config) (*Client, error) {
	if len(cfg.Addrs) == 0 {
		return nil, errors.New("redisx: no addresses configured")
	}

	opts := &redis.UniversalOptions{
		Addrs:        cfg.Addrs,
		Username:     cfg.Username,
		Password:     cfg.Password,
		DB:           cfg.DB,
		PoolSize:     orDefaultInt(cfg.PoolSize, 50),
		MinIdleConns: orDefaultInt(cfg.MinIdleConns, 10),
		DialTimeout:  orDefaultDur(cfg.DialTimeout, 3*time.Second),
		ReadTimeout:  orDefaultDur(cfg.ReadTimeout, 1*time.Second),
		WriteTimeout: orDefaultDur(cfg.WriteTimeout, 1*time.Second),
		// Two attempts, tight backoff: presence and routing lookups sit in the
		// message hot path, so a long retry is worse than a fast miss.
		MaxRetries:      2,
		MinRetryBackoff: 8 * time.Millisecond,
		MaxRetryBackoff: 100 * time.Millisecond,
	}
	if cfg.Cluster {
		opts.RouteByLatency = true
	}
	if cfg.TLS {
		opts.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}

	c := &Client{udc: redis.NewUniversalClient(opts)}
	if err := c.Ping(ctx); err != nil {
		_ = c.udc.Close()
		return nil, err
	}
	return c, nil
}

// Ping verifies the connection; used as a readiness check.
func (c *Client) Ping(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err := c.udc.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("redisx: ping: %w", err)
	}
	return nil
}

// Raw exposes the underlying client.
func (c *Client) Raw() redis.UniversalClient { return c.udc }

// Close releases the pool.
func (c *Client) Close(context.Context) error { return c.udc.Close() }

func orDefaultInt(v, def int) int {
	if v == 0 {
		return def
	}
	return v
}

func orDefaultDur(v, def time.Duration) time.Duration {
	if v == 0 {
		return def
	}
	return v
}

// ---------------------------------------------------------------------------
// Key layout
// ---------------------------------------------------------------------------
//
// Every key is wrapped in a hash tag so that, on Memorystore Cluster, all keys
// belonging to one entity hash to the same slot. Without the tag, a MULTI or a
// Lua script touching two keys of the same user would fail with CROSSSLOT.

func keyPresence(userID int64) string    { return fmt.Sprintf("pres:{u%d}", userID) }
func keyRoute(userID int64) string       { return fmt.Sprintf("route:{u%d}", userID) }
func keySeq(chatID int64) string         { return fmt.Sprintf("seq:{c%d}", chatID) }
func keySeqLock(chatID int64) string     { return fmt.Sprintf("seqlock:{c%d}", chatID) }
func keyMembers(chatID int64) string     { return fmt.Sprintf("members:{c%d}", chatID) }
func keySession(authKeyID string) string { return fmt.Sprintf("sess:{%s}", authKeyID) }

// ChannelUser is the pub/sub channel a gateway subscribes to for one
// connected user. Fanout writes to the recipients' channels, so a gateway
// only ever receives traffic for users it actually holds.
func ChannelUser(userID int64) string { return fmt.Sprintf("u:%d", userID) }

// ChannelChat carries chat-scoped ephemera (typing indicators) that is not
// worth a per-user fanout.
func ChannelChat(chatID int64) string { return fmt.Sprintf("c:%d", chatID) }

// ---------------------------------------------------------------------------
// Sequence allocation
// ---------------------------------------------------------------------------

// SeqAllocator hands out the dense, gap-free, per-chat message sequence.
//
// Why not a Cassandra counter or a snowflake? Clients need "everything after
// seq N" to be answerable with a range read and "unread count" to be
// subtraction. That requires density, which rules out snowflakes, and it
// requires strict monotonicity under concurrency, which rules out Cassandra
// counters (they are not read-modify-write safe).
//
// Redis INCR gives both in one round trip. The cost is that a lost Redis key
// would restart the counter — which is exactly what Reseed guards against.
type SeqAllocator struct {
	c *Client
	// Fallback recovers the high-water mark from durable storage when the
	// Redis key is missing.
	Fallback func(ctx context.Context, chatID int64) (int64, error)
}

// Seq returns the allocator.
func (c *Client) Seq(fallback func(context.Context, int64) (int64, error)) *SeqAllocator {
	return &SeqAllocator{c: c, Fallback: fallback}
}

// Next allocates the next sequence number for a chat.
//
// On a cold key it does not simply start at 1: it takes a short lock, asks
// Cassandra for the true maximum, seeds the counter past it and only then
// increments. Skipping that step after a Memorystore failover would reuse
// sequence numbers and silently overwrite history.
func (a *SeqAllocator) Next(ctx context.Context, chatID int64) (int64, error) {
	key := keySeq(chatID)

	n, err := a.c.udc.Incr(ctx, key).Result()
	if err != nil {
		return 0, fmt.Errorf("redisx: incr %s: %w", key, err)
	}
	if n > 1 {
		return n, nil
	}

	// n == 1 means the key did not exist. Either this really is the first
	// message, or we lost the counter. Reseed under a lock.
	if a.Fallback == nil {
		return n, nil
	}

	lock := keySeqLock(chatID)
	ok, err := a.c.udc.SetNX(ctx, lock, "1", 10*time.Second).Result()
	if err != nil {
		return 0, fmt.Errorf("redisx: seq lock: %w", err)
	}
	if !ok {
		// Another writer is reseeding. Wait briefly, then take a fresh number
		// from the (now seeded) counter.
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
		n, err = a.c.udc.Incr(ctx, key).Result()
		if err != nil {
			return 0, fmt.Errorf("redisx: incr after wait: %w", err)
		}
		return n, nil
	}
	defer a.c.udc.Del(context.WithoutCancel(ctx), lock)

	maxSeq, err := a.Fallback(ctx, chatID)
	if err != nil {
		return 0, fmt.Errorf("redisx: seq reseed lookup: %w", err)
	}
	if maxSeq < 1 {
		return 1, nil // genuinely the first message
	}

	// Jump the counter past the durable maximum. The extra headroom absorbs
	// any writes that were in flight while the key was missing.
	const reseedHeadroom = 100
	target := maxSeq + reseedHeadroom
	if err := a.c.udc.Set(ctx, key, target, 0).Err(); err != nil {
		return 0, fmt.Errorf("redisx: seq reseed: %w", err)
	}
	next, err := a.c.udc.Incr(ctx, key).Result()
	if err != nil {
		return 0, fmt.Errorf("redisx: incr after reseed: %w", err)
	}
	return next, nil
}

// Current reads the counter without advancing it.
func (a *SeqAllocator) Current(ctx context.Context, chatID int64) (int64, error) {
	n, err := a.c.udc.Get(ctx, keySeq(chatID)).Int64()
	if errors.Is(err, redis.Nil) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("redisx: read seq: %w", err)
	}
	return n, nil
}

// ---------------------------------------------------------------------------
// Membership cache
// ---------------------------------------------------------------------------

// MembersCache caches chat membership so the send path never touches Postgres.
type MembersCache struct {
	c   *Client
	ttl time.Duration
}

// Members returns the membership cache with the given TTL.
func (c *Client) Members(ttl time.Duration) *MembersCache {
	if ttl == 0 {
		ttl = 5 * time.Minute
	}
	return &MembersCache{c: c, ttl: ttl}
}

// Get returns the cached member list, or nil on a miss.
func (m *MembersCache) Get(ctx context.Context, chatID int64) ([]int64, error) {
	vals, err := m.c.udc.SMembers(ctx, keyMembers(chatID)).Result()
	if err != nil {
		return nil, fmt.Errorf("redisx: smembers: %w", err)
	}
	if len(vals) == 0 {
		return nil, nil
	}
	out := make([]int64, 0, len(vals))
	for _, v := range vals {
		var id int64
		if _, err := fmt.Sscanf(v, "%d", &id); err == nil {
			out = append(out, id)
		}
	}
	return out, nil
}

// Set replaces the cached member list.
func (m *MembersCache) Set(ctx context.Context, chatID int64, members []int64) error {
	key := keyMembers(chatID)
	args := make([]any, 0, len(members))
	for _, id := range members {
		args = append(args, id)
	}
	pipe := m.c.udc.TxPipeline()
	pipe.Del(ctx, key)
	if len(args) > 0 {
		pipe.SAdd(ctx, key, args...)
		pipe.Expire(ctx, key, m.ttl)
	}
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("redisx: cache members: %w", err)
	}
	return nil
}

// Invalidate drops the cached list, called when membership changes.
func (m *MembersCache) Invalidate(ctx context.Context, chatID int64) error {
	if err := m.c.udc.Del(ctx, keyMembers(chatID)).Err(); err != nil {
		return fmt.Errorf("redisx: invalidate members: %w", err)
	}
	return nil
}

// IsMember answers the authorisation question on the send path.
func (m *MembersCache) IsMember(ctx context.Context, chatID, userID int64) (bool, bool, error) {
	key := keyMembers(chatID)
	exists, err := m.c.udc.Exists(ctx, key).Result()
	if err != nil {
		return false, false, fmt.Errorf("redisx: exists: %w", err)
	}
	if exists == 0 {
		return false, false, nil // cache miss; caller must consult Postgres
	}
	ok, err := m.c.udc.SIsMember(ctx, key, userID).Result()
	if err != nil {
		return false, false, fmt.Errorf("redisx: sismember: %w", err)
	}
	return ok, true, nil
}

// SessionKeyFor exposes the session key layout to the auth service.
func SessionKeyFor(authKeyID string) string { return keySession(authKeyID) }

// NormaliseAddrs trims a comma-separated address list.
func NormaliseAddrs(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
