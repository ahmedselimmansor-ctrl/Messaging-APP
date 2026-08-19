// Package ratelimit implements the distributed limiter that guards every
// entry point: REST, MTProto RPC and OTP issuance.
//
// The algorithm is a token bucket evaluated entirely inside a Lua script.
// Running it server-side matters for two reasons: it is atomic without a
// round-trip lock, and it means one network hop per decision instead of the
// read-modify-write pair a client-side implementation would need.
//
// A sliding-window counter would have been simpler, but it cannot express
// "sustained 1 msg/s but allow a burst of 20", which is exactly the shape of
// human chat traffic.
package ratelimit

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// tokenBucket returns [allowed(0|1), remaining, retry_after_ms].
//
// KEYS[1] = bucket key
// ARGV[1] = capacity (burst)
// ARGV[2] = refill tokens per second
// ARGV[3] = now in milliseconds
// ARGV[4] = requested tokens
// ARGV[5] = key TTL in seconds
var tokenBucket = redis.NewScript(`
local key       = KEYS[1]
local capacity  = tonumber(ARGV[1])
local rate      = tonumber(ARGV[2])
local now       = tonumber(ARGV[3])
local requested = tonumber(ARGV[4])
local ttl       = tonumber(ARGV[5])

local state = redis.call('HMGET', key, 'tokens', 'ts')
local tokens = tonumber(state[1])
local ts     = tonumber(state[2])

if tokens == nil then
  tokens = capacity
  ts = now
end

-- Refill for the elapsed time, capped at the bucket size.
local elapsed = math.max(0, now - ts) / 1000.0
tokens = math.min(capacity, tokens + elapsed * rate)
ts = now

local allowed = 0
local retry_after = 0

if tokens >= requested then
  tokens = tokens - requested
  allowed = 1
else
  -- Time until the bucket holds enough tokens for this request.
  local deficit = requested - tokens
  retry_after = math.ceil((deficit / rate) * 1000)
end

redis.call('HSET', key, 'tokens', tokens, 'ts', ts)
redis.call('EXPIRE', key, ttl)

return { allowed, math.floor(tokens), retry_after }
`)

// Limit describes one bucket.
type Limit struct {
	// Burst is the bucket capacity: the largest instantaneous spike allowed.
	Burst int
	// Rate is the sustained refill in tokens per second.
	Rate float64
}

// Decision is the outcome of a limiter check.
type Decision struct {
	Allowed    bool
	Remaining  int
	RetryAfter time.Duration
}

// Limiter evaluates limits against Redis.
type Limiter struct {
	rdb redis.UniversalClient
	// FailOpen decides what happens when Redis itself is unavailable.
	//
	// For user-facing message sending we fail open: a Redis outage must not
	// stop the product working. For OTP issuance and login we fail closed,
	// because failing open there turns a cache outage into an SMS-billing
	// incident or a credential-stuffing window.
	FailOpen bool
}

// New builds a limiter.
func New(rdb redis.UniversalClient, failOpen bool) *Limiter {
	return &Limiter{rdb: rdb, FailOpen: failOpen}
}

// Allow consumes one token from the named bucket.
func (l *Limiter) Allow(ctx context.Context, key string, lim Limit) (Decision, error) {
	return l.AllowN(ctx, key, lim, 1)
}

// AllowN consumes n tokens. Sending a 4MB file consumes more than sending
// "ok", so callers weight expensive operations.
func (l *Limiter) AllowN(ctx context.Context, key string, lim Limit, n int) (Decision, error) {
	if lim.Burst <= 0 || lim.Rate <= 0 {
		return Decision{Allowed: true}, nil
	}
	// The TTL only needs to outlive a full refill; anything longer just keeps
	// cold buckets in memory.
	ttl := int(float64(lim.Burst)/lim.Rate) + 60

	res, err := tokenBucket.Run(ctx, l.rdb,
		[]string{"rl:{" + key + "}"},
		lim.Burst, lim.Rate, time.Now().UnixMilli(), n, ttl,
	).Slice()
	if err != nil {
		if l.FailOpen {
			return Decision{Allowed: true}, nil
		}
		return Decision{Allowed: false, RetryAfter: time.Second},
			fmt.Errorf("ratelimit: evaluate %s: %w", key, err)
	}
	if len(res) != 3 {
		return Decision{Allowed: l.FailOpen}, errors.New("ratelimit: unexpected script result")
	}

	allowed, _ := res[0].(int64)
	remaining, _ := res[1].(int64)
	retryMS, _ := res[2].(int64)

	return Decision{
		Allowed:    allowed == 1,
		Remaining:  int(remaining),
		RetryAfter: time.Duration(retryMS) * time.Millisecond,
	}, nil
}

// Reset clears a bucket, used after a successful login clears a failed-attempt
// counter.
func (l *Limiter) Reset(ctx context.Context, key string) error {
	if err := l.rdb.Del(ctx, "rl:{"+key+"}").Err(); err != nil {
		return fmt.Errorf("ratelimit: reset %s: %w", key, err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Platform limits
// ---------------------------------------------------------------------------
//
// These numbers come from the shape of real chat use: a fast human types a
// short message every second or two and occasionally pastes a burst. They are
// deliberately generous per user and strict per IP, because the abuse we care
// about (spam accounts, OTP pumping) is cheap per account and expensive per
// address.

var (
	// SendMessage: sustained 5/s with a 30-message burst, per user.
	SendMessage = Limit{Burst: 30, Rate: 5}

	// SendMessagePerChat stops one chat being flooded while other chats of
	// the same user still work.
	SendMessagePerChat = Limit{Burst: 20, Rate: 3}

	// OTPRequestPerPhone: 3 codes, then one per 5 minutes. This is the limit
	// that protects the SMS bill.
	OTPRequestPerPhone = Limit{Burst: 3, Rate: 1.0 / 300.0}

	// OTPRequestPerIP catches an attacker cycling through phone numbers.
	OTPRequestPerIP = Limit{Burst: 10, Rate: 1.0 / 60.0}

	// OTPVerifyPerPhone bounds guessing a 5-digit code.
	OTPVerifyPerPhone = Limit{Burst: 5, Rate: 1.0 / 60.0}

	// LoginPerIP throttles credential stuffing.
	LoginPerIP = Limit{Burst: 20, Rate: 1.0 / 10.0}

	// UploadInit: media uploads are expensive; 10 concurrent-ish, 1/s after.
	UploadInit = Limit{Burst: 10, Rate: 1}

	// ConnectionPerIP bounds realtime connection churn from one address.
	ConnectionPerIP = Limit{Burst: 60, Rate: 2}

	// HandshakePerIP bounds the cost of the DH key exchange, which is the
	// most CPU-expensive unauthenticated operation the gateway performs.
	HandshakePerIP = Limit{Burst: 20, Rate: 0.5}

	// APIReadPerUser covers history/search reads.
	APIReadPerUser = Limit{Burst: 120, Rate: 20}

	// FileReport is deliberately tight. A moderation queue is a
	// denial-of-service target: flooding it buries the real reports, and the
	// people who do that are exactly the people being reported. Ten in a
	// burst covers someone reporting a spam wave; one per five minutes
	// sustained is far more than any genuine user needs.
	FileReport = Limit{Burst: 10, Rate: 1.0 / 300.0}

	// DataExport is per user per day, near enough. Building an export reads a
	// user's entire history, so it is the most expensive request the platform
	// serves — and one nobody legitimately makes twice in an hour.
	DataExport = Limit{Burst: 2, Rate: 1.0 / 43200.0}
)

// KeyUser builds a per-user bucket key.
func KeyUser(op string, userID int64) string { return fmt.Sprintf("%s:u:%d", op, userID) }

// KeyUserChat builds a per-user-per-chat bucket key.
func KeyUserChat(op string, userID, chatID int64) string {
	return fmt.Sprintf("%s:u:%d:c:%d", op, userID, chatID)
}

// KeyIP builds a per-address bucket key.
func KeyIP(op, ip string) string { return fmt.Sprintf("%s:ip:%s", op, ip) }

// KeyPhone builds a per-phone bucket key.
func KeyPhone(op, phone string) string { return fmt.Sprintf("%s:p:%s", op, phone) }
