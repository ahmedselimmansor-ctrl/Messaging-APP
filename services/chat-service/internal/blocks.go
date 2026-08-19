package chat

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/pervagans/messaging-app/pkg/httpx"
	"github.com/pervagans/messaging-app/pkg/pgstore"
	"github.com/redis/go-redis/v9"
)

// Block enforcement on the send path.
//
// The blocklist lives in the auth service, which owns account-scoped data, so
// the chat service asks it. That would be a network call on every private
// message — so the answer is cached in Redis, and the auth service
// invalidates the entry when a block changes. A block therefore takes effect
// on the next message rather than after a TTL.
//
// The cache is the interesting part. A stale "not blocked" lets one more
// message through, which is bad; a stale "blocked" silently drops messages
// between people who are not blocked, which is worse. Eager invalidation on
// the write side is what keeps both windows at zero.

// blockCacheTTL bounds how long a cached decision survives if an invalidation
// is somehow missed.
const blockCacheTTL = 10 * time.Minute

func blockCacheKey(a, b int64) string {
	// Ordered, so both directions share one entry: a block is symmetric, and
	// caching it twice would mean two chances to leave a stale one behind.
	if a > b {
		a, b = b, a
	}
	return fmt.Sprintf("block:{%d:%d}", a, b)
}

// isBlocked reports whether either user has blocked the other.
//
// Fails open. If the auth service and the cache are both unreachable, the
// message goes through: a blocked message getting delivered during an outage
// is a smaller failure than every private message in the platform failing.
func (s *Service) isBlocked(ctx context.Context, a, b int64) bool {
	key := blockCacheKey(a, b)

	switch cached, err := s.Redis.Raw().Get(ctx, key).Result(); {
	case err == nil:
		return cached == "1"
	case err != redis.Nil:
		s.Log.Warn("block cache read failed", "error", err)
	}

	endpoint := fmt.Sprintf("%s/internal/v1/blocks/check?a=%d&b=%d", s.Cfg.AuthServiceURL, a, b)

	reqCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, endpoint, nil)
	if err != nil {
		return false
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		s.Log.Warn("block check failed; allowing the message", "error", err)
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		s.Log.Warn("block check returned an error; allowing the message", "status", resp.Status)
		return false
	}

	var out struct {
		Blocked bool `json:"blocked"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<10)).Decode(&out); err != nil {
		return false
	}

	value := "0"
	if out.Blocked {
		value = "1"
	}
	if err := s.Redis.Raw().Set(ctx, key, value, blockCacheTTL).Err(); err != nil {
		s.Log.Warn("block cache write failed", "error", err)
	}
	return out.Blocked
}

// blockedAmong returns which of a group's recipients have blocked the sender.
//
// Groups are not cached: the membership varies per message and the set of
// blockers is small, so one call with the whole candidate list is cheaper
// than N cache lookups.
func (s *Service) blockedAmong(ctx context.Context, senderID int64, candidates []int64) map[int64]bool {
	empty := map[int64]bool{}
	if len(candidates) == 0 {
		return empty
	}

	body, err := json.Marshal(map[string]any{
		"sender_id": senderID, "candidates": candidates,
	})
	if err != nil {
		return empty
	}

	reqCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost,
		s.Cfg.AuthServiceURL+"/internal/v1/blocks/among", bytes.NewReader(body))
	if err != nil {
		return empty
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		// Fail open, as above.
		s.Log.Warn("group block check failed; delivering to everyone", "error", err)
		return empty
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return empty
	}

	var out struct {
		BlockedBy []int64 `json:"blocked_by"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return empty
	}

	result := make(map[int64]bool, len(out.BlockedBy))
	for _, id := range out.BlockedBy {
		result[id] = true
	}
	return result
}

// enforceBlocks applies the blocklist to a send.
//
// The two cases are genuinely different:
//
//   - In a private chat a block means the message is refused outright. The
//     sender is told nothing useful — "you cannot send messages to this user"
//     rather than "they blocked you", because confirming a block is
//     information the blocker did not agree to share.
//   - In a group a block cannot refuse the message: everyone else is entitled
//     to receive it. Instead the blocker is dropped from the fanout, so they
//     simply do not see it.
func (s *Service) enforceBlocks(ctx context.Context, chat pgstore.Chat, senderID int64, recipients []int64) ([]int64, error) {
	if chat.Type == pgstore.ChatPrivate {
		var peer int64
		for _, id := range recipients {
			if id != senderID {
				peer = id
				break
			}
		}
		if peer != 0 && s.isBlocked(ctx, senderID, peer) {
			return nil, httpx.ErrForbidden("you cannot send messages to this user")
		}
		return recipients, nil
	}

	blocked := s.blockedAmong(ctx, senderID, recipients)
	if len(blocked) == 0 {
		return recipients, nil
	}

	filtered := make([]int64, 0, len(recipients))
	for _, id := range recipients {
		if !blocked[id] {
			filtered = append(filtered, id)
		}
	}
	return filtered, nil
}
