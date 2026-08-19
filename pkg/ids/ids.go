// Package ids generates the identifiers used across the platform.
//
// Two different ID shapes are needed and they solve different problems:
//
//   - Snowflake (int64): time-ordered, sortable, compact. Used for user_id,
//     chat_id and device_id — anything that ends up in a Cassandra partition
//     key or a hot Redis key, where 8 bytes beats a 16-byte UUID and where
//     rough time ordering makes range scans and TTL sweeps cheap.
//   - UUIDv4 (string): opaque, unguessable. Used for message_id, upload_id
//     and anything a client can echo back, so nobody can enumerate.
//
// Message ordering within a chat is *not* handled here — it uses a per-chat
// monotonic sequence allocated by the chat service (see pkg/redisx.SeqAllocator),
// because clients need a dense, gap-free counter for "unread since seq N".
package ids

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Epoch is the custom snowflake epoch: 2024-01-01T00:00:00Z. Starting from a
// recent epoch buys ~69 years of range out of 41 bits.
const Epoch int64 = 1704067200000

const (
	nodeBits = 10
	stepBits = 12

	maxNode = -1 ^ (-1 << nodeBits) // 1023
	maxStep = -1 ^ (-1 << stepBits) // 4095

	timeShift = nodeBits + stepBits
	nodeShift = stepBits
)

// Snowflake is a lock-protected 64-bit ID generator.
//
// Layout: [1 unused][41 ms since Epoch][10 node][12 sequence]
type Snowflake struct {
	mu   sync.Mutex
	node int64
	last int64
	step int64
}

// NewSnowflake builds a generator for the given node id (0..1023).
//
// In Kubernetes the node id comes from the pod's ordinal for StatefulSets, or
// from a hash of the pod name for Deployments. A collision only matters if two
// pods generate an ID in the same millisecond with the same sequence, so the
// hash approach is acceptable at our replica counts; StatefulSet ordinals are
// used where we need a hard guarantee.
func NewSnowflake(node int64) (*Snowflake, error) {
	if node < 0 || node > maxNode {
		return nil, fmt.Errorf("ids: node %d out of range 0..%d", node, maxNode)
	}
	return &Snowflake{node: node}, nil
}

// NodeFromHostname derives a node id from a pod hostname.
//
// StatefulSet pods are named <set>-<ordinal>; we use the ordinal directly so
// the mapping is stable across restarts. Deployment pods fall back to an
// FNV-1a hash of the whole name.
func NodeFromHostname(hostname string) int64 {
	for i := len(hostname) - 1; i >= 0; i-- {
		if hostname[i] == '-' {
			if n, err := strconv.ParseInt(hostname[i+1:], 10, 64); err == nil {
				return n & maxNode
			}
			break
		}
	}
	var h uint32 = 2166136261
	for i := 0; i < len(hostname); i++ {
		h ^= uint32(hostname[i])
		h *= 16777619
	}
	return int64(h) & maxNode
}

// Next returns the next snowflake. It never returns a duplicate and never
// goes backwards, even if the wall clock steps back: on a backwards jump it
// spins until the clock catches up rather than minting a colliding ID.
func (s *Snowflake) Next() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UnixMilli()
	for now < s.last {
		time.Sleep(time.Duration(s.last-now) * time.Millisecond)
		now = time.Now().UnixMilli()
	}

	if now == s.last {
		s.step = (s.step + 1) & maxStep
		if s.step == 0 {
			// Sequence exhausted for this millisecond; wait for the next.
			for now <= s.last {
				now = time.Now().UnixMilli()
			}
		}
	} else {
		s.step = 0
	}
	s.last = now

	return (now-Epoch)<<timeShift | s.node<<nodeShift | s.step
}

// TimeOf recovers the creation time embedded in a snowflake.
func TimeOf(id int64) time.Time {
	return time.UnixMilli((id >> timeShift) + Epoch).UTC()
}

// NewUUID returns a random UUIDv4 string.
func NewUUID() string { return uuid.NewString() }

// ParseUUID validates a UUID string.
func ParseUUID(s string) (uuid.UUID, error) { return uuid.Parse(s) }

// Token returns n cryptographically random bytes, for session keys, OTP
// nonces and upload tokens.
func Token(n int) ([]byte, error) {
	if n <= 0 {
		return nil, errors.New("ids: token length must be positive")
	}
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("ids: read random: %w", err)
	}
	return b, nil
}

// RandomInt64 returns a uniformly random non-negative int64, used for
// MTProto session ids and message salts.
func RandomInt64() (int64, error) {
	b, err := Token(8)
	if err != nil {
		return 0, err
	}
	return int64(binary.BigEndian.Uint64(b) >> 1), nil
}

// NumericCode returns a zero-padded decimal code of n digits, uniformly
// distributed. Used for phone verification.
func NumericCode(n int) (string, error) {
	if n <= 0 || n > 18 {
		return "", errors.New("ids: code length must be 1..18")
	}
	max := int64(1)
	for i := 0; i < n; i++ {
		max *= 10
	}
	// Rejection sampling keeps the distribution flat; a plain modulo would
	// bias low digits.
	limit := (int64(1) << 62 / max) * max
	for {
		v, err := RandomInt64()
		if err != nil {
			return "", err
		}
		v &= 1<<62 - 1
		if v < limit {
			return fmt.Sprintf("%0*d", n, v%max), nil
		}
	}
}
