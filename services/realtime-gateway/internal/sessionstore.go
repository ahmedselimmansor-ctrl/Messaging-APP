package gateway

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/pervagans/messaging-app/pkg/mtproto"
	"github.com/pervagans/messaging-app/pkg/redisx"
	"github.com/redis/go-redis/v9"
)

// SessionStore holds negotiated auth keys and their identity bindings.
//
// It lives in Redis rather than in pod memory for one reason: a client that
// reconnects lands on whichever gateway pod the load balancer picks, which is
// almost never the one it handshook with. Without shared storage every
// reconnect would need a fresh 2048-bit Diffie-Hellman exchange — expensive
// for the client, far more expensive for us, and a self-inflicted thundering
// herd after every rolling update.
//
// Key material in Redis is a real exposure, and it is bounded deliberately:
// the instance is private to the VPC, encrypted in transit, and every key is
// TTL'd. Redis is not the system of record for anything else, so a compromise
// there costs live sessions, not history.
type SessionStore struct {
	rdb redis.UniversalClient
	ttl time.Duration
}

// NewSessionStore builds the store.
func NewSessionStore(c *redisx.Client, ttl time.Duration) *SessionStore {
	if ttl == 0 {
		ttl = 30 * 24 * time.Hour
	}
	return &SessionStore{rdb: c.Raw(), ttl: ttl}
}

// ErrNoSession is returned when an auth key id is unknown.
var ErrNoSession = errors.New("gateway: no such session")

func keyAuth(authKeyID uint64) string {
	return "authkey:{" + mtproto.AuthKeyIDHex(authKeyID) + "}"
}

func keyBinding(authKeyID uint64) string {
	return "authbind:{" + mtproto.AuthKeyIDHex(authKeyID) + "}"
}

// Save persists a negotiated auth key.
func (s *SessionStore) Save(ctx context.Context, key *mtproto.AuthKey) error {
	encoded := base64.StdEncoding.EncodeToString(key.Bytes())
	if err := s.rdb.Set(ctx, keyAuth(key.ID()), encoded, s.ttl).Err(); err != nil {
		return fmt.Errorf("gateway: store auth key: %w", err)
	}
	return nil
}

// Load resolves an auth key id back to its key material.
//
// It also refreshes the TTL, so an actively used session never expires while
// an abandoned one does.
func (s *SessionStore) Load(ctx context.Context, authKeyID uint64) (*mtproto.AuthKey, error) {
	k := keyAuth(authKeyID)

	encoded, err := s.rdb.Get(ctx, k).Result()
	if errors.Is(err, redis.Nil) {
		return nil, ErrNoSession
	}
	if err != nil {
		return nil, fmt.Errorf("gateway: load auth key: %w", err)
	}

	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("gateway: stored auth key is corrupt: %w", err)
	}
	key, err := mtproto.NewAuthKey(raw)
	if err != nil {
		return nil, err
	}
	// Guard against a key id collision or a corrupted entry handing us the
	// wrong key: the id must be derivable from the material itself.
	if key.ID() != authKeyID {
		return nil, fmt.Errorf("gateway: stored key id %s does not match the requested %s",
			key.IDHex(), mtproto.AuthKeyIDHex(authKeyID))
	}

	// Best effort: a failed TTL refresh only shortens the session's life.
	if err := s.rdb.Expire(ctx, k, s.ttl).Err(); err != nil {
		_ = err
	}
	return key, nil
}

// Binding is the identity attached to an auth key.
type Binding struct {
	UserID   int64 `json:"user_id"`
	DeviceID int64 `json:"device_id"`
}

// SaveBinding records which account an auth key belongs to.
func (s *SessionStore) SaveBinding(ctx context.Context, authKeyID uint64, b Binding) error {
	body, err := json.Marshal(b)
	if err != nil {
		return err
	}
	if err := s.rdb.Set(ctx, keyBinding(authKeyID), body, s.ttl).Err(); err != nil {
		return fmt.Errorf("gateway: store binding: %w", err)
	}
	return nil
}

// LoadBinding returns the identity attached to an auth key.
func (s *SessionStore) LoadBinding(ctx context.Context, authKeyID uint64) (Binding, error) {
	raw, err := s.rdb.Get(ctx, keyBinding(authKeyID)).Bytes()
	if errors.Is(err, redis.Nil) {
		return Binding{}, ErrNoSession
	}
	if err != nil {
		return Binding{}, fmt.Errorf("gateway: load binding: %w", err)
	}
	var b Binding
	if err := json.Unmarshal(raw, &b); err != nil {
		return Binding{}, fmt.Errorf("gateway: stored binding is corrupt: %w", err)
	}
	if err := s.rdb.Expire(ctx, keyBinding(authKeyID), s.ttl).Err(); err != nil {
		_ = err
	}
	return b, nil
}

// Delete removes a session. Called on explicit logout and on device
// revocation, which is what makes "log out this session" immediate rather
// than eventual.
func (s *SessionStore) Delete(ctx context.Context, authKeyID uint64) error {
	if err := s.rdb.Del(ctx, keyAuth(authKeyID), keyBinding(authKeyID)).Err(); err != nil {
		return fmt.Errorf("gateway: delete session: %w", err)
	}
	return nil
}
