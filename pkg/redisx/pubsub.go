package redisx

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// UpdateKind enumerates the realtime updates pushed to clients.
type UpdateKind string

const (
	UpdateNewMessage    UpdateKind = "new_message"
	UpdateEditMessage   UpdateKind = "edit_message"
	UpdateDeleteMessage UpdateKind = "delete_message"
	UpdateReadReceipt   UpdateKind = "read_receipt"
	UpdateTyping        UpdateKind = "typing"
	UpdatePresence      UpdateKind = "presence"
	UpdateChatCreated   UpdateKind = "chat_created"
	UpdateMemberChanged UpdateKind = "member_changed"
	UpdateChatDeleted   UpdateKind = "chat_deleted"
	UpdateReconnectHint UpdateKind = "reconnect"
)

// Update is the envelope carried over pub/sub between gateway pods and
// delivered verbatim to the client.
type Update struct {
	Kind   UpdateKind      `json:"kind"`
	ChatID int64           `json:"chat_id,omitempty"`
	Seq    int64           `json:"seq,omitempty"`
	UserID int64           `json:"user_id,omitempty"`
	At     int64           `json:"at"` // unix millis
	Body   json.RawMessage `json:"body,omitempty"`
}

// Bus is the pub/sub fanout between gateway pods.
//
// Redis pub/sub is fire-and-forget: a subscriber that is not connected at
// publish time never sees the message. That is the correct trade for realtime
// delivery — an offline user is served by push notifications and by the
// catch-up range read on reconnect, both of which read from durable storage.
// Using pub/sub here rather than a Kafka partition per user keeps fanout
// latency in the low milliseconds and avoids one consumer group per pod.
type Bus struct{ c *Client }

// PubSub returns the fanout bus.
func (c *Client) PubSub() *Bus { return &Bus{c: c} }

// Publish sends an update to a single channel.
func (b *Bus) Publish(ctx context.Context, channel string, u Update) error {
	if u.At == 0 {
		u.At = time.Now().UnixMilli()
	}
	blob, err := json.Marshal(u)
	if err != nil {
		return fmt.Errorf("redisx: marshal update: %w", err)
	}
	if err := b.c.udc.Publish(ctx, channel, blob).Err(); err != nil {
		return fmt.Errorf("redisx: publish %s: %w", channel, err)
	}
	return nil
}

// PublishToUsers fans an update out to many recipients in one pipeline.
//
// This is the hot path for group chats: a 200-member group becomes 200
// PUBLISH commands, and pipelining turns 200 round trips into one.
func (b *Bus) PublishToUsers(ctx context.Context, userIDs []int64, u Update) error {
	if len(userIDs) == 0 {
		return nil
	}
	if u.At == 0 {
		u.At = time.Now().UnixMilli()
	}
	blob, err := json.Marshal(u)
	if err != nil {
		return fmt.Errorf("redisx: marshal update: %w", err)
	}

	pipe := b.c.udc.Pipeline()
	for _, id := range userIDs {
		pipe.Publish(ctx, ChannelUser(id), blob)
	}
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("redisx: fanout publish: %w", err)
	}
	return nil
}

// Subscription is a live subscriber owned by one gateway pod.
//
// Channels are added and removed as connections come and go, so the pod holds
// exactly one Redis subscriber connection regardless of how many users it
// serves — a pod with 50k connections must not open 50k subscriptions.
type Subscription struct {
	ps  *redis.PubSub
	log *slog.Logger

	mu       sync.Mutex
	channels map[string]int // channel -> refcount (a user may have 2 devices here)
	closed   bool
}

// Subscribe starts a subscriber. Received updates are delivered on the
// returned channel until ctx is cancelled or Close is called.
func (b *Bus) Subscribe(ctx context.Context, log *slog.Logger, buffer int) (*Subscription, <-chan ChannelUpdate) {
	if buffer <= 0 {
		buffer = 1024
	}
	// Subscribing with no channels is valid; channels are added on demand.
	ps := b.c.udc.Subscribe(ctx)

	s := &Subscription{
		ps:       ps,
		log:      log,
		channels: map[string]int{},
	}

	out := make(chan ChannelUpdate, buffer)
	go s.pump(ctx, out)
	return s, out
}

// ChannelUpdate pairs an update with the channel it arrived on.
type ChannelUpdate struct {
	Channel string
	Update  Update
}

func (s *Subscription) pump(ctx context.Context, out chan<- ChannelUpdate) {
	defer close(out)
	ch := s.ps.Channel(redis.WithChannelSize(1024))

	for {
		select {
		case <-ctx.Done():
			return
		case msg, ok := <-ch:
			if !ok {
				return
			}
			var u Update
			if err := json.Unmarshal([]byte(msg.Payload), &u); err != nil {
				s.log.Warn("dropping malformed update", "channel", msg.Channel, "error", err)
				continue
			}
			select {
			case out <- ChannelUpdate{Channel: msg.Channel, Update: u}:
			default:
				// The gateway's dispatch loop is behind. Dropping here is
				// deliberate: blocking would stall every other user on this
				// pod, and the client will resync via the catch-up read.
				s.log.Warn("update dropped, dispatch backlog full", "channel", msg.Channel)
			}
		}
	}
}

// Add subscribes to a channel, refcounted per caller.
func (s *Subscription) Add(ctx context.Context, channel string) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return errors.New("redisx: subscription closed")
	}
	n := s.channels[channel]
	s.channels[channel] = n + 1
	s.mu.Unlock()

	if n > 0 {
		return nil // already subscribed for another device
	}
	if err := s.ps.Subscribe(ctx, channel); err != nil {
		s.mu.Lock()
		s.channels[channel]--
		s.mu.Unlock()
		return fmt.Errorf("redisx: subscribe %s: %w", channel, err)
	}
	return nil
}

// Remove drops one reference and unsubscribes when it reaches zero.
func (s *Subscription) Remove(ctx context.Context, channel string) error {
	s.mu.Lock()
	n := s.channels[channel]
	switch {
	case n <= 1:
		delete(s.channels, channel)
	default:
		s.channels[channel] = n - 1
	}
	closed := s.closed
	s.mu.Unlock()

	if n > 1 || closed {
		return nil
	}
	if err := s.ps.Unsubscribe(ctx, channel); err != nil {
		return fmt.Errorf("redisx: unsubscribe %s: %w", channel, err)
	}
	return nil
}

// Len reports how many distinct channels are subscribed.
func (s *Subscription) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.channels)
}

// Close tears the subscriber down.
func (s *Subscription) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.mu.Unlock()
	return s.ps.Close()
}
