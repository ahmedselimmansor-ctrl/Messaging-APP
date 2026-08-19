// Package gateway terminates client connections and speaks MTProto.
//
// It is the only stateful tier in the platform: a pod holds tens of thousands
// of live connections, each with a negotiated auth key and a subscription to
// its user's update channel. Everything it does with that state is
// recoverable — the auth key lives in Redis, the subscription is rebuilt on
// reconnect — so losing a pod costs a reconnect, not data.
package gateway

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pervagans/messaging-app/pkg/kafkax"
	"github.com/pervagans/messaging-app/pkg/mtproto"
	"github.com/pervagans/messaging-app/pkg/mtproto/transport"
	"github.com/pervagans/messaging-app/pkg/ratelimit"
	"github.com/pervagans/messaging-app/pkg/redisx"
	"github.com/pervagans/messaging-app/pkg/telemetry"
)

// Gateway owns the listeners, the shared Redis subscription and the registry
// of live sessions.
type Gateway struct {
	Cfg       Config
	Log       *slog.Logger
	Redis     *redisx.Client
	Bus       *redisx.Bus
	Presence  *redisx.Presence
	Sessions  *SessionStore
	Upstream  *Upstream
	Producer  *kafkax.Producer
	Limiter   *ratelimit.Limiter
	ServerKey *mtproto.ServerKey

	// sub is the pod's single Redis subscriber. One subscription per pod
	// rather than one per connection: a pod with 40k connections must not
	// open 40k Redis subscriptions.
	sub     *redisx.Subscription
	updates <-chan redisx.ChannelUpdate

	// registry maps a pub/sub channel to the sessions that want it. A user
	// with a phone and a laptop on the same pod shares one subscription.
	mu       sync.RWMutex
	registry map[string]map[*Session]struct{}

	active   atomic.Int64
	draining atomic.Bool
}

// New builds the gateway.
func New(cfg Config, log *slog.Logger, rdb *redisx.Client, upstream *Upstream,
	producer *kafkax.Producer, serverKey *mtproto.ServerKey) *Gateway {
	return &Gateway{
		Cfg:       cfg,
		Log:       log,
		Redis:     rdb,
		Bus:       rdb.PubSub(),
		Presence:  rdb.PresenceOf(cfg.PingInterval * 3),
		Sessions:  NewSessionStore(rdb, cfg.SessionTTL),
		Upstream:  upstream,
		Producer:  producer,
		Limiter:   ratelimit.New(rdb.Raw(), true),
		ServerKey: serverKey,
		registry:  make(map[string]map[*Session]struct{}),
	}
}

// Start opens the shared subscription and begins dispatching updates.
func (g *Gateway) Start(ctx context.Context) {
	g.sub, g.updates = g.Bus.Subscribe(ctx, g.Log, g.Cfg.UpdateQueueSize*16)
	go g.dispatchUpdates(ctx)
}

// dispatchUpdates routes each inbound pub/sub message to the sessions that
// asked for its channel.
//
// This is a single goroutine on purpose. Fanning out to N sessions is a map
// lookup and N non-blocking channel sends, all of which are cheap; running it
// concurrently would need locking per session and buy nothing.
func (g *Gateway) dispatchUpdates(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case cu, ok := <-g.updates:
			if !ok {
				return
			}
			g.mu.RLock()
			sessions := g.registry[cu.Channel]
			targets := make([]*Session, 0, len(sessions))
			for s := range sessions {
				targets = append(targets, s)
			}
			g.mu.RUnlock()

			for _, s := range targets {
				s.Enqueue(cu.Update)
			}
		}
	}
}

// subscribe registers a session's interest in a channel.
func (g *Gateway) subscribe(ctx context.Context, channel string, s *Session) error {
	g.mu.Lock()
	set, exists := g.registry[channel]
	if !exists {
		set = make(map[*Session]struct{}, 2)
		g.registry[channel] = set
	}
	set[s] = struct{}{}
	g.mu.Unlock()

	if err := g.sub.Add(ctx, channel); err != nil {
		g.unsubscribe(ctx, channel, s)
		return err
	}
	return nil
}

// unsubscribe removes a session's interest, dropping the Redis subscription
// when the last interested session goes away.
func (g *Gateway) unsubscribe(ctx context.Context, channel string, s *Session) {
	g.mu.Lock()
	set, exists := g.registry[channel]
	if exists {
		delete(set, s)
		if len(set) == 0 {
			delete(g.registry, channel)
		}
	}
	g.mu.Unlock()

	if err := g.sub.Remove(ctx, channel); err != nil {
		g.Log.Warn("unsubscribe failed", "channel", channel, "error", err)
	}
}

// Handle is the transport.Handler for every listener.
func (g *Gateway) Handle(ctx context.Context, conn transport.Conn) {
	kind := string(conn.Kind())
	telemetry.ConnectionsGauge.WithLabelValues(kind).Inc()
	g.active.Add(1)
	defer func() {
		telemetry.ConnectionsGauge.WithLabelValues(kind).Dec()
		g.active.Add(-1)
	}()

	// Refuse new work while draining: the pod is going away and a client that
	// connects now would just be disconnected seconds later.
	if g.draining.Load() {
		_ = conn.Close()
		return
	}

	remoteIP := hostOf(conn.RemoteAddr())
	if d, err := g.Limiter.Allow(ctx,
		ratelimit.KeyIP("conn", remoteIP), ratelimit.ConnectionPerIP); err == nil && !d.Allowed {
		g.Log.Warn("connection rate limited", "ip", remoteIP)
		_ = conn.Close()
		return
	}

	conn.SetIdleTimeout(g.Cfg.IdleTimeout)

	s := NewSession(g, conn)
	defer s.Close()

	s.Run(ctx)
}

// Drain tells every live session to reconnect elsewhere, then waits briefly
// for them to act on it.
//
// Without this, a rolling update would sever tens of thousands of connections
// at once and every client would reconnect on its own backoff schedule —
// producing a thundering herd against the new pods. Telling clients to move
// first spreads the reconnects over the drain window.
func (g *Gateway) Drain(ctx context.Context) {
	g.draining.Store(true)

	g.mu.RLock()
	seen := make(map[*Session]struct{})
	for _, set := range g.registry {
		for s := range set {
			seen[s] = struct{}{}
		}
	}
	g.mu.RUnlock()

	g.Log.Info("draining connections", "sessions", len(seen), "active", g.active.Load())

	for s := range seen {
		s.Enqueue(redisx.Update{
			Kind: redisx.UpdateReconnectHint,
			At:   time.Now().UnixMilli(),
		})
	}

	// Give clients a moment to disconnect on their own before the process
	// exits and the sockets close underneath them.
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-deadline.C:
			g.Log.Info("drain window elapsed", "remaining", g.active.Load())
			return
		case <-tick.C:
			if g.active.Load() == 0 {
				g.Log.Info("all connections drained")
				return
			}
		}
	}
}

// Close releases the shared subscription.
func (g *Gateway) Close(context.Context) error {
	if g.sub == nil {
		return nil
	}
	return g.sub.Close()
}

// Active reports the live connection count, for metrics and readiness.
func (g *Gateway) Active() int64 { return g.active.Load() }

// ErrDraining is returned to a client that connects during shutdown.
var ErrDraining = errors.New("gateway: draining")
