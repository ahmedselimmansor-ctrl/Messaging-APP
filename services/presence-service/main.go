// Command presence-service answers "who is online?" and broadcasts presence
// transitions.
//
// It owns no durable state. Presence lives in Memorystore with a TTL, because
// the correct answer to "is this user online?" is only ever a few seconds old
// and persisting it would mean a pod crash leaves users permanently "online".
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/pervagans/messaging-app/pkg/app"
	"github.com/pervagans/messaging-app/pkg/config"
	"github.com/pervagans/messaging-app/pkg/events"
	"github.com/pervagans/messaging-app/pkg/httpx"
	"github.com/pervagans/messaging-app/pkg/kafkax"
	"github.com/pervagans/messaging-app/pkg/redisx"
	"github.com/segmentio/kafka-go"
)

func main() {
	app.Run("presence-service", run)
}

type service struct {
	redis    *redisx.Client
	presence *redisx.Presence
	bus      *redisx.Bus
	producer *kafkax.Producer
}

func run(ctx context.Context, a *app.App) error {
	redisCfg := redisx.Config{
		Addrs:    config.Strings("REDIS_ADDRS", []string{"localhost:6379"}),
		Cluster:  config.Bool("REDIS_CLUSTER", false),
		Username: config.String("REDIS_USERNAME", ""),
		Password: config.Secret("REDIS_PASSWORD", ""),
		TLS:      config.Bool("REDIS_TLS", false),
	}
	rdb, err := redisx.Connect(ctx, redisCfg)
	if err != nil {
		return fmt.Errorf("redis: %w", err)
	}
	a.OnShutdown("redis", rdb.Close)
	a.Health.Register("redis", rdb.Ping)

	kafkaCfg := kafkax.Config{
		Brokers:  config.Strings("KAFKA_BROKERS", []string{"localhost:9092"}),
		UseOAuth: config.Bool("KAFKA_OAUTH", a.Cfg.Env != "dev"),
		TLS:      config.Bool("KAFKA_TLS", a.Cfg.Env != "dev"),
		ClientID: "presence-service",
	}
	producer, err := kafkax.NewProducer(kafkaCfg, kafkax.DefaultProducerOptions())
	if err != nil {
		return fmt.Errorf("kafka producer: %w", err)
	}
	a.OnShutdown("kafka-producer", producer.Close)

	ttl := config.Duration("PRESENCE_TTL", 90*time.Second)
	svc := &service{
		redis:    rdb,
		presence: rdb.PresenceOf(ttl),
		bus:      rdb.PubSub(),
		producer: producer,
	}

	// Consume presence.events so a transition raised on any gateway pod is
	// reflected in the shared store and broadcast to interested peers.
	//
	// StartOffset is LastOffset, not FirstOffset: replaying yesterday's
	// presence transitions on a restart would tell every client that a crowd
	// of people just came online.
	consumer, err := kafkax.NewConsumer(kafkaCfg, kafkax.ConsumerOptions{
		Topic:          events.TopicPresenceEvents,
		Group:          config.String("KAFKA_GROUP", "presence-service"),
		StartOffset:    kafka.LastOffset,
		MaxRetries:     3,
		CommitInterval: time.Second,
	}, a.Log)
	if err != nil {
		return fmt.Errorf("kafka consumer: %w", err)
	}
	a.OnShutdown("kafka-consumer", consumer.Close)

	go func() {
		if err := consumer.Run(ctx, svc.handleEvent); err != nil {
			a.Log.Error("presence consumer stopped", "error", err)
		}
	}()

	srv := httpx.NewServer(a.Cfg.HTTPAddr, svc.routes())
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			a.Log.Error("http listener failed", "error", err)
		}
	}()
	a.OnShutdown("http", srv.Shutdown)

	return nil
}

func (s *service) routes() http.Handler {
	r := chi.NewRouter()
	for _, mw := range httpx.BaseMiddleware("presence-service") {
		r.Use(mw)
	}

	// Internal only: presence is exposed to clients through the realtime
	// gateway, which already knows who is asking. Publishing it directly
	// would be a privacy leak — anyone could poll whether a given user is
	// online without being their contact.
	r.Get("/internal/v1/presence/{userID}", httpx.H(s.handleGet))
	r.Post("/internal/v1/presence/bulk", httpx.H(s.handleBulk))
	r.Post("/internal/v1/presence/online", httpx.H(s.handleOnline))
	r.Post("/internal/v1/presence/offline", httpx.H(s.handleOffline))
	r.Post("/internal/v1/presence/heartbeat", httpx.H(s.handleHeartbeat))

	return r
}

func (s *service) handleGet(w http.ResponseWriter, r *http.Request) error {
	userID, err := httpx.PathInt64(r, "userID")
	if err != nil {
		return err
	}
	online, err := s.presence.IsOnline(r.Context(), userID)
	if err != nil {
		return httpx.ErrUnavailable("presence lookup failed").WithCause(err)
	}
	lastSeen, known, err := s.presence.LastSeen(r.Context(), userID)
	if err != nil {
		return httpx.ErrUnavailable("presence lookup failed").WithCause(err)
	}

	out := map[string]any{"user_id": userID, "online": online}
	if known {
		out["last_seen"] = lastSeen
	}
	httpx.WriteJSON(w, http.StatusOK, out)
	return nil
}

type bulkRequest struct {
	UserIDs []int64 `json:"user_ids"`
}

func (s *service) handleBulk(w http.ResponseWriter, r *http.Request) error {
	var req bulkRequest
	if err := httpx.DecodeJSON(r, 256<<10, &req); err != nil {
		return err
	}
	if len(req.UserIDs) > 5000 {
		return httpx.ErrBadRequest("at most 5000 user ids per request")
	}
	states, err := s.presence.OnlineMany(r.Context(), req.UserIDs)
	if err != nil {
		return httpx.ErrUnavailable("presence lookup failed").WithCause(err)
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"online": states})
	return nil
}

type transitionRequest struct {
	UserID   int64  `json:"user_id"`
	DeviceID int64  `json:"device_id"`
	Pod      string `json:"pod,omitempty"`
	Region   string `json:"region,omitempty"`
	Platform string `json:"platform,omitempty"`
	// Contacts are the peers to notify. The gateway supplies them because it
	// already knows the user's dialogs; presence does not read Postgres.
	Contacts []int64 `json:"contacts,omitempty"`
}

func (s *service) handleOnline(w http.ResponseWriter, r *http.Request) error {
	var req transitionRequest
	if err := httpx.DecodeJSON(r, 256<<10, &req); err != nil {
		return err
	}
	if req.UserID == 0 || req.DeviceID == 0 {
		return httpx.ErrBadRequest("user_id and device_id are required")
	}

	if err := s.presence.Online(r.Context(), req.UserID, redisx.DeviceRoute{
		DeviceID: req.DeviceID, Pod: req.Pod, Region: req.Region, Platform: req.Platform,
	}); err != nil {
		return httpx.ErrUnavailable("could not record presence").WithCause(err)
	}

	s.broadcast(r.Context(), req, events.PresenceOnline)
	httpx.WriteJSON(w, http.StatusOK, map[string]bool{"ok": true})
	return nil
}

func (s *service) handleOffline(w http.ResponseWriter, r *http.Request) error {
	var req transitionRequest
	if err := httpx.DecodeJSON(r, 256<<10, &req); err != nil {
		return err
	}
	if req.UserID == 0 || req.DeviceID == 0 {
		return httpx.ErrBadRequest("user_id and device_id are required")
	}

	if err := s.presence.Offline(r.Context(), req.UserID, req.DeviceID); err != nil {
		return httpx.ErrUnavailable("could not clear presence").WithCause(err)
	}

	// Only announce "offline" once the *last* device disconnects. A user with
	// a phone and a laptop must not appear offline because they closed one tab.
	stillOnline, err := s.presence.IsOnline(r.Context(), req.UserID)
	if err == nil && !stillOnline {
		s.broadcast(r.Context(), req, events.PresenceOffline)
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]bool{"ok": true})
	return nil
}

func (s *service) handleHeartbeat(w http.ResponseWriter, r *http.Request) error {
	var req transitionRequest
	if err := httpx.DecodeJSON(r, 4<<10, &req); err != nil {
		return err
	}
	if err := s.presence.Heartbeat(r.Context(), req.UserID, req.DeviceID); err != nil {
		return httpx.ErrUnavailable("heartbeat failed").WithCause(err)
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]bool{"ok": true})
	return nil
}

// broadcast tells the user's contacts about a transition, and records it on
// Kafka for anything that wants the history (analytics, anti-abuse).
func (s *service) broadcast(ctx context.Context, req transitionRequest, state events.PresenceState) {
	evt := events.PresenceEvent{
		V: events.CurrentVersion, UserID: req.UserID, DeviceID: req.DeviceID,
		State: state, At: time.Now().UTC(),
	}
	body, err := json.Marshal(evt)
	if err != nil {
		return
	}

	detached := context.WithoutCancel(ctx)
	go func() {
		bg, cancel := context.WithTimeout(detached, 5*time.Second)
		defer cancel()

		if err := s.producer.Publish(bg, events.TopicPresenceEvents,
			[]byte(fmt.Sprint(req.UserID)), body); err != nil {
			return
		}
		if len(req.Contacts) > 0 {
			payload, _ := json.Marshal(map[string]any{"state": state})
			_ = s.bus.PublishToUsers(bg, req.Contacts, redisx.Update{
				Kind: redisx.UpdatePresence, UserID: req.UserID, Body: payload,
			})
		}
	}()
}

// handleEvent applies a presence transition raised elsewhere in the fleet.
func (s *service) handleEvent(ctx context.Context, m kafka.Message) error {
	var evt events.PresenceEvent
	if err := json.Unmarshal(m.Value, &evt); err != nil {
		// A record we cannot parse is a schema mismatch, not a transient
		// failure; retrying it forever would block the partition.
		return fmt.Errorf("%w: %v", kafkax.ErrSkip, err)
	}
	if evt.UserID == 0 {
		return kafkax.ErrSkip
	}

	// Typing indicators are chat-scoped and ephemeral; they are delivered
	// directly by the chat service and need no presence bookkeeping.
	if evt.State == events.PresenceTyping {
		return nil
	}

	switch evt.State {
	case events.PresenceOnline:
		return s.presence.Heartbeat(ctx, evt.UserID, evt.DeviceID)
	case events.PresenceOffline:
		return s.presence.Offline(ctx, evt.UserID, evt.DeviceID)
	}
	return nil
}
