// Command notification-service sends push notifications through Firebase
// Cloud Messaging.
//
// It exposes a small internal API for one-off sends and consumes
// notifications.push for anything queued asynchronously. Chat messages do not
// come through here — the pusher consumer handles those, because it needs the
// presence check and the mute check that only make sense for a message.
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
	"github.com/pervagans/messaging-app/pkg/pgstore"
	"github.com/pervagans/messaging-app/pkg/push"
	"github.com/segmentio/kafka-go"
)

func main() {
	app.Run("notification-service", run)
}

type service struct {
	fcm     *push.FCM
	devices *pgstore.Devices
}

func run(ctx context.Context, a *app.App) error {
	dsn, err := config.MustString("POSTGRES_DSN")
	if err != nil {
		return err
	}
	pgCfg := pgstore.DefaultConfig()
	pgCfg.DSN = dsn
	pgCfg.MaxConns = int32(config.Int("POSTGRES_MAX_CONNS", 10))

	db, err := pgstore.Connect(ctx, pgCfg)
	if err != nil {
		return fmt.Errorf("postgres: %w", err)
	}
	a.OnShutdown("postgres", db.Close)
	a.Health.Register("postgres", db.Ping)

	projectID := config.String("FIREBASE_PROJECT_ID", a.Cfg.ProjectID)
	if projectID == "" {
		return errors.New("FIREBASE_PROJECT_ID (or GCP_PROJECT_ID) is required")
	}
	fcm, err := push.NewFCM(ctx, push.Config{
		ProjectID: projectID,
		DryRun:    config.Bool("FCM_DRY_RUN", a.Cfg.Env == "dev"),
		Timeout:   config.Duration("FCM_TIMEOUT", 10*time.Second),
	}, a.Log)
	if err != nil {
		return fmt.Errorf("fcm: %w", err)
	}

	svc := &service{fcm: fcm, devices: db.DevicesRepo()}

	kafkaCfg := kafkax.Config{
		Brokers:  config.Strings("KAFKA_BROKERS", []string{"localhost:9092"}),
		UseOAuth: config.Bool("KAFKA_OAUTH", a.Cfg.Env != "dev"),
		TLS:      config.Bool("KAFKA_TLS", a.Cfg.Env != "dev"),
		ClientID: "notification-service",
	}
	dlq, err := kafkax.NewProducer(kafkaCfg, kafkax.DefaultProducerOptions())
	if err != nil {
		return fmt.Errorf("kafka producer: %w", err)
	}
	a.OnShutdown("kafka-producer", dlq.Close)

	consumer, err := kafkax.NewConsumer(kafkaCfg, kafkax.ConsumerOptions{
		Topic:       events.TopicNotificationsPush,
		Group:       config.String("KAFKA_GROUP", "notification-service"),
		StartOffset: kafka.FirstOffset,
		MaxRetries:  4,
		DLQProducer: dlq,
	}, a.Log)
	if err != nil {
		return fmt.Errorf("kafka consumer: %w", err)
	}
	a.OnShutdown("kafka-consumer", consumer.Close)

	go func() {
		if err := consumer.Run(ctx, svc.handleQueued); err != nil {
			a.Log.Error("push consumer stopped", "error", err)
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
	for _, mw := range httpx.BaseMiddleware("notification-service") {
		r.Use(mw)
	}
	r.Post("/internal/v1/push", httpx.H(s.handlePush))
	return r
}

type pushRequest struct {
	UserID      int64             `json:"user_id"`
	Title       string            `json:"title"`
	Body        string            `json:"body"`
	Data        map[string]string `json:"data,omitempty"`
	CollapseKey string            `json:"collapse_key,omitempty"`
	Badge       int               `json:"badge,omitempty"`
}

func (s *service) handlePush(w http.ResponseWriter, r *http.Request) error {
	var req pushRequest
	if err := httpx.DecodeJSON(r, 32<<10, &req); err != nil {
		return err
	}
	if req.UserID == 0 {
		return httpx.ErrBadRequest("user_id is required")
	}

	sent, err := s.send(r.Context(), events.PushRequest{
		V: events.CurrentVersion, UserID: req.UserID, Title: req.Title, Body: req.Body,
		Data: req.Data, CollapseKey: req.CollapseKey, Badge: req.Badge,
		CreatedAt: time.Now().UTC(),
	})
	if err != nil {
		return httpx.ErrUnavailable("push delivery failed").WithCause(err)
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]any{"delivered": sent})
	return nil
}

func (s *service) handleQueued(ctx context.Context, m kafka.Message) error {
	var req events.PushRequest
	if err := json.Unmarshal(m.Value, &req); err != nil {
		return fmt.Errorf("%w: malformed push request: %v", kafkax.ErrSkip, err)
	}
	if req.UserID == 0 {
		return kafkax.ErrSkip
	}
	_, err := s.send(ctx, req)
	return err
}

// send resolves a user's devices and dispatches to FCM.
func (s *service) send(ctx context.Context, req events.PushRequest) (int, error) {
	targets, err := s.devices.PushTargetsFor(ctx, []int64{req.UserID})
	if err != nil {
		return 0, fmt.Errorf("device lookup: %w", err)
	}
	devices := targets[req.UserID]
	if len(devices) == 0 {
		// No registered device is a normal outcome — a web-only user, or one
		// who declined notifications. It is not an error to retry.
		return 0, nil
	}

	msgs := make([]push.Message, 0, len(devices))
	for _, d := range devices {
		msgs = append(msgs, push.Message{
			Token:       d.Token,
			Platform:    d.Platform,
			Title:       req.Title,
			Body:        req.Body,
			Data:        req.Data,
			CollapseKey: req.CollapseKey,
			Badge:       req.Badge,
		})
	}

	results, err := s.fcm.SendAll(ctx, msgs)
	if err != nil {
		return 0, err
	}

	delivered := 0
	for i, res := range results {
		switch {
		case res.OK:
			delivered++
		case res.Unregistered:
			// FCM says this token is dead: the app was uninstalled or the
			// token rotated. Clearing it stops us retrying forever and stops
			// the device row counting towards "has notifications enabled".
			if err := s.devices.ClearPushToken(ctx, devices[i].DeviceID); err != nil {
				return delivered, fmt.Errorf("clear dead token: %w", err)
			}
		case res.Retryable:
			return delivered, fmt.Errorf("fcm transient failure: %s", res.Error)
		}
	}
	return delivered, nil
}
