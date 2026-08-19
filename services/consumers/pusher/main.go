// Command pusher sends notifications for messages whose recipients are
// offline.
//
// It consumes messages.persisted — never messages.raw — so a notification can
// only ever describe a message that is already in the history. Waking someone's
// phone for a message that then failed to persist would be the worst kind of
// bug: visible, unexplainable and unrecoverable.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/pervagans/messaging-app/pkg/app"
	"github.com/pervagans/messaging-app/pkg/config"
	"github.com/pervagans/messaging-app/pkg/events"
	"github.com/pervagans/messaging-app/pkg/kafkax"
	"github.com/pervagans/messaging-app/pkg/logx"
	"github.com/pervagans/messaging-app/pkg/pgstore"
	"github.com/pervagans/messaging-app/pkg/push"
	"github.com/pervagans/messaging-app/pkg/redisx"
	"github.com/pervagans/messaging-app/pkg/telemetry"
	"github.com/segmentio/kafka-go"
)

func main() {
	app.Run("pusher", run)
}

type consumer struct {
	presence *redisx.Presence
	members  *pgstore.Members
	devices  *pgstore.Devices
	users    *pgstore.Users
	chats    *pgstore.Chats
	fcm      *push.FCM

	// showPreview controls whether the notification carries the message text.
	// Off means the phone shows "New message" and the app fetches the content
	// after unlock — the right default for a privacy-focused product, and the
	// only correct behaviour for secret chats.
	showPreview bool
}

func run(ctx context.Context, a *app.App) error {
	dsn, err := config.MustString("POSTGRES_DSN")
	if err != nil {
		return err
	}
	pgCfg := pgstore.DefaultConfig()
	pgCfg.DSN = dsn
	pgCfg.MaxConns = int32(config.Int("POSTGRES_MAX_CONNS", 15))

	db, err := pgstore.Connect(ctx, pgCfg)
	if err != nil {
		return fmt.Errorf("postgres: %w", err)
	}
	a.OnShutdown("postgres", db.Close)
	a.Health.Register("postgres", db.Ping)

	rdb, err := redisx.Connect(ctx, redisx.Config{
		Addrs:    config.Strings("REDIS_ADDRS", []string{"localhost:6379"}),
		Cluster:  config.Bool("REDIS_CLUSTER", false),
		Username: config.String("REDIS_USERNAME", ""),
		Password: config.Secret("REDIS_PASSWORD", ""),
		TLS:      config.Bool("REDIS_TLS", false),
	})
	if err != nil {
		return fmt.Errorf("redis: %w", err)
	}
	a.OnShutdown("redis", rdb.Close)
	a.Health.Register("redis", rdb.Ping)

	projectID := config.String("FIREBASE_PROJECT_ID", a.Cfg.ProjectID)
	fcm, err := push.NewFCM(ctx, push.Config{
		ProjectID:   projectID,
		DryRun:      config.Bool("FCM_DRY_RUN", a.Cfg.Env == "dev"),
		Timeout:     config.Duration("FCM_TIMEOUT", 10*time.Second),
		Concurrency: config.Int("FCM_CONCURRENCY", 64),
	}, a.Log)
	if err != nil {
		return fmt.Errorf("fcm: %w", err)
	}

	c := &consumer{
		presence:    rdb.PresenceOf(config.Duration("PRESENCE_TTL", 90*time.Second)),
		members:     db.MembersRepo(),
		devices:     db.DevicesRepo(),
		users:       db.UsersRepo(),
		chats:       db.ChatsRepo(),
		fcm:         fcm,
		showPreview: config.Bool("PUSH_SHOW_PREVIEW", false),
	}

	kafkaCfg := kafkax.Config{
		Brokers:  config.Strings("KAFKA_BROKERS", []string{"localhost:9092"}),
		UseOAuth: config.Bool("KAFKA_OAUTH", a.Cfg.Env != "dev"),
		TLS:      config.Bool("KAFKA_TLS", a.Cfg.Env != "dev"),
		ClientID: "pusher",
	}
	dlq, err := kafkax.NewProducer(kafkaCfg, kafkax.DefaultProducerOptions())
	if err != nil {
		return fmt.Errorf("kafka producer: %w", err)
	}
	a.OnShutdown("kafka-producer", dlq.Close)

	kc, err := kafkax.NewConsumer(kafkaCfg, kafkax.ConsumerOptions{
		Topic: events.TopicMessagesPersisted,
		Group: config.String("KAFKA_GROUP", "pusher"),
		// LastOffset: on a brand-new group, replaying the backlog would send
		// a flood of notifications for messages users read hours ago.
		StartOffset:    kafka.LastOffset,
		MaxRetries:     4,
		RetryBase:      200 * time.Millisecond,
		RetryMax:       10 * time.Second,
		CommitInterval: time.Second,
		DLQProducer:    dlq,
	}, a.Log)
	if err != nil {
		return fmt.Errorf("kafka consumer: %w", err)
	}
	a.OnShutdown("kafka-consumer", kc.Close)

	go func() {
		if err := kc.Run(ctx, c.handle); err != nil {
			a.Log.Error("pusher stopped", "error", err)
		}
	}()

	return nil
}

func (c *consumer) handle(ctx context.Context, m kafka.Message) error {
	var evt events.MessageEvent
	if err := json.Unmarshal(m.Value, &evt); err != nil {
		return fmt.Errorf("%w: malformed message event: %v", kafkax.ErrSkip, err)
	}
	if evt.ChatID == 0 || evt.SenderID == 0 {
		return kafkax.ErrSkip
	}

	log := logx.From(ctx).With("chat_id", evt.ChatID, "seq", evt.Seq)

	recipients := evt.Recipients
	if len(recipients) == 0 {
		// A large channel omits the inline roster; read it ourselves.
		var err error
		recipients, err = c.members.IDs(ctx, evt.ChatID)
		if err != nil {
			return fmt.Errorf("member lookup: %w", err)
		}
	}

	// The sender never gets a notification for their own message.
	candidates := make([]int64, 0, len(recipients))
	for _, id := range recipients {
		if id != evt.SenderID {
			candidates = append(candidates, id)
		}
	}
	if len(candidates) == 0 {
		return nil
	}

	// Three filters, cheapest first: presence (one Redis pipeline), then mute
	// (one Postgres query), then device tokens (one Postgres query). Ordering
	// them this way means a message to a group where everyone is online costs
	// exactly one Redis round trip.
	online, err := c.presence.OnlineMany(ctx, candidates)
	if err != nil {
		return fmt.Errorf("presence lookup: %w", err)
	}
	offline := make([]int64, 0, len(candidates))
	for _, id := range candidates {
		if !online[id] {
			offline = append(offline, id)
		}
	}
	if len(offline) == 0 {
		log.Debug("every recipient is online; no push needed")
		return nil
	}

	muted, err := c.members.MutedAmong(ctx, evt.ChatID, offline)
	if err != nil {
		return fmt.Errorf("mute lookup: %w", err)
	}
	notifiable := make([]int64, 0, len(offline))
	for _, id := range offline {
		if !muted[id] {
			notifiable = append(notifiable, id)
		}
	}
	if len(notifiable) == 0 {
		return nil
	}

	targets, err := c.devices.PushTargetsFor(ctx, notifiable)
	if err != nil {
		return fmt.Errorf("device lookup: %w", err)
	}
	if len(targets) == 0 {
		return nil
	}

	title, body := c.renderNotification(ctx, &evt)

	// Collapse by chat: a phone that was off for an hour should show one
	// entry per conversation, not forty.
	collapseKey := "chat:" + strconv.FormatInt(evt.ChatID, 10)
	data := map[string]string{
		"chat_id":    strconv.FormatInt(evt.ChatID, 10),
		"seq":        strconv.FormatInt(evt.Seq, 10),
		"message_id": evt.MessageID,
		"sender_id":  strconv.FormatInt(evt.SenderID, 10),
		"type":       string(evt.Type),
	}

	msgs := make([]push.Message, 0, len(targets))
	deviceIDs := make([]int64, 0, len(targets))
	for _, devices := range targets {
		for _, d := range devices {
			msgs = append(msgs, push.Message{
				Token:       d.Token,
				Platform:    d.Platform,
				Title:       title,
				Body:        body,
				Data:        data,
				CollapseKey: collapseKey,
				// A chat notification is worthless a day later.
				TTL: 24 * time.Hour,
			})
			deviceIDs = append(deviceIDs, d.DeviceID)
		}
	}

	results, err := c.fcm.SendAll(ctx, msgs)
	if err != nil {
		return fmt.Errorf("fcm send: %w", err)
	}

	delivered, dead := 0, 0
	var retryable error
	for i, res := range results {
		switch {
		case res.OK:
			delivered++
		case res.Unregistered:
			dead++
			if err := c.devices.ClearPushToken(ctx, deviceIDs[i]); err != nil {
				log.Warn("could not clear a dead push token", "device_id", deviceIDs[i], "error", err)
			}
		case res.Retryable:
			retryable = fmt.Errorf("fcm transient failure: %s", res.Error)
		default:
			log.Warn("push rejected", "device_id", deviceIDs[i], "error", res.Error)
		}
	}

	telemetry.MessagesDelivered.WithLabelValues("push").Add(float64(delivered))
	log.Debug("push dispatched", "delivered", delivered, "dead_tokens", dead)

	// One transient failure retries the whole record. That re-notifies the
	// devices that already succeeded, which is why FCM collapse keys matter:
	// the duplicate replaces the original rather than stacking.
	return retryable
}

// renderNotification builds the alert text.
func (c *consumer) renderNotification(ctx context.Context, evt *events.MessageEvent) (title, body string) {
	title = "New message"
	body = "You have a new message"

	chat, err := c.chats.Get(ctx, evt.ChatID)
	if err == nil && chat.Title != "" {
		title = chat.Title
	} else if sender, err := c.users.GetByID(ctx, evt.SenderID); err == nil {
		title = sender.DisplayName
	}

	// Never put content in a notification for an encrypted message: the whole
	// point of a secret chat is that the server cannot read it, and the server
	// is what composes this string.
	if evt.Encrypted || !c.showPreview {
		switch evt.Type {
		case events.MessagePhoto:
			body = "📷 Photo"
		case events.MessageVideo:
			body = "🎬 Video"
		case events.MessageVoice:
			body = "🎤 Voice message"
		case events.MessageFile:
			body = "📎 File"
		case events.MessageSticker:
			body = "Sticker"
		}
		return title, body
	}

	switch evt.Type {
	case events.MessageText:
		body = truncateRunes(evt.Body, 120)
	case events.MessagePhoto:
		body = "📷 Photo"
	case events.MessageVideo:
		body = "🎬 Video"
	case events.MessageVoice:
		body = "🎤 Voice message"
	case events.MessageFile:
		body = "📎 File"
	case events.MessageSticker:
		body = "Sticker"
	}
	return title, body
}

func truncateRunes(s string, n int) string {
	s = strings.TrimSpace(s)
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}
