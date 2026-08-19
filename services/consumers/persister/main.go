// Command persister writes accepted messages to Cassandra.
//
// It is the step that turns "Kafka has it" into "the history has it". The chat
// service returns a sequence number as soon as Kafka acknowledges the record;
// this consumer then commits it to Cassandra, mirrors the chat's high-water
// mark into Postgres and re-publishes on messages.persisted, which is what the
// push and search consumers key off.
//
// Nothing downstream reads messages.raw except this consumer. That is
// deliberate: notifying a user about a message that a later failure would lose
// is worse than notifying them a few milliseconds later.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/pervagans/messaging-app/pkg/app"
	"github.com/pervagans/messaging-app/pkg/cassandrax"
	"github.com/pervagans/messaging-app/pkg/config"
	"github.com/pervagans/messaging-app/pkg/events"
	"github.com/pervagans/messaging-app/pkg/kafkax"
	"github.com/pervagans/messaging-app/pkg/logx"
	"github.com/pervagans/messaging-app/pkg/pgstore"
	"github.com/pervagans/messaging-app/pkg/telemetry"
	"github.com/segmentio/kafka-go"
)

func main() {
	app.Run("persister", run)
}

type consumer struct {
	messages  *cassandrax.MessageRepo
	mediaACL  *cassandrax.MediaACL
	sequences *pgstore.Sequences
	producer  *kafkax.Producer
}

func run(ctx context.Context, a *app.App) error {
	cassCfg := cassandrax.DefaultConfig()
	cassCfg.Hosts = config.Strings("CASSANDRA_HOSTS", []string{"localhost:9042"})
	cassCfg.Keyspace = config.String("CASSANDRA_KEYSPACE", "messaging")
	cassCfg.Username = config.String("CASSANDRA_USERNAME", "")
	cassCfg.Password = config.Secret("CASSANDRA_PASSWORD", "")
	cassCfg.LocalDC = config.String("CASSANDRA_LOCAL_DC", a.Cfg.Region)

	cass, err := cassandrax.Connect(ctx, cassCfg)
	if err != nil {
		return fmt.Errorf("cassandra: %w", err)
	}
	a.OnShutdown("cassandra", cass.Close)
	a.Health.Register("cassandra", cass.Ping)

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

	kafkaCfg := kafkax.Config{
		Brokers:  config.Strings("KAFKA_BROKERS", []string{"localhost:9092"}),
		UseOAuth: config.Bool("KAFKA_OAUTH", a.Cfg.Env != "dev"),
		TLS:      config.Bool("KAFKA_TLS", a.Cfg.Env != "dev"),
		ClientID: "persister",
	}
	producer, err := kafkax.NewProducer(kafkaCfg, kafkax.DefaultProducerOptions())
	if err != nil {
		return fmt.Errorf("kafka producer: %w", err)
	}
	a.OnShutdown("kafka-producer", producer.Close)

	c := &consumer{
		messages:  cass.Messages(),
		mediaACL:  cass.Media(),
		sequences: db.SequencesRepo(),
		producer:  producer,
	}

	kc, err := kafkax.NewConsumer(kafkaCfg, kafkax.ConsumerOptions{
		Topic: events.TopicMessagesRaw,
		Group: config.String("KAFKA_GROUP", "persister"),
		// FirstOffset: a brand-new group must read the whole retained backlog,
		// because anything it skips is a message that never reaches history.
		StartOffset: kafka.FirstOffset,
		MinBytes:    1,
		MaxBytes:    10 << 20,
		MaxWait:     100 * time.Millisecond,
		MaxRetries:  6,
		RetryBase:   100 * time.Millisecond,
		RetryMax:    5 * time.Second,
		// Synchronous commits. The cost is a commit round trip per message;
		// the benefit is that a pod killed mid-batch replays at most one
		// record instead of a whole interval's worth.
		CommitInterval: 0,
		DLQProducer:    producer,
	}, a.Log)
	if err != nil {
		return fmt.Errorf("kafka consumer: %w", err)
	}
	a.OnShutdown("kafka-consumer", kc.Close)

	go func() {
		if err := kc.Run(ctx, c.handle); err != nil {
			a.Log.Error("persister stopped", "error", err)
		}
	}()

	// Consumer lag is the signal that matters here: if this falls behind,
	// history is behind, and every "message not found" report traces back to
	// it. Surfacing it through readiness would be wrong (a lagging consumer is
	// still working), so it is a metric and an alert instead.
	a.Health.Register("kafka", func(context.Context) error {
		if lag := kc.Lag(); lag > int64(config.Int("MAX_LAG", 100_000)) {
			return fmt.Errorf("consumer lag is %d", lag)
		}
		return nil
	})

	return nil
}

// handle persists one message.
//
// Every write is idempotent, because the consumer is at-least-once: a pod
// killed between the Cassandra write and the offset commit will see the same
// record again. Inserting the same row twice with the same values is a no-op
// in Cassandra, and the sequence mirror uses GREATEST, so a replay changes
// nothing.
func (c *consumer) handle(ctx context.Context, m kafka.Message) error {
	var evt events.MessageEvent
	if err := json.Unmarshal(m.Value, &evt); err != nil {
		// Malformed input will never succeed; retrying blocks the partition
		// and blocks every chat whose messages land on it.
		return fmt.Errorf("%w: malformed message event: %v", kafkax.ErrSkip, err)
	}
	if err := evt.Validate(); err != nil {
		return fmt.Errorf("%w: invalid message event: %v", kafkax.ErrSkip, err)
	}

	log := logx.From(ctx).With("chat_id", evt.ChatID, "seq", evt.Seq, "message_id", evt.MessageID)

	mediaJSON := "{}"
	if evt.Media != nil {
		blob, err := json.Marshal(evt.Media)
		if err != nil {
			return fmt.Errorf("%w: unencodable media reference: %v", kafkax.ErrSkip, err)
		}
		mediaJSON = string(blob)
	}

	if err := c.messages.Insert(ctx, &evt, mediaJSON); err != nil {
		return fmt.Errorf("persist message: %w", err)
	}
	// Record that this bucket exists so the sequence allocator can find the
	// newest partition after a cache loss without scanning.
	if err := c.messages.TouchBucket(ctx, evt.ChatID, evt.Seq); err != nil {
		return fmt.Errorf("record bucket: %w", err)
	}

	// Mirror the high-water mark into Postgres so the chat list — the first
	// screen every client loads — is one query rather than one Cassandra read
	// per chat.
	if err := c.sequences.Advance(ctx, evt.ChatID, evt.Seq); err != nil {
		return fmt.Errorf("advance chat sequence: %w", err)
	}

	// Bind any attached media to this chat, so downloading it requires
	// membership. This happens here, after durability, rather than at send
	// time: an accepted-then-lost message must not leave an object readable
	// by a chat that never received it.
	if evt.Media != nil && evt.Media.Object != "" {
		if err := c.mediaACL.Bind(ctx, evt.Media.Object, evt.ChatID, evt.MessageID, evt.SenderID); err != nil {
			return fmt.Errorf("bind media acl: %w", err)
		}
	}

	// Re-publish now that the message is durable. Push and search hang off
	// this topic, not off messages.raw.
	if err := c.producer.Publish(ctx, events.TopicMessagesPersisted, m.Key, m.Value); err != nil {
		return fmt.Errorf("publish persisted event: %w", err)
	}

	// Queue the search document. A failure here is not worth failing the
	// message over: search being stale is a degraded feature, losing the
	// message would be data loss, and this point is past durability.
	if err := c.indexDoc(ctx, &evt); err != nil {
		log.Warn("search indexing not queued", "error", err)
	}

	telemetry.MessagesDelivered.WithLabelValues("persisted").Inc()
	log.Debug("message persisted")
	return nil
}

func (c *consumer) indexDoc(ctx context.Context, evt *events.MessageEvent) error {
	// Encrypted bodies are opaque to the server, so there is nothing to
	// index — and attempting to would write ciphertext into a search index.
	if evt.Encrypted || evt.Body == "" {
		return nil
	}

	doc := events.SearchDoc{
		V:         events.CurrentVersion,
		Index:     "messages",
		DocID:     evt.MessageID,
		Op:        "upsert",
		ChatID:    evt.ChatID,
		Members:   evt.Recipients,
		Body:      evt.Body,
		SenderID:  evt.SenderID,
		Seq:       evt.Seq,
		CreatedAt: evt.CreatedAt,
	}
	body, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	return c.producer.Publish(ctx, events.TopicSearchIndex, []byte(evt.MessageID), body)
}
