package kafkax

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"time"

	"github.com/pervagans/messaging-app/pkg/events"
	"github.com/pervagans/messaging-app/pkg/logx"
	"github.com/pervagans/messaging-app/pkg/telemetry"
	"github.com/segmentio/kafka-go"
)

// HandlerFunc processes one record. Returning nil commits the offset.
//
// The contract is at-least-once: a handler may see the same record twice
// after a rebalance or a crash between the work and the commit, so every
// handler in this repo is written to be idempotent.
type HandlerFunc func(ctx context.Context, m kafka.Message) error

// ErrSkip tells the consumer to commit the offset without treating the record
// as processed — used for records this build does not understand yet.
var ErrSkip = errors.New("kafkax: skip record")

// ConsumerOptions configures one consumer group member.
type ConsumerOptions struct {
	Topic string
	Group string

	// MinBytes/MaxBytes shape the fetch. Small MinBytes keeps latency low for
	// the message pipeline; a batch consumer such as the indexer can raise it.
	MinBytes int
	MaxBytes int
	MaxWait  time.Duration

	// StartOffset applies only the first time a group ever reads a partition.
	// FirstOffset (earliest) is right for the persister: on a brand-new group
	// we want the whole retained backlog. LastOffset (latest) is right for
	// presence, where stale events are worse than missing ones.
	StartOffset int64

	// MaxRetries is the number of in-process retries before a record goes to
	// the DLQ. Retrying in place preserves partition order, which matters
	// because messages of one chat must not be reordered by a transient
	// Cassandra timeout.
	MaxRetries int
	RetryBase  time.Duration
	RetryMax   time.Duration

	// CommitInterval of 0 means synchronous commit after each handled record.
	// That is the safe default; consumers that can tolerate replay set a
	// non-zero interval to cut commit traffic.
	CommitInterval time.Duration

	// DLQProducer, when set, receives records that exhausted their retries.
	// Without it a poisoned record blocks the partition forever.
	DLQProducer *Producer
}

// Consumer is a single-topic consumer-group member.
type Consumer struct {
	r    *kafka.Reader
	o    ConsumerOptions
	log  *slog.Logger
	stop chan struct{}
}

// NewConsumer builds a consumer-group reader.
func NewConsumer(cfg Config, o ConsumerOptions, log *slog.Logger) (*Consumer, error) {
	if o.Topic == "" || o.Group == "" {
		return nil, errors.New("kafkax: topic and group are required")
	}
	d, err := cfg.dialer()
	if err != nil {
		return nil, err
	}

	r := kafka.NewReader(kafka.ReaderConfig{
		Brokers:  cfg.Brokers,
		Topic:    o.Topic,
		GroupID:  o.Group,
		Dialer:   d,
		MinBytes: orDefault(o.MinBytes, 1),
		MaxBytes: orDefault(o.MaxBytes, 10<<20),
		MaxWait:  orDefault(o.MaxWait, 250*time.Millisecond),

		StartOffset:    orDefault(o.StartOffset, kafka.FirstOffset),
		CommitInterval: o.CommitInterval,

		// A rebalance stalls every partition in the group, so we prefer a
		// slightly slow failure detection over flapping: 30s session timeout
		// with 3s heartbeats tolerates a GC pause or a node hiccup.
		SessionTimeout:    30 * time.Second,
		HeartbeatInterval: 3 * time.Second,
		RebalanceTimeout:  45 * time.Second,
		// Cooperative sticky assignment would be better still; kafka-go only
		// offers eager strategies, so we pick RangeGroupBalancer for stable
		// partition-to-pod affinity across restarts.
		GroupBalancers: []kafka.GroupBalancer{kafka.RangeGroupBalancer{}},

		ErrorLogger: kafka.LoggerFunc(func(msg string, args ...any) {
			log.Error("kafka reader", "detail", fmt.Sprintf(msg, args...))
		}),
	})

	return &Consumer{
		r:    r,
		o:    o,
		log:  log.With("topic", o.Topic, "group", o.Group),
		stop: make(chan struct{}),
	}, nil
}

// Run consumes until ctx is cancelled. It returns nil on a clean shutdown.
func (c *Consumer) Run(ctx context.Context, h HandlerFunc) error {
	c.log.Info("consumer started")
	defer c.log.Info("consumer stopped")

	for {
		m, err := c.r.FetchMessage(ctx)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, io.EOF) {
				return nil
			}
			// FetchMessage errors are almost always transient (rebalance,
			// broker restart). Back off briefly rather than crash-looping.
			c.log.Warn("fetch failed", "error", err)
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(500 * time.Millisecond):
			}
			continue
		}

		telemetry.KafkaLagSeconds.WithLabelValues(c.o.Topic, c.o.Group).
			Observe(time.Since(m.Time).Seconds())

		if err := c.handleWithRetry(ctx, m, h); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			// handleWithRetry only returns an error when the DLQ path also
			// failed. Committing here would lose the record, so we stop and
			// let the pod restart; Kubernetes backoff becomes our circuit
			// breaker and the alert on consumer lag fires.
			return fmt.Errorf("kafkax: unrecoverable on %s[%d]@%d: %w",
				m.Topic, m.Partition, m.Offset, err)
		}

		if err := c.r.CommitMessages(ctx, m); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			c.log.Error("commit failed", "partition", m.Partition, "offset", m.Offset, "error", err)
		}
	}
}

func (c *Consumer) handleWithRetry(ctx context.Context, m kafka.Message, h HandlerFunc) error {
	maxRetries := c.o.MaxRetries
	if maxRetries <= 0 {
		maxRetries = 5
	}
	base := orDefault(c.o.RetryBase, 100*time.Millisecond)
	max := orDefault(c.o.RetryMax, 10*time.Second)

	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		log := c.log.With("partition", m.Partition, "offset", m.Offset, "attempt", attempt)
		err := h(logx.Into(ctx, log), m)

		switch {
		case err == nil:
			telemetry.KafkaConsumed.WithLabelValues(c.o.Topic, c.o.Group, "ok").Inc()
			return nil
		case errors.Is(err, ErrSkip):
			telemetry.KafkaConsumed.WithLabelValues(c.o.Topic, c.o.Group, "skipped").Inc()
			log.Info("record skipped", "reason", err)
			return nil
		case ctx.Err() != nil:
			return ctx.Err()
		}

		lastErr = err
		log.Warn("handler failed", "error", err)

		if attempt == maxRetries {
			break
		}
		delay := base << attempt
		if delay > max {
			delay = max
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
	}

	telemetry.KafkaConsumed.WithLabelValues(c.o.Topic, c.o.Group, "dlq").Inc()
	return c.toDLQ(ctx, m, lastErr, maxRetries+1)
}

// buildDeadLetter assembles the DLQ record.
//
// Separate from the publish so its one piece of judgement can be tested
// without a broker: a record that failed *because* it was malformed would
// otherwise be embedded raw and make the dead letter itself unparseable —
// turning one poisoned record into a poisoned DLQ that no tooling can read.
func buildDeadLetter(m kafka.Message, group string, cause error, attempts int) events.DeadLetter {
	dl := events.DeadLetter{
		V:           events.CurrentVersion,
		SourceTopic: m.Topic,
		Group:       group,
		Partition:   m.Partition,
		Offset:      m.Offset,
		Key:         string(m.Key),
		Payload:     json.RawMessage(m.Value),
		Error:       cause.Error(),
		Attempts:    attempts,
		FailedAt:    time.Now().UTC(),
	}
	// If the payload was not valid JSON, wrap it as a JSON string so the DLQ
	// record stays parseable. Empty counts as invalid: json.RawMessage(nil)
	// marshals to nothing at all and would produce a syntactically broken
	// document.
	if !json.Valid(dl.Payload) {
		raw, err := json.Marshal(string(m.Value))
		if err != nil {
			// Cannot happen for a string, but a silent empty payload here
			// would lose the evidence the DLQ exists to preserve.
			raw = []byte(`"<payload could not be encoded>"`)
		}
		dl.Payload = raw
	}
	return dl
}

func (c *Consumer) toDLQ(ctx context.Context, m kafka.Message, cause error, attempts int) error {
	if c.o.DLQProducer == nil {
		return fmt.Errorf("no DLQ configured: %w", cause)
	}
	body, err := json.Marshal(buildDeadLetter(m, c.o.Group, cause, attempts))
	if err != nil {
		return fmt.Errorf("marshal dead letter: %w (original: %v)", err, cause)
	}

	// Use a fresh context: the parent may already be cancelled by shutdown and
	// the DLQ write is exactly the work we must not lose.
	writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	defer cancel()

	if err := c.o.DLQProducer.Publish(writeCtx, events.TopicDeadLetter, m.Key, body,
		kafka.Header{Key: "source-topic", Value: []byte(m.Topic)},
		kafka.Header{Key: "source-group", Value: []byte(c.o.Group)},
		kafka.Header{Key: "source-offset", Value: []byte(strconv.FormatInt(m.Offset, 10))},
	); err != nil {
		return fmt.Errorf("publish dead letter: %w (original: %v)", err, cause)
	}

	c.log.Error("record sent to DLQ",
		"partition", m.Partition, "offset", m.Offset, "error", cause)
	return nil
}

// Lag reports the reader's current lag, exported for readiness and alerting.
func (c *Consumer) Lag() int64 { return c.r.Lag() }

// Close stops the reader and leaves the consumer group cleanly, which
// triggers an immediate rebalance instead of waiting for the session timeout.
func (c *Consumer) Close(context.Context) error { return c.r.Close() }

// Header returns the value of a record header, or "".
func Header(m kafka.Message, key string) string {
	for _, h := range m.Headers {
		if h.Key == key {
			return string(h.Value)
		}
	}
	return ""
}
