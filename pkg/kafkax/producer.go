// Package kafkax wraps segmentio/kafka-go with the settings this platform
// needs against Google Cloud Managed Service for Apache Kafka.
//
// Two Managed Kafka specifics shape this code:
//
//  1. The cluster has no public endpoint. Clients must sit in the same VPC or
//     reach it through Private Service Connect, so there is no fallback path
//     and a dial failure is always a network/IAM problem, never a routing one.
//  2. Authentication is SASL/OAUTHBEARER backed by the workload's Google
//     service account token, obtained through Workload Identity. There are no
//     static credentials to rotate.
package kafkax

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"time"

	"github.com/pervagans/messaging-app/pkg/telemetry"
	"github.com/segmentio/kafka-go"
)

// Config describes how to reach the cluster.
type Config struct {
	// Brokers is the bootstrap server list. For Managed Kafka this is the
	// cluster's private bootstrap address, e.g.
	// bootstrap.<cluster>.<region>.managedkafka.<project>.cloud.goog:9092
	Brokers []string
	// UseOAuth enables SASL/OAUTHBEARER with Application Default Credentials.
	// Disabled for the local docker-compose broker.
	UseOAuth bool
	// TLS enables transport encryption. Always on for Managed Kafka.
	TLS bool
	// ClientID identifies this workload in broker-side metrics.
	ClientID string
	// DialTimeout bounds connection establishment.
	DialTimeout time.Duration
}

func (c Config) transport() (*kafka.Transport, error) {
	t := &kafka.Transport{
		ClientID:    c.ClientID,
		DialTimeout: orDefault(c.DialTimeout, 10*time.Second),
		IdleTimeout: 9 * time.Minute,
		MetadataTTL: 30 * time.Second,
	}
	if c.TLS {
		t.TLS = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	if c.UseOAuth {
		m, err := newGoogleOAuthMechanism(context.Background())
		if err != nil {
			return nil, err
		}
		t.SASL = m
	}
	return t, nil
}

func (c Config) dialer() (*kafka.Dialer, error) {
	d := &kafka.Dialer{
		ClientID:  c.ClientID,
		Timeout:   orDefault(c.DialTimeout, 10*time.Second),
		DualStack: true,
	}
	if c.TLS {
		d.TLS = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	if c.UseOAuth {
		m, err := newGoogleOAuthMechanism(context.Background())
		if err != nil {
			return nil, err
		}
		d.SASLMechanism = m
	}
	return d, nil
}

func orDefault[T comparable](v, def T) T {
	var zero T
	if v == zero {
		return def
	}
	return v
}

// Producer publishes records with the durability guarantees a chat backlog
// needs.
type Producer struct {
	w   *kafka.Writer
	cfg Config
}

// ProducerOptions tunes batching versus latency.
type ProducerOptions struct {
	// BatchTimeout is how long the writer waits to fill a batch. 5ms keeps
	// send-to-fanout latency low while still amortising network round trips;
	// the default of 1s would be catastrophic for an interactive chat.
	BatchTimeout time.Duration
	BatchSize    int
	BatchBytes   int64
	// Async trades delivery confirmation for throughput. Never enable it for
	// messages.raw — an accepted message that silently fails to reach Kafka
	// is a message the user believes was sent and that nobody will receive.
	Async bool
	// Compression: lz4 is the sweet spot for chat payloads; zstd costs more
	// CPU than the bandwidth it saves on sub-kilobyte records.
	Compression kafka.Compression
	// RequiredAcks: RequireAll means the leader plus all in-sync replicas.
	// Anything less can lose the tail of a partition on a broker failover.
	RequiredAcks kafka.RequiredAcks
	MaxAttempts  int
}

// DefaultProducerOptions returns the settings used for message traffic.
func DefaultProducerOptions() ProducerOptions {
	return ProducerOptions{
		BatchTimeout: 5 * time.Millisecond,
		BatchSize:    200,
		BatchBytes:   1 << 20,
		Async:        false,
		Compression:  kafka.Lz4,
		RequiredAcks: kafka.RequireAll,
		MaxAttempts:  8,
	}
}

// NewProducer builds a writer. The topic is chosen per message, so one
// producer serves every topic a service publishes to.
func NewProducer(cfg Config, o ProducerOptions) (*Producer, error) {
	if len(cfg.Brokers) == 0 {
		return nil, errors.New("kafkax: no brokers configured")
	}
	tr, err := cfg.transport()
	if err != nil {
		return nil, err
	}
	w := &kafka.Writer{
		Addr:      kafka.TCP(cfg.Brokers...),
		Balancer:  &kafka.Hash{}, // key-based partitioning: same chat -> same partition -> ordered
		Transport: tr,

		BatchTimeout: o.BatchTimeout,
		BatchSize:    o.BatchSize,
		BatchBytes:   o.BatchBytes,
		Async:        o.Async,
		Compression:  o.Compression,
		RequiredAcks: o.RequiredAcks,
		MaxAttempts:  o.MaxAttempts,
		// The topics are created by Terraform with explicit partition counts
		// and retention; auto-creation would silently produce a 1-partition
		// topic with default retention and cap throughput forever.
		AllowAutoTopicCreation: false,
		WriteTimeout:           10 * time.Second,
		ReadTimeout:            10 * time.Second,
	}
	return &Producer{w: w, cfg: cfg}, nil
}

// Publish writes one record and blocks until the brokers acknowledge it.
func (p *Producer) Publish(ctx context.Context, topic string, key []byte, value []byte, headers ...kafka.Header) error {
	msg := kafka.Message{
		Topic:   topic,
		Key:     key,
		Value:   value,
		Headers: headers,
		Time:    time.Now(),
	}
	if err := p.w.WriteMessages(ctx, msg); err != nil {
		telemetry.KafkaPublished.WithLabelValues(topic, "error").Inc()
		return fmt.Errorf("kafkax: publish to %s: %w", topic, err)
	}
	telemetry.KafkaPublished.WithLabelValues(topic, "ok").Inc()
	return nil
}

// PublishBatch writes several records in one round trip. All must succeed or
// the call returns an error; kafka-go retries internally up to MaxAttempts.
func (p *Producer) PublishBatch(ctx context.Context, msgs []kafka.Message) error {
	if len(msgs) == 0 {
		return nil
	}
	if err := p.w.WriteMessages(ctx, msgs...); err != nil {
		for _, m := range msgs {
			telemetry.KafkaPublished.WithLabelValues(m.Topic, "error").Inc()
		}
		return fmt.Errorf("kafkax: publish batch: %w", err)
	}
	for _, m := range msgs {
		telemetry.KafkaPublished.WithLabelValues(m.Topic, "ok").Inc()
	}
	return nil
}

// Stats exposes writer counters for debugging.
func (p *Producer) Stats() kafka.WriterStats { return p.w.Stats() }

// Ping verifies the cluster is reachable; used as a readiness check.
func (p *Producer) Ping(ctx context.Context) error {
	d, err := p.cfg.dialer()
	if err != nil {
		return err
	}
	conn, err := d.DialContext(ctx, "tcp", p.cfg.Brokers[0])
	if err != nil {
		return fmt.Errorf("kafkax: dial %s: %w", p.cfg.Brokers[0], err)
	}
	defer conn.Close()
	if _, err := conn.Brokers(); err != nil {
		return fmt.Errorf("kafkax: metadata: %w", err)
	}
	return nil
}

// Close flushes buffered records. Call it during shutdown before the process
// exits, or an async batch still in memory is lost.
func (p *Producer) Close(context.Context) error { return p.w.Close() }
