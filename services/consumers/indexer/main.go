// Command indexer maintains the Elasticsearch index behind message search.
//
// Search is the one component with no GCP-managed equivalent, so it runs
// either on Elastic Cloud (marketplace) or self-hosted on GKE. Either way this
// consumer is the only writer, which keeps the index's schema and its ACL
// model in one place.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/pervagans/messaging-app/pkg/app"
	"github.com/pervagans/messaging-app/pkg/config"
	"github.com/pervagans/messaging-app/pkg/events"
	"github.com/pervagans/messaging-app/pkg/kafkax"
	"github.com/pervagans/messaging-app/pkg/logx"
	"github.com/segmentio/kafka-go"
)

func main() {
	app.Run("indexer", run)
}

type consumer struct {
	es        *elasticsearch.Client
	indexName string

	// Batching: Elasticsearch is far happier with one bulk request of 500
	// documents than with 500 individual index calls. The flush timer bounds
	// how stale search can be — a few seconds, which is fine for search and
	// would not be for message delivery.
	mu         sync.Mutex
	pending    []events.SearchDoc
	batchMax   int
	flushEvery time.Duration
}

func run(ctx context.Context, a *app.App) error {
	addrs := config.Strings("ELASTICSEARCH_ADDRS", []string{"http://localhost:9200"})

	esCfg := elasticsearch.Config{
		Addresses:     addrs,
		Username:      config.String("ELASTICSEARCH_USERNAME", ""),
		Password:      config.Secret("ELASTICSEARCH_PASSWORD", ""),
		APIKey:        config.String("ELASTICSEARCH_API_KEY", ""),
		CloudID:       config.String("ELASTICSEARCH_CLOUD_ID", ""),
		RetryOnStatus: []int{502, 503, 504, 429},
		MaxRetries:    3,
		RetryBackoff: func(attempt int) time.Duration {
			return time.Duration(attempt) * 200 * time.Millisecond
		},
	}
	es, err := elasticsearch.NewClient(esCfg)
	if err != nil {
		return fmt.Errorf("elasticsearch: %w", err)
	}

	c := &consumer{
		es:         es,
		indexName:  config.String("ELASTICSEARCH_INDEX", "messages"),
		batchMax:   config.Int("INDEX_BATCH_SIZE", 500),
		flushEvery: config.Duration("INDEX_FLUSH_INTERVAL", 2*time.Second),
	}

	if err := c.ping(ctx); err != nil {
		return err
	}
	a.Health.Register("elasticsearch", c.ping)

	if err := c.ensureIndex(ctx); err != nil {
		return fmt.Errorf("create index: %w", err)
	}

	kafkaCfg := kafkax.Config{
		Brokers:  config.Strings("KAFKA_BROKERS", []string{"localhost:9092"}),
		UseOAuth: config.Bool("KAFKA_OAUTH", a.Cfg.Env != "dev"),
		TLS:      config.Bool("KAFKA_TLS", a.Cfg.Env != "dev"),
		ClientID: "indexer",
	}
	dlq, err := kafkax.NewProducer(kafkaCfg, kafkax.DefaultProducerOptions())
	if err != nil {
		return fmt.Errorf("kafka producer: %w", err)
	}
	a.OnShutdown("kafka-producer", dlq.Close)

	kc, err := kafkax.NewConsumer(kafkaCfg, kafkax.ConsumerOptions{
		Topic: events.TopicSearchIndex,
		Group: config.String("KAFKA_GROUP", "indexer"),
		// FirstOffset: rebuilding the index from the retained backlog is a
		// supported operation — reset the group's offsets and let it run.
		StartOffset: kafka.FirstOffset,
		// Larger fetches: this consumer trades latency for throughput.
		MinBytes:       64 << 10,
		MaxBytes:       20 << 20,
		MaxWait:        time.Second,
		MaxRetries:     4,
		CommitInterval: 2 * time.Second,
		DLQProducer:    dlq,
	}, a.Log)
	if err != nil {
		return fmt.Errorf("kafka consumer: %w", err)
	}
	a.OnShutdown("kafka-consumer", kc.Close)

	// Flush on shutdown so a rolling update does not drop the current batch.
	a.OnShutdown("index-flush", func(ctx context.Context) error { return c.flush(ctx) })

	go c.flushLoop(ctx, a)
	go func() {
		if err := kc.Run(ctx, c.handle); err != nil {
			a.Log.Error("indexer stopped", "error", err)
		}
	}()

	return nil
}

func (c *consumer) handle(ctx context.Context, m kafka.Message) error {
	var doc events.SearchDoc
	if err := json.Unmarshal(m.Value, &doc); err != nil {
		return fmt.Errorf("%w: malformed search document: %v", kafkax.ErrSkip, err)
	}
	if doc.DocID == "" {
		return kafkax.ErrSkip
	}

	c.mu.Lock()
	c.pending = append(c.pending, doc)
	full := len(c.pending) >= c.batchMax
	c.mu.Unlock()

	if full {
		return c.flush(ctx)
	}
	return nil
}

func (c *consumer) flushLoop(ctx context.Context, a *app.App) {
	t := time.NewTicker(c.flushEvery)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := c.flush(ctx); err != nil {
				a.Log.Error("index flush failed", "error", err)
			}
		}
	}
}

// flush writes the pending batch as one bulk request.
func (c *consumer) flush(ctx context.Context) error {
	c.mu.Lock()
	if len(c.pending) == 0 {
		c.mu.Unlock()
		return nil
	}
	batch := c.pending
	c.pending = nil
	c.mu.Unlock()

	var buf bytes.Buffer
	for _, doc := range batch {
		action := map[string]map[string]string{
			"index": {"_index": c.indexName, "_id": doc.DocID},
		}
		if doc.Op == "delete" {
			action = map[string]map[string]string{
				"delete": {"_index": c.indexName, "_id": doc.DocID},
			}
		}
		meta, err := json.Marshal(action)
		if err != nil {
			continue
		}
		buf.Write(meta)
		buf.WriteByte('\n')

		if doc.Op == "delete" {
			continue
		}
		body, err := json.Marshal(map[string]any{
			"chat_id": doc.ChatID,
			// members is the ACL: every search query filters on it, so a user
			// can only ever match messages from chats they are in. Storing it
			// on the document rather than checking membership at query time
			// keeps search a single Elasticsearch round trip.
			"members":    doc.Members,
			"body":       doc.Body,
			"sender_id":  doc.SenderID,
			"seq":        doc.Seq,
			"created_at": doc.CreatedAt,
		})
		if err != nil {
			continue
		}
		buf.Write(body)
		buf.WriteByte('\n')
	}

	if buf.Len() == 0 {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()

	resp, err := c.es.Bulk(bytes.NewReader(buf.Bytes()),
		c.es.Bulk.WithContext(ctx),
		c.es.Bulk.WithIndex(c.indexName))
	if err != nil {
		// Put the batch back so the next flush retries it. Dropping it would
		// silently lose search coverage for those messages.
		c.requeue(batch)
		return fmt.Errorf("bulk index: %w", err)
	}
	defer resp.Body.Close()

	if resp.IsError() {
		detail, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		c.requeue(batch)
		return fmt.Errorf("bulk index returned %s: %s", resp.Status(), strings.TrimSpace(string(detail)))
	}
	_, _ = io.Copy(io.Discard, resp.Body)

	logx.From(ctx).Debug("indexed batch", "documents", len(batch))
	return nil
}

// requeue puts a failed batch back at the front, bounded so a persistent
// Elasticsearch outage cannot grow the buffer without limit.
func (c *consumer) requeue(batch []events.SearchDoc) {
	const maxBuffered = 50_000

	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.pending)+len(batch) > maxBuffered {
		// Drop the oldest: search being incomplete for a window is
		// recoverable by reindexing from Kafka; running the pod out of memory
		// is not.
		return
	}
	c.pending = append(batch, c.pending...)
}

func (c *consumer) ping(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	resp, err := c.es.Ping(c.es.Ping.WithContext(ctx))
	if err != nil {
		return fmt.Errorf("elasticsearch ping: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.IsError() {
		return fmt.Errorf("elasticsearch ping returned %s", resp.Status())
	}
	return nil
}

// ensureIndex creates the index with an explicit mapping.
//
// Dynamic mapping would be a trap here: the first message containing a
// numeric-looking string would type the body field as a long and every text
// search afterwards would fail.
func (c *consumer) ensureIndex(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	exists, err := c.es.Indices.Exists([]string{c.indexName}, c.es.Indices.Exists.WithContext(ctx))
	if err != nil {
		return err
	}
	defer exists.Body.Close()
	if exists.StatusCode == 200 {
		return nil
	}

	mapping := map[string]any{
		"settings": map[string]any{
			"number_of_shards":   config.Int("INDEX_SHARDS", 3),
			"number_of_replicas": config.Int("INDEX_REPLICAS", 1),
			// Search does not need to be real-time; a one-second refresh is
			// the difference between a comfortable index rate and a struggling
			// cluster.
			"refresh_interval": "1s",
			"analysis": map[string]any{
				"analyzer": map[string]any{
					"message_text": map[string]any{
						"type":      "standard",
						"stopwords": "_none_",
					},
				},
			},
		},
		"mappings": map[string]any{
			"properties": map[string]any{
				"chat_id":    map[string]string{"type": "long"},
				"members":    map[string]string{"type": "long"},
				"body":       map[string]any{"type": "text", "analyzer": "message_text"},
				"sender_id":  map[string]string{"type": "long"},
				"seq":        map[string]string{"type": "long"},
				"created_at": map[string]string{"type": "date"},
			},
		},
	}
	body, err := json.Marshal(mapping)
	if err != nil {
		return err
	}

	resp, err := c.es.Indices.Create(c.indexName,
		c.es.Indices.Create.WithBody(bytes.NewReader(body)),
		c.es.Indices.Create.WithContext(ctx))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.IsError() {
		detail, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<10))
		// A concurrent indexer pod may have won the race; that is fine.
		if strings.Contains(string(detail), "resource_already_exists_exception") {
			return nil
		}
		return fmt.Errorf("create index %s: %s: %s", c.indexName, resp.Status(), detail)
	}
	return nil
}
