// Command auditor verifies and archives the administrative audit trail.
//
// Without this, the hash chain in pkg/auditlog is decorative: a chain nobody
// checks proves nothing. This consumer is what turns it into a control.
//
// It does two things:
//
//  1. Verifies each writer's chain as records arrive. A break — an altered
//     entry, a removed one, a sequence gap — raises a metric that alerts, and
//     is logged with enough detail to say which entry and which writer.
//  2. Archives every entry to Cloud Storage, in a bucket with a retention
//     lock. Kafka's year of retention is long, but it is still a mutable
//     store that an administrator can shorten. A retention-locked object
//     cannot be deleted before its lock expires, by anyone, including the
//     project owner. That is the property that makes the archive worth having.
//
// The archive is what closes the hash chain's one real gap. Cutting entries
// off the *end* of a chain leaves the remainder verifying perfectly, so
// truncation is invisible to Verify alone — but not to an archive that already
// holds them.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/pervagans/messaging-app/pkg/app"
	"github.com/pervagans/messaging-app/pkg/auditlog"
	"github.com/pervagans/messaging-app/pkg/config"
	"github.com/pervagans/messaging-app/pkg/gcsx"
	"github.com/pervagans/messaging-app/pkg/kafkax"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/segmentio/kafka-go"
)

func main() {
	app.Run("auditor", run)
}

var (
	entriesSeen = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "messaging",
		Name:      "audit_entries_total",
		Help:      "Audit entries consumed, by action.",
	}, []string{"action"})

	// The alert. Any non-zero value here means the audit trail is no longer
	// trustworthy, which is a security incident rather than an availability
	// one — it must page, not sit in a dashboard.
	chainBreaks = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "messaging",
		Name:      "audit_chain_breaks_total",
		Help:      "Audit chain verification failures, by writer and kind.",
	}, []string{"writer", "kind"})

	archiveFailures = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "messaging",
		Name:      "audit_archive_failures_total",
		Help:      "Failed writes of an audit batch to the archive bucket.",
	})
)

type auditor struct {
	gcs    *gcsx.Client
	bucket string

	mu sync.Mutex
	// Per writer, the last entry seen. Verification is incremental: each new
	// entry is checked against its predecessor rather than re-reading the
	// whole chain, which would grow unboundedly slower.
	last map[string]auditlog.Entry
	// pending accumulates entries for the archive. Buffered because one
	// object per entry would make a bucket with millions of tiny objects and
	// a listing cost to match.
	pending    []auditlog.Entry
	batchMax   int
	flushEvery time.Duration
}

func run(ctx context.Context, a *app.App) error {
	gcs, err := gcsx.Connect(ctx, gcsx.DefaultConfig())
	if err != nil {
		return fmt.Errorf("gcs: %w", err)
	}
	a.OnShutdown("gcs", gcs.Close)
	a.Health.Register("gcs", gcs.Ping)

	bucket := config.String("AUDIT_ARCHIVE_BUCKET", "")
	if bucket == "" {
		// Refusing to start is deliberate. Running without the archive would
		// look identical in every dashboard while quietly providing none of
		// the tamper evidence this service exists for.
		return fmt.Errorf("auditor: AUDIT_ARCHIVE_BUCKET is required — " +
			"the archive is the point of this consumer, not an optional extra")
	}

	au := &auditor{
		gcs:        gcs,
		bucket:     bucket,
		last:       make(map[string]auditlog.Entry),
		batchMax:   config.Int("AUDIT_BATCH_MAX", 500),
		flushEvery: config.Duration("AUDIT_FLUSH_EVERY", 60*time.Second),
	}

	kafkaCfg := kafkax.Config{
		Brokers:  config.Strings("KAFKA_BROKERS", []string{"localhost:9092"}),
		UseOAuth: config.Bool("KAFKA_OAUTH", a.Cfg.Env != "dev"),
		TLS:      config.Bool("KAFKA_TLS", a.Cfg.Env != "dev"),
		ClientID: "auditor",
	}

	producer, err := kafkax.NewProducer(kafkaCfg, kafkax.DefaultProducerOptions())
	if err != nil {
		return fmt.Errorf("kafka producer: %w", err)
	}
	a.OnShutdown("kafka-producer", producer.Close)

	consumer, err := kafkax.NewConsumer(kafkaCfg, kafkax.ConsumerOptions{
		Topic: auditlog.TopicAudit,
		Group: "auditor",
		// FirstOffset: on a new group we want the entire retained trail, not
		// only what arrives from now on. Verification of a chain that starts
		// mid-stream cannot reach the genesis hash.
		StartOffset: kafka.FirstOffset,
		MinBytes:    1,
		MaxBytes:    1 << 20,
		MaxWait:     5 * time.Second,
		MaxRetries:  5,
		RetryBase:   time.Second,
		RetryMax:    30 * time.Second,
		DLQProducer: producer,
	}, a.Log)
	if err != nil {
		return fmt.Errorf("kafka consumer: %w", err)
	}
	a.OnShutdown("kafka-consumer", consumer.Close)
	a.Health.Register("kafka", func(ctx context.Context) error { return nil })

	// Flush on a timer as well as on size, so a quiet period does not leave
	// the most recent entries unarchived for hours.
	go au.flushLoop(ctx, a)

	// A final flush on the way out. Losing the tail of the buffer would be
	// losing exactly the records closest to whatever prompted the restart.
	a.OnShutdown("audit-flush", func(ctx context.Context) error {
		return au.flush(ctx, a)
	})

	a.Log.Info("auditing the administrative trail",
		"topic", auditlog.TopicAudit, "archive_bucket", bucket)

	return consumer.Run(ctx, func(ctx context.Context, m kafka.Message) error {
		return au.handle(ctx, a, m)
	})
}

func (au *auditor) handle(ctx context.Context, a *app.App, m kafka.Message) error {
	var e auditlog.Entry
	if err := json.Unmarshal(m.Value, &e); err != nil {
		// Malformed audit records go to the DLQ rather than being skipped:
		// something is writing to this topic that should not be.
		return fmt.Errorf("auditor: entry at offset %d is not decodable: %w", m.Offset, err)
	}

	entriesSeen.WithLabelValues(string(e.Action)).Inc()

	au.mu.Lock()
	prev, seen := au.last[e.WriterID]
	au.last[e.WriterID] = e
	au.pending = append(au.pending, e)
	full := len(au.pending) >= au.batchMax
	au.mu.Unlock()

	au.verify(a, e, prev, seen)

	if full {
		return au.flush(ctx, a)
	}
	return nil
}

// verify checks one entry, and its link to its predecessor when we hold one.
//
// The two checks are deliberately separate. The content hash can always be
// checked; the link can only be checked against a predecessor we have actually
// seen. Conflating them makes every writer's first observed entry look like
// tampering, and an alert that fires on every restart is an alert that gets
// muted — which would leave real tampering unnoticed.
//
// A break is logged and counted but does not fail the record. Returning an
// error would retry and then dead-letter it, which would mean detected
// tampering also stopped the archive from recording the evidence — precisely
// backwards.
func (au *auditor) verify(a *app.App, e, prev auditlog.Entry, seen bool) {
	if err := auditlog.VerifyEntry(e); err != nil {
		au.reportBreak(a, e, "altered", err)
		return
	}

	if !seen {
		// No predecessor held. Either this writer is new — a pod that just
		// started, whose chain legitimately begins at the genesis hash — or we
		// began reading mid-stream. Neither is evidence of anything, and the
		// content hash above has already been checked.
		if e.Seq != 1 {
			a.Log.Info("first entry seen for this writer starts mid-chain; "+
				"earlier entries are unverified here and must be checked in the archive",
				"writer", e.WriterID, "seq", e.Seq)
		}
		return
	}

	if err := auditlog.VerifyLink(prev, e); err != nil {
		kind := "linkage"
		if e.Seq != prev.Seq+1 {
			kind = "sequence_gap"
		}
		au.reportBreak(a, e, kind, err)
	}
}

func (au *auditor) reportBreak(a *app.App, e auditlog.Entry, kind string, err error) {
	chainBreaks.WithLabelValues(e.WriterID, kind).Inc()
	a.Log.Error("AUDIT CHAIN BROKEN — the administrative trail cannot be trusted from this point",
		"writer", e.WriterID,
		"seq", e.Seq,
		"action", e.Action,
		"kind", kind,
		"detail", err.Error())
}

func (au *auditor) flushLoop(ctx context.Context, a *app.App) {
	t := time.NewTicker(au.flushEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := au.flush(ctx, a); err != nil {
				a.Log.Error("could not archive audit entries", "error", err)
			}
		}
	}
}

// flush writes the buffered entries to the archive bucket.
func (au *auditor) flush(ctx context.Context, a *app.App) error {
	au.mu.Lock()
	batch := au.pending
	au.pending = nil
	au.mu.Unlock()

	if len(batch) == 0 {
		return nil
	}

	// Newline-delimited JSON: appendable, greppable, and directly loadable
	// into BigQuery when someone needs to query the trail rather than read it.
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, e := range batch {
		if err := enc.Encode(e); err != nil {
			return fmt.Errorf("auditor: encoding the archive batch: %w", err)
		}
	}

	// Partitioned by hour and named by the sequence range it covers, so the
	// object name alone shows where a gap is without opening anything.
	first, last := batch[0], batch[len(batch)-1]
	object := fmt.Sprintf("audit/%s/%s-%d-%d.jsonl",
		first.At.UTC().Format("2006/01/02/15"),
		first.WriterID, first.Seq, last.Seq)

	if err := au.gcs.Upload(ctx, object, buf.Bytes(), "application/x-ndjson", "no-store"); err != nil {
		archiveFailures.Inc()
		// Put the batch back so the next flush retries it. Dropping audit
		// records because a bucket was briefly unavailable is the failure
		// this whole service exists to prevent.
		au.mu.Lock()
		au.pending = append(batch, au.pending...)
		au.mu.Unlock()
		return fmt.Errorf("auditor: archiving %s: %w", object, err)
	}

	a.Log.Info("archived audit entries", "object", object, "count", len(batch))
	return nil
}
