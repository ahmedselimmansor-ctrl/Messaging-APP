package kafkax

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pervagans/messaging-app/pkg/events"
	"github.com/segmentio/kafka-go"
)

// The retry-then-dead-letter path is what keeps one bad record from blocking a
// partition forever. Its failure modes are quiet: a record retried forever
// stalls every message behind it, and a record dropped instead of
// dead-lettered is data the platform accepted and then silently lost.
//
// handleWithRetry touches only c.o and c.log, so it can be exercised directly
// without a broker.

func testConsumer(o ConsumerOptions) *Consumer {
	return &Consumer{
		o:    o,
		log:  slog.New(slog.NewTextHandler(io.Discard, nil)),
		stop: make(chan struct{}),
	}
}

func msg() kafka.Message {
	return kafka.Message{
		Topic: "messages.raw", Partition: 3, Offset: 42,
		Key: []byte("chat-1"), Value: []byte(`{"a":1}`),
	}
}

func TestHandlerSuccessDoesNotRetry(t *testing.T) {
	var calls int32
	c := testConsumer(ConsumerOptions{Topic: "t", Group: "g", MaxRetries: 5})

	err := c.handleWithRetry(context.Background(), msg(), func(context.Context, kafka.Message) error {
		atomic.AddInt32(&calls, 1)
		return nil
	})
	if err != nil {
		t.Fatalf("handleWithRetry returned %v for a successful handler", err)
	}
	if calls != 1 {
		t.Errorf("handler ran %d times, want 1", calls)
	}
}

func TestErrSkipCommitsWithoutRetrying(t *testing.T) {
	// ErrSkip means "this record is not for me" — a video job in a build with
	// no ffmpeg, say. Retrying it would block the partition on something that
	// will never succeed, and dead-lettering it would raise an alert for a
	// non-problem.
	var calls int32
	c := testConsumer(ConsumerOptions{Topic: "t", Group: "g", MaxRetries: 5})

	err := c.handleWithRetry(context.Background(), msg(), func(context.Context, kafka.Message) error {
		atomic.AddInt32(&calls, 1)
		return fmt.Errorf("no transcoder here: %w", ErrSkip)
	})
	if err != nil {
		t.Fatalf("a skipped record returned %v, want nil so the offset commits", err)
	}
	if calls != 1 {
		t.Errorf("a skipped record was retried %d times", calls)
	}
}

func TestTransientFailureIsRetriedThenSucceeds(t *testing.T) {
	// The common case: a database blip. The record must survive it rather than
	// going to the DLQ on the first stumble.
	var calls int32
	c := testConsumer(ConsumerOptions{
		Topic: "t", Group: "g", MaxRetries: 5,
		RetryBase: time.Millisecond, RetryMax: 5 * time.Millisecond,
	})

	err := c.handleWithRetry(context.Background(), msg(), func(context.Context, kafka.Message) error {
		if atomic.AddInt32(&calls, 1) < 3 {
			return errors.New("connection reset")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("handleWithRetry returned %v after the handler eventually succeeded", err)
	}
	if calls != 3 {
		t.Errorf("handler ran %d times, want 3", calls)
	}
}

func TestExhaustedRetriesReachTheDLQPath(t *testing.T) {
	// With no DLQ producer configured, exhaustion must return an error rather
	// than silently committing — a consumer with no dead-letter destination
	// must not quietly discard records.
	var calls int32
	c := testConsumer(ConsumerOptions{
		Topic: "t", Group: "g", MaxRetries: 3,
		RetryBase: time.Millisecond, RetryMax: 2 * time.Millisecond,
	})

	err := c.handleWithRetry(context.Background(), msg(), func(context.Context, kafka.Message) error {
		atomic.AddInt32(&calls, 1)
		return errors.New("permanently broken")
	})
	if err == nil {
		t.Fatal("a record that exhausted its retries with no DLQ was accepted as handled — it would be lost")
	}
	if !strings.Contains(err.Error(), "permanently broken") {
		t.Errorf("the original cause is not preserved: %v", err)
	}
	// MaxRetries is the number of *retries*, so the handler runs once more
	// than that. Getting this wrong silently changes how long a poisoned
	// record stalls its partition.
	if want := int32(4); calls != want {
		t.Errorf("handler ran %d times with MaxRetries=3, want %d", calls, want)
	}
}

func TestCancellationStopsRetrying(t *testing.T) {
	// On shutdown the retry loop must abandon promptly. A consumer that kept
	// backing off through SIGTERM would be killed mid-retry and the record
	// redelivered anyway.
	ctx, cancel := context.WithCancel(context.Background())
	c := testConsumer(ConsumerOptions{
		Topic: "t", Group: "g", MaxRetries: 100,
		RetryBase: 50 * time.Millisecond, RetryMax: time.Second,
	})

	var calls int32
	done := make(chan error, 1)
	go func() {
		done <- c.handleWithRetry(ctx, msg(), func(context.Context, kafka.Message) error {
			if atomic.AddInt32(&calls, 1) == 2 {
				cancel()
			}
			return errors.New("still failing")
		})
	}()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("err = %v, want context.Canceled", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the retry loop did not abandon after cancellation")
	}

	if calls > 5 {
		t.Errorf("handler ran %d times after cancellation; the loop is not checking the context", calls)
	}
}

func TestRetryBackoffIsCapped(t *testing.T) {
	// Exponential backoff without a ceiling reaches minutes within a dozen
	// attempts, and the partition stalls behind it.
	c := testConsumer(ConsumerOptions{
		Topic: "t", Group: "g", MaxRetries: 8,
		RetryBase: time.Millisecond, RetryMax: 3 * time.Millisecond,
	})

	started := time.Now()
	_ = c.handleWithRetry(context.Background(), msg(), func(context.Context, kafka.Message) error {
		return errors.New("nope")
	})
	elapsed := time.Since(started)

	// Uncapped, 1ms doubling over 8 retries is ~255ms. Capped at 3ms it is
	// well under 50ms. A generous bound keeps this from being flaky on a
	// loaded machine while still failing an uncapped implementation.
	if elapsed > 150*time.Millisecond {
		t.Errorf("8 retries took %v; the backoff cap is not being applied", elapsed)
	}
}

// ---------------------------------------------------------------------------
// Dead letters
// ---------------------------------------------------------------------------

func TestDeadLetterPreservesProvenance(t *testing.T) {
	// A dead letter has to say enough to replay the record: which topic, which
	// offset, and what went wrong. Without those it is an alert nobody can act
	// on.
	dl := buildDeadLetter(msg(), "persister", errors.New("cassandra timeout"), 4)

	if dl.SourceTopic != "messages.raw" || dl.Partition != 3 || dl.Offset != 42 {
		t.Errorf("provenance lost: %+v", dl)
	}
	if dl.Group != "persister" || dl.Key != "chat-1" || dl.Attempts != 4 {
		t.Errorf("context lost: %+v", dl)
	}
	if !strings.Contains(dl.Error, "cassandra timeout") {
		t.Errorf("the cause is not recorded: %q", dl.Error)
	}
	if dl.FailedAt.IsZero() {
		t.Error("FailedAt was not stamped")
	}
}

func TestDeadLetterStaysParseableForAMalformedPayload(t *testing.T) {
	// The case that matters. A record often reaches the DLQ *because* it was
	// malformed, so embedding it raw would make the dead letter itself
	// unparseable — one poisoned record becoming a poisoned DLQ that no
	// tooling can read.
	for _, payload := range [][]byte{
		[]byte("not json at all"),
		[]byte(`{"unterminated": `),
		{0x00, 0xff, 0xfe},
		nil,
		[]byte(""),
	} {
		m := msg()
		m.Value = payload

		dl := buildDeadLetter(m, "g", errors.New("decode failed"), 1)

		body, err := json.Marshal(dl)
		if err != nil {
			t.Fatalf("payload %q: the dead letter itself does not encode: %v", payload, err)
		}
		var round events.DeadLetter
		if err := json.Unmarshal(body, &round); err != nil {
			t.Fatalf("payload %q: the dead letter does not parse back: %v (%s)", payload, err, body)
		}
		if len(round.Payload) == 0 {
			t.Errorf("payload %q: the evidence was dropped from the dead letter", payload)
		}
	}
}

func TestDeadLetterKeepsValidJSONInline(t *testing.T) {
	// A well-formed payload must stay a JSON object, not become a quoted
	// string — otherwise every replay tool needs two code paths.
	m := msg()
	m.Value = []byte(`{"message_id":"abc","chat_id":7}`)

	dl := buildDeadLetter(m, "g", errors.New("downstream 500"), 2)

	var inner map[string]any
	if err := json.Unmarshal(dl.Payload, &inner); err != nil {
		t.Fatalf("a valid JSON payload was not kept inline: %v (%s)", err, dl.Payload)
	}
	if inner["message_id"] != "abc" {
		t.Errorf("payload content changed: %v", inner)
	}
}

// ---------------------------------------------------------------------------
// Headers
// ---------------------------------------------------------------------------

func TestHeaderLookup(t *testing.T) {
	m := kafka.Message{Headers: []kafka.Header{
		{Key: "source-topic", Value: []byte("messages.raw")},
		{Key: "trace-id", Value: []byte("abc123")},
	}}

	if got := Header(m, "source-topic"); got != "messages.raw" {
		t.Errorf("Header = %q, want messages.raw", got)
	}
	if got := Header(m, "absent"); got != "" {
		t.Errorf("a missing header returned %q, want the empty string", got)
	}
	if got := Header(kafka.Message{}, "anything"); got != "" {
		t.Errorf("a message with no headers returned %q", got)
	}
}

func TestDefaultProducerOptionsAreDurable(t *testing.T) {
	// acks=all is the platform's durability boundary: the send path returns
	// success to the user once Kafka has acknowledged, and a weaker setting
	// would make that promise false the moment a broker restarted.
	o := DefaultProducerOptions()

	if o.RequiredAcks != kafka.RequireAll {
		t.Errorf("RequiredAcks = %v, want RequireAll (%v) — messages could be "+
			"acknowledged to the user and then lost with one broker",
			o.RequiredAcks, kafka.RequireAll)
	}
	if o.MaxAttempts <= 1 {
		t.Errorf("MaxAttempts = %d; a single transient error would fail a user's send", o.MaxAttempts)
	}
}
