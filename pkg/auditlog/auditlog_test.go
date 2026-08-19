package auditlog

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/segmentio/kafka-go"
)

// recorder captures published entries so a test can inspect what would have
// reached the topic.
type recorder struct {
	mu      sync.Mutex
	topics  []string
	keys    []string
	entries []Entry
	err     error
}

func (r *recorder) Publish(_ context.Context, topic string, key, value []byte, _ ...kafka.Header) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return r.err
	}
	var e Entry
	if err := json.Unmarshal(value, &e); err != nil {
		return err
	}
	r.topics = append(r.topics, topic)
	r.keys = append(r.keys, string(key))
	r.entries = append(r.entries, e)
	return nil
}

func (r *recorder) snapshot() []Entry {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Entry(nil), r.entries...)
}

func TestChainVerifies(t *testing.T) {
	rec := &recorder{}
	l := New(rec, "gateway-0")

	actions := []Action{ActionMemberAdded, ActionMemberRemoved, ActionUserLookup}
	for i, a := range actions {
		err := l.Record(context.Background(), Entry{
			Action:     a,
			ActorID:    int64(100 + i),
			ActorType:  "operator",
			TargetType: "user",
			TargetID:   int64(900 + i),
			Reason:     "ticket-42",
		})
		if err != nil {
			t.Fatalf("Record(%s): %v", a, err)
		}
	}

	got := rec.snapshot()
	if len(got) != 3 {
		t.Fatalf("published %d entries, want 3", len(got))
	}
	if err := Verify(got); err != nil {
		t.Fatalf("a chain written by the logger does not verify: %v", err)
	}

	// The first entry must link to the genesis hash, or a verifier cannot
	// tell whether entries were dropped from the front.
	if got[0].PrevHash != genesisHash {
		t.Errorf("first entry links to %q, want the genesis hash", got[0].PrevHash)
	}
	for i := 1; i < len(got); i++ {
		if got[i].PrevHash != got[i-1].Hash {
			t.Errorf("entry %d links to %q but its predecessor hashes to %q",
				i, got[i].PrevHash, got[i-1].Hash)
		}
		if got[i].Seq != got[i-1].Seq+1 {
			t.Errorf("entry %d has seq %d, want %d", i, got[i].Seq, got[i-1].Seq+1)
		}
	}

	// Everything goes to the audit topic, keyed by writer so one chain stays
	// on one partition and therefore stays ordered.
	for i, topic := range rec.topics {
		if topic != TopicAudit {
			t.Errorf("entry %d went to topic %q, want %q", i, topic, TopicAudit)
		}
		if rec.keys[i] != "gateway-0" {
			t.Errorf("entry %d keyed %q, want the writer id", i, rec.keys[i])
		}
	}
}

// The point of the chain is that quiet edits are detectable. If these do not
// fail, the package provides no more assurance than a plain log line.

func TestTamperedContentIsDetected(t *testing.T) {
	entries := writeChain(t, 4)

	// An operator covering their tracks: change who did it, leave everything
	// else — including the hash — untouched.
	entries[2].ActorID = 1

	err := Verify(entries)
	if err == nil {
		t.Fatal("Verify accepted a chain whose third entry had its actor rewritten")
	}
	if !strings.Contains(err.Error(), "altered") {
		t.Errorf("error does not say the entry was altered: %v", err)
	}
	if !strings.Contains(err.Error(), "entry 2") {
		t.Errorf("error does not point at the altered entry: %v", err)
	}
}

func TestDeletedEntryIsDetected(t *testing.T) {
	entries := writeChain(t, 5)

	// Remove the middle entry entirely. The surviving entries are each
	// internally valid; only the linkage exposes the deletion.
	tampered := append(append([]Entry{}, entries[:2]...), entries[3:]...)

	err := Verify(tampered)
	if err == nil {
		t.Fatal("Verify accepted a chain with an entry cut out of the middle")
	}
	if !strings.Contains(err.Error(), "removed or reordered") {
		t.Errorf("error does not identify a removal: %v", err)
	}
}

func TestReorderedEntriesAreDetected(t *testing.T) {
	entries := writeChain(t, 4)
	entries[1], entries[2] = entries[2], entries[1]

	if err := Verify(entries); err == nil {
		t.Fatal("Verify accepted a chain with two entries swapped")
	}
}

func TestTruncatedTailIsNotDetectable(t *testing.T) {
	// Worth stating explicitly, because it is the limit of the design: a hash
	// chain proves nothing about entries that were never read. Cutting the
	// *end* off leaves a chain that verifies perfectly.
	//
	// What covers this gap is elsewhere — Kafka retention plus the sequence
	// numbers, since a writer that jumps from seq 40 to seq 60 after a restart
	// shows the loss even though each fragment verifies.
	entries := writeChain(t, 5)

	if err := Verify(entries[:3]); err != nil {
		t.Fatalf("a truncated prefix should still verify, but: %v", err)
	}
}

func TestVerifyRejectsAForgedHash(t *testing.T) {
	entries := writeChain(t, 3)

	// Recompute the hash after tampering — what someone would do if they knew
	// the scheme but only had access to one record.
	entries[1].Reason = "authorised"
	h, err := hashEntry(entries[1])
	if err != nil {
		t.Fatal(err)
	}
	entries[1].Hash = h

	// Entry 1 is now self-consistent, but entry 2 still links to the old hash.
	// Rewriting one record is not enough; every later record must be rewritten
	// too, which is exactly the property we wanted.
	err = Verify(entries)
	if err == nil {
		t.Fatal("Verify accepted a chain where one entry was rewritten and rehashed")
	}
	if !strings.Contains(err.Error(), "entry 2") {
		t.Errorf("the break should surface at the following entry: %v", err)
	}
}

func TestPublishFailureIsReported(t *testing.T) {
	// A dropped audit record has to be visible to the caller. Swallowing it
	// would mean the one action nobody logged is the one that mattered.
	rec := &recorder{err: errors.New("broker unavailable")}
	l := New(rec, "gateway-0")

	err := l.Record(context.Background(), Entry{Action: ActionAccountDeleted})
	if err == nil {
		t.Fatal("Record returned nil when the publish failed")
	}
	if !strings.Contains(err.Error(), "broker unavailable") {
		t.Errorf("the underlying cause is not preserved: %v", err)
	}
}

func TestDefaultsAreFilledIn(t *testing.T) {
	rec := &recorder{}
	l := New(rec, "chat-7")

	before := time.Now().UTC().Add(-time.Second)
	if err := l.Record(context.Background(), Entry{Action: ActionChatDeleted}); err != nil {
		t.Fatal(err)
	}
	got := rec.snapshot()[0]

	if got.At.Before(before) {
		t.Errorf("At was not stamped: %v", got.At)
	}
	if got.ActorType != "system" {
		// An entry with no actor type is ambiguous between "a system action"
		// and "we forgot to record who did it", so it defaults rather than
		// staying empty.
		t.Errorf("ActorType = %q, want system for an unattributed action", got.ActorType)
	}
	if got.WriterID != "chat-7" || got.Seq != 1 || got.V != 1 {
		t.Errorf("writer/seq/version not set: %+v", got)
	}
}

func TestConcurrentRecordsFormOneValidChain(t *testing.T) {
	// Handlers write audit entries from whatever goroutine served the request.
	// If the sequence and previous-hash update were not atomic together, two
	// concurrent writers would each link to the same predecessor and the chain
	// would fork — which Verify would then report as tampering on a system
	// that was behaving correctly.
	rec := &recorder{}
	l := New(rec, "chat-0")

	const n = 64
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			if err := l.Record(context.Background(), Entry{
				Action:   ActionMemberRemoved,
				TargetID: int64(i),
			}); err != nil {
				t.Errorf("Record: %v", err)
			}
		}(i)
	}
	wg.Wait()

	got := rec.snapshot()
	if len(got) != n {
		t.Fatalf("recorded %d entries, want %d", len(got), n)
	}

	// The recorder appends under its own lock, so arrival order may differ
	// from sequence order. Kafka restores that ordering via the partition key;
	// here we sort by sequence to check the same invariant.
	bySeq := make([]Entry, n)
	for _, e := range got {
		if e.Seq < 1 || e.Seq > n {
			t.Fatalf("sequence %d out of range", e.Seq)
		}
		if bySeq[e.Seq-1].Seq != 0 {
			t.Fatalf("sequence %d was allocated twice", e.Seq)
		}
		bySeq[e.Seq-1] = e
	}

	if err := Verify(bySeq); err != nil {
		t.Fatalf("concurrent writes did not form one valid chain: %v", err)
	}
}

func TestEmptyChainVerifies(t *testing.T) {
	// A writer that has recorded nothing is not evidence of tampering.
	if err := Verify(nil); err != nil {
		t.Errorf("Verify(nil) = %v, want nil", err)
	}
}

func writeChain(t *testing.T, n int) []Entry {
	t.Helper()
	rec := &recorder{}
	l := New(rec, "test-writer")
	for i := 0; i < n; i++ {
		if err := l.Record(context.Background(), Entry{
			Action:     ActionMemberRemoved,
			ActorID:    int64(i + 1),
			ActorType:  "operator",
			TargetType: "user",
			TargetID:   int64(1000 + i),
			Detail:     map[string]string{"chat_id": "77"},
		}); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}
	got := rec.snapshot()
	if err := Verify(got); err != nil {
		t.Fatalf("the freshly written chain does not verify: %v", err)
	}
	return got
}

// VerifyEntry and VerifyLink split the two halves of verification, because a
// consumer reading mid-stream can honestly check one and not the other.

func TestVerifyEntryIgnoresLinkage(t *testing.T) {
	entries := writeChain(t, 3)

	// The third entry taken alone: its PrevHash points at an entry the caller
	// does not hold. That is not tampering, and VerifyEntry must not say it is.
	if err := VerifyEntry(entries[2]); err != nil {
		t.Errorf("VerifyEntry rejected a valid mid-chain entry: %v", err)
	}
	// Verify, by contrast, does report it — which is exactly why the auditor
	// cannot use Verify for a single entry.
	if err := Verify(entries[2:3]); err == nil {
		t.Error("Verify accepted a lone mid-chain entry; the split would then be pointless")
	}
}

func TestVerifyEntryCatchesAlteredContent(t *testing.T) {
	entries := writeChain(t, 2)
	entries[1].TargetID = 999

	if err := VerifyEntry(entries[1]); err == nil {
		t.Fatal("VerifyEntry accepted an entry whose target was rewritten")
	}
}

func TestVerifyLinkDistinguishesGapFromBreak(t *testing.T) {
	entries := writeChain(t, 3)

	if err := VerifyLink(entries[0], entries[1]); err != nil {
		t.Errorf("VerifyLink rejected an adjacent pair: %v", err)
	}

	// Skipping one entry is a gap, and must be reported as missing entries
	// rather than as a rewrite — the two call for different responses.
	err := VerifyLink(entries[0], entries[2])
	if err == nil {
		t.Fatal("VerifyLink accepted a pair with an entry missing between them")
	}
	if !strings.Contains(err.Error(), "missing") {
		t.Errorf("a gap should be reported as missing entries, got: %v", err)
	}
}
