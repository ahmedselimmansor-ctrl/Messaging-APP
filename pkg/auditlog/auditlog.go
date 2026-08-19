// Package auditlog records administrative and privacy-relevant actions.
//
// Cloud Audit Logs already cover the infrastructure: who changed a firewall,
// who read a secret. What they cannot see is the application's own
// decisions — an admin removing a member, an operator resolving a support
// ticket by looking someone up, an account being deleted. Those are exactly
// the actions that get questioned later.
//
// Two properties make this an audit log rather than just logging:
//
//   - Entries are hash-chained. Each carries the hash of its predecessor, so
//     removing or altering one breaks the chain from that point onwards. It
//     does not prevent tampering — anything with write access can rewrite the
//     whole chain — but it makes selective, quiet tampering detectable, which
//     is the realistic threat.
//   - Entries go to a dedicated Kafka topic with long retention, separate
//     from application logs, so a log-volume purge cannot take the audit
//     trail with it.
package auditlog

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/segmentio/kafka-go"
)

// Publisher is the transport.
//
// Its shape is exactly *kafkax.Producer.Publish — variadic headers and all —
// so production wiring passes a producer directly with no adapter, and a test
// can substitute something that records what was written without standing up
// a broker.
type Publisher interface {
	Publish(ctx context.Context, topic string, key, value []byte, headers ...kafka.Header) error
}

// TopicAudit is the dedicated topic: long retention, never rotated for volume.
const TopicAudit = "platform.audit"

// Action is what happened.
type Action string

const (
	// Membership and moderation.
	ActionMemberAdded    Action = "member.added"
	ActionMemberRemoved  Action = "member.removed"
	ActionRoleChanged    Action = "member.role_changed"
	ActionChatDeleted    Action = "chat.deleted"
	ActionMessageDeleted Action = "message.deleted_by_admin"

	// Account lifecycle.
	ActionAccountDeleted Action = "account.deleted"
	ActionAccountBanned  Action = "account.banned"
	ActionDeviceRevoked  Action = "device.revoked"

	// Privacy-relevant reads. An operator looking someone up is exactly the
	// action that needs a record, because it leaves no other trace — nothing
	// is sent, nothing changes, and without an entry there is no way to tell
	// an investigation from someone reading an ex-partner's account.
	ActionUserLookup Action = "operator.user_lookup"
	ActionDataExport Action = "operator.data_export"

	// Security.
	ActionMalwareBlocked Action = "security.malware_blocked"
)

// There is deliberately no action for an operator reading media, and none for
// secret rotation.
//
// The first because no operator can: admin-service has no Cassandra client and
// no storage role, so the capability does not exist to record. A constant for
// it would imply a code path that someone would eventually write to match.
//
// The second because rotation happens in Secret Manager and Cloud KMS, which
// keep their own audit logs. Recording it here would be a second, weaker copy
// of a trail that already exists — and one the application could forget to
// write.

// Entry is one audit record.
type Entry struct {
	V int `json:"v"`

	// Seq is this writer's monotonic counter. With WriterID it makes a gap
	// visible even when entries arrive out of order.
	Seq      int64  `json:"seq"`
	WriterID string `json:"writer_id"`

	// PrevHash chains this entry to the one before it, so altering an earlier
	// entry invalidates every hash after it.
	PrevHash string `json:"prev_hash"`
	Hash     string `json:"hash"`

	Action Action    `json:"action"`
	At     time.Time `json:"at"`

	// ActorID is who did it. Zero for a system action.
	ActorID int64 `json:"actor_id,omitempty"`
	// ActorType is user|operator|system.
	ActorType string `json:"actor_type"`
	ActorIP   string `json:"actor_ip,omitempty"`

	// TargetType and TargetID are what was acted on.
	TargetType string `json:"target_type,omitempty"`
	TargetID   int64  `json:"target_id,omitempty"`

	// Reason is the operator's justification where one is required. A lookup
	// with no stated reason is itself a finding.
	Reason string `json:"reason,omitempty"`

	// Detail carries action-specific fields.
	//
	// Never message content, never a phone number, never key material. An
	// audit log is read by more people than the data it describes, and one
	// that quietly accumulates personal data becomes its own liability.
	Detail map[string]string `json:"detail,omitempty"`
}

// Logger writes audit entries.
type Logger struct {
	producer Publisher
	writerID string

	mu       sync.Mutex
	seq      int64
	prevHash string
}

// genesisHash starts every chain. A fixed, known origin means a verifier can
// check from the beginning rather than from wherever it happened to start
// reading.
const genesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

// New builds a logger.
//
// writerID identifies this replica, and each writer keeps its own chain. A
// single global chain would need a lock across every pod and would make the
// audit log a bottleneck on the very actions it records.
func New(producer Publisher, writerID string) *Logger {
	return &Logger{producer: producer, writerID: writerID, prevHash: genesisHash}
}

// Record writes one entry.
//
// It returns an error rather than swallowing one. A failed audit write is a
// real problem and the caller has to decide what it means: for a member
// removal, probably proceed anyway; for a data export, probably not.
func (l *Logger) Record(ctx context.Context, e Entry) error {
	l.mu.Lock()
	l.seq++
	e.Seq = l.seq
	e.WriterID = l.writerID
	e.PrevHash = l.prevHash
	e.V = 1
	if e.At.IsZero() {
		e.At = time.Now().UTC()
	}
	if e.ActorType == "" {
		e.ActorType = "system"
	}

	hash, err := hashEntry(e)
	if err != nil {
		l.mu.Unlock()
		return err
	}
	e.Hash = hash
	l.prevHash = hash
	l.mu.Unlock()

	body, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("auditlog: encode entry: %w", err)
	}

	// Keyed by writer, so one writer's chain lands on one partition and stays
	// ordered. Verification depends on that ordering.
	if err := l.producer.Publish(ctx, TopicAudit, []byte(l.writerID), body); err != nil {
		return fmt.Errorf("auditlog: publish entry: %w", err)
	}
	return nil
}

// hashEntry computes the chain hash over an entry's content.
//
// The Hash field is excluded — including it would be self-referential.
// Everything else is covered, so changing any recorded field invalidates it.
func hashEntry(e Entry) (string, error) {
	e.Hash = ""
	// json.Marshal on a struct emits fields in declaration order, which is
	// what makes the hash reproducible by an independent verifier.
	body, err := json.Marshal(e)
	if err != nil {
		return "", fmt.Errorf("auditlog: entry is not encodable: %w", err)
	}
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:]), nil
}

// VerifyEntry checks that one entry's content still matches its own hash.
//
// This is the half of verification that needs no predecessor. A consumer that
// starts reading mid-stream — because retention dropped the earlier records,
// or a group offset was reset — holds no predecessor for the first entry it
// sees from a given writer, and calling Verify on that single entry would
// report a linkage break that is really just a missing history. Checking the
// content hash alone says what can honestly be said at that point.
func VerifyEntry(e Entry) error {
	got, err := hashEntry(e)
	if err != nil {
		return err
	}
	if got != e.Hash {
		return fmt.Errorf(
			"auditlog: entry (seq %d, %s) carries hash %s but its content hashes to %s — it was altered after being written",
			e.Seq, e.Action, e.Hash, got)
	}
	return nil
}

// VerifyLink checks that next follows prev.
//
// Separate from VerifyEntry because the two failures mean different things: a
// bad content hash is an altered record, a bad link is a removed or reordered
// one, and an operator responding to an alert needs to know which.
// The sequence is checked first, deliberately. When entries are removed from
// the middle both checks fail, and "3 entries are missing" tells an operator
// how much is gone, where "the hashes do not match" only tells them something
// is wrong.
func VerifyLink(prev, next Entry) error {
	if next.Seq != prev.Seq+1 {
		return fmt.Errorf(
			"auditlog: the sequence jumped from %d to %d — %d entries are missing",
			prev.Seq, next.Seq, next.Seq-prev.Seq-1)
	}
	if next.PrevHash != prev.Hash {
		return fmt.Errorf(
			"auditlog: entry seq %d links to %s but the preceding entry hashes to %s — an entry was altered or reordered",
			next.Seq, next.PrevHash, prev.Hash)
	}
	return nil
}

// Verify checks a chain of entries from one writer.
//
// It reports the first entry whose hash or linkage does not hold, which is
// where tampering — or a lost record — begins. Entries must be in sequence
// order, which is what the partition key guarantees.
func Verify(entries []Entry) error {
	if len(entries) == 0 {
		return nil
	}

	prev := genesisHash
	var lastSeq int64

	for i, e := range entries {
		got, err := hashEntry(e)
		if err != nil {
			return err
		}
		if got != e.Hash {
			return fmt.Errorf(
				"auditlog: entry %d (seq %d, %s) carries hash %s but its content hashes to %s — it was altered after being written",
				i, e.Seq, e.Action, e.Hash, got)
		}
		if e.PrevHash != prev {
			return fmt.Errorf(
				"auditlog: entry %d (seq %d) links to %s but the preceding entry hashes to %s — an entry was removed or reordered",
				i, e.Seq, e.PrevHash, prev)
		}
		if lastSeq != 0 && e.Seq != lastSeq+1 {
			return fmt.Errorf(
				"auditlog: the sequence jumped from %d to %d — %d entries are missing",
				lastSeq, e.Seq, e.Seq-lastSeq-1)
		}
		prev = e.Hash
		lastSeq = e.Seq
	}
	return nil
}
