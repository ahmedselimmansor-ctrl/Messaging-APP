package events

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// These structs are the contract between producers and consumers that deploy
// independently. A field that silently changes shape breaks a consumer at
// runtime, in production, on a partition nobody is watching — so the wire
// format and the validation are pinned here.

func validMessage() MessageEvent {
	return MessageEvent{
		V:         CurrentVersion,
		MessageID: "msg-1",
		ChatID:    100,
		Seq:       1,
		SenderID:  7,
		Type:      MessageText,
		Body:      "hello",
		CreatedAt: time.Now().UTC(),
	}
}

func TestValidateAcceptsAWellFormedMessage(t *testing.T) {
	m := validMessage()
	if err := m.Validate(); err != nil {
		t.Fatalf("a well-formed message was rejected: %v", err)
	}
}

func TestValidateRejectsMissingIdentity(t *testing.T) {
	// Each of these would produce a row in Cassandra that cannot be addressed
	// or attributed. The persister calls Validate precisely so such a record
	// goes to the dead-letter queue instead of into history.
	cases := map[string]func(*MessageEvent){
		"no message id": func(m *MessageEvent) { m.MessageID = "" },
		"no chat id":    func(m *MessageEvent) { m.ChatID = 0 },
		"no sender":     func(m *MessageEvent) { m.SenderID = 0 },
		"no type":       func(m *MessageEvent) { m.Type = "" },
		"zero seq":      func(m *MessageEvent) { m.Seq = 0 },
		"negative seq":  func(m *MessageEvent) { m.Seq = -1 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			m := validMessage()
			mutate(&m)
			if err := m.Validate(); err == nil {
				t.Errorf("Validate accepted a message with %s", name)
			}
		})
	}
}

func TestValidateRejectsAnEmptyTextBody(t *testing.T) {
	m := validMessage()
	m.Body = ""
	if err := m.Validate(); err == nil {
		t.Fatal("Validate accepted a text message with no body")
	}
}

func TestEncryptedMessagesMayHaveAnEmptyBody(t *testing.T) {
	// The body of a secret-chat message is ciphertext the server never
	// unpacks, so the plaintext field is legitimately empty. Rejecting it
	// would make end-to-end encryption impossible to route.
	m := validMessage()
	m.Body = ""
	m.Encrypted = true
	if err := m.Validate(); err != nil {
		t.Fatalf("Validate rejected an encrypted message with no plaintext body: %v", err)
	}
}

func TestMediaMessagesRequireAReference(t *testing.T) {
	// A photo message with no media is a message the client renders as a
	// broken attachment forever. Better to dead-letter it at the boundary.
	for _, kind := range []MessageType{MessagePhoto, MessageVideo, MessageFile, MessageVoice} {
		m := validMessage()
		m.Type = kind
		m.Body = ""
		m.Media = nil
		if err := m.Validate(); err == nil {
			t.Errorf("Validate accepted a %s message with no media reference", kind)
		}

		m.Media = &MediaRef{Object: "media/1/x.jpg", MimeType: "image/jpeg", SizeBytes: 10}
		if err := m.Validate(); err != nil {
			t.Errorf("Validate rejected a %s message that has media: %v", kind, err)
		}
	}
}

func TestMessageEventSurvivesAJSONRoundTrip(t *testing.T) {
	// Kafka carries JSON. Anything that does not round-trip is a field the
	// consumer will never see.
	in := validMessage()
	in.ReplyToSeq = 42
	in.Media = &MediaRef{
		Object: "media/7/photo.jpg", MimeType: "image/jpeg",
		SizeBytes: 2048, Width: 100, Height: 200,
	}

	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out MessageEvent
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}

	if out.MessageID != in.MessageID || out.ChatID != in.ChatID ||
		out.Seq != in.Seq || out.SenderID != in.SenderID ||
		out.Type != in.Type || out.Body != in.Body || out.ReplyToSeq != in.ReplyToSeq {
		t.Errorf("a field was lost in the round trip:\n in: %+v\nout: %+v", in, out)
	}
	if out.Media == nil || out.Media.Object != in.Media.Object || out.Media.SizeBytes != in.Media.SizeBytes {
		t.Errorf("the media reference did not survive: %+v", out.Media)
	}
	if err := out.Validate(); err != nil {
		t.Errorf("a decoded event no longer validates: %v", err)
	}
}

func TestWireFieldNamesAreStable(t *testing.T) {
	// Consumers deploy independently of producers, so a renamed JSON tag is a
	// silent data loss rather than a compile error. This pins the names that
	// are actually read on the other side.
	raw, err := json.Marshal(validMessage())
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}

	for _, field := range []string{"v", "message_id", "chat_id", "seq", "sender_id", "type", "body"} {
		if _, ok := m[field]; !ok {
			t.Errorf("the wire format no longer carries %q; every consumer reading it breaks", field)
		}
	}
}

func TestVersionIsStampedAndReadable(t *testing.T) {
	// The version is what lets a consumer refuse a payload from a newer
	// producer rather than misreading it.
	m := validMessage()
	if m.V != CurrentVersion {
		t.Errorf("V = %d, want CurrentVersion (%d)", m.V, CurrentVersion)
	}

	raw, _ := json.Marshal(m)
	if !strings.Contains(string(raw), `"v":`) {
		t.Errorf("the encoded event carries no version field: %s", raw)
	}
}

func TestTopicNamesAreDistinct(t *testing.T) {
	// Two constants resolving to one topic would merge two streams — and the
	// symptom would be a consumer receiving payloads it cannot decode.
	topics := map[string]string{
		"messages.raw":       TopicMessagesRaw,
		"messages.persisted": TopicMessagesPersisted,
		"presence.events":    TopicPresenceEvents,
		"notifications.push": TopicNotificationsPush,
		"media.processing":   TopicMediaProcessing,
		"media.processed":    TopicMediaProcessed,
		"user.events":        TopicUserEvents,
		"search.index":       TopicSearchIndex,
		"platform.dlq":       TopicDeadLetter,
	}

	seen := make(map[string]string, len(topics))
	for name, topic := range topics {
		if topic == "" {
			t.Errorf("%s resolves to an empty topic name", name)
		}
		if prev, dup := seen[topic]; dup {
			t.Errorf("%s and %s both resolve to %q", prev, name, topic)
		}
		seen[topic] = name
		// Kafka topic names must not contain characters that would need
		// escaping in a CLI or a metric label.
		if strings.ContainsAny(topic, " \t/\\") {
			t.Errorf("topic %q contains an awkward character", topic)
		}
	}
}

func TestUserEventRoundTrips(t *testing.T) {
	in := UserEvent{
		V: CurrentVersion, Kind: UserBanned, UserID: 42,
		DeviceID: 7, At: time.Now().UTC().Truncate(time.Second),
	}
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out UserEvent
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if out.Kind != in.Kind || out.UserID != in.UserID || out.DeviceID != in.DeviceID {
		t.Errorf("round trip lost a field:\n in: %+v\nout: %+v", in, out)
	}
	if !out.At.Equal(in.At) {
		t.Errorf("timestamp did not survive: %v vs %v", out.At, in.At)
	}
}

func TestSearchDocCarriesTheACLField(t *testing.T) {
	// The search service filters on `members`. If that field were renamed or
	// dropped from the indexed document, the ACL filter would match nothing —
	// or, depending on the query, everything.
	doc := SearchDoc{
		ChatID: 1, Seq: 2, SenderID: 3, Body: "hello",
		Members: []int64{3, 4},
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["members"]; !ok {
		t.Fatalf("the indexed document has no members field; the ACL filter has nothing to match: %s", raw)
	}
}
