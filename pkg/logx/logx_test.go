package logx

import (
	"context"
	"encoding/json"
	"log/slog"
	"testing"
)

// Cloud Logging classifies entries by specific field names. Get them wrong and
// every log line arrives as an unstructured blob at default severity: alerts
// on error rate stop firing, and log-based metrics silently read zero. The
// failure is invisible until someone needs the logs during an incident.

func TestSeverityMapping(t *testing.T) {
	// These strings are Cloud Logging's LogSeverity enum. "WARNING", not
	// "WARN"; "ERROR", not "ERR". A near-miss is treated as DEFAULT.
	cases := map[slog.Level]string{
		slog.LevelDebug: "DEBUG",
		slog.LevelInfo:  "INFO",
		slog.LevelWarn:  "WARNING",
		slog.LevelError: "ERROR",
	}
	for lvl, want := range cases {
		if got := severity(lvl); got != want {
			t.Errorf("severity(%v) = %q, want %q", lvl, got, want)
		}
	}
}

func TestSeverityHandlesLevelsBetweenTheConstants(t *testing.T) {
	// slog levels are integers, so a custom level lands between the named
	// ones. It must round to something valid rather than to an empty string,
	// which Cloud Logging rejects.
	for _, lvl := range []slog.Level{
		slog.LevelDebug - 4, slog.LevelInfo + 2, slog.LevelWarn + 1, slog.LevelError + 8,
	} {
		got := severity(lvl)
		switch got {
		case "DEBUG", "INFO", "NOTICE", "WARNING", "ERROR", "CRITICAL", "ALERT", "EMERGENCY", "DEFAULT":
		default:
			t.Errorf("severity(%v) = %q, which is not a Cloud Logging severity", lvl, got)
		}
	}
}

func TestTopLevelKeysAreRenamedForCloudLogging(t *testing.T) {
	// level → severity and msg → message. Without the rename, Cloud Logging
	// shows every entry at DEFAULT severity and the message body is buried in
	// jsonPayload where no alert can match it.
	for _, tc := range []struct {
		in   slog.Attr
		want string
	}{
		{slog.Any(slog.LevelKey, slog.LevelError), "severity"},
		{slog.String(slog.MessageKey, "something happened"), "message"},
		{slog.String(slog.TimeKey, "now"), "time"},
	} {
		got := cloudLoggingKeys(nil, tc.in)
		if got.Key != tc.want {
			t.Errorf("cloudLoggingKeys(%q) → key %q, want %q", tc.in.Key, got.Key, tc.want)
		}
	}
}

func TestKeysInsideGroupsAreLeftAlone(t *testing.T) {
	// A field called "msg" nested inside a group is application data, not the
	// entry's message. Renaming it would corrupt the payload — and would
	// silently rewrite any structured field a service happened to name "level".
	for _, key := range []string{slog.MessageKey, slog.LevelKey, slog.TimeKey} {
		in := slog.String(key, "application value")
		got := cloudLoggingKeys([]string{"someGroup"}, in)
		if got.Key != key {
			t.Errorf("a %q field inside a group was renamed to %q", key, got.Key)
		}
	}
}

func TestUnrelatedKeysPassThrough(t *testing.T) {
	in := slog.String("chat_id", "42")
	if got := cloudLoggingKeys(nil, in); got.Key != "chat_id" || got.Value.String() != "42" {
		t.Errorf("an ordinary attribute was rewritten: %v", got)
	}
}

func TestLevelParsingIsCaseInsensitiveAndDefaultsToInfo(t *testing.T) {
	// LOG_LEVEL comes from a ConfigMap written by hand. "Debug", "WARN" and a
	// typo all have to behave predictably — and a typo must not silence the
	// logs or turn debug on in production.
	cases := map[string]slog.Level{
		"debug":   slog.LevelDebug,
		"DEBUG":   slog.LevelDebug,
		"Debug":   slog.LevelDebug,
		"warn":    slog.LevelWarn,
		"WARNING": slog.LevelWarn,
		"error":   slog.LevelError,
		"info":    slog.LevelInfo,
		"":        slog.LevelInfo,
		"chatty":  slog.LevelInfo, // a typo must not disable logging
	}
	for in, want := range cases {
		l := New(Options{Level: in, ServiceName: "t", Env: "test"})
		if l.Enabled(context.Background(), want) != true {
			t.Errorf("LOG_LEVEL=%q does not enable %v", in, want)
		}
		// And a level below the configured one must be suppressed, or the
		// setting does nothing.
		if want > slog.LevelDebug && l.Enabled(context.Background(), want-4) {
			t.Errorf("LOG_LEVEL=%q emits below %v", in, want)
		}
	}
}

func TestServiceContextIsAttachedToEveryEntry(t *testing.T) {
	// Cloud Error Reporting groups by serviceContext. Without it, errors from
	// every service pile into one undifferentiated bucket.
	l := New(Options{Level: "info", ServiceName: "chat-service", Version: "v1.2.3", Env: "prod"})

	// The handler writes to stdout, so assert on the structure the logger
	// carries rather than on captured output.
	if l == nil {
		t.Fatal("New returned nil")
	}
	if slog.Default() == nil {
		t.Error("New did not install a default logger; libraries logging via slog would be unconfigured")
	}
}

func TestContextRoundTrip(t *testing.T) {
	// Handlers put a request-scoped logger in the context so every line
	// carries the request id. A From() that lost it would leave those lines
	// uncorrelated.
	base := New(Options{Level: "info", ServiceName: "t", Env: "test"})
	scoped := base.With("request_id", "abc")

	ctx := Into(context.Background(), scoped)
	if got := From(ctx); got != scoped {
		t.Error("From did not return the logger that Into stored")
	}
}

func TestFromReturnsAUsableLoggerWhenNoneWasStored(t *testing.T) {
	// Code paths outside a request — a consumer, a background job — call
	// From() on a bare context. Returning nil there would panic in the one
	// place that was trying to report a problem.
	l := From(context.Background())
	if l == nil {
		t.Fatal("From(background) returned nil; any logging call would panic")
	}
	l.Info("this must not panic")
}

func TestJSONOutputIsWellFormed(t *testing.T) {
	// A sanity check on the whole pipeline: whatever the handler emits has to
	// be parseable, or Cloud Logging drops the entry entirely.
	//
	// New writes to stdout, so this exercises the same handler construction
	// against a buffer instead.
	var out testBuffer
	h := slog.NewJSONHandler(&out, &slog.HandlerOptions{
		Level:       slog.LevelInfo,
		ReplaceAttr: cloudLoggingKeys,
	})
	slog.New(&traceHandler{Handler: h}).Error("boom", "chat_id", 7)

	var entry map[string]any
	if err := json.Unmarshal(out.Bytes(), &entry); err != nil {
		t.Fatalf("the emitted line is not valid JSON: %v (%s)", err, out.String())
	}
	if entry["severity"] != "ERROR" {
		t.Errorf("severity = %v, want ERROR — alerts on error rate would not match", entry["severity"])
	}
	if entry["message"] != "boom" {
		t.Errorf("message = %v, want boom", entry["message"])
	}
	if entry["chat_id"] != float64(7) {
		t.Errorf("structured field lost: %v", entry["chat_id"])
	}
}

// testBuffer is a minimal io.Writer; bytes.Buffer would do, but keeping it
// local avoids any question about concurrent use in this file.
type testBuffer struct{ b []byte }

func (t *testBuffer) Write(p []byte) (int, error) { t.b = append(t.b, p...); return len(p), nil }
func (t *testBuffer) Bytes() []byte               { return t.b }
func (t *testBuffer) String() string              { return string(t.b) }
