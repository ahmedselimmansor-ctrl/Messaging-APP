// Package logx produces structured logs in the shape Cloud Logging expects.
//
// Cloud Logging parses stdout JSON automatically when the payload uses the
// well-known keys: "severity", "message", "logging.googleapis.com/trace" and
// "logging.googleapis.com/sourceLocation". Emitting those directly means we
// need no sidecar and no agent configuration — the GKE logging agent picks
// them up and log entries are correlated with Cloud Trace spans in the UI.
package logx

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"go.opentelemetry.io/otel/trace"
)

type contextKey struct{}

var loggerKey contextKey

// Options configures the root logger.
type Options struct {
	Level       string // debug|info|warn|error
	ServiceName string
	Version     string
	Env         string
	ProjectID   string // required for trace correlation URLs
	// Pretty renders human-readable text instead of JSON. Used locally.
	Pretty bool
}

// New builds the root logger and installs it as the slog default.
func New(o Options) *slog.Logger {
	var lvl slog.Level
	switch strings.ToLower(o.Level) {
	case "debug":
		lvl = slog.LevelDebug
	case "warn", "warning":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}

	var h slog.Handler
	if o.Pretty {
		h = slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: lvl})
	} else {
		h = slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level:       lvl,
			ReplaceAttr: cloudLoggingKeys,
		})
	}

	h = &traceHandler{Handler: h, projectID: o.ProjectID}

	l := slog.New(h).With(
		slog.Group("serviceContext",
			slog.String("service", o.ServiceName),
			slog.String("version", o.Version),
		),
		slog.String("env", o.Env),
	)
	slog.SetDefault(l)
	return l
}

// cloudLoggingKeys rewrites slog's default keys into the ones Cloud Logging
// treats as structured fields rather than generic jsonPayload members.
func cloudLoggingKeys(groups []string, a slog.Attr) slog.Attr {
	if len(groups) > 0 {
		return a
	}
	switch a.Key {
	case slog.LevelKey:
		lvl, ok := a.Value.Any().(slog.Level)
		if !ok {
			return a
		}
		return slog.String("severity", severity(lvl))
	case slog.MessageKey:
		return slog.String("message", a.Value.String())
	case slog.TimeKey:
		return slog.Attr{Key: "time", Value: a.Value}
	}
	return a
}

func severity(l slog.Level) string {
	switch {
	case l >= slog.LevelError:
		return "ERROR"
	case l >= slog.LevelWarn:
		return "WARNING"
	case l >= slog.LevelInfo:
		return "INFO"
	default:
		return "DEBUG"
	}
}

// traceHandler stamps every record with the active trace/span so log lines
// appear inline with the request's trace in the Cloud Trace waterfall.
type traceHandler struct {
	slog.Handler
	projectID string
}

func (h *traceHandler) Handle(ctx context.Context, r slog.Record) error {
	if sc := trace.SpanContextFromContext(ctx); sc.IsValid() {
		if h.projectID != "" {
			r.AddAttrs(slog.String("logging.googleapis.com/trace",
				fmt.Sprintf("projects/%s/traces/%s", h.projectID, sc.TraceID())))
		}
		r.AddAttrs(
			slog.String("logging.googleapis.com/spanId", sc.SpanID().String()),
			slog.Bool("logging.googleapis.com/trace_sampled", sc.IsSampled()),
		)
	}
	return h.Handler.Handle(ctx, r)
}

func (h *traceHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &traceHandler{Handler: h.Handler.WithAttrs(attrs), projectID: h.projectID}
}

func (h *traceHandler) WithGroup(name string) slog.Handler {
	return &traceHandler{Handler: h.Handler.WithGroup(name), projectID: h.projectID}
}

// Into stores a logger on the context so downstream code can pick up
// request-scoped fields without threading a parameter everywhere.
func Into(ctx context.Context, l *slog.Logger) context.Context {
	return context.WithValue(ctx, loggerKey, l)
}

// From returns the context logger, falling back to the process default.
func From(ctx context.Context) *slog.Logger {
	if l, ok := ctx.Value(loggerKey).(*slog.Logger); ok && l != nil {
		return l
	}
	return slog.Default()
}
