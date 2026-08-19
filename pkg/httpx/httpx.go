// Package httpx holds the HTTP conventions shared by the REST services:
// error envelope, JSON helpers, middleware chain and a hardened server.
package httpx

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/pervagans/messaging-app/pkg/logx"
	"github.com/pervagans/messaging-app/pkg/telemetry"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

// ErrorCode is a stable, machine-readable error identifier. Clients switch on
// these; the human-readable message may change freely.
type ErrorCode string

const (
	CodeBadRequest    ErrorCode = "BAD_REQUEST"
	CodeUnauthorized  ErrorCode = "UNAUTHORIZED"
	CodeForbidden     ErrorCode = "FORBIDDEN"
	CodeNotFound      ErrorCode = "NOT_FOUND"
	CodeConflict      ErrorCode = "CONFLICT"
	CodeRateLimited   ErrorCode = "RATE_LIMITED"
	CodeFloodWait     ErrorCode = "FLOOD_WAIT"
	CodeInternal      ErrorCode = "INTERNAL"
	CodeUnavailable   ErrorCode = "UNAVAILABLE"
	CodePayloadLarge  ErrorCode = "PAYLOAD_TOO_LARGE"
	CodeUnprocessable ErrorCode = "UNPROCESSABLE"
)

// APIError is both an error value and the JSON body we return.
type APIError struct {
	Code    ErrorCode `json:"code"`
	Message string    `json:"message"`
	// RetryAfter is seconds; set for RATE_LIMITED and FLOOD_WAIT.
	RetryAfter int `json:"retry_after,omitempty"`
	// Details carries field-level validation errors.
	Details map[string]string `json:"details,omitempty"`

	status int
	cause  error
}

func (e *APIError) Error() string {
	if e.cause != nil {
		return fmt.Sprintf("%s: %s: %v", e.Code, e.Message, e.cause)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

func (e *APIError) Unwrap() error { return e.cause }

// Status returns the HTTP status this error maps to.
func (e *APIError) Status() int {
	if e.status != 0 {
		return e.status
	}
	return http.StatusInternalServerError
}

// WithCause attaches an internal error. The cause is logged, never returned
// to the client — that is the whole point of the wrapper.
func (e *APIError) WithCause(err error) *APIError {
	c := *e
	c.cause = err
	return &c
}

// WithDetails attaches field errors.
func (e *APIError) WithDetails(d map[string]string) *APIError {
	c := *e
	c.Details = d
	return &c
}

// Error constructors.
func Err(status int, code ErrorCode, format string, args ...any) *APIError {
	return &APIError{Code: code, Message: fmt.Sprintf(format, args...), status: status}
}

func ErrBadRequest(format string, args ...any) *APIError {
	return Err(http.StatusBadRequest, CodeBadRequest, format, args...)
}
func ErrUnauthorized(format string, args ...any) *APIError {
	return Err(http.StatusUnauthorized, CodeUnauthorized, format, args...)
}
func ErrForbidden(format string, args ...any) *APIError {
	return Err(http.StatusForbidden, CodeForbidden, format, args...)
}
func ErrNotFound(format string, args ...any) *APIError {
	return Err(http.StatusNotFound, CodeNotFound, format, args...)
}
func ErrConflict(format string, args ...any) *APIError {
	return Err(http.StatusConflict, CodeConflict, format, args...)
}
func ErrInternal(format string, args ...any) *APIError {
	return Err(http.StatusInternalServerError, CodeInternal, format, args...)
}
func ErrUnavailable(format string, args ...any) *APIError {
	return Err(http.StatusServiceUnavailable, CodeUnavailable, format, args...)
}

// ErrFloodWait mirrors MTProto's FLOOD_WAIT_X: the client must back off for
// the given number of seconds before retrying this method.
func ErrFloodWait(seconds int) *APIError {
	e := Err(http.StatusTooManyRequests, CodeFloodWait, "too many requests; retry in %ds", seconds)
	e.RetryAfter = seconds
	return e
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

// Handler is an http.HandlerFunc that can fail. Returning an error is the only
// way to produce a non-2xx body, which keeps error shaping in one place.
type Handler func(http.ResponseWriter, *http.Request) error

// H adapts a Handler to http.HandlerFunc.
func H(h Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := h(w, r); err != nil {
			WriteError(w, r, err)
		}
	}
}

// WriteJSON writes a JSON body with the given status.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	if v == nil {
		return
	}
	if err := json.NewEncoder(w).Encode(v); err != nil {
		// The status line is already on the wire; all we can do is record it.
		logx.From(context.Background()).Error("encode response failed", "error", err)
	}
}

// WriteError maps any error onto the API error envelope.
func WriteError(w http.ResponseWriter, r *http.Request, err error) {
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		apiErr = ErrInternal("internal error").WithCause(err)
	}

	log := logx.From(r.Context())
	if apiErr.Status() >= 500 {
		log.Error("request failed",
			"code", string(apiErr.Code),
			"status", apiErr.Status(),
			"error", apiErr.Error(),
			"path", r.URL.Path,
		)
	} else {
		log.Info("request rejected",
			"code", string(apiErr.Code),
			"status", apiErr.Status(),
			"message", apiErr.Message,
			"path", r.URL.Path,
		)
	}

	if span := trace.SpanFromContext(r.Context()); span.IsRecording() {
		span.SetAttributes(attribute.String("error.code", string(apiErr.Code)))
		span.RecordError(err)
	}

	if apiErr.RetryAfter > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(apiErr.RetryAfter))
	}

	// Never leak the internal cause to the caller.
	body := struct {
		Error *APIError `json:"error"`
	}{Error: &APIError{
		Code:       apiErr.Code,
		Message:    apiErr.Message,
		RetryAfter: apiErr.RetryAfter,
		Details:    apiErr.Details,
	}}
	WriteJSON(w, apiErr.Status(), body)
}

// DecodeJSON reads and validates a JSON request body.
//
// maxBytes caps the read so a malicious client cannot make us allocate
// unbounded memory; DisallowUnknownFields turns typos in client payloads into
// loud 400s instead of silently ignored fields.
func DecodeJSON(r *http.Request, maxBytes int64, dst any) error {
	ct := r.Header.Get("Content-Type")
	if ct != "" && !strings.HasPrefix(ct, "application/json") {
		return ErrBadRequest("expected Content-Type application/json, got %q", ct)
	}
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, maxBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return Err(http.StatusRequestEntityTooLarge, CodePayloadLarge,
				"request body exceeds %d bytes", maxBytes)
		}
		return ErrBadRequest("malformed JSON body: %v", err)
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ErrBadRequest("request body must contain a single JSON object")
	}
	return nil
}

// PathInt64 reads an int64 URL parameter.
func PathInt64(r *http.Request, name string) (int64, error) {
	raw := chi.URLParam(r, name)
	v, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0, ErrBadRequest("path parameter %s must be an integer", name)
	}
	return v, nil
}

// QueryInt reads an integer query parameter with a default and a clamp.
func QueryInt(r *http.Request, name string, def, min, max int) int {
	raw := r.URL.Query().Get(name)
	if raw == "" {
		return def
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		return def
	}
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}

// QueryInt64 reads an int64 query parameter.
func QueryInt64(r *http.Request, name string, def int64) int64 {
	raw := r.URL.Query().Get(name)
	if raw == "" {
		return def
	}
	v, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return def
	}
	return v
}

// ---------------------------------------------------------------------------
// Middleware
// ---------------------------------------------------------------------------

// BaseMiddleware returns the chain every REST service mounts, in order.
func BaseMiddleware(serviceName string) []func(http.Handler) http.Handler {
	return []func(http.Handler) http.Handler{
		middleware.RealIP,
		RequestID,
		Trace(serviceName),
		LogRequests,
		Recoverer,
		middleware.Timeout(30 * time.Second),
	}
}

// ClientIP returns the caller's address.
//
// It belongs here rather than in each service because it is only correct in
// combination with the RealIP middleware above: behind the Google load
// balancer, X-Forwarded-For's last-but-one entry is the client, and RealIP has
// already applied that rule by the time a handler runs. So RemoteAddr is
// authoritative and reading the header again would reintroduce the spoofing
// this arrangement exists to prevent.
func ClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// No port, which happens for a unix socket or a synthesised request.
		return r.RemoteAddr
	}
	return host
}

type ctxKey string

const requestIDKey ctxKey = "request_id"

// RequestID honours the load balancer's trace header or mints an id.
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-Id")
		if id == "" {
			// The Google LB always sets this; falling back keeps local dev
			// and direct in-mesh calls traceable too.
			id = strings.SplitN(r.Header.Get("X-Cloud-Trace-Context"), "/", 2)[0]
		}
		if id == "" {
			id = middleware.GetReqID(r.Context())
		}
		if id == "" {
			id = fmt.Sprintf("%d", time.Now().UnixNano())
		}
		w.Header().Set("X-Request-Id", id)
		ctx := context.WithValue(r.Context(), requestIDKey, id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequestIDFrom reads the request id off the context.
func RequestIDFrom(ctx context.Context) string {
	if v, ok := ctx.Value(requestIDKey).(string); ok {
		return v
	}
	return ""
}

// Trace starts a server span and restores upstream context.
func Trace(serviceName string) func(http.Handler) http.Handler {
	tracer := otel.Tracer(serviceName)
	prop := otel.GetTextMapPropagator()
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := prop.Extract(r.Context(), propagation.HeaderCarrier(r.Header))
			route := chi.RouteContext(ctx).RoutePattern()
			if route == "" {
				route = r.URL.Path
			}
			ctx, span := tracer.Start(ctx, r.Method+" "+route, trace.WithSpanKind(trace.SpanKindServer))
			defer span.End()
			span.SetAttributes(
				attribute.String("http.request.method", r.Method),
				attribute.String("url.path", r.URL.Path),
				attribute.String("network.protocol.name", "http"),
			)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// LogRequests emits one structured line per request and records the metric.
func LogRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)

		log := logx.From(r.Context()).With(
			"request_id", RequestIDFrom(r.Context()),
			"method", r.Method,
			"path", r.URL.Path,
		)
		ctx := logx.Into(r.Context(), log)

		next.ServeHTTP(ww, r.WithContext(ctx))

		status := ww.Status()
		if status == 0 {
			status = http.StatusOK
		}
		route := chi.RouteContext(r.Context()).RoutePattern()
		if route == "" {
			route = "unmatched"
		}
		telemetry.ObserveRPC("http", r.Method+" "+route, strconv.Itoa(status), started)

		// 2xx/3xx at debug keeps prod log volume (and cost) sane; anything
		// the client or server got wrong is logged at info or above.
		lvl := log.Debug
		if status >= 500 {
			lvl = log.Error
		} else if status >= 400 {
			lvl = log.Info
		}
		lvl("request",
			"status", status,
			"bytes", ww.BytesWritten(),
			"duration_ms", time.Since(started).Milliseconds(),
			"user_agent", r.UserAgent(),
		)
	})
}

// Recoverer converts a panic into a 500 without taking down the process.
func Recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				if rec == http.ErrAbortHandler {
					panic(rec) // the http server handles this one itself
				}
				logx.From(r.Context()).Error("panic recovered",
					"panic", fmt.Sprint(rec),
					"path", r.URL.Path,
					"stack", stack(),
				)
				WriteError(w, r, ErrInternal("internal error"))
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// NewServer returns an http.Server with the timeouts a public listener needs.
func NewServer(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      120 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 16,
	}
}
