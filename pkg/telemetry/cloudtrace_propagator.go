package telemetry

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

// cloudTraceContextHeader is the header Google's Global External HTTPS Load
// Balancer stamps on every inbound request.
const cloudTraceContextHeader = "X-Cloud-Trace-Context"

// cloudTraceContext propagates the legacy Google trace header.
//
// Format: TRACE_ID/SPAN_ID_DECIMAL;o=TRACE_TRUE
// e.g. 105445aa7843bc8bf206b12000100000/1;o=1
//
// Without this, the span the load balancer creates is orphaned from our
// application spans and the Cloud Trace waterfall shows two disjoint traces
// for a single user request.
type cloudTraceContext struct{}

var _ propagation.TextMapPropagator = cloudTraceContext{}

func (cloudTraceContext) Fields() []string { return []string{cloudTraceContextHeader} }

func (cloudTraceContext) Inject(ctx context.Context, carrier propagation.TextMapCarrier) {
	sc := trace.SpanContextFromContext(ctx)
	if !sc.IsValid() {
		return
	}
	sampled := 0
	if sc.IsSampled() {
		sampled = 1
	}
	// Cloud Trace encodes the span id as an unsigned decimal integer.
	spanID := binaryToUint64(sc.SpanID())
	carrier.Set(cloudTraceContextHeader,
		fmt.Sprintf("%s/%d;o=%d", sc.TraceID(), spanID, sampled))
}

func (cloudTraceContext) Extract(ctx context.Context, carrier propagation.TextMapCarrier) context.Context {
	// A W3C traceparent, if present, has already been handled by the
	// composite propagator and wins over the legacy header.
	if trace.SpanContextFromContext(ctx).IsValid() {
		return ctx
	}
	h := carrier.Get(cloudTraceContextHeader)
	if h == "" {
		return ctx
	}

	traceIDHex, rest, ok := strings.Cut(h, "/")
	if !ok {
		return ctx
	}
	traceID, err := trace.TraceIDFromHex(traceIDHex)
	if err != nil {
		return ctx
	}

	spanPart, optPart, _ := strings.Cut(rest, ";")
	spanDec, err := strconv.ParseUint(spanPart, 10, 64)
	if err != nil {
		return ctx
	}

	var flags trace.TraceFlags
	if strings.TrimPrefix(optPart, "o=") == "1" {
		flags = trace.FlagsSampled
	}

	return trace.ContextWithRemoteSpanContext(ctx, trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    traceID,
		SpanID:     uint64ToSpanID(spanDec),
		TraceFlags: flags,
		Remote:     true,
	}))
}

func binaryToUint64(id trace.SpanID) uint64 {
	var v uint64
	for _, b := range id {
		v = v<<8 | uint64(b)
	}
	return v
}

func uint64ToSpanID(v uint64) trace.SpanID {
	var id trace.SpanID
	for i := 7; i >= 0; i-- {
		id[i] = byte(v)
		v >>= 8
	}
	return id
}
