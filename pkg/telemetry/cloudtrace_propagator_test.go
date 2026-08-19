package telemetry

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

// The Google load balancer stamps X-Cloud-Trace-Context on every inbound
// request. If this propagator gets the format wrong, the load balancer's span
// and every application span end up in two disjoint traces — so the one view
// that shows where a slow request actually spent its time is broken, and
// nothing errors to say so.

func header(v string) propagation.MapCarrier {
	return propagation.MapCarrier{cloudTraceContextHeader: v}
}

func TestExtractParsesTheLoadBalancerHeader(t *testing.T) {
	// The exact shape Google documents: hex trace id, decimal span id,
	// sampling flag.
	ctx := cloudTraceContext{}.Extract(context.Background(),
		header("105445aa7843bc8bf206b12000100000/1;o=1"))

	sc := trace.SpanContextFromContext(ctx)
	if !sc.IsValid() {
		t.Fatal("a well-formed header produced no span context; traces would be disjoint")
	}
	if got := sc.TraceID().String(); got != "105445aa7843bc8bf206b12000100000" {
		t.Errorf("trace id = %s", got)
	}
	if !sc.IsSampled() {
		t.Error("o=1 did not set the sampled flag; the trace would be dropped")
	}
	if !sc.IsRemote() {
		t.Error("the span context is not marked remote, so it would be treated as locally created")
	}
}

func TestSamplingFlagIsHonoured(t *testing.T) {
	// o=0 means the load balancer decided not to sample. Overriding it to
	// sampled would multiply trace volume — and the bill — by the sampling
	// ratio's inverse.
	ctx := cloudTraceContext{}.Extract(context.Background(),
		header("105445aa7843bc8bf206b12000100000/1;o=0"))

	if trace.SpanContextFromContext(ctx).IsSampled() {
		t.Error("o=0 was treated as sampled")
	}
}

func TestSpanIDIsDecimalNotHex(t *testing.T) {
	// The single most likely mistake. Cloud Trace encodes the span id as an
	// unsigned decimal integer while W3C uses hex, and reading one as the
	// other yields a valid-looking id that matches nothing.
	const spanDec = uint64(1234605616436508552) // 0x1122334455667788

	ctx := cloudTraceContext{}.Extract(context.Background(),
		header("105445aa7843bc8bf206b12000100000/"+"1234605616436508552;o=1"))

	sc := trace.SpanContextFromContext(ctx)
	if got := binaryToUint64(sc.SpanID()); got != spanDec {
		t.Errorf("span id = %d, want %d — decoded as hex rather than decimal?", got, spanDec)
	}
	if got := sc.SpanID().String(); got != "1122334455667788" {
		t.Errorf("span id hex = %s, want 1122334455667788", got)
	}
}

func TestSpanIDConversionRoundTrips(t *testing.T) {
	for _, v := range []uint64{0, 1, 255, 256, 1 << 32, 1234605616436508552, ^uint64(0)} {
		if got := binaryToUint64(uint64ToSpanID(v)); got != v {
			t.Errorf("round trip of %d produced %d", v, got)
		}
	}
}

func TestInjectProducesTheDocumentedFormat(t *testing.T) {
	// Outbound calls to Google services carry this header. A malformed value
	// means the downstream span is orphaned instead.
	traceID, _ := trace.TraceIDFromHex("105445aa7843bc8bf206b12000100000")
	spanID := uint64ToSpanID(1234605616436508552)

	ctx := trace.ContextWithSpanContext(context.Background(), trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: traceID, SpanID: spanID, TraceFlags: trace.FlagsSampled,
	}))

	carrier := propagation.MapCarrier{}
	cloudTraceContext{}.Inject(ctx, carrier)

	got := carrier.Get(cloudTraceContextHeader)
	want := "105445aa7843bc8bf206b12000100000/1234605616436508552;o=1"
	if got != want {
		t.Errorf("injected %q, want %q", got, want)
	}
}

func TestInjectAndExtractAreInverse(t *testing.T) {
	// Service-to-service calls inject and the receiver extracts. Anything lost
	// in that round trip breaks the trace at that hop.
	traceID, _ := trace.TraceIDFromHex("4bf92f3577b34da6a3ce929d0e0e4736")
	spanID := uint64ToSpanID(9876543210)

	original := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: traceID, SpanID: spanID, TraceFlags: trace.FlagsSampled,
	})

	carrier := propagation.MapCarrier{}
	cloudTraceContext{}.Inject(trace.ContextWithSpanContext(context.Background(), original), carrier)

	got := trace.SpanContextFromContext(
		cloudTraceContext{}.Extract(context.Background(), carrier))

	if got.TraceID() != original.TraceID() {
		t.Errorf("trace id changed: %s → %s", original.TraceID(), got.TraceID())
	}
	if got.SpanID() != original.SpanID() {
		t.Errorf("span id changed: %s → %s", original.SpanID(), got.SpanID())
	}
	if got.IsSampled() != original.IsSampled() {
		t.Error("the sampling decision did not survive the round trip")
	}
}

func TestInjectWritesNothingWithoutAValidSpan(t *testing.T) {
	// A header naming an all-zero trace is worse than no header: Cloud Trace
	// would attach the request to a trace that does not exist.
	carrier := propagation.MapCarrier{}
	cloudTraceContext{}.Inject(context.Background(), carrier)

	if v := carrier.Get(cloudTraceContextHeader); v != "" {
		t.Errorf("injected %q with no active span", v)
	}
}

func TestW3CTraceparentWinsOverTheLegacyHeader(t *testing.T) {
	// Both headers arrive when a Google load balancer fronts a caller that
	// already speaks W3C. The composite propagator handles traceparent first,
	// and this one must not overwrite it — otherwise the caller's own trace is
	// discarded at the edge.
	traceID, _ := trace.TraceIDFromHex("4bf92f3577b34da6a3ce929d0e0e4736")
	existing := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: traceID, SpanID: uint64ToSpanID(42), TraceFlags: trace.FlagsSampled,
	})
	ctx := trace.ContextWithSpanContext(context.Background(), existing)

	got := trace.SpanContextFromContext(cloudTraceContext{}.Extract(ctx,
		header("105445aa7843bc8bf206b12000100000/999;o=1")))

	if got.TraceID() != existing.TraceID() {
		t.Errorf("the legacy header overwrote an existing W3C context: %s", got.TraceID())
	}
}

func TestMalformedHeadersAreIgnoredNotFatal(t *testing.T) {
	// This header is attacker-influenced on any request that reaches the load
	// balancer. Every malformed shape must leave the context untouched rather
	// than panicking in middleware that runs before authentication.
	for _, h := range []string{
		"",
		"garbage",
		"no-slash;o=1",
		"nothex/1;o=1",
		"105445aa7843bc8bf206b12000100000",  // no span
		"105445aa7843bc8bf206b12000100000/", // empty span
		"105445aa7843bc8bf206b12000100000/notanumber",                  // non-numeric span
		"105445aa7843bc8bf206b12000100000/-1;o=1",                      // negative
		"105445aa7843bc8bf206b12000100000/99999999999999999999999;o=1", // overflows uint64
		"/1;o=1",
		strings.Repeat("a", 10000),
		"00000000000000000000000000000000/1;o=1", // all-zero trace id is invalid
	} {
		t.Run(h[:min(len(h), 30)], func(t *testing.T) {
			ctx := cloudTraceContext{}.Extract(context.Background(), header(h))
			if trace.SpanContextFromContext(ctx).IsValid() {
				t.Errorf("malformed header %q produced a valid span context", h)
			}
		})
	}
}

func TestMissingSamplingFlagDefaultsToUnsampled(t *testing.T) {
	// Some callers omit ";o=". Defaulting to sampled would inflate trace
	// volume for every such request.
	ctx := cloudTraceContext{}.Extract(context.Background(),
		header("105445aa7843bc8bf206b12000100000/1"))

	sc := trace.SpanContextFromContext(ctx)
	if !sc.IsValid() {
		t.Fatal("a header without the sampling flag was rejected entirely")
	}
	if sc.IsSampled() {
		t.Error("a missing sampling flag was treated as sampled")
	}
}

func TestFieldsNamesTheHeaderItOwns(t *testing.T) {
	// The composite propagator uses Fields() to clear stale headers before
	// injecting. A wrong name leaves the caller's header in place on an
	// outbound request.
	fields := cloudTraceContext{}.Fields()
	if len(fields) != 1 || fields[0] != cloudTraceContextHeader {
		t.Errorf("Fields() = %v, want [%s]", fields, cloudTraceContextHeader)
	}
	// And it must match the header the load balancer actually sends, in the
	// canonical form Go's http.Header uses.
	if http.CanonicalHeaderKey(cloudTraceContextHeader) != cloudTraceContextHeader {
		t.Errorf("%q is not in canonical form; HeaderCarrier lookups would miss it",
			cloudTraceContextHeader)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
