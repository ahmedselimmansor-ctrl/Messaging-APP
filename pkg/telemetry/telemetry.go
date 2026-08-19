// Package telemetry wires OpenTelemetry tracing and Prometheus metrics.
//
// Traces are exported over OTLP. On GKE the OTLP endpoint points at the
// OpenTelemetry Collector DaemonSet, which forwards to Cloud Trace; running
// the collector rather than a direct Cloud Trace exporter keeps the
// application vendor-neutral and lets us tail-sample at the node.
//
// Metrics are exposed on the admin listener in Prometheus format and scraped
// by Google Cloud Managed Service for Prometheus via a PodMonitoring resource.
package telemetry

import (
	"context"
	"fmt"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.34.0"
	"go.opentelemetry.io/otel/trace"
)

// Config describes the tracing exporter.
type Config struct {
	ServiceName  string
	Version      string
	Env          string
	OTLPEndpoint string // host:port; empty disables export
	SampleRatio  float64
}

// Shutdown flushes and stops the exporter.
type Shutdown func(context.Context) error

// Init installs the global tracer provider and propagators.
//
// The propagator set includes both W3C tracecontext and the legacy
// X-Cloud-Trace-Context header so traces started at the Google load balancer
// stitch together with our own spans.
func Init(ctx context.Context, c Config) (Shutdown, error) {
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
		cloudTraceContext{},
	))

	if c.OTLPEndpoint == "" {
		otel.SetTracerProvider(trace.NewNoopTracerProvider())
		return func(context.Context) error { return nil }, nil
	}

	exp, err := otlptracegrpc.New(ctx,
		otlptracegrpc.WithEndpoint(c.OTLPEndpoint),
		otlptracegrpc.WithInsecure(), // in-cluster hop, protected by mesh mTLS
		otlptracegrpc.WithTimeout(5*time.Second),
	)
	if err != nil {
		return nil, fmt.Errorf("telemetry: otlp exporter: %w", err)
	}

	res, err := resource.Merge(resource.Default(), resource.NewWithAttributes(
		semconv.SchemaURL,
		semconv.ServiceName(c.ServiceName),
		semconv.ServiceVersion(c.Version),
		semconv.DeploymentEnvironmentName(c.Env),
	))
	if err != nil {
		return nil, fmt.Errorf("telemetry: resource: %w", err)
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp, sdktrace.WithMaxQueueSize(4096)),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(c.SampleRatio))),
	)
	otel.SetTracerProvider(tp)

	return func(ctx context.Context) error { return tp.Shutdown(ctx) }, nil
}

// Tracer returns a named tracer from the global provider.
func Tracer(name string) trace.Tracer { return otel.Tracer(name) }

// Attr is a convenience alias so callers do not import attribute directly.
func Attr(k string, v string) attribute.KeyValue { return attribute.String(k, v) }

// ---------------------------------------------------------------------------
// Shared metrics
// ---------------------------------------------------------------------------

var (
	// RPCDuration measures inbound request latency for HTTP and MTProto RPCs.
	RPCDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "messaging",
		Name:      "rpc_duration_seconds",
		Help:      "Inbound request latency by transport, method and status.",
		Buckets:   []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10},
	}, []string{"transport", "method", "status"})

	// ConnectionsGauge tracks live realtime connections per transport.
	ConnectionsGauge = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "messaging",
		Name:      "realtime_connections",
		Help:      "Currently established realtime connections.",
	}, []string{"transport"})

	// KafkaPublished counts produced records.
	KafkaPublished = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "messaging",
		Name:      "kafka_published_total",
		Help:      "Records produced to Kafka.",
	}, []string{"topic", "result"})

	// KafkaConsumed counts consumed records.
	KafkaConsumed = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "messaging",
		Name:      "kafka_consumed_total",
		Help:      "Records consumed from Kafka.",
	}, []string{"topic", "group", "result"})

	// KafkaLagSeconds observes the age of a record when it is handled.
	KafkaLagSeconds = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "messaging",
		Name:      "kafka_record_age_seconds",
		Help:      "Wall-clock age of a record when the consumer handled it.",
		Buckets:   []float64{.01, .05, .1, .5, 1, 5, 15, 60, 300},
	}, []string{"topic", "group"})

	// MessagesDelivered counts realtime fanout deliveries.
	MessagesDelivered = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "messaging",
		Name:      "messages_delivered_total",
		Help:      "Message updates pushed to clients.",
	}, []string{"path"}) // path=realtime|push
)

// ObserveRPC records a completed inbound call.
func ObserveRPC(transportName, method, status string, started time.Time) {
	RPCDuration.WithLabelValues(transportName, method, status).Observe(time.Since(started).Seconds())
}
