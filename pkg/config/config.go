// Package config loads service configuration from the environment.
//
// Every deployable in this repo reads the same base configuration and then
// layers its own service-specific struct on top. Secrets are never read from
// files on disk: on GKE they arrive as environment variables projected from
// Secret Manager through the Secret Manager CSI driver or through
// `secretEnv` in the pod spec.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Base holds the settings shared by every service in the platform.
type Base struct {
	// ServiceName is used for logging, tracing and metrics labels.
	ServiceName string
	// Env is one of dev, staging, prod.
	Env string
	// Version is the container image tag ($SHORT_SHA from Cloud Build).
	Version string
	// Region is the GCP region the workload runs in, e.g. europe-west1.
	Region string
	// ProjectID is the GCP project number/id, injected by Terraform.
	ProjectID string

	// HTTPAddr is the address the public/internal HTTP server binds to.
	HTTPAddr string
	// AdminAddr serves /healthz, /readyz and /metrics. Kept off the public
	// listener so probes and Prometheus never travel the same path as users.
	AdminAddr string

	// ShutdownGrace is how long we keep serving in-flight work after SIGTERM.
	// Must stay below terminationGracePeriodSeconds in the Deployment.
	ShutdownGrace time.Duration

	// LogLevel is debug, info, warn or error.
	LogLevel string
	// TraceSampleRatio is the head sampling ratio for OpenTelemetry.
	TraceSampleRatio float64
	// OTLPEndpoint is the collector endpoint; empty disables tracing export.
	OTLPEndpoint string
}

// LoadBase reads the shared configuration for the named service.
func LoadBase(serviceName string) (Base, error) {
	b := Base{
		ServiceName:      serviceName,
		Env:              String("ENV", "dev"),
		Version:          String("VERSION", "dev"),
		Region:           String("GCP_REGION", "europe-west1"),
		ProjectID:        String("GCP_PROJECT_ID", ""),
		HTTPAddr:         String("HTTP_ADDR", ":8080"),
		AdminAddr:        String("ADMIN_ADDR", ":9090"),
		ShutdownGrace:    Duration("SHUTDOWN_GRACE", 25*time.Second),
		LogLevel:         String("LOG_LEVEL", "info"),
		TraceSampleRatio: Float("TRACE_SAMPLE_RATIO", 0.05),
		OTLPEndpoint:     String("OTLP_ENDPOINT", ""),
	}
	switch b.Env {
	case "dev", "staging", "prod":
	default:
		return Base{}, fmt.Errorf("config: ENV must be dev|staging|prod, got %q", b.Env)
	}
	return b, nil
}

// String returns the environment variable or def when unset/empty.
func String(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}

// Secret returns a credential, preferring the file that KEY_FILE points at.
//
// Two reasons a file beats an environment variable for a secret:
//
//   - An environment variable is readable from /proc/<pid>/environ, is
//     inherited by every child process, and lands in a crash dump. A file read
//     once at startup does none of that.
//   - The Secret Manager CSI driver projects secrets as files. Turning one
//     into an environment variable needs a synced Kubernetes Secret, which is
//     visible to anything in the namespace that can read Secrets — the exact
//     namespace-wide exposure that per-service credentials exist to avoid.
//
// The variable itself is still honoured, because local development and
// docker-compose have no CSI driver and a file would be pure ceremony there.
//
// A trailing newline is stripped: `printf` writes one, editors add one, and a
// password with an invisible newline on the end fails to authenticate in a way
// that takes hours to diagnose.
func Secret(key, def string) string {
	if path := String(key+"_FILE", ""); path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			// Deliberately not silent. A missing secret file means the service
			// is about to try to authenticate with the default — usually the
			// empty string — and fail somewhere far less obvious.
			fmt.Fprintf(os.Stderr, "config: cannot read %s from %s: %v\n", key, path, err)
			return def
		}
		if v := strings.TrimRight(string(b), "\r\n"); v != "" {
			return v
		}
		return def
	}
	return String(key, def)
}

// MustSecret is Secret for a credential the service cannot start without.
func MustSecret(key string) (string, error) {
	if v := Secret(key, ""); v != "" {
		return v, nil
	}
	return "", fmt.Errorf("config: required secret %s is not set (neither %[1]s nor %[1]s_FILE)", key)
}

// MustString returns the environment variable or an error when unset.
func MustString(key string) (string, error) {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return "", fmt.Errorf("config: required environment variable %s is not set", key)
	}
	return v, nil
}

// Int returns the environment variable parsed as an int, or def.
func Int(key string, def int) int {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

// Float returns the environment variable parsed as a float64, or def.
func Float(key string, def float64) float64 {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return def
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return def
	}
	return f
}

// Bool returns the environment variable parsed as a bool, or def.
func Bool(key string, def bool) bool {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}

// Duration returns the environment variable parsed as a duration, or def.
func Duration(key string, def time.Duration) time.Duration {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return def
	}
	return d
}

// Strings splits a comma-separated environment variable, trimming whitespace.
func Strings(key string, def []string) []string {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return def
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return def
	}
	return out
}
