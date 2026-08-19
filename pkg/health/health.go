// Package health serves the admin listener: liveness, readiness, metrics and
// pprof. It is deliberately bound to a separate port from user traffic so a
// saturated public listener never starves kubelet probes.
package health

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/pprof"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Check reports whether one dependency is usable.
type Check func(context.Context) error

// Registry aggregates readiness checks.
//
// Liveness is intentionally dumb — it answers "is the process wedged?" and
// never consults dependencies. If liveness followed Cassandra availability a
// database blip would restart every pod in the fleet and turn a degradation
// into an outage.
type Registry struct {
	mu     sync.RWMutex
	checks map[string]Check

	ready    atomic.Bool
	draining atomic.Bool

	// Timeout bounds each individual readiness check.
	Timeout time.Duration
}

// NewRegistry returns an empty, not-yet-ready registry.
func NewRegistry() *Registry {
	return &Registry{checks: map[string]Check{}, Timeout: 2 * time.Second}
}

// Register adds a named readiness check.
func (r *Registry) Register(name string, c Check) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.checks[name] = c
}

// SetReady flips the readiness flag once startup work has finished.
func (r *Registry) SetReady(v bool) { r.ready.Store(v) }

// BeginDrain marks the pod as going away. Readiness starts failing
// immediately so the endpoints controller pulls us out of the Service before
// we stop accepting connections — this is what makes rolling updates
// invisible to clients.
func (r *Registry) BeginDrain() { r.draining.Store(true) }

// Draining reports whether shutdown has started.
func (r *Registry) Draining() bool { return r.draining.Load() }

type statusBody struct {
	Status string            `json:"status"`
	Checks map[string]string `json:"checks,omitempty"`
}

// Handler builds the admin mux.
func (r *Registry) Handler(enablePprof bool) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	mux.HandleFunc("/readyz", func(w http.ResponseWriter, req *http.Request) {
		body := statusBody{Status: "ok", Checks: map[string]string{}}
		code := http.StatusOK

		switch {
		case r.draining.Load():
			body.Status = "draining"
			code = http.StatusServiceUnavailable
		case !r.ready.Load():
			body.Status = "starting"
			code = http.StatusServiceUnavailable
		default:
			r.mu.RLock()
			checks := make(map[string]Check, len(r.checks))
			for k, v := range r.checks {
				checks[k] = v
			}
			r.mu.RUnlock()

			for name, check := range checks {
				ctx, cancel := context.WithTimeout(req.Context(), r.Timeout)
				err := check(ctx)
				cancel()
				if err != nil {
					body.Checks[name] = err.Error()
					body.Status = "degraded"
					code = http.StatusServiceUnavailable
					continue
				}
				body.Checks[name] = "ok"
			}
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(body)
	})

	mux.Handle("/metrics", promhttp.Handler())

	if enablePprof {
		mux.HandleFunc("/debug/pprof/", pprof.Index)
		mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
		mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
		mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
		mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	}

	return mux
}
