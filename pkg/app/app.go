// Package app is the common process bootstrap: configuration, logging,
// tracing, the admin listener, signal handling and ordered shutdown.
//
// Every service's main() is a thin wrapper around app.Run so that operational
// behaviour — how we drain, how long we wait, what we log on the way out — is
// identical across the fleet and lives in exactly one place.
package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/pervagans/messaging-app/pkg/config"
	"github.com/pervagans/messaging-app/pkg/health"
	"github.com/pervagans/messaging-app/pkg/logx"
	"github.com/pervagans/messaging-app/pkg/telemetry"
)

// App carries everything a service needs from the bootstrap.
type App struct {
	Cfg    config.Base
	Log    *slog.Logger
	Health *health.Registry

	mu       sync.Mutex
	closers  []namedCloser
	preDrain []func(context.Context)
}

type namedCloser struct {
	name  string
	close func(context.Context) error
}

// OnShutdown registers a cleanup function. Closers run in reverse order of
// registration, so a service that registers Kafka after Cassandra will flush
// Kafka first and only then drop the database session.
func (a *App) OnShutdown(name string, fn func(context.Context) error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.closers = append(a.closers, namedCloser{name: name, close: fn})
}

// OnDrain registers a hook that runs the moment SIGTERM arrives, before any
// closer. The realtime gateway uses it to send a "reconnect elsewhere" frame
// to every live connection so clients migrate without a visible disconnect.
func (a *App) OnDrain(fn func(context.Context)) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.preDrain = append(a.preDrain, fn)
}

// Main is the service body. It should start listeners and return; blocking
// until ctx is done is handled by Run.
type Main func(ctx context.Context, a *App) error

// Run bootstraps the process and blocks until shutdown completes.
func Run(serviceName string, main Main) {
	cfg, err := config.LoadBase(serviceName)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	log := logx.New(logx.Options{
		Level:       cfg.LogLevel,
		ServiceName: cfg.ServiceName,
		Version:     cfg.Version,
		Env:         cfg.Env,
		ProjectID:   cfg.ProjectID,
		Pretty:      cfg.Env == "dev" && config.Bool("LOG_PRETTY", false),
	})

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	shutdownTracing, err := telemetry.Init(ctx, telemetry.Config{
		ServiceName:  cfg.ServiceName,
		Version:      cfg.Version,
		Env:          cfg.Env,
		OTLPEndpoint: cfg.OTLPEndpoint,
		SampleRatio:  cfg.TraceSampleRatio,
	})
	if err != nil {
		log.Error("tracing init failed; continuing without export", "error", err)
		shutdownTracing = func(context.Context) error { return nil }
	}

	a := &App{Cfg: cfg, Log: log, Health: health.NewRegistry()}

	admin := &http.Server{
		Addr:              cfg.AdminAddr,
		Handler:           a.Health.Handler(config.Bool("ENABLE_PPROF", cfg.Env != "prod")),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		if err := admin.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("admin listener failed", "error", err)
		}
	}()

	log.Info("starting",
		"service", cfg.ServiceName,
		"version", cfg.Version,
		"env", cfg.Env,
		"region", cfg.Region,
		"http_addr", cfg.HTTPAddr,
		"admin_addr", cfg.AdminAddr,
	)

	if err := main(ctx, a); err != nil {
		log.Error("startup failed", "error", err)
		a.shutdown(log, admin, shutdownTracing, 5*time.Second)
		os.Exit(1)
	}

	a.Health.SetReady(true)
	log.Info("ready")

	<-ctx.Done()
	stop() // a second signal now kills the process immediately
	log.Info("shutdown signal received", "grace", cfg.ShutdownGrace.String())

	a.shutdown(log, admin, shutdownTracing, cfg.ShutdownGrace)
	log.Info("stopped")
}

func (a *App) shutdown(log *slog.Logger, admin *http.Server, tracing telemetry.Shutdown, grace time.Duration) {
	// Fail readiness first and give the endpoints controller a moment to
	// notice. Without this pause, kube-proxy on some nodes still has us in
	// its rules and in-flight connections get reset.
	a.Health.BeginDrain()

	ctx, cancel := context.WithTimeout(context.Background(), grace)
	defer cancel()

	a.mu.Lock()
	preDrain := append([]func(context.Context){}, a.preDrain...)
	closers := append([]namedCloser{}, a.closers...)
	a.mu.Unlock()

	if len(preDrain) > 0 {
		var wg sync.WaitGroup
		for _, fn := range preDrain {
			wg.Add(1)
			go func(f func(context.Context)) { defer wg.Done(); f(ctx) }(fn)
		}
		wg.Wait()
	}

	select {
	case <-time.After(propagationDelay):
	case <-ctx.Done():
	}

	for i := len(closers) - 1; i >= 0; i-- {
		c := closers[i]
		if err := c.close(ctx); err != nil {
			log.Error("closer failed", "component", c.name, "error", err)
			continue
		}
		log.Info("closed", "component", c.name)
	}

	if err := tracing(ctx); err != nil {
		log.Warn("tracing flush failed", "error", err)
	}
	_ = admin.Shutdown(ctx)
}

// propagationDelay is the window we give Kubernetes to observe the failing
// readiness probe and remove this pod from Service endpoints.
var propagationDelay = 5 * time.Second
