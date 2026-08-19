package app

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/pervagans/messaging-app/pkg/health"
	"github.com/pervagans/messaging-app/pkg/telemetry"
)

// Shutdown ordering is what makes a rolling deploy invisible. Every property
// below corresponds to a specific way a deploy goes wrong:
//
//   - Closers in the wrong order → Kafka's buffered messages flushed after the
//     database session it needs is already closed, so the flush fails and
//     accepted messages are lost.
//   - Readiness not failed first → kube-proxy still routes to this pod while
//     it is tearing down, and clients see connection resets.
//   - Drain hooks after closers → the gateway's "reconnect elsewhere" frame is
//     written to connections that have already been dropped.

func testApp(t *testing.T) *App {
	t.Helper()
	return &App{
		Log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		Health: health.NewRegistry(),
	}
}

// noTracing satisfies the tracing-flush argument without exporting anything.
func noTracing() telemetry.Shutdown {
	return func(context.Context) error { return nil }
}

// fastPropagation shortens the endpoints-propagation pause for tests and
// restores it afterwards.
func fastPropagation(t *testing.T) {
	t.Helper()
	original := propagationDelay
	propagationDelay = time.Millisecond
	t.Cleanup(func() { propagationDelay = original })
}

func TestClosersRunInReverseOrder(t *testing.T) {
	// Services register in dependency order — database, then the things built
	// on it — so unwinding must run backwards. Registering Kafka after
	// Cassandra means Kafka flushes first, while the session it may need is
	// still open.
	fastPropagation(t)
	a := testApp(t)

	var mu sync.Mutex
	var order []string
	record := func(name string) func(context.Context) error {
		return func(context.Context) error {
			mu.Lock()
			defer mu.Unlock()
			order = append(order, name)
			return nil
		}
	}

	a.OnShutdown("postgres", record("postgres"))
	a.OnShutdown("cassandra", record("cassandra"))
	a.OnShutdown("kafka", record("kafka"))

	a.shutdown(a.Log, &http.Server{}, noTracing(), 5*time.Second)

	want := []string{"kafka", "cassandra", "postgres"}
	if len(order) != len(want) {
		t.Fatalf("ran %v, want %v", order, want)
	}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("shutdown order was %v, want %v", order, want)
		}
	}
}

func TestAFailingCloserDoesNotStopTheRest(t *testing.T) {
	// If one closer's failure aborted the sequence, a Kafka flush error would
	// leave database sessions and file handles open until the kubelet's grace
	// period expired and SIGKILL arrived.
	fastPropagation(t)
	a := testApp(t)

	var mu sync.Mutex
	var ran []string
	a.OnShutdown("first", func(context.Context) error {
		mu.Lock()
		defer mu.Unlock()
		ran = append(ran, "first")
		return nil
	})
	a.OnShutdown("broken", func(context.Context) error {
		mu.Lock()
		defer mu.Unlock()
		ran = append(ran, "broken")
		return errors.New("flush failed")
	})
	a.OnShutdown("last", func(context.Context) error {
		mu.Lock()
		defer mu.Unlock()
		ran = append(ran, "last")
		return nil
	})

	a.shutdown(a.Log, &http.Server{}, noTracing(), 5*time.Second)

	if len(ran) != 3 {
		t.Fatalf("only %v ran; a failing closer aborted the sequence", ran)
	}
}

func TestReadinessFailsBeforeAnyCloserRuns(t *testing.T) {
	// The ordering that makes rolling updates lossless: fail readiness, let
	// the endpoints controller notice, and only then start tearing down. A
	// closer that ran first would drop connections still being routed to us.
	fastPropagation(t)
	a := testApp(t)
	a.Health.SetReady(true)

	drainingWhenClosed := false
	a.OnShutdown("check", func(context.Context) error {
		drainingWhenClosed = a.Health.Draining()
		return nil
	})

	a.shutdown(a.Log, &http.Server{}, noTracing(), 5*time.Second)

	if !drainingWhenClosed {
		t.Error("a closer ran while the pod was still reporting ready — " +
			"in-flight requests would be routed to a pod that is shutting down")
	}
	if !a.Health.Draining() {
		t.Error("shutdown did not put the registry into draining")
	}
}

func TestDrainHooksRunBeforeClosers(t *testing.T) {
	// The gateway writes a "reconnect elsewhere" frame from a drain hook. If
	// closers ran first, that frame would be written to sockets that were
	// already closed, and every client would see a hard disconnect instead of
	// migrating cleanly.
	fastPropagation(t)
	a := testApp(t)

	var mu sync.Mutex
	var order []string

	a.OnDrain(func(context.Context) {
		mu.Lock()
		defer mu.Unlock()
		order = append(order, "drain")
	})
	a.OnShutdown("closer", func(context.Context) error {
		mu.Lock()
		defer mu.Unlock()
		order = append(order, "closer")
		return nil
	})

	a.shutdown(a.Log, &http.Server{}, noTracing(), 5*time.Second)

	if len(order) != 2 || order[0] != "drain" || order[1] != "closer" {
		t.Fatalf("order was %v, want drain before closer", order)
	}
}

func TestDrainHooksRunConcurrentlyAndAreAllWaitedFor(t *testing.T) {
	// The gateway may hold tens of thousands of connections. Running hooks
	// sequentially would serialise the notification and blow the grace period;
	// not waiting for them would cut the notification off mid-flight.
	fastPropagation(t)
	a := testApp(t)

	const n = 8
	var mu sync.Mutex
	completed := 0

	for i := 0; i < n; i++ {
		a.OnDrain(func(context.Context) {
			time.Sleep(30 * time.Millisecond)
			mu.Lock()
			defer mu.Unlock()
			completed++
		})
	}

	started := time.Now()
	a.shutdown(a.Log, &http.Server{}, noTracing(), 5*time.Second)
	elapsed := time.Since(started)

	if completed != n {
		t.Errorf("%d of %d drain hooks completed; shutdown did not wait for them", completed, n)
	}
	// Sequential would be ~240ms. Concurrent is ~30ms plus the propagation
	// pause; a generous bound keeps this stable on a loaded machine.
	if elapsed > 200*time.Millisecond {
		t.Errorf("drain took %v; the hooks appear to run sequentially", elapsed)
	}
}

func TestShutdownRespectsTheGracePeriod(t *testing.T) {
	// A closer that hangs must not hold the process past its grace period —
	// the kubelet would SIGKILL it, and every other closer after it would
	// never run at all.
	fastPropagation(t)
	a := testApp(t)

	a.OnShutdown("hangs", func(ctx context.Context) error {
		<-ctx.Done() // must be cancelled by the grace timeout
		return ctx.Err()
	})

	done := make(chan time.Duration, 1)
	go func() {
		started := time.Now()
		a.shutdown(a.Log, &http.Server{}, noTracing(), 100*time.Millisecond)
		done <- time.Since(started)
	}()

	select {
	case elapsed := <-done:
		if elapsed > 2*time.Second {
			t.Errorf("shutdown took %v despite a 100ms grace period", elapsed)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown never returned; a hanging closer blocks the process until SIGKILL")
	}
}

func TestTracingIsFlushedAfterClosers(t *testing.T) {
	// Spans emitted while closing — the flush, the final commits — are exactly
	// the ones an operator wants after a bad deploy. Flushing first would drop
	// them.
	fastPropagation(t)
	a := testApp(t)

	var mu sync.Mutex
	var order []string

	a.OnShutdown("closer", func(context.Context) error {
		mu.Lock()
		defer mu.Unlock()
		order = append(order, "closer")
		return nil
	})

	tracing := telemetry.Shutdown(func(context.Context) error {
		mu.Lock()
		defer mu.Unlock()
		order = append(order, "tracing")
		return nil
	})

	a.shutdown(a.Log, &http.Server{}, tracing, 5*time.Second)

	if len(order) != 2 || order[0] != "closer" || order[1] != "tracing" {
		t.Errorf("order was %v, want the closer before the tracing flush", order)
	}
}

func TestAFailingTracingFlushIsNotFatal(t *testing.T) {
	// The collector being unreachable must not turn a clean shutdown into a
	// crash.
	fastPropagation(t)
	a := testApp(t)

	tracing := telemetry.Shutdown(func(context.Context) error {
		return errors.New("collector unreachable")
	})
	a.shutdown(a.Log, &http.Server{}, tracing, time.Second)
}

func TestRegistrationIsSafeFromMultipleGoroutines(t *testing.T) {
	// Services register closers from the goroutines that build their
	// dependencies, sometimes concurrently. A race here would corrupt the
	// slice that shutdown then walks.
	a := testApp(t)

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			a.OnShutdown("c", func(context.Context) error { return nil })
		}()
		go func() {
			defer wg.Done()
			a.OnDrain(func(context.Context) {})
		}()
	}
	wg.Wait()

	if len(a.closers) != 32 {
		t.Errorf("registered %d closers, want 32", len(a.closers))
	}
	if len(a.preDrain) != 32 {
		t.Errorf("registered %d drain hooks, want 32", len(a.preDrain))
	}
}

func TestShutdownWithNothingRegisteredIsHarmless(t *testing.T) {
	// A service that failed during startup shuts down with an empty registry.
	// It must not panic on the way out and hide the real error.
	fastPropagation(t)
	a := testApp(t)
	a.shutdown(a.Log, &http.Server{}, noTracing(), time.Second)
}
