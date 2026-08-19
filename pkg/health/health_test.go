package health

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// Readiness is what Kubernetes uses to decide whether to send this pod
// traffic. Every failure mode here is a production incident:
//
//   - Ready when a dependency is down → traffic to a pod that cannot serve it.
//   - Not ready when everything is fine → capacity silently removed, and in
//     the worst case a rollout that never completes.
//   - Ready while draining → requests land on a pod that is about to exit,
//     which is exactly the connection reset a rolling update is supposed to
//     avoid.

func get(t *testing.T, h http.Handler, path string) (int, statusBody) {
	t.Helper()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))

	var body statusBody
	if strings.HasPrefix(w.Header().Get("Content-Type"), "application/json") {
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("%s returned unparseable JSON: %v (%s)", path, err, w.Body.String())
		}
	}
	return w.Code, body
}

func TestNotReadyUntilSetReady(t *testing.T) {
	// A registry starts not-ready on purpose. A pod that reported ready before
	// its startup work finished would receive traffic it cannot serve — the
	// window is small but it lands on every deploy.
	r := NewRegistry()
	h := r.Handler(false)

	code, body := get(t, h, "/readyz")
	if code != http.StatusServiceUnavailable {
		t.Errorf("a fresh registry returned %d, want 503", code)
	}
	if body.Status != "starting" {
		t.Errorf("status = %q, want starting", body.Status)
	}

	r.SetReady(true)
	if code, _ := get(t, h, "/readyz"); code != http.StatusOK {
		t.Errorf("after SetReady(true), status = %d, want 200", code)
	}
}

func TestReadyWhenEveryCheckPasses(t *testing.T) {
	r := NewRegistry()
	r.Register("postgres", func(context.Context) error { return nil })
	r.Register("redis", func(context.Context) error { return nil })
	r.SetReady(true)

	code, body := get(t, r.Handler(false), "/readyz")
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	if body.Status != "ok" {
		t.Errorf("status = %q, want ok", body.Status)
	}
	for _, name := range []string{"postgres", "redis"} {
		if body.Checks[name] != "ok" {
			t.Errorf("check %q = %q, want ok", name, body.Checks[name])
		}
	}
}

func TestOneFailingCheckMakesThePodUnready(t *testing.T) {
	// The important direction. A pod that stays ready with a dead database
	// keeps receiving requests it can only fail.
	r := NewRegistry()
	r.Register("postgres", func(context.Context) error { return nil })
	r.Register("cassandra", func(context.Context) error { return errors.New("connection refused") })
	r.SetReady(true)

	code, body := get(t, r.Handler(false), "/readyz")
	if code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 — one dead dependency must take the pod out of the Service", code)
	}
	if body.Status != "degraded" {
		t.Errorf("status = %q, want degraded", body.Status)
	}
	if body.Checks["cassandra"] == "ok" || body.Checks["cassandra"] == "" {
		t.Errorf("the failing check is not reported: %q", body.Checks["cassandra"])
	}
	// The healthy ones are still reported, so an operator can see which of
	// several dependencies is the problem.
	if body.Checks["postgres"] != "ok" {
		t.Errorf("the healthy check was not reported: %q", body.Checks["postgres"])
	}
}

func TestEveryCheckRunsEvenAfterOneFails(t *testing.T) {
	// Stopping at the first failure would report one dependency as broken and
	// say nothing about the rest — so an operator fixes one thing, redeploys,
	// and discovers the next.
	var ran sync.Map
	r := NewRegistry()
	for _, name := range []string{"a", "b", "c"} {
		n := name
		r.Register(n, func(context.Context) error {
			ran.Store(n, true)
			return errors.New("down")
		})
	}
	r.SetReady(true)

	code, body := get(t, r.Handler(false), "/readyz")
	if code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", code)
	}
	for _, name := range []string{"a", "b", "c"} {
		if _, ok := ran.Load(name); !ok {
			t.Errorf("check %q never ran", name)
		}
		if body.Checks[name] == "" {
			t.Errorf("check %q is missing from the response", name)
		}
	}
}

func TestDrainingIsUnreadyEvenWhenHealthy(t *testing.T) {
	// This is what makes a rolling update invisible. BeginDrain must fail
	// readiness immediately, before the process stops accepting connections,
	// so the endpoints controller removes the pod first.
	r := NewRegistry()
	r.Register("postgres", func(context.Context) error { return nil })
	r.SetReady(true)
	h := r.Handler(false)

	if code, _ := get(t, h, "/readyz"); code != http.StatusOK {
		t.Fatal("the pod was not ready before draining")
	}

	r.BeginDrain()

	code, body := get(t, h, "/readyz")
	if code != http.StatusServiceUnavailable {
		t.Fatalf("a draining pod returned %d, want 503 — it will keep receiving traffic while shutting down", code)
	}
	if body.Status != "draining" {
		t.Errorf("status = %q, want draining", body.Status)
	}
	if !r.Draining() {
		t.Error("Draining() does not report the drain")
	}
}

func TestDrainingTakesPrecedenceOverHealth(t *testing.T) {
	// Draining must win even when the checks would fail anyway, so the reason
	// reported is the true one. An operator reading "degraded" during a
	// deliberate shutdown would go looking for a dependency problem.
	r := NewRegistry()
	r.Register("postgres", func(context.Context) error { return errors.New("down") })
	r.SetReady(true)
	r.BeginDrain()

	_, body := get(t, r.Handler(false), "/readyz")
	if body.Status != "draining" {
		t.Errorf("status = %q, want draining", body.Status)
	}
}

func TestLivenessNeverConsultsDependencies(t *testing.T) {
	// The single most important property in this file. If liveness followed
	// Cassandra, a database blip would restart every pod in the fleet at once
	// and turn a degradation into a full outage.
	called := false
	r := NewRegistry()
	r.Register("cassandra", func(context.Context) error {
		called = true
		return errors.New("everything is on fire")
	})
	r.SetReady(true)
	r.BeginDrain() // even while draining, liveness must stay green

	w := httptest.NewRecorder()
	r.Handler(false).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/healthz", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("liveness returned %d with a dead dependency — this would restart the whole fleet", w.Code)
	}
	if called {
		t.Error("liveness ran a dependency check; it must not")
	}
}

func TestASlowCheckIsBoundedByTheTimeout(t *testing.T) {
	// A check that hangs must not hang the probe. Kubelet has its own timeout,
	// but a probe that never returns leaves the pod in an ambiguous state for
	// far longer than necessary.
	r := NewRegistry()
	r.Timeout = 50 * time.Millisecond
	r.Register("slow", func(ctx context.Context) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
			return nil
		}
	})
	r.SetReady(true)

	done := make(chan int, 1)
	go func() {
		code, _ := get(t, r.Handler(false), "/readyz")
		done <- code
	}()

	select {
	case code := <-done:
		if code != http.StatusServiceUnavailable {
			t.Errorf("a timed-out check produced %d, want 503", code)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("readiness did not return within 2s despite a 50ms check timeout")
	}
}

func TestConcurrentProbesAndRegistrations(t *testing.T) {
	// Kubelet probes on its own schedule while startup code is still calling
	// Register. A data race between the two would be a crash in the one
	// endpoint that decides whether the pod is usable.
	r := NewRegistry()
	r.SetReady(true)
	h := r.Handler(false)

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(2)
		go func(i int) {
			defer wg.Done()
			r.Register(string(rune('a'+i)), func(context.Context) error { return nil })
		}(i)
		go func() {
			defer wg.Done()
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/readyz", nil))
		}()
	}
	wg.Wait()
}

func TestMetricsAreServed(t *testing.T) {
	// PodMonitoring scrapes /metrics on this listener. If it did not serve,
	// every dashboard and alert would be silently empty.
	w := httptest.NewRecorder()
	NewRegistry().Handler(false).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("/metrics returned %d, want 200", w.Code)
	}
	if w.Body.Len() == 0 {
		t.Error("/metrics returned an empty body")
	}
}

func TestPprofIsOffUnlessAskedFor(t *testing.T) {
	// pprof exposes goroutine stacks and heap contents. It is useful in an
	// incident and inappropriate by default, so the default must be off.
	w := httptest.NewRecorder()
	NewRegistry().Handler(false).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/debug/pprof/", nil))
	if w.Code == http.StatusOK {
		t.Error("pprof is served when it was not enabled")
	}

	w = httptest.NewRecorder()
	NewRegistry().Handler(true).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/debug/pprof/", nil))
	if w.Code != http.StatusOK {
		t.Errorf("pprof was enabled but returned %d", w.Code)
	}
}
