package ratelimit

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

// The token bucket is a Lua script that runs inside Redis. Testing it against
// a mock would prove that the mock implements the mock; these tests use a real
// server and skip when there is not one, so a green run without Redis is
// honestly reported as skipped rather than passing.
//
//	docker run -d --rm -p 63799:6379 redis:7-alpine
//	REDIS_TEST_ADDR=127.0.0.1:63799 go test ./pkg/ratelimit/

func testRedis(t *testing.T) redis.UniversalClient {
	t.Helper()

	addr := os.Getenv("REDIS_TEST_ADDR")
	if addr == "" {
		addr = "127.0.0.1:63799"
	}
	rdb := redis.NewClient(&redis.Options{Addr: addr, DialTimeout: 500 * time.Millisecond})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := rdb.Ping(ctx).Err(); err != nil {
		_ = rdb.Close()
		t.Skipf("no Redis at %s (%v) — start one with: docker run -d --rm -p 63799:6379 redis:7-alpine", addr, err)
	}
	t.Cleanup(func() { _ = rdb.Close() })
	return rdb
}

// uniqueKey keeps parallel tests and repeat runs from sharing a bucket.
func uniqueKey(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("test:%s:%d", t.Name(), time.Now().UnixNano())
}

func TestBurstIsAllowedThenRefused(t *testing.T) {
	rdb := testRedis(t)
	l := New(rdb, false)
	ctx := context.Background()
	key := uniqueKey(t)

	// A slow refill so the bucket does not top up during the test.
	lim := Limit{Burst: 5, Rate: 0.01}

	for i := 0; i < 5; i++ {
		d, err := l.Allow(ctx, key, lim)
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		if !d.Allowed {
			t.Fatalf("request %d was refused inside the burst of 5", i+1)
		}
	}

	d, err := l.Allow(ctx, key, lim)
	if err != nil {
		t.Fatal(err)
	}
	if d.Allowed {
		t.Fatal("the sixth request was allowed against a burst of 5")
	}
	if d.RetryAfter <= 0 {
		t.Error("a refusal carried no RetryAfter; the client cannot back off correctly")
	}
}

func TestRemainingCountsDown(t *testing.T) {
	rdb := testRedis(t)
	l := New(rdb, false)
	ctx := context.Background()
	key := uniqueKey(t)
	lim := Limit{Burst: 3, Rate: 0.01}

	for i, want := range []int{2, 1, 0} {
		d, err := l.Allow(ctx, key, lim)
		if err != nil {
			t.Fatal(err)
		}
		if d.Remaining != want {
			t.Errorf("after request %d, Remaining = %d, want %d", i+1, d.Remaining, want)
		}
	}
}

func TestBucketsAreIndependent(t *testing.T) {
	// Per-user limiting only works if one user exhausting their bucket leaves
	// everyone else's untouched.
	rdb := testRedis(t)
	l := New(rdb, false)
	ctx := context.Background()
	lim := Limit{Burst: 2, Rate: 0.01}

	a, b := uniqueKey(t)+":a", uniqueKey(t)+":b"

	for i := 0; i < 2; i++ {
		if d, _ := l.Allow(ctx, a, lim); !d.Allowed {
			t.Fatalf("bucket a refused request %d inside its burst", i+1)
		}
	}
	if d, _ := l.Allow(ctx, a, lim); d.Allowed {
		t.Fatal("bucket a was not exhausted")
	}

	if d, err := l.Allow(ctx, b, lim); err != nil || !d.Allowed {
		t.Fatalf("exhausting bucket a also limited bucket b: %v", err)
	}
}

func TestTokensRefill(t *testing.T) {
	rdb := testRedis(t)
	l := New(rdb, false)
	ctx := context.Background()
	key := uniqueKey(t)

	// 20 per second: one token back in 50ms.
	lim := Limit{Burst: 1, Rate: 20}

	if d, _ := l.Allow(ctx, key, lim); !d.Allowed {
		t.Fatal("the first request was refused")
	}
	if d, _ := l.Allow(ctx, key, lim); d.Allowed {
		t.Fatal("a second immediate request was allowed against a burst of 1")
	}

	time.Sleep(300 * time.Millisecond)

	if d, err := l.Allow(ctx, key, lim); err != nil || !d.Allowed {
		t.Fatalf("the bucket did not refill after 300ms at 20/s: allowed=%v err=%v", d.Allowed, err)
	}
}

func TestAllowNConsumesTheWeight(t *testing.T) {
	// Expensive operations are charged more than cheap ones. If AllowN
	// consumed one token regardless, an upload would cost the same as a
	// typing notification.
	rdb := testRedis(t)
	l := New(rdb, false)
	ctx := context.Background()
	key := uniqueKey(t)
	lim := Limit{Burst: 10, Rate: 0.01}

	d, err := l.AllowN(ctx, key, lim, 7)
	if err != nil {
		t.Fatal(err)
	}
	if !d.Allowed || d.Remaining != 3 {
		t.Fatalf("AllowN(7) → allowed=%v remaining=%d, want true/3", d.Allowed, d.Remaining)
	}

	if d, _ := l.AllowN(ctx, key, lim, 5); d.Allowed {
		t.Fatal("a 5-token request was allowed with only 3 remaining")
	}
	// The refused request must not have consumed anything.
	if d, _ := l.AllowN(ctx, key, lim, 3); !d.Allowed {
		t.Fatal("a refused request consumed tokens from the bucket")
	}
}

func TestResetClearsABucket(t *testing.T) {
	// Used after a successful login to clear the failed-attempt counter, so a
	// user who eventually gets their password right is not locked out.
	rdb := testRedis(t)
	l := New(rdb, false)
	ctx := context.Background()
	key := uniqueKey(t)
	lim := Limit{Burst: 1, Rate: 0.01}

	l.Allow(ctx, key, lim)
	if d, _ := l.Allow(ctx, key, lim); d.Allowed {
		t.Fatal("the bucket was not exhausted")
	}

	if err := l.Reset(ctx, key); err != nil {
		t.Fatal(err)
	}
	if d, _ := l.Allow(ctx, key, lim); !d.Allowed {
		t.Fatal("Reset did not clear the bucket")
	}
}

func TestConcurrentCallersCannotExceedTheBurst(t *testing.T) {
	// The whole reason the bucket lives in a Lua script: read-modify-write in
	// the client would let N concurrent requests each see a full bucket. If
	// this over-admits, the limiter does not limit under exactly the load it
	// exists for.
	rdb := testRedis(t)
	l := New(rdb, false)
	ctx := context.Background()
	key := uniqueKey(t)
	lim := Limit{Burst: 10, Rate: 0.001}

	const callers = 50
	results := make(chan bool, callers)
	for i := 0; i < callers; i++ {
		go func() {
			d, err := l.Allow(ctx, key, lim)
			results <- err == nil && d.Allowed
		}()
	}

	allowed := 0
	for i := 0; i < callers; i++ {
		if <-results {
			allowed++
		}
	}
	if allowed != 10 {
		t.Errorf("%d of %d concurrent requests were allowed against a burst of 10", allowed, callers)
	}
}

func TestZeroLimitIsUnlimited(t *testing.T) {
	// A zero-valued Limit means "no limit configured", not "allow nothing".
	// The inverse would make an unconfigured endpoint refuse every request.
	rdb := testRedis(t)
	l := New(rdb, false)
	ctx := context.Background()

	for i := 0; i < 100; i++ {
		d, err := l.Allow(ctx, uniqueKey(t), Limit{})
		if err != nil || !d.Allowed {
			t.Fatalf("a zero Limit refused a request: allowed=%v err=%v", d.Allowed, err)
		}
	}
}

// ---------------------------------------------------------------------------
// Failure behaviour — no Redis needed, and the most important tests here
// ---------------------------------------------------------------------------

// deadRedis points at a port nothing is listening on, so every command fails.
func deadRedis(t *testing.T) redis.UniversalClient {
	t.Helper()
	rdb := redis.NewClient(&redis.Options{
		Addr:        "127.0.0.1:1",
		DialTimeout: 100 * time.Millisecond,
		MaxRetries:  -1,
	})
	t.Cleanup(func() { _ = rdb.Close() })
	return rdb
}

func TestFailOpenAllowsWhenRedisIsDown(t *testing.T) {
	// The message path. A Redis outage must degrade rate limiting, not stop
	// people sending messages — the limiter is there to shape load, and
	// silencing the platform to enforce it inverts the priorities.
	l := New(deadRedis(t), true)

	d, err := l.Allow(context.Background(), "k", Limit{Burst: 1, Rate: 1})
	if !d.Allowed {
		t.Error("a fail-open limiter refused a request while Redis was unreachable")
	}
	if err != nil {
		t.Errorf("a fail-open limiter surfaced an error rather than allowing quietly: %v", err)
	}
}

func TestFailClosedRefusesWhenRedisIsDown(t *testing.T) {
	// The OTP path. Here the limiter is the only thing between an attacker and
	// an unbounded SMS bill plus a brute-force window, so an outage must stop
	// the endpoint rather than open it.
	l := New(deadRedis(t), false)

	d, err := l.Allow(context.Background(), "k", Limit{Burst: 1, Rate: 1})
	if d.Allowed {
		t.Fatal("a fail-closed limiter allowed a request while Redis was unreachable — " +
			"this is an open door to OTP brute force and SMS billing abuse")
	}
	if err == nil {
		t.Error("a fail-closed refusal carried no error, so the outage would be invisible")
	}
	if d.RetryAfter <= 0 {
		t.Error("a fail-closed refusal carried no RetryAfter")
	}
}

// ---------------------------------------------------------------------------
// Keys and configured limits
// ---------------------------------------------------------------------------

func TestKeysAreDistinctPerSubject(t *testing.T) {
	// A key collision silently merges two subjects' buckets — one user's
	// traffic would limit another's.
	keys := map[string]string{
		"user 1":        KeyUser("send", 1),
		"user 2":        KeyUser("send", 2),
		"user 1 other":  KeyUser("read", 1),
		"user 1 chat 2": KeyUserChat("send", 1, 2),
		"user 2 chat 1": KeyUserChat("send", 2, 1),
		"ip":            KeyIP("login", "1.2.3.4"),
		"ip other":      KeyIP("login", "1.2.3.5"),
		"phone":         KeyPhone("otp", "+441234567890"),
	}

	seen := make(map[string]string, len(keys))
	for name, k := range keys {
		if prev, dup := seen[k]; dup {
			t.Errorf("%s and %s both produce key %q", prev, name, k)
		}
		seen[k] = name
	}

	// KeyUserChat(1,2) and KeyUserChat(2,1) are different subjects and must
	// not collapse into one bucket.
	if KeyUserChat("send", 1, 2) == KeyUserChat("send", 2, 1) {
		t.Error("KeyUserChat is symmetric; two different users share one bucket")
	}
}

func TestConfiguredLimitsAreSane(t *testing.T) {
	// Guards against a zero slipping into a table that is edited by hand. A
	// Burst of 0 would refuse everything; a Rate of 0 means the bucket never
	// refills and the first burst is all a user ever gets.
	limits := map[string]Limit{
		"SendMessage":        SendMessage,
		"SendMessagePerChat": SendMessagePerChat,
		"OTPRequestPerPhone": OTPRequestPerPhone,
		"OTPRequestPerIP":    OTPRequestPerIP,
		"OTPVerifyPerPhone":  OTPVerifyPerPhone,
		"LoginPerIP":         LoginPerIP,
		"UploadInit":         UploadInit,
		"ConnectionPerIP":    ConnectionPerIP,
		"HandshakePerIP":     HandshakePerIP,
		"APIReadPerUser":     APIReadPerUser,
		"FileReport":         FileReport,
		"DataExport":         DataExport,
	}
	for name, lim := range limits {
		if lim.Burst <= 0 {
			t.Errorf("%s has Burst %d; a non-positive burst means the limiter is disabled", name, lim.Burst)
		}
		if lim.Rate <= 0 {
			t.Errorf("%s has Rate %v; the bucket would never refill", name, lim.Rate)
		}
	}

	// The OTP limits are the ones that cost real money when wrong, so they
	// get an explicit ceiling rather than only a positivity check.
	if OTPRequestPerPhone.Burst > 5 {
		t.Errorf("OTPRequestPerPhone.Burst = %d; each one is a paid SMS", OTPRequestPerPhone.Burst)
	}
	if OTPRequestPerPhone.Rate > 0.1 {
		t.Errorf("OTPRequestPerPhone.Rate = %v, which is more than 6 SMS a minute to one number",
			OTPRequestPerPhone.Rate)
	}
}
