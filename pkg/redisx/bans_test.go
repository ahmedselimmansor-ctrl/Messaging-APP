package redisx

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

// The ban cache is what the send path consults, so a defect here means a
// banned account keeps messaging people. Tested against a real server for the
// same reason as the rate limiter: the semantics that matter are Redis's.
//
//	docker run -d --rm -p 63799:6379 redis:7-alpine
//	REDIS_TEST_ADDR=127.0.0.1:63799 go test ./pkg/redisx/

func testClient(t *testing.T) *Client {
	t.Helper()

	addr := os.Getenv("REDIS_TEST_ADDR")
	if addr == "" {
		addr = "127.0.0.1:63799"
	}

	probe := redis.NewClient(&redis.Options{Addr: addr, DialTimeout: 500 * time.Millisecond})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := probe.Ping(ctx).Err(); err != nil {
		_ = probe.Close()
		t.Skipf("no Redis at %s (%v) — start one with: docker run -d --rm -p 63799:6379 redis:7-alpine", addr, err)
	}
	_ = probe.Close()

	c, err := Connect(context.Background(), Config{Addrs: []string{addr}})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { _ = c.Close(context.Background()) })
	return c
}

// uid keeps concurrent runs from sharing a key.
func uid() int64 { return time.Now().UnixNano() }

func TestUnknownUserIsNotBanned(t *testing.T) {
	// Absence means "not banned". This is the failure mode the whole design
	// rests on: if a missing key meant banned, a Redis flush would silence
	// every account on the platform at once.
	b := testClient(t).Bans(time.Hour)
	ctx := context.Background()

	banned, err := b.IsBanned(ctx, uid())
	if err != nil {
		t.Fatal(err)
	}
	if banned {
		t.Fatal("an account with no cache entry was reported as banned")
	}
}

func TestSetThenIsBanned(t *testing.T) {
	b := testClient(t).Bans(time.Hour)
	ctx := context.Background()
	id := uid()

	if err := b.Set(ctx, id, "spam"); err != nil {
		t.Fatal(err)
	}
	banned, err := b.IsBanned(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if !banned {
		t.Fatal("an account that was just banned is not reported as banned")
	}
}

func TestClearLiftsABan(t *testing.T) {
	b := testClient(t).Bans(time.Hour)
	ctx := context.Background()
	id := uid()

	if err := b.Set(ctx, id, "spam"); err != nil {
		t.Fatal(err)
	}
	if err := b.Clear(ctx, id); err != nil {
		t.Fatal(err)
	}

	banned, err := b.IsBanned(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if banned {
		t.Fatal("an unbanned account is still reported as banned")
	}
}

func TestClearIsIdempotent(t *testing.T) {
	// Unbanning an account that was never banned is a no-op, not an error.
	// The admin service calls Clear before checking Postgres, so this path
	// runs on every unban of an already-clear account.
	b := testClient(t).Bans(time.Hour)
	if err := b.Clear(context.Background(), uid()); err != nil {
		t.Errorf("Clear on an unbanned account returned %v, want nil", err)
	}
}

func TestBansAreIndependentPerUser(t *testing.T) {
	b := testClient(t).Bans(time.Hour)
	ctx := context.Background()
	a, c := uid(), uid()+1

	if err := b.Set(ctx, a, "spam"); err != nil {
		t.Fatal(err)
	}

	if banned, _ := b.IsBanned(ctx, c); banned {
		t.Fatal("banning one account reported another as banned")
	}
	if banned, _ := b.IsBanned(ctx, a); !banned {
		t.Fatal("the banned account is not banned")
	}
}

func TestReloadRepopulatesTheCache(t *testing.T) {
	// The reconcile path. Without it, a Redis flush silently stops send-path
	// enforcement and nothing ever says so.
	b := testClient(t).Bans(time.Hour)
	ctx := context.Background()

	a, c := uid(), uid()+1
	if err := b.Reload(ctx, map[int64]string{a: "spam", c: "abuse"}); err != nil {
		t.Fatal(err)
	}

	for _, id := range []int64{a, c} {
		banned, err := b.IsBanned(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if !banned {
			t.Errorf("account %d was not restored by Reload", id)
		}
	}
}

func TestReloadDoesNotRemoveBansItWasNotToldAbout(t *testing.T) {
	// Reload adds rather than replaces, deliberately: a ban applied between
	// reading the list from Postgres and writing it here must survive. A
	// replace would lift it.
	b := testClient(t).Bans(time.Hour)
	ctx := context.Background()

	recent := uid()
	if err := b.Set(ctx, recent, "banned after the list was read"); err != nil {
		t.Fatal(err)
	}

	if err := b.Reload(ctx, map[int64]string{uid() + 1: "spam"}); err != nil {
		t.Fatal(err)
	}

	banned, err := b.IsBanned(ctx, recent)
	if err != nil {
		t.Fatal(err)
	}
	if !banned {
		t.Fatal("Reload lifted a ban applied while the list was being read")
	}
}

func TestReloadOfAnEmptyListIsANoOp(t *testing.T) {
	// A platform with no banned accounts must not have its cache disturbed —
	// and an empty map must not be read as "clear everything".
	b := testClient(t).Bans(time.Hour)
	ctx := context.Background()

	id := uid()
	if err := b.Set(ctx, id, "spam"); err != nil {
		t.Fatal(err)
	}
	if err := b.Reload(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if banned, _ := b.IsBanned(ctx, id); !banned {
		t.Fatal("Reload(nil) cleared an existing ban")
	}
}

func TestBanEntriesExpire(t *testing.T) {
	// The TTL is a backstop against a missed delete, not the mechanism. It
	// still has to actually be set, or a lifted ban that failed to clear would
	// persist forever.
	c := testClient(t)
	b := c.Bans(2 * time.Second)
	ctx := context.Background()
	id := uid()

	if err := b.Set(ctx, id, "spam"); err != nil {
		t.Fatal(err)
	}

	ttl, err := c.Raw().TTL(ctx, keyBan(id)).Result()
	if err != nil {
		t.Fatal(err)
	}
	if ttl <= 0 || ttl > 2*time.Second {
		t.Errorf("TTL = %v, want a positive value no greater than 2s", ttl)
	}
}

func TestDefaultTTLIsLongRatherThanShort(t *testing.T) {
	// The asymmetry is deliberate and worth pinning: a ban that lingers too
	// long is a support ticket, one that expires too early puts an abuser back
	// online. A short default would quietly choose the worse failure.
	c := testClient(t)
	b := c.Bans(0)
	ctx := context.Background()
	id := uid()

	if err := b.Set(ctx, id, "spam"); err != nil {
		t.Fatal(err)
	}
	ttl, err := c.Raw().TTL(ctx, keyBan(id)).Result()
	if err != nil {
		t.Fatal(err)
	}
	if ttl < time.Hour {
		t.Errorf("the default ban TTL is %v; anything short risks lifting a ban by expiry", ttl)
	}
}
