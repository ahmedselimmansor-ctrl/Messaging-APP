package ids

import (
	"strings"
	"sync"
	"testing"
	"time"
)

// Snowflakes are message ids. A duplicate is a message that overwrites
// another, and a non-monotonic one sorts history into the wrong order — so
// uniqueness and ordering are the two properties worth proving.

func TestNextIsUniqueUnderLoad(t *testing.T) {
	s, err := NewSnowflake(1)
	if err != nil {
		t.Fatal(err)
	}

	// More than one millisecond's worth of sequence space (4096), so the
	// rollover path is exercised rather than skipped.
	const n = 20000
	seen := make(map[int64]struct{}, n)
	for i := 0; i < n; i++ {
		id := s.Next()
		if _, dup := seen[id]; dup {
			t.Fatalf("id %d was issued twice after %d generations", id, i)
		}
		seen[id] = struct{}{}
	}
}

func TestNextIsMonotonic(t *testing.T) {
	s, err := NewSnowflake(1)
	if err != nil {
		t.Fatal(err)
	}

	prev := s.Next()
	for i := 0; i < 20000; i++ {
		id := s.Next()
		if id <= prev {
			t.Fatalf("id went backwards: %d then %d", prev, id)
		}
		prev = id
	}
}

func TestNextIsUniqueAcrossGoroutines(t *testing.T) {
	// Every handler generates ids concurrently. If the lock did not cover both
	// the timestamp read and the sequence increment, two goroutines in the
	// same millisecond would get the same id — and one message would silently
	// replace another.
	s, err := NewSnowflake(7)
	if err != nil {
		t.Fatal(err)
	}

	const goroutines, each = 32, 500
	var mu sync.Mutex
	seen := make(map[int64]struct{}, goroutines*each)

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			local := make([]int64, each)
			for i := range local {
				local[i] = s.Next()
			}
			mu.Lock()
			defer mu.Unlock()
			for _, id := range local {
				if _, dup := seen[id]; dup {
					t.Errorf("id %d was issued twice", id)
					return
				}
				seen[id] = struct{}{}
			}
		}()
	}
	wg.Wait()

	if len(seen) != goroutines*each {
		t.Errorf("generated %d distinct ids, want %d", len(seen), goroutines*each)
	}
}

func TestDifferentNodesNeverCollide(t *testing.T) {
	// Two pods generating in the same millisecond must not produce the same
	// id. The node bits are the only thing separating them.
	a, err := NewSnowflake(1)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewSnowflake(2)
	if err != nil {
		t.Fatal(err)
	}

	seen := make(map[int64]struct{}, 4000)
	for i := 0; i < 2000; i++ {
		for _, id := range []int64{a.Next(), b.Next()} {
			if _, dup := seen[id]; dup {
				t.Fatalf("nodes 1 and 2 both produced %d", id)
			}
			seen[id] = struct{}{}
		}
	}
}

func TestNodeIDIsRecoverableAndRangeChecked(t *testing.T) {
	for _, node := range []int64{0, 1, 511, 1023} {
		s, err := NewSnowflake(node)
		if err != nil {
			t.Fatalf("NewSnowflake(%d): %v", node, err)
		}
		id := s.Next()
		got := (id >> nodeShift) & maxNode
		if got != node {
			t.Errorf("node %d encoded as %d", node, got)
		}
	}

	// Out of range must be refused rather than silently truncated: a node id
	// of 1024 wrapping to 0 would collide with a real node 0.
	for _, bad := range []int64{-1, 1024, 99999} {
		if _, err := NewSnowflake(bad); err == nil {
			t.Errorf("NewSnowflake(%d) succeeded, want an error", bad)
		}
	}
}

func TestTimeOfRoundTrips(t *testing.T) {
	s, err := NewSnowflake(3)
	if err != nil {
		t.Fatal(err)
	}

	before := time.Now().UTC().Add(-2 * time.Second)
	id := s.Next()
	after := time.Now().UTC().Add(2 * time.Second)

	got := TimeOf(id)
	if got.Before(before) || got.After(after) {
		t.Errorf("TimeOf = %v, want between %v and %v", got, before, after)
	}
}

func TestIDsFitInAPositiveInt64(t *testing.T) {
	// The sign bit must stay clear. A negative id would break every
	// bigint column and every client that treats these as unsigned.
	s, err := NewSnowflake(1023)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 1000; i++ {
		if id := s.Next(); id <= 0 {
			t.Fatalf("generated a non-positive id: %d", id)
		}
	}
}

func TestNodeFromHostnameIsStableAndInRange(t *testing.T) {
	// A pod that restarts with the same name must get the same node id;
	// otherwise a rolling restart could reuse another pod's id space.
	for _, host := range []string{
		"chat-service-7d9f8b6c4-x2n9k", "auth-0", "", "a", strings.Repeat("x", 500),
	} {
		first := NodeFromHostname(host)
		if first != NodeFromHostname(host) {
			t.Errorf("NodeFromHostname(%q) is not deterministic", host)
		}
		if first < 0 || first > maxNode {
			t.Errorf("NodeFromHostname(%q) = %d, outside 0..%d", host, first, maxNode)
		}
	}
}

func TestNodeFromHostnameSpreadsAcrossTheSpace(t *testing.T) {
	// Not a uniformity proof — just enough to catch a hash that collapses
	// every pod onto one node, which would reintroduce the collisions the
	// node bits exist to prevent.
	seen := make(map[int64]struct{})
	for i := 0; i < 200; i++ {
		seen[NodeFromHostname("chat-service-abc-"+string(rune('a'+i%26))+string(rune('a'+i/26)))] = struct{}{}
	}
	if len(seen) < 50 {
		t.Errorf("200 distinct hostnames produced only %d distinct node ids", len(seen))
	}
}

// ---------------------------------------------------------------------------
// Random values
// ---------------------------------------------------------------------------

func TestNumericCodeShape(t *testing.T) {
	// OTP codes. The leading zero is the interesting part: formatting that
	// drops it turns a 5-digit code space into a smaller one, and users see
	// a code of the wrong length.
	for _, n := range []int{1, 4, 5, 6, 8, 18} {
		code, err := NumericCode(n)
		if err != nil {
			t.Fatalf("NumericCode(%d): %v", n, err)
		}
		if len(code) != n {
			t.Errorf("NumericCode(%d) = %q, length %d", n, code, len(code))
		}
		for _, r := range code {
			if r < '0' || r > '9' {
				t.Errorf("NumericCode(%d) = %q contains a non-digit", n, code)
				break
			}
		}
	}

	for _, bad := range []int{0, -1, 19, 100} {
		if _, err := NumericCode(bad); err == nil {
			t.Errorf("NumericCode(%d) succeeded, want an error", bad)
		}
	}
}

func TestNumericCodeUsesTheWholeSpace(t *testing.T) {
	// A generator that never emits a leading zero has lost a tenth of its
	// space, which for a 5-digit OTP is a meaningful reduction in the work an
	// attacker has to do.
	sawLeadingZero := false
	distinct := make(map[string]struct{})
	for i := 0; i < 3000; i++ {
		code, err := NumericCode(5)
		if err != nil {
			t.Fatal(err)
		}
		distinct[code] = struct{}{}
		if code[0] == '0' {
			sawLeadingZero = true
		}
	}
	if !sawLeadingZero {
		t.Error("3000 five-digit codes and none began with 0; the space is not being used fully")
	}
	// Birthday collisions are expected in 100000 possibilities; a generator
	// stuck on a handful of values is not.
	if len(distinct) < 2500 {
		t.Errorf("3000 codes produced only %d distinct values", len(distinct))
	}
}

func TestTokenLengthAndRandomness(t *testing.T) {
	a, err := Token(32)
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != 32 {
		t.Fatalf("Token(32) returned %d bytes", len(a))
	}

	b, err := Token(32)
	if err != nil {
		t.Fatal(err)
	}
	if string(a) == string(b) {
		t.Fatal("Token returned identical bytes twice — it is not random")
	}

	// All-zero would mean the buffer was never filled.
	allZero := true
	for _, c := range a {
		if c != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Fatal("Token returned 32 zero bytes")
	}
}

func TestUUIDsAreDistinctAndParseable(t *testing.T) {
	seen := make(map[string]struct{}, 1000)
	for i := 0; i < 1000; i++ {
		u := NewUUID()
		if _, dup := seen[u]; dup {
			t.Fatalf("NewUUID returned %q twice", u)
		}
		seen[u] = struct{}{}
		if _, err := ParseUUID(u); err != nil {
			t.Fatalf("a generated UUID does not parse: %v", err)
		}
	}
	if _, err := ParseUUID("not-a-uuid"); err == nil {
		t.Error("ParseUUID accepted a non-UUID")
	}
}

func TestRandomInt64Varies(t *testing.T) {
	seen := make(map[int64]struct{}, 500)
	for i := 0; i < 500; i++ {
		v, err := RandomInt64()
		if err != nil {
			t.Fatal(err)
		}
		seen[v] = struct{}{}
	}
	if len(seen) < 500 {
		t.Errorf("500 calls produced %d distinct values", len(seen))
	}
}
